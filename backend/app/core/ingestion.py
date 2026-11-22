"""Secure repository ingestion engine for Red Mercury.

Implements defense-in-depth controls for ZIP archives and Git repositories:
1. Upload size limits, quota management, and zip-bomb mitigation.
2. Path traversal (Zip Slip) prevention and symlink defense.
3. SSRF mitigation: protocol restrictions, DNS resolution, and IP range blocking.
4. Binary/executable filtration and metadata extraction.
5. Strict execution isolation (zero code execution during ingestion).
"""
import ipaddress
import os
import re
import shutil
import signal
import socket
import stat
import subprocess
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import urllib.parse
import zipfile
import zlib

from .config import settings
from .errors import SecurityPolicyViolationError, ValidationError
from .logging import get_logger

logger = get_logger("redmercury.ingestion")

# Nested archive extensions tracked to prevent nested archive bomb abuse
NESTED_ARCHIVE_EXTENSIONS: Set[str] = {
    ".zip", ".tar", ".gz", ".tgz", ".7z", ".rar", ".bz2", ".xz",
    ".jar", ".war", ".ear",
}

# Excluded binary and executable file extensions to prevent malware staging
EXCLUDED_EXTENSIONS: Set[str] = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".iso", ".img",
    ".tar", ".gz", ".tgz", ".zip", ".7z", ".rar", ".bz2", ".xz",
    ".pyc", ".pyo", ".pyd", ".class", ".jar", ".war", ".ear",
    ".node", ".obj", ".o", ".a", ".lib", ".ko", ".sys",
    ".msi", ".com", ".scr", ".bat", ".cmd", ".vbs", ".ps1",
}

# Sensitive internal/metadata hostnames blocked for SSRF protection
BLOCKED_GIT_HOSTNAMES: Set[str] = {
    "localhost",
    "localhost.localdomain",
    "127.0.0.1",
    "::1",
    "::",
    "0.0.0.0",  # nosec B104 - SSRF blocklist entry, not a socket bind
    "metadata.google.internal",
    "metadata.goog",
    "metadata",
    "instance-data",
    "169.254.169.254",
}

BLOCKED_GIT_HOSTNAME_SUFFIXES: Tuple[str, ...] = (
    ".localhost",
    ".local",
    ".internal",
    ".home.arpa",
)

# CGNAT (RFC 6598) and cloud metadata IP ranges not always flagged by is_private
_CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")
_IPV6_ULA_NETWORK = ipaddress.ip_network("fc00::/7")
_IPV6_SITELOCAL_NETWORK = ipaddress.ip_network("fec0::/10")
_EXPLICIT_BLOCKED_IPS: Set[str] = {
    "169.254.169.254",
    "169.254.170.2",
    "100.100.100.200",
    "fd00:ec2::254",
}

# Windows reserved device names
WINDOWS_RESERVED_NAMES: Set[str] = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
}

# Programming language extension map
LANGUAGE_EXTENSIONS: Dict[str, str] = {
    ".py": "Python",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".go": "Go",
    ".rs": "Rust",
    ".java": "Java",
    ".c": "C",
    ".cpp": "C++",
    ".cc": "C++",
    ".h": "C/C++ Header",
    ".hpp": "C++ Header",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".swift": "Swift",
    ".kt": "Kotlin",
    ".scala": "Scala",
    ".sh": "Shell",
    ".bash": "Shell",
    ".sql": "SQL",
    ".html": "HTML",
    ".css": "CSS",
    ".scss": "SCSS",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".json": "JSON",
    ".md": "Markdown",
}


def get_workspace_root() -> Path:
    """Resolve and ensure the base workspace directory."""
    root = Path(settings.WORKSPACE_ROOT)
    if not root.is_absolute():
        # Resolve relative to backend base
        root = Path(__file__).resolve().parent.parent.parent / root
    root.mkdir(parents=True, exist_ok=True)
    return root


def get_repository_workspace(user_id: str, repo_id: str) -> Path:
    """Get isolated filesystem directory for a specific user and repository."""
    base = get_workspace_root()
    # Sanitize user_id and repo_id to prevent any directory escape
    safe_user = re.sub(r"[^a-zA-Z0-9_\-]", "", user_id)
    safe_repo = re.sub(r"[^a-zA-Z0-9_\-]", "", repo_id)
    repo_dir = (base / safe_user / safe_repo / "source").resolve()

    # Enforce confinement within base workspace (immune to prefix collisions)
    if not repo_dir.is_relative_to(base.resolve()):
        raise SecurityPolicyViolationError("Workspace path resolves outside designated root directory.")

    return repo_dir


def is_ip_blocked(ip_str: str) -> bool:
    """Check if an IP address belongs to loopback, private, link-local, CGNAT, or cloud metadata ranges.

    Handles IPv4, IPv6, IPv4-mapped IPv6 (::ffff:x.x.x.x), 6to4, and Teredo transition addresses.
    """
    try:
        # Strip IPv6 zone index (e.g., fe80::1%eth0) if present
        cleaned = ip_str.strip().split("%", 1)[0]
        ip = ipaddress.ip_address(cleaned)

        # Unwrap IPv6 transition mechanisms to prevent IPv4-in-IPv6 SSRF bypasses
        if isinstance(ip, ipaddress.IPv6Address):
            if ip.ipv4_mapped is not None and is_ip_blocked(str(ip.ipv4_mapped)):
                return True
            if ip.sixtofour is not None and is_ip_blocked(str(ip.sixtofour)):
                return True
            if ip.teredo is not None:
                server_ip, client_ip = ip.teredo
                if is_ip_blocked(str(server_ip)) or is_ip_blocked(str(client_ip)):
                    return True
            if ip in _IPV6_ULA_NETWORK or ip in _IPV6_SITELOCAL_NETWORK:
                return True

        if isinstance(ip, ipaddress.IPv4Address):
            if ip in _CGNAT_NETWORK:
                return True

        if (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
            or not ip.is_global
        ):
            return True

        if str(ip).lower() in _EXPLICIT_BLOCKED_IPS:
            return True

        return False
    except ValueError:
        return True


def validate_git_url(
    url: str,
    allow_private: bool = False,
    allow_proxy_dns_resolution: bool = False,
) -> str:
    """Strictly validate Git clone URL to prevent SSRF, local path cloning, and protocol smuggling."""
    if not url or not isinstance(url, str):
        raise ValidationError("Git repository URL must be a non-empty string.")

    cleaned_url = url.strip()
    if "\0" in cleaned_url or any(ch in cleaned_url for ch in ("\r", "\n", "\t", " ")):
        raise ValidationError("Git repository URL contains illegal control or whitespace characters.")

    # Reject Git remote-helper syntax (e.g., ext::sh -c ..., fd::..., http::...) and local filesystem paths
    if cleaned_url.startswith(("/", "\\", ".", "~")) or re.match(r"^[a-zA-Z]:[\\/]", cleaned_url):
        raise SecurityPolicyViolationError("Local filesystem paths are prohibited as Git repository URLs.")
    if "::" in cleaned_url.split("/", 1)[0]:
        raise SecurityPolicyViolationError("Unsupported Git remote-helper syntax is prohibited.")

    parsed = urllib.parse.urlsplit(cleaned_url)
    scheme = (parsed.scheme or "").lower()

    # Protocol check: strictly HTTPS (HTTP only permitted when allow_private is explicitly enabled)
    if scheme != "https" and not (allow_private and scheme == "http"):
        raise SecurityPolicyViolationError(
            f"Unsupported Git protocol '{scheme or 'none'}'. Only secure HTTPS repositories are supported."
        )

    # Disallow embedding credentials in URL (e.g., https://user:pass@host/repo)
    if parsed.username or parsed.password:
        raise ValidationError("Embedding user credentials or tokens directly in repository URLs is prohibited.")

    hostname = (parsed.hostname or "").strip().rstrip(".")
    if not hostname:
        raise ValidationError("Invalid repository URL: missing hostname.")

    lower_host = hostname.lower()

    if not allow_private:
        # Block explicit sensitive/metadata hostnames and internal suffixes
        if lower_host in BLOCKED_GIT_HOSTNAMES or any(
            lower_host.endswith(suffix) for suffix in BLOCKED_GIT_HOSTNAME_SUFFIXES
        ):
            raise SecurityPolicyViolationError(f"Target host '{hostname}' is not permitted (SSRF protection).")

        # Direct IP literal check before DNS lookup
        is_ip_literal = False
        try:
            ipaddress.ip_address(lower_host)
            is_ip_literal = True
        except ValueError:
            is_ip_literal = False

        if is_ip_literal:
            if is_ip_blocked(lower_host):
                raise SecurityPolicyViolationError(
                    f"Target host '{hostname}' resolves to restricted network address ({lower_host})."
                )
        else:
            # Block single-label internal hostnames (e.g., 'postgres', 'redis', 'intranet')
            if "." not in lower_host:
                raise SecurityPolicyViolationError(
                    f"Internal single-label hostname '{hostname}' is not permitted (SSRF protection)."
                )

        # Resolve all DNS addresses (IPv4 + IPv6) and verify every single one
        try:
            port = parsed.port or (443 if scheme == "https" else 80)
            addr_info = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
            resolved_ips = {item[4][0] for item in addr_info}
            if not resolved_ips:
                raise ValidationError(f"Could not resolve repository host '{hostname}'.")

            for ip_str in resolved_ips:
                if is_ip_blocked(ip_str):
                    logger.warning(f"SSRF attempt blocked: host '{hostname}' resolved to restricted IP '{ip_str}'")
                    raise SecurityPolicyViolationError(
                        f"Target host '{hostname}' resolves to restricted network address ({ip_str})."
                    )
        except socket.gaierror as e:
            if allow_proxy_dns_resolution:
                logger.info(
                    f"Local DNS resolution unavailable for '{hostname}' while routing via SSRF-filtering egress proxy; "
                    "deferring hostname resolution to proxy."
                )
            else:
                raise ValidationError(f"DNS resolution failed for repository host '{hostname}': {str(e)}")

    # Return sanitized URL (without query parameters or fragments)
    sanitized_url = urllib.parse.urlunsplit((scheme, parsed.netloc, parsed.path, "", ""))
    return sanitized_url


def _is_zip_entry_symlink_or_special(member: zipfile.ZipInfo) -> Tuple[bool, str]:
    """Detect symlink, hardlink/special POSIX file modes (FIFO, device, socket) in a ZIP entry."""
    unix_mode = (member.external_attr >> 16) & 0o170000
    if unix_mode == stat.S_IFLNK:
        return True, "symbolic link"
    if unix_mode in (stat.S_IFIFO, stat.S_IFCHR, stat.S_IFBLK, stat.S_IFSOCK):
        return True, "special filesystem node"
    # MS-DOS / NTFS reparse point attribute (0x0400 in lower 16 bits)
    if (member.external_attr & 0x0400) != 0 and member.create_system in (0, 10, 14):
        return True, "reparse point / symlink"
    return False, ""


def _normalize_and_validate_zip_member_path(raw_filename: str) -> Tuple[List[str], str]:
    """Safely normalize a ZIP member filename and reject traversal, absolute paths, and unsafe names."""
    if not raw_filename or "\0" in raw_filename:
        raise ValidationError("Archive contains entry with empty or illegal null byte in filename.")

    if any(ord(ch) < 32 for ch in raw_filename):
        raise ValidationError(f"Archive entry contains illegal control characters: {raw_filename!r}")

    # Convert Windows backslashes to forward slashes BEFORE checking traversal/absolute paths
    unified = raw_filename.replace("\\", "/")

    # Reject absolute Unix paths, UNC paths, and Windows drive-letter / NTFS ADS colon paths
    if unified.startswith("/") or re.match(r"^[a-zA-Z]:", unified) or ":" in unified:
        raise ValidationError(f"Archive entry contains illegal absolute path: {raw_filename}")

    raw_segments = unified.split("/")
    parts: List[str] = []
    for seg in raw_segments:
        if seg == "" or seg == ".":
            continue
        if seg == "..":
            raise ValidationError(f"Path traversal attempt detected in archive entry: {raw_filename}")
        if seg.endswith(".") or seg.endswith(" "):
            raise ValidationError(f"Archive entry contains unsafe trailing dot or space: {raw_filename}")
        base_part = seg.split(".", 1)[0].upper()
        if base_part in WINDOWS_RESERVED_NAMES:
            raise ValidationError(f"Archive entry contains reserved system name: {raw_filename}")
        parts.append(seg)

    normalized_key = "/".join(parts)
    return parts, normalized_key


def validate_and_extract_zip(zip_path: Path, dest_dir: Path) -> Tuple[int, int, str]:
    """Validate archive structure, prevent Zip Slip / path traversal / zip bombs, and extract safely.

    Security invariants:
    - Never trusts archive header sizes alone: streams in 64 KiB chunks and enforces actual bytes written.
    - Rejects path traversal (../, ..\\), absolute paths, Windows drive-letter paths, null bytes, and reserved names.
    - Rejects symlink and special-node entries.
    - Rejects duplicate normalized file entries.
    - Enforces MAX_FILE_COUNT, MAX_SINGLE_FILE_BYTES, MAX_EXTRACTED_SIZE_BYTES, MAX_COMPRESSION_RATIO,
      and MAX_NESTED_ARCHIVES.
    - Cleans up partially extracted files in dest_dir on any failure.

    Returns:
        (file_count, actual_total_bytes_written, language_metadata_string)
    """
    if not zip_path.exists() or zip_path.stat().st_size == 0:
        raise ValidationError("Uploaded archive is empty or does not exist.")

    # 1. Enforce upload size limit
    upload_size = zip_path.stat().st_size
    if upload_size > settings.MAX_UPLOAD_SIZE_BYTES:
        raise ValidationError(
            f"Archive size exceeds maximum allowed upload limit ({settings.MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)} MB)."
        )

    # 2. Check zip file magic header
    with open(zip_path, "rb") as f:
        magic = f.read(4)
        if magic not in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
            raise ValidationError("File is not a valid ZIP archive (invalid header signature).")

    if not zipfile.is_zipfile(zip_path):
        raise ValidationError("File failed ZIP integrity verification.")

    # 3. Clean and prepare destination directory
    dest_dir = dest_dir.resolve()
    if dest_dir.exists():
        shutil.rmtree(dest_dir, ignore_errors=True)
    dest_dir.mkdir(parents=True, exist_ok=True)

    extracted_files_count = 0
    actual_total_bytes = 0
    total_header_uncompressed = 0
    total_header_compressed = 0
    nested_archive_count = 0
    seen_file_keys: Set[str] = set()
    detected_languages: Counter = Counter()
    chunk_size = 64 * 1024  # 64 KiB bounded streaming chunks

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            infolist = zf.infolist()

            # Check total member count (headers)
            if len(infolist) > settings.MAX_FILE_COUNT:
                raise ValidationError(
                    f"Archive contains {len(infolist)} entries, exceeding the maximum allowed limit of {settings.MAX_FILE_COUNT} files."
                )

            # Fast pre-check on header metadata (actual byte accounting is ALSO enforced during streaming)
            for member in infolist:
                total_header_uncompressed += max(0, member.file_size)
                total_header_compressed += max(0, member.compress_size)

            if total_header_uncompressed > settings.MAX_EXTRACTED_SIZE_BYTES:
                raise ValidationError(
                    f"Uncompressed archive size ({total_header_uncompressed // (1024 * 1024)} MB) "
                    f"exceeds quota ({settings.MAX_EXTRACTED_SIZE_BYTES // (1024 * 1024)} MB)."
                )

            if total_header_compressed > 0:
                expansion_ratio = total_header_uncompressed / total_header_compressed
                if expansion_ratio > settings.MAX_COMPRESSION_RATIO:
                    raise ValidationError(
                        f"Suspicious compression ratio ({expansion_ratio:.1f}x) detected (potential Zip Bomb attack)."
                    )

            # 4. Safe bounded streaming extraction
            for member in infolist:
                raw_filename = member.filename

                # Reject encrypted entries cleanly
                if member.flag_bits & 0x1:
                    raise ValidationError(f"Encrypted ZIP archive entry is not supported: {raw_filename}")

                # Reject symbolic links & special POSIX nodes
                is_special, special_kind = _is_zip_entry_symlink_or_special(member)
                if is_special:
                    logger.warning(f"Rejected {special_kind} in ZIP archive: {raw_filename}")
                    raise SecurityPolicyViolationError(
                        f"Archive entry '{raw_filename}' is a prohibited {special_kind}."
                    )

                # Normalize and validate entry path
                parts, normalized_key = _normalize_and_validate_zip_member_path(raw_filename)
                if not parts:
                    continue

                # Directory entry
                if member.is_dir() or raw_filename.endswith("/") or raw_filename.endswith("\\"):
                    target_folder = (dest_dir / Path(*parts)).resolve()
                    if not target_folder.is_relative_to(dest_dir):
                        raise ValidationError(f"Extraction path escapes destination directory: {raw_filename}")
                    target_folder.mkdir(parents=True, exist_ok=True)
                    continue

                # Reject duplicate normalized file entries (case-insensitive for cross-platform safety)
                dedup_key = normalized_key.lower()
                if dedup_key in seen_file_keys:
                    raise ValidationError(
                        f"Archive contains duplicate file entry: '{normalized_key}'."
                    )
                seen_file_keys.add(dedup_key)

                # Target file destination with strict confinement
                target_file = (dest_dir / Path(*parts)).resolve()
                if not target_file.is_relative_to(dest_dir):
                    raise ValidationError(f"Extraction path escapes destination directory: {raw_filename}")

                suffix = target_file.suffix.lower()

                # Track nested archives and enforce nested archive limit
                if suffix in NESTED_ARCHIVE_EXTENSIONS:
                    nested_archive_count += 1
                    if nested_archive_count > settings.MAX_NESTED_ARCHIVES:
                        raise ValidationError(
                            f"Archive contains too many nested archive entries (limit: {settings.MAX_NESTED_ARCHIVES})."
                        )
                    logger.info(f"Skipping nested archive binary entry: {raw_filename}")
                    continue

                # Filter unwanted binary / executable files
                if suffix in EXCLUDED_EXTENSIONS:
                    logger.info(f"Skipping excluded binary file: {raw_filename}")
                    continue

                # Pre-check declared individual file size (reject oversized files)
                if member.file_size > settings.MAX_SINGLE_FILE_BYTES:
                    raise ValidationError(
                        f"Archive file '{normalized_key}' ({member.file_size} bytes) exceeds maximum single-file limit "
                        f"({settings.MAX_SINGLE_FILE_BYTES} bytes)."
                    )

                extracted_files_count += 1
                if extracted_files_count > settings.MAX_FILE_COUNT:
                    raise ValidationError(
                        f"Archive exceeds maximum allowed limit of {settings.MAX_FILE_COUNT} extracted files."
                    )

                # Ensure parent directories exist and verify no parent is a symlink
                target_file.parent.mkdir(parents=True, exist_ok=True)
                if _path_or_ancestors_contain_symlink(target_file):
                    raise SecurityPolicyViolationError(
                        f"Extraction target '{normalized_key}' traverses a symbolic link."
                    )

                # Stream file content in fixed chunks with strict actual-byte accounting
                file_bytes_written = 0
                with zf.open(member, "r") as source_stream, open(target_file, "wb") as dest_stream:
                    while True:
                        chunk = source_stream.read(chunk_size)
                        if not chunk:
                            break
                        chunk_len = len(chunk)
                        file_bytes_written += chunk_len
                        actual_total_bytes += chunk_len

                        if file_bytes_written > settings.MAX_SINGLE_FILE_BYTES:
                            raise ValidationError(
                                f"Archive file '{normalized_key}' exceeded maximum single-file size limit "
                                f"({settings.MAX_SINGLE_FILE_BYTES} bytes) during extraction."
                            )

                        if actual_total_bytes > settings.MAX_EXTRACTED_SIZE_BYTES:
                            raise ValidationError(
                                f"Cumulative extracted archive size exceeded quota "
                                f"({settings.MAX_EXTRACTED_SIZE_BYTES // (1024 * 1024)} MB) during extraction."
                            )

                        # Enforce actual compression ratio against zip-bomb forged headers
                        effective_compressed = max(total_header_compressed, upload_size, 1)
                        if (
                            actual_total_bytes > chunk_size
                            and (actual_total_bytes / effective_compressed) > settings.MAX_COMPRESSION_RATIO
                        ):
                            raise ValidationError(
                                "Suspicious actual expansion ratio detected during extraction (potential Zip Bomb attack)."
                            )

                        dest_stream.write(chunk)

                # Language metadata tracking
                if suffix in LANGUAGE_EXTENSIONS:
                    detected_languages[LANGUAGE_EXTENSIONS[suffix]] += 1

    except (zipfile.BadZipFile, zipfile.LargeZipFile, zlib.error, EOFError, RuntimeError) as exc:
        if dest_dir.exists():
            shutil.rmtree(dest_dir, ignore_errors=True)
        raise ValidationError(f"Malformed or corrupted ZIP archive: {exc}")
    except Exception:
        # Failure-safe cleanup: remove any partially extracted files on error
        if dest_dir.exists():
            shutil.rmtree(dest_dir, ignore_errors=True)
        raise

    # Format language metadata string (top 3 languages)
    top_languages = [lang for lang, _ in detected_languages.most_common(3)]
    language_metadata = ", ".join(top_languages) if top_languages else "Generic Code"

    return extracted_files_count, actual_total_bytes, language_metadata


def collect_directory_metadata(directory: Path) -> Tuple[int, int, str]:
    """Scan an ingested directory for file count, size, and languages."""
    total_files = 0
    total_bytes = 0
    language_counts: Counter = Counter()

    for root, _, files in os.walk(directory):
        for file in files:
            file_path = Path(root) / file
            if file_path.is_symlink():
                continue
            suffix = file_path.suffix.lower()
            if suffix in EXCLUDED_EXTENSIONS:
                continue

            try:
                size = file_path.stat().st_size
                total_bytes += size
                total_files += 1
                if suffix in LANGUAGE_EXTENSIONS:
                    language_counts[LANGUAGE_EXTENSIONS[suffix]] += 1
            except OSError:
                pass

    top_languages = [lang for lang, _ in language_counts.most_common(3)]
    language_metadata = ", ".join(top_languages) if top_languages else "Generic Code"

    return total_files, total_bytes, language_metadata


def _path_or_ancestors_contain_symlink(raw_path: Path) -> bool:
    """Inspect a path and its existing ancestors for symlinks BEFORE calling resolve()."""
    candidate = raw_path if raw_path.is_absolute() else (Path.cwd() / raw_path)
    # Normalize lexical '.' without resolving symlinks or '..'
    current = candidate
    checked = set()
    while True:
        key = str(current)
        if key in checked:
            break
        checked.add(key)
        try:
            if current.is_symlink():
                return True
        except OSError:
            return True
        parent = current.parent
        if parent == current:
            break
        current = parent
    return False


def validate_local_ingest_path(local_path: str, user_id: str) -> Path:
    """Validate and confine local directory paths for ingestion.

    Enforces:
    1. Disabled in production by default unless ALLOW_LOCAL_INGESTION_IN_PRODUCTION=True
       with an explicit non-empty LOCAL_INGESTION_ALLOWED_ROOTS allowlist.
    2. Rejects empty, null-byte, or malformed path strings.
    3. Rejects symlinks BEFORE resolving paths (both target and ancestor components).
    4. Cross-Tenant Confinement via Path.is_relative_to() (immune to prefix collisions).
    5. Host Root Protection: Rejects filesystem roots and sensitive OS directories.
    6. Explicit Allowlist Confinement when LOCAL_INGESTION_ALLOWED_ROOTS is configured.
    """
    if not local_path or not isinstance(local_path, str) or "\0" in local_path:
        raise ValidationError("Local repository path must be a valid, non-empty directory path.")

    allowed_roots_raw = (
        settings.LOCAL_INGESTION_ALLOWED_ROOTS
        if isinstance(settings.LOCAL_INGESTION_ALLOWED_ROOTS, list)
        else [settings.LOCAL_INGESTION_ALLOWED_ROOTS]
    )
    allowed_roots = [str(r).strip() for r in allowed_roots_raw if str(r).strip()]

    # 1. Production & staging lockdown (disabled by default)
    if settings.is_strict_env:
        if not settings.ALLOW_LOCAL_INGESTION_IN_PRODUCTION or not allowed_roots:
            logger.warning(
                f"Local filesystem ingestion blocked in {settings.APP_ENV} for actor '{user_id}'"
            )
            raise SecurityPolicyViolationError(
                "Local filesystem ingestion is disabled in production environments. Use ZIP upload or Git ingestion."
            )

    raw_path = Path(local_path)

    # 2. Symlink defense BEFORE resolve()
    if _path_or_ancestors_contain_symlink(raw_path):
        logger.warning(f"Symlink local ingestion attempt blocked for actor '{user_id}': '{local_path}'")
        raise SecurityPolicyViolationError("Local directory path cannot be or traverse a symbolic link.")

    # Reject explicit parent traversal segments before resolution
    if ".." in raw_path.parts:
        raise SecurityPolicyViolationError("Directory traversal segments ('..') are prohibited in local ingestion paths.")

    target_dir = raw_path.resolve(strict=False)
    if not target_dir.exists() or not target_dir.is_dir():
        raise ValidationError(f"Directory path does not exist or is not a directory: {local_path}")

    # 3. Cross-Tenant Confinement Check using Path.is_relative_to()
    workspace_root = get_workspace_root().resolve()
    safe_user = re.sub(r"[^a-zA-Z0-9_\-]", "", user_id)
    user_allowed_workspace = (workspace_root / safe_user).resolve()

    if target_dir.is_relative_to(workspace_root):
        if not target_dir.is_relative_to(user_allowed_workspace):
            logger.warning(
                f"Cross-tenant directory traversal blocked: actor '{user_id}' attempted to ingest '{target_dir}'"
            )
            raise SecurityPolicyViolationError(
                "Access denied: Local path references another tenant's workspace or restricted area."
            )

    # 4. Disallow filesystem roots and sensitive operating system directories
    if target_dir.parent == target_dir or target_dir == Path(target_dir.anchor):
        raise SecurityPolicyViolationError("Access denied: System root directories cannot be ingested.")

    target_str = str(target_dir).lower() if os.name == "nt" else str(target_dir)
    norm_target = target_str.rstrip("\\/")
    forbidden_prefixes = {
        "c:\\windows", "c:/windows", "c:\\program files", "c:/program files",
        "c:\\program files (x86)", "c:/program files (x86)",
        "/etc", "/proc", "/sys", "/root", "/var", "/dev", "/boot", "/run",
    }
    if any(
        norm_target == fp or norm_target.startswith(fp + "\\") or norm_target.startswith(fp + "/")
        for fp in forbidden_prefixes
    ):
        raise SecurityPolicyViolationError("Access denied: Restricted system directory cannot be ingested.")

    # 5. Explicit allowlist enforcement (mandatory in production; enforced whenever configured)
    if allowed_roots:
        resolved_roots: List[Path] = []
        for root_entry in allowed_roots:
            root_path = Path(root_entry)
            if not _path_or_ancestors_contain_symlink(root_path):
                resolved_roots.append(root_path.resolve(strict=False))

        if not any(target_dir.is_relative_to(root) for root in resolved_roots):
            logger.warning(
                f"Local ingestion outside authorized roots blocked for actor '{user_id}': '{target_dir}'"
            )
            raise SecurityPolicyViolationError(
                "Access denied: Local path is outside explicitly authorized ingestion roots."
            )

    return target_dir


LOCAL_INGEST_IGNORED_DIRS: Set[str] = {
    ".git", "node_modules", "__pycache__", ".pytest_cache", "venv", ".venv",
}


def copy_local_directory_safely(local_dir: Path, workspace_dir: Path) -> Tuple[int, int, str]:
    """Copy a validated local directory into an isolated workspace without dereferencing symlinks.

    Enforces:
    - Zero symlink dereferencing: rejects any symlinked file or directory encountered.
    - Maximum file count (settings.MAX_FILE_COUNT).
    - Maximum single file size (settings.MAX_SINGLE_FILE_BYTES).
    - Maximum cumulative copied size (settings.MAX_EXTRACTED_SIZE_BYTES).
    - Strict destination confinement inside workspace_dir.
    """
    resolved_source = local_dir.resolve()
    resolved_dest = workspace_dir.resolve()

    if resolved_dest.exists():
        shutil.rmtree(resolved_dest, ignore_errors=True)
    resolved_dest.mkdir(parents=True, exist_ok=True)

    file_count = 0
    total_bytes = 0
    detected_languages: Counter = Counter()
    chunk_size = 64 * 1024  # 64 KiB bounded stream chunks

    try:
        for current_root, dirs, files in os.walk(resolved_source, topdown=True, followlinks=False):
            current_root_path = Path(current_root)

            # Filter ignored directories and reject any symlinked subdirectories
            kept_dirs: List[str] = []
            for dname in dirs:
                if dname in LOCAL_INGEST_IGNORED_DIRS:
                    continue
                dpath = current_root_path / dname
                if dpath.is_symlink():
                    raise SecurityPolicyViolationError(
                        f"Symbolic link directory detected during local ingestion: '{dname}'. Symlinks are prohibited."
                    )
                kept_dirs.append(dname)
            dirs[:] = kept_dirs

            rel_root = current_root_path.relative_to(resolved_source)
            dest_subdir = (resolved_dest / rel_root).resolve()
            if not dest_subdir.is_relative_to(resolved_dest):
                raise SecurityPolicyViolationError("Local ingestion destination escapes isolated workspace.")
            dest_subdir.mkdir(parents=True, exist_ok=True)

            for fname in files:
                src_file = current_root_path / fname
                if src_file.is_symlink():
                    raise SecurityPolicyViolationError(
                        f"Symbolic link file detected during local ingestion: '{fname}'. Symlinks are prohibited."
                    )

                suffix = src_file.suffix.lower()
                if suffix in EXCLUDED_EXTENSIONS:
                    continue

                file_count += 1
                if file_count > settings.MAX_FILE_COUNT:
                    raise ValidationError(
                        f"Local directory exceeds maximum allowed limit of {settings.MAX_FILE_COUNT} files."
                    )

                try:
                    st = src_file.lstat()
                except OSError as exc:
                    raise ValidationError(f"Unable to read file metadata for '{fname}': {exc}")

                if st.st_size > settings.MAX_SINGLE_FILE_BYTES:
                    raise ValidationError(
                        f"File '{fname}' ({st.st_size} bytes) exceeds maximum single-file limit "
                        f"({settings.MAX_SINGLE_FILE_BYTES} bytes)."
                    )

                if total_bytes + st.st_size > settings.MAX_EXTRACTED_SIZE_BYTES:
                    raise ValidationError(
                        f"Local directory size exceeds maximum workspace quota "
                        f"({settings.MAX_EXTRACTED_SIZE_BYTES // (1024 * 1024)} MB)."
                    )

                dest_file = (dest_subdir / fname).resolve()
                if not dest_file.is_relative_to(resolved_dest):
                    raise SecurityPolicyViolationError("Local ingestion file destination escapes isolated workspace.")

                copied_for_file = 0
                with open(src_file, "rb") as src_stream, open(dest_file, "wb") as dst_stream:
                    while True:
                        chunk = src_stream.read(chunk_size)
                        if not chunk:
                            break
                        copied_for_file += len(chunk)
                        total_bytes += len(chunk)
                        if copied_for_file > settings.MAX_SINGLE_FILE_BYTES:
                            raise ValidationError(
                                f"File '{fname}' exceeded maximum single-file size limit during copy."
                            )
                        if total_bytes > settings.MAX_EXTRACTED_SIZE_BYTES:
                            raise ValidationError(
                                f"Local directory exceeded maximum workspace size quota "
                                f"({settings.MAX_EXTRACTED_SIZE_BYTES // (1024 * 1024)} MB) during copy."
                            )
                        dst_stream.write(chunk)

                if suffix in LANGUAGE_EXTENSIONS:
                    detected_languages[LANGUAGE_EXTENSIONS[suffix]] += 1

    except Exception:
        if resolved_dest.exists():
            shutil.rmtree(resolved_dest, ignore_errors=True)
        raise

    top_languages = [lang for lang, _ in detected_languages.most_common(3)]
    language_metadata = ", ".join(top_languages) if top_languages else "Generic Code"
    return file_count, total_bytes, language_metadata


def validate_git_egress_proxy_url(
    proxy_url: Optional[str],
    allow_private_proxy: Optional[bool] = None,
) -> str:
    """Validate GIT_EGRESS_PROXY_URL for fail-closed Git egress protection (Phase 5 / SEC-06).

    Enforces:
    - Non-empty string with no whitespace, control characters, or null bytes.
    - Scheme strictly 'http' or 'https'.
    - No embedded username or password credentials.
    - Explicit hostname and valid integer port (1..65535).
    - Rejects loopback, link-local, cloud metadata (169.254.169.254), CGNAT, and private RFC1918
      destinations unless allow_private_proxy is True AND the host is an explicitly approved
      internal proxy service name (never loopback/link-local/metadata).
    """
    if not proxy_url or not isinstance(proxy_url, str) or not proxy_url.strip():
        raise ValidationError("GIT_EGRESS_PROXY_URL must be a non-empty proxy URL.")

    cleaned = proxy_url.strip()
    if "\0" in cleaned or any(ord(ch) <= 32 for ch in cleaned):
        raise ValidationError("Invalid GIT_EGRESS_PROXY_URL: contains control or whitespace characters.")

    parsed = urllib.parse.urlsplit(cleaned)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise ValidationError(
            f"Invalid GIT_EGRESS_PROXY_URL scheme '{scheme or 'none'}'. Only 'http' or 'https' proxies are supported."
        )

    if parsed.username or parsed.password or "@" in (parsed.netloc or ""):
        raise SecurityPolicyViolationError(
            "Embedding credentials in GIT_EGRESS_PROXY_URL is strictly prohibited."
        )

    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValidationError("GIT_EGRESS_PROXY_URL must not contain path segments, query parameters, or fragments.")

    hostname = (parsed.hostname or "").strip().rstrip(".").lower()
    if not hostname:
        raise ValidationError("Invalid GIT_EGRESS_PROXY_URL: missing proxy hostname.")

    try:
        port = parsed.port
    except ValueError:
        raise ValidationError("Invalid GIT_EGRESS_PROXY_URL: malformed proxy port.")
    if port is None or port < 1 or port > 65535:
        raise ValidationError("Invalid GIT_EGRESS_PROXY_URL: an explicit port (1..65535) is required.")

    # Always block loopback, link-local, and cloud metadata endpoints unconditionally
    always_forbidden_hosts = {
        "localhost",
        "localhost.localdomain",
        "127.0.0.1",
        "::1",
        "::",
        "0.0.0.0",  # nosec B104 - SSRF blocklist entry, not a socket bind
        "169.254.169.254",
        "169.254.170.2",
        "fd00:ec2::254",
        "metadata.google.internal",
        "metadata.goog",
        "metadata",
        "instance-data",
    }
    if hostname in always_forbidden_hosts or hostname.endswith(".localhost"):
        raise SecurityPolicyViolationError(
            f"GIT_EGRESS_PROXY_URL destination '{hostname}' is prohibited (loopback/metadata protection)."
        )

    permit_private = (
        getattr(settings, "ALLOW_PRIVATE_GIT_EGRESS_PROXY", False)
        if allow_private_proxy is None
        else allow_private_proxy
    )
    approved_raw = getattr(settings, "APPROVED_GIT_EGRESS_PROXY_HOSTS", ["egress-proxy", "smokescreen"])
    if isinstance(approved_raw, str):
        approved_hosts = {h.strip().lower() for h in approved_raw.split(",") if h.strip()}
    else:
        approved_hosts = {str(h).strip().lower() for h in approved_raw if str(h).strip()}

    # Check IP literal
    try:
        ip_obj = ipaddress.ip_address(hostname.split("%", 1)[0])
        # Unwrap IPv4-mapped IPv6
        check_ip = ip_obj.ipv4_mapped if (isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped) else ip_obj
        if (
            check_ip.is_loopback
            or check_ip.is_link_local
            or check_ip.is_unspecified
            or check_ip.is_multicast
            or str(check_ip) in _EXPLICIT_BLOCKED_IPS
        ):
            raise SecurityPolicyViolationError(
                f"GIT_EGRESS_PROXY_URL IP '{hostname}' is prohibited (loopback/link-local/metadata)."
            )
        if is_ip_blocked(hostname) and not (permit_private and hostname in approved_hosts):
            raise SecurityPolicyViolationError(
                f"GIT_EGRESS_PROXY_URL IP '{hostname}' is in a restricted private/reserved network range."
            )
    except ValueError:
        # Hostname (not an IP literal)
        if "." not in hostname or hostname.endswith((".local", ".internal", ".home.arpa")):
            if not (permit_private and hostname in approved_hosts):
                raise SecurityPolicyViolationError(
                    f"GIT_EGRESS_PROXY_URL internal hostname '{hostname}' is not permitted unless explicitly approved."
                )

    return f"{scheme}://{parsed.netloc}"


def resolve_required_git_egress_proxy() -> Optional[str]:
    """Resolve and validate GIT_EGRESS_PROXY_URL, enforcing fail-closed behavior in strict environments."""
    raw_proxy = (getattr(settings, "GIT_EGRESS_PROXY_URL", None) or "").strip()
    if not raw_proxy:
        if settings.is_strict_env:
            raise SecurityPolicyViolationError(
                "Public Git repository ingestion is disabled in production and staging environments unless "
                "a validated SSRF-filtering GIT_EGRESS_PROXY_URL is configured (fail-closed SSRF egress policy)."
            )
        return None

    return validate_git_egress_proxy_url(raw_proxy)


def verify_artifact_sha256(artifact_path: Path, expected_sha256: Optional[str]) -> str:
    """Verify a downloaded supply-chain artifact against a trusted pinned SHA-256 digest (Phase 5 / SEC-20).

    Fails closed if expected_sha256 is missing/malformed or if the computed digest does not match.
    """
    import hashlib
    import hmac

    if not expected_sha256 or not isinstance(expected_sha256, str):
        raise ValidationError("Supply-chain verification failed: expected SHA-256 checksum is missing.")

    cleaned_expected = expected_sha256.strip().lower()
    if not re.match(r"^[0-9a-f]{64}$", cleaned_expected):
        raise ValidationError("Supply-chain verification failed: expected SHA-256 checksum is not a valid 64-char hex digest.")

    if not artifact_path or not artifact_path.exists() or not artifact_path.is_file():
        raise ValidationError(f"Supply-chain verification failed: artifact '{artifact_path}' does not exist.")

    hasher = hashlib.sha256()
    with open(artifact_path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            hasher.update(chunk)

    actual_digest = hasher.hexdigest().lower()
    if not hmac.compare_digest(actual_digest, cleaned_expected):
        raise SecurityPolicyViolationError(
            f"Supply-chain SHA-256 checksum mismatch for '{artifact_path.name}': "
            f"expected {cleaned_expected}, got {actual_digest}."
        )
    return actual_digest


def _build_sanitized_git_env(
    allow_private: bool = False,
    egress_proxy_url: Optional[str] = None,
) -> Dict[str, str]:
    """Construct a minimal, hardened environment for git subprocess execution.

    Strips dangerous Git hooks/SSH/proxy/config overrides and locks GIT_ALLOW_PROTOCOL.
    """
    blocked_keys = {
        "GIT_SSH",
        "GIT_SSH_COMMAND",
        "GIT_PROXY_COMMAND",
        "GIT_EXEC_PATH",
        "GIT_TEMPLATE_DIR",
        "GIT_EXTERNAL_DIFF",
        "GIT_ASKPASS",
        "SSH_ASKPASS",
        "GIT_CONFIG",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_SYSTEM",
        "GIT_CONFIG_GLOBAL",
        "GIT_PROTOCOL_FROM_USER",
        "GIT_ALLOW_PROTOCOL",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    }
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in blocked_keys
        and not k.startswith("GIT_CONFIG_KEY_")
        and not k.startswith("GIT_CONFIG_VALUE_")
    }
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_ALLOW_PROTOCOL"] = "https:http" if allow_private else "https"
    return env


def _terminate_subprocess_tree(proc: subprocess.Popen) -> None:
    """Reliably terminate a subprocess and all its children (e.g. git-remote-https)."""
    if proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/pid", str(proc.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            )
        else:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                proc.kill()
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    try:
        proc.wait(timeout=5)
    except Exception:
        pass


def _run_git_command(
    cmd: List[str],
    cwd: Path,
    env: Dict[str, str],
    timeout: int,
) -> subprocess.CompletedProcess:
    """Execute a git command with shell=False, explicit cwd, and reliable tree termination on timeout."""
    popen_kwargs: Dict[str, object] = {
        "cwd": str(cwd),
        "env": env,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "shell": False,
    }
    if os.name != "nt":
        popen_kwargs["start_new_session"] = True

    proc = subprocess.Popen(cmd, **popen_kwargs)
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        return subprocess.CompletedProcess(args=cmd, returncode=proc.returncode, stdout=stdout, stderr=stderr)
    except subprocess.TimeoutExpired:
        _terminate_subprocess_tree(proc)
        raise


def _enforce_cloned_directory_limits(dest_dir: Path) -> Tuple[int, int, str]:
    """Validate cloned repository contents: reject symlinks and enforce file-count & size quotas."""
    resolved_dest = dest_dir.resolve()
    total_files = 0
    total_bytes = 0
    language_counts: Counter = Counter()

    for root, dirs, files in os.walk(resolved_dest, topdown=True, followlinks=False):
        root_path = Path(root)
        for dname in list(dirs):
            dpath = root_path / dname
            if dpath.is_symlink():
                raise SecurityPolicyViolationError(
                    f"Cloned repository contains prohibited symbolic link directory: '{dname}'."
                )

        for fname in files:
            fpath = root_path / fname
            if fpath.is_symlink():
                raise SecurityPolicyViolationError(
                    f"Cloned repository contains prohibited symbolic link file: '{fname}'."
                )

            suffix = fpath.suffix.lower()
            if suffix in EXCLUDED_EXTENSIONS:
                try:
                    fpath.unlink(missing_ok=True)
                except OSError:
                    pass
                continue

            total_files += 1
            if total_files > settings.MAX_FILE_COUNT:
                raise ValidationError(
                    f"Cloned repository exceeds maximum allowed limit of {settings.MAX_FILE_COUNT} files."
                )

            try:
                fsize = fpath.lstat().st_size
            except OSError as exc:
                raise ValidationError(f"Unable to inspect cloned file '{fname}': {exc}")

            if fsize > settings.MAX_SINGLE_FILE_BYTES:
                raise ValidationError(
                    f"Cloned file '{fname}' ({fsize} bytes) exceeds maximum single-file limit "
                    f"({settings.MAX_SINGLE_FILE_BYTES} bytes)."
                )

            total_bytes += fsize
            if total_bytes > settings.MAX_EXTRACTED_SIZE_BYTES:
                raise ValidationError(
                    f"Cloned repository size exceeds maximum workspace quota "
                    f"({settings.MAX_EXTRACTED_SIZE_BYTES // (1024 * 1024)} MB)."
                )

            if suffix in LANGUAGE_EXTENSIONS:
                language_counts[LANGUAGE_EXTENSIONS[suffix]] += 1

    top_languages = [lang for lang, _ in language_counts.most_common(3)]
    language_metadata = ", ".join(top_languages) if top_languages else "Generic Code"
    return total_files, total_bytes, language_metadata


def clone_git_repository(
    git_url: str,
    dest_dir: Path,
    branch: str = "main",
    timeout: int = 60,
    allow_private: bool = False,
) -> Tuple[int, int, str, str]:
    """Safely clone a public Git repository into an isolated directory with SSRF and subprocess hardening.

    Security controls:
    - Re-validates URL scheme, hostname, and all resolved IPv4/IPv6 addresses immediately before clone.
    - Enforces valid Git security options: core.hooksPath=devnull, protocol.file.allow=never,
      protocol.allow=never, protocol.https.allow=always, http.followRedirects=false,
      core.symlinks=false, submodule.recurse=false, --no-recurse-submodules.
    - Uses sanitized environment (GIT_ALLOW_PROTOCOL, GIT_CONFIG_NOSYSTEM, stripped SSH/proxy overrides).
    - Supports optional deployment-level SSRF-filtering egress proxy via GIT_EGRESS_PROXY_URL (-c http.proxy).
    - Executes with shell=False, explicit cwd, and reliable process-tree termination on timeout.
    - Enforces post-clone symlink rejection and file-count/size quotas; cleans up dest_dir on any failure.

    Deployment note: Application-level DNS validation + disabled redirects mitigate most SSRF vectors,
    but complete protection against connection-time DNS rebinding requires network-level egress
    isolation (firewall/NetworkPolicy or SSRF-filtering proxy via GIT_EGRESS_PROXY_URL).
    """
    dest_dir = dest_dir.resolve()
    if dest_dir.exists():
        shutil.rmtree(dest_dir, ignore_errors=True)
    dest_dir.parent.mkdir(parents=True, exist_ok=True)

    # Validate branch name to prevent git option/flag injection
    branch_name = branch.strip()
    git_branch_regex = re.compile(r"^[a-zA-Z0-9_\-\./]+$")
    if not branch_name or not git_branch_regex.match(branch_name) or branch_name.startswith("-") or ".." in branch_name:
        raise ValidationError(
            f"Invalid git branch name: '{branch}'. Branch names must not start with hyphens or contain path traversal/shell characters."
        )

    # Enforce fail-closed Git egress proxy policy before any DNS or subprocess call (Phase 5 / SEC-06)
    validated_egress_proxy = resolve_required_git_egress_proxy()

    # Re-validate URL and DNS resolution at execution time (reduces TOCTOU window)
    sanitized_url = validate_git_url(
        git_url,
        allow_private=allow_private,
        allow_proxy_dns_resolution=bool(validated_egress_proxy),
    )

    # Build strictly valid Git security flags (no invalid -c http.resolve)
    cmd = [
        "git",
        "-c", f"core.hooksPath={os.devnull}",
        "-c", "core.symlinks=false",
        "-c", "protocol.file.allow=never",
        "-c", "protocol.allow=never",
        "-c", "protocol.https.allow=always",
        "-c", "http.followRedirects=false",
        "-c", "submodule.recurse=false",
    ]
    if allow_private:
        cmd.extend(["-c", "protocol.http.allow=always"])

    if validated_egress_proxy:
        cmd.extend([
            "-c", f"http.proxy={validated_egress_proxy}",
            "-c", f"https.proxy={validated_egress_proxy}",
        ])
    else:
        # Pin the validated resolved IP address(es) into libcurl via http.curloptResolve
        # to eliminate connection-time DNS rebinding between Python validation and git clone
        try:
            parsed_git = urllib.parse.urlsplit(sanitized_url)
            git_host = (parsed_git.hostname or "").strip().rstrip(".").lower()
            git_port = parsed_git.port or (443 if (parsed_git.scheme or "https").lower() == "https" else 80)
            if git_host:
                addr_infos = socket.getaddrinfo(git_host, git_port, proto=socket.IPPROTO_TCP)
                pinned_ips: List[str] = []
                for info in addr_infos:
                    raw_ip = str(info[4][0]).split("%", 1)[0]
                    if not allow_private and is_ip_blocked(raw_ip):
                        raise SecurityPolicyViolationError(
                            f"DNS rebinding defense blocked resolved IP '{raw_ip}' for host '{git_host}'."
                        )
                    if raw_ip not in pinned_ips:
                        pinned_ips.append(raw_ip)
                if pinned_ips:
                    cmd.extend(["-c", f"http.curloptResolve={git_host}:{git_port}:{','.join(pinned_ips)}"])
        except SecurityPolicyViolationError:
            raise
        except Exception:
            pass

    cmd.extend([
        "clone",
        "--depth", "1",
        "--no-recurse-submodules",
        "--branch", branch_name,
        "--single-branch",
        "--",
        sanitized_url,
        str(dest_dir),
    ])

    git_env = _build_sanitized_git_env(
        allow_private=allow_private,
        egress_proxy_url=validated_egress_proxy,
    )

    import time as _time
    deadline = _time.monotonic() + max(1, int(timeout))

    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
        result = _run_git_command(cmd=cmd, cwd=dest_dir.parent, env=git_env, timeout=timeout)

        if result.returncode != 0:
            stderr_msg = (result.stderr or "").strip()
            # If specified branch was not found upstream (e.g., master vs main), fallback to default branch
            # while bounding total wall-clock duration within the original timeout budget
            if "not found in upstream origin" in stderr_msg.lower() or "remote branch" in stderr_msg.lower():
                remaining = int(deadline - _time.monotonic())
                if remaining >= 2:
                    logger.info(f"Branch '{branch_name}' not found upstream. Retrying clone with upstream default branch...")
                    if dest_dir.exists():
                        shutil.rmtree(dest_dir, ignore_errors=True)
                    dest_dir.mkdir(parents=True, exist_ok=True)

                    fallback_cmd = []
                    skip_next = False
                    for token in cmd:
                        if skip_next:
                            skip_next = False
                            continue
                        if token == "--branch":
                            skip_next = True
                            continue
                        fallback_cmd.append(token)

                    result = _run_git_command(cmd=fallback_cmd, cwd=dest_dir.parent, env=git_env, timeout=remaining)

        if result.returncode != 0:
            stderr_msg = (result.stderr or "").strip()
            safe_err = re.sub(r"https?://[^@\s]+@", "https://", stderr_msg)
            raise ValidationError(f"Git clone failed: {safe_err or 'Repository not found or branch does not exist.'}")

        actual_branch = branch_name
        dot_git = dest_dir / ".git"
        if dot_git.exists():
            try:
                head_proc = _run_git_command(
                    cmd=["git", "rev-parse", "--abbrev-ref", "HEAD"],
                    cwd=dest_dir,
                    env=git_env,
                    timeout=5,
                )
                if head_proc.returncode == 0 and (head_proc.stdout or "").strip():
                    detected = head_proc.stdout.strip()
                    if detected and detected != "HEAD":
                        actual_branch = detected
            except Exception:
                pass

            # Remove .git directory to save space and strip any hooks/config
            shutil.rmtree(dot_git, ignore_errors=True)

        file_count, total_bytes, language_metadata = _enforce_cloned_directory_limits(dest_dir)
        return (file_count, total_bytes, language_metadata, actual_branch)

    except subprocess.TimeoutExpired:
        if dest_dir.exists():
            shutil.rmtree(dest_dir, ignore_errors=True)
        raise ValidationError(f"Git clone operation timed out after {timeout} seconds.")
    except FileNotFoundError:
        if dest_dir.exists():
            shutil.rmtree(dest_dir, ignore_errors=True)
        raise ValidationError("Git executable is not installed or available on the host system.")
    except Exception:
        if dest_dir.exists():
            shutil.rmtree(dest_dir, ignore_errors=True)
        raise
