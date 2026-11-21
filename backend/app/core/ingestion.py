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
import socket
import subprocess
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import urllib.parse
import zipfile

from .config import settings
from .errors import SecurityPolicyViolationError, ValidationError
from .logging import get_logger

logger = get_logger("redmercury.ingestion")

# Excluded binary and executable file extensions to prevent malware staging
EXCLUDED_EXTENSIONS: Set[str] = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".iso", ".img",
    ".tar", ".gz", ".zip", ".7z", ".rar", ".bz2", ".xz",
    ".pyc", ".pyo", ".pyd", ".class", ".jar", ".war", ".ear",
    ".node", ".obj", ".o", ".a", ".lib", ".ko", ".sys",
    ".msi", ".com", ".scr", ".bat", ".cmd", ".vbs", ".ps1",
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

    # Enforce confinement within base workspace
    if not str(repo_dir).startswith(str(base.resolve())):
        raise SecurityPolicyViolationError("Workspace path resolves outside designated root directory.")

    return repo_dir


def is_ip_blocked(ip_str: str) -> bool:
    """Check if an IP address belongs to loopback, private, link-local, or cloud metadata ranges."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return True
        # Explicit check for AWS/GCP/Azure link-local metadata address
        if str(ip) == "169.254.169.254" or str(ip) == "fd00:ec2::254":
            return True
        return False
    except ValueError:
        return True


def validate_git_url(url: str, allow_private: bool = False) -> str:
    """Strictly validate Git clone URL to prevent SSRF and protocol smuggling."""
    if not url or not isinstance(url, str):
        raise ValidationError("Git repository URL must be a non-empty string.")

    cleaned_url = url.strip()

    # Protocol check: strictly HTTPS (HTTP only permitted when allow_private is explicitly enabled)
    parsed = urllib.parse.urlsplit(cleaned_url)
    if parsed.scheme.lower() != "https" and not (allow_private and parsed.scheme.lower() == "http"):
        raise SecurityPolicyViolationError(
            f"Unsupported Git protocol '{parsed.scheme}'. Only secure HTTPS repositories are supported."
        )

    # Disallow embedding credentials in URL (e.g., https://user:pass@host/repo)
    if parsed.username or parsed.password:
        raise ValidationError("Embedding user credentials or tokens directly in repository URLs is prohibited.")

    hostname = parsed.hostname
    if not hostname:
        raise ValidationError("Invalid repository URL: missing hostname.")

    # Block localhost and all-interface strings by name
    if hostname.lower() in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "metadata.google.internal"):  # nosec B104
        if not allow_private:
            raise SecurityPolicyViolationError(f"Target host '{hostname}' is not permitted (SSRF protection).")

    # Resolve all DNS addresses and check each one
    if not allow_private:
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
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
            raise ValidationError(f"DNS resolution failed for repository host '{hostname}': {str(e)}")

    # Return sanitized URL (without query parameters or fragments)
    sanitized_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
    return sanitized_url


def validate_and_extract_zip(zip_path: Path, dest_dir: Path) -> Tuple[int, int, str]:
    """Validate archive structure, prevent Zip Slip / path traversal, and extract safely.

    Returns:
        (file_count, total_size_bytes, language_metadata_string)
    """
    if not zip_path.exists() or zip_path.stat().st_size == 0:
        raise ValidationError("Uploaded archive is empty or does not exist.")

    # 1. Enforce upload size limit
    if zip_path.stat().st_size > settings.MAX_UPLOAD_SIZE_BYTES:
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
    total_uncompressed_bytes = 0
    total_compressed_bytes = 0
    detected_languages: Counter = Counter()

    with zipfile.ZipFile(zip_path, "r") as zf:
        infolist = zf.infolist()

        # Check total member count
        if len(infolist) > settings.MAX_FILE_COUNT:
            raise ValidationError(
                f"Archive contains {len(infolist)} entries, exceeding the maximum allowed limit of {settings.MAX_FILE_COUNT} files."
            )

        # Check total expansion size and compression ratio (Zip Bomb defense)
        for member in infolist:
            total_uncompressed_bytes += member.file_size
            total_compressed_bytes += member.compress_size

        if total_uncompressed_bytes > settings.MAX_EXTRACTED_SIZE_BYTES:
            raise ValidationError(
                f"Uncompressed archive size ({total_uncompressed_bytes // (1024 * 1024)} MB) "
                f"exceeds quota ({settings.MAX_EXTRACTED_SIZE_BYTES // (1024 * 1024)} MB)."
            )

        if total_compressed_bytes > 0:
            expansion_ratio = total_uncompressed_bytes / total_compressed_bytes
            if expansion_ratio > settings.MAX_COMPRESSION_RATIO:
                raise ValidationError(
                    f"Suspicious compression ratio ({expansion_ratio:.1f}x) detected (potential Zip Bomb attack)."
                )

        # 4. Safe entry extraction
        for member in infolist:
            raw_filename = member.filename

            # Null byte check
            if "\0" in raw_filename:
                raise ValidationError("Archive contains entry with illegal null byte in filename.")

            # Path normalization
            normalized_name = os.path.normpath(raw_filename).replace("\\", "/")

            # Reject absolute paths
            if (
                normalized_name.startswith("/")
                or normalized_name.startswith("\\")
                or re.match(r"^[a-zA-Z]:", normalized_name)
            ):
                raise ValidationError(f"Archive entry contains illegal absolute path: {raw_filename}")

            # Reject path traversal (Zip Slip vulnerability)
            parts = [p for p in normalized_name.split("/") if p and p != "."]
            if ".." in parts:
                raise ValidationError(f"Path traversal attempt detected in archive entry: {raw_filename}")

            # Check for Windows device names in components
            for part in parts:
                base_part = part.split(".")[0].upper()
                if base_part in WINDOWS_RESERVED_NAMES:
                    raise ValidationError(f"Archive entry contains reserved system name: {raw_filename}")

            # Check for symbolic links (do not follow or extract symlinks)
            is_symlink = (member.external_attr >> 16) & 0o170000 == 0o120000
            if is_symlink:
                logger.info(f"Skipping symbolic link in archive for security: {raw_filename}")
                continue

            # Directory entry
            if member.is_dir():
                target_folder = (dest_dir / "/".join(parts)).resolve()
                try:
                    target_folder.relative_to(dest_dir)
                except ValueError:
                    raise ValidationError(f"Extraction path escapes destination directory: {raw_filename}")
                target_folder.mkdir(parents=True, exist_ok=True)
                continue

            # Target file destination
            target_file = (dest_dir / "/".join(parts)).resolve()
            try:
                target_file.relative_to(dest_dir)
            except ValueError:
                raise ValidationError(f"Extraction path escapes destination directory: {raw_filename}")

            # Check individual file size limit
            if member.file_size > settings.MAX_SINGLE_FILE_BYTES:
                logger.info(f"Skipping oversized file in archive: {raw_filename} ({member.file_size} bytes)")
                continue

            # Filter unwanted binary / executable files
            suffix = target_file.suffix.lower()
            if suffix in EXCLUDED_EXTENSIONS:
                logger.info(f"Skipping excluded binary file: {raw_filename}")
                continue

            # Ensure parent directories exist
            target_file.parent.mkdir(parents=True, exist_ok=True)

            # Safely write file content
            with zf.open(member) as source_stream, open(target_file, "wb") as dest_stream:
                shutil.copyfileobj(source_stream, dest_stream)

            extracted_files_count += 1

            # Language metadata tracking
            if suffix in LANGUAGE_EXTENSIONS:
                detected_languages[LANGUAGE_EXTENSIONS[suffix]] += 1

    # Format language metadata string (top 3 languages)
    top_languages = [lang for lang, _ in detected_languages.most_common(3)]
    language_metadata = ", ".join(top_languages) if top_languages else "Generic Code"

    return extracted_files_count, total_uncompressed_bytes, language_metadata


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


def validate_local_ingest_path(local_path: str, user_id: str) -> Path:
    """Validate and confine local directory paths for ingestion.

    Enforces:
    1. Rejects empty, null-byte, or malformed path strings.
    2. Resolves path to canonical form, rejecting non-existent paths or non-directories.
    3. Cross-Tenant Confinement: If path is located within the workspace hierarchy,
       it MUST be strictly within the requesting user's tenant subdirectory.
       Cross-tenant traversal (e.g. into another user's workspace) is blocked with 403.
    4. Host Root Protection: Rejects dangerous system root directories (/, C:\\, /etc, /root, etc.).
    5. Symlink Defense: Symlinks pointing outside the verified directory or to sensitive targets are rejected.
    """
    if not local_path or not isinstance(local_path, str) or "\0" in local_path:
        raise ValidationError("Local repository path must be a valid, non-empty directory path.")

    target_dir = Path(local_path).resolve()
    if not target_dir.exists() or not target_dir.is_dir():
        raise ValidationError(f"Directory path does not exist or is not a directory: {local_path}")

    # Symlink root defense
    if target_dir.is_symlink():
        real_target = target_dir.resolve(strict=True)
        if real_target != target_dir:
            raise SecurityPolicyViolationError("Local directory path is a symbolic link escaping its target.")

    # Cross-Tenant Confinement Check
    workspace_root = get_workspace_root().resolve()
    safe_user = re.sub(r"[^a-zA-Z0-9_\-]", "", user_id)
    user_allowed_workspace = (workspace_root / safe_user).resolve()

    target_str = str(target_dir).lower() if os.name == "nt" else str(target_dir)
    ws_str = str(workspace_root).lower() if os.name == "nt" else str(workspace_root)
    user_ws_str = str(user_allowed_workspace).lower() if os.name == "nt" else str(user_allowed_workspace)

    # If the target path lies anywhere inside the Red Mercury workspace hierarchy:
    if target_str.startswith(ws_str):
        # It MUST start with this specific user's workspace directory
        if not target_str.startswith(user_ws_str):
            logger.warning(
                f"Cross-tenant directory traversal blocked: actor '{user_id}' attempted to ingest '{target_dir}'"
            )
            raise SecurityPolicyViolationError(
                "Access denied: Local path references another tenant's workspace or restricted area."
            )

    # Disallow filesystem roots and sensitive operating system directories
    if target_dir.parent == target_dir or target_dir == Path(target_dir.anchor):
        raise SecurityPolicyViolationError("Access denied: System root directories cannot be ingested.")

    norm_target = target_str.rstrip("\\/")
    forbidden_prefixes = {"c:\\windows", "c:/windows", "c:\\program files", "c:/program files", "/etc", "/proc", "/sys", "/root", "/var", "/dev"}
    if any(norm_target == fp or norm_target.startswith(fp + "\\") or norm_target.startswith(fp + "/") for fp in forbidden_prefixes):
        raise SecurityPolicyViolationError("Access denied: Restricted system directory cannot be ingested.")

    return target_dir


def clone_git_repository(
    git_url: str,
    dest_dir: Path,
    branch: str = "main",
    timeout: int = 60,
    allow_private: bool = False,
) -> Tuple[int, int, str, str]:
    """Safely clone a public Git repository into an isolated directory with DNS rebinding defenses.

    Zero code execution: hooks disabled, credentials disallowed, timeout enforced.
    Pins the validated IP to the hostname and disables redirects to prevent SSRF via TOCTOU rebinding.
    """
    dest_dir = dest_dir.resolve()
    if dest_dir.exists():
        shutil.rmtree(dest_dir, ignore_errors=True)
    dest_dir.mkdir(parents=True, exist_ok=True)

    # Validate branch name to prevent git option/flag injection
    branch_name = branch.strip()
    git_branch_regex = re.compile(r"^[a-zA-Z0-9_\-\./]+$")
    if not branch_name or not git_branch_regex.match(branch_name) or branch_name.startswith("-") or ".." in branch_name:
        raise ValidationError(
            f"Invalid git branch name: '{branch}'. Branch names must not start with hyphens or contain path traversal/shell characters."
        )

    # 1. Parse and re-validate destination at the moment of execution (TOCTOU / DNS rebinding protection)
    parsed = urllib.parse.urlsplit(git_url)
    hostname = parsed.hostname
    if not hostname:
        raise ValidationError("Invalid repository URL: missing hostname.")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    primary_ip = None

    if not allow_private:
        if hostname.lower() in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "metadata.google.internal"):  # nosec B104
            raise SecurityPolicyViolationError(f"Target host '{hostname}' is not permitted (SSRF protection).")

        try:
            addr_info = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
            resolved_ips = [item[4][0] for item in addr_info]
            if not resolved_ips:
                raise ValidationError(f"Could not resolve repository host '{hostname}'.")

            for ip_str in resolved_ips:
                if is_ip_blocked(ip_str):
                    logger.warning(f"SSRF / DNS rebinding blocked: '{hostname}' resolved to restricted IP '{ip_str}'")
                    raise SecurityPolicyViolationError(
                        f"Target host '{hostname}' resolves to restricted network address ({ip_str})."
                    )
            primary_ip = resolved_ips[0]
        except socket.gaierror as e:
            raise ValidationError(f"DNS resolution failed for repository host '{hostname}': {str(e)}")

    # Git command with security flags:
    # 1. core.hooksPath=/dev/null ensures no client-side hooks execute
    # 2. protocol.file.allow=never prohibits local file protocol access
    # 3. protocol.allow=never and protocol.https.allow=always enforces strict HTTPS
    # 4. http.followRedirects=false prevents redirect-based SSRF bypass
    # 5. http.resolve pins the validated IP address to prevent connection-time DNS rebinding
    cmd = [
        "git",
        "-c", "core.hooksPath=/dev/null",
        "-c", "protocol.file.allow=never",
        "-c", "protocol.allow=never",
        "-c", "protocol.https.allow=always",
        "-c", "http.followRedirects=false",
    ]

    if primary_ip:
        resolve_opt = f"{hostname}:{port}:{primary_ip}"
        cmd.extend([
            "-c", f"http.resolve={resolve_opt}",
            "-c", f"http.{git_url}.resolve={resolve_opt}",
        ])

    cmd.extend([
        "clone",
        "--depth", "1",
        "--branch", branch_name,
        "--single-branch",
        "--",
        git_url,
        str(dest_dir),
    ])

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )

        if result.returncode != 0:
            stderr_msg = result.stderr.strip()
            # If specified branch was not found upstream (e.g., master vs main), fallback to default branch
            if "not found in upstream origin" in stderr_msg.lower() or "remote branch" in stderr_msg.lower():
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

                result = subprocess.run(
                    fallback_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=timeout,
                    check=False,
                )

        if result.returncode != 0:
            stderr_msg = result.stderr.strip()
            # Strip any sensitive info from git error message
            safe_err = re.sub(r"https://[^@]+@", "https://", stderr_msg)
            raise ValidationError(f"Git clone failed: {safe_err or 'Repository not found or branch does not exist.'}")

        actual_branch = branch_name
        dot_git = dest_dir / ".git"
        if dot_git.exists():
            try:
                head_proc = subprocess.run(
                    ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                    cwd=str(dest_dir),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=5,
                )
                if head_proc.returncode == 0 and head_proc.stdout.strip():
                    detected = head_proc.stdout.strip()
                    if detected and detected != "HEAD":
                        actual_branch = detected
            except Exception:
                pass

            # Remove the .git directory to save space and remove any potential git hooks
            shutil.rmtree(dot_git, ignore_errors=True)

        file_count, total_bytes, language_metadata = collect_directory_metadata(dest_dir)
        return (file_count, total_bytes, language_metadata, actual_branch)

    except subprocess.TimeoutExpired:
        if dest_dir.exists():
            shutil.rmtree(dest_dir, ignore_errors=True)
        raise ValidationError(f"Git clone operation timed out after {timeout} seconds.")
    except FileNotFoundError:
        raise ValidationError("Git executable is not installed or available on the host system.")
