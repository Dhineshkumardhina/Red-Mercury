"""Isolated Disposable Workspace Management for Fix Verification.

Enforces:
1. Creation of disposable copies/worktrees in isolated temporary directories.
2. Calculation of cryptographic SHA-256 baseline and patched content hashes.
3. Secret-sanitized execution environments (stripping API keys, DB credentials).
4. Resource limits & automated workspace cleanup.
"""
from dataclasses import dataclass
import hashlib
import logging
import os
from pathlib import Path
import platform
import shutil
import stat
import struct
import subprocess
import tempfile
from typing import Dict, List, Optional

logger = logging.getLogger("redmercury.verification.workspace")

# Linux kernel POSIX ACL xattr constants (uapi/linux/posix_acl_xattr.h)
_ACL_EA_VERSION = 2
_ACL_UNDEFINED_ID = 0xFFFFFFFF
_ACL_USER_OBJ = 0x01
_ACL_USER = 0x02
_ACL_GROUP_OBJ = 0x04
_ACL_MASK = 0x10
_ACL_OTHER = 0x20
_ACL_READ = 0x04
_ACL_WRITE = 0x02
_ACL_EXECUTE = 0x01


# Environment variables to purge from runner sub-processes to avoid secret leakage
SENSITIVE_ENV_VARS = {
    "GEMINI_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "SECRET_KEY",
    "DATABASE_URL",
    "DB_PASSWORD",
    "POSTGRES_PASSWORD",
    "POSTGRES_USER",
    "POSTGRES_DB",
    "GITHUB_TOKEN",
    "GITHUB_CLIENT_SECRET",
    "GITHUB_CLIENT_ID",
    "GITHUB_WEBHOOK_SECRET",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_ACCESS_KEY_ID",
    "AWS_SESSION_TOKEN",
    "STRIPE_API_KEY",
    "JWT_SECRET",
    "PRIVATE_KEY",
    "DOCKER_AUTH_CONFIG",
    "DEV_SEED_PASSWORD",
}

SENSITIVE_KEYWORD_PATTERNS = (
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "API_KEY",
    "PRIVATE_KEY",
    "DATABASE",
    "DB_PASS",
    "AUTH",
    "CREDENTIAL",
    "COOKIE",
)


def calculate_directory_hash(root_dir: Path) -> str:
    """Calculate reproducible SHA-256 digest over file contents in directory."""
    hasher = hashlib.sha256()
    if not root_dir.exists() or not root_dir.is_dir():
        return hashlib.sha256(b"empty").hexdigest()

    file_paths: List[Path] = []
    for p in root_dir.rglob("*"):
        if p.is_file() and not p.name.startswith(".") and "__pycache__" not in str(p):
            file_paths.append(p)

    # Sort deterministically
    file_paths.sort(key=lambda p: str(p.relative_to(root_dir)).replace("\\", "/"))

    for p in file_paths:
        rel_path = str(p.relative_to(root_dir)).replace("\\", "/")
        hasher.update(rel_path.encode("utf-8"))
        try:
            hasher.update(p.read_bytes())
        except Exception:
            pass

    return hasher.hexdigest()


def calculate_file_or_content_hash(content_or_path: str) -> str:
    """Compute SHA-256 hash of a content string or file."""
    return hashlib.sha256(content_or_path.encode("utf-8")).hexdigest()


def get_sanitized_runner_env() -> Dict[str, str]:
    """Return environment dictionary with all application secrets and private credentials stripped.
    
    Also sets flags to disable network package installations during verification runs.
    """
    env = os.environ.copy()
    for var in list(env.keys()):
        var_upper = var.upper()
        if var in SENSITIVE_ENV_VARS or any(sec in var_upper for sec in SENSITIVE_KEYWORD_PATTERNS):
            env.pop(var, None)

    # Offline and isolation flags for runners
    env["PIP_NO_INDEX"] = "1"
    env["NO_PROXY"] = "*"
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def safe_copy_source_tree(source_dir: Path, workspace_path: Path) -> None:
    """Safely copy files from source repository to isolated disposable workspace.
    
    Defenses:
    1. Ignores VCS (.git) and build caches.
    2. Inspects symbolic links: strictly skips any symlink whose target escapes source_dir.
    3. Writes regular file copies in the destination so that no dangling symlinks persist.
    """
    source_resolved = source_dir.resolve()
    workspace_resolved = workspace_path.resolve()

    excluded_names = {".git", "__pycache__", ".pytest_cache", "node_modules", ".venv", ".tox"}

    for root, dirs, files in os.walk(source_dir, followlinks=False):
        curr_root = Path(root)

        # Exclude specified directories in-place
        dirs[:] = [d for d in dirs if d not in excluded_names]

        # Calculate relative directory path from source root
        try:
            rel_dir = curr_root.resolve().relative_to(source_resolved)
        except ValueError:
            # Current directory walked outside source_resolved (e.g. via parent symlink)
            continue

        target_dir = workspace_resolved / rel_dir
        target_dir.mkdir(parents=True, exist_ok=True)

        # Inspect directories for symlink escapes
        for d in list(dirs):
            d_path = curr_root / d
            if d_path.is_symlink():
                try:
                    resolved_target = d_path.resolve()
                    resolved_target.relative_to(source_resolved)
                except ValueError:
                    # Symlink points outside source root - remove from traversal list
                    dirs.remove(d)

        for f in files:
            if f in excluded_names:
                continue

            f_path = curr_root / f
            dest_file = target_dir / f

            if f_path.is_symlink():
                # Check if symlink target points outside source directory
                try:
                    resolved_target = f_path.resolve()
                    resolved_target.relative_to(source_resolved)
                except (ValueError, RuntimeError):
                    # Escapes source directory or circular symlink - skip copying
                    continue

                if resolved_target.is_file():
                    try:
                        shutil.copyfile(str(resolved_target), str(dest_file))
                    except Exception:
                        pass
            elif f_path.is_file():
                try:
                    shutil.copyfile(str(f_path), str(dest_file))
                except Exception:
                    pass


@dataclass
class VerificationWorkspace:
    """Represents an isolated disposable workspace on disk."""
    workspace_dir: Path
    baseline_hash: str
    patched_hash: str = ""
    is_disposable: bool = True
    temp_dir_obj: Optional[tempfile.TemporaryDirectory] = None

    def __enter__(self) -> "VerificationWorkspace":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.cleanup()

    def cleanup(self) -> None:
        """Safely and reliably destroy disposable workspace files."""
        def _force_remove_readonly(func, path, exc_info):
            """Error callback to handle read-only file permissions on Windows/Linux."""
            import stat
            try:
                os.chmod(path, stat.S_IWRITE)
                func(path)
            except Exception:
                pass

        if self.temp_dir_obj is not None:
            try:
                self.temp_dir_obj.cleanup()
            except Exception:
                pass

        if self.workspace_dir.exists() and self.is_disposable:
            try:
                shutil.rmtree(self.workspace_dir, onerror=_force_remove_readonly)
            except Exception:
                try:
                    shutil.rmtree(self.workspace_dir, ignore_errors=True)
                except Exception:
                    pass


def create_verification_workspace(
    source_dir: Optional[Path] = None,
    synthetic_files: Optional[Dict[str, str]] = None
) -> VerificationWorkspace:
    """Initialize a disposable verification workspace.
    
    Copies existing source directory safely if provided, or seeds with synthetic files.
    Calculates initial baseline content hash.
    """
    temp_dir = tempfile.TemporaryDirectory(prefix="redmercury_verify_")
    workspace_path = Path(temp_dir.name).resolve()
    try:
        from ..core.jobs import get_active_tracker
        tracker = get_active_tracker()
        if tracker is not None:
            tracker.register_temp_workspace(workspace_path)
    except Exception:
        pass

    if source_dir and source_dir.exists() and source_dir.is_dir():
        safe_copy_source_tree(source_dir=source_dir, workspace_path=workspace_path)

    # If synthetic files are provided (for testing or mock findings), write them
    if synthetic_files:
        for rel_path, content in synthetic_files.items():
            clean_rel = rel_path.lstrip("/\\")
            dest_file = (workspace_path / clean_rel).resolve()
            # Enforce that synthetic files do not escape the workspace
            try:
                dest_file.relative_to(workspace_path)
            except ValueError:
                continue
            dest_file.parent.mkdir(parents=True, exist_ok=True)
            dest_file.write_text(content, encoding="utf-8")

    baseline_hash = calculate_directory_hash(workspace_path)
    ensure_sandbox_readable_workspace(workspace_path)

    return VerificationWorkspace(
        workspace_dir=workspace_path,
        baseline_hash=baseline_hash,
        is_disposable=True,
        temp_dir_obj=temp_dir
    )


def parse_sandbox_uid(sandbox_user: Optional[str]) -> int:
    """Extract numeric container UID from '<uid>[:<gid>]' configuration."""
    raw_uid = (sandbox_user or "10002:10002").strip().split(":", 1)[0].strip()
    try:
        uid = int(raw_uid)
    except ValueError as exc:
        raise PermissionError(f"Invalid sandbox container UID specification '{sandbox_user}'.") from exc
    if uid < 0:
        raise PermissionError(f"Invalid negative sandbox container UID '{uid}'.")
    return uid


def validate_strict_temp_workspace(workspace_dir: Path) -> Path:
    """Validate that workspace_dir is an existing directory strictly inside system temp_root.

    Rejects the temp root itself, paths outside temp_root, non-existent/non-directory
    paths, and any path traversing or resolving through symbolic links.
    """
    if not isinstance(workspace_dir, Path):
        raise ValueError("Workspace path must be a pathlib.Path instance.")

    if workspace_dir.is_symlink():
        raise PermissionError(f"Refusing symbolic link workspace root: {workspace_dir}")

    temp_root = Path(tempfile.gettempdir()).resolve(strict=True)
    try:
        resolved_ws = workspace_dir.resolve(strict=True)
    except OSError as exc:
        raise FileNotFoundError(f"Workspace directory does not exist or cannot be resolved: {workspace_dir}") from exc

    if not resolved_ws.is_dir():
        raise NotADirectoryError(f"Workspace path is not a directory: {resolved_ws}")

    if resolved_ws == temp_root or temp_root not in resolved_ws.parents:
        raise PermissionError(
            f"Refusing workspace outside strict temporary-root descendant boundary: {resolved_ws}"
        )

    # Walk ancestor components back to temp_root to reject intermediate symlink redirects
    curr = workspace_dir
    while curr != curr.parent:
        try:
            if curr.resolve(strict=True) == temp_root:
                break
        except OSError as exc:
            raise PermissionError(f"Unresolvable workspace ancestor path: {curr}") from exc
        if curr.is_symlink():
            raise PermissionError(f"Workspace path traverses symbolic link ancestor: {curr}")
        curr = curr.parent

    return resolved_ws


def _build_posix_acl_xattr(owner_perm: int, target_uid: int, target_perm: int) -> bytes:
    """Serialize a minimal POSIX ACL v2 xattr granting access strictly to owner and target_uid."""
    entries = (
        (_ACL_USER_OBJ, owner_perm, _ACL_UNDEFINED_ID),
        (_ACL_USER, target_perm, target_uid),
        (_ACL_GROUP_OBJ, 0, _ACL_UNDEFINED_ID),
        (_ACL_MASK, target_perm, _ACL_UNDEFINED_ID),
        (_ACL_OTHER, 0, _ACL_UNDEFINED_ID),
    )
    return struct.pack("<I", _ACL_EA_VERSION) + b"".join(
        struct.pack("<HHI", tag, perm, eid) for tag, perm, eid in entries
    )


def _apply_scoped_posix_permissions(path: Path, target_uid: int, is_dir: bool, owner_exec: bool) -> None:
    """Enforce owner-only base mode plus UID-scoped POSIX ACL without world-readable bits."""
    base_mode = (
        stat.S_IRWXU
        if is_dir
        else (stat.S_IRUSR | stat.S_IWUSR | (stat.S_IXUSR if owner_exec else 0))
    )
    os.chmod(path, base_mode)

    host_uid_fn = getattr(os, "getuid", None)
    if host_uid_fn is not None and host_uid_fn() == target_uid:
        # Process already runs under container UID; private 0o700/0o600 owner permissions suffice.
        return

    owner_acl_perm = _ACL_READ | _ACL_WRITE | (_ACL_EXECUTE if (is_dir or owner_exec) else 0)
    target_acl_perm = _ACL_READ | (_ACL_EXECUTE if (is_dir or owner_exec) else 0)

    setxattr_fn = getattr(os, "setxattr", None)
    if setxattr_fn is not None:
        acl_blob = _build_posix_acl_xattr(
            owner_perm=owner_acl_perm,
            target_uid=target_uid,
            target_perm=target_acl_perm,
        )
        try:
            setxattr_fn(path, "system.posix_acl_access", acl_blob, follow_symlinks=False)
        except OSError as exc:
            raise PermissionError(
                f"Failed setting POSIX ACL for UID {target_uid} on '{path}': {exc}. "
                "Refusing insecure world-readable fallback."
            ) from exc
    else:
        setfacl_bin = shutil.which("setfacl")
        if not setfacl_bin:
            raise PermissionError(
                f"Cannot establish private container access for UID {target_uid} on '{path}': "
                "POSIX ACL support (os.setxattr/setfacl) is unavailable. "
                "Refusing insecure world-readable fallback."
            )
        acl_perm_str = "rx" if (is_dir or owner_exec) else "r"
        acl_spec = f"u:{target_uid}:{acl_perm_str},g::-,m::{acl_perm_str},o::-"
        res = subprocess.run(
            [setfacl_bin, "--no-dereference", "-m", acl_spec, str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if res.returncode != 0:
            raise PermissionError(
                f"setfacl failed for UID {target_uid} on '{path}': {res.stderr.strip() or res.returncode}. "
                "Refusing insecure world-readable fallback."
            )

    if os.name == "posix":
        other_bits = stat.S_IMODE(os.lstat(path).st_mode) & stat.S_IRWXO
        if other_bits != 0:
            raise PermissionError(
                f"Security invariant violated: non-zero world permission bits ({oct(other_bits)}) on '{path}'."
            )


def ensure_sandbox_readable_workspace(
    workspace_dir: Path,
    sandbox_uid: Optional[int] = None,
) -> None:
    """Grant private container UID (default 10002) read/execute access to temp workspaces on POSIX.

    Enforces strict temporary-root boundary validation, skips all symbolic links without
    following them, keeps other/world permissions strictly disabled (zero 0o007 bits),
    and fails closed with PermissionError if POSIX ACL setup fails.
    """
    resolved_ws = validate_strict_temp_workspace(workspace_dir)

    if platform.system() == "Windows":
        return

    if platform.system() == "Darwin":
        # macOS Docker Desktop shares VirtioFS/gRPC-FUSE mounts under the host user identity
        # without Linux POSIX ACLs; enforce strict owner-only permissions and zero world/group bits.
        os.chmod(resolved_ws, stat.S_IRWXU)
        for root, dirs, files in os.walk(resolved_ws, followlinks=False):
            root_path = Path(root)
            for d in list(dirs):
                d_path = root_path / d
                if d_path.is_symlink():
                    dirs.remove(d)
                    continue
                os.chmod(d_path, stat.S_IRWXU)
            for fname in files:
                f_path = root_path / fname
                if f_path.is_symlink():
                    continue
                mode = f_path.stat(follow_symlinks=False).st_mode
                target_mode = stat.S_IRUSR | stat.S_IWUSR | (stat.S_IXUSR if (mode & stat.S_IXUSR) else 0)
                os.chmod(f_path, target_mode)
        return

    if sandbox_uid is None:
        from ..core.config import settings
        target_uid = parse_sandbox_uid(settings.SANDBOX_USER)
    else:
        target_uid = parse_sandbox_uid(str(sandbox_uid))

    _apply_scoped_posix_permissions(resolved_ws, target_uid=target_uid, is_dir=True, owner_exec=True)

    for root, dirs, files in os.walk(resolved_ws, followlinks=False):
        root_path = Path(root)
        for d in list(dirs):
            d_path = root_path / d
            if d_path.is_symlink():
                dirs.remove(d)
                continue
            _apply_scoped_posix_permissions(d_path, target_uid=target_uid, is_dir=True, owner_exec=True)

        for fname in files:
            f_path = root_path / fname
            if f_path.is_symlink():
                continue
            mode = f_path.stat(follow_symlinks=False).st_mode
            _apply_scoped_posix_permissions(
                f_path,
                target_uid=target_uid,
                is_dir=False,
                owner_exec=bool(mode & stat.S_IXUSR),
            )
