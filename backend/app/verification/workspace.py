"""Isolated Disposable Workspace Management for Fix Verification.

Enforces:
1. Creation of disposable copies/worktrees in isolated temporary directories.
2. Calculation of cryptographic SHA-256 baseline and patched content hashes.
3. Secret-sanitized execution environments (stripping API keys, DB credentials).
4. Resource limits & automated workspace cleanup.
"""
from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import shutil
import tempfile
from typing import Dict, List, Optional


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

    return VerificationWorkspace(
        workspace_dir=workspace_path,
        baseline_hash=baseline_hash,
        is_disposable=True,
        temp_dir_obj=temp_dir
    )
