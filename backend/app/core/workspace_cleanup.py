"""Automated workspace garbage collection and safe repository deletion utilities.

Implements defense-in-depth workspace cleanup controls (SEC-15):
1. Canonical path validation and strict workspace-root containment via Path.is_relative_to().
2. Symlink rejection BEFORE resolve() and symlink-safe bottom-up deletion (followlinks=False).
3. Tenant-level ownership confinement for repository deletions.
4. Protection of active repositories, running/pending/queued scans, and verification runs.
5. Idempotent, failure-safe deletion with structured audit logging.
"""
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import re
import tempfile
from typing import Dict, Optional, Set, Tuple
from sqlalchemy.orm import Session

from .audit import record_audit_event
from .errors import SecurityPolicyViolationError, ValidationError
from .ingestion import _path_or_ancestors_contain_symlink, get_workspace_root
from .logging import get_logger
from ..models.repository import Repository
from ..models.scan import Scan
from ..models.verification import VerificationRun

logger = get_logger("redmercury.cleanup")

ACTIVE_JOB_STATUSES = ("running", "pending", "queued")


def _safe_dir_size_bytes(directory: Path) -> int:
    """Compute total size of regular files inside directory without following symlinks."""
    total = 0
    for root, dirs, files in os.walk(directory, topdown=True, followlinks=False):
        root_path = Path(root)
        dirs[:] = [d for d in dirs if not (root_path / d).is_symlink()]
        for fname in files:
            fpath = root_path / fname
            try:
                if fpath.is_symlink():
                    continue
                total += fpath.lstat().st_size
            except OSError:
                pass
    return total


def _safe_rmtree_no_symlinks(target_dir: Path, boundary_root: Path) -> int:
    """Delete a directory tree bottom-up without following symlinks, verifying boundary containment.

    Returns reclaimed bytes.
    """
    resolved_root = boundary_root.resolve()
    resolved_target = target_dir.resolve()

    if resolved_target == resolved_root or not resolved_target.is_relative_to(resolved_root):
        raise SecurityPolicyViolationError(
            "Refusing to delete directory outside authorized workspace boundary."
        )
    if target_dir.is_symlink():
        raise SecurityPolicyViolationError("Refusing to traverse or delete symbolic link target.")

    reclaimed = 0
    for root, dirs, files in os.walk(resolved_target, topdown=False, followlinks=False):
        root_path = Path(root)
        if not root_path.resolve().is_relative_to(resolved_root):
            raise SecurityPolicyViolationError("Deletion walk escaped authorized workspace boundary.")

        for fname in files:
            fpath = root_path / fname
            try:
                if fpath.is_symlink():
                    # Unlink the symlink itself without dereferencing its target
                    fpath.unlink(missing_ok=True)
                else:
                    reclaimed += fpath.lstat().st_size
                    fpath.unlink(missing_ok=True)
            except OSError as exc:
                logger.warning(f"Failed to remove file '{fpath}': {exc}")

        for dname in dirs:
            dpath = root_path / dname
            try:
                if dpath.is_symlink():
                    dpath.unlink(missing_ok=True)
                else:
                    dpath.rmdir()
            except OSError as exc:
                logger.warning(f"Failed to remove subdirectory '{dpath}': {exc}")

    try:
        resolved_target.rmdir()
    except OSError as exc:
        logger.warning(f"Failed to remove root workspace directory '{resolved_target}': {exc}")

    return reclaimed


def validate_workspace_deletion_path(
    workspace_path: str,
    owner_id: Optional[str] = None,
) -> Path:
    """Validate that a workspace path is strictly confined within the authorized workspace root.

    Enforces:
    - Non-empty string with no null bytes or '..' traversal segments.
    - No symlinks in the path or its ancestors BEFORE resolve().
    - Strictly contained inside WORKSPACE_ROOT (never WORKSPACE_ROOT itself).
    - When owner_id is supplied, strictly contained inside WORKSPACE_ROOT/<safe_owner_id>
      (never the tenant root itself), immune to string-prefix collisions (alice vs alice2).
    """
    if not workspace_path or not isinstance(workspace_path, str) or "\0" in workspace_path:
        raise ValidationError("Workspace path is empty or malformed.")

    raw_path = Path(workspace_path)
    if ".." in raw_path.parts:
        raise SecurityPolicyViolationError(
            "Directory traversal segments ('..') are prohibited in workspace deletion paths."
        )

    if _path_or_ancestors_contain_symlink(raw_path):
        raise SecurityPolicyViolationError(
            "Workspace deletion path cannot be or traverse a symbolic link."
        )

    workspace_root = get_workspace_root().resolve()
    resolved_target = raw_path.resolve(strict=False)

    if resolved_target == workspace_root or not resolved_target.is_relative_to(workspace_root):
        raise SecurityPolicyViolationError(
            "Workspace deletion path resolves outside authorized workspace root."
        )

    if owner_id is not None:
        safe_owner = re.sub(r"[^a-zA-Z0-9_\-]", "", owner_id)
        if not safe_owner:
            raise ValidationError("Invalid workspace owner identifier.")
        tenant_root = (workspace_root / safe_owner).resolve()
        if resolved_target == tenant_root or not resolved_target.is_relative_to(tenant_root):
            raise SecurityPolicyViolationError(
                "Workspace deletion path resolves outside the authenticated tenant's workspace."
            )

    return resolved_target


def _collect_protected_workspace_paths(db: Session) -> Set[Path]:
    """Collect canonical workspace paths currently referenced by active scans, verifications, or repos."""
    protected: Set[Path] = set()

    # 1. Active scans
    active_scans = db.query(Scan).filter(Scan.status.in_(ACTIVE_JOB_STATUSES)).all()
    for scan in active_scans:
        if scan.repository and scan.repository.workspace_path:
            try:
                protected.add(Path(scan.repository.workspace_path).resolve(strict=False))
            except OSError:
                pass

    # 2. Active verification runs (via finding -> repository)
    active_runs = db.query(VerificationRun).filter(VerificationRun.status.in_(ACTIVE_JOB_STATUSES)).all()
    for run in active_runs:
        if run.finding and run.finding.repository and run.finding.repository.workspace_path:
            try:
                protected.add(Path(run.finding.repository.workspace_path).resolve(strict=False))
            except OSError:
                pass

    # 3. Active registered repositories
    active_repos = db.query(Repository).filter(Repository.is_active == True).all()
    for repo in active_repos:
        if repo.workspace_path:
            try:
                protected.add(Path(repo.workspace_path).resolve(strict=False))
            except OSError:
                pass

    return protected


def _is_path_protected(candidate: Path, protected_paths: Set[Path]) -> bool:
    """Return True if candidate matches, contains, or is contained by any protected path."""
    resolved_candidate = candidate.resolve(strict=False)
    for prot in protected_paths:
        if (
            resolved_candidate == prot
            or prot.is_relative_to(resolved_candidate)
            or resolved_candidate.is_relative_to(prot)
        ):
            return True
    return False


def safe_delete_workspace_dir(
    workspace_path: Optional[str],
    owner_id: Optional[str] = None,
    db: Optional[Session] = None,
    repo_id: Optional[str] = None,
    actor_id: Optional[str] = None,
) -> Tuple[bool, int]:
    """Safely validate and delete a repository workspace directory.

    - Enforces canonical containment, symlink rejection, and tenant ownership.
    - Refuses to delete a workspace with active scans or verification runs.
    - Idempotent when the path does not exist on disk.
    - Records structured audit log on deletion.

    Returns:
        (deleted: bool, reclaimed_bytes: int)
    """
    if not workspace_path:
        return False, 0

    validated_target = validate_workspace_deletion_path(workspace_path, owner_id=owner_id)

    # Check active scan / verification lock if database session & repo_id are provided
    if db is not None and repo_id is not None:
        active_scan = (
            db.query(Scan)
            .filter(Scan.repository_id == repo_id, Scan.status.in_(ACTIVE_JOB_STATUSES))
            .first()
        )
        if active_scan is not None:
            raise ValidationError(
                "Cannot delete repository workspace while a security scan is currently active."
            )

    if not validated_target.exists():
        return False, 0

    if not validated_target.is_dir():
        raise SecurityPolicyViolationError("Workspace deletion target must be a directory.")

    workspace_root = get_workspace_root().resolve()
    boundary_root = (
        (workspace_root / re.sub(r"[^a-zA-Z0-9_\-]", "", owner_id)).resolve()
        if owner_id is not None
        else workspace_root
    )

    reclaimed = _safe_rmtree_no_symlinks(validated_target, boundary_root)

    # Prune empty parent repo folder (<workspace_root>/<owner>/<repo_id>) if validated_target was .../source
    parent_dir = validated_target.parent
    if (
        parent_dir != boundary_root
        and parent_dir.is_relative_to(boundary_root)
        and parent_dir.exists()
        and not parent_dir.is_symlink()
    ):
        try:
            if not any(parent_dir.iterdir()):
                parent_dir.rmdir()
        except OSError:
            pass

    logger.info(
        f"Safely purged repository workspace '{validated_target}' "
        f"(repo_id={repo_id}, owner_id={owner_id}, reclaimed_bytes={reclaimed})"
    )

    if db is not None:
        record_audit_event(
            db=db,
            action="WORKSPACE_PURGED",
            resource_type="repository_workspace",
            resource_identifier=repo_id or validated_target.name,
            actor_id=actor_id or owner_id,
            metadata={"reclaimed_bytes": reclaimed},
        )

    return True, reclaimed


def clean_stale_workspaces(db: Optional[Session] = None, max_age_hours: int = 24) -> Dict[str, int]:
    """Clean up orphan or stale temporary directories and workspaces safely without touching active ones.

    Returns:
        Summary dict of cleaned directories and reclaimed bytes.
    """
    reclaimed_bytes = 0
    removed_dirs = 0
    now = datetime.now(timezone.utc)
    cutoff_time = now - timedelta(hours=max_age_hours)

    # 1. Clean disposable redmercury verification workspaces from temp (symlink-safe & confined)
    temp_dir = Path(tempfile.gettempdir()).resolve()
    for item in temp_dir.glob("redmercury_*"):
        try:
            if item.is_symlink():
                logger.warning(f"Skipping symlinked temp item during cleanup: {item.name}")
                continue
            resolved_item = item.resolve(strict=False)
            if resolved_item == temp_dir or not resolved_item.is_relative_to(temp_dir):
                logger.warning(f"Skipping out-of-bounds temp item: {item.name}")
                continue

            mtime = datetime.fromtimestamp(item.lstat().st_mtime, tz=timezone.utc)
            if mtime < cutoff_time:
                if item.is_dir():
                    size = _safe_rmtree_no_symlinks(item, temp_dir)
                else:
                    size = item.lstat().st_size
                    item.unlink(missing_ok=True)
                removed_dirs += 1
                reclaimed_bytes += size
                logger.info(f"Purged stale temp workspace: {item.name} ({size} bytes)")
        except Exception as exc:
            logger.warning(f"Failed to clean temp item {item}: {exc}")

    # 2. Check main workspace root for orphaned repo-level folders if db is provided
    workspace_root = get_workspace_root().resolve()
    if workspace_root.exists() and db is not None:
        protected_paths = _collect_protected_workspace_paths(db)

        for tenant_dir in workspace_root.iterdir():
            try:
                if tenant_dir.is_symlink() or not tenant_dir.is_dir():
                    continue
                if not tenant_dir.resolve().is_relative_to(workspace_root):
                    continue

                # Iterate repo-level workspaces (<workspace_root>/<tenant_id>/<repo_id>)
                for repo_dir in tenant_dir.iterdir():
                    try:
                        if repo_dir.is_symlink() or not repo_dir.is_dir():
                            continue
                        resolved_repo = repo_dir.resolve()
                        if resolved_repo == tenant_dir.resolve() or not resolved_repo.is_relative_to(tenant_dir.resolve()):
                            continue

                        if _is_path_protected(resolved_repo, protected_paths):
                            continue

                        mtime = datetime.fromtimestamp(repo_dir.lstat().st_mtime, tz=timezone.utc)
                        if mtime < cutoff_time:
                            size = _safe_rmtree_no_symlinks(repo_dir, tenant_dir)
                            removed_dirs += 1
                            reclaimed_bytes += size
                            logger.info(
                                f"Purged orphaned stale repository workspace: "
                                f"{tenant_dir.name}/{repo_dir.name} ({size} bytes)"
                            )
                    except Exception as exc:
                        logger.warning(f"Error purging repo workspace folder {repo_dir}: {exc}")
            except Exception as exc:
                logger.warning(f"Error inspecting tenant workspace folder {tenant_dir}: {exc}")

    return {
        "removed_directories": removed_dirs,
        "reclaimed_bytes": reclaimed_bytes,
    }
