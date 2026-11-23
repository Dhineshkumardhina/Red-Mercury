"""System Capabilities, Offline Boundaries, and Local Backup & Recovery Endpoints (Phase 4)."""
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, Form, UploadFile, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ....analyzer.client import gemini_analyst_client
from ....core.audit import record_audit_event
from ....core.auth import get_current_user, require_mutating_role
from ....core.backup import (
    create_backup_archive,
    list_backup_archives,
    resolve_backup_dir,
    resolve_sqlite_db_path,
    restore_backup_archive,
    sanitize_backup_filename,
    stage_backup_restore,
    verify_backup_archive,
)
from ....core.config import settings
from ....core.errors import ValidationError
from ....db.session import engine, get_db
from ....models.user import User
from ....verification.sandbox import (
    build_approved_worker_image,
    check_docker_availability,
    get_sandbox_diagnostics,
)

router = APIRouter()


class BackupFileRequest(BaseModel):
    filename: str = Field(..., min_length=6, max_length=128)


class BackupRestoreRequest(BaseModel):
    filename: str = Field(..., min_length=6, max_length=128)
    stage_for_restart: bool = Field(
        default=True,
        description="Stage verified backup for atomic application on restart (recommended for desktop multi-process safety).",
    )


def compute_system_capabilities(probe_docker: bool = True) -> Dict[str, Any]:
    """Return honest capability boundaries separating offline scanning, external APIs, GitHub, and Docker."""
    offline_active = bool(settings.OFFLINE_MODE and not os.environ.get("FORCE_ONLINE"))
    ai_live = bool(gemini_analyst_client.is_configured())

    if probe_docker:
        docker_ok, docker_reason = check_docker_availability(
            timeout_seconds=1.5,
            required_image=None,
        )
    else:
        docker_ok, docker_reason = False, "Docker probe skipped"

    dialect = "sqlite" if settings.is_sqlite else "postgresql"
    redis_configured = bool((settings.REDIS_URL or "").strip())

    return {
        "environment": settings.APP_ENV,
        "offline_mode": offline_active,
        "database": {
            "dialect": dialect,
            "wal_enabled": dialect == "sqlite",
            "local_backup_supported": resolve_sqlite_db_path() is not None,
        },
        "background_queue": {
            "engine": f"{dialect}_durable_outbox",
            "redis_configured": redis_configured,
            "redis_required": False,
        },
        "capabilities": {
            "offline_scanning": {
                "available": True,
                "requires_internet": False,
                "status": "available",
                "mode": "local_offline",
                "tools": ["gitleaks", "bandit", "pip-audit", "secret_detector", "deterministic_rule_analyzer"],
                "message": "Static, secret, and deterministic rule analysis operate locally without internet access.",
            },
            "external_ai": {
                "available": ai_live,
                "requires_external_api": True,
                "status": "available" if ai_live else ("disabled_offline" if offline_active else "missing_api_key"),
                "active_engine": settings.GEMINI_MODEL if ai_live else "redmercury-deterministic-fallback-v1.0",
                "message": (
                    f"External Gemini AI ({settings.GEMINI_MODEL}) is configured and active."
                    if ai_live
                    else (
                        "External AI (Gemini API) is disabled in Offline Mode. Deterministic local rule analysis is active instead."
                        if offline_active
                        else "External AI (Gemini API) is not configured (GEMINI_API_KEY missing). Deterministic local rule analysis is active."
                    )
                ),
            },
            "github_integrations": {
                "available": not offline_active,
                "requires_internet": True,
                "status": "available" if not offline_active else "disabled_offline",
                "message": (
                    "GitHub API integrations and remote Git cloning are enabled."
                    if not offline_active
                    else "GitHub PR sync and remote HTTPS repository cloning require internet access and are disabled in Offline Mode. Local folder and ZIP ingestion remain available."
                ),
            },
            "docker_verification": {
                "available": docker_ok,
                "requires_docker": True,
                "fail_closed": bool(settings.SANDBOX_FAIL_CLOSED),
                "status": "available" if docker_ok else "unavailable",
                "image": settings.SANDBOX_CONTAINER_IMAGE,
                "message": docker_reason,
            },
        },
    }


@router.get(
    "/capabilities",
    summary="Inspect runtime capability matrix (offline scanning, external AI, GitHub, Docker)",
)
def get_system_capabilities(
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    return compute_system_capabilities(probe_docker=True)


@router.get(
    "/sandbox/status",
    summary="Inspect cross-platform Docker Desktop, architecture, worker image, digest, and sandbox invariants",
)
def get_sandbox_status(
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    return get_sandbox_diagnostics()


@router.post(
    "/sandbox/build-worker-image",
    summary="Build Red Mercury's approved worker container image from Dockerfile.worker",
)
def provision_approved_worker_image(
    current_user: User = Depends(require_mutating_role),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    result = build_approved_worker_image()
    if result.get("built"):
        record_audit_event(
            db=db,
            action="SANDBOX_WORKER_IMAGE_BUILT",
            resource_type="sandbox_image",
            resource_identifier=str(result.get("image") or settings.SANDBOX_CONTAINER_IMAGE),
            actor_id=current_user.id,
            metadata={
                "digest": result.get("digest"),
                "architecture": result.get("architecture"),
            },
        )
    return result


@router.get(
    "/backups",
    summary="List local database & configuration backups",
)
def get_local_backups(
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    return {
        "supported": resolve_sqlite_db_path() is not None,
        "backups": list_backup_archives(),
    }


@router.post(
    "/backups",
    status_code=status.HTTP_201_CREATED,
    summary="Create an integrity-checked local database and configuration backup",
)
def create_local_backup(
    current_user: User = Depends(require_mutating_role),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    created = create_backup_archive()
    record_audit_event(
        db=db,
        action="LOCAL_BACKUP_CREATED",
        resource_type="system_backup",
        resource_identifier=created["filename"],
        actor_id=current_user.id,
        metadata={
            "size_bytes": created["size_bytes"],
            "sha256": created["sha256"],
            "includes_config": created["includes_config"],
        },
    )
    return {
        "filename": created["filename"],
        "size_bytes": created["size_bytes"],
        "sha256": created["sha256"],
        "created_at": created["created_at"],
        "alembic_revision": created["alembic_revision"],
        "includes_config": created["includes_config"],
        "excludes_secrets": created["excludes_secrets"],
    }


@router.post(
    "/backups/verify",
    summary="Verify integrity and SHA-256 checksums of a local backup archive",
)
def verify_local_backup(
    payload: BackupFileRequest,
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    safe_name = sanitize_backup_filename(payload.filename)
    archive_path = resolve_backup_dir() / safe_name
    return verify_backup_archive(archive_path)


@router.post(
    "/backups/upload-verify",
    summary="Validate integrity of an uploaded backup archive without applying it",
)
async def upload_and_verify_backup(
    file: UploadFile = File(...),
    current_user: User = Depends(require_mutating_role),
) -> Dict[str, Any]:
    safe_name = sanitize_backup_filename(file.filename or "uploaded.rmbkp")
    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_path = Path(tmp_dir_str) / safe_name
        with open(tmp_path, "wb") as dst:
            shutil.copyfileobj(file.file, dst)
        return verify_backup_archive(tmp_path)


@router.get(
    "/backups/{filename}/download",
    summary="Download a local backup archive",
)
def download_local_backup(
    filename: str,
    current_user: User = Depends(get_current_user),
) -> FileResponse:
    safe_name = sanitize_backup_filename(filename)
    archive_path = resolve_backup_dir() / safe_name
    if not archive_path.is_file():
        raise ValidationError(f"Backup archive '{safe_name}' not found.")
    return FileResponse(
        path=str(archive_path),
        filename=safe_name,
        media_type="application/octet-stream",
    )


@router.post(
    "/backups/restore",
    summary="Verify and restore a local backup archive",
)
def restore_local_backup(
    payload: BackupRestoreRequest,
    current_user: User = Depends(require_mutating_role),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    safe_name = sanitize_backup_filename(payload.filename)
    archive_path = resolve_backup_dir() / safe_name
    if payload.stage_for_restart:
        result = stage_backup_restore(archive_path)
        record_audit_event(
            db=db,
            action="LOCAL_BACKUP_RESTORE_STAGED",
            resource_type="system_backup",
            resource_identifier=safe_name,
            actor_id=current_user.id,
            metadata={"archive_sha256": result["archive_sha256"]},
        )
        return result

    result = restore_backup_archive(archive_path, engine_to_dispose=engine)
    return result


@router.post(
    "/backups/restore-upload",
    summary="Upload, verify, and restore an external .rmbkp backup archive",
)
async def restore_uploaded_backup(
    file: UploadFile = File(...),
    stage_for_restart: bool = Form(True),
    current_user: User = Depends(require_mutating_role),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    safe_name = sanitize_backup_filename(file.filename or "restore.rmbkp")
    backups_dir = resolve_backup_dir()
    with tempfile.TemporaryDirectory(dir=str(backups_dir)) as tmp_dir_str:
        tmp_path = Path(tmp_dir_str) / safe_name
        with open(tmp_path, "wb") as dst:
            shutil.copyfileobj(file.file, dst)

        if stage_for_restart:
            result = stage_backup_restore(tmp_path)
            record_audit_event(
                db=db,
                action="LOCAL_BACKUP_RESTORE_STAGED",
                resource_type="system_backup",
                resource_identifier=safe_name,
                actor_id=current_user.id,
                metadata={"archive_sha256": result["archive_sha256"], "source": "upload"},
            )
            return result

        return restore_backup_archive(tmp_path, engine_to_dispose=engine)
