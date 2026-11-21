from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, BackgroundTasks, Depends, Query, Response, status
from sqlalchemy.orm import Session

from ....core.audit import record_audit_event
from ....core.auth import get_current_user, require_mutating_role, verify_repository_ownership, verify_scan_ownership
from ....core.errors import ForbiddenError, NotFoundError
from ....core.logging import get_logger
from ....db.session import SessionLocal, get_db
from ....models.repository import Repository
from ....models.scan import Scan
from ....models.user import User
from ....schemas.scan import ScanCreate, ScanRead, ScanResultDetail, ScanStatusResponse, ScannerToolInfo
from ....scanner.registry import scanner_registry
from ....scanner.runner import run_security_scan

logger = get_logger("redmercury.api.scans")
router = APIRouter()


def _execute_background_scan(
    scan_id: str,
    repo_id: str,
    selected_tools: Optional[List[str]],
    timeout_per_tool: int,
) -> None:
    """Executes the security scan pipeline asynchronously in a background worker thread."""
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        repo = db.query(Repository).filter(Repository.id == repo_id).first()
        if not scan or not repo:
            logger.error(f"Cannot execute background scan: Scan {scan_id} or Repo {repo_id} not found.")
            return

        # Atomic transition to prevent duplicate worker execution and race conditions
        rows = (
            db.query(Scan)
            .filter(Scan.id == scan_id, Scan.status.in_(["queued", "pending"]))
            .update({"status": "running", "started_at": datetime.now(timezone.utc)})
        )
        db.commit()
        if rows == 0:
            logger.info(f"Background scan {scan_id} already running, completed, or cancelled.")
            return

        db.refresh(scan)
        run_security_scan(
            repo=repo,
            scan=scan,
            db=db,
            selected_tools=selected_tools,
            timeout_per_tool=timeout_per_tool,
        )
    except Exception as exc:
        logger.error(f"Background scan {scan_id} failed with error: {exc}", exc_info=True)
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan and scan.status not in ("completed", "partial"):
                scan.status = "failed"
                scan.completed_at = datetime.now(timezone.utc)
                scan.summary = json.dumps({"error": f"Internal scan execution error: {str(exc)}"})
                db.commit()
        except Exception:
            pass
    finally:
        db.close()


@router.get(
    "/tools",
    response_model=List[ScannerToolInfo],
    summary="List available security scanning engines and their versions",
)
def get_available_tools(
    current_user: User = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    return scanner_registry.describe_scanners()


@router.get(
    "",
    response_model=List[ScanRead],
    summary="List security scans for repositories owned by the current user",
)
def list_scans(
    repository_id: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[Scan]:
    if repository_id:
        verify_repository_ownership(repo_id=repository_id, current_user=current_user, db=db)
        query = db.query(Scan).filter(Scan.repository_id == repository_id)
    else:
        query = (
            db.query(Scan)
            .join(Repository, Scan.repository_id == Repository.id)
            .filter(Repository.owner_id == current_user.id)
        )

    if status_filter:
        query = query.filter(Scan.status == status_filter)

    return query.offset(skip).limit(limit).all()


@router.post(
    "",
    response_model=ScanRead,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Initiate an asynchronous security scan on a user-owned repository",
)
def create_scan(
    scan_in: ScanCreate,
    response: Response,
    background_tasks: BackgroundTasks,
    sync: bool = Query(False, description="Run scan synchronously (legacy / testing mode)"),
    current_user: User = Depends(require_mutating_role),
    db: Session = Depends(get_db),
) -> Scan:
    # 1. Verify target repository belongs to user
    repo = verify_repository_ownership(repo_id=scan_in.repository_id, current_user=current_user, db=db)

    # 2. Guard against duplicate concurrent scans on the same repository
    active_repo_scan = (
        db.query(Scan)
        .filter(
            Scan.repository_id == scan_in.repository_id,
            Scan.status.in_(["running", "pending", "queued"]),
        )
        .first()
    )
    if active_repo_scan:
        logger.warning(
            f"Duplicate scan rejected: scan {active_repo_scan.id} ({active_repo_scan.status}) already active for repo {repo.id}"
        )
        from ....core.errors import AppSecException
        raise AppSecException(
            message=f"A security scan is already in progress ({active_repo_scan.status}) for this repository. Please wait for scan '{active_repo_scan.id}' to complete or cancel it.",
            code="SCAN_ALREADY_IN_PROGRESS",
            status_code=status.HTTP_409_CONFLICT,
        )

    # 3. Enforce concurrency limits and daily scan quotas
    from ....core.quotas import check_scan_concurrency_and_quota
    check_scan_concurrency_and_quota(user=current_user, db=db)

    # 3. Create persistent scan record in queued state
    initial_status = "pending" if sync else "queued"
    scan = Scan(
        repository_id=scan_in.repository_id,
        status=initial_status,
        scanner_configuration=scan_in.scanner_configuration,
        summary=scan_in.summary or f"Automated scan for {repo.name}",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    record_audit_event(
        db=db,
        action="SCAN_TRIGGERED",
        resource_type="scan",
        resource_identifier=scan.id,
        actor_id=current_user.id,
        metadata={"repository_id": scan.repository_id, "mode": "sync" if sync else "async"},
    )

    if sync:
        # Synchronous execution mode for deterministic integration testing
        response.status_code = status.HTTP_201_CREATED
        scan = run_security_scan(
            repo=repo,
            scan=scan,
            db=db,
            selected_tools=scan_in.tools,
            timeout_per_tool=scan_in.timeout_seconds or 60,
        )
        return scan

    # Default: Non-blocking asynchronous execution returning HTTP 202 Accepted
    response.status_code = status.HTTP_202_ACCEPTED
    background_tasks.add_task(
        _execute_background_scan,
        scan_id=scan.id,
        repo_id=repo.id,
        selected_tools=scan_in.tools,
        timeout_per_tool=scan_in.timeout_seconds or 60,
    )
    return scan


@router.get(
    "/{scan_id}/status",
    response_model=ScanStatusResponse,
    summary="Get real-time execution status for a security scan",
)
def get_scan_status(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ScanStatusResponse:
    scan = verify_scan_ownership(scan_id=scan_id, current_user=current_user, db=db)

    is_complete = scan.status in ("completed", "partial", "failed", "timed_out")
    exec_time = None
    if scan.started_at:
        end_time = scan.completed_at or datetime.now(timezone.utc)
        t_start = scan.started_at if scan.started_at.tzinfo else scan.started_at.replace(tzinfo=timezone.utc)
        t_end = end_time if end_time.tzinfo else end_time.replace(tzinfo=timezone.utc)
        exec_time = max(0.0, round((t_end - t_start).total_seconds(), 2))

    total_findings = None
    error_msg = None
    if scan.summary:
        try:
            s_data = json.loads(scan.summary)
            if isinstance(s_data, dict):
                total_findings = s_data.get("total_findings")
                error_msg = s_data.get("error")
        except Exception:
            pass

    return ScanStatusResponse(
        id=scan.id,
        repository_id=scan.repository_id,
        status=scan.status,
        is_complete=is_complete,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        execution_time_seconds=exec_time,
        total_findings=total_findings,
        error_message=error_msg,
    )


@router.get(
    "/{scan_id}/results",
    response_model=ScanResultDetail,
    summary="Get detailed scanner results and tool execution reports for a scan",
)
def get_scan_results(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ScanResultDetail:
    scan = verify_scan_ownership(scan_id=scan_id, current_user=current_user, db=db)
    repo = scan.repository or db.query(Repository).filter(Repository.id == scan.repository_id).first()

    summary_obj = {}
    if scan.summary:
        try:
            summary_obj = json.loads(scan.summary)
        except Exception:
            summary_obj = {"raw": scan.summary}

    scanners_list = summary_obj.get("scanners", [])
    total_findings = summary_obj.get("total_findings", len(scan.findings))
    health_score_after = summary_obj.get("health_score_after", repo.health_score if repo else 0)

    return ScanResultDetail(
        id=scan.id,
        repository_id=scan.repository_id,
        status=scan.status,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        raw_summary=scan.summary,
        total_findings=total_findings,
        scanners=scanners_list,
        health_score_after=health_score_after,
    )


@router.get(
    "/{scan_id}",
    response_model=ScanRead,
    summary="Get scan details by ID, enforcing repository ownership",
)
def get_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Scan:
    return verify_scan_ownership(scan_id=scan_id, current_user=current_user, db=db)


@router.post(
    "/{scan_id}/cancel",
    response_model=ScanRead,
    summary="Cancel an active, pending, or queued security scan",
)
def cancel_scan(
    scan_id: str,
    current_user: User = Depends(require_mutating_role),
    db: Session = Depends(get_db),
) -> Scan:
    scan = verify_scan_ownership(scan_id=scan_id, current_user=current_user, db=db)

    # Terminal states cannot be cancelled
    if scan.status in ("completed", "partial", "failed", "timed_out", "cancelled"):
        return scan

    scan.status = "cancelled"
    scan.completed_at = datetime.now(timezone.utc)
    scan.summary = json.dumps({"status": "cancelled", "message": "Scan cancelled by user request."})
    db.commit()
    db.refresh(scan)

    record_audit_event(
        db=db,
        action="SCAN_CANCELLED",
        resource_type="scan",
        resource_identifier=scan.id,
        actor_id=current_user.id,
        metadata={"repository_id": scan.repository_id},
    )
    return scan
