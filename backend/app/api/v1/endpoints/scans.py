from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
import uuid
from fastapi import APIRouter, Depends, Header, Query, Response, status
from sqlalchemy.orm import Session

from ....core.audit import record_audit_event
from ....core.auth import get_current_user, require_mutating_role, verify_repository_ownership, verify_scan_ownership
from ....core.config import settings
from ....core.errors import AppSecException, ForbiddenError, NotFoundError
from ....core.jobs import (
    JobState,
    TERMINAL_JOB_STATES,
    cancel_durable_job,
    claim_durable_job_by_id,
    create_durable_job_with_outbox,
    dispatch_outbox_events,
    execute_claimed_durable_job,
    get_existing_idempotent_job,
    sanitize_job_error_detail,
)
from ....core.logging import get_logger
from ....db.session import get_db
from ....models.job import DurableJob
from ....models.repository import Repository
from ....models.scan import Scan
from ....models.user import User
from ....schemas.scan import ScanCreate, ScanRead, ScanResultDetail, ScanStatusResponse, ScannerToolInfo
from ....scanner.registry import scanner_registry

logger = get_logger("redmercury.api.scans")
router = APIRouter()


def _drain_local_auto_job_if_eligible(db: Session, scan: Scan) -> Scan:
    """In single-process local development ('auto' mode), claim and execute a non-enqueue_only queued scan on poll.

    Never executes in strict environments ('production', 'staging'), when JOB_DISPATCH_MODE == 'queue_only',
    when enqueue_only was requested, or when an external worker has claimed or touched the job.
    """
    if settings.is_strict_env or settings.JOB_DISPATCH_MODE.lower() == "queue_only":
        return scan
    if scan.status not in ("queued", "pending"):
        return scan

    djob = (
        db.query(DurableJob)
        .filter(DurableJob.job_type == "scan", DurableJob.resource_id == scan.id)
        .first()
    )
    if djob is None:
        return scan
    if djob.status != JobState.QUEUED.value or djob.attempt_count > 0 or djob.worker_id is not None:
        return scan

    payload = {}
    if djob.payload_json:
        try:
            payload = json.loads(djob.payload_json)
        except Exception:
            payload = {}
    if payload.get("enqueue_only"):
        return scan

    claimed = claim_durable_job_by_id(db=db, job_id=djob.id, worker_id="local-auto-worker")
    if claimed is not None:
        execute_claimed_durable_job(
            db=db,
            job=claimed,
            worker_id="local-auto-worker",
            start_heartbeat=False,
        )
        db.refresh(scan)
    return scan


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
    summary="Enqueue a durable security scan on a user-owned repository",
)
def create_scan(
    scan_in: ScanCreate,
    response: Response,
    sync: bool = Query(False, description="Run scan synchronously via durable job worker (testing mode)"),
    enqueue_only: bool = Query(False, description=" strictly enqueue job for worker consumption without auto-drain"),
    idempotency_key_header: Optional[str] = Header(None, alias="Idempotency-Key"),
    current_user: User = Depends(require_mutating_role),
    db: Session = Depends(get_db),
) -> Scan:
    # 1. Verify target repository belongs to user
    repo = verify_repository_ownership(repo_id=scan_in.repository_id, current_user=current_user, db=db)

    # 2. Check tenant-scoped idempotency key before creating new records (Task 4)
    effective_idem_key = (idempotency_key_header or scan_in.idempotency_key or "").strip() or None
    if effective_idem_key:
        existing_job = get_existing_idempotent_job(
            db=db,
            tenant_id=current_user.id,
            job_type="scan",
            idempotency_key=effective_idem_key,
        )
        if existing_job is not None:
            existing_scan = db.query(Scan).filter(Scan.id == existing_job.resource_id).first()
            if existing_scan is not None:
                if existing_scan.repository_id != repo.id:
                    raise AppSecException(
                        message="Idempotency key is already bound to a different repository scan request.",
                        code="IDEMPOTENCY_KEY_CONFLICT",
                        status_code=status.HTTP_409_CONFLICT,
                    )
                response.status_code = status.HTTP_201_CREATED if sync else status.HTTP_202_ACCEPTED
                return existing_scan

    # 3. Create Scan, DurableJob, ActiveJobSlot (atomic concurrency & single-active-repo lock), and JobOutboxEvent
    #    in a SINGLE atomic database transaction (Tasks 1, 2, 4, 5)
    scan_id = str(uuid.uuid4())
    initial_status = "queued"
    scan = Scan(
        id=scan_id,
        repository_id=scan_in.repository_id,
        status=initial_status,
        scanner_configuration=scan_in.scanner_configuration,
        summary=scan_in.summary or f"Automated scan for {repo.name}",
    )
    job_payload = {
        "repository_id": repo.id,
        "tools": scan_in.tools,
        "timeout_seconds": scan_in.timeout_seconds or 60,
        "scanner_configuration": scan_in.scanner_configuration,
        "enqueue_only": bool(enqueue_only),
    }

    try:
        db.add(scan)
        db.flush()

        job, outbox, is_new = create_durable_job_with_outbox(
            db=db,
            user=current_user,
            job_type="scan",
            resource_id=scan.id,
            repository_id=repo.id,
            payload=job_payload,
            idempotency_key=effective_idem_key,
            reserve_slot=True,
        )
    except Exception:
        db.rollback()
        raise

    if not is_new:
        # Concurrent request with identical idempotency key won the race
        db.rollback()
        existing_scan = db.query(Scan).filter(Scan.id == job.resource_id).first()
        if existing_scan:
            response.status_code = status.HTTP_201_CREATED if sync else status.HTTP_202_ACCEPTED
            return existing_scan

    db.commit()
    db.refresh(scan)
    db.refresh(job)

    record_audit_event(
        db=db,
        action="SCAN_TRIGGERED",
        resource_type="scan",
        resource_identifier=scan.id,
        actor_id=current_user.id,
        metadata={
            "repository_id": scan.repository_id,
            "job_id": job.id,
            "mode": "sync" if sync else "durable_async",
        },
    )

    # 4. Dispatch transactional outbox event to Redis (fault-tolerant: DB remains authoritative if Redis is down)
    dispatch_outbox_events(db=db, job_id=job.id)

    if sync:
        response.status_code = status.HTTP_201_CREATED
        claimed = claim_durable_job_by_id(db=db, job_id=job.id, worker_id="api-sync-worker")
        if claimed is not None:
            execute_claimed_durable_job(
                db=db,
                job=claimed,
                worker_id="api-sync-worker",
                start_heartbeat=False,
            )
        db.refresh(scan)
        return scan

    # Default: Durable asynchronous job queued for worker consumption (HTTP 202 Accepted)
    response.status_code = status.HTTP_202_ACCEPTED
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
    scan = _drain_local_auto_job_if_eligible(db=db, scan=scan)

    djob = (
        db.query(DurableJob)
        .filter(DurableJob.job_type == "scan", DurableJob.resource_id == scan.id)
        .first()
    )

    effective_status = scan.status
    if djob is not None and djob.status in (
        JobState.RETRYING.value,
        JobState.CANCELLING.value,
        JobState.CANCELLED.value,
        JobState.INTERRUPTED.value,
    ):
        effective_status = djob.status

    is_complete = effective_status in ("completed", "partial", "failed", "timed_out", "cancelled", "interrupted")
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
                raw_err = s_data.get("error")
                if raw_err:
                    error_msg = sanitize_job_error_detail(str(raw_err))
        except Exception:
            pass

    if not error_msg and djob is not None and djob.error_detail:
        error_msg = sanitize_job_error_detail(djob.error_detail)

    return ScanStatusResponse(
        id=scan.id,
        repository_id=scan.repository_id,
        status=effective_status,
        is_complete=is_complete,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        execution_time_seconds=exec_time,
        total_findings=total_findings,
        error_message=error_msg,
        job_id=djob.id if djob else None,
        attempt_count=djob.attempt_count if djob else 0,
        max_attempts=djob.max_attempts if djob else settings.JOB_MAX_ATTEMPTS,
        worker_id=djob.worker_id if djob else None,
        heartbeat_at=djob.heartbeat_at if djob else None,
        lease_expires_at=djob.lease_expires_at if djob else None,
        next_retry_at=djob.next_retry_at if djob else None,
        failure_category=djob.failure_category if djob else None,
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
    scan = _drain_local_auto_job_if_eligible(db=db, scan=scan)
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
    summary="Cancel an active, pending, or queued security scan and terminate running subprocesses",
)
def cancel_scan(
    scan_id: str,
    current_user: User = Depends(require_mutating_role),
    db: Session = Depends(get_db),
) -> Scan:
    scan = verify_scan_ownership(scan_id=scan_id, current_user=current_user, db=db)

    djob = (
        db.query(DurableJob)
        .filter(DurableJob.job_type == "scan", DurableJob.resource_id == scan.id)
        .first()
    )

    # Idempotent return if already terminal
    if scan.status in ("completed", "partial", "failed", "timed_out", "cancelled", "interrupted"):
        if djob and djob.status not in TERMINAL_JOB_STATES:
            cancel_durable_job(
                db=db,
                job=djob,
                resource_type="scan",
                resource_id=scan.id,
                actor_id=current_user.id,
            )
        return scan

    cancel_durable_job(
        db=db,
        job=djob,
        resource_type="scan",
        resource_id=scan.id,
        actor_id=current_user.id,
    )
    db.refresh(scan)

    record_audit_event(
        db=db,
        action="SCAN_CANCELLED",
        resource_type="scan",
        resource_identifier=scan.id,
        actor_id=current_user.id,
        metadata={"repository_id": scan.repository_id, "job_id": djob.id if djob else None},
    )
    return scan
