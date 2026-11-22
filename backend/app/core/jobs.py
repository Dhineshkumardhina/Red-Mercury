"""Durable Background Job Execution, Transactional Outbox, Atomic Lease Claiming, Crash Recovery & Cancellation Engine (Phase 6 / REL-01).

Implements:
1. Centralized Job State Machine (queued, running, retrying, completed, failed, cancelling, cancelled, interrupted).
2. Transactional Outbox pattern eliminating the database/Redis dual-write vulnerability.
3. PostgreSQL FOR UPDATE SKIP LOCKED and cross-dialect atomic CAS job claiming with lease fencing tokens.
4. Tenant-scoped idempotency key deduplication enforced at the database level.
5. Database-enforced atomic quota and concurrency slot reservation (ActiveJobSlot).
6. Periodic worker heartbeats, lease expiration detection, and bounded exponential backoff + jitter retries.
7. Real cancellation propagating to scanner subprocess trees, Docker sandbox containers, and confined temp workspaces.
8. Idempotent API startup and worker startup reconciliation.
"""
from datetime import datetime, timedelta, timezone
from enum import Enum
import json
import os
from pathlib import Path
import platform
import random
import re
import shutil
import signal
import socket
import subprocess
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import uuid

from sqlalchemy import event, func, or_, text
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from .audit import record_audit_event
from .config import settings
from .errors import AppSecException, ForbiddenError, NotFoundError, SecurityPolicyViolationError, ValidationError
from .logging import get_logger, scrub_log_message
from ..models.finding import SecurityFinding
from ..models.github import PullRequestScan, WebhookDelivery
from ..models.job import ActiveJobSlot, DurableJob, JobOutboxEvent
from ..models.repository import Repository
from ..models.scan import Scan
from ..models.user import User
from ..models.verification import VerificationRun

logger = get_logger("redmercury.core.jobs")


class JobState(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    RETRYING = "retrying"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLING = "cancelling"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"


TERMINAL_JOB_STATES: Set[str] = {
    JobState.COMPLETED.value,
    JobState.FAILED.value,
    JobState.CANCELLED.value,
    JobState.INTERRUPTED.value,
}

ACTIVE_JOB_STATES: Set[str] = {
    JobState.QUEUED.value,
    JobState.RUNNING.value,
    JobState.RETRYING.value,
    JobState.CANCELLING.value,
}

# Centralized valid state transitions (Task 2 Requirement 1 & 2)
VALID_JOB_STATE_TRANSITIONS: Dict[str, Set[str]] = {
    JobState.QUEUED.value: {
        JobState.RUNNING.value,
        JobState.CANCELLING.value,
        JobState.CANCELLED.value,
        JobState.FAILED.value,
        JobState.INTERRUPTED.value,
    },
    JobState.RUNNING.value: {
        JobState.COMPLETED.value,
        JobState.RETRYING.value,
        JobState.FAILED.value,
        JobState.CANCELLING.value,
        JobState.CANCELLED.value,
        JobState.INTERRUPTED.value,
        JobState.QUEUED.value,  # Graceful worker shutdown lease release
    },
    JobState.RETRYING.value: {
        JobState.QUEUED.value,
        JobState.RUNNING.value,
        JobState.CANCELLING.value,
        JobState.CANCELLED.value,
        JobState.FAILED.value,
        JobState.INTERRUPTED.value,
    },
    JobState.CANCELLING.value: {
        JobState.CANCELLED.value,
        JobState.FAILED.value,
        JobState.INTERRUPTED.value,
    },
    JobState.INTERRUPTED.value: {
        JobState.QUEUED.value,
        JobState.RUNNING.value,
        JobState.RETRYING.value,
        JobState.FAILED.value,
        JobState.CANCELLED.value,
    },
    JobState.COMPLETED.value: set(),
    JobState.FAILED.value: set(),
    JobState.CANCELLED.value: set(),
}


class InvalidJobStateTransitionError(ValidationError):
    """Raised when an invalid job state transition is attempted."""
    def __init__(self, current_state: str, target_state: str, job_id: Optional[str] = None):
        prefix = f"Job '{job_id}': " if job_id else ""
        super().__init__(
            f"{prefix}Invalid job state transition from '{current_state}' to '{target_state}'."
        )


class StaleWorkerLeaseError(AppSecException):
    """Raised when a worker attempts to mutate a job after its lease expired or was reassigned."""
    def __init__(self, job_id: str, worker_id: str):
        super().__init__(
            message=f"Worker '{worker_id}' no longer holds a valid lease for job '{job_id}'.",
            code="STALE_WORKER_LEASE",
            status_code=409,
        )


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def validate_job_transition(current_state: str, target_state: str, job_id: Optional[str] = None) -> None:
    """Enforce centralized state machine transition rules."""
    curr = (current_state or "").strip().lower()
    targ = (target_state or "").strip().lower()
    if curr == targ and curr in (JobState.CANCELLED.value, JobState.CANCELLING.value):
        # Idempotent cancellation request
        return
    allowed = VALID_JOB_STATE_TRANSITIONS.get(curr)
    if allowed is None or targ not in allowed:
        raise InvalidJobStateTransitionError(curr, targ, job_id=job_id)


def sanitize_job_error_detail(raw_error: Optional[str], max_length: int = 400) -> str:
    """Scrub secrets, credentials, and raw tracebacks from error details before persistence/API display."""
    if not raw_error:
        return "Job execution encountered an error."
    first_line = str(raw_error).strip().splitlines()[0]
    scrubbed = scrub_log_message(first_line)
    # Strip internal file system stack trace prefixes if any
    scrubbed = re.sub(r'File "[^"]+", line \d+.*', "Internal execution error", scrubbed)
    return scrubbed[:max_length]


# ==============================================================================
# Redis Queue Client & Fault-Tolerant Outbox Dispatcher
# ==============================================================================

_REDIS_CLIENT_OVERRIDE: Optional[Any] = None


def set_redis_client_override(client: Optional[Any]) -> None:
    """Allow integration tests to inject a live or fault-injecting Redis client."""
    global _REDIS_CLIENT_OVERRIDE
    _REDIS_CLIENT_OVERRIDE = client


def get_job_redis_client() -> Optional[Any]:
    """Return a configured Redis client if REDIS_URL is set, or None."""
    if _REDIS_CLIENT_OVERRIDE is not None:
        return _REDIS_CLIENT_OVERRIDE
    if not settings.REDIS_URL:
        return None
    try:
        import redis
        return redis.Redis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=1.5,
            socket_timeout=1.5,
        )
    except Exception as exc:
        logger.warning(f"Unable to initialize Redis client for job dispatch: {scrub_log_message(str(exc))}")
        return None


# Operational metrics counters (in-process + DB query synthesis for Task 12)
_JOB_METRICS = {
    "dispatch_latencies_ms": [],
    "execution_durations_ms": [],
    "cancellation_latencies_ms": [],
}
_METRICS_LOCK = threading.Lock()


def _record_metric_sample(key: str, value_ms: float) -> None:
    with _METRICS_LOCK:
        bucket = _JOB_METRICS.get(key)
        if bucket is not None:
            bucket.append(max(0.0, float(value_ms)))
            if len(bucket) > 200:
                del bucket[:-200]


def dispatch_outbox_events(
    db: Session,
    job_id: Optional[str] = None,
    limit: int = 50,
    redis_client: Optional[Any] = None,
) -> int:
    """Dispatch pending transactional outbox events to Redis.

    Uses PostgreSQL FOR UPDATE SKIP LOCKED (when running on PostgreSQL) so concurrent
    outbox dispatchers/recovery sweeps never select or push the same pending event twice.
    Marks each event as 'dispatched' ONLY after Redis confirms RPUSH succeeded.
    """
    client = redis_client if redis_client is not None else get_job_redis_client()
    dialect = db.bind.dialect.name if db.bind is not None else "sqlite"

    query = db.query(JobOutboxEvent).filter(JobOutboxEvent.status == "pending")
    if job_id:
        query = query.filter(JobOutboxEvent.job_id == job_id)
    query = query.order_by(JobOutboxEvent.created_at.asc()).limit(limit)

    if dialect == "postgresql":
        query = query.with_for_update(skip_locked=True)

    pending_events = query.all()
    if not pending_events:
        if dialect == "postgresql":
            db.rollback()
        return 0

    dispatched_count = 0
    now = _utc_now()

    for event in pending_events:
        job = db.query(DurableJob).filter(DurableJob.id == event.job_id).first()
        if not job or job.status in TERMINAL_JOB_STATES or job.status == JobState.CANCELLING.value:
            event.status = "cancelled"
            event.updated_at = now
            continue

        if client is None:
            # No Redis configured or reachable; event stays pending in DB for DB-polling workers or later Redis recovery
            event.dispatch_attempts = (event.dispatch_attempts or 0) + 1
            event.last_error = "Redis client not configured or unavailable"
            event.updated_at = now
            continue

        message = json.dumps({
            "outbox_id": event.id,
            "job_id": job.id,
            "job_type": job.job_type,
            "resource_id": job.resource_id,
            "enqueued_at": now.isoformat(),
        })
        try:
            client.rpush(event.queue_name or settings.JOB_QUEUE_NAME, message)
            event.status = "dispatched"
            event.dispatch_attempts = (event.dispatch_attempts or 0) + 1
            event.dispatched_at = now
            event.last_error = None
            event.updated_at = now
            dispatched_count += 1
            created_utc = _ensure_utc(event.created_at) or now
            _record_metric_sample("dispatch_latencies_ms", (now - created_utc).total_seconds() * 1000.0)
        except Exception as exc:
            event.dispatch_attempts = (event.dispatch_attempts or 0) + 1
            event.last_error = sanitize_job_error_detail(str(exc), max_length=250)
            event.updated_at = _utc_now()
            logger.warning(
                f"[job:{event.job_id}] Outbox event '{event.id}' Redis dispatch failed "
                f"(will recover via outbox sweep): {sanitize_job_error_detail(str(exc))}"
            )

    try:
        db.commit()
    except Exception:
        db.rollback()
        return 0

    return dispatched_count


def recover_undispatched_outbox_events(
    db: Session,
    limit: int = 100,
    redis_client: Optional[Any] = None,
) -> int:
    """Sweep and dispatch any pending outbox events left behind by temporary Redis outages or restarts."""
    return dispatch_outbox_events(db=db, job_id=None, limit=limit, redis_client=redis_client)


def pop_job_from_redis_queue(
    queue_name: Optional[str] = None,
    redis_client: Optional[Any] = None,
) -> Optional[Dict[str, Any]]:
    """Non-blocking LPOP from the Redis job notification queue.

    Note: The worker NEVER trusts tenant identity or state from the Redis message;
    it uses only job_id as a wake-up hint and atomically claims the authoritative DB record.
    """
    client = redis_client if redis_client is not None else get_job_redis_client()
    if client is None:
        return None
    q_name = queue_name or settings.JOB_QUEUE_NAME
    try:
        raw = client.lpop(q_name)
        if not raw:
            return None
        data = json.loads(raw) if isinstance(raw, str) else json.loads(raw.decode("utf-8"))
        if isinstance(data, dict) and data.get("job_id"):
            return data
        return None
    except Exception as exc:
        logger.warning(f"Redis queue LPOP failed (falling back to DB polling): {sanitize_job_error_detail(str(exc))}")
        return None


# ==============================================================================
# Atomic Quota & Concurrency Slot Reservation (Task 5)
# ==============================================================================

def _cleanup_stale_active_slots(db: Session, tenant_id: str, job_type: str) -> None:
    """Release any ActiveJobSlot whose parent DurableJob or underlying Scan/VerificationRun is already terminal."""
    slots = (
        db.query(ActiveJobSlot)
        .filter(ActiveJobSlot.tenant_id == tenant_id, ActiveJobSlot.job_type == job_type)
        .all()
    )
    for slot in slots:
        job = db.query(DurableJob).filter(DurableJob.id == slot.job_id).first()
        if not job or job.status in TERMINAL_JOB_STATES:
            db.delete(slot)
            if job and job.quota_reserved:
                job.quota_reserved = False
            continue
        if job.job_type == "scan":
            scan = db.query(Scan).filter(Scan.id == job.resource_id).first()
            if not scan or scan.status in ("completed", "partial", "failed", "timed_out", "cancelled", "interrupted"):
                db.delete(slot)
                job.quota_reserved = False
                if scan and job.status not in TERMINAL_JOB_STATES:
                    job.status = JobState.COMPLETED.value if scan.status in ("completed", "partial") else JobState.FAILED.value
        elif job.job_type == "verification":
            run = db.query(VerificationRun).filter(VerificationRun.id == job.resource_id).first()
            if not run or run.status in (
                "VERIFIED_AGAINST_DEFINED_CHECKS",
                "FAILED_VERIFICATION",
                "INCONCLUSIVE",
                "COMPLETED",
                "CANCELLED",
                "INTERRUPTED",
            ):
                db.delete(slot)
                job.quota_reserved = False
    db.flush()


def reserve_atomic_job_slot(
    db: Session,
    job: DurableJob,
    user: User,
    repository_id: Optional[str] = None,
) -> ActiveJobSlot:
    """Atomically reserve a concurrency slot and active repository lock in the database.

    Uses database-level UniqueConstraints on `active_job_slots`:
    - `ix_active_job_slots_repository_active_lock` prevents concurrent active scans on the same repository (409 Conflict).
    - `uq_active_job_slots_tenant_type_slot` prevents concurrent requests from exceeding MAX_CONCURRENT_*_PER_USER.
    """
    _cleanup_stale_active_slots(db, tenant_id=user.id, job_type=job.job_type)

    # 1. For scans, also verify no legacy raw Scan row is currently active on the same repository
    repo_lock_key: Optional[str] = None
    if job.job_type == "scan" and repository_id:
        repo_lock_key = f"scan:{repository_id}"
        active_repo_scan = (
            db.query(Scan)
            .filter(
                Scan.repository_id == repository_id,
                Scan.id != job.resource_id,
                Scan.status.in_(["running", "pending", "queued", "retrying", "cancelling"]),
            )
            .first()
        )
        if active_repo_scan:
            raise AppSecException(
                message=(
                    f"A security scan is already in progress ({active_repo_scan.status}) for this repository. "
                    f"Please wait for scan '{active_repo_scan.id}' to complete or cancel it."
                ),
                code="SCAN_ALREADY_IN_PROGRESS",
                status_code=409,
            )

    # 2. Enforce daily 24-hour quota for scans (serialize per-tenant on PostgreSQL via xact advisory lock,
    # avoiding FOR UPDATE vs FK FOR KEY SHARE deadlocks on the users table)
    if job.job_type == "scan":
        dialect = db.bind.dialect.name if db.bind is not None else "sqlite"
        if dialect == "postgresql":
            db.execute(
                text("SELECT pg_advisory_xact_lock(hashtext(:uid))"),
                {"uid": str(user.id)},
            )
        cutoff = _utc_now() - timedelta(hours=24)
        # Count scans in last 24h excluding cancelled-before-execution scans
        daily_scans_count = (
            db.query(Scan)
            .join(Repository, Scan.repository_id == Repository.id)
            .filter(
                Repository.owner_id == user.id,
                Scan.id != job.resource_id,
                Scan.created_at >= cutoff,
                ~Scan.status.in_(["cancelled"]),
            )
            .count()
        )
        if daily_scans_count >= settings.MAX_DAILY_SCANS_PER_USER:
            raise SecurityPolicyViolationError(
                f"Daily scan quota exceeded: you have executed {daily_scans_count} scans in the last 24 hours. "
                f"Maximum quota is {settings.MAX_DAILY_SCANS_PER_USER} scans per day."
            )

    # 3. Determine concurrency ceiling and account for any legacy raw rows without ActiveJobSlot
    if job.job_type == "scan":
        max_concurrent = max(1, int(settings.MAX_CONCURRENT_SCANS_PER_USER))
        legacy_active_count = (
            db.query(Scan)
            .join(Repository, Scan.repository_id == Repository.id)
            .outerjoin(
                DurableJob,
                (DurableJob.resource_id == Scan.id) & (DurableJob.job_type == "scan"),
            )
            .filter(
                Repository.owner_id == user.id,
                Scan.id != job.resource_id,
                Scan.status.in_(["running", "pending", "queued", "retrying", "cancelling"]),
                DurableJob.id.is_(None),
            )
            .count()
        )
    elif job.job_type == "verification":
        max_concurrent = max(1, int(settings.MAX_CONCURRENT_VERIFICATIONS_PER_USER))
        legacy_active_count = (
            db.query(VerificationRun)
            .join(SecurityFinding, VerificationRun.finding_id == SecurityFinding.id)
            .join(Repository, SecurityFinding.repo_id == Repository.id)
            .outerjoin(
                DurableJob,
                (DurableJob.resource_id == VerificationRun.id) & (DurableJob.job_type == "verification"),
            )
            .filter(
                Repository.owner_id == user.id,
                VerificationRun.id != job.resource_id,
                VerificationRun.status.in_(["RUNNING", "QUEUED", "RETRYING", "CANCELLING", "queued", "running"]),
                DurableJob.id.is_(None),
            )
            .count()
        )
    else:
        max_concurrent = 10
        legacy_active_count = 0

    usable_slots = max(0, max_concurrent - legacy_active_count)
    if usable_slots <= 0:
        label = "scans" if job.job_type == "scan" else "fix verifications"
        raise SecurityPolicyViolationError(
            f"Concurrency limit reached: you currently have {max_concurrent} {label} in progress. "
            f"Maximum allowed concurrent {label} is {max_concurrent}."
        )

    # 4. Try reserving a numbered slot [1 .. usable_slots] enforced by database UniqueConstraint
    occupied_slots = {
        row[0]
        for row in db.query(ActiveJobSlot.slot_number)
        .filter(ActiveJobSlot.tenant_id == user.id, ActiveJobSlot.job_type == job.job_type)
        .all()
    }

    for slot_num in range(1, usable_slots + 1):
        if slot_num in occupied_slots:
            continue
        candidate_slot = ActiveJobSlot(
            job_id=job.id,
            tenant_id=user.id,
            job_type=job.job_type,
            slot_number=slot_num,
            repository_active_lock=repo_lock_key,
        )
        try:
            with db.begin_nested():
                db.add(candidate_slot)
                db.flush()
            job.quota_reserved = True
            return candidate_slot
        except IntegrityError as exc:
            err_text = str(exc).lower()
            if repo_lock_key and ("repository_active_lock" in err_text or "repo_lock" in err_text):
                raise AppSecException(
                    message="A security scan is already in progress for this repository.",
                    code="SCAN_ALREADY_IN_PROGRESS",
                    status_code=409,
                )
            # Slot number was concurrently claimed by another transaction; try next slot_num
            continue

    # Double-check if failure was due to repository_active_lock collision
    if repo_lock_key:
        existing_repo_lock = (
            db.query(ActiveJobSlot)
            .filter(ActiveJobSlot.repository_active_lock == repo_lock_key)
            .first()
        )
        if existing_repo_lock:
            raise AppSecException(
                message="A security scan is already in progress for this repository.",
                code="SCAN_ALREADY_IN_PROGRESS",
                status_code=409,
            )

    label = "scans" if job.job_type == "scan" else "fix verifications"
    raise SecurityPolicyViolationError(
        f"Concurrency limit reached: you currently have {max_concurrent} {label} in progress. "
        f"Maximum allowed concurrent {label} is {max_concurrent}."
    )


def release_atomic_job_slot(db: Session, job: DurableJob, count_quota: bool) -> None:
    """Release active concurrency and repository lock slot upon terminal state transition."""
    db.query(ActiveJobSlot).filter(ActiveJobSlot.job_id == job.id).delete(synchronize_session=False)
    job.quota_reserved = False
    if count_quota and not job.quota_counted:
        job.quota_counted = True
    elif not count_quota:
        job.quota_counted = False


# ==============================================================================
# Transactional Job Creation & Idempotency (Tasks 1, 2, 4, 5)
# ==============================================================================

def get_existing_idempotent_job(
    db: Session,
    tenant_id: str,
    job_type: str,
    idempotency_key: Optional[str],
) -> Optional[DurableJob]:
    """Lookup an existing job by tenant-scoped idempotency key."""
    if not idempotency_key or not str(idempotency_key).strip():
        return None
    clean_key = str(idempotency_key).strip()[:128]
    return (
        db.query(DurableJob)
        .filter(
            DurableJob.tenant_id == tenant_id,
            DurableJob.job_type == job_type,
            DurableJob.idempotency_key == clean_key,
        )
        .first()
    )


def create_durable_job_with_outbox(
    db: Session,
    user: User,
    job_type: str,
    resource_id: str,
    repository_id: Optional[str],
    payload: Dict[str, Any],
    idempotency_key: Optional[str] = None,
    max_attempts: Optional[int] = None,
    reserve_slot: bool = True,
) -> Tuple[DurableJob, JobOutboxEvent, bool]:
    """Create a DurableJob, ActiveJobSlot, and JobOutboxEvent in the current database transaction.

    Returns:
        (job, outbox_event, is_new)
    """
    clean_idem = str(idempotency_key).strip()[:128] if idempotency_key and str(idempotency_key).strip() else None
    if clean_idem:
        existing = get_existing_idempotent_job(db, tenant_id=user.id, job_type=job_type, idempotency_key=clean_idem)
        if existing:
            outbox = (
                db.query(JobOutboxEvent)
                .filter(JobOutboxEvent.job_id == existing.id)
                .order_by(JobOutboxEvent.created_at.desc())
                .first()
            )
            return existing, outbox, False

    job = DurableJob(
        id=str(uuid.uuid4()),
        job_type=job_type,
        resource_id=resource_id,
        tenant_id=user.id,
        repository_id=repository_id,
        idempotency_key=clean_idem,
        status=JobState.QUEUED.value,
        payload_json=json.dumps(payload or {}),
        attempt_count=0,
        max_attempts=max_attempts if max_attempts is not None else settings.JOB_MAX_ATTEMPTS,
        quota_reserved=reserve_slot,
        quota_counted=False,
    )

    try:
        with db.begin_nested():
            db.add(job)
            db.flush()
            if reserve_slot:
                reserve_atomic_job_slot(db=db, job=job, user=user, repository_id=repository_id)
            outbox = JobOutboxEvent(
                id=str(uuid.uuid4()),
                job_id=job.id,
                job_type=job_type,
                resource_id=resource_id,
                queue_name=settings.JOB_QUEUE_NAME,
                status="pending",
                dispatch_attempts=0,
            )
            db.add(outbox)
            db.flush()
        return job, outbox, True
    except IntegrityError:
        if clean_idem:
            existing = get_existing_idempotent_job(db, tenant_id=user.id, job_type=job_type, idempotency_key=clean_idem)
            if existing:
                outbox = (
                    db.query(JobOutboxEvent)
                    .filter(JobOutboxEvent.job_id == existing.id)
                    .order_by(JobOutboxEvent.created_at.desc())
                    .first()
                )
                return existing, outbox, False
        raise


# ==============================================================================
# Atomic Job Claiming, Lease Fencing & Heartbeats (Tasks 3 & 6)
# ==============================================================================

def claim_durable_job_by_id(
    db: Session,
    job_id: str,
    worker_id: str,
    lease_seconds: Optional[int] = None,
) -> Optional[DurableJob]:
    """Atomically claim a specific queued/retrying job by ID with a new fencing lease_token."""
    now = _utc_now()
    lease_dur = lease_seconds if lease_seconds is not None else settings.JOB_LEASE_DURATION_SECONDS
    lease_exp = now + timedelta(seconds=max(1, int(lease_dur)))
    new_token = uuid.uuid4().hex

    dialect = db.bind.dialect.name if db.bind is not None else "sqlite"

    if dialect == "postgresql":
        row = db.execute(
            text(
                """
                SELECT id, started_at
                FROM durable_jobs
                WHERE id = :job_id
                  AND status IN ('queued', 'retrying')
                  AND (next_retry_at IS NULL OR next_retry_at <= :now)
                FOR UPDATE SKIP LOCKED
                """
            ),
            {"job_id": job_id, "now": now},
        ).fetchone()
        if not row:
            db.rollback()
            return None

    updated = (
        db.query(DurableJob)
        .filter(
            DurableJob.id == job_id,
            DurableJob.status.in_([JobState.QUEUED.value, JobState.RETRYING.value]),
            or_(DurableJob.next_retry_at.is_(None), DurableJob.next_retry_at <= now),
        )
        .update(
            {
                "status": JobState.RUNNING.value,
                "worker_id": worker_id,
                "lease_token": new_token,
                "lease_expires_at": lease_exp,
                "heartbeat_at": now,
                "started_at": now,
                "attempt_count": DurableJob.attempt_count + 1,
                "updated_at": now,
            },
            synchronize_session=False,
        )
    )
    if updated != 1:
        db.rollback()
        return None

    # Synchronize underlying resource status to running in the same transaction
    job = db.query(DurableJob).filter(DurableJob.id == job_id).first()
    if not job:
        db.rollback()
        return None
    db.refresh(job)
    if job.lease_token != new_token:
        db.rollback()
        return None

    if job.job_type == "scan":
        db.query(Scan).filter(Scan.id == job.resource_id).update(
            {"status": "running", "started_at": now, "updated_at": now},
            synchronize_session=False,
        )
    elif job.job_type == "verification":
        db.query(VerificationRun).filter(VerificationRun.id == job.resource_id).update(
            {"status": "RUNNING", "started_at": now, "updated_at": now},
            synchronize_session=False,
        )

    db.commit()
    db.refresh(job)
    logger.info(
        f"[job:{job.id}] Worker '{worker_id}' claimed {job.job_type} job "
        f"(resource={job.resource_id}, attempt={job.attempt_count}/{job.max_attempts}, lease_token={new_token[:8]})"
    )
    return job


def claim_next_durable_job(
    db: Session,
    worker_id: str,
    job_types: Optional[List[str]] = None,
    lease_seconds: Optional[int] = None,
    redis_client: Optional[Any] = None,
) -> Optional[DurableJob]:
    """Atomically claim the next available queued or due-for-retry job.

    1. First checks Redis queue notification for O(1) dispatch wake-up.
    2. Falls back to authoritative database scan using PostgreSQL FOR UPDATE SKIP LOCKED
       (or atomic conditional UPDATE on SQLite) so jobs are processed even if Redis was down.
    """
    # 1. Try Redis queue wake-up hint first
    for _ in range(5):
        msg = pop_job_from_redis_queue(redis_client=redis_client)
        if not msg:
            break
        cand_id = msg.get("job_id")
        if cand_id:
            claimed = claim_durable_job_by_id(
                db=db,
                job_id=str(cand_id),
                worker_id=worker_id,
                lease_seconds=lease_seconds,
            )
            if claimed is not None:
                return claimed

    # 2. Authoritative database claim
    now = _utc_now()
    dialect = db.bind.dialect.name if db.bind is not None else "sqlite"

    if dialect == "postgresql":
        type_clause = ""
        params: Dict[str, Any] = {"now": now}
        if job_types:
            placeholders = ", ".join(f":jt_{i}" for i in range(len(job_types)))
            type_clause = f"AND job_type IN ({placeholders})"
            for i, jt in enumerate(job_types):
                params[f"jt_{i}"] = jt

        row = db.execute(
            text(
                f"""
                SELECT id
                FROM durable_jobs
                WHERE status IN ('queued', 'retrying')
                  AND (next_retry_at IS NULL OR next_retry_at <= :now)
                  {type_clause}
                ORDER BY created_at ASC
                LIMIT 1
                FOR UPDATE SKIP LOCKED
                """
            ),
            params,
        ).fetchone()
        if not row:
            db.rollback()
            return None
        return claim_durable_job_by_id(
            db=db,
            job_id=str(row[0]),
            worker_id=worker_id,
            lease_seconds=lease_seconds,
        )

    # Cross-dialect / SQLite atomic CAS loop
    query = db.query(DurableJob.id).filter(
        DurableJob.status.in_([JobState.QUEUED.value, JobState.RETRYING.value]),
        or_(DurableJob.next_retry_at.is_(None), DurableJob.next_retry_at <= now),
    )
    if job_types:
        query = query.filter(DurableJob.job_type.in_(job_types))

    candidates = [r[0] for r in query.order_by(DurableJob.created_at.asc()).limit(10).all()]
    for cand_id in candidates:
        claimed = claim_durable_job_by_id(
            db=db,
            job_id=cand_id,
            worker_id=worker_id,
            lease_seconds=lease_seconds,
        )
        if claimed is not None:
            return claimed

    return None


def renew_job_lease(
    db: Session,
    job_id: str,
    worker_id: str,
    lease_token: str,
    lease_seconds: Optional[int] = None,
) -> bool:
    """Renew a running job's lease ONLY if the worker still owns the valid, non-expired fencing token.

    Returns False if the lease expired, was reassigned to another worker, or cancellation was requested.
    """
    now = _utc_now()
    lease_dur = lease_seconds if lease_seconds is not None else settings.JOB_LEASE_DURATION_SECONDS
    new_exp = now + timedelta(seconds=max(1, int(lease_dur)))
    _clear_fenced_leases_for_job(db, job_id)

    updated = (
        db.query(DurableJob)
        .filter(
            DurableJob.id == job_id,
            DurableJob.worker_id == worker_id,
            DurableJob.lease_token == lease_token,
            DurableJob.status == JobState.RUNNING.value,
            DurableJob.lease_expires_at > now,
        )
        .update(
            {
                "lease_expires_at": new_exp,
                "heartbeat_at": now,
                "updated_at": now,
            },
            synchronize_session=False,
        )
    )
    db.commit()
    return updated == 1


def verify_worker_owns_valid_lease(
    db: Session,
    job_id: str,
    worker_id: str,
    lease_token: str,
) -> DurableJob:
    """Assert that (worker_id, lease_token) currently holds an active, non-expired lease on job_id."""
    now = _utc_now()
    job = db.query(DurableJob).filter(DurableJob.id == job_id).first()
    if not job:
        raise NotFoundError(f"Durable job '{job_id}' not found.")

    exp_utc = _ensure_utc(job.lease_expires_at)
    if (
        job.worker_id != worker_id
        or job.lease_token != lease_token
        or job.status != JobState.RUNNING.value
        or (exp_utc is not None and exp_utc <= now)
    ):
        raise StaleWorkerLeaseError(job_id=job_id, worker_id=worker_id)
    return job


def compute_retry_backoff_seconds(
    attempt_count: int,
    base_delay: Optional[float] = None,
    max_delay: Optional[float] = None,
    deterministic_jitter: Optional[float] = None,
) -> float:
    """Compute exponential backoff with bounded jitter for retry attempt N."""
    base = float(base_delay if base_delay is not None else settings.JOB_RETRY_BASE_DELAY_SECONDS)
    ceiling = float(max_delay if max_delay is not None else settings.JOB_RETRY_MAX_DELAY_SECONDS)
    exp_delay = min(ceiling, base * (2 ** max(0, int(attempt_count) - 1)))
    if deterministic_jitter is not None:
        jitter = float(deterministic_jitter)
    else:
        jitter = random.uniform(0.0, exp_delay * 0.25)
    return round(min(ceiling, exp_delay + jitter), 3)


def complete_claimed_job(
    db: Session,
    job_id: str,
    worker_id: str,
    lease_token: str,
) -> DurableJob:
    """Atomically transition a claimed job to 'completed', fenced by (worker_id, lease_token)."""
    now = _utc_now()
    _clear_fenced_leases_for_job(db, job_id)
    job = verify_worker_owns_valid_lease(db, job_id=job_id, worker_id=worker_id, lease_token=lease_token)
    validate_job_transition(job.status, JobState.COMPLETED.value, job_id=job.id)

    updated = (
        db.query(DurableJob)
        .filter(
            DurableJob.id == job_id,
            DurableJob.worker_id == worker_id,
            DurableJob.lease_token == lease_token,
            DurableJob.status == JobState.RUNNING.value,
            DurableJob.lease_expires_at > now,
        )
        .update(
            {
                "status": JobState.COMPLETED.value,
                "completed_at": now,
                "heartbeat_at": now,
                "lease_token": None,
                "lease_expires_at": None,
                "quota_reserved": False,
                "quota_counted": True,
                "updated_at": now,
            },
            synchronize_session=False,
        )
    )
    if updated != 1:
        db.rollback()
        raise StaleWorkerLeaseError(job_id=job_id, worker_id=worker_id)

    db.query(ActiveJobSlot).filter(ActiveJobSlot.job_id == job_id).delete(synchronize_session=False)
    db.commit()
    db.refresh(job)

    if job.started_at:
        s_utc = _ensure_utc(job.started_at) or now
        _record_metric_sample("execution_durations_ms", (now - s_utc).total_seconds() * 1000.0)

    logger.info(f"[job:{job.id}] Completed by worker '{worker_id}' on attempt {job.attempt_count}")
    return job


def fail_claimed_job(
    db: Session,
    job_id: str,
    worker_id: str,
    lease_token: str,
    failure_category: str,
    error_detail: str,
    retryable: bool = True,
    redis_client: Optional[Any] = None,
) -> DurableJob:
    """Handle job failure for a lease-holding worker: schedule bounded retry or transition to terminal 'failed'."""
    now = _utc_now()
    _clear_fenced_leases_for_job(db, job_id)
    job = verify_worker_owns_valid_lease(db, job_id=job_id, worker_id=worker_id, lease_token=lease_token)
    safe_error = sanitize_job_error_detail(error_detail)
    safe_category = (failure_category or "execution_error").strip()[:64]

    can_retry = retryable and (job.attempt_count < job.max_attempts)
    target_state = JobState.RETRYING.value if can_retry else JobState.FAILED.value
    validate_job_transition(job.status, target_state, job_id=job.id)

    if can_retry:
        delay_sec = compute_retry_backoff_seconds(job.attempt_count)
        next_retry = now + timedelta(seconds=delay_sec)
        updated = (
            db.query(DurableJob)
            .filter(
                DurableJob.id == job_id,
                DurableJob.worker_id == worker_id,
                DurableJob.lease_token == lease_token,
                DurableJob.status == JobState.RUNNING.value,
                DurableJob.lease_expires_at > now,
            )
            .update(
                {
                    "status": JobState.RETRYING.value,
                    "next_retry_at": next_retry,
                    "failure_category": safe_category,
                    "error_detail": safe_error,
                    "lease_token": None,
                    "lease_expires_at": None,
                    "updated_at": now,
                },
                synchronize_session=False,
            )
        )
        if updated != 1:
            db.rollback()
            raise StaleWorkerLeaseError(job_id=job_id, worker_id=worker_id)

        if job.job_type == "scan":
            db.query(Scan).filter(Scan.id == job.resource_id).update(
                {"status": "retrying", "updated_at": now},
                synchronize_session=False,
            )
        elif job.job_type == "verification":
            db.query(VerificationRun).filter(VerificationRun.id == job.resource_id).update(
                {"status": "RETRYING", "updated_at": now},
                synchronize_session=False,
            )

        outbox = JobOutboxEvent(
            id=str(uuid.uuid4()),
            job_id=job.id,
            job_type=job.job_type,
            resource_id=job.resource_id,
            queue_name=settings.JOB_QUEUE_NAME,
            status="pending",
            dispatch_attempts=0,
        )
        db.add(outbox)
        db.commit()
        db.refresh(job)
        logger.warning(
            f"[job:{job.id}] Attempt {job.attempt_count}/{job.max_attempts} failed ({safe_category}); "
            f"scheduled retry in {delay_sec:.2f}s"
        )
        return job

    # Terminal failure (max retries exhausted or non-retryable error)
    final_category = safe_category if not retryable else (safe_category or "max_retries_exceeded")
    updated = (
        db.query(DurableJob)
        .filter(
            DurableJob.id == job_id,
            DurableJob.worker_id == worker_id,
            DurableJob.lease_token == lease_token,
            DurableJob.status == JobState.RUNNING.value,
            DurableJob.lease_expires_at > now,
        )
        .update(
            {
                "status": JobState.FAILED.value,
                "failed_at": now,
                "completed_at": now,
                "failure_category": final_category,
                "error_detail": safe_error,
                "lease_token": None,
                "lease_expires_at": None,
                "quota_reserved": False,
                "quota_counted": True,
                "updated_at": now,
            },
            synchronize_session=False,
        )
    )
    if updated != 1:
        db.rollback()
        raise StaleWorkerLeaseError(job_id=job_id, worker_id=worker_id)

    db.query(ActiveJobSlot).filter(ActiveJobSlot.job_id == job_id).delete(synchronize_session=False)

    if job.job_type == "scan":
        db.query(Scan).filter(Scan.id == job.resource_id).update(
            {
                "status": "failed",
                "completed_at": now,
                "summary": json.dumps({"error": safe_error, "failure_category": final_category}),
                "updated_at": now,
            },
            synchronize_session=False,
        )
    elif job.job_type == "verification":
        db.query(VerificationRun).filter(VerificationRun.id == job.resource_id).update(
            {
                "status": "INCONCLUSIVE",
                "completed_at": now,
                "reasons": json.dumps([safe_error]),
                "updated_at": now,
            },
            synchronize_session=False,
        )

    db.commit()
    db.refresh(job)
    logger.error(
        f"[job:{job.id}] Permanently failed on attempt {job.attempt_count}/{job.max_attempts} "
        f"[category={final_category}]: {safe_error}"
    )
    return job


def release_claimed_job_on_shutdown(
    db: Session,
    job_id: str,
    worker_id: str,
    lease_token: str,
) -> bool:
    """Gracefully release an active lease back to 'queued' when a worker receives SIGTERM."""
    now = _utc_now()
    _clear_fenced_leases_for_job(db, job_id)
    updated = (
        db.query(DurableJob)
        .filter(
            DurableJob.id == job_id,
            DurableJob.worker_id == worker_id,
            DurableJob.lease_token == lease_token,
            DurableJob.status == JobState.RUNNING.value,
        )
        .update(
            {
                "status": JobState.QUEUED.value,
                "worker_id": None,
                "lease_token": None,
                "lease_expires_at": None,
                "attempt_count": func.max(0, DurableJob.attempt_count - 1),
                "updated_at": now,
            },
            synchronize_session=False,
        )
    )
    if updated == 1:
        job = db.query(DurableJob).filter(DurableJob.id == job_id).first()
        if job:
            if job.job_type == "scan":
                db.query(Scan).filter(Scan.id == job.resource_id).update(
                    {"status": "queued", "updated_at": now},
                    synchronize_session=False,
                )
            outbox = JobOutboxEvent(
                id=str(uuid.uuid4()),
                job_id=job.id,
                job_type=job.job_type,
                resource_id=job.resource_id,
                queue_name=settings.JOB_QUEUE_NAME,
                status="pending",
            )
            db.add(outbox)
        db.commit()
        return True
    db.rollback()
    return False


# ==============================================================================
# Subprocess Tree, Docker Sandbox Container & Workspace Cancellation Tracker (Task 7)
# ==============================================================================

class JobExecutionTracker:
    """Tracks live child subprocesses, Docker sandbox containers, and disposable workspaces for an active job.

    Enables immediate process-tree termination, container cleanup, and tenant-confined workspace deletion
    when a running job is cancelled or loses its lease.
    """
    def __init__(
        self,
        job_id: str,
        resource_id: str,
        tenant_id: Optional[str],
        worker_id: Optional[str] = None,
        lease_token: Optional[str] = None,
        session_factory: Optional[Callable[[], Session]] = None,
    ):
        self.job_id = job_id
        self.resource_id = resource_id
        self.tenant_id = tenant_id
        self.worker_id = worker_id
        self.lease_token = lease_token
        self.session_factory = session_factory
        self.cancel_event = threading.Event()
        self.lease_lost_event = threading.Event()
        self._lock = threading.Lock()
        self._processes: Set[subprocess.Popen] = set()
        self._child_processes: Dict[int, Dict[str, Any]] = {}
        self._containers: Set[str] = set()
        self._temp_workspaces: Set[Path] = set()

    def _persist_runtime_artifacts(self, db: Optional[Session] = None) -> None:
        with self._lock:
            child_procs = [dict(v) for _, v in sorted(self._child_processes.items())]
            pids = sorted(self._child_processes.keys())
            containers = sorted(self._containers)
            workspaces = [str(p) for p in sorted(self._temp_workspaces)]
        record_job_runtime_artifacts(
            job_id=self.job_id,
            child_pids=pids,
            child_processes=child_procs,
            containers=containers,
            temp_workspaces=workspaces,
            db=db,
            session_factory=self.session_factory,
        )

    def register_process(self, proc: subprocess.Popen, db: Optional[Session] = None) -> None:
        pid_val = getattr(proc, "pid", None)
        with self._lock:
            self._processes.add(proc)
            if pid_val:
                pid_int = int(pid_val)
                self._child_processes[pid_int] = {
                    "pid": pid_int,
                    "hostname": _get_local_hostname(),
                    "start_time": _get_pid_start_time(pid_int),
                    "job_id": self.job_id,
                }
        self._persist_runtime_artifacts(db=db)
        if self.should_abort():
            self._kill_process_tree(proc)

    def unregister_process(self, proc: subprocess.Popen, db: Optional[Session] = None) -> None:
        pid_val = getattr(proc, "pid", None)
        with self._lock:
            self._processes.discard(proc)
            if pid_val:
                self._child_processes.pop(int(pid_val), None)
        self._persist_runtime_artifacts(db=db)

    def register_container(self, container_name: str, db: Optional[Session] = None) -> None:
        with self._lock:
            self._containers.add(container_name)
        self._persist_runtime_artifacts(db=db)
        if self.should_abort():
            self._kill_container(container_name)

    def unregister_container(self, container_name: str, db: Optional[Session] = None) -> None:
        with self._lock:
            self._containers.discard(container_name)
        self._persist_runtime_artifacts(db=db)

    def register_temp_workspace(self, workspace_dir: Path, db: Optional[Session] = None) -> None:
        with self._lock:
            self._temp_workspaces.add(workspace_dir.resolve())
        self._persist_runtime_artifacts(db=db)

    def should_abort(self) -> bool:
        return self.cancel_event.is_set() or self.lease_lost_event.is_set()

    @staticmethod
    def _kill_process_tree(proc: subprocess.Popen) -> None:
        if proc.poll() is not None:
            return
        try:
            pid = proc.pid
            if platform.system() == "Windows":
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(pid)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                    check=False,
                    shell=False,
                )
            else:
                try:
                    pgid = os.getpgid(pid)
                    os.killpg(pgid, signal.SIGKILL)
                except Exception:
                    proc.kill()
            proc.kill()
            proc.wait(timeout=2)
        except Exception:
            pass

    @staticmethod
    def _kill_container(container_name: str) -> None:
        if not container_name:
            return
        for subcmd in (["docker", "kill", container_name], ["docker", "rm", "-f", container_name]):
            try:
                subprocess.run(
                    subcmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                    check=False,
                    shell=False,
                )
            except Exception:
                pass

    def cleanup_temp_workspaces(self, allowed_roots: Optional[List[Path]] = None) -> int:
        """Delete only disposable temporary workspaces registered to this job within authorized temp roots."""
        with self._lock:
            workspaces = list(self._temp_workspaces)
            self._temp_workspaces.clear()

        cleaned = 0
        import tempfile
        default_temp_root = Path(tempfile.gettempdir()).resolve()
        valid_roots = [r.resolve() for r in (allowed_roots or [])] + [default_temp_root]
        if os.environ.get("WORKER_TEMP_DIR"):
            valid_roots.append(Path(os.environ["WORKER_TEMP_DIR"]).resolve())

        for ws in workspaces:
            try:
                resolved = ws.resolve()
                if not resolved.exists() or resolved.is_symlink():
                    continue
                # Confine deletion strictly inside a valid temp directory root, never the root itself,
                # and ONLY directories bearing an explicit Red Mercury disposable verification workspace prefix.
                has_disposable_prefix = resolved.name.startswith(
                    ("redmercury_verify_", "rm_verify_", "rm_p6_cancel_ws_", "rm_p7a_cancel_ws_")
                )
                is_confined = has_disposable_prefix and any(
                    resolved != root and resolved.is_relative_to(root)
                    for root in valid_roots
                )
                if not is_confined:
                    logger.warning(f"[job:{self.job_id}] Refusing to delete unconfined temp workspace '{resolved}'")
                    continue
                shutil.rmtree(resolved, ignore_errors=True)
                cleaned += 1
            except Exception as exc:
                logger.warning(f"[job:{self.job_id}] Error cleaning temp workspace '{ws}': {exc}")
        return cleaned

    def terminate_all(self, reason: str = "cancelled") -> None:
        """Signal abort, kill all child process trees, stop all Docker containers, and clean temp workspaces."""
        if reason == "lease_lost":
            self.lease_lost_event.set()
        else:
            self.cancel_event.set()

        with self._lock:
            procs = list(self._processes)
            containers = list(self._containers)

        for proc in procs:
            self._kill_process_tree(proc)
        for cname in containers:
            self._kill_container(cname)
        self.cleanup_temp_workspaces()


_ACTIVE_TRACKERS_LOCK = threading.Lock()
_ACTIVE_TRACKERS_BY_JOB_ID: Dict[str, JobExecutionTracker] = {}
_ACTIVE_TRACKERS_BY_RESOURCE_ID: Dict[str, JobExecutionTracker] = {}
_THREAD_LOCAL_CONTEXT = threading.local()


def register_active_tracker(tracker: JobExecutionTracker) -> None:
    with _ACTIVE_TRACKERS_LOCK:
        _ACTIVE_TRACKERS_BY_JOB_ID[tracker.job_id] = tracker
        _ACTIVE_TRACKERS_BY_RESOURCE_ID[tracker.resource_id] = tracker
    _THREAD_LOCAL_CONTEXT.tracker = tracker


def unregister_active_tracker(tracker: JobExecutionTracker) -> None:
    with _ACTIVE_TRACKERS_LOCK:
        _ACTIVE_TRACKERS_BY_JOB_ID.pop(tracker.job_id, None)
        _ACTIVE_TRACKERS_BY_RESOURCE_ID.pop(tracker.resource_id, None)
    if getattr(_THREAD_LOCAL_CONTEXT, "tracker", None) is tracker:
        _THREAD_LOCAL_CONTEXT.tracker = None


def get_active_tracker(job_or_resource_id: Optional[str] = None) -> Optional[JobExecutionTracker]:
    if job_or_resource_id:
        with _ACTIVE_TRACKERS_LOCK:
            return (
                _ACTIVE_TRACKERS_BY_JOB_ID.get(job_or_resource_id)
                or _ACTIVE_TRACKERS_BY_RESOURCE_ID.get(job_or_resource_id)
            )
    return getattr(_THREAD_LOCAL_CONTEXT, "tracker", None)


def assert_active_worker_lease_or_abort(
    db: Session,
    resource_id: Optional[str] = None,
    job_id: Optional[str] = None,
    worker_id: Optional[str] = None,
    lease_token: Optional[str] = None,
) -> Optional[DurableJob]:
    """Verify that the active worker still holds a valid, non-expired lease before writing any business data.

    Protects all business-data writes (SecurityFinding, VerificationRun, SecurityEvidence,
    VerificationEvidence, Scan status, Repository posture, AuditEvent) against stale workers.
    If the lease was lost, expired, or reassigned, rolls back uncommitted changes and raises StaleWorkerLeaseError.
    """
    tracker = get_active_tracker(job_id or resource_id) or get_active_tracker()
    eff_job_id = job_id or (tracker.job_id if tracker else None)
    eff_res_id = resource_id or (tracker.resource_id if tracker else None)
    eff_worker_id = worker_id or (tracker.worker_id if tracker else None)
    eff_lease_token = lease_token or (tracker.lease_token if tracker else None)

    if tracker is not None and tracker.lease_lost_event.is_set():
        db.rollback()
        raise StaleWorkerLeaseError(
            job_id=eff_job_id or eff_res_id or "unknown",
            worker_id=eff_worker_id or "stale-worker",
        )

    djob: Optional[DurableJob] = None
    if eff_job_id:
        djob = db.query(DurableJob).filter(DurableJob.id == eff_job_id).first()
    elif eff_res_id:
        djob = db.query(DurableJob).filter(DurableJob.resource_id == eff_res_id).first()

    if djob is None:
        return None

    # Always inspect the latest committed state from the database
    try:
        row = db.connection().execute(
            text(
                "SELECT status, worker_id, lease_token, lease_expires_at "
                "FROM durable_jobs WHERE id = :jid"
            ),
            {"jid": djob.id},
        ).fetchone()
    except Exception:
        row = None

    now = _utc_now()
    if row is not None:
        db_status, db_worker, db_token, db_expires = row[0], row[1], row[2], row[3]
        if isinstance(db_expires, str):
            try:
                db_expires = datetime.fromisoformat(db_expires.replace("Z", "+00:00"))
            except Exception:
                db_expires = None
        exp_utc = _ensure_utc(db_expires)
    else:
        db_status = djob.status
        db_worker = djob.worker_id
        db_token = djob.lease_token
        exp_utc = _ensure_utc(djob.lease_expires_at)

    # Only enforce lease checks when the job has entered the leased execution lifecycle
    # (or when an explicit worker_id / lease_token is asserting ownership)
    is_leased_attempt = (
        eff_worker_id is not None
        or eff_lease_token is not None
        or djob.attempt_count > 0
        or db_worker is not None
    )
    if not is_leased_attempt:
        return djob

    if (
        db_status != JobState.RUNNING.value
        or not db_token
        or (exp_utc is not None and exp_utc <= now)
        or (eff_worker_id is not None and db_worker != eff_worker_id)
        or (eff_lease_token is not None and db_token != eff_lease_token)
    ):
        db.rollback()
        raise StaleWorkerLeaseError(
            job_id=djob.id,
            worker_id=eff_worker_id or db_worker or "stale-worker",
        )

    # Bind the verified fencing token to the owning SessionTransaction so nested savepoint
    # rollbacks only discard leases introduced in that savepoint while preserving outer leases.
    owning_tx = db.get_nested_transaction() or db.get_transaction()
    tx_key = id(owning_tx) if owning_tx is not None else 0
    by_tx = db.info.setdefault("_fenced_leases_by_tx", {})
    tx_leases = by_tx.setdefault(tx_key, set())
    lease_tuple = (
        djob.id,
        eff_worker_id or db_worker,
        eff_lease_token or db_token,
    )
    tx_leases.add(lease_tuple)
    _sync_flat_fenced_leases(db)
    return djob


def _sync_flat_fenced_leases(session: Session) -> None:
    """Keep session.info['_fenced_job_leases'] synchronized with '_fenced_leases_by_tx'."""
    by_tx = session.info.get("_fenced_leases_by_tx")
    if not by_tx:
        session.info.pop("_fenced_leases_by_tx", None)
        session.info.pop("_fenced_job_leases", None)
        return
    flat: Set[Tuple[str, str, str]] = set()
    for s in by_tx.values():
        if s:
            flat.update(s)
    if flat:
        session.info["_fenced_job_leases"] = flat
    else:
        session.info.pop("_fenced_leases_by_tx", None)
        session.info.pop("_fenced_job_leases", None)


def _clear_all_fenced_leases(session: Session) -> None:
    session.info.pop("_fenced_leases_by_tx", None)
    session.info.pop("_fenced_job_leases", None)
    session.info.pop("_committed_fenced_tx_ids", None)


def _clear_fenced_leases_for_job(session: Session, job_id: Optional[str]) -> int:
    """Remove fencing registrations belonging ONLY to `job_id` across active transaction buckets.

    Preserves all unrelated job fencing registrations (including outer and nested savepoint scopes)
    and keeps `_fenced_job_leases` synchronized with `_fenced_leases_by_tx`.
    """
    if not job_id:
        return 0
    by_tx = session.info.get("_fenced_leases_by_tx")
    if not by_tx:
        return 0
    removed = 0
    for tx_key in list(by_tx.keys()):
        tx_set = by_tx.get(tx_key)
        if not tx_set:
            by_tx.pop(tx_key, None)
            continue
        to_remove = {item for item in tx_set if item[0] == job_id}
        if to_remove:
            tx_set.difference_update(to_remove)
            removed += len(to_remove)
            if not tx_set:
                by_tx.pop(tx_key, None)
    _sync_flat_fenced_leases(session)
    return removed


@event.listens_for(Session, "before_commit")
def _enforce_lease_fencing_before_commit(session: Session) -> None:
    """Atomic transaction-level lease fencing at the exact database COMMIT boundary (Phase 7A / 7E).

    Verifies every fenced (job_id, worker_id, lease_token) registered on this Session via an atomic
    row-locking UPDATE on durable_jobs inside the committing transaction. If any lease expired or
    was reassigned, raises StaleWorkerLeaseError and aborts the commit.
    """
    _sync_flat_fenced_leases(session)
    fenced_set = session.info.get("_fenced_job_leases")
    if not fenced_set:
        return

    active_tx = session.get_nested_transaction() or session.get_transaction()
    if active_tx is not None:
        session.info.setdefault("_committed_fenced_tx_ids", set()).add(id(active_tx))

    # During a nested savepoint commit, defer the actual DB row-lock UPDATE until outer commit,
    # while marking the savepoint as committed so its leases are promoted to the parent transaction.
    if session.in_nested_transaction():
        return

    now = _utc_now()
    for job_id, worker_id, lease_token in sorted(fenced_set):
        if not job_id or not worker_id or not lease_token:
            continue
        res = session.connection().execute(
            text(
                """
                UPDATE durable_jobs
                SET heartbeat_at = :now
                WHERE id = :jid
                  AND status = :running_status
                  AND worker_id = :wid
                  AND lease_token = :tok
                  AND lease_expires_at > :now
                """
            ),
            {
                "now": now,
                "jid": job_id,
                "running_status": JobState.RUNNING.value,
                "wid": worker_id,
                "tok": lease_token,
            },
        )
        if res.rowcount != 1:
            raise StaleWorkerLeaseError(job_id=job_id, worker_id=worker_id)


@event.listens_for(Session, "after_transaction_end")
def _cleanup_fenced_leases_on_transaction_end(session: Session, transaction: Any) -> None:
    """Transaction-scoped cleanup on commit or rollback (outer or nested savepoint).

    - Nested savepoint rollback: discards ONLY leases registered in that savepoint; outer leases survive.
    - Nested savepoint commit: promotes leases registered in that savepoint into transaction.parent.
    - Outer transaction end (commit or rollback): clears all fenced lease state cleanly.
    """
    by_tx = session.info.get("_fenced_leases_by_tx")
    committed_ids = session.info.get("_committed_fenced_tx_ids")
    tx_id = id(transaction)
    was_committed = bool(committed_ids and tx_id in committed_ids)
    if committed_ids is not None:
        committed_ids.discard(tx_id)
        if not committed_ids:
            session.info.pop("_committed_fenced_tx_ids", None)

    if getattr(transaction, "parent", None) is None:
        _clear_all_fenced_leases(session)
        return

    if not by_tx:
        return

    tx_leases = by_tx.pop(tx_id, None)
    if was_committed and tx_leases:
        parent_key = id(transaction.parent)
        by_tx.setdefault(parent_key, set()).update(tx_leases)

    _sync_flat_fenced_leases(session)


def _get_local_hostname() -> str:
    try:
        return socket.gethostname() or "unknown"
    except Exception:
        return "unknown"


def _get_pid_start_time(pid: int) -> Optional[str]:
    """Return an OS-level process creation-time fingerprint to prevent PID-reuse misidentification."""
    if not pid or int(pid) <= 0:
        return None
    try:
        if platform.system() == "Windows":
            import ctypes
            from ctypes import wintypes

            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
            if not handle:
                return None
            try:
                creation = wintypes.FILETIME()
                exit_t = wintypes.FILETIME()
                kernel_t = wintypes.FILETIME()
                user_t = wintypes.FILETIME()
                if kernel32.GetProcessTimes(
                    handle,
                    ctypes.byref(creation),
                    ctypes.byref(exit_t),
                    ctypes.byref(kernel_t),
                    ctypes.byref(user_t),
                ):
                    ticks = (creation.dwHighDateTime << 32) | creation.dwLowDateTime
                    return str(ticks)
                return None
            finally:
                kernel32.CloseHandle(handle)
        else:
            stat_path = Path(f"/proc/{int(pid)}/stat")
            if not stat_path.exists():
                return None
            raw = stat_path.read_text(encoding="utf-8", errors="ignore")
            rparen = raw.rfind(")")
            if rparen == -1:
                return None
            fields = raw[rparen + 2:].split()
            # Field 22 (starttime) is index 19 after comm
            if len(fields) > 19:
                return str(fields[19])
            return None
    except Exception:
        return None


def record_job_runtime_artifacts(
    job_id: str,
    child_pids: Optional[List[int]] = None,
    child_processes: Optional[List[Dict[str, Any]]] = None,
    containers: Optional[List[str]] = None,
    temp_workspaces: Optional[List[str]] = None,
    db: Optional[Session] = None,
    session_factory: Optional[Callable[[], Session]] = None,
) -> None:
    """Persist active subprocess identities, sandbox container names, and disposable workspace paths in payload_json.

    Note (P7B-F08): When `db` is None and `session_factory` is bound to SQLite, autonomous persistence
    is intentionally skipped to avoid SQLite file-lock contention from background threads; in single-process
    SQLite dev mode, the in-memory JobExecutionTracker tracks all active child artifacts directly.
    """
    own_session = False
    sess = db
    if sess is None and session_factory is not None:
        try:
            sess = session_factory()
            own_session = True
            if sess.bind is not None and sess.bind.dialect.name == "sqlite":
                sess.close()
                return
        except Exception:
            return
    if sess is None:
        return

    try:
        job = sess.query(DurableJob).filter(DurableJob.id == job_id).first()
        if not job:
            return
        payload: Dict[str, Any] = {}
        if job.payload_json:
            try:
                payload = json.loads(job.payload_json)
                if not isinstance(payload, dict):
                    payload = {}
            except Exception:
                payload = {}
        payload["_runtime_artifacts"] = {
            "child_pids": [int(p) for p in (child_pids or []) if p],
            "child_processes": [
                {
                    "pid": int(proc_info["pid"]),
                    "hostname": str(proc_info.get("hostname") or ""),
                    "start_time": proc_info.get("start_time"),
                    "job_id": str(proc_info.get("job_id") or job_id),
                }
                for proc_info in (child_processes or [])
                if isinstance(proc_info, dict) and proc_info.get("pid")
            ],
            "containers": [str(c) for c in (containers or []) if c],
            "temp_workspaces": [str(w) for w in (temp_workspaces or []) if w],
        }
        sess.query(DurableJob).filter(DurableJob.id == job_id).update(
            {"payload_json": json.dumps(payload)},
            synchronize_session=False,
        )
        if own_session:
            sess.commit()
        else:
            sess.flush()
    except Exception:
        if own_session:
            try:
                sess.rollback()
            except Exception:
                pass
    finally:
        if own_session and sess is not None:
            try:
                sess.close()
            except Exception:
                pass


def _is_pid_running(pid: int) -> bool:
    """Check whether an OS process with the given PID is currently alive in the process table."""
    if not pid or int(pid) <= 0:
        return False
    try:
        if platform.system() == "Windows":
            res = subprocess.run(
                ["tasklist", "/FI", f"PID eq {int(pid)}", "/NH", "/FO", "CSV"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=4,
                check=False,
                shell=False,
            )
            out = (res.stdout or "").strip()
            return f'"{int(pid)}"' in out
        else:
            os.kill(int(pid), 0)
            return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except Exception:
        return False


def _kill_pid_tree_safely(pid: int) -> None:
    """Safely terminate a tracked child process tree by PID without broad process killing."""
    if not pid or int(pid) <= 0 or int(pid) == os.getpid():
        return
    try:
        if platform.system() == "Windows":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(int(pid))],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
                shell=False,
            )
        else:
            try:
                pgid = os.getpgid(int(pid))
                if pgid != os.getpgid(os.getpid()):
                    os.killpg(pgid, signal.SIGKILL)
                else:
                    os.kill(int(pid), signal.SIGKILL)
            except Exception:
                os.kill(int(pid), signal.SIGKILL)
    except Exception:
        pass


_SAFE_SANDBOX_CONTAINER_RE = re.compile(r"^redmercury-sbx-[a-zA-Z0-9_\-]+$")


def _is_container_running(container_name: str) -> bool:
    """Check whether a specific Red Mercury sandbox container is still present/running in Docker."""
    if not container_name or not _SAFE_SANDBOX_CONTAINER_RE.match(container_name):
        return False
    try:
        res = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Running}}", container_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=4,
            check=False,
            shell=False,
        )
        return res.returncode == 0 and "true" in (res.stdout or "").strip().lower()
    except Exception:
        return False


def reap_and_verify_orphaned_job_resources(
    job: DurableJob,
    kill_resources: bool = True,
    allowed_temp_roots: Optional[List[Path]] = None,
) -> Tuple[bool, Dict[str, Any]]:
    """Reap and verify orphaned child processes, sandbox containers, and disposable workspaces for an expired job.

    Invariants (Phase 7A Section 3):
    1. Only targets child PIDs, `redmercury-sbx-*` container names, and confined disposable temp workspaces
       explicitly registered to `job.id` (never broad `docker rm` or arbitrary PID killing).
    2. Inspects the actual OS process table and Docker container list after cleanup.
    3. Returns `verified_stopped=False` if any child process or sandbox container remains alive so
       recovery refuses to report a clean terminal cancellation or release the concurrency slot.
    """
    payload: Dict[str, Any] = {}
    if job.payload_json:
        try:
            payload = json.loads(job.payload_json)
        except Exception:
            payload = {}

    artifacts = payload.get("_runtime_artifacts")
    if not isinstance(artifacts, dict):
        artifacts = {}

    raw_child_procs = artifacts.get("child_processes")
    child_process_entries: List[Dict[str, Any]] = []
    if isinstance(raw_child_procs, list):
        for entry in raw_child_procs:
            if not isinstance(entry, dict):
                continue
            try:
                pid_val = int(entry.get("pid") or 0)
            except (TypeError, ValueError):
                continue
            if pid_val > 0:
                child_process_entries.append({
                    "pid": pid_val,
                    "hostname": str(entry.get("hostname") or ""),
                    "start_time": entry.get("start_time"),
                    "job_id": str(entry.get("job_id") or ""),
                })

    raw_containers = artifacts.get("containers")
    containers: List[str] = []
    if isinstance(raw_containers, list):
        containers = [
            str(c) for c in raw_containers
            if isinstance(c, str) and _SAFE_SANDBOX_CONTAINER_RE.match(c)
        ]

    raw_workspaces = artifacts.get("temp_workspaces")
    temp_workspaces: List[str] = (
        [str(w) for w in raw_workspaces if isinstance(w, str) and w.strip()]
        if isinstance(raw_workspaces, list)
        else []
    )

    # Also discover any Docker sandbox containers labeled specifically with redmercury.job_id=<job.id>
    try:
        res = subprocess.run(
            ["docker", "ps", "-a", "--filter", f"label=redmercury.job_id={job.id}", "--format", "{{.Names}}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=4,
            check=False,
            shell=False,
        )
        if res.returncode == 0 and res.stdout:
            for line in res.stdout.splitlines():
                cname = line.strip()
                if cname and _SAFE_SANDBOX_CONTAINER_RE.match(cname) and cname not in containers:
                    containers.append(cname)
    except Exception:
        pass

    current_host = _get_local_hostname()
    reaped_pids: List[int] = []
    still_running_pids: List[int] = []
    for entry in child_process_entries:
        pid = entry["pid"]
        entry_host = entry.get("hostname") or ""
        entry_start = entry.get("start_time")
        entry_job_id = entry.get("job_id") or ""

        # Never inspect or signal PIDs from a different container/host PID namespace,
        # mismatched job_id, or without a valid process start_time fingerprint.
        if entry_host != current_host or entry_job_id != job.id or not entry_start:
            continue

        if not _is_pid_running(pid):
            continue

        observed_start = _get_pid_start_time(pid)
        if observed_start is None:
            # Permission-denied or unreadable process metadata: NEVER kill an unverified PID,
            # and do not claim proof that our child stopped if we cannot inspect it.
            continue
        if observed_start != str(entry_start):
            # OS recycled this numeric PID to a different process -> already terminated!
            continue

        if kill_resources:
            _kill_pid_tree_safely(pid)
            reaped_pids.append(pid)

        if _is_pid_running(pid) and _get_pid_start_time(pid) == str(entry_start):
            still_running_pids.append(pid)

    reaped_containers: List[str] = []
    still_running_containers: List[str] = []
    for cname in containers:
        if kill_resources:
            JobExecutionTracker._kill_container(cname)
            reaped_containers.append(cname)
        if _is_container_running(cname):
            still_running_containers.append(cname)

    cleaned_workspaces: List[str] = []
    temp_tracker = JobExecutionTracker(
        job_id=job.id,
        resource_id=job.resource_id,
        tenant_id=job.tenant_id,
    )
    for ws_str in temp_workspaces:
        temp_tracker.register_temp_workspace(Path(ws_str))
    if temp_workspaces and kill_resources:
        temp_tracker.cleanup_temp_workspaces(allowed_roots=allowed_temp_roots)
        for ws_str in temp_workspaces:
            if not Path(ws_str).exists():
                cleaned_workspaces.append(ws_str)

    verified_stopped = (len(still_running_pids) == 0 and len(still_running_containers) == 0)
    details = {
        "verified_stopped": verified_stopped,
        "reaped_pids": reaped_pids,
        "still_running_pids": still_running_pids,
        "reaped_containers": reaped_containers,
        "still_running_containers": still_running_containers,
        "cleaned_workspaces": cleaned_workspaces,
    }
    return verified_stopped, details


class JobHeartbeatMonitor:
    """Periodic background lease renewal and cancellation checker for an actively executing worker job."""
    def __init__(
        self,
        session_factory: Callable[[], Session],
        job_id: str,
        worker_id: str,
        lease_token: str,
        tracker: JobExecutionTracker,
        interval_seconds: Optional[float] = None,
        lease_seconds: Optional[int] = None,
    ):
        self.session_factory = session_factory
        self.job_id = job_id
        self.worker_id = worker_id
        self.lease_token = lease_token
        self.tracker = tracker
        self.interval_seconds = float(
            interval_seconds if interval_seconds is not None else settings.JOB_HEARTBEAT_INTERVAL_SECONDS
        )
        self.lease_seconds = int(
            lease_seconds if lease_seconds is not None else settings.JOB_LEASE_DURATION_SECONDS
        )
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run,
            name=f"rm-heartbeat-{self.job_id[:8]}",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def _run(self) -> None:
        while not self._stop_event.wait(timeout=max(0.05, self.interval_seconds)):
            db = None
            try:
                db = self.session_factory()
                job = db.query(DurableJob).filter(DurableJob.id == self.job_id).first()
                r_client = get_job_redis_client()
                redis_cancel = False
                if r_client is not None:
                    try:
                        redis_cancel = bool(r_client.get(f"redmercury:job:cancel:{self.job_id}"))
                    except Exception:
                        redis_cancel = False

                if not job or job.status in (JobState.CANCELLING.value, JobState.CANCELLED.value) or redis_cancel:
                    logger.info(f"[job:{self.job_id}] Heartbeat detected cancellation; terminating active work.")
                    self.tracker.terminate_all(reason="cancelled")
                    if job is not None and job.status != JobState.CANCELLED.value:
                        acknowledge_job_cancellation(
                            db=db,
                            job=job,
                            resource_type=job.job_type,
                            resource_id=job.resource_id,
                            worker_id=self.worker_id,
                        )
                    break

                ok = renew_job_lease(
                    db=db,
                    job_id=self.job_id,
                    worker_id=self.worker_id,
                    lease_token=self.lease_token,
                    lease_seconds=self.lease_seconds,
                )
                if not ok:
                    logger.warning(
                        f"[job:{self.job_id}] Worker '{self.worker_id}' failed to renew lease; "
                        "halting job execution to prevent split-brain overwrite."
                    )
                    self.tracker.terminate_all(reason="lease_lost")
                    break
            except Exception as exc:
                logger.warning(f"[job:{self.job_id}] Heartbeat renewal error: {sanitize_job_error_detail(str(exc))}")
            finally:
                if db is not None:
                    try:
                        db.close()
                    except Exception:
                        pass


# ==============================================================================
# Cancellation Engine & Worker Cancellation Acknowledgment (Task 7 & Phase 7 Sec 5)
# ==============================================================================

def acknowledge_job_cancellation(
    db: Session,
    job: Optional[DurableJob],
    resource_type: str,
    resource_id: str,
    worker_id: Optional[str] = None,
) -> Optional[DurableJob]:
    """Finalize a 'cancelling' job into terminal 'cancelled' state AFTER the worker has stopped active work."""
    now = _utc_now()
    if job is not None:
        _clear_fenced_leases_for_job(db, job.id)
        if job.status != JobState.CANCELLED.value:
            if job.status != JobState.CANCELLING.value:
                validate_job_transition(job.status, JobState.CANCELLING.value, job_id=job.id)
                job.status = JobState.CANCELLING.value
            validate_job_transition(job.status, JobState.CANCELLED.value, job_id=job.id)
            job.status = JobState.CANCELLED.value
        job.completed_at = now
        job.lease_token = None
        job.lease_expires_at = None
        job.failure_category = "cancelled"
        job.error_detail = (
            f"Job cancellation acknowledged by worker '{worker_id}'."
            if worker_id
            else "Job cancelled by user request."
        )
        release_atomic_job_slot(db, job, count_quota=False)
        req_utc = _ensure_utc(job.cancel_requested_at) or now
        _record_metric_sample("cancellation_latencies_ms", (now - req_utc).total_seconds() * 1000.0)

    if resource_type == "scan":
        scan = db.query(Scan).filter(Scan.id == resource_id).first()
        if scan and scan.status not in ("completed", "partial", "failed", "timed_out", "cancelled", "interrupted"):
            scan.status = "cancelled"
            scan.completed_at = now
            scan.summary = json.dumps({"status": "cancelled", "message": "Scan cancelled by user request."})
    elif resource_type == "verification":
        run = db.query(VerificationRun).filter(VerificationRun.id == resource_id).first()
        if run and run.status not in (
            "VERIFIED_AGAINST_DEFINED_CHECKS",
            "FAILED_VERIFICATION",
            "CANCELLED",
        ):
            run.status = "CANCELLED"
            run.completed_at = now
            run.reasons = json.dumps(["Verification cancelled by user request."])

    db.commit()
    if job is not None:
        db.refresh(job)
    return job


def cancel_durable_job(
    db: Session,
    job: Optional[DurableJob],
    resource_type: str,
    resource_id: str,
    actor_id: str,
    redis_client: Optional[Any] = None,
    require_worker_ack: bool = False,
) -> Optional[DurableJob]:
    """Cancel a queued, retrying, or running job safely and idempotently.

    - Queued / retrying jobs transition directly to 'cancelled' without executing,
      cancel pending outbox events, and release quota reservations.
    - Running jobs with an active remote worker lease transition to 'cancelling' and signal
      Redis + any active JobExecutionTracker. When require_worker_ack=True (or a remote worker
      holds a live lease and no local tracker is present in this process), the job remains in
      'cancelling' until the worker stops its subprocesses/containers and calls
      acknowledge_job_cancellation() (or its lease expires and recovery finalizes it).
    - Terminal jobs ('completed', 'failed', 'cancelled', 'interrupted') are returned unchanged.
    """
    now = _utc_now()
    if job is not None:
        _clear_fenced_leases_for_job(db, job.id)
    client = redis_client if redis_client is not None else get_job_redis_client()

    if job is not None:
        if job.status in TERMINAL_JOB_STATES:
            return job

        if job.cancel_requested_at is None:
            job.cancel_requested_at = now

        # Cancel any undispatched outbox events
        db.query(JobOutboxEvent).filter(
            JobOutboxEvent.job_id == job.id,
            JobOutboxEvent.status == "pending",
        ).update({"status": "cancelled", "updated_at": now}, synchronize_session=False)

        if job.status in (JobState.QUEUED.value, JobState.RETRYING.value):
            return acknowledge_job_cancellation(
                db=db,
                job=job,
                resource_type=resource_type,
                resource_id=resource_id,
            )

        if job.status in (JobState.RUNNING.value, JobState.CANCELLING.value):
            validate_job_transition(job.status, JobState.CANCELLING.value, job_id=job.id)
            job.status = JobState.CANCELLING.value
            db.flush()

            # Signal Redis cancellation channel/key for remote workers
            if client is not None:
                try:
                    client.setex(f"redmercury:job:cancel:{job.id}", 3600, "1")
                except Exception:
                    pass

            # Check if the worker's execution tracker is in the current process
            tracker = get_active_tracker(job.id) or get_active_tracker(resource_id)
            if tracker is not None:
                tracker.terminate_all(reason="cancelled")

            exp_utc = _ensure_utc(job.lease_expires_at)
            has_live_remote_lease = (
                job.lease_token is not None
                and exp_utc is not None
                and exp_utc > now
                and tracker is None
            )

            if require_worker_ack or has_live_remote_lease:
                # Do NOT mark terminally cancelled before the remote worker acknowledges cancellation and stops active work!
                if resource_type == "scan":
                    scan = db.query(Scan).filter(Scan.id == resource_id).first()
                    if scan and scan.status == "running":
                        scan.status = "cancelling"
                elif resource_type == "verification":
                    run = db.query(VerificationRun).filter(VerificationRun.id == resource_id).first()
                    if run and run.status == "RUNNING":
                        run.status = "CANCELLING"
                db.commit()
                db.refresh(job)
                return job

            # Local tracker already terminated all subprocesses/containers synchronously (or lease is not active)
            return acknowledge_job_cancellation(
                db=db,
                job=job,
                resource_type=resource_type,
                resource_id=resource_id,
                worker_id=job.worker_id,
            )
    else:
        tracker = get_active_tracker(resource_id)
        if tracker is not None:
            tracker.terminate_all(reason="cancelled")
        return acknowledge_job_cancellation(
            db=db,
            job=None,
            resource_type=resource_type,
            resource_id=resource_id,
        )

    return job


# ==============================================================================
# Expired Lease Detection, Crash Recovery & Reconciliation (Tasks 6 & 8)
# ==============================================================================

def recover_expired_job_leases(
    db: Session,
    max_batch: int = 50,
    redis_client: Optional[Any] = None,
    kill_orphans: bool = True,
) -> Dict[str, int]:
    """Detect and recover jobs abandoned by crashed workers whose lease_expires_at has passed.

    Concurrency-safe across multiple concurrent recovery processes:
    - Uses atomic CAS on (id, status, lease_token) so two recovery processes never double-recover a job.
    - Reaps and verifies orphaned child processes, sandbox containers, and disposable workspaces before
      finalizing cancellation or releasing concurrency slots (Phase 7A Section 3).
    - If active execution cannot be proven stopped, refuses to mark terminal cancellation or release the slot.
    - Retries eligible jobs (attempt_count < max_attempts) with exponential backoff + jitter.
    - Moves exhausted jobs (attempt_count >= max_attempts) into terminal 'failed' state and releases quota slots.
    - Completes pending cancellations ('cancelling' with expired lease -> 'cancelled') once orphans are stopped.
    """
    now = _utc_now()
    stats = {"retried": 0, "failed": 0, "cancelled": 0, "deferred_active": 0}

    expired_jobs = (
        db.query(DurableJob)
        .filter(
            DurableJob.status.in_([JobState.RUNNING.value, JobState.CANCELLING.value]),
            DurableJob.lease_expires_at.isnot(None),
            DurableJob.lease_expires_at <= now,
        )
        .order_by(DurableJob.lease_expires_at.asc())
        .limit(max_batch)
        .all()
    )

    for exp_job in expired_jobs:
        old_status = exp_job.status
        old_token = exp_job.lease_token
        _clear_fenced_leases_for_job(db, exp_job.id)

        # Reap and verify any orphaned child processes, sandbox containers, and disposable workspaces
        verified_stopped, reap_details = reap_and_verify_orphaned_job_resources(
            exp_job,
            kill_resources=kill_orphans,
        )
        if not verified_stopped:
            # Fail-closed (Phase 7A Section 3): Cannot prove execution has stopped!
            # Do NOT report a clean terminal cancellation or release the concurrency slot.
            defer_msg = (
                f"Recovery deferred: orphaned execution still active "
                f"(pids={reap_details['still_running_pids']}, containers={reap_details['still_running_containers']})."
            )
            db.query(DurableJob).filter(
                DurableJob.id == exp_job.id,
                DurableJob.status == old_status,
                DurableJob.lease_token == old_token,
            ).update(
                {
                    "error_detail": defer_msg[:400],
                    "updated_at": now,
                },
                synchronize_session=False,
            )
            db.commit()
            stats["deferred_active"] += 1
            logger.warning(f"[job:{exp_job.id}] {defer_msg}")
            continue

        # 1. If job was in 'cancelling' when worker crashed, finalize to 'cancelled'
        if old_status == JobState.CANCELLING.value:
            updated = (
                db.query(DurableJob)
                .filter(
                    DurableJob.id == exp_job.id,
                    DurableJob.status == JobState.CANCELLING.value,
                    DurableJob.lease_token == old_token,
                    DurableJob.lease_expires_at <= now,
                )
                .update(
                    {
                        "status": JobState.CANCELLED.value,
                        "completed_at": now,
                        "lease_token": None,
                        "lease_expires_at": None,
                        "failure_category": "cancelled",
                        "error_detail": "Job cancelled after worker lease expiration.",
                        "quota_reserved": False,
                        "quota_counted": False,
                        "updated_at": now,
                    },
                    synchronize_session=False,
                )
            )
            if updated == 1:
                db.query(ActiveJobSlot).filter(ActiveJobSlot.job_id == exp_job.id).delete(synchronize_session=False)
                if exp_job.job_type == "scan":
                    db.query(Scan).filter(Scan.id == exp_job.resource_id).update(
                        {
                            "status": "cancelled",
                            "completed_at": now,
                            "summary": json.dumps({"status": "cancelled", "message": "Cancelled during recovery."}),
                        },
                        synchronize_session=False,
                    )
                elif exp_job.job_type == "verification":
                    db.query(VerificationRun).filter(VerificationRun.id == exp_job.resource_id).update(
                        {"status": "CANCELLED", "completed_at": now},
                        synchronize_session=False,
                    )
                db.commit()
                stats["cancelled"] += 1
            continue

        # 2. Running job with expired lease: retry if under max_attempts, else terminal failed
        if exp_job.attempt_count < exp_job.max_attempts:
            delay_sec = compute_retry_backoff_seconds(exp_job.attempt_count)
            next_retry = now + timedelta(seconds=delay_sec)
            preserved_category = exp_job.failure_category or "lease_expired"
            updated = (
                db.query(DurableJob)
                .filter(
                    DurableJob.id == exp_job.id,
                    DurableJob.status == JobState.RUNNING.value,
                    DurableJob.lease_token == old_token,
                    DurableJob.lease_expires_at <= now,
                )
                .update(
                    {
                        "status": JobState.RETRYING.value,
                        "next_retry_at": next_retry,
                        "lease_token": None,
                        "lease_expires_at": None,
                        "failure_category": preserved_category,
                        "error_detail": (
                            f"Worker '{exp_job.worker_id}' lease expired on attempt "
                            f"{exp_job.attempt_count}/{exp_job.max_attempts}; scheduled for retry."
                        ),
                        "updated_at": now,
                    },
                    synchronize_session=False,
                )
            )
            if updated == 1:
                if exp_job.job_type == "scan":
                    db.query(Scan).filter(Scan.id == exp_job.resource_id).update(
                        {"status": "retrying", "updated_at": now},
                        synchronize_session=False,
                    )
                elif exp_job.job_type == "verification":
                    db.query(VerificationRun).filter(VerificationRun.id == exp_job.resource_id).update(
                        {"status": "RETRYING", "updated_at": now},
                        synchronize_session=False,
                    )
                outbox = JobOutboxEvent(
                    id=str(uuid.uuid4()),
                    job_id=exp_job.id,
                    job_type=exp_job.job_type,
                    resource_id=exp_job.resource_id,
                    queue_name=settings.JOB_QUEUE_NAME,
                    status="pending",
                )
                db.add(outbox)
                db.commit()
                stats["retried"] += 1
                logger.warning(
                    f"[job:{exp_job.id}] Recovered expired lease from worker '{exp_job.worker_id}' "
                    f"(attempt {exp_job.attempt_count}/{exp_job.max_attempts} -> retrying in {delay_sec:.2f}s)"
                )
        else:
            preserved_category = exp_job.failure_category or "max_retries_exceeded"
            err_msg = (
                f"Job failed permanently after {exp_job.attempt_count} attempts "
                f"(last worker '{exp_job.worker_id}' lease expired)."
            )
            updated = (
                db.query(DurableJob)
                .filter(
                    DurableJob.id == exp_job.id,
                    DurableJob.status == JobState.RUNNING.value,
                    DurableJob.lease_token == old_token,
                    DurableJob.lease_expires_at <= now,
                )
                .update(
                    {
                        "status": JobState.FAILED.value,
                        "failed_at": now,
                        "completed_at": now,
                        "lease_token": None,
                        "lease_expires_at": None,
                        "failure_category": preserved_category,
                        "error_detail": err_msg,
                        "quota_reserved": False,
                        "quota_counted": True,
                        "updated_at": now,
                    },
                    synchronize_session=False,
                )
            )
            if updated == 1:
                db.query(ActiveJobSlot).filter(ActiveJobSlot.job_id == exp_job.id).delete(synchronize_session=False)
                if exp_job.job_type == "scan":
                    db.query(Scan).filter(Scan.id == exp_job.resource_id).update(
                        {
                            "status": "failed",
                            "completed_at": now,
                            "summary": json.dumps({"error": err_msg, "failure_category": preserved_category}),
                        },
                        synchronize_session=False,
                    )
                elif exp_job.job_type == "verification":
                    db.query(VerificationRun).filter(VerificationRun.id == exp_job.resource_id).update(
                        {
                            "status": "INCONCLUSIVE",
                            "completed_at": now,
                            "reasons": json.dumps([err_msg]),
                        },
                        synchronize_session=False,
                    )
                db.commit()
                stats["failed"] += 1
                logger.error(f"[job:{exp_job.id}] Lease expired and max attempts ({exp_job.max_attempts}) reached -> failed")

    if stats["retried"] > 0:
        dispatch_outbox_events(db=db, redis_client=redis_client)

    return stats


def reconcile_jobs_on_startup(
    db: Session,
    component: str = "api",
    redis_client: Optional[Any] = None,
) -> Dict[str, int]:
    """Idempotent startup reconciliation for API and Worker processes (Task 8).

    Invariants:
    1. NEVER marks a running job as interrupted if it holds a valid, non-expired worker lease.
    2. Recovers expired worker leases (transitioning to retrying or terminal failed/cancelled).
    3. Recovers and dispatches any undispatched outbox events.
    4. Reconciles legacy lease-less stale jobs that exceeded STALE_JOB_TIMEOUT_MINUTES.
    """
    lease_stats = recover_expired_job_leases(db=db, redis_client=redis_client)
    outbox_dispatched = recover_undispatched_outbox_events(db=db, redis_client=redis_client)

    from .quotas import reconcile_interrupted_jobs
    legacy_reconciled = reconcile_interrupted_jobs(db=db)

    summary = {
        "expired_leases_retried": lease_stats["retried"],
        "expired_leases_failed": lease_stats["failed"],
        "expired_leases_cancelled": lease_stats["cancelled"],
        "outbox_events_dispatched": outbox_dispatched,
        "legacy_stale_jobs_interrupted": legacy_reconciled,
    }
    total_actions = sum(summary.values())
    if total_actions > 0:
        try:
            record_audit_event(
                db=db,
                action="JOB_RECONCILIATION_COMPLETED",
                resource_type="job_queue",
                resource_identifier=component,
                actor_id="system",
                metadata=summary,
            )
        except Exception:
            pass
    return summary


# ==============================================================================
# Worker Execution Engine with Tenant Revalidation (Tasks 1, 7, 9)
# ==============================================================================

def execute_claimed_durable_job(
    db: Session,
    job: DurableJob,
    worker_id: str,
    session_factory: Optional[Callable[[], Session]] = None,
    start_heartbeat: bool = True,
    redis_client: Optional[Any] = None,
) -> DurableJob:
    """Execute a claimed DurableJob with tenant ownership revalidation, heartbeat renewal, and cancellation tracking.

    Security invariants (Task 9):
    - Never trusts tenant identity from Redis; derives tenant_id, Repository, Scan, and VerificationRun from DB.
    - Revalidates repository and resource ownership before execution.
    - Enforces lease fencing before committing results so an expired worker cannot overwrite newer state.
    """
    from ..db.session import SessionLocal
    from ..scanner.runner import run_security_scan
    from ..schemas.verification import VerificationRunRequest
    from ..verification.service import execute_fix_verification

    sess_factory = session_factory or SessionLocal
    lease_token = job.lease_token or ""
    tracker = JobExecutionTracker(
        job_id=job.id,
        resource_id=job.resource_id,
        tenant_id=job.tenant_id,
        worker_id=worker_id,
        lease_token=lease_token,
        session_factory=sess_factory,
    )
    register_active_tracker(tracker)

    hb_monitor: Optional[JobHeartbeatMonitor] = None
    if start_heartbeat:
        hb_monitor = JobHeartbeatMonitor(
            session_factory=sess_factory,
            job_id=job.id,
            worker_id=worker_id,
            lease_token=lease_token,
            tracker=tracker,
        )
        hb_monitor.start()

    try:
        # Check if cancellation was already requested before execution begins
        db.refresh(job)
        if job.status in (JobState.CANCELLING.value, JobState.CANCELLED.value) or tracker.should_abort():
            cancel_durable_job(
                db=db,
                job=job,
                resource_type=job.job_type,
                resource_id=job.resource_id,
                actor_id=job.tenant_id or "system",
                redis_client=redis_client,
            )
            return job

        payload: Dict[str, Any] = {}
        if job.payload_json:
            try:
                payload = json.loads(job.payload_json)
            except Exception:
                payload = {}

        if job.job_type == "scan":
            scan = db.query(Scan).filter(Scan.id == job.resource_id).first()
            if not scan:
                return fail_claimed_job(
                    db=db,
                    job_id=job.id,
                    worker_id=worker_id,
                    lease_token=lease_token,
                    failure_category="resource_not_found",
                    error_detail=f"Target scan '{job.resource_id}' not found.",
                    retryable=False,
                )

            repo = db.query(Repository).filter(Repository.id == scan.repository_id).first()
            if not repo:
                return fail_claimed_job(
                    db=db,
                    job_id=job.id,
                    worker_id=worker_id,
                    lease_token=lease_token,
                    failure_category="resource_not_found",
                    error_detail=f"Target repository '{scan.repository_id}' not found.",
                    retryable=False,
                )

            # Task 9 Requirement 1–3: Revalidate tenant ownership from authoritative database records
            if not job.tenant_id or repo.owner_id != job.tenant_id or (job.repository_id and job.repository_id != repo.id):
                return fail_claimed_job(
                    db=db,
                    job_id=job.id,
                    worker_id=worker_id,
                    lease_token=lease_token,
                    failure_category="policy_violation",
                    error_detail="Tenant ownership verification failed for scan job.",
                    retryable=False,
                )

            selected_tools = payload.get("tools")
            timeout_per_tool = int(payload.get("timeout_seconds") or 60)

            # Verify lease before running scanner adapters
            verify_worker_owns_valid_lease(db, job_id=job.id, worker_id=worker_id, lease_token=lease_token)

            updated_scan = run_security_scan(
                repo=repo,
                scan=scan,
                db=db,
                selected_tools=selected_tools,
                timeout_per_tool=timeout_per_tool,
                commit_changes=False,
            )

            # If lease was lost during scan execution, roll back uncommitted findings and raise StaleWorkerLeaseError
            if tracker.lease_lost_event.is_set():
                db.rollback()
                raise StaleWorkerLeaseError(job_id=job.id, worker_id=worker_id)

            # Check if job was cancelled while running
            current_job_status = db.query(DurableJob.status).filter(DurableJob.id == job.id).scalar()
            if current_job_status in (JobState.CANCELLING.value, JobState.CANCELLED.value) or tracker.cancel_event.is_set():
                db.rollback()
                tracker.terminate_all(reason="cancelled")
                job_reloaded = db.query(DurableJob).filter(DurableJob.id == job.id).first()
                acknowledge_job_cancellation(
                    db=db,
                    job=job_reloaded,
                    resource_type="scan",
                    resource_id=scan.id,
                    worker_id=worker_id,
                )
                return job_reloaded or job

            # Re-verify lease ownership BEFORE committing scan findings & posture updates!
            verify_worker_owns_valid_lease(db, job_id=job.id, worker_id=worker_id, lease_token=lease_token)

            if updated_scan.status == "failed":
                err_msg = "Security scan failed."
                if updated_scan.summary:
                    try:
                        err_msg = json.loads(updated_scan.summary).get("error") or err_msg
                    except Exception:
                        pass
                retryable_flag = bool(payload.get("retry_on_scanner_failure", False))
                db.commit()
                return fail_claimed_job(
                    db=db,
                    job_id=job.id,
                    worker_id=worker_id,
                    lease_token=lease_token,
                    failure_category="scanner_error",
                    error_detail=err_msg,
                    retryable=retryable_flag,
                )

            return complete_claimed_job(
                db=db,
                job_id=job.id,
                worker_id=worker_id,
                lease_token=lease_token,
            )

        elif job.job_type == "verification":
            run = db.query(VerificationRun).filter(VerificationRun.id == job.resource_id).first()
            if not run or not run.finding_id:
                return fail_claimed_job(
                    db=db,
                    job_id=job.id,
                    worker_id=worker_id,
                    lease_token=lease_token,
                    failure_category="resource_not_found",
                    error_detail=f"Target verification run '{job.resource_id}' not found.",
                    retryable=False,
                )

            finding = db.query(SecurityFinding).filter(SecurityFinding.id == run.finding_id).first()
            repo = db.query(Repository).filter(Repository.id == finding.repo_id).first() if finding else None
            if not finding or not repo or not job.tenant_id or repo.owner_id != job.tenant_id:
                return fail_claimed_job(
                    db=db,
                    job_id=job.id,
                    worker_id=worker_id,
                    lease_token=lease_token,
                    failure_category="policy_violation",
                    error_detail="Tenant ownership verification failed for verification job.",
                    retryable=False,
                )

            verify_worker_owns_valid_lease(db, job_id=job.id, worker_id=worker_id, lease_token=lease_token)

            req = VerificationRunRequest(
                finding_id=run.finding_id,
                proposed_patch=run.patch_diff or payload.get("proposed_patch", ""),
                patch_id=run.patch_id,
                scanner_names=payload.get("scanner_names"),
                scanner_config=payload.get("scanner_config") or {},
                run_existing_tests=bool(payload.get("run_existing_tests", True)),
                run_regression_tests=bool(payload.get("run_regression_tests", True)),
                regression_test_code=payload.get("regression_test_code"),
                regression_test_file=payload.get("regression_test_file"),
                timeout_seconds=int(payload.get("timeout_seconds") or 60),
            )

            execute_fix_verification(
                request=req,
                db=db,
                user_id=job.tenant_id,
                existing_run_id=run.id,
                commit_changes=False,
            )

            if tracker.lease_lost_event.is_set():
                db.rollback()
                raise StaleWorkerLeaseError(job_id=job.id, worker_id=worker_id)

            current_job_status = db.query(DurableJob.status).filter(DurableJob.id == job.id).scalar()
            if current_job_status in (JobState.CANCELLING.value, JobState.CANCELLED.value) or tracker.cancel_event.is_set():
                db.rollback()
                tracker.terminate_all(reason="cancelled")
                job_reloaded = db.query(DurableJob).filter(DurableJob.id == job.id).first()
                acknowledge_job_cancellation(
                    db=db,
                    job=job_reloaded,
                    resource_type="verification",
                    resource_id=run.id,
                    worker_id=worker_id,
                )
                return job_reloaded or job

            verify_worker_owns_valid_lease(db, job_id=job.id, worker_id=worker_id, lease_token=lease_token)

            return complete_claimed_job(
                db=db,
                job_id=job.id,
                worker_id=worker_id,
                lease_token=lease_token,
            )

        elif job.job_type == "webhook":
            delivery = db.query(WebhookDelivery).filter(WebhookDelivery.id == job.resource_id).first()
            if not delivery:
                return fail_claimed_job(
                    db=db,
                    job_id=job.id,
                    worker_id=worker_id,
                    lease_token=lease_token,
                    failure_category="resource_not_found",
                    error_detail=f"Webhook delivery '{job.resource_id}' not found.",
                    retryable=False,
                )
            verify_worker_owns_valid_lease(db, job_id=job.id, worker_id=worker_id, lease_token=lease_token)
            delivery.status = "completed"
            return complete_claimed_job(
                db=db,
                job_id=job.id,
                worker_id=worker_id,
                lease_token=lease_token,
            )

        else:
            return fail_claimed_job(
                db=db,
                job_id=job.id,
                worker_id=worker_id,
                lease_token=lease_token,
                failure_category="unsupported_job_type",
                error_detail=f"Unsupported job type '{job.job_type}'.",
                retryable=False,
            )

    except StaleWorkerLeaseError:
        db.rollback()
        raise
    except Exception as exc:
        db.rollback()
        try:
            return fail_claimed_job(
                db=db,
                job_id=job.id,
                worker_id=worker_id,
                lease_token=lease_token,
                failure_category="execution_exception",
                error_detail=str(exc),
                retryable=True,
                redis_client=redis_client,
            )
        except StaleWorkerLeaseError:
            db.rollback()
            raise
    finally:
        if hb_monitor is not None:
            hb_monitor.stop()
        tracker.cleanup_temp_workspaces()
        unregister_active_tracker(tracker)


# ==============================================================================
# Operational Metrics & Health Introspection (Task 12)
# ==============================================================================

def get_job_operational_metrics(
    db: Session,
    heartbeat_file: Optional[Path] = None,
    redis_client: Optional[Any] = None,
) -> Dict[str, Any]:
    """Return safe, non-sensitive operational metrics for the job queue, outbox, leases, and workers."""
    now = _utc_now()
    client = redis_client if redis_client is not None else get_job_redis_client()

    queue_depth = 0
    redis_status = "unconfigured"
    if client is not None:
        try:
            queue_depth = int(client.llen(settings.JOB_QUEUE_NAME) or 0)
            redis_status = "connected"
        except Exception:
            redis_status = "unreachable"

    pending_outbox = db.query(JobOutboxEvent).filter(JobOutboxEvent.status == "pending").count()
    queued_jobs = db.query(DurableJob).filter(DurableJob.status == JobState.QUEUED.value).count()
    running_jobs = db.query(DurableJob).filter(DurableJob.status == JobState.RUNNING.value).count()
    retrying_jobs = db.query(DurableJob).filter(DurableJob.status == JobState.RETRYING.value).count()
    cancelling_jobs = db.query(DurableJob).filter(DurableJob.status == JobState.CANCELLING.value).count()
    completed_jobs = db.query(DurableJob).filter(DurableJob.status == JobState.COMPLETED.value).count()
    failed_jobs = db.query(DurableJob).filter(DurableJob.status == JobState.FAILED.value).count()
    cancelled_jobs = db.query(DurableJob).filter(DurableJob.status == JobState.CANCELLED.value).count()
    interrupted_jobs = db.query(DurableJob).filter(DurableJob.status == JobState.INTERRUPTED.value).count()

    expired_leases = (
        db.query(DurableJob)
        .filter(
            DurableJob.status.in_([JobState.RUNNING.value, JobState.CANCELLING.value]),
            DurableJob.lease_expires_at.isnot(None),
            DurableJob.lease_expires_at <= now,
        )
        .count()
    )

    total_attempts = db.query(func.coalesce(func.sum(DurableJob.attempt_count), 0)).scalar() or 0
    executed_jobs_count = db.query(DurableJob).filter(DurableJob.attempt_count > 0).count()
    retry_counts = max(0, int(total_attempts) - int(executed_jobs_count))

    # Worker heartbeat age from most recent active job heartbeat or worker heartbeat file
    latest_hb = db.query(func.max(DurableJob.heartbeat_at)).scalar()
    hb_age_seconds: Optional[float] = None
    worker_status = "idle"

    if heartbeat_file is None:
        from ..scanner.worker import get_heartbeat_path
        heartbeat_file = get_heartbeat_path()

    if heartbeat_file and heartbeat_file.exists():
        try:
            hb_data = json.loads(heartbeat_file.read_text(encoding="utf-8"))
            file_ts = float(hb_data.get("timestamp", 0))
            if file_ts > 0:
                hb_age_seconds = round(max(0.0, time.time() - file_ts), 2)
                worker_status = "healthy" if hb_age_seconds <= 60.0 else "stale"
        except Exception:
            worker_status = "degraded"
    elif latest_hb is not None:
        hb_utc = _ensure_utc(latest_hb)
        if hb_utc:
            hb_age_seconds = round(max(0.0, (now - hb_utc).total_seconds()), 2)
            worker_status = "healthy" if hb_age_seconds <= float(settings.JOB_LEASE_DURATION_SECONDS) else "stale"

    with _METRICS_LOCK:
        disp_samples = list(_JOB_METRICS["dispatch_latencies_ms"])
        exec_samples = list(_JOB_METRICS["execution_durations_ms"])
        canc_samples = list(_JOB_METRICS["cancellation_latencies_ms"])

    avg_disp = round(sum(disp_samples) / len(disp_samples), 2) if disp_samples else 0.0
    avg_exec = round(sum(exec_samples) / len(exec_samples), 2) if exec_samples else 0.0
    avg_canc = round(sum(canc_samples) / len(canc_samples), 2) if canc_samples else 0.0

    return {
        "queue_depth": max(queue_depth, queued_jobs),
        "redis_queue_depth": queue_depth,
        "redis_status": redis_status,
        "pending_outbox_events": pending_outbox,
        "active_jobs": queued_jobs + running_jobs + retrying_jobs + cancelling_jobs,
        "queued_jobs": queued_jobs,
        "running_jobs": running_jobs,
        "retrying_jobs": retrying_jobs,
        "cancelling_jobs": cancelling_jobs,
        "completed_jobs": completed_jobs,
        "failed_jobs": failed_jobs,
        "cancelled_jobs": cancelled_jobs,
        "interrupted_jobs": interrupted_jobs,
        "expired_leases": expired_leases,
        "retry_counts": retry_counts,
        "worker_status": worker_status,
        "worker_heartbeat_age_seconds": hb_age_seconds,
        "avg_queue_dispatch_latency_ms": avg_disp,
        "avg_job_execution_duration_ms": avg_exec,
        "avg_cancellation_latency_ms": avg_canc,
        "operational_guidance": {
            "stuck_jobs": "Expired leases are automatically recovered via recover_expired_job_leases() into 'retrying' or 'failed' states.",
            "failed_workers": "Workers that fail to renew heartbeats within JOB_LEASE_DURATION_SECONDS lose their lease_token and cannot overwrite newer state.",
        },
    }
