"""Job quotas, concurrency limit enforcement, and interrupted job reconciliation."""
from datetime import datetime, timedelta, timezone
import json
from sqlalchemy.orm import Session

from .config import settings
from .errors import SecurityPolicyViolationError
from .logging import get_logger
from ..models.finding import SecurityFinding
from ..models.github import PullRequestScan
from ..models.repository import Repository
from ..models.scan import Scan
from ..models.user import User
from ..models.verification import VerificationRun

logger = get_logger("redmercury.quotas")


def check_scan_concurrency_and_quota(user: User, db: Session) -> None:
    """Enforce per-user active scan concurrency limits and 24-hour scan quotas."""
    # 1. Check concurrent running scans
    active_scans_count = (
        db.query(Scan)
        .join(Repository, Scan.repository_id == Repository.id)
        .filter(
            Repository.owner_id == user.id,
            Scan.status.in_(["running", "pending", "queued"]),
        )
        .count()
    )

    if active_scans_count >= settings.MAX_CONCURRENT_SCANS_PER_USER:
        logger.warning(
            f"Concurrency limit exceeded for user {user.id}: {active_scans_count} active scans"
        )
        raise SecurityPolicyViolationError(
            f"Concurrency limit reached: you currently have {active_scans_count} scans in progress. "
            f"Maximum allowed concurrent scans is {settings.MAX_CONCURRENT_SCANS_PER_USER}."
        )

    # 2. Check 24-hour quota
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    daily_scans_count = (
        db.query(Scan)
        .join(Repository, Scan.repository_id == Repository.id)
        .filter(
            Repository.owner_id == user.id,
            Scan.created_at >= cutoff,
        )
        .count()
    )

    if daily_scans_count >= settings.MAX_DAILY_SCANS_PER_USER:
        logger.warning(
            f"Daily scan quota exceeded for user {user.id}: {daily_scans_count} scans in last 24h"
        )
        raise SecurityPolicyViolationError(
            f"Daily scan quota exceeded: you have executed {daily_scans_count} scans in the last 24 hours. "
            f"Maximum quota is {settings.MAX_DAILY_SCANS_PER_USER} scans per day."
        )


def check_verification_concurrency(user: User, db: Session) -> None:
    """Enforce per-user concurrent verification run limits."""
    active_verifications_count = (
        db.query(VerificationRun)
        .join(SecurityFinding, VerificationRun.finding_id == SecurityFinding.id)
        .join(Repository, SecurityFinding.repo_id == Repository.id)
        .filter(
            Repository.owner_id == user.id,
            VerificationRun.status == "RUNNING",
        )
        .count()
    )

    if active_verifications_count >= settings.MAX_CONCURRENT_VERIFICATIONS_PER_USER:
        logger.warning(
            f"Verification concurrency limit exceeded for user {user.id}: {active_verifications_count} runs"
        )
        raise SecurityPolicyViolationError(
            f"Concurrency limit reached: you currently have {active_verifications_count} fix verifications in progress. "
            f"Maximum allowed concurrent verifications is {settings.MAX_CONCURRENT_VERIFICATIONS_PER_USER}."
        )


def reconcile_interrupted_jobs(db: Session) -> int:
    """Transition hanging/interrupted jobs into a deterministic state upon service startup.

    Phase 6 Invariants:
    1. First runs lease-aware recovery (`recover_expired_job_leases`) for DurableJob records.
    2. NEVER marks a running Scan or VerificationRun as interrupted if it has an active, non-expired worker lease!
    3. Reconciles legacy lease-less stale jobs whose `created_at <= stale_cutoff`.
    """
    reconciled_count = 0
    now = datetime.now(timezone.utc)
    stale_cutoff = now - timedelta(minutes=settings.STALE_JOB_TIMEOUT_MINUTES)

    from ..models.job import ActiveJobSlot, DurableJob
    from .jobs import JobState, recover_expired_job_leases

    lease_stats = recover_expired_job_leases(db=db)
    reconciled_count += (
        lease_stats.get("retried", 0)
        + lease_stats.get("failed", 0)
        + lease_stats.get("cancelled", 0)
    )

    # 1. Reconcile legacy stale scans that do NOT have an active non-expired worker lease
    hanging_scans = db.query(Scan).filter(
        Scan.status.in_(["running", "pending", "queued"]),
        Scan.created_at <= stale_cutoff,
    ).all()

    for scan in hanging_scans:
        djob = (
            db.query(DurableJob)
            .filter(DurableJob.job_type == "scan", DurableJob.resource_id == scan.id)
            .first()
        )
        if djob is not None:
            exp = djob.lease_expires_at
            if exp is not None and exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            djob_created = djob.created_at
            if djob_created is not None and djob_created.tzinfo is None:
                djob_created = djob_created.replace(tzinfo=timezone.utc)
            # Do NOT interrupt a healthy running job with a valid lease or a healthy queued durable job
            if djob.status == JobState.RUNNING.value and exp is not None and exp > now:
                continue
            if djob.status in (JobState.QUEUED.value, JobState.RETRYING.value) and djob_created is not None and djob_created > stale_cutoff:
                continue
            djob.status = JobState.INTERRUPTED.value
            djob.completed_at = now
            djob.lease_token = None
            djob.lease_expires_at = None
            djob.quota_reserved = False
            djob.failure_category = "interrupted"
            djob.error_detail = "Scan execution interrupted by worker restart, host eviction, or timeout."
            db.query(ActiveJobSlot).filter(ActiveJobSlot.job_id == djob.id).delete(synchronize_session=False)

        scan.status = "interrupted"
        scan.completed_at = now
        scan.summary = json.dumps({
            "error": "Scan execution interrupted by worker restart, host eviction, or timeout.",
            "reconciled_at": now.isoformat(),
        })
        reconciled_count += 1
        logger.warning(f"Reconciled hanging scan {scan.id} -> interrupted")

    # 2. Reconcile interrupted verification runs that do NOT have an active non-expired worker lease
    hanging_runs = db.query(VerificationRun).filter(
        VerificationRun.status == "RUNNING",
        VerificationRun.created_at <= stale_cutoff,
    ).all()

    for run in hanging_runs:
        djob = (
            db.query(DurableJob)
            .filter(DurableJob.job_type == "verification", DurableJob.resource_id == run.id)
            .first()
        )
        if djob is not None:
            exp = djob.lease_expires_at
            if exp is not None and exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if djob.status == JobState.RUNNING.value and exp is not None and exp > now:
                continue
            djob.status = JobState.INTERRUPTED.value
            djob.completed_at = now
            djob.lease_token = None
            djob.lease_expires_at = None
            djob.quota_reserved = False
            djob.failure_category = "interrupted"
            djob.error_detail = "Verification interrupted by worker container restart or timeout."
            db.query(ActiveJobSlot).filter(ActiveJobSlot.job_id == djob.id).delete(synchronize_session=False)

        run.status = "INCONCLUSIVE"
        run.completed_at = now
        reasons = run.reasons or []
        if isinstance(reasons, str):
            try:
                reasons = json.loads(reasons)
            except Exception:
                reasons = [reasons]
        reasons.append("Verification interrupted by worker container restart or timeout.")
        run.reasons = reasons if isinstance(run.reasons, list) else json.dumps(reasons)
        reconciled_count += 1
        logger.warning(f"Reconciled hanging verification run {run.id} -> INCONCLUSIVE")

    # 3. Reconcile interrupted PR scans
    hanging_pr_scans = db.query(PullRequestScan).filter(
        PullRequestScan.status == "analyzing",
        PullRequestScan.started_at <= stale_cutoff,
    ).all()

    for pr_scan in hanging_pr_scans:
        pr_scan.status = "inconclusive"
        pr_scan.completed_at = now
        pr_scan.execution_log = "PR scan interrupted by worker container restart."
        reconciled_count += 1
        logger.warning(f"Reconciled hanging PR scan {pr_scan.id} -> inconclusive")

    if reconciled_count > 0:
        db.commit()
        logger.info(f"Reconciliation complete: safely terminated {reconciled_count} orphaned jobs.")

    return reconciled_count
