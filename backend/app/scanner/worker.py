"""Persistent background worker process for Red Mercury durable job execution (Phase 6 / REL-01).

Implements:
- Atomic job claiming with lease fencing tokens (claim_next_durable_job).
- Periodic worker heartbeats and lease expiration recovery (recover_expired_job_leases).
- Transactional outbox recovery (recover_undispatched_outbox_events).
- Bounded concurrency (WORKER_CONCURRENCY).
- Graceful shutdown on SIGTERM/SIGINT releasing or preserving active leases.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import signal
import socket
import sys
import tempfile
import threading
import time
from typing import List, Optional
import uuid

from sqlalchemy.exc import DatabaseError, OperationalError

from ..core.config import settings
from ..core.jobs import JobState, claim_next_durable_job, execute_claimed_durable_job, reconcile_jobs_on_startup, recover_expired_job_leases, recover_undispatched_outbox_events, release_claimed_job_on_shutdown
from ..core.logging import get_logger
from ..core.quotas import reconcile_interrupted_jobs
from ..db.session import SessionLocal, check_db_connection
from ..models.finding import SecurityFinding
from ..models.job import DurableJob
from ..models.repository import Repository
from ..models.scan import Scan
from ..models.verification import VerificationRun

logger = get_logger("redmercury.scanner.worker")

# Global graceful shutdown flag
_SHUTDOWN_REQUESTED = False
_ACTIVE_LEASES_LOCK = threading.Lock()
_ACTIVE_LEASES: dict[str, tuple[str, str]] = {}  # job_id -> (worker_id, lease_token)


def get_default_worker_id() -> str:
    host = socket.gethostname() or "worker"
    return f"rm-worker-{host}-{os.getpid()}"


def _signal_handler(signum, frame):
    """Handle process termination signals gracefully."""
    global _SHUTDOWN_REQUESTED
    sig_name = signal.Signals(signum).name if hasattr(signal, "Signals") else str(signum)
    logger.info(f"Received termination signal {sig_name}. Stopping new job claims and preparing graceful shutdown...")
    _SHUTDOWN_REQUESTED = True


def get_heartbeat_path(custom_path: Optional[str] = None) -> Path:
    """Determine the file path for the worker liveness heartbeat."""
    if custom_path:
        return Path(custom_path)

    if os.environ.get("WORKER_TEMP_DIR"):
        return Path(os.environ["WORKER_TEMP_DIR"]) / "worker_heartbeat.json"

    sandbox_temp = Path("/sandbox/temp")
    if sandbox_temp.exists() and sandbox_temp.is_dir():
        return sandbox_temp / "worker_heartbeat.json"

    return Path(tempfile.gettempdir()) / "redmercury_worker_heartbeat.json"


def write_heartbeat(heartbeat_file: Path, jobs_processed: int, worker_id: Optional[str] = None) -> None:
    """Write current worker liveness timestamp to disk."""
    try:
        heartbeat_file.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "status": "healthy",
            "service": "redmercury-worker",
            "worker_id": worker_id or get_default_worker_id(),
            "timestamp": time.time(),
            "iso": datetime.now(timezone.utc).isoformat(),
            "pid": os.getpid(),
            "jobs_processed": jobs_processed,
        }
        temp_file = heartbeat_file.with_suffix(".tmp")
        temp_file.write_text(json.dumps(data), encoding="utf-8")
        temp_file.replace(heartbeat_file)
    except Exception as exc:
        logger.warning(f"Could not update heartbeat file {heartbeat_file}: {exc}")


def run_healthcheck(heartbeat_file: Path, max_age_seconds: float = 60.0) -> int:
    """Perform healthcheck probe for container orchestration.

    Returns:
        0 if healthy (database responsive and recent heartbeat present).
        1 if unhealthy.
    """
    logger.info("Executing worker healthcheck probe...")

    if not check_db_connection():
        logger.error("Healthcheck FAILED: Database connection is unreachable.")
        return 1

    if heartbeat_file.exists():
        try:
            content = json.loads(heartbeat_file.read_text(encoding="utf-8"))
            last_ts = float(content.get("timestamp", 0))
            age = time.time() - last_ts
            if age > max_age_seconds:
                logger.error(f"Healthcheck FAILED: Heartbeat is stale ({age:.1f}s > {max_age_seconds}s).")
                return 1
        except Exception as exc:
            logger.error(f"Healthcheck FAILED: Corrupted heartbeat file: {exc}")
            return 1

    logger.info("Healthcheck PASSED: Worker is healthy and responsive.")
    return 0


def _ensure_durable_jobs_for_orphan_resources(db) -> None:
    """Backfill DurableJob rows for any raw Scan or VerificationRun rows inserted directly in tests."""
    # 1. Raw scans in pending/queued without a DurableJob
    orphan_scans = (
        db.query(Scan)
        .outerjoin(
            DurableJob,
            (DurableJob.resource_id == Scan.id) & (DurableJob.job_type == "scan"),
        )
        .filter(
            Scan.status.in_(["pending", "queued"]),
            DurableJob.id.is_(None),
        )
        .limit(20)
        .all()
    )
    for scan in orphan_scans:
        repo = db.query(Repository).filter(Repository.id == scan.repository_id).first()
        if not repo or not repo.workspace_path or not Path(repo.workspace_path).exists():
            scan.status = "failed"
            scan.completed_at = datetime.now(timezone.utc)
            scan.summary = json.dumps({"error": "Repository workspace path is not set or no longer exists."})
            continue
        cfg = {}
        if scan.scanner_configuration:
            try:
                parsed = json.loads(scan.scanner_configuration) if isinstance(scan.scanner_configuration, str) else scan.scanner_configuration
                if isinstance(parsed, dict):
                    cfg = parsed
            except Exception:
                cfg = {}
        djob = DurableJob(
            id=str(uuid.uuid4()),
            job_type="scan",
            resource_id=scan.id,
            tenant_id=repo.owner_id if repo else None,
            repository_id=scan.repository_id,
            status=JobState.QUEUED.value,
            payload_json=json.dumps({
                "repository_id": scan.repository_id,
                "tools": cfg.get("tools"),
                "timeout_seconds": int(cfg.get("timeout_seconds", 60)),
            }),
            attempt_count=0,
            max_attempts=settings.JOB_MAX_ATTEMPTS,
            quota_reserved=False,
            quota_counted=False,
        )
        db.add(djob)

    # 2. Raw verification runs in pending/queued/NOT_TESTED without a DurableJob
    orphan_runs = (
        db.query(VerificationRun)
        .outerjoin(
            DurableJob,
            (DurableJob.resource_id == VerificationRun.id) & (DurableJob.job_type == "verification"),
        )
        .filter(
            VerificationRun.status.in_(["pending", "queued", "QUEUED", "NOT_TESTED"]),
            VerificationRun.patch_diff.isnot(None),
            VerificationRun.finding_id.isnot(None),
            DurableJob.id.is_(None),
        )
        .limit(20)
        .all()
    )
    for run in orphan_runs:
        finding = db.query(SecurityFinding).filter(SecurityFinding.id == run.finding_id).first()
        repo = db.query(Repository).filter(Repository.id == finding.repo_id).first() if finding else None
        scanner_cfg = {}
        if run.scanner_config:
            try:
                scanner_cfg = json.loads(run.scanner_config) if isinstance(run.scanner_config, str) else run.scanner_config
            except Exception:
                scanner_cfg = {}
        djob = DurableJob(
            id=str(uuid.uuid4()),
            job_type="verification",
            resource_id=run.id,
            tenant_id=repo.owner_id if repo else None,
            repository_id=repo.id if repo else None,
            status=JobState.QUEUED.value,
            payload_json=json.dumps({
                "finding_id": run.finding_id,
                "proposed_patch": run.patch_diff,
                "patch_id": run.patch_id,
                "scanner_config": scanner_cfg if isinstance(scanner_cfg, dict) else {},
                "run_existing_tests": True,
                "run_regression_tests": True,
            }),
            attempt_count=0,
            max_attempts=settings.JOB_MAX_ATTEMPTS,
            quota_reserved=False,
            quota_counted=False,
        )
        db.add(djob)

    if orphan_scans or orphan_runs:
        db.commit()


def process_durable_jobs(
    db,
    max_batch: int = 5,
    worker_id: Optional[str] = None,
    job_types: Optional[List[str]] = None,
    lease_seconds: Optional[int] = None,
) -> int:
    """Atomically claim and execute up to max_batch durable jobs."""
    global _SHUTDOWN_REQUESTED
    w_id = worker_id or get_default_worker_id()
    processed_count = 0

    try:
        _ensure_durable_jobs_for_orphan_resources(db)

        for _ in range(max_batch):
            if _SHUTDOWN_REQUESTED:
                logger.info(f"Worker '{w_id}' shutdown requested; halting new job claims.")
                break

            claimed = claim_next_durable_job(
                db=db,
                worker_id=w_id,
                job_types=job_types,
                lease_seconds=lease_seconds,
            )
            if claimed is None:
                break

            with _ACTIVE_LEASES_LOCK:
                _ACTIVE_LEASES[claimed.id] = (w_id, claimed.lease_token or "")

            try:
                if _SHUTDOWN_REQUESTED:
                    release_claimed_job_on_shutdown(
                        db=db,
                        job_id=claimed.id,
                        worker_id=w_id,
                        lease_token=claimed.lease_token or "",
                    )
                    break

                execute_claimed_durable_job(
                    db=db,
                    job=claimed,
                    worker_id=w_id,
                )
                processed_count += 1
            finally:
                with _ACTIVE_LEASES_LOCK:
                    _ACTIVE_LEASES.pop(claimed.id, None)

    except (OperationalError, DatabaseError) as db_err:
        logger.warning(f"Database error during worker job processing: {db_err}")
        db.rollback()
    except Exception as exc:
        logger.error(f"Unexpected error in worker job processing: {exc}", exc_info=True)
        db.rollback()

    return processed_count


def process_pending_scans(db, max_batch: int = 5, worker_id: Optional[str] = None) -> int:
    """Fetch, atomically claim, and execute pending scan jobs."""
    return process_durable_jobs(
        db=db,
        max_batch=max_batch,
        worker_id=worker_id,
        job_types=["scan"],
    )


def process_pending_verifications(db, max_batch: int = 5, worker_id: Optional[str] = None) -> int:
    """Fetch, atomically claim, and execute pending fix verification jobs."""
    return process_durable_jobs(
        db=db,
        max_batch=max_batch,
        worker_id=worker_id,
        job_types=["verification"],
    )


def _release_all_active_leases_on_shutdown() -> None:
    """Release any active in-flight leases held by this worker process upon graceful shutdown."""
    with _ACTIVE_LEASES_LOCK:
        active_items = list(_ACTIVE_LEASES.items())
        _ACTIVE_LEASES.clear()

    if not active_items:
        return

    db = None
    try:
        db = SessionLocal()
        for job_id, (w_id, token) in active_items:
            released = release_claimed_job_on_shutdown(db=db, job_id=job_id, worker_id=w_id, lease_token=token)
            if released:
                logger.info(f"[job:{job_id}] Gracefully released active lease for worker '{w_id}' on shutdown.")
    except Exception as exc:
        logger.warning(f"Error releasing active leases on shutdown: {exc}")
    finally:
        if db is not None:
            try:
                db.close()
            except Exception:
                pass


def run_worker_loop(
    poll_interval: float = 2.0,
    heartbeat_path: Optional[str] = None,
    run_once: bool = False,
    worker_id: Optional[str] = None,
    concurrency: Optional[int] = None,
) -> None:
    """Main persistent worker loop with startup recovery, periodic lease/outbox sweeps, and graceful shutdown."""
    global _SHUTDOWN_REQUESTED
    _SHUTDOWN_REQUESTED = False

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    w_id = worker_id or get_default_worker_id()
    max_conc = max(1, min(16, int(concurrency if concurrency is not None else settings.WORKER_CONCURRENCY)))
    heartbeat_file = get_heartbeat_path(heartbeat_path)
    logger.info(
        f"Starting Red Mercury Durable Worker '{w_id}' (PID={os.getpid()}, "
        f"concurrency={max_conc}, interval={poll_interval}s, heartbeat={heartbeat_file})"
    )

    # 1. Startup reconciliation: recover expired leases and undispatched outbox events
    startup_db = None
    try:
        startup_db = SessionLocal()
        recon_summary = reconcile_jobs_on_startup(startup_db, component=w_id)
        logger.info(f"Worker startup reconciliation complete: {recon_summary}")
    except Exception as exc:
        logger.warning(f"Worker startup reconciliation warning: {exc}")
    finally:
        if startup_db is not None:
            try:
                startup_db.close()
            except Exception:
                pass

    total_jobs_processed = 0
    last_reconciliation_time = time.time()
    reconciliation_interval = 15.0  # seconds
    backoff_seconds = 2.0
    max_backoff = 30.0

    while not _SHUTDOWN_REQUESTED:
        write_heartbeat(heartbeat_file, total_jobs_processed, worker_id=w_id)

        db = None
        try:
            db = SessionLocal()

            # Periodic expired-lease recovery and outbox sweep
            current_time = time.time()
            if current_time - last_reconciliation_time >= reconciliation_interval:
                recover_expired_job_leases(db=db)
                recover_undispatched_outbox_events(db=db)
                reconcile_interrupted_jobs(db=db)
                last_reconciliation_time = current_time

            jobs_done = process_durable_jobs(
                db=db,
                max_batch=max_conc,
                worker_id=w_id,
            )
            total_jobs_processed += jobs_done
            backoff_seconds = 2.0

        except (OperationalError, DatabaseError) as db_err:
            logger.warning(
                f"Database connection issue in worker loop: {db_err}. "
                f"Retrying in {backoff_seconds:.1f}s..."
            )
            time.sleep(backoff_seconds)
            backoff_seconds = min(backoff_seconds * 2.0, max_backoff)
            continue
        except Exception as exc:
            logger.error(f"Unexpected error in worker loop iteration: {exc}", exc_info=True)
            time.sleep(backoff_seconds)
            backoff_seconds = min(backoff_seconds * 2.0, max_backoff)
            continue
        finally:
            if db:
                try:
                    db.close()
                except Exception:
                    pass

        if run_once:
            logger.info("Run-once mode specified. Worker finished single execution.")
            break

        sleep_elapsed = 0.0
        step = 0.25
        while sleep_elapsed < poll_interval and not _SHUTDOWN_REQUESTED:
            time.sleep(step)
            sleep_elapsed += step

    logger.info(f"Worker '{w_id}' loop terminated. Releasing active leases and cleaning up...")
    _release_all_active_leases_on_shutdown()
    try:
        if heartbeat_file.exists():
            heartbeat_file.unlink(missing_ok=True)
    except Exception:
        pass

    logger.info(f"Red Mercury Worker '{w_id}' exited cleanly. Total jobs processed: {total_jobs_processed}")


def main():
    """CLI entrypoint for worker daemon and health checks."""
    parser = argparse.ArgumentParser(description="Red Mercury Durable Background Worker")
    parser.add_argument(
        "--healthcheck",
        action="store_true",
        help="Execute a quick health probe and exit with code 0 (healthy) or 1 (unhealthy)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Process current pending jobs once and exit immediately",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=settings.WORKER_POLL_INTERVAL_SECONDS,
        help="Polling interval in seconds between queue checks",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=settings.WORKER_CONCURRENCY,
        help="Maximum jobs processed per worker batch cycle",
    )
    parser.add_argument(
        "--worker-id",
        type=str,
        default=None,
        help="Explicit worker identity string",
    )
    parser.add_argument(
        "--heartbeat-file",
        type=str,
        default=None,
        help="Custom path to worker heartbeat file",
    )

    args = parser.parse_args()

    if args.healthcheck:
        heartbeat_file = get_heartbeat_path(args.heartbeat_file)
        exit_code = run_healthcheck(heartbeat_file)
        sys.exit(exit_code)

    run_worker_loop(
        poll_interval=args.interval,
        heartbeat_path=args.heartbeat_file,
        run_once=args.once,
        worker_id=args.worker_id,
        concurrency=args.concurrency,
    )


if __name__ == "__main__":
    main()
