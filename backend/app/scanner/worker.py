"""Persistent background worker process for Red Mercury security scanning.

Polls the database for pending security scan jobs, executes security scanners
within hardened sandbox constraints, reconciles stale/orphaned jobs, and supports
graceful termination on SIGTERM/SIGINT.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
from typing import Optional

from sqlalchemy.exc import OperationalError, DatabaseError

from ..core.config import settings
from ..core.logging import get_logger
from ..core.quotas import reconcile_interrupted_jobs
from ..db.session import SessionLocal, check_db_connection
from ..models.repository import Repository
from ..models.scan import Scan
from .runner import run_security_scan

logger = get_logger("redmercury.scanner.worker")

# Global graceful shutdown flag
_SHUTDOWN_REQUESTED = False


def _signal_handler(signum, frame):
    """Handle process termination signals gracefully."""
    global _SHUTDOWN_REQUESTED
    sig_name = signal.Signals(signum).name if hasattr(signal, "Signals") else str(signum)
    logger.info(f"Received termination signal {sig_name}. Preparing graceful shutdown...")
    _SHUTDOWN_REQUESTED = True


def get_heartbeat_path(custom_path: Optional[str] = None) -> Path:
    """Determine the file path for the worker liveness heartbeat."""
    if custom_path:
        return Path(custom_path)
    
    # Priority: WORKER_TEMP_DIR -> /sandbox/temp (Docker volume) -> system temp
    if os.environ.get("WORKER_TEMP_DIR"):
        return Path(os.environ["WORKER_TEMP_DIR"]) / "worker_heartbeat.json"
    
    sandbox_temp = Path("/sandbox/temp")
    if sandbox_temp.exists() and sandbox_temp.is_dir():
        return sandbox_temp / "worker_heartbeat.json"
    
    return Path(tempfile.gettempdir()) / "redmercury_worker_heartbeat.json"


def write_heartbeat(heartbeat_file: Path, jobs_processed: int) -> None:
    """Write current worker liveness timestamp to disk."""
    try:
        heartbeat_file.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "status": "healthy",
            "service": "redmercury-worker",
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
    
    # 1. Probe database connectivity
    if not check_db_connection():
        logger.error("Healthcheck FAILED: Database connection is unreachable.")
        return 1

    # 2. Probe heartbeat freshness if file exists
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


def process_pending_scans(db, max_batch: int = 5) -> int:
    """Fetch and execute pending scans from the database.

    Returns:
        Number of scans processed in this batch.
    """
    global _SHUTDOWN_REQUESTED
    processed_count = 0

    try:
        pending_scans = (
            db.query(Scan)
            .filter(Scan.status.in_(["pending", "queued"]))
            .order_by(Scan.created_at.asc())
            .limit(max_batch)
            .all()
        )

        for scan in pending_scans:
            if _SHUTDOWN_REQUESTED:
                logger.info("Shutdown requested. Halting pending scan processing.")
                break

            logger.info(f"Worker picked up scan {scan.id} for execution")
            repo = db.query(Repository).filter(Repository.id == scan.repository_id).first()

            if not repo:
                logger.error(f"Repository {scan.repository_id} not found for scan {scan.id}. Marking failed.")
                scan.status = "failed"
                scan.completed_at = datetime.now(timezone.utc)
                scan.summary = json.dumps({"error": f"Repository {scan.repository_id} not found"})
                db.commit()
                processed_count += 1
                continue

            # Parse scanner configuration if present
            selected_tools = None
            timeout_per_tool = 60
            if scan.scanner_configuration:
                try:
                    cfg = json.loads(scan.scanner_configuration) if isinstance(scan.scanner_configuration, str) else scan.scanner_configuration
                    if isinstance(cfg, dict):
                        selected_tools = cfg.get("tools")
                        timeout_per_tool = int(cfg.get("timeout_seconds", 60))
                except Exception as parse_err:
                    logger.warning(f"Could not parse scan configuration for {scan.id}: {parse_err}")

            try:
                run_security_scan(
                    repo=repo,
                    scan=scan,
                    db=db,
                    selected_tools=selected_tools,
                    timeout_per_tool=timeout_per_tool,
                )
                processed_count += 1
            except Exception as scan_err:
                logger.error(f"Error processing scan {scan.id}: {scan_err}", exc_info=True)
                scan.status = "failed"
                scan.completed_at = datetime.now(timezone.utc)
                scan.summary = json.dumps({"error": f"Execution error in worker: {str(scan_err)}"})
                db.commit()
                processed_count += 1

    except (OperationalError, DatabaseError) as db_err:
        logger.warning(f"Database error during scan polling: {db_err}")
        db.rollback()
    except Exception as exc:
        logger.error(f"Unexpected error in worker scan processing: {exc}", exc_info=True)
        db.rollback()

    return processed_count


def process_pending_verifications(db, max_batch: int = 5) -> int:
    """Fetch and execute pending fix verification jobs from the database.

    Runs within the hardened worker container environment under UID 10002
    (redmercury-sandbox) with dropped capabilities and strict resource bounding.
    """
    global _SHUTDOWN_REQUESTED
    processed_count = 0

    try:
        from ..models.verification import VerificationRun
        from ..schemas.verification import VerificationRunRequest
        from ..verification.service import execute_fix_verification

        pending_runs = (
            db.query(VerificationRun)
            .filter(VerificationRun.status.in_(["pending", "queued", "NOT_TESTED"]))
            .filter(VerificationRun.patch_diff.isnot(None))
            .filter(VerificationRun.finding_id.isnot(None))
            .order_by(VerificationRun.created_at.asc())
            .limit(max_batch)
            .all()
        )

        for run in pending_runs:
            if _SHUTDOWN_REQUESTED:
                logger.info("Shutdown requested. Halting pending verification processing.")
                break

            logger.info(f"Worker picked up verification run {run.id} for execution")

            # Parse scanner configuration if present
            scanner_cfg = None
            if run.scanner_config:
                try:
                    scanner_cfg = json.loads(run.scanner_config) if isinstance(run.scanner_config, str) else run.scanner_config
                except Exception:
                    scanner_cfg = None

            # Reconstruct request for execution service
            req = VerificationRunRequest(
                finding_id=run.finding_id,
                patch_id=run.patch_id,
                proposed_patch=run.patch_diff,
                run_existing_tests=True,
                run_regression_tests=True,
                scanner_config=scanner_cfg,
            )

            try:
                outcome = execute_fix_verification(request=req, db=db)
                run.status = outcome.status.value if hasattr(outcome.status, "value") else str(outcome.status)
                run.completed_at = datetime.now(timezone.utc)
                if outcome.reasons:
                    run.reasons = json.dumps(outcome.reasons)
                db.commit()
                processed_count += 1
            except Exception as ver_err:
                logger.error(f"Error processing verification run {run.id}: {ver_err}", exc_info=True)
                run.status = "INCONCLUSIVE"
                run.completed_at = datetime.now(timezone.utc)
                err_reasons = [f"Worker execution error: {str(ver_err)}"]
                run.reasons = json.dumps(err_reasons)
                db.commit()
                processed_count += 1

    except (OperationalError, DatabaseError) as db_err:
        logger.warning(f"Database error during verification polling: {db_err}")
        db.rollback()
    except Exception as exc:
        logger.error(f"Unexpected error in worker verification processing: {exc}", exc_info=True)
        db.rollback()

    return processed_count


def run_worker_loop(poll_interval: float = 3.0, heartbeat_path: Optional[str] = None, run_once: bool = False) -> None:
    """Main persistent worker polling loop."""
    global _SHUTDOWN_REQUESTED
    
    # Register termination signal listeners
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    heartbeat_file = get_heartbeat_path(heartbeat_path)
    logger.info(
        f"Starting Red Mercury Scanner Worker (PID={os.getpid()}, "
        f"interval={poll_interval}s, heartbeat={heartbeat_file})"
    )

    total_jobs_processed = 0
    last_reconciliation_time = 0.0
    reconciliation_interval = 60.0  # seconds
    backoff_seconds = 2.0
    max_backoff = 30.0

    while not _SHUTDOWN_REQUESTED:
        # 1. Update liveness heartbeat
        write_heartbeat(heartbeat_file, total_jobs_processed)

        # 2. Check and process jobs with safe session lifecycle
        db = None
        try:
            db = SessionLocal()

            # Periodic orphaned job reconciliation
            current_time = time.time()
            if current_time - last_reconciliation_time >= reconciliation_interval:
                reconciled = reconcile_interrupted_jobs(db)
                if reconciled > 0:
                    logger.info(f"Reconciled {reconciled} hanging/stale jobs.")
                last_reconciliation_time = current_time

            # Process pending security scans
            scans_done = process_pending_scans(db)
            total_jobs_processed += scans_done

            # Process pending fix verifications
            verifications_done = process_pending_verifications(db)
            total_jobs_processed += verifications_done

            # Successful database interaction: reset backoff
            backoff_seconds = 2.0

        except (OperationalError, DatabaseError) as db_err:
            logger.warning(
                f"Database connection issue in worker loop: {db_err}. "
                f"Retrying in {backoff_seconds:.1f}s (backoff prevents restart loops)..."
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

        # 3. Sleep with interrupt check
        sleep_elapsed = 0.0
        step = 0.5
        while sleep_elapsed < poll_interval and not _SHUTDOWN_REQUESTED:
            time.sleep(step)
            sleep_elapsed += step

    # Graceful shutdown cleanup
    logger.info("Worker loop terminated. Cleaning up before process exit...")
    try:
        if heartbeat_file.exists():
            heartbeat_file.unlink(missing_ok=True)
    except Exception:
        pass

    logger.info(f"Red Mercury Worker exited cleanly. Total jobs processed: {total_jobs_processed}")


def main():
    """CLI entrypoint for worker daemon and health checks."""
    parser = argparse.ArgumentParser(description="Red Mercury Background Scanner Worker")
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
        default=3.0,
        help="Polling interval in seconds between queue checks (default: 3.0s)",
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
    )


if __name__ == "__main__":
    main()
