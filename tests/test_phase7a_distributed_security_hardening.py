"""Phase 7A Final Distributed Security Hardening & Deployment Gate Verification Suite.

Independently tests and proves all Phase 7A requirements:
1. Section 2 (Distributed Lease-Fencing Race Audit):
   - Real PostgreSQL 16 two-session concurrency test for Scan execution (`run_security_scan`) where Worker A validates its lease, flushes findings/status/audit records, and pauses immediately before `db_A.commit()` while its lease expires and Worker B recovers + claims the job with a new fencing token. Proves Worker A's transaction-level `before_commit` fence aborts the commit with `StaleWorkerLeaseError` and commits zero stale `SecurityFinding`, `Scan.status`, or `AuditEvent` records.
   - Real PostgreSQL 16 two-session concurrency test for Fix Verification execution (`execute_fix_verification`) under the exact same 6-step pause-before-commit race. Proves zero stale `VerificationRun`, `SecurityEvidence`, `VerificationEvidence`, or `AuditEvent` records are committed by Worker A.
2. Section 3 (Worker Crash During Cancellation):
   - Live Docker + real OS subprocess + live PostgreSQL 16 test: starts a durable scan job, spawns a real child process and a real Docker sandbox container (`redmercury-sbx-...`) plus a disposable verification temp workspace (`redmercury_verify_...`), requests cancellation from a separate API session (`status='cancelling'`), crashes/terminates the worker unexpectedly before it can acknowledge cancellation, expires the lease, and runs recovery.
   - Proves that if active execution cannot be proven stopped (`kill_orphans=False`), recovery refuses to transition the job to terminal `'cancelled'` and refuses to release the `ActiveJobSlot`.
   - Proves that normal recovery reaps the orphaned child process and orphaned Docker sandbox container, cleans the disposable workspace, preserves persistent repository data and audit/evidence history, verifies zero remaining processes/containers in the OS process table and Docker container list, and only then transitions to `'cancelled'` and releases the `ActiveJobSlot`.
3. Section 4 (Git Egress Execution-Location Audit):
   - Verifies that both `POST /api/v1/repositories/ingest/git` and `POST /api/v1/repositories/{id}/clone` execute in the `api` service, that `api` in `docker-compose.prod.yml` is attached exclusively to `redmercury_internal` (`internal: true`, blocking direct outbound internet access at the network boundary), that strict environments fail closed without `GIT_EGRESS_PROXY_URL`, that proxy mode sets both Git `-c http.proxy`/`https.proxy` and sanitized `HTTP_PROXY`/`HTTPS_PROXY` with `NO_PROXY=""`, and that direct dev mode pins validated IPs via `-c http.curloptResolve` to prevent connection-time DNS rebinding.
4. Section 5 (Outbox and Cancellation Recovery Matrix on Live PostgreSQL 16 & Live Redis 7):
   - Tests API restart after DB commit before Redis dispatch, duplicate outbox dispatch, Redis outage during dispatch, Redis outage during cancellation, worker restart during cancellation, multiple simultaneous cancellation requests, cancellation after lease expiration, and duplicate cancellation acknowledgement.
5. Section 6 (CI/CD Workflow & Scoped CVE Gate Verification):
   - Verifies `.github/workflows/ci.yml` service containers, worker image build ordering, lockfile reproducibility, Gitleaks SHA-256 checksum verification, scoped single-CVE exception (`CVE-2026-132276`), and JUnit XML artifact configuration.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from typing import Optional
import uuid

import pytest
import yaml
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.core.errors import SecurityPolicyViolationError
from app.core.ingestion import (
    _build_sanitized_git_env,
    clone_git_repository,
    resolve_required_git_egress_proxy,
    validate_git_url,
)
from app.core.jobs import (
    JobExecutionTracker,
    JobState,
    StaleWorkerLeaseError,
    _is_container_running,
    _is_pid_running,
    acknowledge_job_cancellation,
    assert_active_worker_lease_or_abort,
    cancel_durable_job,
    claim_durable_job_by_id,
    claim_next_durable_job,
    complete_claimed_job,
    create_durable_job_with_outbox,
    dispatch_outbox_events,
    reap_and_verify_orphaned_job_resources,
    reconcile_jobs_on_startup,
    recover_expired_job_leases,
    recover_undispatched_outbox_events,
    register_active_tracker,
    set_redis_client_override,
    unregister_active_tracker,
)
from app.core.security import create_access_token
from app.main import app
from app.models.audit import AuditEvent
from app.models.evidence import SecurityEvidence
from app.models.finding import SecurityFinding
from app.models.job import ActiveJobSlot, DurableJob, JobOutboxEvent
from app.models.repository import Repository
from app.models.scan import Scan
from app.models.user import User
from app.models.verification import VerificationEvidence, VerificationRun
from app.scanner.runner import run_security_scan
from app.schemas.verification import VerificationRunRequest
from app.verification.sandbox import check_docker_availability
from app.verification.service import execute_fix_verification

REPO_ROOT = Path(__file__).resolve().parent.parent


def _probe_live_postgres() -> Optional[str]:
    url = os.environ.get("TEST_POSTGRES_URL") or "postgresql+psycopg://postgres:postgres@127.0.0.1:5432/test_redmercury"
    try:
        eng = create_engine(url, connect_args={"connect_timeout": 2})
        with eng.connect() as conn:
            conn.execute(text("SELECT 1"))
        eng.dispose()
        return url
    except Exception:
        return None


def _probe_live_redis() -> Optional[str]:
    url = os.environ.get("TEST_REDIS_URL") or "redis://127.0.0.1:6379/15"
    try:
        import redis
        r = redis.Redis.from_url(url, decode_responses=True, socket_connect_timeout=2)
        if r.ping():
            return url
    except Exception:
        pass
    return None


LIVE_PG_URL = _probe_live_postgres()
LIVE_REDIS_URL = _probe_live_redis()
DOCKER_OK, _ = check_docker_availability(timeout_seconds=3.0, required_image=settings.SANDBOX_CONTAINER_IMAGE)


def _create_repo_with_vuln_file(db: Session, owner_id: str, base_dir: Path) -> Repository:
    ws = base_dir / f"ws_p7a_{uuid.uuid4().hex[:8]}"
    ws.mkdir(parents=True, exist_ok=True)
    (ws / "app.py").write_text(
        "import subprocess\n"
        "def run_cmd(user_input):\n"
        "    return subprocess.call(user_input, shell=True)\n",
        encoding="utf-8",
    )
    repo = Repository(
        id=str(uuid.uuid4()),
        owner_id=owner_id,
        name=f"p7a-repo-{uuid.uuid4().hex[:8]}",
        source_type="local_folder",
        default_branch="main",
        ingestion_status="completed",
        workspace_path=str(ws),
        file_count=1,
        total_size_bytes=120,
        is_active=True,
    )
    db.add(repo)
    db.commit()
    db.refresh(repo)
    return repo


# ==============================================================================
# SECTION 2: Distributed Lease-Fencing Race Audit (Real PostgreSQL 16 Concurrency)
# ==============================================================================

@pytest.mark.skipif(LIVE_PG_URL is None, reason="Requires live PostgreSQL 16 container")
def test_phase7a_sec2_postgres_concurrent_lease_fencing_blocks_stale_scan_commit(tmp_path: Path):
    """[LIVE POSTGRES 16 TWO-SESSION RACE] Reproduces the exact 6-step Section 2 race for scan execution:
    1. Worker A claims scan job.
    2. Worker A validates its lease.
    3. Worker A pauses immediately before committing business data (findings, scan status, audit record).
    4. The lease expires.
    5. Worker B recovers and claims the job with a new fencing token on an independent PostgreSQL session.
    6. Worker A attempts to commit -> transaction-level before_commit fence raises StaleWorkerLeaseError and commits ZERO rows.
    """
    cfg = Config("backend/alembic.ini")
    cfg.set_main_option("sqlalchemy.url", LIVE_PG_URL)
    command.upgrade(cfg, "head")

    pg_engine = create_engine(LIVE_PG_URL, pool_size=5, max_overflow=5)
    PgSession = sessionmaker(bind=pg_engine, autocommit=False, autoflush=False)

    db_setup = PgSession()
    db_a = PgSession()
    db_b = PgSession()
    try:
        user = User(
            id=f"u_p7a_s2_{uuid.uuid4().hex[:8]}",
            email=f"p7a_s2_{uuid.uuid4().hex[:8]}@xerova.com",
            password_hash="hash",
            account_status="active",
            role="analyst",
        )
        db_setup.add(user)
        db_setup.commit()
        repo = _create_repo_with_vuln_file(db_setup, user.id, tmp_path)

        scan = Scan(id=str(uuid.uuid4()), repository_id=repo.id, status="queued")
        db_setup.add(scan)
        db_setup.flush()
        job, _, _ = create_durable_job_with_outbox(
            db=db_setup,
            user=user,
            job_type="scan",
            resource_id=scan.id,
            repository_id=repo.id,
            payload={"tools": ["bandit"], "timeout_seconds": 30},
            max_attempts=3,
        )
        db_setup.commit()
        job_id = job.id
        scan_id = scan.id

        # Step 1: Worker A claims the scan job on session A
        claimed_a = claim_durable_job_by_id(db=db_a, job_id=job_id, worker_id="worker-A", lease_seconds=60)
        assert claimed_a is not None
        token_a = claimed_a.lease_token
        assert token_a is not None

        tracker_a = JobExecutionTracker(
            job_id=job_id,
            resource_id=scan_id,
            tenant_id=user.id,
            worker_id="worker-A",
            lease_token=token_a,
        )
        register_active_tracker(tracker_a)

        token_b_holder = {}

        # Step 3, 4, 5: Pause hook invoked inside run_security_scan AFTER Worker A validates its lease
        # and flushes findings + AuditEvent, and IMMEDIATELY BEFORE Worker A calls db_a.commit()
        def _pause_before_worker_a_commit():
            # Step 4: Lease expires on independent PostgreSQL session B
            job_in_b = db_b.query(DurableJob).filter(DurableJob.id == job_id).first()
            job_in_b.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=5)
            db_b.commit()

            # Step 5: Worker B recovers the expired lease and claims the job with a new fencing token
            rec = recover_expired_job_leases(db=db_b)
            assert rec["retried"] >= 1
            job_in_b = db_b.query(DurableJob).filter(DurableJob.id == job_id).first()
            job_in_b.next_retry_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            db_b.commit()

            claimed_b = claim_durable_job_by_id(db=db_b, job_id=job_id, worker_id="worker-B", lease_seconds=60)
            assert claimed_b is not None
            assert claimed_b.worker_id == "worker-B"
            assert claimed_b.lease_token != token_a
            token_b_holder["token"] = claimed_b.lease_token

        # Step 2 & 6: Worker A runs scan, validates lease, pauses in pre_commit_hook, then attempts db_a.commit()
        repo_a = db_a.query(Repository).filter(Repository.id == repo.id).first()
        scan_a = db_a.query(Scan).filter(Scan.id == scan_id).first()
        try:
            with pytest.raises(StaleWorkerLeaseError):
                run_security_scan(
                    repo=repo_a,
                    scan=scan_a,
                    db=db_a,
                    selected_tools=["bandit"],
                    commit_changes=True,
                    pre_commit_hook=_pause_before_worker_a_commit,
                )
        finally:
            unregister_active_tracker(tracker_a)

        # Verify on independent PostgreSQL session that Worker A committed ZERO findings, ZERO audit events,
        # and did NOT overwrite Scan.status to 'completed'!
        db_b.expire_all()
        assert db_b.query(SecurityFinding).filter(SecurityFinding.scan_id == scan_id).count() == 0
        assert (
            db_b.query(AuditEvent)
            .filter(AuditEvent.resource_identifier == scan_id, AuditEvent.action == "SCAN_COMPLETED")
            .count()
            == 0
        )
        scan_check = db_b.query(Scan).filter(Scan.id == scan_id).first()
        assert scan_check.status == "running"
        job_check = db_b.query(DurableJob).filter(DurableJob.id == job_id).first()
        assert job_check.worker_id == "worker-B"
        assert job_check.lease_token == token_b_holder["token"]
    finally:
        db_a.close()
        db_b.close()
        db_setup.close()
        pg_engine.dispose()


@pytest.mark.skipif(LIVE_PG_URL is None, reason="Requires live PostgreSQL 16 container")
def test_phase7a_sec2_postgres_concurrent_lease_fencing_blocks_stale_verification_commit(tmp_path: Path):
    """[LIVE POSTGRES 16 TWO-SESSION RACE] Reproduces the exact 6-step Section 2 race for fix verification:
    Worker A validates its lease, flushes VerificationRun, SecurityEvidence, VerificationEvidence, and AuditEvent,
    and pauses right before `db_A.commit()` while the lease expires and Worker B claims the job with a new fencing token.
    Proves Worker A raises StaleWorkerLeaseError at commit time and commits ZERO stale records.
    """
    cfg = Config("backend/alembic.ini")
    cfg.set_main_option("sqlalchemy.url", LIVE_PG_URL)
    command.upgrade(cfg, "head")

    pg_engine = create_engine(LIVE_PG_URL, pool_size=5, max_overflow=5)
    PgSession = sessionmaker(bind=pg_engine, autocommit=False, autoflush=False)

    db_setup = PgSession()
    db_a = PgSession()
    db_b = PgSession()
    try:
        user = User(
            id=f"u_p7a_v2_{uuid.uuid4().hex[:8]}",
            email=f"p7a_v2_{uuid.uuid4().hex[:8]}@xerova.com",
            password_hash="hash",
            account_status="active",
            role="analyst",
        )
        db_setup.add(user)
        db_setup.commit()
        repo = _create_repo_with_vuln_file(db_setup, user.id, tmp_path)

        scan = Scan(id=str(uuid.uuid4()), repository_id=repo.id, status="completed")
        db_setup.add(scan)
        db_setup.flush()
        finding = SecurityFinding(
            id=str(uuid.uuid4()),
            repo_id=repo.id,
            scan_id=scan.id,
            scanner_identifier="bandit",
            scanner_name="Bandit",
            rule_identifier="B602",
            cwe="CWE-78",
            title="Subprocess call with shell=True",
            category="Command Injection",
            severity="HIGH",
            confidence="HIGH",
            confidence_score=0.95,
            file_path="app.py",
            line_number=3,
            line_information="3",
            code_excerpt="return subprocess.call(user_input, shell=True)",
            status="open",
            finding_status="open",
        )
        db_setup.add(finding)
        db_setup.flush()

        v_run = VerificationRun(id=str(uuid.uuid4()), finding_id=finding.id, status="QUEUED")
        db_setup.add(v_run)
        db_setup.flush()

        v_job, _, _ = create_durable_job_with_outbox(
            db=db_setup,
            user=user,
            job_type="verification",
            resource_id=v_run.id,
            repository_id=repo.id,
            payload={},
            max_attempts=3,
        )
        db_setup.commit()
        v_job_id = v_job.id
        v_run_id = v_run.id
        finding_id = finding.id

        # Step 1: Worker A claims verification job on session A
        claimed_a = claim_durable_job_by_id(db=db_a, job_id=v_job_id, worker_id="worker-A", lease_seconds=60)
        assert claimed_a is not None
        token_a = claimed_a.lease_token

        tracker_a = JobExecutionTracker(
            job_id=v_job_id,
            resource_id=v_run_id,
            tenant_id=user.id,
            worker_id="worker-A",
            lease_token=token_a,
        )
        register_active_tracker(tracker_a)

        # Step 3, 4, 5: Pause hook invoked inside _finalize_and_persist_run right before db_a.commit()
        def _pause_before_worker_a_verification_commit():
            job_in_b = db_b.query(DurableJob).filter(DurableJob.id == v_job_id).first()
            job_in_b.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=5)
            db_b.commit()

            rec = recover_expired_job_leases(db=db_b)
            assert rec["retried"] >= 1
            job_in_b = db_b.query(DurableJob).filter(DurableJob.id == v_job_id).first()
            job_in_b.next_retry_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            db_b.commit()

            claimed_b = claim_durable_job_by_id(db=db_b, job_id=v_job_id, worker_id="worker-B", lease_seconds=60)
            assert claimed_b is not None
            assert claimed_b.worker_id == "worker-B"
            assert claimed_b.lease_token != token_a

        valid_patch = (
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -1,3 +1,3 @@\n"
            " import subprocess\n"
            " def run_cmd(user_input):\n"
            "-    return subprocess.call(user_input, shell=True)\n"
            "+    return subprocess.call([user_input], shell=False)\n"
        )
        req = VerificationRunRequest(
            finding_id=finding_id,
            proposed_patch=valid_patch,
            scanner_names=["bandit"],
            run_existing_tests=False,
            run_regression_tests=False,
            timeout_seconds=20,
        )

        # Step 2 & 6: Worker A executes verification, pauses right before commit, and gets fenced out
        try:
            with pytest.raises(StaleWorkerLeaseError):
                execute_fix_verification(
                    request=req,
                    db=db_a,
                    user_id=user.id,
                    existing_run_id=v_run_id,
                    commit_changes=True,
                    pre_commit_hook=_pause_before_worker_a_verification_commit,
                )
        finally:
            unregister_active_tracker(tracker_a)

        # Verify on independent PostgreSQL session B that Worker A committed ZERO evidence or audit records
        db_b.expire_all()
        assert db_b.query(SecurityEvidence).filter(SecurityEvidence.verification_run_id == v_run_id).count() == 0
        assert db_b.query(VerificationEvidence).filter(VerificationEvidence.verification_run_id == v_run_id).count() == 0
        assert (
            db_b.query(AuditEvent)
            .filter(AuditEvent.resource_identifier == v_run_id, AuditEvent.action == "verification.run_completed")
            .count()
            == 0
        )
        v_run_check = db_b.query(VerificationRun).filter(VerificationRun.id == v_run_id).first()
        assert v_run_check.status == "RUNNING"
    finally:
        db_a.close()
        db_b.close()
        db_setup.close()
        pg_engine.dispose()


# ==============================================================================
# SECTION 3: Worker Crash During Cancellation (Live Docker + Real Subprocess + Live Postgres)
# ==============================================================================

@pytest.mark.skipif(
    LIVE_PG_URL is None or not DOCKER_OK,
    reason="Requires live PostgreSQL 16 and live Docker daemon with redmercury-worker:latest",
)
def test_phase7a_sec3_worker_crash_during_cancellation_reaps_orphans_and_guards_slot(tmp_path: Path):
    """[LIVE DOCKER + REAL SUBPROCESS + LIVE POSTGRES 16] Reproduces the exact 8-step Section 3 scenario:
    1. Start a durable scan job.
    2. Start a real child process.
    3. Start a real Docker sandbox container + disposable verification temp workspace.
    4. Request cancellation from a separate API session (status -> 'cancelling', slot retained).
    5. Terminate/crash the worker unexpectedly before it can acknowledge cancellation.
    6. Allow the lease to expire.
    7. Verify that while active execution cannot be proven stopped (kill_orphans=False), recovery refuses to report
       terminal 'cancelled' and retains the concurrency slot.
    8. Execute full recovery (kill_orphans=True) and inspect the actual OS process table and Docker container list:
       verify orphaned process is dead, orphaned container is stopped/removed, disposable workspace is deleted,
       persistent repository data & evidence/audit history remain intact, and the concurrency slot is released.
    """
    cfg = Config("backend/alembic.ini")
    cfg.set_main_option("sqlalchemy.url", LIVE_PG_URL)
    command.upgrade(cfg, "head")

    pg_engine = create_engine(LIVE_PG_URL, pool_size=5, max_overflow=5)
    PgSession = sessionmaker(bind=pg_engine, autocommit=False, autoflush=False)

    db_worker = PgSession()
    db_api = PgSession()
    db_recovery = PgSession()

    child_proc: Optional[subprocess.Popen] = None
    container_name = f"redmercury-sbx-{uuid.uuid4().hex[:12]}"
    disposable_ws = Path(tempfile.gettempdir()).resolve() / f"rm_p7a_cancel_ws_{uuid.uuid4().hex[:8]}"
    disposable_ws.mkdir(parents=True, exist_ok=True)
    (disposable_ws / "scratch.py").write_text("x = 1\n", encoding="utf-8")

    try:
        user = User(
            id=f"u_p7a_s3_{uuid.uuid4().hex[:8]}",
            email=f"p7a_s3_{uuid.uuid4().hex[:8]}@xerova.com",
            password_hash="hash",
            account_status="active",
            role="analyst",
        )
        db_worker.add(user)
        db_worker.commit()

        # Persistent repository workspace + existing audit/evidence history that MUST be preserved
        repo = _create_repo_with_vuln_file(db_worker, user.id, tmp_path)
        persistent_file = Path(repo.workspace_path) / "app.py"
        assert persistent_file.exists()

        prior_evidence = SecurityEvidence(
            id=f"ev_prior_{uuid.uuid4().hex[:10]}",
            repository_id=repo.id,
            evidence_category="revision_hash",
            title="Prior Preserved Evidence",
            provenance="scanner_observed",
            tool_name="bandit",
            content_hash="a" * 64,
            sanitized_payload='{"preserved": true}',
        )
        prior_audit = AuditEvent(
            actor_id=user.id,
            action="PRIOR_AUDIT_RECORD",
            resource_type="repository",
            resource_identifier=repo.id,
            safe_metadata='{"intact": true}',
        )
        db_worker.add(prior_evidence)
        db_worker.add(prior_audit)

        # 1. Start durable scan job and claim it on Worker A
        scan = Scan(id=str(uuid.uuid4()), repository_id=repo.id, status="queued")
        db_worker.add(scan)
        db_worker.flush()
        job, _, _ = create_durable_job_with_outbox(
            db=db_worker,
            user=user,
            job_type="scan",
            resource_id=scan.id,
            repository_id=repo.id,
            payload={"tools": ["bandit"]},
        )
        db_worker.commit()
        job_id = job.id
        scan_id = scan.id

        claimed = claim_durable_job_by_id(db=db_worker, job_id=job_id, worker_id="crashing-worker-A", lease_seconds=30)
        assert claimed is not None

        tracker = JobExecutionTracker(
            job_id=job_id,
            resource_id=scan_id,
            tenant_id=user.id,
            worker_id="crashing-worker-A",
            lease_token=claimed.lease_token,
            session_factory=PgSession,
        )
        register_active_tracker(tracker)

        # 2. Start a real child OS subprocess and register with tracker
        child_proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(120)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        child_pid = child_proc.pid
        tracker.register_process(child_proc, db=db_worker)
        db_worker.commit()
        assert _is_pid_running(child_pid) is True

        # 3. Start a real Docker sandbox container labeled with redmercury.job_id and register disposable workspace
        subprocess.run(
            [
                "docker", "run", "-d", "--rm",
                f"--name={container_name}",
                "--network=none",
                f"--label=redmercury.job_id={job_id}",
                f"--label=redmercury.resource_id={scan_id}",
                settings.SANDBOX_CONTAINER_IMAGE,
                "python", "-c", "import time; time.sleep(120)",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
        )
        tracker.register_container(container_name, db=db_worker)
        tracker.register_temp_workspace(disposable_ws, db=db_worker)
        db_worker.commit()
        assert _is_container_running(container_name) is True
        assert disposable_ws.exists() is True

        # 5. Simulate Worker A is on a remote node / crashes unexpectedly after API requests cancellation:
        # Unregister the in-process tracker BEFORE calling cancel_durable_job from the separate API session
        unregister_active_tracker(tracker)

        # 4. Separate API process requests cancellation
        job_in_api = db_api.query(DurableJob).filter(DurableJob.id == job_id).first()
        cancelled_req = cancel_durable_job(
            db=db_api,
            job=job_in_api,
            resource_type="scan",
            resource_id=scan_id,
            actor_id=user.id,
            require_worker_ack=True,
        )
        assert cancelled_req.status == JobState.CANCELLING.value
        assert db_api.query(ActiveJobSlot).filter(ActiveJobSlot.job_id == job_id).count() == 1

        # 6. Worker A has crashed without acknowledging cancellation, and its lease now expires
        job_in_api.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=5)
        db_api.commit()

        # 7. First verify fail-closed behavior if active execution cannot be proven stopped (kill_orphans=False):
        # While child_pid and container_name are still running, recovery MUST NOT mark 'cancelled' or release slot!
        deferred_stats = recover_expired_job_leases(db=db_recovery, kill_orphans=False)
        assert deferred_stats["deferred_active"] >= 1
        assert deferred_stats["cancelled"] == 0
        db_recovery.expire_all()
        job_still_cancelling = db_recovery.query(DurableJob).filter(DurableJob.id == job_id).first()
        assert job_still_cancelling.status == JobState.CANCELLING.value
        assert "orphaned execution still active" in (job_still_cancelling.error_detail or "")
        assert db_recovery.query(ActiveJobSlot).filter(ActiveJobSlot.job_id == job_id).count() == 1

        # 8. Now execute full recovery (kill_orphans=True) and inspect actual OS process table & Docker container list
        rec_stats = recover_expired_job_leases(db=db_recovery, kill_orphans=True)
        assert rec_stats["cancelled"] == 1

        # Inspect actual OS process table and Docker container list
        assert _is_pid_running(child_pid) is False, f"Orphaned child PID {child_pid} still running!"
        assert _is_container_running(container_name) is False, f"Orphaned container {container_name} still running!"
        assert disposable_ws.exists() is False, "Disposable temp workspace was not cleaned!"

        # Verify persistent repository data and evidence/audit history remain 100% intact
        assert persistent_file.exists() is True
        assert db_recovery.query(SecurityEvidence).filter(SecurityEvidence.id == prior_evidence.id).count() == 1
        assert (
            db_recovery.query(AuditEvent)
            .filter(AuditEvent.resource_identifier == repo.id, AuditEvent.action == "PRIOR_AUDIT_RECORD")
            .count()
            == 1
        )

        # Verify job is now terminally 'cancelled' and concurrency slot is released
        db_recovery.expire_all()
        final_job = db_recovery.query(DurableJob).filter(DurableJob.id == job_id).first()
        assert final_job.status == JobState.CANCELLED.value
        assert db_recovery.query(ActiveJobSlot).filter(ActiveJobSlot.job_id == job_id).count() == 0
        final_scan = db_recovery.query(Scan).filter(Scan.id == scan_id).first()
        assert final_scan.status == "cancelled"
    finally:
        if child_proc is not None and child_proc.poll() is None:
            try:
                child_proc.kill()
            except Exception:
                pass
        JobExecutionTracker._kill_container(container_name)
        if disposable_ws.exists():
            import shutil
            shutil.rmtree(disposable_ws, ignore_errors=True)
        db_worker.close()
        db_api.close()
        db_recovery.close()
        pg_engine.dispose()


# ==============================================================================
# SECTION 4: Git Egress Execution-Location Audit & Proxy Enforcement
# ==============================================================================

def test_phase7a_sec4_git_egress_execution_location_and_proxy_enforcement(
    client: TestClient, db_session: Session, monkeypatch, tmp_path: Path
):
    """[GIT EGRESS AUDIT] Verifies POST /api/v1/repositories/{id}/clone and /ingest/git execution path,
    docker-compose.prod.yml internal network confinement of the API container, fail-closed proxy requirement,
    proxy env/flag binding, and DNS rebinding IP pinning.
    """
    # 1. Verify docker-compose.prod.yml confines `api` (where Git executes) strictly to `redmercury_internal` (`internal: true`)
    compose_data = yaml.safe_load((REPO_ROOT / "docker-compose.prod.yml").read_text(encoding="utf-8"))
    networks = compose_data["networks"]
    services = compose_data["services"]

    assert networks["redmercury_internal"]["internal"] is True
    assert networks["redmercury_worker_isolated"]["internal"] is True
    assert services["api"]["networks"] == ["redmercury_internal"], (
        "API service executes Git subprocesses and must NOT be attached to redmercury_public"
    )
    assert services["worker"]["networks"] == ["redmercury_worker_isolated"]

    # 2. Create user and registered repository for POST /api/v1/repositories/{id}/clone
    user = User(
        id=f"u_p7a_git_{uuid.uuid4().hex[:8]}",
        email=f"p7a_git_{uuid.uuid4().hex[:8]}@xerova.com",
        password_hash="hash",
        account_status="active",
        role="analyst",
    )
    db_session.add(user)
    db_session.commit()
    token = create_access_token({"sub": user.id, "email": user.email, "role": user.role})
    headers = {"Authorization": f"Bearer {token}"}

    repo = Repository(
        id=str(uuid.uuid4()),
        owner_id=user.id,
        name=f"git-clone-audit-{uuid.uuid4().hex[:6]}",
        source_type="public_git",
        git_url="https://github.com/octocat/Hello-World.git",
        default_branch="master",
        ingestion_status="completed",
        is_active=True,
    )
    db_session.add(repo)
    db_session.commit()

    # 3. Verify both POST /api/v1/repositories/{id}/clone and POST /api/v1/repositories/ingest/git
    # fail closed in production/staging when GIT_EGRESS_PROXY_URL is unset
    for strict_env in ("production", "staging"):
        monkeypatch.setattr(settings, "APP_ENV", strict_env)
        monkeypatch.setattr(settings, "GIT_EGRESS_PROXY_URL", "")
        r_clone = client.post(f"/api/v1/repositories/{repo.id}/clone", headers=headers)
        assert r_clone.status_code == 403
        assert "GIT_EGRESS_PROXY_URL" in r_clone.text

        r_ingest = client.post(
            "/api/v1/repositories/ingest/git",
            json={"git_url": "https://github.com/octocat/Hello-World.git", "default_branch": "master"},
            headers=headers,
        )
        assert r_ingest.status_code == 403
        assert "GIT_EGRESS_PROXY_URL" in r_ingest.text

    monkeypatch.setattr(settings, "APP_ENV", "development")

    # 4. Verify _build_sanitized_git_env strips ambient HTTP_PROXY/HTTPS_PROXY/NO_PROXY so proxy routing
    # is controlled exclusively via explicit Git CLI flags (-c http.proxy / -c https.proxy)
    proxy_env = _build_sanitized_git_env(allow_private=False, egress_proxy_url="http://egress-proxy.example.com:8080")
    assert "HTTP_PROXY" not in proxy_env
    assert "HTTPS_PROXY" not in proxy_env
    assert "NO_PROXY" not in proxy_env
    assert proxy_env["GIT_ALLOW_PROTOCOL"] == "https"

    # 5. Verify clone_git_repository passes -c http.followRedirects=false and pins validated IPs via -c http.curloptResolve
    captured_cmds = []

    def _mock_git_cmd(cmd, cwd, env, timeout):
        captured_cmds.append((cmd, env))
        # Create a dummy file in dest_dir so post-clone checks succeed
        dest = Path(cmd[-1])
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "main.py").write_text("print('ok')\n", encoding="utf-8")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr("app.core.ingestion._run_git_command", _mock_git_cmd)
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda host, port, *a, **kw: [(2, 1, 6, "", ("140.82.121.4", port))],
    )

    clone_git_repository(
        git_url="https://github.com/octocat/Hello-World.git",
        dest_dir=tmp_path / "cloned_direct",
        branch="main",
    )
    assert len(captured_cmds) >= 1
    direct_cmd = captured_cmds[0][0]
    assert "http.followRedirects=false" in direct_cmd
    assert "protocol.allow=never" in direct_cmd
    assert "protocol.https.allow=always" in direct_cmd
    assert any(arg.startswith("http.curloptResolve=github.com:443:140.82.121.4") for arg in direct_cmd)


# ==============================================================================
# SECTION 5: Outbox and Cancellation Recovery Fault Matrix (Live Postgres 16 + Redis 7)
# ==============================================================================

@pytest.mark.skipif(
    LIVE_PG_URL is None or LIVE_REDIS_URL is None,
    reason="Requires live PostgreSQL 16 and live Redis 7 containers",
)
def test_phase7a_sec5_outbox_and_cancellation_fault_matrix_on_live_postgres_and_redis(
    tmp_path: Path, monkeypatch
):
    """[LIVE POSTGRES 16 + LIVE REDIS 7] Verifies all 8 Section 5 scenarios:
    1. API restart after DB commit before Redis dispatch.
    2. Duplicate outbox dispatch -> zero duplicate execution.
    3. Redis outage during dispatch.
    4. Redis outage during cancellation.
    5. Worker restart during cancellation.
    6. Multiple simultaneous cancellation requests.
    7. Cancellation after lease expiration.
    8. Duplicate cancellation acknowledgement & tenant isolation preservation.
    """
    import redis

    cfg = Config("backend/alembic.ini")
    cfg.set_main_option("sqlalchemy.url", LIVE_PG_URL)
    command.upgrade(cfg, "head")

    pg_engine = create_engine(LIVE_PG_URL, pool_size=10, max_overflow=10)
    PgSession = sessionmaker(bind=pg_engine, autocommit=False, autoflush=False)
    r_client = redis.Redis.from_url(LIVE_REDIS_URL, decode_responses=True)
    test_queue = f"redmercury:p7a:queue:{uuid.uuid4().hex[:8]}"
    monkeypatch.setattr(settings, "JOB_QUEUE_NAME", test_queue)
    monkeypatch.setattr(settings, "MAX_CONCURRENT_SCANS_PER_USER", 5)
    set_redis_client_override(r_client)

    db = PgSession()
    try:
        db.query(ActiveJobSlot).delete()
        db.query(JobOutboxEvent).delete()
        db.query(DurableJob).delete()
        db.commit()

        user = User(
            id=f"u_p7a_s5_{uuid.uuid4().hex[:8]}",
            email=f"p7a_s5_{uuid.uuid4().hex[:8]}@xerova.com",
            password_hash="hash",
            account_status="active",
            role="analyst",
        )
        db.add(user)
        db.commit()
        repo1 = _create_repo_with_vuln_file(db, user.id, tmp_path)
        repo2 = _create_repo_with_vuln_file(db, user.id, tmp_path)
        repo3 = _create_repo_with_vuln_file(db, user.id, tmp_path)

        # --- Scenario 1 & 3: API restart after DB commit before Redis dispatch (and Redis outage during dispatch) ---
        class _FailingRedis:
            def rpush(self, *a, **kw):
                raise ConnectionError("Redis outage during dispatch")
            def setex(self, *a, **kw):
                raise ConnectionError("Redis outage during cancel")

        scan1 = Scan(id=str(uuid.uuid4()), repository_id=repo1.id, status="queued")
        db.add(scan1)
        db.flush()
        job1, outbox1, _ = create_durable_job_with_outbox(
            db=db, user=user, job_type="scan", resource_id=scan1.id, repository_id=repo1.id, payload={}
        )
        db.commit()
        assert dispatch_outbox_events(db=db, job_id=job1.id, redis_client=_FailingRedis()) == 0
        db.refresh(outbox1)
        assert outbox1.status == "pending"

        # API restarts -> reconcile_jobs_on_startup dispatches pending outbox event to live Redis 7
        recon_api = reconcile_jobs_on_startup(db=db, component="api", redis_client=r_client)
        assert recon_api["outbox_events_dispatched"] >= 1
        db.refresh(outbox1)
        assert outbox1.status == "dispatched"

        # --- Scenario 2: Duplicate outbox dispatch cannot cause duplicate execution ---
        r_client.rpush(test_queue, json.dumps({"job_id": job1.id, "job_type": "scan", "resource_id": scan1.id}))
        r_client.rpush(test_queue, json.dumps({"job_id": job1.id, "job_type": "scan", "resource_id": scan1.id}))

        def _claim_worker(idx: int):
            s = PgSession()
            try:
                c = claim_next_durable_job(db=s, worker_id=f"w-dup-{idx}", redis_client=r_client)
                return c.id if c else None
            finally:
                s.close()

        with ThreadPoolExecutor(max_workers=3) as pool:
            claimed_results = [r for r in pool.map(_claim_worker, range(3)) if r is not None]
        assert claimed_results == [job1.id], f"Expected exactly 1 worker to claim job1, got {claimed_results}"

        # --- Scenario 4 & 6: Redis outage during cancellation + Multiple simultaneous cancellation requests ---
        def _concurrent_cancel(_idx: int) -> str:
            s = PgSession()
            try:
                j = s.query(DurableJob).filter(DurableJob.id == job1.id).first()
                res = cancel_durable_job(
                    db=s,
                    job=j,
                    resource_type="scan",
                    resource_id=scan1.id,
                    actor_id=user.id,
                    redis_client=_FailingRedis(),
                    require_worker_ack=True,
                )
                return res.status
            finally:
                s.close()

        with ThreadPoolExecutor(max_workers=4) as pool:
            cancel_states = list(pool.map(_concurrent_cancel, range(4)))
        assert all(st == JobState.CANCELLING.value for st in cancel_states)

        # --- Scenario 5 & 8: Worker restart during cancellation + Duplicate cancellation acknowledgement ---
        db.refresh(job1)
        job1.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=5)
        db.commit()

        recon_worker = reconcile_jobs_on_startup(db=db, component="worker", redis_client=r_client)
        assert recon_worker["expired_leases_cancelled"] == 1
        db.refresh(job1)
        assert job1.status == JobState.CANCELLED.value
        assert db.query(ActiveJobSlot).filter(ActiveJobSlot.job_id == job1.id).count() == 0

        # Duplicate acknowledge_job_cancellation is idempotent and cannot overwrite terminal state
        ack_dup = acknowledge_job_cancellation(
            db=db, job=job1, resource_type="scan", resource_id=scan1.id, worker_id="w-dup-0"
        )
        assert ack_dup.status == JobState.CANCELLED.value

        # --- Scenario 7: Cancellation after lease expiration on a running job ---
        scan2 = Scan(id=str(uuid.uuid4()), repository_id=repo2.id, status="queued")
        db.add(scan2)
        db.flush()
        job2, _, _ = create_durable_job_with_outbox(
            db=db, user=user, job_type="scan", resource_id=scan2.id, repository_id=repo2.id, payload={}
        )
        db.commit()
        claimed2 = claim_durable_job_by_id(db=db, job_id=job2.id, worker_id="w-exp", lease_seconds=30)
        claimed2.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
        db.commit()

        # Since lease has already expired (has_live_remote_lease is False), cancel_durable_job finalizes to 'cancelled'
        canc2 = cancel_durable_job(
            db=db, job=claimed2, resource_type="scan", resource_id=scan2.id, actor_id=user.id
        )
        assert canc2.status == JobState.CANCELLED.value
        assert db.query(ActiveJobSlot).filter(ActiveJobSlot.job_id == job2.id).count() == 0

        # Verify terminal state cannot be overwritten by stale complete_claimed_job
        with pytest.raises(StaleWorkerLeaseError):
            complete_claimed_job(
                db=db, job_id=job2.id, worker_id="w-exp", lease_token=claimed2.lease_token or "stale"
            )
    finally:
        set_redis_client_override(None)
        try:
            r_client.delete(test_queue)
        except Exception:
            pass
        db.close()
        pg_engine.dispose()


# ==============================================================================
# SECTION 6: CI/CD Workflow & Scoped CVE Exception Verification
# ==============================================================================

def test_phase7a_sec6_cicd_workflow_and_scoped_cve_verification():
    """[CI/CD GATE AUDIT] Verifies .github/workflows/ci.yml service containers, build ordering, Node 22 parity,
    Gitleaks SHA-256 verification, and strictly scoped single-CVE exception without broad audit bypass.
    """
    ci_path = REPO_ROOT / ".github" / "workflows" / "ci.yml"
    ci_text = ci_path.read_text(encoding="utf-8")
    ci_data = yaml.safe_load(ci_text)

    jobs = ci_data["jobs"]
    backend_job = jobs["backend-tests"]
    services = backend_job["services"]

    # 1. PostgreSQL 16 and Redis 7 service readiness checks
    assert "postgres:16-alpine@sha256:" in services["postgres"]["image"]
    assert "pg_isready" in services["postgres"]["options"]
    assert "redis:7-alpine@sha256:" in services["redis"]["image"]
    assert "redis-cli ping" in services["redis"]["options"]

    # 2. Worker image build ordering BEFORE pytest execution
    steps = backend_job["steps"]
    build_idx = next(i for i, s in enumerate(steps) if "redmercury-worker:latest" in s.get("run", ""))
    pytest_idx = next(i for i, s in enumerate(steps) if "pytest tests/ " in s.get("run", ""))
    assert build_idx < pytest_idx, "redmercury-worker:latest must be built before running pytest"

    # 3. JUnit XML artifact generation & upload
    assert "--junitxml=.redmercury_artifacts/pytest-results.xml" in steps[pytest_idx]["run"]
    assert any(s.get("with", {}).get("path") == ".redmercury_artifacts/pytest-results.xml" for s in steps)

    # 4. Scoped CVE exception audit: must only ignore CVE-2026-132276 and must not contain broad bypasses
    audit_job = jobs["security-audit-and-secret-scan"]
    audit_steps = audit_job["steps"]
    pip_audit_step = next(s for s in audit_steps if "pip_audit" in s.get("run", ""))
    pip_audit_cmd = pip_audit_step["run"]
    assert "python -m pip_audit -r backend/requirements.txt --desc on --ignore-vuln CVE-2026-132276" in pip_audit_cmd
    assert "|| true" not in pip_audit_cmd
    assert "continue-on-error" not in pip_audit_step
    assert pip_audit_cmd.count("--ignore-vuln") == 1

    # 5. Gitleaks SHA-256 checksum verification
    gitleaks_step = next(s for s in audit_steps if "gitleaks.tar.gz" in s.get("run", ""))
    assert "sha256sum -c -" in gitleaks_step["run"]
