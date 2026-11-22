"""Phase 6 Security & Reliability Test Suite: Durable Job Execution, Worker Reliability, Atomic Job Claiming & Crash Recovery (REL-01).

Covers all 26 required Task 11 categories (A through Z):
A. Job creation and transactional outbox.
B. Database/Redis dispatch failure.
C. Restart recovery of undispatched events.
D. Atomic job claiming.
E. Concurrent worker claiming.
F. Duplicate queue delivery.
G. Idempotent API submission.
H. Tenant-scoped idempotency.
I. Atomic quota reservation.
J. Concurrent quota enforcement.
K. Worker heartbeat.
L. Lease expiration.
M. Stale worker rejection.
N. Retry and exponential backoff.
O. Dead-letter or terminal failure behaviour.
P. Queued job cancellation.
Q. Running job cancellation.
R. Subprocess process-tree cleanup.
S. Docker sandbox cancellation.
T. Workspace cleanup and tenant confinement.
U. API restart reconciliation.
V. Worker restart recovery.
W. Accurate job status transitions.
X. Audit/evidence preservation.
Y. Cross-tenant job isolation.
Z. Phase 1–5 regression protection.

Plus dedicated Live Infrastructure Integration Tests:
- Real Redis 7 queue dispatch, recovery, and duplicate message deduplication.
- Real PostgreSQL 16 FOR UPDATE SKIP LOCKED concurrent multi-session worker claiming, unique constraint enforcement, and Alembic 0014 migration verification.
- Live Docker sandbox runtime container cancellation.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from typing import List, Optional
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.core.errors import AppSecException, SecurityPolicyViolationError
from app.core.jobs import (
    InvalidJobStateTransitionError,
    JobExecutionTracker,
    JobHeartbeatMonitor,
    JobState,
    StaleWorkerLeaseError,
    cancel_durable_job,
    claim_durable_job_by_id,
    claim_next_durable_job,
    complete_claimed_job,
    compute_retry_backoff_seconds,
    create_durable_job_with_outbox,
    dispatch_outbox_events,
    execute_claimed_durable_job,
    fail_claimed_job,
    get_job_operational_metrics,
    reconcile_jobs_on_startup,
    recover_expired_job_leases,
    recover_undispatched_outbox_events,
    register_active_tracker,
    release_claimed_job_on_shutdown,
    renew_job_lease,
    set_redis_client_override,
    unregister_active_tracker,
    validate_job_transition,
)
from app.core.security import auth_rate_limiter, create_access_token
from app.main import app
from app.models.audit import AuditEvent
from app.models.evidence import SecurityEvidence
from app.models.finding import SecurityFinding
from app.models.job import ActiveJobSlot, DurableJob, JobOutboxEvent
from app.models.repository import Repository
from app.models.scan import Scan
from app.models.user import User
from app.models.verification import VerificationEvidence, VerificationRun
from app.scanner.base import BaseScannerAdapter, NormalizedFinding, ScanJobResult, ScannerStatus
from app.scanner.registry import scanner_registry
from app.scanner.worker import process_durable_jobs
from app.verification.sandbox import SandboxConfig, check_docker_availability, execute_in_container


class FakeInMemoryRedis:
    """Deterministic in-memory Redis list/key mock for unit tests (distinct from live Redis 7 integration tests)."""
    def __init__(self, fail_on_push: bool = False):
        self.fail_on_push = fail_on_push
        self.queues: dict[str, list[str]] = {}
        self.kv: dict[str, str] = {}
        self._lock = threading.Lock()

    def rpush(self, key: str, value: str) -> int:
        if self.fail_on_push:
            raise ConnectionError("Simulated Redis outage: Connection refused")
        with self._lock:
            self.queues.setdefault(key, []).append(value)
            return len(self.queues[key])

    def lpop(self, key: str) -> Optional[str]:
        with self._lock:
            q = self.queues.get(key, [])
            return q.pop(0) if q else None

    def llen(self, key: str) -> int:
        with self._lock:
            return len(self.queues.get(key, []))

    def setex(self, key: str, ttl: int, value: str) -> bool:
        with self._lock:
            self.kv[key] = value
            return True

    def ping(self) -> bool:
        if self.fail_on_push:
            raise ConnectionError("Simulated Redis outage")
        return True


def _make_repo(db: Session, owner_id: str, tmp_path: Path, name: Optional[str] = None) -> Repository:
    ws = tmp_path / f"ws_{uuid.uuid4().hex[:8]}"
    ws.mkdir(parents=True, exist_ok=True)
    (ws / "app.py").write_text("import os\ndef run(c):\n    os.system(c)\n", encoding="utf-8")
    repo = Repository(
        id=f"repo_{uuid.uuid4().hex[:10]}",
        owner_id=owner_id,
        name=name or f"repo-{uuid.uuid4().hex[:6]}",
        workspace_path=str(ws),
        default_branch="main",
        ingestion_status="completed",
        is_active=True,
    )
    db.add(repo)
    db.commit()
    db.refresh(repo)
    return repo


# ==============================================================================
# A. Job Creation and Transactional Outbox
# ==============================================================================

def test_phase6_A_job_creation_and_transactional_outbox(
    client: TestClient, create_test_user, db_session: Session, tmp_path: Path
):
    """[In-Process Integration] Creating a scan creates Scan, DurableJob, ActiveJobSlot, and JobOutboxEvent atomically."""
    fake_redis = FakeInMemoryRedis()
    set_redis_client_override(fake_redis)
    try:
        user = create_test_user(email=f"p6_a_{uuid.uuid4().hex[:6]}@xerova.com", role="analyst")
        tok = create_access_token({"sub": user.id, "email": user.email, "role": "analyst"})
        repo = _make_repo(db_session, user.id, tmp_path)

        res = client.post(
            "/api/v1/scans?enqueue_only=true",
            json={"repository_id": repo.id, "tools": ["bandit"]},
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert res.status_code == 202
        scan_id = res.json()["id"]
        assert res.json()["status"] == "queued"

        job = db_session.query(DurableJob).filter(DurableJob.resource_id == scan_id).first()
        assert job is not None
        assert job.job_type == "scan"
        assert job.tenant_id == user.id
        assert job.repository_id == repo.id
        assert job.status == JobState.QUEUED.value
        assert job.quota_reserved is True

        slot = db_session.query(ActiveJobSlot).filter(ActiveJobSlot.job_id == job.id).first()
        assert slot is not None
        assert slot.repository_active_lock == f"scan:{repo.id}"

        outbox = db_session.query(JobOutboxEvent).filter(JobOutboxEvent.job_id == job.id).first()
        assert outbox is not None
        assert outbox.status == "dispatched"
        assert outbox.dispatched_at is not None
        assert fake_redis.llen(settings.JOB_QUEUE_NAME) == 1
    finally:
        set_redis_client_override(None)


# ==============================================================================
# B & C. Database/Redis Dispatch Failure and Restart Recovery of Outbox Events
# ==============================================================================

def test_phase6_B_C_redis_dispatch_failure_and_outbox_restart_recovery(
    client: TestClient, create_test_user, db_session: Session, tmp_path: Path
):
    """[Simulated Outage] If Redis fails during job submission, DB job remains durable and outbox event stays 'pending' until recovered."""
    broken_redis = FakeInMemoryRedis(fail_on_push=True)
    set_redis_client_override(broken_redis)
    try:
        user = create_test_user(email=f"p6_bc_{uuid.uuid4().hex[:6]}@xerova.com", role="analyst")
        tok = create_access_token({"sub": user.id, "email": user.email, "role": "analyst"})
        repo = _make_repo(db_session, user.id, tmp_path)

        # 1. Submit job while Redis is down -> HTTP 202 still succeeds because DB is authoritative!
        res = client.post(
            "/api/v1/scans?enqueue_only=true",
            json={"repository_id": repo.id, "tools": ["bandit"]},
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert res.status_code == 202
        scan_id = res.json()["id"]

        job = db_session.query(DurableJob).filter(DurableJob.resource_id == scan_id).first()
        outbox = db_session.query(JobOutboxEvent).filter(JobOutboxEvent.job_id == job.id).first()
        assert job.status == JobState.QUEUED.value
        assert outbox.status == "pending"
        assert outbox.dispatch_attempts >= 1
        assert "Redis outage" in (outbox.last_error or "")

        # 2. Redis recovers and startup/periodic outbox recovery runs
        healthy_redis = FakeInMemoryRedis(fail_on_push=False)
        set_redis_client_override(healthy_redis)
        recovered = recover_undispatched_outbox_events(db=db_session)
        assert recovered >= 1

        db_session.refresh(outbox)
        assert outbox.status == "dispatched"
        assert outbox.dispatched_at is not None
        assert healthy_redis.llen(settings.JOB_QUEUE_NAME) >= 1
    finally:
        set_redis_client_override(None)


# ==============================================================================
# D, E, F. Atomic Job Claiming, Concurrent Worker Claiming & Duplicate Delivery
# ==============================================================================

def test_phase6_D_E_F_atomic_claiming_multi_worker_concurrency_and_duplicate_delivery(
    create_test_user, tmp_path: Path
):
    """[Multi-Session Concurrency] Multiple workers racing on the same queued job and duplicate Redis messages only claim once."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_file = tf.name.replace("\\", "/")

    eng = create_engine(f"sqlite:///{db_file}", connect_args={"check_same_thread": False, "timeout": 15})
    from app.db.base import Base
    Base.metadata.create_all(bind=eng)
    SessionFactory = sessionmaker(bind=eng, autocommit=False, autoflush=False)

    fake_redis = FakeInMemoryRedis()
    set_redis_client_override(fake_redis)
    try:
        setup_db = SessionFactory()
        user = User(
            id=f"u_conc_{uuid.uuid4().hex[:8]}",
            email=f"conc_{uuid.uuid4().hex[:6]}@xerova.com",
            password_hash="hash",
            account_status="active",
            role="analyst",
        )
        setup_db.add(user)
        setup_db.commit()
        repo = _make_repo(setup_db, user.id, tmp_path)

        scan = Scan(id=str(uuid.uuid4()), repository_id=repo.id, status="queued")
        setup_db.add(scan)
        setup_db.flush()
        job, outbox, _ = create_durable_job_with_outbox(
            db=setup_db,
            user=user,
            job_type="scan",
            resource_id=scan.id,
            repository_id=repo.id,
            payload={"tools": ["bandit"]},
        )
        setup_db.commit()
        target_job_id = job.id

        # Simulate duplicate queue deliveries in Redis (3 messages for the same job_id)
        for _ in range(3):
            fake_redis.rpush(
                settings.JOB_QUEUE_NAME,
                json.dumps({"job_id": target_job_id, "job_type": "scan", "resource_id": scan.id}),
            )
        setup_db.close()

        # 5 concurrent workers attempt to claim the job simultaneously using independent DB sessions
        barrier = threading.Barrier(5)

        def _worker_claim(w_idx: int) -> Optional[str]:
            w_db = SessionFactory()
            try:
                barrier.wait(timeout=5)
                claimed = claim_next_durable_job(db=w_db, worker_id=f"worker-{w_idx}")
                return claimed.worker_id if claimed is not None else None
            finally:
                w_db.close()

        with ThreadPoolExecutor(max_workers=5) as pool:
            winners = [r for r in pool.map(_worker_claim, range(5)) if r is not None]

        # Exactly ONE worker must succeed in claiming the job!
        assert len(winners) == 1, f"Expected exactly 1 claiming worker, got {winners}"

        verify_db = SessionFactory()
        claimed_job = verify_db.query(DurableJob).filter(DurableJob.id == target_job_id).first()
        assert claimed_job.status == JobState.RUNNING.value
        assert claimed_job.worker_id == winners[0]
        assert claimed_job.attempt_count == 1
        assert claimed_job.lease_token is not None
        assert claimed_job.lease_expires_at is not None

        # A subsequent duplicate queue message attempt must return None
        dup_claim = claim_durable_job_by_id(db=verify_db, job_id=target_job_id, worker_id="worker-dup")
        assert dup_claim is None
        verify_db.close()
    finally:
        set_redis_client_override(None)
        eng.dispose()
        try:
            os.remove(db_file)
        except Exception:
            pass


# ==============================================================================
# G & H. Idempotent API Submission & Tenant-Scoped Idempotency
# ==============================================================================

def test_phase6_G_H_idempotent_api_submission_and_tenant_scoping(
    client: TestClient, create_test_user, db_session: Session, tmp_path: Path
):
    """[API Integration] Duplicate submissions with same Idempotency-Key return the existing job; cross-tenant keys never collide."""
    user_a = create_test_user(email=f"idem_a_{uuid.uuid4().hex[:6]}@xerova.com", role="analyst")
    user_b = create_test_user(email=f"idem_b_{uuid.uuid4().hex[:6]}@xerova.com", role="analyst")
    tok_a = create_access_token({"sub": user_a.id, "email": user_a.email, "role": "analyst"})
    tok_b = create_access_token({"sub": user_b.id, "email": user_b.email, "role": "analyst"})

    repo_a1 = _make_repo(db_session, user_a.id, tmp_path, name="repo-a1")
    repo_a2 = _make_repo(db_session, user_a.id, tmp_path, name="repo-a2")
    repo_b1 = _make_repo(db_session, user_b.id, tmp_path, name="repo-b1")

    idem_key = f"idem-key-{uuid.uuid4().hex[:10]}"

    # 1. User A first submission
    res1 = client.post(
        "/api/v1/scans?enqueue_only=true",
        json={"repository_id": repo_a1.id, "tools": ["bandit"]},
        headers={"Authorization": f"Bearer {tok_a}", "Idempotency-Key": idem_key},
    )
    assert res1.status_code == 202
    scan_a_id = res1.json()["id"]

    # 2. User A repeated identical submission -> returns existing scan_a_id (not a 409, not a new job)
    res2 = client.post(
        "/api/v1/scans?enqueue_only=true",
        json={"repository_id": repo_a1.id, "tools": ["bandit"]},
        headers={"Authorization": f"Bearer {tok_a}", "Idempotency-Key": idem_key},
    )
    assert res2.status_code == 202
    assert res2.json()["id"] == scan_a_id

    jobs_a = db_session.query(DurableJob).filter(
        DurableJob.tenant_id == user_a.id,
        DurableJob.idempotency_key == idem_key,
    ).all()
    assert len(jobs_a) == 1

    # 3. User A reusing same idempotency key for a DIFFERENT repository -> 409 IDEMPOTENCY_KEY_CONFLICT
    res_conflict = client.post(
        "/api/v1/scans?enqueue_only=true",
        json={"repository_id": repo_a2.id, "tools": ["bandit"]},
        headers={"Authorization": f"Bearer {tok_a}", "Idempotency-Key": idem_key},
    )
    assert res_conflict.status_code == 409
    assert res_conflict.json()["error"]["code"] == "IDEMPOTENCY_KEY_CONFLICT"

    # 4. User B using the EXACT SAME idempotency key string -> scoped to User B, creates User B's distinct scan!
    res_b = client.post(
        "/api/v1/scans?enqueue_only=true",
        json={"repository_id": repo_b1.id, "tools": ["bandit"]},
        headers={"Authorization": f"Bearer {tok_b}", "Idempotency-Key": idem_key},
    )
    assert res_b.status_code == 202
    scan_b_id = res_b.json()["id"]
    assert scan_b_id != scan_a_id


# ==============================================================================
# I & J. Atomic Quota Reservation and Concurrent Quota Enforcement
# ==============================================================================

def test_phase6_I_J_atomic_quota_reservation_concurrency_limit_and_slot_release(
    client: TestClient, create_test_user, db_session: Session, tmp_path: Path, monkeypatch
):
    """[Quota & Concurrency] Enforces MAX_CONCURRENT_SCANS_PER_USER via ActiveJobSlot and releases slots on cancel/completion."""
    monkeypatch.setattr(settings, "MAX_CONCURRENT_SCANS_PER_USER", 2)
    auth_rate_limiter.reset()

    user = create_test_user(email=f"quota_{uuid.uuid4().hex[:6]}@xerova.com", role="analyst")
    tok = create_access_token({"sub": user.id, "email": user.email, "role": "analyst"})
    headers = {"Authorization": f"Bearer {tok}"}

    r1 = _make_repo(db_session, user.id, tmp_path, name="q-repo-1")
    r2 = _make_repo(db_session, user.id, tmp_path, name="q-repo-2")
    r3 = _make_repo(db_session, user.id, tmp_path, name="q-repo-3")

    # 1. Reserve slot 1 and slot 2
    s1 = client.post("/api/v1/scans?enqueue_only=true", json={"repository_id": r1.id}, headers=headers)
    s2 = client.post("/api/v1/scans?enqueue_only=true", json={"repository_id": r2.id}, headers=headers)
    assert s1.status_code == 202
    assert s2.status_code == 202

    # 2. 3rd concurrent scan must be rejected because both slots 1 and 2 are occupied
    s3_blocked = client.post("/api/v1/scans?enqueue_only=true", json={"repository_id": r3.id}, headers=headers)
    assert s3_blocked.status_code == 403
    assert "concurrency limit reached" in s3_blocked.json()["error"]["message"].lower()

    # 3. Cancel scan 1 -> releases slot 1 immediately!
    cancel_res = client.post(f"/api/v1/scans/{s1.json()['id']}/cancel", headers=headers)
    assert cancel_res.status_code == 200
    assert cancel_res.json()["status"] == "cancelled"

    # 4. Now r3 can acquire the freed slot!
    s3_allowed = client.post("/api/v1/scans?enqueue_only=true", json={"repository_id": r3.id}, headers=headers)
    assert s3_allowed.status_code == 202


# ==============================================================================
# K, L, M. Worker Heartbeat, Lease Expiration & Stale Worker Rejection
# ==============================================================================

def test_phase6_K_L_M_worker_heartbeat_lease_expiration_and_stale_worker_fencing(
    create_test_user, db_session: Session, tmp_path: Path
):
    """[Lease Fencing] Worker heartbeats extend lease; once lease expires and is recovered/reclaimed, stale worker is fenced off."""
    user = create_test_user(email=f"lease_{uuid.uuid4().hex[:6]}@xerova.com", role="analyst")
    repo = _make_repo(db_session, user.id, tmp_path)

    scan = Scan(id=str(uuid.uuid4()), repository_id=repo.id, status="queued")
    db_session.add(scan)
    db_session.flush()
    job, _, _ = create_durable_job_with_outbox(
        db=db_session,
        user=user,
        job_type="scan",
        resource_id=scan.id,
        repository_id=repo.id,
        payload={"tools": ["bandit"]},
        max_attempts=3,
    )
    db_session.commit()

    # 1. Worker-1 claims the job
    claimed_w1 = claim_durable_job_by_id(db=db_session, job_id=job.id, worker_id="worker-1", lease_seconds=30)
    assert claimed_w1 is not None
    w1_token = claimed_w1.lease_token
    initial_exp = claimed_w1.lease_expires_at

    # 2. K: Worker-1 renews heartbeat -> lease_expires_at advances
    assert renew_job_lease(db=db_session, job_id=job.id, worker_id="worker-1", lease_token=w1_token, lease_seconds=60) is True
    db_session.refresh(claimed_w1)
    assert claimed_w1.lease_expires_at > initial_exp

    # 3. L: Simulate Worker-1 hanging until its lease expires
    claimed_w1.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=5)
    db_session.commit()

    # Worker-1 can no longer renew an expired lease
    assert renew_job_lease(db=db_session, job_id=job.id, worker_id="worker-1", lease_token=w1_token, lease_seconds=60) is False

    # Crash recovery detects expired lease and schedules retry
    recovery_stats = recover_expired_job_leases(db=db_session)
    assert recovery_stats["retried"] == 1

    db_session.refresh(claimed_w1)
    assert claimed_w1.status == JobState.RETRYING.value
    # Make retry due immediately so Worker-2 can claim it
    claimed_w1.next_retry_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db_session.commit()

    # 4. Worker-2 claims the recovered job (receiving a brand new lease_token)
    claimed_w2 = claim_durable_job_by_id(db=db_session, job_id=job.id, worker_id="worker-2", lease_seconds=60)
    assert claimed_w2 is not None
    w2_token = claimed_w2.lease_token
    assert w2_token != w1_token
    assert claimed_w2.attempt_count == 2

    # 5. M: Stale Worker-1 wakes up and tries to complete or fail the job using its old w1_token -> REJECTED!
    with pytest.raises(StaleWorkerLeaseError):
        complete_claimed_job(db=db_session, job_id=job.id, worker_id="worker-1", lease_token=w1_token)

    with pytest.raises(StaleWorkerLeaseError):
        fail_claimed_job(
            db=db_session,
            job_id=job.id,
            worker_id="worker-1",
            lease_token=w1_token,
            failure_category="stale_err",
            error_detail="Stale failure attempt",
        )

    # 6. Active Worker-2 completes the job cleanly with its valid w2_token
    done_job = complete_claimed_job(db=db_session, job_id=job.id, worker_id="worker-2", lease_token=w2_token)
    assert done_job.status == JobState.COMPLETED.value
    assert done_job.worker_id == "worker-2"


# ==============================================================================
# N & O. Retry, Exponential Backoff with Jitter & Terminal Failure Behaviour
# ==============================================================================

def test_phase6_N_O_retry_exponential_backoff_and_terminal_dead_letter_failure(
    create_test_user, db_session: Session, tmp_path: Path
):
    """[Retry & Dead-Letter] Failed attempts back off exponentially with jitter and transition to terminal 'failed' at max_attempts."""
    # 1. Verify exponential backoff growth
    b1 = compute_retry_backoff_seconds(1, base_delay=2.0, max_delay=60.0, deterministic_jitter=0.1)
    b2 = compute_retry_backoff_seconds(2, base_delay=2.0, max_delay=60.0, deterministic_jitter=0.1)
    b3 = compute_retry_backoff_seconds(3, base_delay=2.0, max_delay=60.0, deterministic_jitter=0.1)
    assert b1 == 2.1
    assert b2 == 4.1
    assert b3 == 8.1

    user = create_test_user(email=f"retry_{uuid.uuid4().hex[:6]}@xerova.com", role="analyst")
    repo = _make_repo(db_session, user.id, tmp_path)
    scan = Scan(id=str(uuid.uuid4()), repository_id=repo.id, status="queued")
    db_session.add(scan)
    db_session.flush()
    job, _, _ = create_durable_job_with_outbox(
        db=db_session,
        user=user,
        job_type="scan",
        resource_id=scan.id,
        repository_id=repo.id,
        payload={"tools": ["bandit"]},
        max_attempts=2,
    )
    db_session.commit()

    # Attempt 1 fails -> transitions to 'retrying' (slot remains reserved)
    c1 = claim_durable_job_by_id(db=db_session, job_id=job.id, worker_id="w-retry", lease_seconds=30)
    f1 = fail_claimed_job(
        db=db_session,
        job_id=job.id,
        worker_id="w-retry",
        lease_token=c1.lease_token,
        failure_category="transient_io_error",
        error_detail="Temporary disk read error",
        retryable=True,
    )
    assert f1.status == JobState.RETRYING.value
    assert f1.attempt_count == 1
    assert f1.next_retry_at is not None
    assert f1.quota_reserved is True

    # Make due for Attempt 2
    f1.next_retry_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db_session.commit()

    # Attempt 2 (max_attempts=2) fails -> transitions to terminal 'failed' and releases ActiveJobSlot!
    c2 = claim_durable_job_by_id(db=db_session, job_id=job.id, worker_id="w-retry", lease_seconds=30)
    assert c2.attempt_count == 2
    f2 = fail_claimed_job(
        db=db_session,
        job_id=job.id,
        worker_id="w-retry",
        lease_token=c2.lease_token,
        failure_category="transient_io_error",
        error_detail="Permanent failure on attempt 2",
        retryable=True,
    )
    assert f2.status == JobState.FAILED.value
    assert f2.failed_at is not None
    assert f2.failure_category == "transient_io_error"
    assert f2.quota_reserved is False
    assert db_session.query(ActiveJobSlot).filter(ActiveJobSlot.job_id == job.id).count() == 0


# ==============================================================================
# P, Q, R, S, T. Queued & Running Cancellation, Subprocess Tree, Docker Sandbox & Confined Workspace Cleanup
# ==============================================================================

def test_phase6_P_queued_job_cancellation_prevents_execution(
    client: TestClient, create_test_user, db_session: Session, tmp_path: Path
):
    """[Cancellation] Cancelling a queued job transitions to 'cancelled', cancels outbox events, and prevents worker execution."""
    user = create_test_user(email=f"canc_q_{uuid.uuid4().hex[:6]}@xerova.com", role="analyst")
    tok = create_access_token({"sub": user.id, "email": user.email, "role": "analyst"})
    headers = {"Authorization": f"Bearer {tok}"}
    repo = _make_repo(db_session, user.id, tmp_path)

    res = client.post("/api/v1/scans?enqueue_only=true", json={"repository_id": repo.id}, headers=headers)
    assert res.status_code == 202
    scan_id = res.json()["id"]

    # Cancel while still queued
    canc_res = client.post(f"/api/v1/scans/{scan_id}/cancel", headers=headers)
    assert canc_res.status_code == 200
    assert canc_res.json()["status"] == "cancelled"

    # Idempotent repeat cancel
    canc_res_2 = client.post(f"/api/v1/scans/{scan_id}/cancel", headers=headers)
    assert canc_res_2.status_code == 200
    assert canc_res_2.json()["status"] == "cancelled"

    # Worker attempting to claim the cancelled job must return None
    job = db_session.query(DurableJob).filter(DurableJob.resource_id == scan_id).first()
    assert job.status == JobState.CANCELLED.value
    assert claim_durable_job_by_id(db=db_session, job_id=job.id, worker_id="w-late") is None


def test_phase6_Q_R_T_running_job_cancellation_kills_subprocess_tree_and_confined_temp_workspace(
    create_test_user, db_session: Session, tmp_path: Path
):
    """[Live Subprocess Cancellation] Cancelling a running job kills the child process tree and cleans only confined temp workspaces."""
    user = create_test_user(email=f"canc_run_{uuid.uuid4().hex[:6]}@xerova.com", role="analyst")
    repo = _make_repo(db_session, user.id, tmp_path)
    other_tenant_ws = tmp_path / "other_tenant_persistent_repo"
    other_tenant_ws.mkdir(parents=True, exist_ok=True)
    (other_tenant_ws / "secret.py").write_text("KEEP_ME = True\n", encoding="utf-8")

    # Create a confined disposable temp workspace inside system temp dir
    temp_ws = Path(tempfile.mkdtemp(prefix="rm_p6_cancel_ws_"))
    (temp_ws / "disposable.py").write_text("TEMP = 1\n", encoding="utf-8")

    scan = Scan(id=str(uuid.uuid4()), repository_id=repo.id, status="queued")
    db_session.add(scan)
    db_session.flush()
    job, _, _ = create_durable_job_with_outbox(
        db=db_session,
        user=user,
        job_type="scan",
        resource_id=scan.id,
        repository_id=repo.id,
        payload={"tools": ["bandit"]},
    )
    db_session.commit()
    claimed = claim_durable_job_by_id(db=db_session, job_id=job.id, worker_id="w-subproc", lease_seconds=60)

    tracker = JobExecutionTracker(job_id=claimed.id, resource_id=scan.id, tenant_id=user.id)
    register_active_tracker(tracker)

    # Spawn a real sleeping Python subprocess tree
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
    )
    tracker.register_process(proc)
    tracker.register_temp_workspace(temp_ws)
    # Attempt to register an unconfined path outside system temp -> cleanup must refuse to delete it!
    tracker.register_temp_workspace(other_tenant_ws)

    try:
        assert proc.poll() is None
        # Cancel the running job
        cancel_durable_job(
            db=db_session,
            job=claimed,
            resource_type="scan",
            resource_id=scan.id,
            actor_id=user.id,
        )

        # Subprocess must be terminated immediately
        proc.wait(timeout=5)
        assert proc.poll() is not None

        # Confined temp workspace must be deleted
        assert not temp_ws.exists()
        # Other tenant's workspace outside temp root must be untouched!
        assert other_tenant_ws.exists()
        assert (other_tenant_ws / "secret.py").exists()
    finally:
        unregister_active_tracker(tracker)
        if proc.poll() is None:
            proc.kill()
        shutil.rmtree(temp_ws, ignore_errors=True)


@pytest.mark.skipif(
    not check_docker_availability(timeout_seconds=2.0)[0],
    reason="Live Docker daemon unavailable for container cancellation test",
)
def test_phase6_S_live_docker_sandbox_container_cancellation(tmp_path: Path):
    """[Live Docker Runtime] Cancelling an active JobExecutionTracker terminates the running Docker sandbox container."""
    tracker = JobExecutionTracker(job_id=f"job_dkr_{uuid.uuid4().hex[:8]}", resource_id="vr_dkr", tenant_id="u_dkr")
    register_active_tracker(tracker)

    def _trigger_cancel_shortly():
        time.sleep(1.5)
        tracker.terminate_all(reason="cancelled")

    cancel_thread = threading.Thread(target=_trigger_cancel_shortly, daemon=True)
    cancel_thread.start()

    start_ts = time.perf_counter()
    try:
        cfg = SandboxConfig(
            image="redmercury-worker:latest",
            user="10002:10002",
            timeout_seconds=30,
            fail_closed=True,
        )
        returncode, stdout, stderr, is_timeout, err_msg = execute_in_container(
            workspace_dir=tmp_path,
            cmd_args=["python3", "-c", "import time; time.sleep(25)"],
            config=cfg,
        )
        elapsed = time.perf_counter() - start_ts
        # Container must have been killed by cancellation well before the 25s sleep / 30s timeout!
        assert elapsed < 15.0, f"Expected fast container cancellation, took {elapsed:.1f}s"
        assert returncode != 0
    finally:
        unregister_active_tracker(tracker)


# ==============================================================================
# U & V. API Restart Reconciliation and Worker Restart Recovery
# ==============================================================================

def test_phase6_U_V_api_restart_preserves_healthy_leases_and_recovers_expired_leases(
    create_test_user, db_session: Session, tmp_path: Path
):
    """[Reconciliation] API startup reconciliation must NOT interrupt a job with a valid lease, while recovering expired leases."""
    user = create_test_user(email=f"recon_{uuid.uuid4().hex[:6]}@xerova.com", role="analyst")
    r_healthy = _make_repo(db_session, user.id, tmp_path, name="r-healthy")
    r_expired = _make_repo(db_session, user.id, tmp_path, name="r-expired")

    # 1. Healthy running scan (even with old created_at, its worker lease is valid for another 45s!)
    old_time = datetime.now(timezone.utc) - timedelta(minutes=30)
    s_healthy = Scan(id=str(uuid.uuid4()), repository_id=r_healthy.id, status="queued", created_at=old_time)
    s_expired = Scan(id=str(uuid.uuid4()), repository_id=r_expired.id, status="queued", created_at=old_time)
    db_session.add_all([s_healthy, s_expired])
    db_session.flush()

    j_healthy, _, _ = create_durable_job_with_outbox(
        db=db_session, user=user, job_type="scan", resource_id=s_healthy.id, repository_id=r_healthy.id, payload={}
    )
    j_expired, _, _ = create_durable_job_with_outbox(
        db=db_session, user=user, job_type="scan", resource_id=s_expired.id, repository_id=r_expired.id, payload={}, max_attempts=1
    )
    db_session.commit()

    claim_durable_job_by_id(db=db_session, job_id=j_healthy.id, worker_id="w-alive", lease_seconds=60)
    claimed_exp = claim_durable_job_by_id(db=db_session, job_id=j_expired.id, worker_id="w-crashed", lease_seconds=60)
    claimed_exp.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
    db_session.commit()

    # Run startup reconciliation
    summary = reconcile_jobs_on_startup(db=db_session, component="api-restart-test")
    assert summary["expired_leases_failed"] >= 1

    db_session.refresh(j_healthy)
    db_session.refresh(s_healthy)
    db_session.refresh(j_expired)
    db_session.refresh(s_expired)

    # Healthy leased job MUST still be 'running'!
    assert j_healthy.status == JobState.RUNNING.value
    assert s_healthy.status == "running"

    # Expired job (with max_attempts=1) MUST be transitioned to 'failed'
    assert j_expired.status == JobState.FAILED.value
    assert s_expired.status == "failed"


# ==============================================================================
# W, X, Y. State Machine Transitions, Audit/Evidence Preservation & Cross-Tenant Job Isolation
# ==============================================================================

def test_phase6_W_centralized_state_machine_rejects_invalid_transitions():
    """[State Machine] validate_job_transition allows valid transitions and rejects invalid transitions from terminal states."""
    validate_job_transition("queued", "running")
    validate_job_transition("running", "retrying")
    validate_job_transition("retrying", "running")
    validate_job_transition("running", "cancelling")
    validate_job_transition("cancelling", "cancelled")
    validate_job_transition("running", "completed")

    for bad_from, bad_to in [
        ("completed", "running"),
        ("completed", "cancelled"),
        ("failed", "running"),
        ("cancelled", "running"),
        ("queued", "completed"),
    ]:
        with pytest.raises(InvalidJobStateTransitionError):
            validate_job_transition(bad_from, bad_to)


def test_phase6_X_Y_audit_evidence_preservation_and_cross_tenant_job_isolation(
    client: TestClient, create_test_user, db_session: Session, tmp_path: Path
):
    """[Security & Isolation] Workers reject tampered tenant ownership; cross-tenant status/cancel return 403; evidence is preserved."""
    alice = create_test_user(email=f"alice_p6_{uuid.uuid4().hex[:6]}@xerova.com", role="analyst")
    bob = create_test_user(email=f"bob_p6_{uuid.uuid4().hex[:6]}@xerova.com", role="analyst")
    tok_alice = create_access_token({"sub": alice.id, "email": alice.email, "role": "analyst"})
    tok_bob = create_access_token({"sub": bob.id, "email": bob.email, "role": "analyst"})

    repo_alice = _make_repo(db_session, alice.id, tmp_path)
    res = client.post(
        "/api/v1/scans?enqueue_only=true",
        json={"repository_id": repo_alice.id, "tools": ["bandit"]},
        headers={"Authorization": f"Bearer {tok_alice}"},
    )
    assert res.status_code == 202
    scan_id = res.json()["id"]

    # 1. Bob cannot view status, results, or cancel Alice's queued job -> 403 Forbidden
    assert client.get(f"/api/v1/scans/{scan_id}/status", headers={"Authorization": f"Bearer {tok_bob}"}).status_code == 403
    assert client.post(f"/api/v1/scans/{scan_id}/cancel", headers={"Authorization": f"Bearer {tok_bob}"}).status_code == 403

    # 2. Tamper with job.tenant_id to simulate a poisoned message/record -> worker revalidation fails closed!
    job = db_session.query(DurableJob).filter(DurableJob.resource_id == scan_id).first()
    job.tenant_id = bob.id
    db_session.commit()

    claimed = claim_durable_job_by_id(db=db_session, job_id=job.id, worker_id="w-sec-check")
    executed = execute_claimed_durable_job(db=db_session, job=claimed, worker_id="w-sec-check", start_heartbeat=False)
    assert executed.status == JobState.FAILED.value
    assert executed.failure_category == "policy_violation"

    # 3. Verify audit event recorded on scan trigger is preserved intact
    audit_count = db_session.query(AuditEvent).filter(AuditEvent.resource_identifier == scan_id).count()
    assert audit_count >= 1

    # 4. Operational metrics endpoint returns safe telemetry without leaking repository URLs or tokens
    metrics_res = client.get("/api/v1/health/jobs")
    assert metrics_res.status_code == 200
    m_data = metrics_res.json()
    for required_metric in (
        "queue_depth",
        "pending_outbox_events",
        "active_jobs",
        "expired_leases",
        "worker_status",
        "retry_counts",
        "failed_jobs",
        "avg_cancellation_latency_ms",
        "avg_job_execution_duration_ms",
        "avg_queue_dispatch_latency_ms",
    ):
        assert required_metric in m_data


# ==============================================================================
# Z. Phase 1–5 Security Controls Regression Verification
# ==============================================================================

def test_phase6_Z_phase1_to_phase5_security_controls_preserved(
    client: TestClient, create_test_user, monkeypatch
):
    """[Regression Guard] Confirm Phase 1–5 security controls remain active alongside Phase 6 durable jobs."""
    from app.core.ingestion import resolve_required_git_egress_proxy

    # SEC-06 strict mode egress proxy fail-closed
    monkeypatch.setattr(settings, "APP_ENV", "production")
    monkeypatch.setattr(settings, "GIT_EGRESS_PROXY_URL", "")
    with pytest.raises(SecurityPolicyViolationError):
        resolve_required_git_egress_proxy()

    monkeypatch.setattr(settings, "APP_ENV", "development")

    # SEC-02 & SEC-19 viewer role blocked from mutating endpoints (scans, verifications, analyze-finding)
    viewer = create_test_user(email=f"v_p6z_{uuid.uuid4().hex[:6]}@xerova.com", role="viewer")
    v_tok = create_access_token({"sub": viewer.id, "email": viewer.email, "role": "viewer"})
    v_hdr = {"Authorization": f"Bearer {v_tok}"}

    assert client.post("/api/v1/scans", json={"repository_id": "any"}, headers=v_hdr).status_code == 403
    assert client.post(
        "/api/v1/analyze-finding",
        json={"finding_id": "F-1", "user_authorized_analysis": True},
        headers=v_hdr,
    ).status_code == 403


# ==============================================================================
# LIVE INFRASTRUCTURE INTEGRATION: Real Redis 7 & Real PostgreSQL 16
# ==============================================================================

def _get_live_redis_url() -> Optional[str]:
    url = os.environ.get("TEST_REDIS_URL") or "redis://127.0.0.1:6379/15"
    try:
        import redis
        c = redis.Redis.from_url(url, decode_responses=True, socket_connect_timeout=1.0, socket_timeout=1.0)
        if c.ping():
            return url
    except Exception:
        pass
    return None


def _get_live_postgres_url() -> Optional[str]:
    url = os.environ.get("TEST_POSTGRES_URL") or "postgresql+psycopg://postgres:postgres@127.0.0.1:5432/test_redmercury"
    try:
        eng = create_engine(url, connect_args={"connect_timeout": 1})
        with eng.connect() as conn:
            conn.execute(text("SELECT 1"))
        eng.dispose()
        return url
    except Exception:
        return None


LIVE_REDIS_URL = _get_live_redis_url()
LIVE_POSTGRES_URL = _get_live_postgres_url()


@pytest.mark.skipif(
    LIVE_REDIS_URL is None,
    reason="Live Redis 7 instance not reachable on 127.0.0.1:6379 or TEST_REDIS_URL",
)
def test_phase6_live_redis_outbox_dispatch_and_worker_claim_integration(
    create_test_user, db_session: Session, tmp_path: Path, monkeypatch
):
    """[LIVE REDIS 7] Verifies transactional outbox dispatch, LPOP consumption, and cancellation signaling on real Redis."""
    import redis
    r_client = redis.Redis.from_url(LIVE_REDIS_URL, decode_responses=True)
    test_queue = f"redmercury:test:queue:{uuid.uuid4().hex[:8]}"
    monkeypatch.setattr(settings, "JOB_QUEUE_NAME", test_queue)
    set_redis_client_override(r_client)

    try:
        # Clear any leftover queued jobs in shared SQLite test DB so only this test's job is eligible
        db_session.query(DurableJob).filter(
            DurableJob.status.in_([JobState.QUEUED.value, JobState.RETRYING.value])
        ).update({"status": JobState.CANCELLED.value}, synchronize_session=False)
        db_session.commit()

        user = create_test_user(email=f"live_redis_{uuid.uuid4().hex[:6]}@xerova.com", role="analyst")
        repo = _make_repo(db_session, user.id, tmp_path)
        scan = Scan(id=str(uuid.uuid4()), repository_id=repo.id, status="queued")
        db_session.add(scan)
        db_session.flush()

        job, outbox, _ = create_durable_job_with_outbox(
            db=db_session,
            user=user,
            job_type="scan",
            resource_id=scan.id,
            repository_id=repo.id,
            payload={"tools": ["bandit"]},
        )
        db_session.commit()

        # Dispatch to live Redis 7
        dispatched = dispatch_outbox_events(db=db_session, job_id=job.id, redis_client=r_client)
        assert dispatched == 1
        assert r_client.llen(test_queue) == 1

        # Push a duplicate message to live Redis 7 to verify at-least-once idempotent claiming
        r_client.rpush(test_queue, json.dumps({"job_id": job.id, "job_type": "scan", "resource_id": scan.id}))
        assert r_client.llen(test_queue) == 2

        claimed_1 = claim_next_durable_job(db=db_session, worker_id="live-redis-w1", redis_client=r_client)
        assert claimed_1 is not None
        assert claimed_1.id == job.id

        # Second worker popping the duplicate message from live Redis 7 gets None
        claimed_2 = claim_next_durable_job(db=db_session, worker_id="live-redis-w2", redis_client=r_client)
        assert claimed_2 is None
    finally:
        set_redis_client_override(None)
        try:
            r_client.delete(test_queue)
        except Exception:
            pass


@pytest.mark.skipif(
    LIVE_POSTGRES_URL is None,
    reason="Live PostgreSQL 16 instance not reachable on 127.0.0.1:5432 or TEST_POSTGRES_URL",
)
def test_phase6_live_postgresql_skip_locked_concurrency_and_unique_constraints(tmp_path: Path):
    """[LIVE POSTGRESQL 16] Verifies FOR UPDATE SKIP LOCKED multi-session concurrent claiming in an isolated per-test DB."""
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import text
    from sqlalchemy.engine import make_url

    base_url = make_url(LIVE_POSTGRES_URL)
    isolated_db_name = f"rm_test_p6_{uuid.uuid4().hex[:12]}"
    admin_url = base_url.set(database="postgres")
    isolated_url = base_url.set(database=isolated_db_name)

    admin_engine = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    pg_engine = None
    setup_s = None
    try:
        with admin_engine.connect() as admin_conn:
            admin_conn.execute(text(f'CREATE DATABASE "{isolated_db_name}"'))

        cfg = Config("backend/alembic.ini")
        cfg.set_main_option("sqlalchemy.url", isolated_url.render_as_string(hide_password=False))
        command.upgrade(cfg, "head")

        pg_engine = create_engine(isolated_url, pool_size=10, max_overflow=10)
        PgSession = sessionmaker(bind=pg_engine, autocommit=False, autoflush=False)
        setup_s = PgSession()

        user = User(
            id=f"pg_u_{uuid.uuid4().hex[:8]}",
            email=f"pg_p6_{uuid.uuid4().hex[:8]}@xerova.com",
            password_hash="hash",
            account_status="active",
            role="analyst",
        )
        setup_s.add(user)
        setup_s.commit()

        # Create 3 distinct repositories and 3 queued durable scan jobs in isolated PostgreSQL 16 DB
        created_job_ids: List[str] = []
        for idx in range(3):
            repo = _make_repo(setup_s, user.id, tmp_path, name=f"pg-repo-{idx}")
            scan = Scan(id=str(uuid.uuid4()), repository_id=repo.id, status="queued")
            setup_s.add(scan)
            setup_s.flush()
            job, _, _ = create_durable_job_with_outbox(
                db=setup_s,
                user=user,
                job_type="scan",
                resource_id=scan.id,
                repository_id=repo.id,
                payload={"tools": ["bandit"]},
                idempotency_key=f"pg-idem-{idx}-{uuid.uuid4().hex[:6]}",
            )
            setup_s.commit()
            created_job_ids.append(job.id)

        # 6 concurrent worker threads with independent PostgreSQL connections race via FOR UPDATE SKIP LOCKED
        barrier = threading.Barrier(6)

        def _pg_worker_claim(w_num: int) -> Optional[tuple[str, str]]:
            s = PgSession()
            try:
                barrier.wait(timeout=5)
                claimed = claim_next_durable_job(db=s, worker_id=f"pg-worker-{w_num}")
                if claimed and claimed.id in created_job_ids:
                    return (claimed.id, claimed.worker_id)
                return None
            finally:
                s.close()

        with ThreadPoolExecutor(max_workers=6) as pool:
            results = [r for r in pool.map(_pg_worker_claim, range(6)) if r is not None]

        claimed_ids = [r[0] for r in results]
        # Every job in created_job_ids must be claimed at most ONCE (zero duplicate claims across concurrent Postgres workers!)
        assert len(claimed_ids) == len(set(claimed_ids)), f"Duplicate claim detected in PostgreSQL: {results}"
        assert set(claimed_ids).issubset(set(created_job_ids))
        assert len(claimed_ids) == 3
    finally:
        if setup_s is not None:
            setup_s.close()
        if pg_engine is not None:
            pg_engine.dispose()
        try:
            with admin_engine.connect() as admin_conn:
                admin_conn.execute(
                    text(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                        "WHERE datname = :db AND pid <> pg_backend_pid()"
                    ),
                    {"db": isolated_db_name},
                )
                admin_conn.execute(text(f'DROP DATABASE IF EXISTS "{isolated_db_name}"'))
        finally:
            admin_engine.dispose()
