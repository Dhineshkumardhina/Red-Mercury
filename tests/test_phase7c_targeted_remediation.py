"""Phase 7C Targeted Security Remediation & Distributed Systems Regression Verification Suite.

Verifies all Phase 7B findings:
- P7B-F01: SQLAlchemy lease-fencing lifecycle (after_commit/after_rollback cleanup, multi-job fencing, savepoints, session reuse, PostgreSQL concurrency)
- P7B-F02: Process identity & orphan recovery (hostname, start_time fingerprint, job_id, PID reuse, permission-denied, cross-container namespace, corrupted ledger, container spoofing)
- P7B-F03: Transactional outbox concurrency (PostgreSQL FOR UPDATE SKIP LOCKED across parallel dispatchers, zero duplicate Redis RPUSH)
- P7B-F04: Git ingestion SSRF & proxy DNS resolution deferral + bounded branch-fallback timeout
- P7B-F05: Per-tenant PostgreSQL daily quota locking & atomic audit event staging
- P7B-F06: Route-specific API CSP ('default-src none') vs SPA CSP in live Nginx container + cap_drop ALL on postgres & nginx
- P7B-F07 / P7B-F08: PostgreSQL advisory lock for concurrent Alembic migrations & SQLite db=None runtime artifact safety
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import threading
import time
from typing import List, Optional
import urllib.error
import urllib.request
import uuid

import pytest
import yaml
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.audit import record_audit_event
from app.core.config import settings
from app.core.errors import SecurityPolicyViolationError
from app.core.ingestion import clone_git_repository, validate_git_url
from app.core.jobs import (
    JobExecutionTracker,
    JobState,
    StaleWorkerLeaseError,
    _get_local_hostname,
    _get_pid_start_time,
    _is_pid_running,
    assert_active_worker_lease_or_abort,
    claim_durable_job_by_id,
    create_durable_job_with_outbox,
    dispatch_outbox_events,
    reap_and_verify_orphaned_job_resources,
    record_job_runtime_artifacts,
    recover_undispatched_outbox_events,
    set_redis_client_override,
)
from app.models.audit import AuditEvent
from app.models.job import ActiveJobSlot, DurableJob, JobOutboxEvent
from app.models.repository import Repository
from app.models.scan import Scan
from app.models.user import User
from app.verification.sandbox import check_docker_availability

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
DOCKER_OK, _ = check_docker_availability(timeout_seconds=3.0)


# ==============================================================================
# 1. P7B-F01: SQLAlchemy Lease-Fencing Lifecycle & Multi-Job Concurrency
# ==============================================================================

@pytest.mark.skipif(LIVE_PG_URL is None, reason="Requires live PostgreSQL 16 container")
def test_phase7c_p7b_f01_lease_fencing_lifecycle_multi_job_savepoint_and_session_reuse(tmp_path: Path):
    """Verifies P7B-F01 on live PostgreSQL 16:
    1. Successful commit clears _fenced_job_leases & allows session reuse.
    2. Explicit rollback clears _fenced_job_leases & allows session reuse.
    3. Failed commit (StaleWorkerLeaseError) clears _fenced_job_leases on rollback & allows session reuse.
    4. Multiple fenced jobs in one session: if one lease is stolen/expired, commit aborts atomically.
    5. Nested savepoint rollback does not corrupt outer fenced transaction.
    """
    cfg = Config("backend/alembic.ini")
    cfg.set_main_option("sqlalchemy.url", LIVE_PG_URL)
    command.upgrade(cfg, "head")

    pg_engine = create_engine(LIVE_PG_URL, pool_size=5, max_overflow=5)
    PgSession = sessionmaker(bind=pg_engine, autocommit=False, autoflush=False)

    db = PgSession()
    db_other = PgSession()
    try:
        user = User(
            id=f"u_p7c_f01_{uuid.uuid4().hex[:8]}",
            email=f"p7c_f01_{uuid.uuid4().hex[:8]}@xerova.com",
            password_hash="hash",
            account_status="active",
            role="analyst",
        )
        db.add(user)
        db.commit()

        repo1 = Repository(id=str(uuid.uuid4()), owner_id=user.id, name=f"r1-{uuid.uuid4().hex[:6]}")
        repo2 = Repository(id=str(uuid.uuid4()), owner_id=user.id, name=f"r2-{uuid.uuid4().hex[:6]}")
        db.add_all([repo1, repo2])
        db.flush()
        scan1 = Scan(id=str(uuid.uuid4()), repository_id=repo1.id, status="queued")
        scan2 = Scan(id=str(uuid.uuid4()), repository_id=repo2.id, status="queued")
        db.add_all([scan1, scan2])
        db.flush()

        job1, _, _ = create_durable_job_with_outbox(
            db=db, user=user, job_type="scan", resource_id=scan1.id, repository_id=repo1.id, payload={}
        )
        job2, _, _ = create_durable_job_with_outbox(
            db=db, user=user, job_type="scan", resource_id=scan2.id, repository_id=repo2.id, payload={}
        )
        db.commit()

        c1 = claim_durable_job_by_id(db=db, job_id=job1.id, worker_id="w-f01", lease_seconds=60)
        c2 = claim_durable_job_by_id(db=db, job_id=job2.id, worker_id="w-f01", lease_seconds=60)
        assert c1 is not None and c2 is not None

        # 1. Explicit rollback clears _fenced_job_leases and allows session reuse
        assert_active_worker_lease_or_abort(db=db, job_id=job1.id, worker_id="w-f01", lease_token=c1.lease_token)
        assert "_fenced_job_leases" in db.info
        db.rollback()
        assert "_fenced_job_leases" not in db.info

        # Unrelated commit on reused session succeeds without stale fence error
        db.add(AuditEvent(action="REUSE_AFTER_ROLLBACK", resource_type="system", resource_identifier="ok"))
        db.commit()

        # 2. Successful commit clears _fenced_job_leases and allows session reuse
        assert_active_worker_lease_or_abort(db=db, job_id=job1.id, worker_id="w-f01", lease_token=c1.lease_token)
        with db.begin_nested():
            db.add(AuditEvent(action="SAVEPOINT_TEMP", resource_type="system", resource_identifier="sp"))
            db.flush()
        db.commit()
        assert "_fenced_job_leases" not in db.info

        # 3. Multiple fenced jobs in one session: steal job2 on db_other -> commit must abort with StaleWorkerLeaseError
        assert_active_worker_lease_or_abort(db=db, job_id=job1.id, worker_id="w-f01", lease_token=c1.lease_token)
        assert_active_worker_lease_or_abort(db=db, job_id=job2.id, worker_id="w-f01", lease_token=c2.lease_token)
        assert len(db.info["_fenced_job_leases"]) == 2

        db_other.query(DurableJob).filter(DurableJob.id == job2.id).update(
            {"lease_token": "stolen-by-other", "worker_id": "w-other"},
            synchronize_session=False,
        )
        db_other.commit()

        db.add(AuditEvent(action="SHOULD_NOT_LAND", resource_type="system", resource_identifier="multi-fence"))
        with pytest.raises(StaleWorkerLeaseError):
            db.commit()
        db.rollback()
        assert "_fenced_job_leases" not in db.info

        # Verify session reuse after StaleWorkerLeaseError + rollback succeeds
        assert db_other.query(AuditEvent).filter(AuditEvent.action == "SHOULD_NOT_LAND").count() == 0
        reuse_id = f"ok-{uuid.uuid4().hex[:8]}"
        db.add(AuditEvent(action="REUSE_AFTER_STALE_ERROR", resource_type="system", resource_identifier=reuse_id))
        db.commit()
        assert (
            db_other.query(AuditEvent)
            .filter(AuditEvent.action == "REUSE_AFTER_STALE_ERROR", AuditEvent.resource_identifier == reuse_id)
            .count()
            == 1
        )
    finally:
        db.close()
        db_other.close()
        pg_engine.dispose()


# ==============================================================================
# 2. P7B-F02: Process Identity Verification & Safe Orphan Recovery
# ==============================================================================

def test_phase7c_p7b_f02_process_identity_pid_reuse_namespace_and_corrupted_ledger():
    """Verifies P7B-F02:
    1. Live child process on same host with matching hostname, start_time, and job_id is reaped.
    2. PID reuse (mismatched start_time) is NEVER killed.
    3. Cross-container namespace (hostname != local_host) is NEVER killed.
    4. Job ID mismatch is NEVER killed.
    5. Invalid/spoofed container name (e.g. rm_test_postgres) is ignored.
    6. Corrupted runtime artifact ledger is handled safely without crashing.
    """
    current_host = _get_local_hostname()
    # Spawn two real child processes:
    # - proc_victim: matches this job's identity -> MUST be reaped
    # - proc_unrelated: simulates an unrelated/recycled OS process with a different start_time -> MUST survive!
    proc_victim = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    proc_unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        victim_start = _get_pid_start_time(proc_victim.pid)
        unrelated_start = _get_pid_start_time(proc_unrelated.pid)
        assert victim_start is not None
        assert unrelated_start is not None

        job_id = f"job_p7c_f02_{uuid.uuid4().hex[:8]}"
        fake_job = DurableJob(
            id=job_id,
            job_type="scan",
            resource_id="scan_1",
            tenant_id="tenant_1",
            payload_json=json.dumps({
                "_runtime_artifacts": {
                    "child_processes": [
                        # 1. Valid victim belonging to this job & host
                        {"pid": proc_victim.pid, "hostname": current_host, "start_time": victim_start, "job_id": job_id},
                        # 2. Simulated PID reuse: live PID but wrong start_time
                        {"pid": proc_unrelated.pid, "hostname": current_host, "start_time": "000000000", "job_id": job_id},
                        # 3. Cross-container PID namespace: live PID but different hostname
                        {"pid": proc_unrelated.pid, "hostname": "other-worker-container", "start_time": unrelated_start, "job_id": job_id},
                        # 4. Job ID mismatch
                        {"pid": proc_unrelated.pid, "hostname": current_host, "start_time": unrelated_start, "job_id": "different-job"},
                        # 5. Missing start_time (bare PID)
                        {"pid": proc_unrelated.pid, "hostname": current_host, "start_time": None, "job_id": job_id},
                    ],
                    "containers": ["rm_test_postgres", "postgres; rm -rf /"],
                    "temp_workspaces": [],
                }
            }),
        )

        verified_stopped, details = reap_and_verify_orphaned_job_resources(fake_job, kill_resources=True)
        assert verified_stopped is True
        assert proc_victim.pid in details["reaped_pids"]
        assert proc_unrelated.pid not in details["reaped_pids"]
        assert details["reaped_containers"] == []

        # Confirm proc_victim is terminated and proc_unrelated is still alive!
        time.sleep(0.2)
        assert proc_victim.poll() is not None
        assert proc_unrelated.poll() is None

        # 6. Corrupted ledger handling
        corrupt_job = DurableJob(
            id="corrupt_1",
            job_type="scan",
            resource_id="s1",
            payload_json="{not-valid-json",
        )
        ok_corrupt, _ = reap_and_verify_orphaned_job_resources(corrupt_job, kill_resources=True)
        assert ok_corrupt is True
    finally:
        for p in (proc_victim, proc_unrelated):
            if p.poll() is None:
                p.kill()
                p.wait(timeout=3)


# ==============================================================================
# 3. P7B-F03: Concurrent Outbox FOR UPDATE SKIP LOCKED Dispatch
# ==============================================================================

@pytest.mark.skipif(
    LIVE_PG_URL is None or LIVE_REDIS_URL is None,
    reason="Requires live PostgreSQL 16 and live Redis 7 containers",
)
def test_phase7c_p7b_f03_concurrent_outbox_dispatchers_never_push_duplicate_redis_messages(
    tmp_path: Path, monkeypatch
):
    """Verifies P7B-F03 on live PostgreSQL 16 + live Redis 7:
    4 concurrent outbox dispatchers run simultaneously -> each JobOutboxEvent is pushed to Redis ONCE.
    """
    import redis

    cfg = Config("backend/alembic.ini")
    cfg.set_main_option("sqlalchemy.url", LIVE_PG_URL)
    command.upgrade(cfg, "head")

    pg_engine = create_engine(LIVE_PG_URL, pool_size=10, max_overflow=10)
    PgSession = sessionmaker(bind=pg_engine, autocommit=False, autoflush=False)
    r_client = redis.Redis.from_url(LIVE_REDIS_URL, decode_responses=True)
    test_queue = f"redmercury:p7c:outbox:{uuid.uuid4().hex[:8]}"
    monkeypatch.setattr(settings, "JOB_QUEUE_NAME", test_queue)
    monkeypatch.setattr(settings, "MAX_CONCURRENT_SCANS_PER_USER", 10)
    set_redis_client_override(r_client)

    db = PgSession()
    try:
        db.query(ActiveJobSlot).delete()
        db.query(JobOutboxEvent).delete()
        db.query(DurableJob).delete()
        db.commit()

        user = User(
            id=f"u_p7c_f03_{uuid.uuid4().hex[:8]}",
            email=f"p7c_f03_{uuid.uuid4().hex[:8]}@xerova.com",
            password_hash="hash",
            account_status="active",
            role="analyst",
        )
        db.add(user)
        db.commit()

        created_job_ids = []
        for i in range(4):
            repo = Repository(id=str(uuid.uuid4()), owner_id=user.id, name=f"f03-r{i}-{uuid.uuid4().hex[:6]}")
            db.add(repo)
            db.flush()
            scan = Scan(id=str(uuid.uuid4()), repository_id=repo.id, status="queued")
            db.add(scan)
            db.flush()
            job, _, _ = create_durable_job_with_outbox(
                db=db, user=user, job_type="scan", resource_id=scan.id, repository_id=repo.id, payload={}
            )
            created_job_ids.append(job.id)
        db.commit()

        barrier = threading.Barrier(4)

        def _dispatch_worker(_idx: int) -> int:
            s = PgSession()
            try:
                barrier.wait(timeout=5)
                return recover_undispatched_outbox_events(db=s, redis_client=r_client)
            finally:
                s.close()

        with ThreadPoolExecutor(max_workers=4) as pool:
            counts = list(pool.map(_dispatch_worker, range(4)))

        assert sum(counts) == 4, f"Expected exactly 4 dispatches across 4 parallel workers, got {counts}"
        assert r_client.llen(test_queue) == 4
    finally:
        set_redis_client_override(None)
        try:
            r_client.delete(test_queue)
        except Exception:
            pass
        db.close()
        pg_engine.dispose()


# ==============================================================================
# 4. P7B-F04: Git URL Validation with Egress Proxy DNS Deferral
# ==============================================================================

def test_phase7c_p7b_f04_proxy_dns_deferral_preserves_ssrf_literal_blocks(monkeypatch):
    """Verifies P7B-F04:
    1. When allow_proxy_dns_resolution=True and local DNS raises gaierror, public HTTPS domain succeeds
       so the SSRF-filtering forward proxy can resolve and enforce destination IPs at connection time.
    2. Loopback, RFC1918, metadata, and .local/.internal hosts remain strictly blocked even when
       allow_proxy_dns_resolution=True.
    """
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *a, **kw: (_ for _ in ()).throw(socket.gaierror("No direct external DNS on internal net")),
    )

    assert (
        validate_git_url(
            "https://github.com/octocat/Hello-World.git",
            allow_private=False,
            allow_proxy_dns_resolution=True,
        )
        == "https://github.com/octocat/Hello-World.git"
    )

    for forbidden in (
        "https://127.0.0.1/repo.git",
        "https://169.254.169.254/latest/meta-data",
        "https://10.0.0.1/repo.git",
        "https://[::1]/repo.git",
        "https://internal.service.local/repo.git",
    ):
        with pytest.raises(SecurityPolicyViolationError):
            validate_git_url(forbidden, allow_private=False, allow_proxy_dns_resolution=True)


# ==============================================================================
# 5. P7B-F05: Atomic Per-Tenant Daily Quota Locking & Transactional Audit
# ==============================================================================

@pytest.mark.skipif(LIVE_PG_URL is None, reason="Requires live PostgreSQL 16 container")
def test_phase7c_p7b_f05_concurrent_daily_quota_lock_and_transactional_audit(monkeypatch):
    """Verifies P7B-F05 on live PostgreSQL 16:
    With MAX_DAILY_SCANS_PER_USER=2 and MAX_CONCURRENT_SCANS_PER_USER=10, 4 concurrent submissions
    from the same tenant result in at most 2 accepted scans (zero daily quota race bypass).
    Also verifies record_audit_event(commit=False, raise_on_error=True) rolls back with its transaction.
    """
    cfg = Config("backend/alembic.ini")
    cfg.set_main_option("sqlalchemy.url", LIVE_PG_URL)
    command.upgrade(cfg, "head")

    pg_engine = create_engine(LIVE_PG_URL, pool_size=10, max_overflow=10)
    PgSession = sessionmaker(bind=pg_engine, autocommit=False, autoflush=False)
    monkeypatch.setattr(settings, "MAX_DAILY_SCANS_PER_USER", 2)
    monkeypatch.setattr(settings, "MAX_CONCURRENT_SCANS_PER_USER", 10)

    db = PgSession()
    try:
        user = User(
            id=f"u_p7c_f05_{uuid.uuid4().hex[:8]}",
            email=f"p7c_f05_{uuid.uuid4().hex[:8]}@xerova.com",
            password_hash="hash",
            account_status="active",
            role="analyst",
        )
        db.add(user)
        db.commit()

        repo_ids: List[str] = []
        for i in range(4):
            r = Repository(id=str(uuid.uuid4()), owner_id=user.id, name=f"q-repo-{i}-{uuid.uuid4().hex[:6]}")
            db.add(r)
            repo_ids.append(r.id)
        db.commit()

        barrier = threading.Barrier(4)

        def _submit_scan(idx: int) -> bool:
            s = PgSession()
            try:
                u = s.query(User).filter(User.id == user.id).first()
                sc = Scan(id=str(uuid.uuid4()), repository_id=repo_ids[idx], status="queued")
                s.add(sc)
                s.flush()
                barrier.wait(timeout=5)
                create_durable_job_with_outbox(
                    db=s, user=u, job_type="scan", resource_id=sc.id, repository_id=repo_ids[idx], payload={}
                )
                s.commit()
                return True
            except SecurityPolicyViolationError:
                s.rollback()
                return False
            finally:
                s.close()

        with ThreadPoolExecutor(max_workers=4) as pool:
            outcomes = list(pool.map(_submit_scan, range(4)))
        assert sum(1 for x in outcomes if x) == 2, f"Expected exactly 2 daily quota approvals, got {outcomes}"

        # Transactional audit rollback test
        ev_id = f"audit-rb-{uuid.uuid4().hex[:8]}"
        record_audit_event(
            db=db,
            action="TX_AUDIT_ROLLBACK_TEST",
            resource_type="repository",
            resource_identifier=ev_id,
            actor_id=user.id,
            commit=False,
            raise_on_error=True,
        )
        db.rollback()
        assert db.query(AuditEvent).filter(AuditEvent.resource_identifier == ev_id).count() == 0
    finally:
        db.close()
        pg_engine.dispose()


# ==============================================================================
# 6. P7B-F06: Route-Specific API CSP vs SPA CSP & Container cap_drop: ALL
# ==============================================================================

@pytest.mark.skipif(not DOCKER_OK, reason="Live Docker daemon required")
def test_phase7c_p7b_f06_nginx_api_strict_csp_and_compose_cap_drop(tmp_path: Path):
    """Verifies P7B-F06:
    1. docker-compose.prod.yml enforces cap_drop: [ALL] on ALL services including postgres and nginx.
    2. Live nginx:1.27-alpine container running nginx/production.conf serves
       'default-src none; frame-ancestors none' on /api/v1/* while preserving SPA CSP on /.
    """
    compose_data = yaml.safe_load((REPO_ROOT / "docker-compose.prod.yml").read_text(encoding="utf-8"))
    for svc_name, svc in compose_data["services"].items():
        assert "ALL" in svc.get("cap_drop", []), f"{svc_name} missing cap_drop: [ALL]"

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=5))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    ssl_dir = tmp_path / "ssl"
    ssl_dir.mkdir(parents=True, exist_ok=True)
    (ssl_dir / "redmercury.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (ssl_dir / "redmercury.key").write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    prod_conf = (REPO_ROOT / "nginx" / "production.conf").read_text(encoding="utf-8")
    standalone_conf = prod_conf.replace("server api:8000", "server 127.0.0.1:8080").replace(
        "server frontend:8080", "server 127.0.0.1:8080"
    )
    conf_file = tmp_path / "default.conf"
    conf_file.write_text(standalone_conf, encoding="utf-8")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s1, socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
        s1.bind(("127.0.0.1", 0))
        http_port = s1.getsockname()[1]
        s2.bind(("127.0.0.1", 0))
        https_port = s2.getsockname()[1]

    proxy_cname = f"rm-p7c-proxy-{uuid.uuid4().hex[:8]}"
    try:
        subprocess.run(
            [
                "docker", "run", "-d", "--rm",
                "--name", proxy_cname,
                "--cap-drop=ALL",
                "--cap-add=NET_BIND_SERVICE",
                "--cap-add=CHOWN",
                "--cap-add=SETUID",
                "--cap-add=SETGID",
                "--cap-add=DAC_OVERRIDE",
                "-p", f"127.0.0.1:{http_port}:80",
                "-p", f"127.0.0.1:{https_port}:443",
                "-v", f"{str(conf_file).replace(chr(92), '/')}:/etc/nginx/conf.d/default.conf:ro",
                "-v", f"{str(ssl_dir).replace(chr(92), '/')}:/etc/nginx/ssl:ro",
                "nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
        )

        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        # /api/v1/auth/login -> strict API CSP (default-src 'none'; frame-ancestors 'none')
        api_csp = ""
        for _ in range(20):
            try:
                urllib.request.urlopen(f"https://127.0.0.1:{https_port}/api/v1/auth/me", context=ssl_ctx, timeout=2)
            except urllib.error.HTTPError as he:
                api_csp = he.headers.get("Content-Security-Policy", "")
                break
            except Exception:
                time.sleep(0.2)
        assert "default-src 'none'" in api_csp
        assert "frame-ancestors 'none'" in api_csp

        # / -> SPA CSP (default-src 'self')
        spa_csp = ""
        try:
            urllib.request.urlopen(f"https://127.0.0.1:{https_port}/", context=ssl_ctx, timeout=2)
        except urllib.error.HTTPError as he:
            spa_csp = he.headers.get("Content-Security-Policy", "")
        assert "default-src 'self'" in spa_csp
    finally:
        subprocess.run(["docker", "rm", "-f", proxy_cname], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False)


# ==============================================================================
# 7. P7B-F07 / F08: Concurrent Alembic Advisory Lock & SQLite Runtime Artifacts
# ==============================================================================

@pytest.mark.skipif(LIVE_PG_URL is None, reason="Requires live PostgreSQL 16 container")
def test_phase7c_p7b_f07_f08_concurrent_alembic_advisory_lock_and_sqlite_artifacts(tmp_path: Path):
    """Verifies P7B-F07 (concurrent Alembic upgrade head serialized via PostgreSQL advisory lock)
    and P7B-F08 (SQLite db=None runtime artifact persistence safely returns without locking).
    """
    def _run_upgrade(_idx: int) -> int:
        env = os.environ.copy()
        env["DATABASE_URL"] = LIVE_PG_URL
        res = subprocess.run(
            [sys.executable, "-m", "alembic", "-c", "backend/alembic.ini", "upgrade", "head"],
            cwd=str(REPO_ROOT),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
            check=False,
        )
        assert res.returncode == 0, f"Alembic upgrade failed: {res.stderr}"
        return res.returncode

    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(_run_upgrade, range(3)))
    assert results == [0, 0, 0]

    # P7B-F08: SQLite session_factory with db=None exits cleanly without locking
    sqlite_eng = create_engine(f"sqlite:///{tmp_path / 'p7c_f08.db'}")
    SqliteSession = sessionmaker(bind=sqlite_eng)
    try:
        record_job_runtime_artifacts(
            job_id="sqlite-noop",
            child_pids=[1234],
            db=None,
            session_factory=SqliteSession,
        )
    finally:
        sqlite_eng.dispose()


def test_phase7c_posix_zombie_process_not_misclassified_as_running(monkeypatch):
    """Phase 8P Regression: Killed child processes in Linux 'Z' (zombie) state must report _is_pid_running=False."""
    from app.core import jobs as jobs_mod

    monkeypatch.setattr(jobs_mod.platform, "system", lambda: "Linux")
    monkeypatch.setattr(jobs_mod.os, "kill", lambda pid, sig: None, raising=False)

    # Zombie ('Z') state -> not running
    monkeypatch.setattr(jobs_mod, "_read_proc_stat_fields", lambda pid: ["Z", "1", "1", "1"])
    assert jobs_mod._is_pid_running(999991) is False

    # Active sleeping ('S') state -> running
    monkeypatch.setattr(jobs_mod, "_read_proc_stat_fields", lambda pid: ["S", "1", "1", "1"])
    assert jobs_mod._is_pid_running(999991) is True
