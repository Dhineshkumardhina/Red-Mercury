"""Phase 7G Targeted Lease-Fencing Cleanup Isolation & Regression Suite (P7F-F01).

Verifies all 10 mandatory scenarios A through J on live PostgreSQL 16:
- A: Outer transaction fences Job A; helper transitions Job B; Job A remains fenced.
- B: Outer transaction fences Job A and Job B; cleanup of Job A preserves Job B.
- C: Nested savepoint owns Job B; cleanup of Job A does not remove Job B.
- D: Nested savepoint rollback still removes only registrations introduced inside that savepoint.
- E: Nested savepoint commit still promotes its registrations to the parent transaction.
- F: Stale Job A lease still rejects outer commit after unrelated Job B cleanup.
- G: Session reuse after successful commit, rollback, and stale-worker rejection.
- H: record_job_runtime_artifacts() cannot silently remove an unrelated active transaction's fencing protection.
- I: Lifecycle helpers operating on dedicated sessions retain their existing behavior.
- J: Full outer transaction cleanup removes all remaining registrations.
"""
import os
from typing import Optional
import uuid

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.core.jobs import (
    StaleWorkerLeaseError,
    _clear_fenced_leases_for_job,
    assert_active_worker_lease_or_abort,
    claim_durable_job_by_id,
    complete_claimed_job,
    create_durable_job_with_outbox,
    get_job_operational_metrics,
    record_job_runtime_artifacts,
    recover_expired_job_leases,
)
from app.models.audit import AuditEvent
from app.models.job import DurableJob
from app.models.repository import Repository
from app.models.scan import Scan
from app.models.user import User


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


LIVE_PG_URL = _probe_live_postgres()


@pytest.mark.skipif(LIVE_PG_URL is None, reason="Requires live PostgreSQL 16 container")
def test_phase7g_all_ten_cleanup_isolation_scenarios_on_live_postgres():
    """Executes Scenarios A through J against live PostgreSQL 16."""
    cfg = Config("backend/alembic.ini")
    cfg.set_main_option("sqlalchemy.url", LIVE_PG_URL)
    command.upgrade(cfg, "head")

    pg_engine = create_engine(LIVE_PG_URL, pool_size=5, max_overflow=5)
    PgSession = sessionmaker(bind=pg_engine, autocommit=False, autoflush=False)

    db = PgSession()
    db_other = PgSession()
    db_dedicated = PgSession()
    try:
        u = User(
            id=f"u_7g_{uuid.uuid4().hex[:8]}",
            email=f"u7g_{uuid.uuid4().hex[:8]}@xerova.com",
            password_hash="hash",
            account_status="active",
            role="analyst",
        )
        db.add(u)
        db.commit()

        r1 = Repository(id=str(uuid.uuid4()), owner_id=u.id, name=f"r1-{uuid.uuid4().hex[:6]}")
        r2 = Repository(id=str(uuid.uuid4()), owner_id=u.id, name=f"r2-{uuid.uuid4().hex[:6]}")
        r3 = Repository(id=str(uuid.uuid4()), owner_id=u.id, name=f"r3-{uuid.uuid4().hex[:6]}")
        db.add_all([r1, r2, r3])
        db.flush()

        s1 = Scan(id=str(uuid.uuid4()), repository_id=r1.id, status="queued")
        s2 = Scan(id=str(uuid.uuid4()), repository_id=r2.id, status="queued")
        s3 = Scan(id=str(uuid.uuid4()), repository_id=r3.id, status="queued")
        db.add_all([s1, s2, s3])
        db.flush()

        j1, _, _ = create_durable_job_with_outbox(db=db, user=u, job_type="scan", resource_id=s1.id, repository_id=r1.id, payload={})
        j2, _, _ = create_durable_job_with_outbox(db=db, user=u, job_type="scan", resource_id=s2.id, repository_id=r2.id, payload={})
        j3, _, _ = create_durable_job_with_outbox(db=db, user=u, job_type="scan", resource_id=s3.id, repository_id=r3.id, payload={})
        db.commit()

        c1 = claim_durable_job_by_id(db=db, job_id=j1.id, worker_id="w-7g", lease_seconds=60)
        c2 = claim_durable_job_by_id(db=db, job_id=j2.id, worker_id="w-7g", lease_seconds=60)
        c3 = claim_durable_job_by_id(db=db, job_id=j3.id, worker_id="w-7g", lease_seconds=60)
        assert c1 is not None and c2 is not None and c3 is not None

        # Clean up any leftover expired jobs from prior test suites before starting Scenario A
        recover_expired_job_leases(db=db_dedicated)

        # ------------------------------------------------------------------
        # Scenario A & F: Outer tx fences Job A; helper/cleanup transitions Job B;
        # Job A remains fenced & stale Job A rejects outer commit!
        # ------------------------------------------------------------------
        assert_active_worker_lease_or_abort(db=db, job_id=c1.id, worker_id="w-7g", lease_token=c1.lease_token)
        assert len(db.info["_fenced_job_leases"]) == 1

        # Calling recover_expired_job_leases(db=db) when no expired jobs exist does not commit or wipe Job A
        recover_expired_job_leases(db=db)
        assert len(db.info.get("_fenced_job_leases", set())) == 1
        assert (c1.id, "w-7g", c1.lease_token) in db.info["_fenced_job_leases"]

        # Job-specific cleanup of unrelated Job B preserves Job A's fence on db
        _clear_fenced_leases_for_job(db, c2.id)
        assert (c1.id, "w-7g", c1.lease_token) in db.info["_fenced_job_leases"]

        # Read-only metrics on same session also preserves Job A's fence
        get_job_operational_metrics(db=db)
        assert (c1.id, "w-7g", c1.lease_token) in db.info["_fenced_job_leases"]

        # Scenario H: record_job_runtime_artifacts() on same session cannot remove Job A's fence
        record_job_runtime_artifacts(job_id=c2.id, child_pids=[99999], db=db)
        assert (c1.id, "w-7g", c1.lease_token) in db.info["_fenced_job_leases"]

        # Scenario F: Steal Job A -> outer commit MUST reject with StaleWorkerLeaseError!
        db_other.query(DurableJob).filter(DurableJob.id == c1.id).update({"lease_token": "stolen-7g-A"}, synchronize_session=False)
        db_other.commit()
        marker_f = f"f7g-{uuid.uuid4().hex[:8]}"
        db.add(AuditEvent(action="P7G_STALE_A", resource_type="system", resource_identifier=marker_f))
        with pytest.raises(StaleWorkerLeaseError):
            db.commit()
        db.rollback()
        assert db_other.query(AuditEvent).filter(AuditEvent.resource_identifier == marker_f).count() == 0
        # Restore c1 lease token
        db_other.query(DurableJob).filter(DurableJob.id == c1.id).update({"lease_token": c1.lease_token}, synchronize_session=False)
        db_other.commit()

        # ------------------------------------------------------------------
        # Scenario B: Outer tx fences Job A and Job B; cleanup of Job A preserves Job B
        # ------------------------------------------------------------------
        assert_active_worker_lease_or_abort(db=db, job_id=c1.id, worker_id="w-7g", lease_token=c1.lease_token)
        assert_active_worker_lease_or_abort(db=db, job_id=c2.id, worker_id="w-7g", lease_token=c2.lease_token)
        assert len(db.info["_fenced_job_leases"]) == 2
        _clear_fenced_leases_for_job(db, c1.id)
        assert len(db.info["_fenced_job_leases"]) == 1
        assert (c2.id, "w-7g", c2.lease_token) in db.info["_fenced_job_leases"]
        db.rollback()
        assert "_fenced_job_leases" not in db.info

        # ------------------------------------------------------------------
        # Scenario C, D, E, J: Nested savepoint owns Job B; cleanup of Job A preserves Job B;
        # nested rollback removes only SP; nested commit promotes to outer; outer commit cleans all!
        # ------------------------------------------------------------------
        assert_active_worker_lease_or_abort(db=db, job_id=c1.id, worker_id="w-7g", lease_token=c1.lease_token)
        with db.begin_nested():
            assert_active_worker_lease_or_abort(db=db, job_id=c2.id, worker_id="w-7g", lease_token=c2.lease_token)
            # Cleanup of Job A does NOT remove Job B inside nested savepoint
            _clear_fenced_leases_for_job(db, c1.id)
            assert (c2.id, "w-7g", c2.lease_token) in db.info["_fenced_job_leases"]
            assert (c1.id, "w-7g", c1.lease_token) not in db.info["_fenced_job_leases"]
        # Scenario E: Savepoint committed -> Job B promoted to outer tx
        assert (c2.id, "w-7g", c2.lease_token) in db.info["_fenced_job_leases"]

        # Scenario D: Nested savepoint with Job C rolled back -> Job B preserved, Job C removed
        try:
            with db.begin_nested():
                assert_active_worker_lease_or_abort(db=db, job_id=c3.id, worker_id="w-7g", lease_token=c3.lease_token)
                assert len(db.info["_fenced_job_leases"]) == 2
                raise RuntimeError("sp rollback")
        except RuntimeError:
            pass
        assert len(db.info["_fenced_job_leases"]) == 1
        assert (c2.id, "w-7g", c2.lease_token) in db.info["_fenced_job_leases"]

        # Scenario J: Outer commit clears all remaining registrations
        db.commit()
        assert "_fenced_job_leases" not in db.info
        assert "_fenced_leases_by_tx" not in db.info

        # ------------------------------------------------------------------
        # Scenario G & I: Session reuse & lifecycle helper on dedicated session
        # ------------------------------------------------------------------
        reuse_marker = f"reuse7g-{uuid.uuid4().hex[:8]}"
        db.add(AuditEvent(action="P7G_REUSE", resource_type="system", resource_identifier=reuse_marker))
        db.commit()
        assert db_other.query(AuditEvent).filter(AuditEvent.resource_identifier == reuse_marker).count() == 1

        # Dedicated session complete_claimed_job works identically
        done_c3 = complete_claimed_job(db=db_dedicated, job_id=c3.id, worker_id="w-7g", lease_token=c3.lease_token)
        assert done_c3.status == "completed"
        assert "_fenced_job_leases" not in db_dedicated.info
    finally:
        db.close()
        db_other.close()
        db_dedicated.close()
        pg_engine.dispose()
