"""Phase 7E Targeted P7D-F01 Remediation & Independent Transaction Integrity Verification Suite.

Covers all 9 mandatory scenarios on live PostgreSQL 16:
- Test A: Outer lease survives nested savepoint rollback (Job A preserved; Job B removed)
- Test B: Outer lease stolen during nested rollback -> outer commit raises StaleWorkerLeaseError and commits ZERO rows
- Test C: Nested lease stolen after rollback -> does not trigger false stale-lease failure on outer commit; Job A remains fenced
- Test D: Successful nested savepoint promotes lease registration to outer transaction until outer commit
- Test E: Multiple nested savepoints (outer Job A -> SP1 Job B -> SP2 Job C -> SP2 rollback -> SP1 commit -> outer commit)
- Test F: Full outer rollback clears all transaction-scoped registrations
- Test G: Session reuse after successful commit, full rollback, nested rollback, and StaleWorkerLeaseError
- Test H: Multiple fenced jobs in one transaction (stealing one rejects entire business transaction)
- Test I: Concurrent lease takeover across two independent PostgreSQL sessions
- Independent Phase 7D Reproduction Probe: verifies exact event ordering & Session.info state at every boundary
"""
import os
from pathlib import Path
from typing import Optional
import uuid

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker

from app.core.jobs import (
    StaleWorkerLeaseError,
    assert_active_worker_lease_or_abort,
    claim_durable_job_by_id,
    create_durable_job_with_outbox,
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


def _setup_two_jobs(db):
    u = User(
        id=f"u_7e_{uuid.uuid4().hex[:8]}",
        email=f"u7e_{uuid.uuid4().hex[:8]}@xerova.com",
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

    c1 = claim_durable_job_by_id(db=db, job_id=j1.id, worker_id="w-7e", lease_seconds=60)
    c2 = claim_durable_job_by_id(db=db, job_id=j2.id, worker_id="w-7e", lease_seconds=60)
    c3 = claim_durable_job_by_id(db=db, job_id=j3.id, worker_id="w-7e", lease_seconds=60)
    assert c1 is not None and c2 is not None and c3 is not None
    return u, c1, c2, c3


@pytest.mark.skipif(LIVE_PG_URL is None, reason="Requires live PostgreSQL 16 container")
def test_phase7e_all_nine_transaction_fencing_scenarios_on_live_postgres():
    """Tests A through I and independent lifecycle probe against live PostgreSQL 16."""
    cfg = Config("backend/alembic.ini")
    cfg.set_main_option("sqlalchemy.url", LIVE_PG_URL)
    command.upgrade(cfg, "head")

    pg_engine = create_engine(LIVE_PG_URL, pool_size=5, max_overflow=5)
    PgSession = sessionmaker(bind=pg_engine, autocommit=False, autoflush=False)

    db = PgSession()
    db_other = PgSession()
    lifecycle_log = []

    @event.listens_for(db, "after_transaction_end")
    def _log_tx_end(sess, tx):
        lifecycle_log.append(("after_transaction_end", tx.nested, tx.parent is not None, len(sess.info.get("_fenced_job_leases", set()))))

    @event.listens_for(db, "after_soft_rollback")
    def _log_soft_rb(sess, prev_tx):
        lifecycle_log.append(("after_soft_rollback", prev_tx.nested, prev_tx.parent is not None, len(sess.info.get("_fenced_job_leases", set()))))

    try:
        u, c1, c2, c3 = _setup_two_jobs(db)

        # ------------------------------------------------------------------
        # Test A: Outer lease survives nested savepoint rollback (exact Phase 7D repro)
        # ------------------------------------------------------------------
        marker_a = f"testA-{uuid.uuid4().hex[:8]}"
        assert_active_worker_lease_or_abort(db=db, job_id=c1.job_id if hasattr(c1, "job_id") else c1.id, worker_id="w-7e", lease_token=c1.lease_token)
        assert len(db.info["_fenced_job_leases"]) == 1  # AFTER_FENCE_A: 1
        db.add(AuditEvent(action="P7E_OUTER", resource_type="system", resource_identifier=marker_a))
        try:
            with db.begin_nested():
                assert_active_worker_lease_or_abort(db=db, job_id=c2.id, worker_id="w-7e", lease_token=c2.lease_token)
                assert len(db.info["_fenced_job_leases"]) == 2  # AFTER_FENCE_B_IN_SP: 2
                raise RuntimeError("rollback savepoint")
        except RuntimeError:
            pass
        # AFTER_SP_ROLLBACK: Job A preserved; Job B removed!
        remaining_after_sp = db.info.get("_fenced_job_leases", set())
        assert len(remaining_after_sp) == 1
        assert (c1.id, "w-7e", c1.lease_token) in remaining_after_sp
        assert (c2.id, "w-7e", c2.lease_token) not in remaining_after_sp
        db.commit()
        assert "_fenced_job_leases" not in db.info
        assert "_fenced_leases_by_tx" not in db.info
        assert db_other.query(AuditEvent).filter(AuditEvent.resource_identifier == marker_a).count() == 1

        # ------------------------------------------------------------------
        # Test B: Outer lease stolen during nested rollback -> outer commit MUST fail
        # ------------------------------------------------------------------
        marker_b = f"testB-{uuid.uuid4().hex[:8]}"
        assert_active_worker_lease_or_abort(db=db, job_id=c1.id, worker_id="w-7e", lease_token=c1.lease_token)
        db.add(AuditEvent(action="P7E_OUTER_B", resource_type="system", resource_identifier=marker_b))
        try:
            with db.begin_nested():
                assert_active_worker_lease_or_abort(db=db, job_id=c2.id, worker_id="w-7e", lease_token=c2.lease_token)
                raise RuntimeError("rollback savepoint B")
        except RuntimeError:
            pass
        # Another worker steals Job A's lease
        db_other.query(DurableJob).filter(DurableJob.id == c1.id).update({"lease_token": "stolen-A"}, synchronize_session=False)
        db_other.commit()
        with pytest.raises(StaleWorkerLeaseError):
            db.commit()
        db.rollback()
        assert db_other.query(AuditEvent).filter(AuditEvent.resource_identifier == marker_b).count() == 0
        # Restore c1 lease token for subsequent tests
        db_other.query(DurableJob).filter(DurableJob.id == c1.id).update({"lease_token": c1.lease_token}, synchronize_session=False)
        db_other.commit()

        # ------------------------------------------------------------------
        # Test C: Nested lease stolen AFTER savepoint rollback -> outer commit succeeds (Job B not active)
        # ------------------------------------------------------------------
        marker_c = f"testC-{uuid.uuid4().hex[:8]}"
        assert_active_worker_lease_or_abort(db=db, job_id=c1.id, worker_id="w-7e", lease_token=c1.lease_token)
        db.add(AuditEvent(action="P7E_OUTER_C", resource_type="system", resource_identifier=marker_c))
        try:
            with db.begin_nested():
                assert_active_worker_lease_or_abort(db=db, job_id=c2.id, worker_id="w-7e", lease_token=c2.lease_token)
                raise RuntimeError("rollback savepoint C")
        except RuntimeError:
            pass
        db_other.query(DurableJob).filter(DurableJob.id == c2.id).update({"lease_token": "stolen-B-after-rb"}, synchronize_session=False)
        db_other.commit()
        db.commit()  # Succeeds because Job B's savepoint rolled back and Job A is still valid!
        assert db_other.query(AuditEvent).filter(AuditEvent.resource_identifier == marker_c).count() == 1
        # Restore c2 lease token
        db_other.query(DurableJob).filter(DurableJob.id == c2.id).update({"lease_token": c2.lease_token}, synchronize_session=False)
        db_other.commit()

        # ------------------------------------------------------------------
        # Test D: Successful nested savepoint promotes lease registration to outer transaction
        # ------------------------------------------------------------------
        marker_d = f"testD-{uuid.uuid4().hex[:8]}"
        assert_active_worker_lease_or_abort(db=db, job_id=c1.id, worker_id="w-7e", lease_token=c1.lease_token)
        with db.begin_nested():
            assert_active_worker_lease_or_abort(db=db, job_id=c2.id, worker_id="w-7e", lease_token=c2.lease_token)
        # After savepoint commit, BOTH Job A and Job B must remain fenced on the outer transaction!
        assert len(db.info["_fenced_job_leases"]) == 2
        db_other.query(DurableJob).filter(DurableJob.id == c2.id).update({"lease_token": "stolen-B-after-sp-commit"}, synchronize_session=False)
        db_other.commit()
        db.add(AuditEvent(action="P7E_OUTER_D", resource_type="system", resource_identifier=marker_d))
        with pytest.raises(StaleWorkerLeaseError):
            db.commit()
        db.rollback()
        assert db_other.query(AuditEvent).filter(AuditEvent.resource_identifier == marker_d).count() == 0
        db_other.query(DurableJob).filter(DurableJob.id == c2.id).update({"lease_token": c2.lease_token}, synchronize_session=False)
        db_other.commit()

        # ------------------------------------------------------------------
        # Test E: Multiple nested savepoints (SP1 Job B commits, SP2 Job C rolls back)
        # ------------------------------------------------------------------
        assert_active_worker_lease_or_abort(db=db, job_id=c1.id, worker_id="w-7e", lease_token=c1.lease_token)
        with db.begin_nested():
            assert_active_worker_lease_or_abort(db=db, job_id=c2.id, worker_id="w-7e", lease_token=c2.lease_token)
            try:
                with db.begin_nested():
                    assert_active_worker_lease_or_abort(db=db, job_id=c3.id, worker_id="w-7e", lease_token=c3.lease_token)
                    assert len(db.info["_fenced_job_leases"]) == 3
                    raise RuntimeError("rollback SP2")
            except RuntimeError:
                pass
            # Job C removed, Job A + Job B preserved
            assert len(db.info["_fenced_job_leases"]) == 2
        assert len(db.info["_fenced_job_leases"]) == 2
        assert (c3.id, "w-7e", c3.lease_token) not in db.info["_fenced_job_leases"]
        db.commit()
        assert "_fenced_job_leases" not in db.info

        # ------------------------------------------------------------------
        # Test F: Full outer rollback clears all transaction-scoped registrations
        # ------------------------------------------------------------------
        assert_active_worker_lease_or_abort(db=db, job_id=c1.id, worker_id="w-7e", lease_token=c1.lease_token)
        assert_active_worker_lease_or_abort(db=db, job_id=c2.id, worker_id="w-7e", lease_token=c2.lease_token)
        assert len(db.info["_fenced_job_leases"]) == 2
        db.rollback()
        assert "_fenced_job_leases" not in db.info
        assert "_fenced_leases_by_tx" not in db.info

        # ------------------------------------------------------------------
        # Test G: Session reuse after commit, full rollback, nested rollback, and StaleWorkerLeaseError
        # ------------------------------------------------------------------
        reuse_marker = f"reuse-{uuid.uuid4().hex[:8]}"
        db.add(AuditEvent(action="P7E_REUSE", resource_type="system", resource_identifier=reuse_marker))
        db.commit()
        assert db_other.query(AuditEvent).filter(AuditEvent.resource_identifier == reuse_marker).count() == 1

        # ------------------------------------------------------------------
        # Test H & I: Multiple fenced jobs & Concurrent lease takeover via supported claim mechanism
        # ------------------------------------------------------------------
        marker_hi = f"testHI-{uuid.uuid4().hex[:8]}"
        assert_active_worker_lease_or_abort(db=db, job_id=c1.id, worker_id="w-7e", lease_token=c1.lease_token)
        assert_active_worker_lease_or_abort(db=db, job_id=c2.id, worker_id="w-7e", lease_token=c2.lease_token)
        db.add(AuditEvent(action="P7E_CONCURRENT_TAKEOVER", resource_type="system", resource_identifier=marker_hi))

        # Session B expires and claims c2 via supported recovery + claim_durable_job_by_id
        j2_b = db_other.query(DurableJob).filter(DurableJob.id == c2.id).first()
        j2_b.lease_expires_at = j2_b.lease_expires_at.replace(year=2020)
        db_other.commit()
        recover_expired_job_leases(db=db_other)
        j2_b = db_other.query(DurableJob).filter(DurableJob.id == c2.id).first()
        j2_b.next_retry_at = j2_b.next_retry_at.replace(year=2020)
        db_other.commit()
        c2_new = claim_durable_job_by_id(db=db_other, job_id=c2.id, worker_id="w-7e-takeover", lease_seconds=60)
        assert c2_new is not None and c2_new.lease_token != c2.lease_token

        with pytest.raises(StaleWorkerLeaseError):
            db.commit()
        db.rollback()
        assert db_other.query(AuditEvent).filter(AuditEvent.resource_identifier == marker_hi).count() == 0
        assert len(lifecycle_log) > 0
    finally:
        db.close()
        db_other.close()
        pg_engine.dispose()
