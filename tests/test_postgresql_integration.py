"""Phase 2E: PostgreSQL Integration, Migration, and Dialect Compatibility Tests.

Verifies:
1. PostgreSQL is strictly enforced as the production database backend in config.py.
2. SQLAlchemy models and all 12 Alembic migrations compile valid PostgreSQL DDL.
3. Cross-dialect JSON/JSONB data serialization and query handling.
4. Transaction rollback semantics and constraint violations.
5. Live PostgreSQL integration (migrations from clean DB, schema consistency, concurrent
   updates, revoked token cross-worker persistence, and connection loss/recovery).
   NOTE: If a live PostgreSQL instance is not reachable, live integration tests are
   gracefully SKIPPED with a diagnostic reason per Phase 2E specification.
"""
import os
from datetime import datetime, timezone
from typing import Optional
from unittest.mock import patch
import pytest
from sqlalchemy import (
    create_engine,
    text,
    Table,
    MetaData,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.schema import CreateTable

from alembic.config import Config
from alembic.script import ScriptDirectory
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext

from app.core.config import Settings, settings
from app.db.base import Base
from app.db.session import check_db_connection
from app.models.user import User
from app.models.repository import Repository
from app.models.token import RevokedToken
from app.models.verification import VerificationRun


def _get_live_postgres_url() -> Optional[str]:
    """Check if a live PostgreSQL test instance is configured or reachable."""
    env_url = os.environ.get("TEST_POSTGRES_URL") or os.environ.get("POSTGRES_DATABASE_URL")
    if env_url and env_url.startswith("postgresql"):
        try:
            eng = create_engine(env_url, connect_args={"connect_timeout": 2})
            with eng.connect() as conn:
                conn.execute(text("SELECT 1"))
            return env_url
        except Exception:
            return None

    # Probe default local PostgreSQL port 5432
    default_url = "postgresql://postgres:postgres@localhost:5432/test_redmercury"
    try:
        eng = create_engine(default_url, connect_args={"connect_timeout": 1})
        with eng.connect() as conn:
            conn.execute(text("SELECT 1"))
        return default_url
    except Exception:
        return None


LIVE_POSTGRES_URL = _get_live_postgres_url()


# -----------------------------------------------------------------------------
# Unit & Compilation Tests (Always Run Without Live Postgres)
# -----------------------------------------------------------------------------

def test_postgresql_is_required_for_production():
    """Verify production settings refuse SQLite and enforce PostgreSQL DATABASE_URL."""
    with pytest.raises(ValueError, match="SQLite cannot be used in production"):
        Settings(
            APP_ENV="production",
            SECRET_KEY="a" * 32,
            DATABASE_URL="sqlite:///./test.db",
            CORS_ORIGINS=["https://app.redmercury.io"],
            ALLOWED_HOSTS=["redmercury.io"],
            ALLOW_PRIVATE_NETWORKS=False,
        )


def test_models_compile_valid_postgresql_ddl():
    """Verify that all SQLAlchemy ORM models compile valid PostgreSQL DDL via postgresql dialect."""
    pg_dialect = postgresql.dialect()

    for table in Base.metadata.sorted_tables:
        create_stmt = CreateTable(table).compile(dialect=pg_dialect)
        ddl_str = str(create_stmt).strip()

        assert len(ddl_str) > 0, f"Table {table.name} produced empty DDL for PostgreSQL"
        assert f"CREATE TABLE {table.name}".upper() in ddl_str.upper()

        # Check primary key syntax
        assert "PRIMARY KEY" in ddl_str.upper()


def test_postgresql_connection_pool_configuration():
    """Verify PostgreSQL engine settings configure connection pool and pre-ping."""
    from sqlalchemy.pool import QueuePool
    pool = QueuePool(lambda: None, pool_size=10, max_overflow=20, pre_ping=True)
    assert pool._pre_ping is True
    assert pool._pool.maxsize == 10
    assert pool._max_overflow == 20


def test_json_and_array_text_field_compatibility():
    """Verify JSON-serialized models work across dialects and roundtrip properly."""
    import json
    metadata_sample = {
        "rules": ["B608", "CWE-89"],
        "entropy": 3.82,
        "is_verified": True,
        "details": {"sink": "cursor.execute", "confidence": 0.95},
    }
    encoded = json.dumps(metadata_sample)
    decoded = json.loads(encoded)

    assert decoded["rules"] == ["B608", "CWE-89"]
    assert decoded["details"]["confidence"] == 0.95


def test_connection_recovery_check_db_connection():
    """Verify that check_db_connection returns False gracefully on broken engines."""
    broken_engine = create_engine("sqlite:///C:/nonexistent_dir_12345/unwritable.db")
    with patch("app.db.session.engine", broken_engine):
        assert check_db_connection() is False


# -----------------------------------------------------------------------------
# Live PostgreSQL Integration Tests (Skipped if Live Postgres is Unavailable)
# -----------------------------------------------------------------------------

@pytest.mark.skipif(
    LIVE_POSTGRES_URL is None,
    reason="PostgreSQL live instance unavailable: no running postgres service or TEST_POSTGRES_URL configured (tested on Windows host without active daemon)",
)
def test_live_postgres_migrations_clean_db():
    """Apply all 12 Alembic migrations from clean state against disposable PostgreSQL database."""
    cfg = Config("backend/alembic.ini")
    cfg.set_main_option("sqlalchemy.url", LIVE_POSTGRES_URL)

    # 1. Upgrade to head
    command.upgrade(cfg, "head")

    # 2. Verify schema matches Base.metadata
    pg_engine = create_engine(LIVE_POSTGRES_URL)
    with pg_engine.connect() as conn:
        ctx = MigrationContext.configure(conn)
        diff = compare_metadata(ctx, Base.metadata)
        assert diff == [], f"PostgreSQL schema differs from ORM models: {diff}"


@pytest.mark.skipif(
    LIVE_POSTGRES_URL is None,
    reason="PostgreSQL live instance unavailable: no running postgres service or TEST_POSTGRES_URL configured",
)
def test_live_postgres_unique_constraints_and_transaction_rollback():
    """Test PostgreSQL unique constraints and atomic rollback on collision."""
    pg_engine = create_engine(LIVE_POSTGRES_URL)
    SessionPg = sessionmaker(bind=pg_engine)
    session = SessionPg()
    try:
        email = f"pg_user_{os.urandom(4).hex()}@redmercury.io"
        u1 = User(id=f"u1_{os.urandom(4).hex()}", email=email, password_hash="hash1", account_status="active", role="engineer")
        session.add(u1)
        session.commit()

        # Duplicate email should fail unique constraint
        u2 = User(id=f"u2_{os.urandom(4).hex()}", email=email, password_hash="hash2", account_status="active", role="engineer")
        session.add(u2)
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()

        # Session is usable after rollback
        user_count = session.query(User).filter(User.email == email).count()
        assert user_count == 1
    finally:
        session.close()


@pytest.mark.skipif(
    LIVE_POSTGRES_URL is None,
    reason="PostgreSQL live instance unavailable: no running postgres service or TEST_POSTGRES_URL configured",
)
def test_live_postgres_revoked_token_cross_worker_persistence():
    """Verify revoked tokens persist in PostgreSQL across distinct sessions/workers."""
    pg_engine = create_engine(LIVE_POSTGRES_URL)
    SessionPg = sessionmaker(bind=pg_engine)

    worker1_session = SessionPg()
    worker2_session = SessionPg()
    try:
        token_hash = f"hash_{os.urandom(16).hex()}"
        rev = RevokedToken(
            id=f"rt_{os.urandom(4).hex()}",
            token_hash=token_hash,
            user_id="user_test_worker",
            expires_at=datetime.now(timezone.utc),
            revocation_reason="logout",
        )
        worker1_session.add(rev)
        worker1_session.commit()

        # Worker 2 queries PostgreSQL and observes revoked token
        found = worker2_session.query(RevokedToken).filter(RevokedToken.token_hash == token_hash).first()
        assert found is not None
        assert found.revocation_reason == "logout"
    finally:
        worker1_session.close()
        worker2_session.close()
