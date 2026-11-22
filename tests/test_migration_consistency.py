"""Tests for Alembic migration ordering, schema consistency, and critical constraints."""
import os
import sqlite3
import tempfile
import pytest
from alembic.config import Config
from alembic import command
from alembic.script import ScriptDirectory
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import create_engine

from app.db.base import Base
from app.core.config import settings


def test_migration_chain_is_strictly_linear():
    """Verify that all migrations form a single linear chain with no split heads or orphans."""
    cfg = Config("backend/alembic.ini")
    script = ScriptDirectory.from_config(cfg)
    heads = script.get_heads()
    assert len(heads) == 1, f"Expected exactly 1 migration head, found {len(heads)}: {heads}"
    assert heads[0] == "0014_add_durable_jobs_and_outbox", f"Expected head to be 0014_add_durable_jobs_and_outbox, got {heads[0]}"

    # Verify linear revision sequence from 0001 to 0011
    revisions = []
    current = script.get_revision("0001_initial_schema")
    while current:
        revisions.append(current.revision)
        down = current.down_revision
        if not down:
            break
        current = script.get_revision(down)
    
    # 0011 down to 0001
    head_rev = script.get_revision(heads[0])
    chain = []
    curr = head_rev
    while curr:
        chain.append(curr.revision)
        if not curr.down_revision:
            break
        curr = script.get_revision(curr.down_revision)
    
    expected_chain = [
        "0014_add_durable_jobs_and_outbox",
        "0013_add_refresh_token_sessions",
        "0012_add_revoked_tokens_and_user_role",
        "0011_sync_model_constraints",
        "0010_make_patch_proposal_id_nullable",
        "0009_add_commit_sha_to_scans",
        "0008_verification_classified_and_provenance",
        "0007_vulnerability_validation",
        "0006_github_ci_integration",
        "0005_security_evidence_management",
        "0004_fix_verification_engine",
        "0003_repository_ingestion",
        "0002_authentication_and_models",
        "0001_initial_schema",
    ]
    assert chain == expected_chain, f"Migration chain diverged from expected sequence: {chain}"


def test_schema_and_models_are_in_sync_no_diff():
    """Verify that compare_metadata detects 0 schema divergences between Base.metadata and upgraded DB."""
    cfg = Config("backend/alembic.ini")
    engine = create_engine(settings.DATABASE_URL)
    with engine.connect() as connection:
        context = MigrationContext.configure(connection)
        diff = compare_metadata(context, Base.metadata)
        assert diff == [], f"Alembic detected schema differences: {diff}"


def test_migrations_against_disposable_database():
    """Test full migration lifecycle (upgrade to head, constraints verify, downgrade, re-upgrade) on disposable DB."""
    orig_db_url = settings.DATABASE_URL

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name.replace("\\", "/")

    try:
        disposable_url = f"sqlite:///{db_path}"
        settings.DATABASE_URL = disposable_url
        os.environ["DATABASE_URL"] = disposable_url
        cfg = Config("backend/alembic.ini")

        # 1. Full upgrade from scratch to head
        command.upgrade(cfg, "head")

        con = sqlite3.connect(db_path)
        cur = con.cursor()

        # A. Verify repositories.owner_id is NOT NULL (notnull == 1)
        cur.execute("PRAGMA table_info(repositories)")
        repo_cols = {row[1]: row for row in cur.fetchall()}
        assert "owner_id" in repo_cols
        assert repo_cols["owner_id"][3] == 1, "repositories.owner_id must be NOT NULL"

        # Attempting to insert a repository with NULL owner_id raises IntegrityError
        with pytest.raises(sqlite3.IntegrityError):
            cur.execute("""
                INSERT INTO repositories (id, name, default_branch, health_score, critical_count, high_count, medium_count, low_count, is_active, created_at, updated_at, owner_id)
                VALUES ('repo_orphan', 'test_repo', 'main', 100, 0, 0, 0, 0, 1, '2026-10-19 12:00:00', '2026-10-19 12:00:00', NULL)
            """)

        # B. Verify repositories.name index is non-unique
        cur.execute("PRAGMA index_list(repositories)")
        repo_indexes = {row[1]: row for row in cur.fetchall()}
        assert "ix_repositories_name" in repo_indexes
        assert repo_indexes["ix_repositories_name"][2] == 0, "ix_repositories_name must be non-unique (unique=0)"

        # Verify two different owners can have repositories with the same name
        cur.execute("""
            INSERT INTO users (id, email, password_hash, account_status, created_at, updated_at)
            VALUES ('usr_1', 'user1@xerova.com', 'hash1', 'active', '2026-10-19 12:00:00', '2026-10-19 12:00:00')
        """)
        cur.execute("""
            INSERT INTO users (id, email, password_hash, account_status, created_at, updated_at)
            VALUES ('usr_2', 'user2@xerova.com', 'hash2', 'active', '2026-10-19 12:00:00', '2026-10-19 12:00:00')
        """)
        cur.execute("""
            INSERT INTO repositories (id, name, default_branch, health_score, critical_count, high_count, medium_count, low_count, is_active, created_at, updated_at, owner_id)
            VALUES ('repo_1', 'common-service', 'main', 100, 0, 0, 0, 0, 1, '2026-10-19 12:00:00', '2026-10-19 12:00:00', 'usr_1')
        """)
        cur.execute("""
            INSERT INTO repositories (id, name, default_branch, health_score, critical_count, high_count, medium_count, low_count, is_active, created_at, updated_at, owner_id)
            VALUES ('repo_2', 'common-service', 'main', 100, 0, 0, 0, 0, 1, '2026-10-19 12:00:00', '2026-10-19 12:00:00', 'usr_2')
        """)
        con.commit()

        # C. Verify audit_events.resource_identifier index exists
        cur.execute("PRAGMA index_list(audit_events)")
        audit_indexes = {row[1]: row for row in cur.fetchall()}
        assert "ix_audit_events_resource_identifier" in audit_indexes

        # D. Verify pull_request_scans indexes exist
        cur.execute("PRAGMA index_list(pull_request_scans)")
        pr_indexes = {row[1]: row for row in cur.fetchall()}
        assert "ix_pr_scans_scan_id" in pr_indexes
        assert "ix_pr_scans_status" in pr_indexes

        # E. Verify verification_runs.status accommodates 64-char status strings
        long_status = "VERIFIED_AGAINST_DEFINED_CHECKS"
        cur.execute(f"""
            INSERT INTO verification_runs (id, status, started_at, created_at, updated_at)
            VALUES ('vr_status_test', '{long_status}', '2026-10-19 12:00:00', '2026-10-19 12:00:00', '2026-10-19 12:00:00')
        """)
        con.commit()
        cur.execute("SELECT status FROM verification_runs WHERE id = 'vr_status_test'")
        assert cur.fetchone()[0] == long_status
        con.close()

        # 2. Downgrade to 0010
        command.downgrade(cfg, "0010_make_patch_proposal_id_nullable")

        # 3. Re-upgrade to head
        command.upgrade(cfg, "head")

        # 4. Final verify no diff
        engine = create_engine(disposable_url)
        with engine.connect() as conn:
            ctx = MigrationContext.configure(conn)
            diff = compare_metadata(ctx, Base.metadata)
            assert diff == []

    finally:
        settings.DATABASE_URL = orig_db_url
        os.environ["DATABASE_URL"] = orig_db_url
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except Exception:
                pass
