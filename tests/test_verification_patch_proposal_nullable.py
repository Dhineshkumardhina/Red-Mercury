"""Regression tests for BUG 1: fix verification with patch_proposal_id=None and clean input validation."""
import os
import sqlite3
import tempfile
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from alembic.config import Config
from alembic import command

from app.models.finding import SecurityFinding
from app.models.repository import Repository
from app.models.verification import VerificationRun
from app.schemas.verification import VerificationRunRequest
from app.verification.service import execute_fix_verification
from app.core.errors import NotFoundError, ValidationError

SAMPLE_PATCH = """--- a/src/app.py
+++ b/src/app.py
@@ -1,3 +1,3 @@
-def query(name):
-    return f"SELECT * FROM users WHERE name = '{name}'"
+def query(name):
+    return "SELECT * FROM users WHERE name = :name"
"""


@pytest.fixture
def test_repo_and_finding(auth_client: TestClient, db_session: Session):
    """Fixture providing user-owned repository and security finding for verification tests."""
    user = auth_client.current_user

    repo = Repository(
        id=f"repo_{os.urandom(4).hex()}",
        owner_id=user.id,
        name="test-verification-repo",
        source_type="local",
        default_branch="main",
        health_score=100,
        is_active=True,
    )
    db_session.add(repo)
    db_session.commit()
    db_session.refresh(repo)

    finding = SecurityFinding(
        id=f"FIND-{os.urandom(4).hex()}",
        repo_id=repo.id,
        title="SQL Injection in user query",
        severity="CRITICAL",
        cwe="CWE-89: SQL Injection",
        file_path="src/app.py",
        line_number=2,
        scanner_name="bandit",
        rule_identifier="B608",
        status="open",
        code_excerpt="return f\"SELECT * FROM users WHERE name = '{name}'\"",
    )
    db_session.add(finding)
    db_session.commit()
    db_session.refresh(finding)

    return repo, finding


def test_verification_run_with_null_patch_proposal_via_service(db_session: Session, test_repo_and_finding):
    """Verify execute_fix_verification succeeds and persists VerificationRun with patch_proposal_id=None."""
    repo, finding = test_repo_and_finding

    request = VerificationRunRequest(
        finding_id=finding.id,
        proposed_patch=SAMPLE_PATCH,
        patch_id=None,
        run_existing_tests=False,
        run_regression_tests=False,
    )

    response = execute_fix_verification(request=request, db=db_session, user_id=repo.owner_id)

    assert response is not None
    assert response.id.startswith("vr_")
    assert response.finding_id == finding.id
    assert response.status in ("INCONCLUSIVE", "VERIFIED_AGAINST_DEFINED_CHECKS", "FAILED_VERIFICATION")

    # Assert database record was persisted with NULL patch_proposal_id without SQLite integrity crash
    persisted_run = db_session.query(VerificationRun).filter(VerificationRun.id == response.id).first()
    assert persisted_run is not None
    assert persisted_run.patch_proposal_id is None
    assert persisted_run.finding_id == finding.id


def test_verification_run_with_null_patch_proposal_via_api(auth_client: TestClient, test_repo_and_finding, db_session: Session):
    """Verify POST /api/v1/verifications returns HTTP 200 with patch_proposal_id=None."""
    repo, finding = test_repo_and_finding

    payload = {
        "finding_id": finding.id,
        "proposed_patch": SAMPLE_PATCH,
        "patch_id": None,
        "run_existing_tests": False,
        "run_regression_tests": False,
    }

    res = auth_client.post("/api/v1/verifications", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["id"].startswith("vr_")
    assert data["finding_id"] == finding.id
    assert "status" in data

    # Verify database state
    persisted = db_session.query(VerificationRun).filter(VerificationRun.id == data["id"]).first()
    assert persisted is not None
    assert persisted.patch_proposal_id is None


def test_verification_service_clean_error_on_invalid_input(db_session: Session, test_repo_and_finding):
    """Verify service returns clean domain exceptions (not unhandled 500) for genuinely invalid input."""
    repo, finding = test_repo_and_finding

    # 1. Non-existent finding ID raises NotFoundError
    with pytest.raises(NotFoundError) as exc_info:
        execute_fix_verification(
            request=VerificationRunRequest(
                finding_id="NON_EXISTENT_FINDING_9999",
                proposed_patch=SAMPLE_PATCH
            ),
            db=db_session
        )
    assert "does not exist" in str(exc_info.value)

    # 2. Empty finding ID raises ValidationError
    with pytest.raises(ValidationError) as exc_info:
        execute_fix_verification(
            request=VerificationRunRequest(
                finding_id="",
                proposed_patch=SAMPLE_PATCH
            ),
            db=db_session
        )
    assert "Finding ID cannot be empty" in str(exc_info.value)

    # 3. Empty proposed patch raises ValidationError
    with pytest.raises(ValidationError) as exc_info:
        execute_fix_verification(
            request=VerificationRunRequest(
                finding_id=finding.id,
                proposed_patch="   "
            ),
            db=db_session
        )
    assert "Proposed patch diff cannot be empty" in str(exc_info.value)

    # 4. Non-positive timeout raises ValidationError
    with pytest.raises(ValidationError) as exc_info:
        req = VerificationRunRequest(finding_id=finding.id, proposed_patch=SAMPLE_PATCH)
        req.timeout_seconds = 0
        execute_fix_verification(request=req, db=db_session)
    assert "timeout must be greater than zero" in str(exc_info.value)


def test_verification_api_clean_error_on_invalid_input(auth_client: TestClient, test_repo_and_finding):
    """Verify API returns 404 / 422 clean JSON envelopes on invalid inputs."""
    repo, finding = test_repo_and_finding

    # Non-existent finding -> 404
    res = auth_client.post("/api/v1/verifications", json={
        "finding_id": "NON_EXISTENT_ID",
        "proposed_patch": SAMPLE_PATCH
    })
    assert res.status_code == 404

    # Empty patch -> 422
    res = auth_client.post("/api/v1/verifications", json={
        "finding_id": finding.id,
        "proposed_patch": "   "
    })
    assert res.status_code == 422


def test_migration_0010_makes_patch_proposal_id_nullable_in_sqlite():
    """Verify migration 0010 alters SQLite notnull constraint from 1 (in 0009) to 0 (in 0010)."""
    from app.core.config import settings
    orig_db_url = settings.DATABASE_URL

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name.replace("\\", "/")

    try:
        settings.DATABASE_URL = f"sqlite:///{db_path}"
        os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
        cfg = Config("backend/alembic.ini")

        # 1. Establish state at revision 0009 by upgrading and downgrading
        command.upgrade(cfg, "head")
        command.downgrade(cfg, "0009_add_commit_sha_to_scans")

        con = sqlite3.connect(db_path)
        cur = con.cursor()
        cur.execute("PRAGMA table_info(verification_runs)")
        cols_0009 = {row[1]: row for row in cur.fetchall()}
        # At revision 0009, notnull is 1
        assert cols_0009["patch_proposal_id"][3] == 1, "At revision 0009, patch_proposal_id must have notnull=1"

        # Attempting to insert NULL patch_proposal_id at revision 0009 raises IntegrityError
        with pytest.raises(sqlite3.IntegrityError) as exc_info:
            cur.execute("""
                INSERT INTO verification_runs (id, patch_proposal_id, status, started_at, created_at, updated_at)
                VALUES ('vr_should_fail', NULL, 'NOT_TESTED', '2026-10-18 20:00:00', '2026-10-18 20:00:00', '2026-10-18 20:00:00')
            """)
        assert "NOT NULL constraint failed: verification_runs.patch_proposal_id" in str(exc_info.value)
        con.close()

        # 2. Upgrade to revision 0010 (HEAD)
        command.upgrade(cfg, "head")

        con = sqlite3.connect(db_path)
        cur = con.cursor()
        cur.execute("PRAGMA table_info(verification_runs)")
        cols_0010 = {row[1]: row for row in cur.fetchall()}
        # In revision 0010, notnull is 0 (nullable)
        assert cols_0010["patch_proposal_id"][3] == 0, "At revision 0010, patch_proposal_id must have notnull=0"

        # Inserting NULL patch_proposal_id at revision 0010 succeeds without error
        cur.execute("""
            INSERT INTO verification_runs (id, patch_proposal_id, status, started_at, created_at, updated_at)
            VALUES ('vr_should_succeed', NULL, 'NOT_TESTED', '2026-10-18 20:00:00', '2026-10-18 20:00:00', '2026-10-18 20:00:00')
        """)
        con.commit()

        cur.execute("SELECT id, patch_proposal_id FROM verification_runs WHERE id = 'vr_should_succeed'")
        row = cur.fetchone()
        assert row[0] == "vr_should_succeed"
        assert row[1] is None

        # 3. Verify downgrade does not fail when NULL rows exist
        con.close()
        command.downgrade(cfg, "0009_add_commit_sha_to_scans")

        con = sqlite3.connect(db_path)
        cur = con.cursor()
        cur.execute("PRAGMA table_info(verification_runs)")
        cols_reverted = {row[1]: row for row in cur.fetchall()}
        assert cols_reverted["patch_proposal_id"][3] == 1
        con.close()

    finally:
        settings.DATABASE_URL = orig_db_url
        os.environ["DATABASE_URL"] = orig_db_url
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except Exception:
                pass
