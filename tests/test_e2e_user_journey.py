"""End-to-End User Journey and API Integration Test Suite for Red Mercury.

Validates the complete user lifecycle from authentication, dashboard access,
repository management, security scan execution, finding review, fix verification,
report generation/export, session termination, cross-tenant isolation, and negative states.
"""
import os
import uuid
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.core.security import hash_password, create_access_token, auth_rate_limiter
from app.models.user import User
from app.models.repository import Repository
from app.models.scan import Scan
from app.models.finding import SecurityFinding
from app.models.evidence import SecurityEvidence
from app.models.verification import VerificationRun


@pytest.fixture
def clean_rate_limiter():
    """Ensure the operational rate limiter is reset before each journey test."""
    auth_rate_limiter.reset()
    yield
    auth_rate_limiter.reset()


def test_complete_user_journey_e2e(client: TestClient, db_session: Session, clean_rate_limiter):
    """User Journey:

    1. Sign up / login with valid credentials -> receives Bearer token.
    2. Check profile via /auth/me.
    3. View repository dashboard (initially empty).
    4. Register/create an authorized test repository.
    5. Trigger a security scan.
    6. Observe scan progress until completion.
    7. Query and verify detected findings and severity levels.
    8. Open detailed finding information and associated evidence.
    9. Submit a fix verification request for the vulnerability.
    10. Verify the execution result and integrity of the verification run.
    11. Generate and download an authorized findings report (SARIF & JSON).
    12. Log out and confirm session termination (token revocation).
    """
    unique_id = uuid.uuid4().hex[:8]
    user_email = f"practitioner_{unique_id}@xerova.com"
    password = "DevSecOpsPass2026!"

    # 1. Register and Login
    # Create user in DB with analyst role (mutating permissions)
    user = User(
        id=f"usr-{unique_id}",
        email=user_email,
        password_hash=hash_password(password),
        account_status="active",
        role="analyst",
    )
    db_session.add(user)
    db_session.commit()

    # Login with valid credentials
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": user_email, "password": password},
    )
    assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
    token_data = login_resp.json()
    assert "access_token" in token_data
    access_token = token_data["access_token"]
    auth_headers = {"Authorization": f"Bearer {access_token}"}

    # 2. Verify Session via /auth/me
    me_resp = client.get("/api/v1/auth/me", headers=auth_headers)
    assert me_resp.status_code == 200
    profile = me_resp.json()
    assert profile["email"] == user_email
    assert profile["account_status"] == "active"
    assert profile["role"] == "analyst"

    # 3. View Repository Dashboard (Empty state)
    repos_resp = client.get("/api/v1/repositories", headers=auth_headers)
    assert repos_resp.status_code == 200
    assert repos_resp.json() == []

    # 4. Add/Register an Authorized Test Repository
    create_repo_resp = client.post(
        "/api/v1/repositories",
        headers=auth_headers,
        json={
            "name": f"payment-service-{unique_id}",
            "clone_url": f"https://github.com/xerova/payment-service-{unique_id}.git",
            "default_branch": "main",
        },
    )
    assert create_repo_resp.status_code == 201, f"Repo creation failed: {create_repo_resp.text}"
    repo_data = create_repo_resp.json()
    repo_id = repo_data["id"]
    assert repo_data["name"] == f"payment-service-{unique_id}"

    # Verify repository appears in list
    repos_after = client.get("/api/v1/repositories", headers=auth_headers).json()
    assert len(repos_after) == 1
    assert repos_after[0]["id"] == repo_id

    # 5. Start a Security Scan
    scan_resp = client.post(
        "/api/v1/scans",
        headers=auth_headers,
        json={
            "repository_id": repo_id,
            "scan_type": "full",
            "tools": ["bandit", "secret_detector"],
            "summary": "Phase 3D E2E Validation Scan",
        },
    )
    assert scan_resp.status_code == 202, f"Scan start failed: {scan_resp.text}"
    scan_data = scan_resp.json()
    scan_id = scan_data["id"]
    assert scan_data["status"] in ["queued", "pending", "running", "completed"]

    # 6. Observe Scan Progress
    status_resp = client.get(f"/api/v1/scans/{scan_id}", headers=auth_headers)
    assert status_resp.status_code == 200
    scan_status_data = status_resp.json()
    assert scan_status_data["id"] == scan_id
    assert "status" in scan_status_data

    # Ensure findings exist for this scan and repo for testing downstream review
    finding_1 = SecurityFinding(
        id=f"fnd-{unique_id}-1",
        scan_id=scan_id,
        repo_id=repo_id,
        rule_identifier="B608",
        scanner_identifier="bandit",
        scanner_name="bandit",
        cwe="CWE-89",
        title="Hardcoded SQL String Formatting",
        severity="HIGH",
        file_path="src/payments/dao.py",
        line_number=42,
        status="open",
        confidence_score=0.92,
    )
    db_session.add(finding_1)

    evidence_1 = SecurityEvidence(
        id=f"evi-{unique_id}-1",
        repository_id=repo_id,
        scan_id=scan_id,
        finding_id=finding_1.id,
        evidence_category="scanner_output",
        title="Bandit AST Taint Output",
        tool_name="bandit",
        content_hash="abc123mockhash",
        sanitized_payload="query = 'SELECT * FROM accounts WHERE id = %s' % account_id",
    )
    db_session.add(evidence_1)
    db_session.commit()

    # 7. View Findings and Severity Information
    findings_resp = client.get(f"/api/v1/findings?repository_id={repo_id}", headers=auth_headers)
    assert findings_resp.status_code == 200
    findings = findings_resp.json()
    assert len(findings) >= 1
    target_finding = next((f for f in findings if f["id"] == finding_1.id), None)
    assert target_finding is not None
    assert target_finding["severity"] == "HIGH"
    assert target_finding["cwe"] == "CWE-89"
    assert target_finding["file_path"] == "src/payments/dao.py"

    # 8. Open Detailed Finding Information and Evidence
    detail_resp = client.get(f"/api/v1/findings/{finding_1.id}", headers=auth_headers)
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["title"] == "Hardcoded SQL String Formatting"
    assert detail["line_number"] == 42

    evidence_resp = client.get(f"/api/v1/evidence/{evidence_1.id}", headers=auth_headers)
    assert evidence_resp.status_code == 200
    evidence_data = evidence_resp.json()
    assert evidence_data["id"] == evidence_1.id
    assert evidence_data["finding_id"] == finding_1.id

    # 9. Request Fix Verification
    patch_diff = """--- a/src/payments/dao.py
+++ b/src/payments/dao.py
@@ -41,3 +41,3 @@
-query = 'SELECT * FROM accounts WHERE id = %s' % account_id
+query = 'SELECT * FROM accounts WHERE id = :account_id'
"""
    verify_resp = client.post(
        "/api/v1/verifications",
        headers=auth_headers,
        json={
            "finding_id": finding_1.id,
            "proposed_patch": patch_diff,
        },
    )
    assert verify_resp.status_code in [200, 201], f"Verification failed: {verify_resp.text}"
    verify_data = verify_resp.json()
    verification_id = verify_data["id"]
    assert "status" in verify_data

    # 10. View Actual Verification Result
    run_resp = client.get(f"/api/v1/verifications/{verification_id}", headers=auth_headers)
    assert run_resp.status_code == 200
    run_data = run_resp.json()
    assert run_data["id"] == verification_id
    assert run_data["finding_id"] == finding_1.id
    assert run_data["status"] in ["PENDING", "VERIFIED_AGAINST_DEFINED_CHECKS", "FAILED_VERIFICATION", "INCONCLUSIVE"]

    # 11. Generate and Download Authorized Reports
    report_json_resp = client.get(
        f"/api/v1/evidence/reports/findings?repo_id={repo_id}&format=json",
        headers=auth_headers,
    )
    assert report_json_resp.status_code == 200
    report_json = report_json_resp.json()
    assert "report_title" in report_json
    assert "content" in report_json

    download_resp = client.get(
        f"/api/v1/evidence/reports/findings/download?repo_id={repo_id}&format=json",
        headers=auth_headers,
    )
    assert download_resp.status_code == 200
    assert "attachment" in download_resp.headers.get("Content-Disposition", "")

    # 12. Log out and Verify Session Termination
    logout_resp = client.post("/api/v1/auth/logout", headers=auth_headers)
    assert logout_resp.status_code == 200

    # Subsequent access with revoked token MUST be rejected
    rejected_resp = client.get("/api/v1/auth/me", headers=auth_headers)
    assert rejected_resp.status_code == 401
    assert rejected_resp.json()["error"]["code"] in ["UNAUTHORIZED", "TOKEN_REVOKED", "NOT_AUTHENTICATED"]
    assert "revoked" in rejected_resp.json()["error"]["message"].lower()


def test_invalid_credentials_and_rejections(client: TestClient, db_session: Session, clean_rate_limiter):
    """Verify that invalid credentials, missing passwords, and malformed tokens are strictly rejected."""
    # 1. Non-existent user
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": "nobody_exists@xerova.com", "password": "WrongPassword123!"},
    )
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] in ["UNAUTHORIZED", "INVALID_CREDENTIALS"]

    # 2. Existing user with wrong password
    user = User(
        email=f"valid_user_{uuid.uuid4().hex[:6]}@xerova.com",
        password_hash=hash_password("CorrectPass123!"),
        account_status="active",
        role="analyst",
    )
    db_session.add(user)
    db_session.commit()

    resp_bad_pw = client.post(
        "/api/v1/auth/login",
        json={"email": user.email, "password": "IncorrectPassword!"},
    )
    assert resp_bad_pw.status_code == 401
    assert resp_bad_pw.json()["error"]["code"] in ["UNAUTHORIZED", "INVALID_CREDENTIALS"]

    # 3. Missing password
    resp_empty = client.post(
        "/api/v1/auth/login",
        json={"email": user.email, "password": ""},
    )
    assert resp_empty.status_code in [400, 422]

    # 4. Malformed/forged Bearer token
    resp_forged = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer forged.invalid.token"},
    )
    assert resp_forged.status_code == 401


def test_cross_user_isolation_e2e(client: TestClient, db_session: Session, clean_rate_limiter):
    """Verify that User B cannot access User A's repositories, scans, findings, evidence, or reports."""
    # User A (Alice)
    alice = User(
        id=f"usr-alice-{uuid.uuid4().hex[:6]}",
        email=f"alice_{uuid.uuid4().hex[:6]}@xerova.com",
        password_hash=hash_password("AliceSecurePass1!"),
        account_status="active",
        role="analyst",
    )
    # User B (Bob)
    bob = User(
        id=f"usr-bob-{uuid.uuid4().hex[:6]}",
        email=f"bob_{uuid.uuid4().hex[:6]}@xerova.com",
        password_hash=hash_password("BobSecurePass1!"),
        account_status="active",
        role="analyst",
    )
    db_session.add_all([alice, bob])
    db_session.commit()

    token_alice = create_access_token({"sub": alice.id, "email": alice.email})
    token_bob = create_access_token({"sub": bob.id, "email": bob.email})
    headers_alice = {"Authorization": f"Bearer {token_alice}"}
    headers_bob = {"Authorization": f"Bearer {token_bob}"}

    # Alice creates a private repository
    repo_resp = client.post(
        "/api/v1/repositories",
        headers=headers_alice,
        json={"name": "alice-core-vault", "clone_url": "https://github.com/alice/vault.git", "default_branch": "main"},
    )
    assert repo_resp.status_code == 201
    repo_alice_id = repo_resp.json()["id"]

    # Alice creates a scan
    scan_resp = client.post(
        "/api/v1/scans",
        headers=headers_alice,
        json={"repository_id": repo_alice_id, "scan_type": "full", "tools": ["bandit"]},
    )
    scan_alice_id = scan_resp.json()["id"]

    # Bob lists repositories -> should NOT include Alice's repo
    bob_repos = client.get("/api/v1/repositories", headers=headers_bob).json()
    assert not any(r["id"] == repo_alice_id for r in bob_repos)

    # Bob attempts direct access to Alice's repository
    bob_repo_get = client.get(f"/api/v1/repositories/{repo_alice_id}", headers=headers_bob)
    assert bob_repo_get.status_code in [403, 404]

    # Bob attempts direct access to Alice's scan
    bob_scan_get = client.get(f"/api/v1/scans/{scan_alice_id}", headers=headers_bob)
    assert bob_scan_get.status_code in [403, 404]

    # Bob attempts to download Alice's findings report
    bob_report_get = client.get(
        f"/api/v1/evidence/reports/findings?repo_id={repo_alice_id}&format=json",
        headers=headers_bob,
    )
    assert bob_report_get.status_code in [403, 404]


def test_viewer_role_prohibited_from_mutations(client: TestClient, db_session: Session, clean_rate_limiter):
    """Verify that viewer/auditor roles cannot perform mutating actions."""
    viewer = User(
        id=f"usr-viewer-{uuid.uuid4().hex[:6]}",
        email=f"viewer_{uuid.uuid4().hex[:6]}@xerova.com",
        password_hash=hash_password("ViewerPass123!"),
        account_status="active",
        role="viewer",
    )
    db_session.add(viewer)
    db_session.commit()

    token = create_access_token({"sub": viewer.id, "email": viewer.email})
    headers = {"Authorization": f"Bearer {token}"}

    # Viewer attempts to create a repository
    resp_repo = client.post(
        "/api/v1/repositories",
        headers=headers,
        json={"name": "viewer-repo", "clone_url": "https://github.com/v/r.git"},
    )
    assert resp_repo.status_code == 403
    assert resp_repo.json()["error"]["code"] in ["FORBIDDEN", "INSUFFICIENT_PERMISSIONS"]

    # Viewer attempts to start a scan
    resp_scan = client.post(
        "/api/v1/scans",
        headers=headers,
        json={"repository_id": "any-id", "tools": ["bandit"]},
    )
    assert resp_scan.status_code == 403
    assert resp_scan.json()["error"]["code"] in ["FORBIDDEN", "INSUFFICIENT_PERMISSIONS"]


def test_duplicate_active_scan_rejected(client: TestClient, db_session: Session, clean_rate_limiter):
    """Verify that concurrent duplicate scans on the same repo return 409 Conflict."""
    analyst = User(
        id=f"usr-analyst-{uuid.uuid4().hex[:6]}",
        email=f"analyst_{uuid.uuid4().hex[:6]}@xerova.com",
        password_hash=hash_password("AnalystPass123!"),
        account_status="active",
        role="analyst",
    )
    db_session.add(analyst)
    db_session.commit()

    token = create_access_token({"sub": analyst.id, "email": analyst.email})
    headers = {"Authorization": f"Bearer {token}"}

    repo = Repository(
        id=f"repo-{uuid.uuid4().hex[:6]}",
        owner_id=analyst.id,
        name="concurrent-test-repo",
        git_url="https://github.com/test/concurrent.git",
        default_branch="main",
    )
    db_session.add(repo)
    db_session.commit()

    # Create an active scan in progress
    active_scan = Scan(
        id=f"scan-{uuid.uuid4().hex[:6]}",
        repository_id=repo.id,
        status="running",
        started_at=datetime.now(timezone.utc),
    )
    db_session.add(active_scan)
    db_session.commit()

    # Attempt to submit another scan while one is running
    resp = client.post(
        "/api/v1/scans",
        headers=headers,
        json={"repository_id": repo.id, "tools": ["bandit"]},
    )
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "SCAN_ALREADY_IN_PROGRESS"


def test_expired_token_rejected(client: TestClient, db_session: Session):
    """Verify that expired JWT access tokens are rejected with 401 Unauthorized."""
    from datetime import timedelta
    analyst = User(
        id=f"usr-expired-{uuid.uuid4().hex[:6]}",
        email=f"expired_{uuid.uuid4().hex[:6]}@xerova.com",
        password_hash=hash_password("Pass123!"),
        account_status="active",
        role="analyst",
    )
    db_session.add(analyst)
    db_session.commit()

    # Generate token already expired by 1 hour
    expired_token = create_access_token(
        {"sub": analyst.id, "email": analyst.email},
        expires_delta=timedelta(seconds=-3600),
    )
    resp = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] in ["UNAUTHORIZED", "TOKEN_EXPIRED", "SESSION_EXPIRED"]


def test_failed_scan_never_reports_success(client: TestClient, db_session: Session):
    """Verify that a scan that encounters errors marks status='failed' and never reports 'completed'."""
    from app.scanner.runner import run_security_scan

    analyst = User(
        id=f"usr-crash-{uuid.uuid4().hex[:6]}",
        email=f"crash_{uuid.uuid4().hex[:6]}@xerova.com",
        password_hash=hash_password("Pass123!"),
        account_status="active",
        role="analyst",
    )
    db_session.add(analyst)
    db_session.commit()

    repo = Repository(
        id=f"repo-crash-{uuid.uuid4().hex[:6]}",
        owner_id=analyst.id,
        name="crash-test-repo",
        workspace_path=None,  # Intentionally missing workspace
        default_branch="main",
    )
    db_session.add(repo)
    db_session.commit()

    scan = Scan(
        id=f"scan-crash-{uuid.uuid4().hex[:6]}",
        repository_id=repo.id,
        status="pending",
    )
    db_session.add(scan)
    db_session.commit()

    # Run scan with invalid workspace
    run_security_scan(
        repo=repo,
        scan=scan,
        db=db_session,
    )

    db_session.refresh(scan)
    # Scan MUST be failed, never 'completed' or 'verified'
    assert scan.status == "failed"
    assert scan.status != "completed"
    assert scan.summary is not None
    assert "error" in scan.summary.lower()


def test_operational_rate_limiting_in_journey(client: TestClient, db_session: Session, clean_rate_limiter):
    """Verify that operational endpoints throttle when requests exceed the per-minute limit."""
    from app.core.config import settings

    analyst = User(
        id=f"usr-ratelimit-{uuid.uuid4().hex[:6]}",
        email=f"ratelimit_{uuid.uuid4().hex[:6]}@xerova.com",
        password_hash=hash_password("Pass123!"),
        account_status="active",
        role="analyst",
    )
    db_session.add(analyst)
    db_session.commit()

    token = create_access_token({"sub": analyst.id, "email": analyst.email})
    headers = {"Authorization": f"Bearer {token}"}

    # Simulate bursting requests on /api/v1/scans
    limit = settings.RATE_LIMIT_SCAN_MAX
    got_429 = False
    for i in range(limit + 5):
        resp = client.post(
            "/api/v1/scans",
            headers=headers,
            json={"repository_id": "nonexistent-id", "tools": ["bandit"]},
        )
        if resp.status_code == 429:
            got_429 = True
            assert "Retry-After" in resp.headers
            assert resp.json()["error"]["code"] == "RATE_LIMIT_EXCEEDED"
            break

    assert got_429, f"Expected 429 after exceeding {limit} requests, but did not receive one."

