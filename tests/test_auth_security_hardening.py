"""Automated regression and security hardening test suite for authentication,
authorization, multi-user isolation, CSRF protection, and rate limiting.
"""
import json
import subprocess
import sys
from datetime import timedelta
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import Settings, settings
from app.core.security import auth_rate_limiter, create_access_token, hash_password
from app.models.audit import AuditEvent
from app.models.evidence import SecurityEvidence
from app.models.finding import SecurityFinding
from app.models.github import GitHubIntegration, PullRequestScan
from app.models.repository import Repository
from app.models.scan import Scan
from app.models.user import User
from app.models.verification import VerificationRun


# ==============================================================================
# 1. Production Seed Account & Development Credential Lockdown (Task 3)
# ==============================================================================

def test_production_mode_blocks_dev_seed_account_login(client: TestClient, db_session: Session, monkeypatch):
    """Ensure that in production APP_ENV, login with dev@xerova.com is strictly rejected."""
    # Ensure dev seed user exists in db
    dev_user = db_session.query(User).filter(User.email == "dev@xerova.com").first()
    if not dev_user:
        dev_user = User(
            id="usr-dev-seed-001",
            email="dev@xerova.com",
            password_hash=hash_password("XerovaDevPass2026!"),
            account_status="active",
        )
        db_session.add(dev_user)
        db_session.commit()

    # Simulate production environment
    monkeypatch.setattr(settings, "APP_ENV", "production")

    res = client.post(
        "/api/v1/auth/login",
        json={"email": "dev@xerova.com", "password": "XerovaDevPass2026!"},
    )
    assert res.status_code == 401
    assert res.json()["error"]["code"] == "UNAUTHORIZED"

    # Verify audit event was logged
    audit = db_session.query(AuditEvent).filter(
        AuditEvent.action == "LOGIN_BLOCKED_DEV_SEED_IN_PRODUCTION"
    ).first()
    assert audit is not None


def test_production_mode_blocks_dev_seed_user_token(client: TestClient, db_session: Session, monkeypatch):
    """Even if an existing dev seed token is presented, production mode must reject it."""
    dev_user = db_session.query(User).filter(User.email == "dev@xerova.com").first()
    if not dev_user:
        dev_user = User(
            id="usr-dev-seed-001",
            email="dev@xerova.com",
            password_hash=hash_password("XerovaDevPass2026!"),
            account_status="active",
        )
        db_session.add(dev_user)
        db_session.commit()

    seed_token = create_access_token({"sub": dev_user.id, "email": dev_user.email})

    monkeypatch.setattr(settings, "APP_ENV", "production")

    res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {seed_token}"})
    assert res.status_code == 401
    assert "disabled in production" in res.json()["error"]["message"].lower()


def test_seed_dev_script_blocks_non_development_execution():
    """Verify that scripts/seed_dev.py aborts immediately when run in non-development environments."""
    result = subprocess.run(
        [sys.executable, "scripts/seed_dev.py"],
        capture_output=True,
        text=True,
        env={"APP_ENV": "production", "PYTHONPATH": "backend"},
    )
    assert result.returncode != 0
    assert "strictly prohibited" in result.stdout or "blocked" in result.stdout or result.returncode == 1


# ==============================================================================
# 2. Brute-Force, Account Enumeration, and Abuse Protection (Task 4)
# ==============================================================================

def test_ip_spoofing_via_x_forwarded_for_is_rejected(client: TestClient):
    """Untrusted clients cannot bypass IP rate limiting by spoofing X-Forwarded-For."""
    auth_rate_limiter.reset()

    # Client tries to spoof IP on every request from untrusted connection
    for i in range(settings.AUTH_RATE_LIMIT_LOGIN_MAX):
        client.post(
            "/api/v1/auth/login",
            json={"email": "attacker.target@xerova.com", "password": "WrongPassword!"},
            headers={"X-Forwarded-For": f"198.51.100.{i}"},
        )

    # The (MAX+1)th request must still be throttled because untrusted X-Forwarded-For is ignored
    throttled = client.post(
        "/api/v1/auth/login",
        json={"email": "attacker.target@xerova.com", "password": "WrongPassword!"},
        headers={"X-Forwarded-For": "198.51.100.254"},
    )
    assert throttled.status_code == 429
    assert throttled.json()["error"]["code"] == "RATE_LIMIT_EXCEEDED"
    auth_rate_limiter.reset()


def test_account_level_rate_limiting_protects_target_user(client: TestClient):
    """Repeated login failures against a specific email are throttled to protect the account."""
    auth_rate_limiter.reset()
    target_email = "target.executive@xerova.com"

    for _ in range(10):
        client.post(
            "/api/v1/auth/login",
            json={"email": target_email, "password": "BadPassword123!"},
        )

    # Next attempt against the same email must trigger 429
    res = client.post(
        "/api/v1/auth/login",
        json={"email": target_email, "password": "BadPassword123!"},
    )
    assert res.status_code == 429
    assert res.json()["error"]["code"] == "RATE_LIMIT_EXCEEDED"
    auth_rate_limiter.reset()


def test_login_timing_protection_for_nonexistent_account(client: TestClient):
    """Non-existent email returns identical error message to invalid password on existing account."""
    # Existing user bad password
    res_existing = client.post(
        "/api/v1/auth/login",
        json={"email": "lead.secops@xerova.com", "password": "WrongPassword999!"},
    )

    # Non-existent email
    res_nonexistent = client.post(
        "/api/v1/auth/login",
        json={"email": "totally.nonexistent.user.999@xerova.com", "password": "WrongPassword999!"},
    )

    assert res_existing.status_code == 401
    assert res_nonexistent.status_code == 401
    assert res_existing.json()["error"]["message"] == res_nonexistent.json()["error"]["message"]
    assert res_existing.json()["error"]["code"] == res_nonexistent.json()["error"]["code"]


# ==============================================================================
# 3. Cookie-Based Authentication & CSRF Protection (Task 5)
# ==============================================================================

def test_cookie_auth_rejects_cross_site_untrusted_origin(client: TestClient, user_a: User):
    """Cookie-authenticated state-modifying requests from untrusted origins are blocked with 403."""
    token = create_access_token({"sub": user_a.id, "email": user_a.email})
    client.cookies.set(settings.COOKIE_NAME, token)
    client.headers.pop("Authorization", None)

    # Cross-site origin attempt
    res = client.post(
        "/api/v1/repositories",
        json={"name": "csrf-repo", "git_url": "https://github.com/alice/csrf"},
        headers={"Origin": "https://attacker-evil-site.com"},
    )
    assert res.status_code == 403
    assert "csrf" in res.json()["error"]["message"].lower()


def test_cookie_auth_accepts_trusted_origin(client: TestClient, user_a: User):
    """Cookie-authenticated state-modifying requests from configured CORS origins succeed."""
    token = create_access_token({"sub": user_a.id, "email": user_a.email})
    client.cookies.set(settings.COOKIE_NAME, token)
    client.headers.pop("Authorization", None)

    res = client.post(
        "/api/v1/repositories",
        json={"name": f"valid-cookie-repo-{user_a.id[:6]}", "git_url": "https://github.com/alice/valid"},
        headers={"Origin": "http://localhost:5173"},
    )
    assert res.status_code == 201
    assert res.json()["name"] == f"valid-cookie-repo-{user_a.id[:6]}"


def test_bearer_token_is_exempt_from_csrf_origin_check(client: TestClient, user_a: User):
    """Bearer tokens in Authorization header are not subject to cookie CSRF origin checks."""
    token = create_access_token({"sub": user_a.id, "email": user_a.email})
    client.headers["Authorization"] = f"Bearer {token}"
    client.cookies.clear()

    # Even with unusual Origin, Bearer headers succeed
    res = client.post(
        "/api/v1/repositories",
        json={"name": f"bearer-repo-{user_a.id[:6]}", "git_url": "https://github.com/alice/bearer"},
        headers={"Origin": "https://api-client.external.tools"},
    )
    assert res.status_code == 201


# ==============================================================================
# 4. Multi-User Isolation & IDOR Testing Across ALL Entities (Tasks 8, 9, 10, 11)
# ==============================================================================

@pytest.fixture
def alice_and_bob_setup(client_a: TestClient, client_b: TestClient, db_session: Session):
    """Set up a full graph of entities for Alice to test unauthorized access by Bob."""
    # 1. Alice's repository
    repo_res = client_a.post(
        "/api/v1/repositories",
        json={"name": "alice/core-engine", "git_url": "https://github.com/alice/core-engine"},
    )
    assert repo_res.status_code == 201
    repo_id = repo_res.json()["id"]

    # 2. Alice's security finding
    find_res = client_a.post(
        "/api/v1/findings",
        json={
            "repo_id": repo_id,
            "cwe": "CWE-89: SQL Injection",
            "title": "SQL Injection in auth handler",
            "severity": "CRITICAL",
            "scanner_name": "Semgrep OSS",
            "file_path": "src/auth.py",
            "line_number": 42,
            "code_excerpt": "cursor.execute(f'SELECT * FROM users WHERE id={uid}')",
        },
    )
    assert find_res.status_code == 201
    finding_id = find_res.json()["id"]

    # 3. Alice's scan
    scan = Scan(
        repository_id=repo_id,
        status="completed",
        summary=json.dumps({"total_findings": 1, "scanners": ["Semgrep OSS"]}),
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)
    scan_id = scan.id

    # 4. Alice's verification run
    v_run = VerificationRun(
        id=f"vrun-alice-{repo_id[:8]}",
        finding_id=finding_id,
        patch_id="patch-01",
        status="VERIFIED_AGAINST_DEFINED_CHECKS",
        baseline_hash="a" * 64,
        patched_hash="b" * 64,
        patch_diff="--- a/src/auth.py\n+++ b/src/auth.py\n@@ -1 +1 @@\n-cursor.execute(f'SELECT * FROM users WHERE id={uid}')\n+cursor.execute('SELECT * FROM users WHERE id=%s', (uid,))",
        test_results=json.dumps({"passed": 2, "failed": 0}),
    )
    db_session.add(v_run)
    db_session.commit()
    db_session.refresh(v_run)
    run_id = v_run.id

    # 5. Alice's security evidence
    ev_res = client_a.post(
        "/api/v1/evidence",
        json={
            "repository_id": repo_id,
            "evidence_category": "scanner_finding",
            "title": "Alice Confidential Evidence",
            "tool_name": "Semgrep",
            "raw_payload": {"sensitive_internal_query": "SELECT * FROM secrets"},
            "finding_id": finding_id,
        },
    )
    assert ev_res.status_code == 201
    evidence_id = ev_res.json()["id"]

    # 6. Alice's GitHub PR Scan
    pr_scan = PullRequestScan(
        repository_id=repo_id,
        pr_number=101,
        pr_title="Alice Secret Fix PR",
        head_commit_sha="c" * 40,
        base_commit_sha="d" * 40,
        status="completed",
        findings_diff_json="[]",
        changed_files='["src/auth.py"]',
    )
    db_session.add(pr_scan)
    db_session.commit()
    db_session.refresh(pr_scan)
    pr_scan_id = pr_scan.id

    return {
        "repo_id": repo_id,
        "finding_id": finding_id,
        "scan_id": scan_id,
        "run_id": run_id,
        "evidence_id": evidence_id,
        "pr_scan_id": pr_scan_id,
    }


def test_cross_user_repository_access_denied(client_b: TestClient, alice_and_bob_setup):
    """Bob cannot view details, status, or delete Alice's repository."""
    repo_id = alice_and_bob_setup["repo_id"]

    # Bob GET repo details -> 403
    res_get = client_b.get(f"/api/v1/repositories/{repo_id}")
    assert res_get.status_code == 403
    assert res_get.json()["error"]["code"] == "FORBIDDEN"

    # Bob GET ingestion status -> 403
    res_status = client_b.get(f"/api/v1/repositories/{repo_id}/ingestion-status")
    assert res_status.status_code == 403
    assert res_status.json()["error"]["code"] == "FORBIDDEN"

    # Bob DELETE repo -> 403
    res_del = client_b.delete(f"/api/v1/repositories/{repo_id}")
    assert res_del.status_code == 403
    assert res_del.json()["error"]["code"] == "FORBIDDEN"


def test_cross_user_finding_access_denied(client_b: TestClient, alice_and_bob_setup):
    """Bob cannot access, prioritize, validate, or analyze Alice's security finding."""
    fid = alice_and_bob_setup["finding_id"]

    # GET finding
    res_get = client_b.get(f"/api/v1/findings/{fid}")
    assert res_get.status_code == 403
    assert res_get.json()["error"]["code"] == "FORBIDDEN"

    # GET prioritization
    res_prio = client_b.get(f"/api/v1/findings/{fid}/prioritization")
    assert res_prio.status_code == 403
    assert res_prio.json()["error"]["code"] == "FORBIDDEN"

    # POST prioritize with environment
    res_env = client_b.post(f"/api/v1/findings/{fid}/prioritize", json={"is_internet_facing": True})
    assert res_env.status_code == 403
    assert res_env.json()["error"]["code"] == "FORBIDDEN"

    # POST validate finding
    res_val = client_b.post(f"/api/v1/findings/{fid}/validate", json={})
    assert res_val.status_code == 403
    assert res_val.json()["error"]["code"] == "FORBIDDEN"

    # GET validation history
    res_val_hist = client_b.get(f"/api/v1/findings/{fid}/validations")
    assert res_val_hist.status_code == 403
    assert res_val_hist.json()["error"]["code"] == "FORBIDDEN"

    # GET analyses
    res_analyses = client_b.get(f"/api/v1/findings/{fid}/analyses")
    assert res_analyses.status_code == 403
    assert res_analyses.json()["error"]["code"] == "FORBIDDEN"

    # POST /api/v1/analyze-finding pointing to Alice's finding
    res_ai = client_b.post(
        "/api/v1/analyze-finding",
        json={"finding_id": fid, "user_authorized_analysis": True},
    )
    assert res_ai.status_code == 403
    assert res_ai.json()["error"]["code"] == "FORBIDDEN"


def test_cross_user_scan_access_denied(client_b: TestClient, alice_and_bob_setup):
    """Bob cannot access details, status, or results of Alice's security scan."""
    scan_id = alice_and_bob_setup["scan_id"]

    # GET scan details
    res_get = client_b.get(f"/api/v1/scans/{scan_id}")
    assert res_get.status_code == 403
    assert res_get.json()["error"]["code"] == "FORBIDDEN"

    # GET scan status
    res_status = client_b.get(f"/api/v1/scans/{scan_id}/status")
    assert res_status.status_code == 403
    assert res_status.json()["error"]["code"] == "FORBIDDEN"

    # GET scan results
    res_results = client_b.get(f"/api/v1/scans/{scan_id}/results")
    assert res_results.status_code == 403
    assert res_results.json()["error"]["code"] == "FORBIDDEN"


def test_cross_user_verification_run_access_denied(client_b: TestClient, alice_and_bob_setup):
    """Bob cannot access, rerun, or approve Alice's verification runs."""
    run_id = alice_and_bob_setup["run_id"]

    # GET verification run
    res_get = client_b.get(f"/api/v1/verifications/{run_id}")
    assert res_get.status_code == 403
    assert res_get.json()["error"]["code"] == "FORBIDDEN"

    # POST rerun
    res_rerun = client_b.post(f"/api/v1/verifications/{run_id}/rerun")
    assert res_rerun.status_code == 403
    assert res_rerun.json()["error"]["code"] == "FORBIDDEN"

    # POST approve-and-merge
    res_merge = client_b.post(f"/api/v1/verifications/{run_id}/approve-and-merge")
    assert res_merge.status_code == 403
    assert res_merge.json()["error"]["code"] == "FORBIDDEN"


def test_cross_user_evidence_and_reports_access_denied(client_b: TestClient, alice_and_bob_setup):
    """Bob cannot view evidence artifacts or generate/download reports for Alice's resources."""
    repo_id = alice_and_bob_setup["repo_id"]
    ev_id = alice_and_bob_setup["evidence_id"]
    run_id = alice_and_bob_setup["run_id"]

    # GET individual evidence
    res_ev = client_b.get(f"/api/v1/evidence/{ev_id}")
    assert res_ev.status_code == 403
    assert res_ev.json()["error"]["code"] == "FORBIDDEN"

    # GET evidence integrity check
    res_ev_int = client_b.get(f"/api/v1/evidence/{ev_id}/verify-integrity")
    assert res_ev_int.status_code == 403
    assert res_ev_int.json()["error"]["code"] == "FORBIDDEN"

    # GET findings report export
    res_fr = client_b.get(f"/api/v1/evidence/reports/findings?repo_id={repo_id}")
    assert res_fr.status_code == 403
    assert res_fr.json()["error"]["code"] == "FORBIDDEN"

    # GET findings report download
    res_fr_dl = client_b.get(f"/api/v1/evidence/reports/findings/download?repo_id={repo_id}")
    assert res_fr_dl.status_code == 403
    assert res_fr_dl.json()["error"]["code"] == "FORBIDDEN"

    # GET verification report export
    res_vr = client_b.get(f"/api/v1/evidence/reports/verification/{run_id}")
    assert res_vr.status_code == 403
    assert res_vr.json()["error"]["code"] == "FORBIDDEN"

    # GET verification report download
    res_vr_dl = client_b.get(f"/api/v1/evidence/reports/verification/{run_id}/download")
    assert res_vr_dl.status_code == 403
    assert res_vr_dl.json()["error"]["code"] == "FORBIDDEN"

    # GET verification run integrity
    res_vri = client_b.get(f"/api/v1/evidence/verification-runs/{run_id}/verify-integrity")
    assert res_vri.status_code == 403
    assert res_vri.json()["error"]["code"] == "FORBIDDEN"


def test_cross_user_github_integrations_denied(client_b: TestClient, alice_and_bob_setup):
    """Bob cannot view PR scans or publish comments on Alice's repository PRs."""
    pr_scan_id = alice_and_bob_setup["pr_scan_id"]

    # GET PR scan details
    res_pr = client_b.get(f"/api/v1/integrations/github/pr-scans/{pr_scan_id}")
    assert res_pr.status_code == 403
    assert res_pr.json()["error"]["code"] == "FORBIDDEN"

    # POST publish PR comment
    res_pub = client_b.post(
        f"/api/v1/integrations/github/pr-scans/{pr_scan_id}/publish",
        json={"publish_comment": True},
    )
    assert res_pub.status_code == 403
    assert res_pub.json()["error"]["code"] == "FORBIDDEN"


# ==============================================================================
# 5. Sensitive Information Leakage Prevention & Audit Events (Task 12)
# ==============================================================================

def test_failed_authorization_does_not_leak_sensitive_information(client_b: TestClient, alice_and_bob_setup):
    """When authorization fails, response must contain only generic error info, no resource leaks."""
    endpoints_to_test = [
        f"/api/v1/repositories/{alice_and_bob_setup['repo_id']}",
        f"/api/v1/findings/{alice_and_bob_setup['finding_id']}",
        f"/api/v1/scans/{alice_and_bob_setup['scan_id']}",
        f"/api/v1/verifications/{alice_and_bob_setup['run_id']}",
        f"/api/v1/evidence/{alice_and_bob_setup['evidence_id']}",
        f"/api/v1/integrations/github/pr-scans/{alice_and_bob_setup['pr_scan_id']}",
    ]

    for ep in endpoints_to_test:
        res = client_b.get(ep)
        assert res.status_code == 403
        data = res.json()

        # Must have standard error structure
        assert data["success"] is False
        assert "error" in data
        assert "code" in data["error"]
        assert "message" in data["error"]

        # Must NOT leak secret query, code excerpt, repo name, git url, or patch diff
        raw_text = res.text
        assert "SELECT * FROM secrets" not in raw_text
        assert "cursor.execute" not in raw_text
        assert "Alice Secret Fix" not in raw_text
        assert "alice/core-engine" not in raw_text
        assert "https://github.com/alice" not in raw_text


def test_failed_authorization_records_security_audit_event(
    client_b: TestClient,
    alice_and_bob_setup,
    db_session: Session,
):
    """Every blocked cross-user attempt must generate an audited security event."""
    repo_id = alice_and_bob_setup["repo_id"]
    finding_id = alice_and_bob_setup["finding_id"]
    scan_id = alice_and_bob_setup["scan_id"]
    run_id = alice_and_bob_setup["run_id"]
    ev_id = alice_and_bob_setup["evidence_id"]

    client_b.get(f"/api/v1/repositories/{repo_id}")
    client_b.get(f"/api/v1/findings/{finding_id}")
    client_b.get(f"/api/v1/scans/{scan_id}")
    client_b.get(f"/api/v1/verifications/{run_id}")
    client_b.get(f"/api/v1/evidence/{ev_id}")

    actions = {
        "UNAUTHORIZED_REPO_ACCESS_BLOCKED",
        "UNAUTHORIZED_FINDING_ACCESS_BLOCKED",
        "UNAUTHORIZED_SCAN_ACCESS_BLOCKED",
        "UNAUTHORIZED_VERIFICATION_ACCESS_BLOCKED",
        "UNAUTHORIZED_EVIDENCE_ACCESS_BLOCKED",
    }

    recorded_actions = {
        event.action
        for event in db_session.query(AuditEvent)
        .filter(AuditEvent.actor_id == client_b.user.id)
        .all()
    }

    for action in actions:
        assert action in recorded_actions, f"Audit event '{action}' was not recorded!"
