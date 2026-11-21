"""Comprehensive tests for authentication, authorization, token validation, rate limiting, and config security."""
import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import Settings, settings
from app.core.security import auth_rate_limiter, create_access_token
from app.models.finding import SecurityFinding
from app.models.repository import Repository
from app.models.user import User


# ============================================================================
# 1. Unauthorized Requests: Verify Unauthenticated Access is Strictly Blocked
# ============================================================================

@pytest.mark.parametrize(
    "method,endpoint,payload",
    [
        ("GET", "/api/v1/auth/me", None),
        ("GET", "/api/v1/repositories", None),
        ("POST", "/api/v1/repositories", {"name": "test/repo", "git_url": "https://github.com/test/repo"}),
        ("GET", "/api/v1/scans", None),
        ("POST", "/api/v1/scans", {"repository_id": "dummy-id"}),
        ("GET", "/api/v1/findings", None),
        ("POST", "/api/v1/analyze-finding", {"code_excerpt": "eval(x)"}),
        ("GET", "/api/v1/prioritization/remediation-queue", None),
        ("GET", "/api/v1/evidence?repo_id=dummy-id", None),
        ("POST", "/api/v1/evidence", {"repository_id": "dummy-id", "evidence_category": "scanner_finding", "title": "test", "tool_name": "test", "raw_payload": {}}),
        ("GET", "/api/v1/integrations/github/installations", None),
        ("POST", "/api/v1/integrations/ci/evaluate", {"repository_id": "dummy-id", "head_commit_sha": "abc123"}),
    ],
)
def test_unauthenticated_requests_return_401(client: TestClient, method: str, endpoint: str, payload: dict):
    """Ensure that all sensitive endpoints reject requests that lack authentication tokens."""
    # Ensure client has no Authorization header
    client.headers.pop("Authorization", None)
    client.cookies.clear()

    if method == "GET":
        response = client.get(endpoint)
    elif method == "POST":
        response = client.post(endpoint, json=payload)
    elif method == "DELETE":
        response = client.delete(endpoint)
    else:
        pytest.fail(f"Unsupported HTTP method {method}")

    assert response.status_code == 401, f"Expected 401 for {method} {endpoint}, got {response.status_code}: {response.text}"
    data = response.json()
    assert data["success"] is False
    assert data["error"]["code"] in ("UNAUTHORIZED", "SESSION_EXPIRED")


# ============================================================================
# 2. Token Security: Invalid, Malformed, Corrupted, or Tampered Tokens
# ============================================================================

def test_malformed_bearer_token_returns_401(client: TestClient):
    """Corrupted bearer tokens must be cleanly rejected with 401."""
    client.headers["Authorization"] = "Bearer this.is.a.malformed.token"
    res = client.get("/api/v1/auth/me")
    assert res.status_code == 401
    assert res.json()["error"]["code"] == "UNAUTHORIZED"


def test_token_signed_with_wrong_key_returns_401(client: TestClient, user_a: User):
    """Tokens signed with an attacker's or foreign secret key must fail signature verification."""
    attacker_secret = "completely-wrong-attacker-secret-key-32chars"
    forged_token = jwt.encode(
        {"sub": user_a.id, "email": user_a.email},
        attacker_secret,
        algorithm="HS256",
    )
    client.headers["Authorization"] = f"Bearer {forged_token}"
    res = client.get("/api/v1/auth/me")
    assert res.status_code == 401
    assert res.json()["error"]["code"] == "UNAUTHORIZED"


def test_token_missing_subject_claim_returns_401(client: TestClient):
    """Tokens missing the 'sub' claim cannot identify an actor and must be rejected."""
    token_without_sub = jwt.encode(
        {"email": "nobody@xerova.com"},
        settings.SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    client.headers["Authorization"] = f"Bearer {token_without_sub}"
    res = client.get("/api/v1/auth/me")
    assert res.status_code == 401
    assert res.json()["error"]["code"] == "UNAUTHORIZED"


def test_token_with_nonexistent_user_returns_401(client: TestClient):
    """Tokens referencing deleted or nonexistent user IDs must be rejected."""
    ghost_token = create_access_token({"sub": "usr-ghost-nonexistent-id", "email": "ghost@xerova.com"})
    client.headers["Authorization"] = f"Bearer {ghost_token}"
    res = client.get("/api/v1/auth/me")
    assert res.status_code == 401
    assert res.json()["error"]["code"] == "UNAUTHORIZED"


# ============================================================================
# 3. Multi-Tenant Authorization: Cross-User Access Isolation
# ============================================================================

def test_cross_user_vulnerability_validation_blocked(client_a: TestClient, client_b: TestClient):
    """User B must be strictly forbidden from validating or viewing validation for User A's finding."""
    # 1. User A creates repository & finding
    repo_res = client_a.post("/api/v1/repositories", json={"name": "alice/auth", "git_url": "https://github.com/alice/auth"})
    repo_id = repo_res.json()["id"]

    find_res = client_a.post("/api/v1/findings", json={
        "repo_id": repo_id,
        "cwe": "CWE-798: Hardcoded Credentials",
        "title": "AWS Secret Key Committed",
        "severity": "CRITICAL",
        "scanner_name": "Gitleaks",
        "file_path": "config.py",
        "line_number": 10,
    })
    finding_id = find_res.json()["id"]

    # 2. User B attempts to trigger validation on User A's finding -> 403 Forbidden
    validate_res = client_b.post(f"/api/v1/findings/{finding_id}/validate", json={})
    assert validate_res.status_code == 403
    assert validate_res.json()["error"]["code"] == "FORBIDDEN"

    # 3. User B attempts to get validation history for User A's finding -> 403 Forbidden
    history_res = client_b.get(f"/api/v1/findings/{finding_id}/validations")
    assert history_res.status_code == 403
    assert history_res.json()["error"]["code"] == "FORBIDDEN"


def test_cross_user_evidence_and_reports_blocked(client_a: TestClient, client_b: TestClient):
    """User B must be forbidden from listing, creating, or exporting evidence for User A's repo."""
    # 1. User A creates repository
    repo_res = client_a.post("/api/v1/repositories", json={"name": "alice/sec-repo", "git_url": "https://github.com/alice/sec-repo"})
    repo_id = repo_res.json()["id"]

    # 2. User B attempts to list evidence for Alice's repo -> 403 Forbidden
    list_res = client_b.get(f"/api/v1/evidence?repo_id={repo_id}")
    assert list_res.status_code == 403
    assert list_res.json()["error"]["code"] == "FORBIDDEN"

    # 3. User B attempts to record evidence for Alice's repo -> 403 Forbidden
    create_res = client_b.post("/api/v1/evidence", json={
        "repository_id": repo_id,
        "evidence_category": "scanner_finding",
        "title": "Malicious Injected Evidence",
        "tool_name": "AttackerTool",
        "raw_payload": {"injected": True},
    })
    assert create_res.status_code == 403
    assert create_res.json()["error"]["code"] == "FORBIDDEN"

    # 4. User B attempts to export findings report for Alice's repo -> 403 Forbidden
    report_res = client_b.get(f"/api/v1/evidence/reports/findings?repo_id={repo_id}")
    assert report_res.status_code == 403
    assert report_res.json()["error"]["code"] == "FORBIDDEN"


def test_cross_user_github_linking_and_ci_gate_blocked(client_a: TestClient, client_b: TestClient):
    """User B cannot link GitHub integration or evaluate CI security gate on User A's repo."""
    # 1. User A creates repository
    repo_res = client_a.post("/api/v1/repositories", json={"name": "alice/ci-service", "git_url": "https://github.com/alice/ci-service"})
    repo_id = repo_res.json()["id"]

    # 2. User B attempts to link Alice's repo to Bob's GitHub app -> 403 Forbidden
    link_res = client_b.post("/api/v1/integrations/github/links", json={
        "repository_id": repo_id,
        "installation_id": "inst-bob-123",
        "github_repo_full_name": "bob/ci-service",
    })
    assert link_res.status_code == 403
    assert link_res.json()["error"]["code"] == "FORBIDDEN"

    # 3. User B attempts to trigger CI evaluation on Alice's repo -> 403 Forbidden
    ci_res = client_b.post("/api/v1/integrations/ci/evaluate", json={
        "repository_id": repo_id,
        "head_commit_sha": "a" * 40,
    })
    assert ci_res.status_code == 403
    assert ci_res.json()["error"]["code"] == "FORBIDDEN"


# ============================================================================
# 4. Authentication Rate Limiting
# ============================================================================

def test_authentication_rate_limiting_triggers_429(client: TestClient):
    """Rapid repeated authentication requests from an IP must be throttled with HTTP 429."""
    auth_rate_limiter.reset()

    # Perform 10 allowed attempts
    for _ in range(settings.AUTH_RATE_LIMIT_LOGIN_MAX):
        res = client.post("/api/v1/auth/login", json={"email": "ratelimit@xerova.com", "password": "WrongPassword!"})
        assert res.status_code in (401, 200)

    # 11th attempt must be rate limited
    throttled_res = client.post("/api/v1/auth/login", json={"email": "ratelimit@xerova.com", "password": "WrongPassword!"})
    assert throttled_res.status_code == 429
    assert throttled_res.headers.get("Retry-After") is not None
    data = throttled_res.json()
    assert data["success"] is False
    assert data["error"]["code"] == "RATE_LIMIT_EXCEEDED"

    # Reset limiter after test
    auth_rate_limiter.reset()


# ============================================================================
# 5. Production Configuration Safety: Missing/Insecure Secrets Fail at Startup
# ============================================================================

def test_production_rejects_insecure_default_secret_key():
    """Settings must raise ValueError if production runs with insecure default SECRET_KEY."""
    with pytest.raises(ValueError, match="SECRET_KEY"):
        Settings(
            APP_ENV="production",
            SECRET_KEY="dev-insecure-secret-key-32-chars-long!!",
            DATABASE_URL="postgresql://user:pass@localhost/db",
            DEBUG=False,
            CORS_ORIGINS=["https://app.redmercury.io"],
            ALLOW_PRIVATE_NETWORKS=False,
            SANDBOX_ALLOW_HOST_FALLBACK=False,
        )


def test_production_rejects_short_secret_key():
    """Settings must raise ValueError if production runs with SECRET_KEY shorter than 32 chars."""
    with pytest.raises(ValueError, match="SECRET_KEY"):
        Settings(
            APP_ENV="production",
            SECRET_KEY="short-secret-key-12345",
            DATABASE_URL="postgresql://user:pass@localhost/db",
            DEBUG=False,
            CORS_ORIGINS=["https://app.redmercury.io"],
            ALLOW_PRIVATE_NETWORKS=False,
            SANDBOX_ALLOW_HOST_FALLBACK=False,
        )


def test_production_rejects_sqlite_database():
    """Settings must raise ValueError if production attempts to use SQLite."""
    with pytest.raises(ValueError, match="SQLite cannot be used in production"):
        Settings(
            APP_ENV="production",
            SECRET_KEY="a" * 32,
            DATABASE_URL="sqlite:///./redmercury.db",
            DEBUG=False,
            CORS_ORIGINS=["https://app.redmercury.io"],
            ALLOW_PRIVATE_NETWORKS=False,
            SANDBOX_ALLOW_HOST_FALLBACK=False,
        )


def test_production_rejects_wildcard_cors():
    """Settings must raise ValueError if production allows wildcard '*' CORS origins."""
    with pytest.raises(ValueError, match="Wildcard '\\*' in CORS_ORIGINS is strictly prohibited"):
        Settings(
            APP_ENV="production",
            SECRET_KEY="a" * 32,
            DATABASE_URL="postgresql://user:pass@localhost/db",
            DEBUG=False,
            CORS_ORIGINS=["*"],
            ALLOW_PRIVATE_NETWORKS=False,
            SANDBOX_ALLOW_HOST_FALLBACK=False,
        )


def test_production_rejects_private_network_ssrf_bypass():
    """Settings must raise ValueError if production has ALLOW_PRIVATE_NETWORKS=True."""
    with pytest.raises(ValueError, match="ALLOW_PRIVATE_NETWORKS must be False"):
        Settings(
            APP_ENV="production",
            SECRET_KEY="a" * 32,
            DATABASE_URL="postgresql://user:pass@localhost/db",
            DEBUG=False,
            CORS_ORIGINS=["https://app.redmercury.io"],
            ALLOW_PRIVATE_NETWORKS=True,
            SANDBOX_ALLOW_HOST_FALLBACK=False,
        )


# ============================================================================
# 6. GitHub Webhook Security: Signature Enforcement and Secret Decoupling
# ============================================================================

def test_github_webhook_missing_delivery_header_rejected(client: TestClient):
    """Webhook ingestion without X-GitHub-Delivery must be rejected with 403 (replay defense)."""
    res = client.post("/api/v1/integrations/github/webhook", json={"action": "ping"})
    assert res.status_code == 403
    assert "delivery" in res.json()["error"]["message"].lower()


def test_github_webhook_missing_signature_rejected(client: TestClient):
    """Webhook ingestion without X-Hub-Signature-256 header must return 401 Unauthorized."""
    res = client.post(
        "/api/v1/integrations/github/webhook",
        json={"action": "ping"},
        headers={"X-GitHub-Delivery": "test-delivery-id-001", "X-GitHub-Event": "ping"},
    )
    assert res.status_code == 401
    assert "signature" in res.json()["error"]["message"].lower()


def test_github_webhook_invalid_signature_rejected(client: TestClient, monkeypatch):
    """Webhook ingestion with invalid signature must return 401 Unauthorized."""
    # Configure webhook secret
    monkeypatch.setattr(settings, "GITHUB_WEBHOOK_SECRET", "super-secret-webhook-key")
    res = client.post(
        "/api/v1/integrations/github/webhook",
        json={"action": "ping"},
        headers={
            "X-GitHub-Event": "ping",
            "X-GitHub-Delivery": "test-delivery-id-002",
            "X-Hub-Signature-256": "sha256=invalid0000000000000000000000000000000000000000000000000000000000",
        },
    )
    assert res.status_code == 401
    assert "signature" in res.json()["error"]["message"].lower()


def test_github_webhook_no_secret_configured_fails_closed(client: TestClient, monkeypatch):
    """Webhook verification fails closed if no webhook secret is configured."""
    monkeypatch.setattr(settings, "GITHUB_WEBHOOK_SECRET", None)
    res = client.post(
        "/api/v1/integrations/github/webhook",
        json={"action": "ping"},
        headers={
            "X-GitHub-Event": "ping",
            "X-GitHub-Delivery": "test-delivery-id-003",
            "X-Hub-Signature-256": "sha256=abcdef0000000000000000000000000000000000000000000000000000000000",
        },
    )
    assert res.status_code == 401
    assert "not configured" in res.json()["error"]["message"].lower()
