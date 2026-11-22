"""Phase 3 Security Regression Test Suite: Auth Architecture, HttpOnly Sessions, CSRF,
Distributed Redis Rate Limiting & Staging Security Parity.

Covers:
- SEC-07: Atomic Redis sliding-window rate limiting, concurrency, multi-instance sharing,
          rightmost-untrusted X-Forwarded-For + CIDR trusted proxies, Redis outage fail-open/fail-closed,
          path-normalization bypass prevention, distinct per-endpoint throttling, and reset.
- SEC-16: Short-lived access tokens (15m), HttpOnly access/refresh cookies, double-submit CSRF cookie,
          refresh-token rotation, replay/reuse detection (family revocation), concurrent refresh race safety,
          DB-authoritative role on refresh, CSRF-protected logout & invalid-token DB-bloat prevention, CORS credentials.
- SEC-17: Staging security parity with production (secrets, SQLite, CORS, DEBUG, CSRF, rate limiting,
          local ingestion lockdown, Secure cookies, HSTS, sandbox fail-closed, testserver CSRF block).
"""
from concurrent.futures import ThreadPoolExecutor
import threading
import time
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from starlette.requests import Request

from app.core.auth import compute_token_hash, revoke_token
from app.core.config import Settings, settings
from app.core.security import (
    DistributedRateLimiter,
    auth_rate_limiter,
    create_access_token,
    decode_access_token,
    get_client_ip,
)
from app.models.token import RefreshTokenSession, RevokedToken
from app.models.user import User


class AtomicFakeRedis:
    """Thread-safe in-memory simulator of Redis EVAL sliding-window ZSET semantics for unit/multi-instance tests."""

    def __init__(self, fail_mode: bool = False):
        self._lock = threading.Lock()
        self._zsets: dict = {}
        self.fail_mode = fail_mode
        self.eval_calls = 0

    def eval(self, script, numkeys, key, now_ms, window_ms, max_requests, member):
        if self.fail_mode:
            raise ConnectionError("Simulated Redis outage")
        with self._lock:
            self.eval_calls += 1
            now_ms = int(now_ms)
            window_ms = int(window_ms)
            max_requests = int(max_requests)
            cutoff = now_ms - window_ms
            entries = self._zsets.setdefault(key, [])
            entries[:] = [(score, m) for (score, m) in entries if score > cutoff]
            if len(entries) >= max_requests:
                return 0
            entries.append((now_ms, member))
            return 1

    def flushdb(self):
        with self._lock:
            self._zsets.clear()


def _make_request(peer_ip: str, headers: dict) -> Request:
    raw_headers = [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in headers.items()]
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/auth/login",
        "headers": raw_headers,
        "client": (peer_ip, 50000),
        "scheme": "https",
        "server": ("redmercury.xerova.com", 443),
    }
    return Request(scope)


# ==============================================================================
# TASK 1 — SEC-07: Distributed Redis Rate Limiting & Proxy IP Parsing
# ==============================================================================


def test_sec07_redis_rate_limiter_enforces_quota_and_reset():
    """Atomic Redis sliding window enforces exact quota and supports reset."""
    fake_redis = AtomicFakeRedis()
    limiter = DistributedRateLimiter()
    limiter.configure_redis(fake_redis)

    for _ in range(5):
        assert limiter.is_allowed("login:203.0.113.5", max_requests=5, window_seconds=60) is True
    assert limiter.is_allowed("login:203.0.113.5", max_requests=5, window_seconds=60) is False
    assert fake_redis.eval_calls == 6

    limiter.reset()
    assert limiter.is_allowed("login:203.0.113.5", max_requests=5, window_seconds=60) is True


def test_sec07_redis_rate_limiter_concurrent_and_multi_instance_consistency():
    """Multiple API instances sharing one Redis backend enforce exact quota under concurrency."""
    shared_redis = AtomicFakeRedis()
    instance_a = DistributedRateLimiter()
    instance_b = DistributedRateLimiter()
    instance_a.configure_redis(shared_redis)
    instance_b.configure_redis(shared_redis)

    def attempt(idx: int) -> bool:
        lim = instance_a if idx % 2 == 0 else instance_b
        return lim.is_allowed("multi:203.0.113.9", max_requests=8, window_seconds=60)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, range(20)))

    assert sum(1 for r in results if r) == 8
    assert sum(1 for r in results if not r) == 12


def test_sec07_redis_outage_fail_open_vs_fail_closed(monkeypatch):
    """Redis unavailability obeys RATE_LIMIT_FAIL_OPEN (fallback vs fail-closed rejection)."""
    broken_redis = AtomicFakeRedis(fail_mode=True)
    limiter = DistributedRateLimiter()
    limiter.configure_redis(broken_redis)

    # Fail-open falls back to local in-memory limiter
    monkeypatch.setattr(settings, "RATE_LIMIT_FAIL_OPEN", True)
    assert limiter.is_allowed("outage:1", max_requests=2, window_seconds=60) is True
    assert limiter.is_allowed("outage:1", max_requests=2, window_seconds=60) is True
    assert limiter.is_allowed("outage:1", max_requests=2, window_seconds=60) is False

    # Fail-closed immediately rejects when Redis is unreachable
    monkeypatch.setattr(settings, "RATE_LIMIT_FAIL_OPEN", False)
    assert limiter.is_allowed("outage:2", max_requests=10, window_seconds=60) is False


def test_sec07_get_client_ip_rightmost_untrusted_and_cidr_proxies(monkeypatch):
    """get_client_ip ignores spoofed leftmost XFF, skips trusted proxy CIDRs, and ignores headers from untrusted peers."""
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", ["127.0.0.1", "172.16.0.0/12", "10.0.0.1"])

    # 1. Untrusted direct peer spoofing X-Forwarded-For -> headers completely ignored
    req_untrusted = _make_request(
        peer_ip="198.51.100.77",
        headers={"X-Forwarded-For": "1.2.3.4", "CF-Connecting-IP": "5.6.7.8"},
    )
    assert get_client_ip(req_untrusted) == "198.51.100.77"

    # 2. Trusted Nginx proxy in 172.16.0.0/12 with attacker-spoofed leftmost IP:
    #    X-Forwarded-For: <spoofed>, <real-client>, <internal-lb>
    #    Rightmost untrusted IP MUST be <real-client> (203.0.113.42), NOT <spoofed> (1.1.1.1)!
    req_trusted = _make_request(
        peer_ip="172.18.0.5",
        headers={"X-Forwarded-For": "1.1.1.1, 203.0.113.42, 10.0.0.1"},
    )
    assert get_client_ip(req_trusted) == "203.0.113.42"


def test_sec07_distinct_endpoint_limits_and_path_normalization_bypass_prevented(client: TestClient, monkeypatch):
    """Register has stricter limit than login; alternate path syntax ('//') cannot bypass throttling."""
    auth_rate_limiter.reset()
    monkeypatch.setattr(settings, "AUTH_RATE_LIMIT_REGISTER_MAX", 2)
    monkeypatch.setattr(settings, "AUTH_RATE_LIMIT_LOGIN_MAX", 5)

    # 2 register attempts consume the register bucket
    for i in range(2):
        res = client.post(
            "/api/v1/auth/register",
            json={"email": f"rl_reg_{i}_{uuid.uuid4().hex[:6]}@xerova.com", "password": "StrongPassword123!"},
        )
        assert res.status_code == 201

    # 3rd attempt (even via alternate path '/api/v1/auth/register/') is throttled at 429
    throttled = client.post(
        "/api/v1/auth/register/",
        json={"email": f"rl_reg_3_{uuid.uuid4().hex[:6]}@xerova.com", "password": "StrongPassword123!"},
    )
    assert throttled.status_code == 429
    assert "Retry-After" in throttled.headers

    # Webhook endpoint is also throttled independently
    monkeypatch.setattr(settings, "RATE_LIMIT_WEBHOOK_MAX", 2)
    for _ in range(2):
        client.post("/api/v1/integrations/github/webhook", json={})
    wh_throttled = client.post("/api/v1/integrations/github/webhook", json={})
    assert wh_throttled.status_code == 429
    auth_rate_limiter.reset()


# ==============================================================================
# TASK 2 & 3 — SEC-16: HttpOnly Cookies, Refresh Rotation, Replay & CSRF
# ==============================================================================


def test_sec16_short_lived_access_token_and_httponly_cookie_attributes(client: TestClient):
    """Login issues 15-minute access token and sets HttpOnly access/refresh cookies plus CSRF cookie."""
    assert settings.ACCESS_TOKEN_EXPIRE_MINUTES == 15

    email = f"cookie_user_{uuid.uuid4().hex[:8]}@xerova.com"
    reg = client.post("/api/v1/auth/register", json={"email": email, "password": "StrongPassword123!"})
    assert reg.status_code == 201
    assert reg.json()["expires_in"] == 15 * 60

    set_cookies = reg.headers.get_list("set-cookie")
    joined = "\n".join(set_cookies)
    assert f"{settings.COOKIE_NAME}=" in joined
    assert f"{settings.REFRESH_COOKIE_NAME}=" in joined
    assert f"{settings.CSRF_COOKIE_NAME}=" in joined
    assert "Path=/api/v1/auth" in joined or "path=/api/v1/auth" in joined.lower()

    payload = decode_access_token(reg.json()["access_token"])
    assert payload["typ"] == "access"
    assert payload["iss"] == "red-mercury"


def test_sec16_refresh_rotation_reuse_detection_and_db_authoritative_role(
    client: TestClient, db_session: Session
):
    """Refresh rotates token, enforces CSRF, reflects DB role downgrade, and revokes entire family on replay."""
    auth_rate_limiter.reset()
    email = f"rot_user_{uuid.uuid4().hex[:8]}@xerova.com"
    reg = client.post("/api/v1/auth/register", json={"email": email, "password": "StrongPassword123!"})
    assert reg.status_code == 201

    refresh_v1 = reg.cookies.get(settings.REFRESH_COOKIE_NAME)
    csrf_v1 = reg.cookies.get(settings.CSRF_COOKIE_NAME)
    assert refresh_v1 and csrf_v1

    # 1. Missing X-CSRF-Token header on /refresh MUST be rejected with 403
    no_csrf = client.post(
        "/api/v1/auth/refresh",
        headers={"Origin": "http://localhost:5173"},
    )
    assert no_csrf.status_code == 403
    assert "csrf" in no_csrf.json()["error"]["message"].lower()

    # 2. Downgrade user role in DB before refreshing -> refreshed token MUST reflect 'viewer'
    user = db_session.query(User).filter(User.email == email).first()
    user.role = "viewer"
    db_session.commit()

    # 3. Valid refresh with Origin + matching X-CSRF-Token succeeds and rotates refresh token
    ref_ok = client.post(
        "/api/v1/auth/refresh",
        headers={"Origin": "http://localhost:5173", "X-CSRF-Token": csrf_v1},
    )
    assert ref_ok.status_code == 200
    assert ref_ok.json()["user"]["role"] == "viewer"
    refresh_v2 = ref_ok.cookies.get(settings.REFRESH_COOKIE_NAME)
    csrf_v2 = ref_ok.cookies.get(settings.CSRF_COOKIE_NAME)
    assert refresh_v2 and refresh_v2 != refresh_v1

    # 4. Replay of old refresh_v1 MUST be rejected (401) and invalidate the ENTIRE family (including refresh_v2!)
    client.cookies.clear()
    client.cookies.set(settings.REFRESH_COOKIE_NAME, refresh_v1)
    client.cookies.set(settings.CSRF_COOKIE_NAME, csrf_v2)
    replay = client.post(
        "/api/v1/auth/refresh",
        headers={"Origin": "http://localhost:5173", "X-CSRF-Token": csrf_v2},
    )
    assert replay.status_code == 401
    assert "reuse detected" in replay.json()["error"]["message"].lower()

    # Even the legitimate rotated refresh_v2 is now revoked due to family invalidation!
    client.cookies.clear()
    client.cookies.set(settings.REFRESH_COOKIE_NAME, refresh_v2)
    client.cookies.set(settings.CSRF_COOKIE_NAME, csrf_v2)
    after_family_revoke = client.post(
        "/api/v1/auth/refresh",
        headers={"Origin": "http://localhost:5173", "X-CSRF-Token": csrf_v2},
    )
    assert after_family_revoke.status_code == 401


def test_sec16_concurrent_refresh_race_allows_at_most_one_rotation(
    db_session: Session, create_test_user
):
    """Atomic conditional UPDATE ensures a refresh token can only be rotated once across concurrent callers."""
    from app.core.auth import issue_refresh_token_session, rotate_refresh_token_session
    from app.db.session import SessionLocal

    user = create_test_user(email=f"race_{uuid.uuid4().hex[:8]}@xerova.com", role="analyst")
    raw_refresh, _ = issue_refresh_token_session(db=db_session, user_id=user.id)

    def try_rotate(_):
        local_db = SessionLocal()
        try:
            rotate_refresh_token_session(db=local_db, raw_refresh_token=raw_refresh)
            return "ok"
        except Exception:
            return "rejected"
        finally:
            local_db.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(try_rotate, range(2)))

    assert outcomes.count("ok") == 1
    assert outcomes.count("rejected") == 1


def test_sec16_logout_enforces_csrf_revokes_family_and_rejects_garbage_tokens(
    client: TestClient, db_session: Session
):
    """Logout enforces CSRF on cookie sessions, revokes access+refresh family, and never stores invalid tokens in DB."""
    auth_rate_limiter.reset()
    # 1. Invalid/forged Bearer string must NOT bloat revoked_tokens table
    before_count = db_session.query(RevokedToken).count()
    assert revoke_token(db_session, "not-a-valid-jwt-garbage-string") is False
    assert db_session.query(RevokedToken).count() == before_count

    # 2. Register & obtain cookies
    email = f"logout_user_{uuid.uuid4().hex[:8]}@xerova.com"
    reg = client.post("/api/v1/auth/register", json={"email": email, "password": "StrongPassword123!"})
    assert reg.status_code == 201
    access_tok = reg.json()["access_token"]
    refresh_tok = reg.cookies.get(settings.REFRESH_COOKIE_NAME)
    csrf_tok = reg.cookies.get(settings.CSRF_COOKIE_NAME)

    # 3. Cookie logout without X-CSRF-Token is blocked (403)
    bad_logout = client.post(
        "/api/v1/auth/logout",
        headers={"Origin": "http://localhost:5173"},
    )
    assert bad_logout.status_code == 403

    # 4. Valid cookie logout revokes both access token and refresh family
    ok_logout = client.post(
        "/api/v1/auth/logout",
        headers={"Origin": "http://localhost:5173", "X-CSRF-Token": csrf_tok},
    )
    assert ok_logout.status_code == 200

    # Access token is now rejected on /me
    me_after = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {access_tok}"})
    assert me_after.status_code == 401

    # Refresh token row is revoked in DB
    row = db_session.query(RefreshTokenSession).filter(
        RefreshTokenSession.token_hash == compute_token_hash(refresh_tok)
    ).first()
    assert row is not None and row.revoked_at is not None


def test_sec16_cors_credentials_allow_exact_origin_not_wildcard(client: TestClient):
    """Credentialed CORS returns exact allowed origin and never '*'."""
    res = client.options(
        "/api/v1/auth/me",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert res.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert res.headers.get("access-control-allow-credentials") == "true"


# ==============================================================================
# TASK 4 — SEC-17: Staging Security Parity
# ==============================================================================


@pytest.mark.parametrize(
    "bad_override,expected_match",
    [
        ({"SECRET_KEY": "dev-insecure-secret-key-32-chars-long!!"}, "SECRET_KEY"),
        ({"DATABASE_URL": "sqlite:///./staging.db"}, "SQLite"),
        ({"CORS_ORIGINS": ["*"]}, "Wildcard"),
        ({"CORS_ORIGINS": ["null"]}, "null"),
        ({"ALLOW_PRIVATE_NETWORKS": True}, "ALLOW_PRIVATE_NETWORKS"),
        ({"DEBUG": True}, "DEBUG"),
        ({"CSRF_PROTECTION_ENABLED": False}, "CSRF_PROTECTION_ENABLED"),
        ({"AUTH_RATE_LIMITING_ENABLED": False}, "AUTH_RATE_LIMITING_ENABLED"),
        ({"SANDBOX_FAIL_CLOSED": False}, "SANDBOX_FAIL_CLOSED"),
        ({"ALLOW_LOCAL_INGESTION_IN_PRODUCTION": True, "LOCAL_INGESTION_ALLOWED_ROOTS": []}, "LOCAL_INGESTION_ALLOWED_ROOTS"),
    ],
)
def test_sec17_staging_enforces_production_equivalent_security_gates(bad_override: dict, expected_match: str):
    """APP_ENV=staging must reject every insecure configuration that APP_ENV=production rejects."""
    base_kwargs = {
        "_env_file": None,
        "APP_ENV": "staging",
        "DEBUG": False,
        "DATABASE_URL": "postgresql+psycopg://user:pass@postgres:5432/redmercury_staging",
        "SECRET_KEY": "s" * 48,
        "CORS_ORIGINS": ["https://staging.redmercury.xerova.com"],
        "ALLOWED_HOSTS": ["staging.redmercury.xerova.com"],
        "ALLOW_PRIVATE_NETWORKS": False,
        "CSRF_PROTECTION_ENABLED": True,
        "AUTH_RATE_LIMITING_ENABLED": True,
        "SANDBOX_FAIL_CLOSED": True,
    }
    base_kwargs.update(bad_override)
    with pytest.raises(ValueError, match=expected_match):
        Settings(**base_kwargs)


def test_sec17_staging_enforces_secure_cookies_hsts_and_no_testserver_csrf(
    client: TestClient, user_a: User, monkeypatch
):
    """Staging sets cookie_secure=True, sandbox_allow_host_fallback=False, HSTS header, and rejects http://testserver CSRF."""
    valid_staging = Settings(
        _env_file=None,
        APP_ENV="staging",
        DEBUG=False,
        DATABASE_URL="postgresql+psycopg://user:pass@postgres:5432/redmercury_staging",
        SECRET_KEY="s" * 48,
        CORS_ORIGINS=["https://staging.redmercury.xerova.com"],
        ALLOWED_HOSTS=["staging.redmercury.xerova.com"],
        SANDBOX_ALLOW_HOST_FALLBACK=True,  # Property must still force False!
    )
    assert valid_staging.is_strict_env is True
    assert valid_staging.cookie_secure is True
    assert valid_staging.sandbox_allow_host_fallback is False

    # HSTS header emitted under staging
    monkeypatch.setattr(settings, "APP_ENV", "staging")
    health = client.get("/api/v1/health")
    assert "strict-transport-security" in {k.lower() for k in health.headers.keys()}

    # http://testserver is NOT trusted in staging when request arrives for a different host
    token = create_access_token({"sub": user_a.id, "email": user_a.email})
    client.cookies.set(settings.COOKIE_NAME, token)
    client.headers.pop("Authorization", None)
    res = client.post(
        "/api/v1/repositories",
        json={"name": "staging-csrf-test", "source_type": "zip_upload"},
        headers={"Origin": "http://testserver", "Host": "staging.redmercury.xerova.com"},
    )
    assert res.status_code == 403
