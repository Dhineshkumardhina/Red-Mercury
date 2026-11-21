"""Tests for additional security hardening invariants (headers, CORS, rate limiter bounds, Cloudflare _headers)."""
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.app.core.config import Settings
from backend.app.core.security import InMemoryRateLimiter
from backend.app.main import app


def test_security_headers_and_request_id_sanitization():
    client = TestClient(app)

    # Malicious X-Request-ID with CRLF / control chars must be replaced with a safe UUID
    res = client.get("/health", headers={"X-Request-ID": "bad\r\ninjected-header"})
    assert res.status_code == 200
    assert res.headers["X-Request-ID"] != "bad\r\ninjected-header"
    assert len(res.headers["X-Request-ID"]) == 36
    assert res.headers["Content-Security-Policy"] == "default-src 'none'; frame-ancestors 'none'"
    assert "camera=()" in res.headers["Permissions-Policy"]
    assert res.headers["Cross-Origin-Resource-Policy"] == "same-origin"

    # Valid X-Request-ID is preserved
    res_ok = client.get("/health", headers={"X-Request-ID": "req_123.abc-456"})
    assert res_ok.headers["X-Request-ID"] == "req_123.abc-456"


def test_auth_endpoints_disable_caching():
    client = TestClient(app)
    res = client.get("/api/v1/auth/me")
    assert "no-store" in res.headers.get("Cache-Control", "")


def test_rate_limiter_prunes_stale_keys_to_prevent_unbounded_growth():
    limiter = InMemoryRateLimiter(max_keys=5)
    for i in range(10):
        assert limiter.is_allowed(f"key-{i}", max_requests=5, window_seconds=60)
    assert len(limiter._requests) <= 6


def test_production_blocks_null_cors_origin_and_disabled_csrf():
    base_kwargs = dict(
        APP_ENV="production",
        SECRET_KEY="a" * 64,
        DATABASE_URL="postgresql+psycopg://user:pass@db.internal:5432/redmercury?sslmode=require",
        ALLOWED_HOSTS=["redmercury.xerova.com"],
        DEBUG=False,
        ALLOW_PRIVATE_NETWORKS=False,
    )

    with pytest.raises(ValueError, match="'null' origin"):
        Settings(**base_kwargs, CORS_ORIGINS=["null"])

    with pytest.raises(ValueError, match="CSRF_PROTECTION_ENABLED"):
        Settings(**base_kwargs, CORS_ORIGINS=["https://redmercury.xerova.com"], CSRF_PROTECTION_ENABLED=False)

    with pytest.raises(ValueError, match="AUTH_RATE_LIMITING_ENABLED"):
        Settings(**base_kwargs, CORS_ORIGINS=["https://redmercury.xerova.com"], AUTH_RATE_LIMITING_ENABLED=False)


def test_railway_database_url_normalization():
    s1 = Settings(DATABASE_URL="postgresql://user:pass@host:5432/railway")
    assert s1.DATABASE_URL == "postgresql+psycopg://user:pass@host:5432/railway"
    s2 = Settings(DATABASE_URL="postgres://user:pass@host:5432/railway")
    assert s2.DATABASE_URL == "postgresql+psycopg://user:pass@host:5432/railway"


def test_cloudflare_static_assets_security_headers_file_exists():
    headers_file = Path(__file__).resolve().parent.parent / "frontend" / "public" / "_headers"
    assert headers_file.exists(), "Cloudflare Workers Static Assets _headers file is missing"
    content = headers_file.read_text(encoding="utf-8")
    for required in (
        "Content-Security-Policy:",
        "Strict-Transport-Security:",
        "X-Content-Type-Options: nosniff",
        "X-Frame-Options: DENY",
        "Referrer-Policy:",
        "Permissions-Policy:",
    ):
        assert required in content
