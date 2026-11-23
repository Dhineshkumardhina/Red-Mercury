"""Phase 2 tests for desktop mode configuration, storage isolation, IPC token verification, and audit history."""
import logging
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.logging import setup_logging
from app.main import app


def test_desktop_mode_allows_sqlite_and_requires_strong_secret_and_localhost(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("WORKSPACE_ROOT", raising=False)
    data_dir = tmp_path / "rm_appdata"
    valid_secret = "a" * 64

    cfg = Settings(
        APP_ENV="desktop",
        SECRET_KEY=valid_secret,
        REDMERCURY_DATA_DIR=str(data_dir),
        HOST="127.0.0.1",
        DEBUG=False,
    )
    assert cfg.is_desktop_env is True
    assert cfg.is_strict_env is False
    assert cfg.is_dev_seed_blocked is True
    assert cfg.sandbox_allow_host_fallback is False
    assert cfg.cookie_secure is False
    assert cfg.DATABASE_URL.startswith("sqlite:///")
    assert "rm_appdata" in cfg.DATABASE_URL
    assert Path(cfg.WORKSPACE_ROOT).parent == data_dir.resolve()

    with pytest.raises(ValueError, match="SECRET_KEY"):
        Settings(APP_ENV="desktop", SECRET_KEY="dev-insecure-secret-key-32-chars-long!!", HOST="127.0.0.1")

    with pytest.raises(ValueError, match="localhost"):
        Settings(APP_ENV="desktop", SECRET_KEY=valid_secret, HOST="0.0.0.0")


def test_desktop_logging_writes_scrubbed_rotating_file(tmp_path):
    log_dir = tmp_path / "logs"
    setup_logging(level="INFO", json_format=False, log_dir=str(log_dir), log_filename="test_desktop.log")
    logger = logging.getLogger("redmercury.desktop.test")
    logger.info('Starting with token="supersecrettoken1234" and postgres://admin:dbpass@127.0.0.1:5432/db')

    for handler in logging.getLogger().handlers:
        handler.flush()

    log_file = log_dir / "test_desktop.log"
    assert log_file.exists()
    content = log_file.read_text(encoding="utf-8")
    assert "supersecrettoken1234" not in content
    assert "dbpass" not in content
    assert "[REDACTED_SECRET]" in content
    assert "[REDACTED_DB_PASSWORD]" in content

    # Restore clean handlers without test file lock
    setup_logging(level="INFO", json_format=False, log_dir=None)


def test_health_ipc_verification_header_only_matches_valid_token(monkeypatch):
    from app.core import config as config_mod

    monkeypatch.setattr(config_mod.settings, "REDMERCURY_IPC_TOKEN", "expected-ipc-secret-999")
    client = TestClient(app)

    res_no_hdr = client.get("/api/v1/health")
    assert res_no_hdr.status_code == 200
    assert "X-RedMercury-IPC-Verified" not in res_no_hdr.headers

    res_wrong = client.get("/api/v1/health", headers={"X-RedMercury-IPC-Token": "wrong"})
    assert res_wrong.status_code == 200
    assert "X-RedMercury-IPC-Verified" not in res_wrong.headers

    res_ok = client.get("/api/v1/health", headers={"X-RedMercury-IPC-Token": "expected-ipc-secret-999"})
    assert res_ok.status_code == 200
    assert res_ok.headers.get("X-RedMercury-IPC-Verified") == "true"


def test_audit_history_endpoint_requires_auth_and_returns_actor_events(client, create_test_user):
    from app.core.security import create_access_token

    unauth = client.get("/api/v1/audit")
    assert unauth.status_code == 401

    user = create_test_user()
    token = create_access_token({"sub": user.id, "email": user.email})
    headers = {"Authorization": f"Bearer {token}"}

    # Trigger an auditable repository creation
    resp = client.post(
        "/api/v1/repositories",
        json={"name": "desktop-audit-test-repo", "default_branch": "main"},
        headers=headers,
    )
    assert resp.status_code in (200, 201)

    audit_resp = client.get("/api/v1/audit", headers=headers)
    assert audit_resp.status_code == 200
    events = audit_resp.json()
    assert isinstance(events, list)
    assert any(ev["action"] == "REPOSITORY_REGISTERED" for ev in events)
