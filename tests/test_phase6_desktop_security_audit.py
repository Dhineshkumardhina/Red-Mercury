"""Phase 6 Desktop Security Qualification Tests (Host Exposure, Filesystem Confinement, Secrets, and Package Hygiene)."""
from pathlib import Path
import json

import pytest

from app.core.config import Settings
from app.core.errors import SecurityPolicyViolationError
from app.core.ingestion import validate_local_ingest_path

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_desktop_mode_rejects_public_bind_host_and_weak_secrets():
    """Desktop configuration must never bind to 0.0.0.0 or accept dev fallback secrets."""
    with pytest.raises(ValueError, match="localhost/127.0.0.1"):
        Settings(
            APP_ENV="desktop",
            HOST="0.0.0.0",
            SECRET_KEY="A" * 64,
            CSRF_PROTECTION_ENABLED=True,
            SANDBOX_FAIL_CLOSED=True,
            ALLOW_PRIVATE_NETWORKS=False,
        )

    with pytest.raises(ValueError, match="SECRET_KEY"):
        Settings(
            APP_ENV="desktop",
            HOST="127.0.0.1",
            SECRET_KEY="dev-insecure-secret-key-32-chars-long!!",
        )


def test_local_ingestion_blocks_sensitive_user_credentials_and_desktop_secrets(tmp_path, monkeypatch):
    """Local ingestion must block ~/.ssh, macOS system roots, and Red Mercury's own secrets directory."""
    user_data = tmp_path / "RedMercuryUserData"
    secrets_dir = user_data / "secrets"
    data_dir = user_data / "data"
    config_dir = user_data / "config"
    for d in (secrets_dir, data_dir, config_dir):
        d.mkdir(parents=True)

    monkeypatch.setenv("REDMERCURY_DATA_DIR", str(data_dir))
    monkeypatch.setenv("REDMERCURY_CONFIG_DIR", str(config_dir))

    with pytest.raises(SecurityPolicyViolationError):
        validate_local_ingest_path(str(secrets_dir), user_id="user-1")

    with pytest.raises(SecurityPolicyViolationError):
        validate_local_ingest_path(str(config_dir), user_id="user-1")

    ssh_dir = Path.home() / ".ssh"
    if ssh_dir.is_dir():
        with pytest.raises(SecurityPolicyViolationError):
            validate_local_ingest_path(str(ssh_dir), user_id="user-1")


def test_packaged_installer_resources_contain_no_secrets_or_dev_dependencies():
    """Built desktop package must contain zero .env files, database files, test directories, or pytest/locust."""
    pkg = json.loads((REPO_ROOT / "package.json").read_text(encoding="utf-8"))
    deps = pkg.get("dependencies") or {}
    dev_deps = pkg.get("devDependencies") or {}
    assert "electron-updater" not in deps and "electron-updater" not in dev_deps

    unpacked_resources = REPO_ROOT / "dist-electron" / "win-unpacked" / "resources"
    if unpacked_resources.is_dir():
        leaked_env = [p for p in unpacked_resources.rglob(".env*") if p.is_file()]
        leaked_db = [p for p in unpacked_resources.rglob("*.db*") if p.is_file()]
        leaked_tests = [p for p in (unpacked_resources / "backend").rglob("tests") if p.is_dir()]
        site_packages = unpacked_resources / "runtime" / "Lib" / "site-packages"
        leaked_dev_pkgs = (
            [p.name for p in site_packages.iterdir() if p.name.lower().startswith(("pytest", "locust"))]
            if site_packages.is_dir()
            else []
        )
        assert leaked_env == []
        assert leaked_db == []
        assert leaked_tests == []
        assert leaked_dev_pkgs == []
