"""Phase 1 Critical Security Remediation Regression Test Suite.

Covers:
- SEC-01: Local filesystem ingestion lockdown, allowlist, symlink rejection, quotas, workspace confinement
- SEC-02: Admin privilege escalation prevention, strict role enum, authoritative DB roles
- SEC-03: Removal of hardcoded dev account seeding from startup
- INFRA-01: Production worker configuration validation & fail-closed behavior
"""
import os
from pathlib import Path
import subprocess
import sys
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import Settings, settings
from app.core.errors import SecurityPolicyViolationError, ValidationError
from app.core.ingestion import (
    copy_local_directory_safely,
    get_repository_workspace,
    validate_local_ingest_path,
)
from app.core.security import create_access_token
from app.main import app
from app.models.user import User


# ==============================================================================
# TASK 1 — SEC-01: Local Filesystem Ingestion Hardening
# ==============================================================================


def test_sec01_local_ingestion_blocked_in_production_by_default(
    auth_client: TestClient, tmp_path: Path, monkeypatch
):
    """Local filesystem ingestion must be rejected (403) in production by default."""
    sample_dir = tmp_path / "sample_repo"
    sample_dir.mkdir()
    (sample_dir / "app.py").write_text("print('hello')\n", encoding="utf-8")

    monkeypatch.setattr(settings, "APP_ENV", "production")
    monkeypatch.setattr(settings, "ALLOW_LOCAL_INGESTION_IN_PRODUCTION", False)
    monkeypatch.setattr(settings, "LOCAL_INGESTION_ALLOWED_ROOTS", [])

    res = auth_client.post(
        "/api/v1/repositories/ingest/local",
        json={"name": f"prod-local-{uuid.uuid4().hex[:6]}", "local_path": str(sample_dir)},
    )
    assert res.status_code == 403
    assert "disabled in production" in res.json()["error"]["message"].lower()


def test_sec01_production_allow_local_ingestion_requires_non_empty_allowlist():
    """Enabling ALLOW_LOCAL_INGESTION_IN_PRODUCTION without LOCAL_INGESTION_ALLOWED_ROOTS must fail closed."""
    with pytest.raises(ValueError, match="LOCAL_INGESTION_ALLOWED_ROOTS"):
        Settings(
            _env_file=None,
            APP_ENV="production",
            DEBUG=False,
            DATABASE_URL="postgresql+psycopg://user:pass@postgres:5432/redmercury",
            SECRET_KEY="a" * 48,
            CORS_ORIGINS=["https://redmercury.xerova.com"],
            ALLOW_LOCAL_INGESTION_IN_PRODUCTION=True,
            LOCAL_INGESTION_ALLOWED_ROOTS=[],
        )


def test_sec01_local_ingestion_enforces_explicit_allowlist(
    auth_client: TestClient, tmp_path: Path, monkeypatch
):
    """When LOCAL_INGESTION_ALLOWED_ROOTS is configured, only paths inside authorized roots are accepted."""
    allowed_root = tmp_path / "authorized_root"
    allowed_repo = allowed_root / "my_project"
    allowed_repo.mkdir(parents=True)
    (allowed_repo / "main.py").write_text("x = 1\n", encoding="utf-8")

    unauthorized_repo = tmp_path / "unauthorized_dir"
    unauthorized_repo.mkdir()
    (unauthorized_repo / "secret.py").write_text("SECRET = 'nope'\n", encoding="utf-8")

    monkeypatch.setattr(settings, "APP_ENV", "production")
    monkeypatch.setattr(settings, "ALLOW_LOCAL_INGESTION_IN_PRODUCTION", True)
    monkeypatch.setattr(settings, "LOCAL_INGESTION_ALLOWED_ROOTS", [str(allowed_root)])

    # Outside allowlist -> 403
    blocked = auth_client.post(
        "/api/v1/repositories/ingest/local",
        json={"name": f"unauth-{uuid.uuid4().hex[:6]}", "local_path": str(unauthorized_repo)},
    )
    assert blocked.status_code == 403
    assert "outside explicitly authorized" in blocked.json()["error"]["message"].lower()

    # Inside allowlist -> 201
    allowed = auth_client.post(
        "/api/v1/repositories/ingest/local",
        json={"name": f"auth-{uuid.uuid4().hex[:6]}", "local_path": str(allowed_repo)},
    )
    assert allowed.status_code == 201
    assert allowed.json()["file_count"] == 1


def test_sec01_local_ingestion_rejects_directory_traversal(auth_client: TestClient, tmp_path: Path):
    """Explicit '..' traversal segments in local_path must be rejected."""
    target = tmp_path / "a" / ".." / "b"
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()

    res = auth_client.post(
        "/api/v1/repositories/ingest/local",
        json={"name": f"trav-{uuid.uuid4().hex[:6]}", "local_path": str(target)},
    )
    assert res.status_code in (400, 403, 422)


def test_sec01_local_ingestion_rejects_symlink_before_resolve(tmp_path: Path, monkeypatch):
    """Symlink paths must be rejected BEFORE Path.resolve() is invoked."""
    sample_dir = tmp_path / "linked_repo"
    sample_dir.mkdir()

    original_is_symlink = Path.is_symlink

    def fake_is_symlink(self: Path) -> bool:
        if self == sample_dir:
            return True
        return original_is_symlink(self)

    monkeypatch.setattr(Path, "is_symlink", fake_is_symlink)

    with pytest.raises(SecurityPolicyViolationError, match="symbolic link"):
        validate_local_ingest_path(str(sample_dir), user_id="user-symlink-test")


def test_sec01_copy_local_directory_rejects_internal_symlink_without_dereferencing(
    tmp_path: Path, monkeypatch
):
    """Internal symlink files inside a local directory must be rejected and never copied."""
    src_dir = tmp_path / "src_repo"
    src_dir.mkdir()
    evil_file = src_dir / "link_to_env.txt"
    evil_file.write_text("SHOULD_NOT_BE_COPIED", encoding="utf-8")
    dest_dir = tmp_path / "isolated_ws"

    original_is_symlink = Path.is_symlink

    def fake_is_symlink(self: Path) -> bool:
        if self.name == "link_to_env.txt":
            return True
        return original_is_symlink(self)

    monkeypatch.setattr(Path, "is_symlink", fake_is_symlink)

    with pytest.raises(SecurityPolicyViolationError, match="Symbolic link"):
        copy_local_directory_safely(src_dir, dest_dir)

    assert not dest_dir.exists()


def test_sec01_local_ingestion_enforces_max_file_count(
    auth_client: TestClient, tmp_path: Path, monkeypatch
):
    """Local ingestion must reject directories exceeding MAX_FILE_COUNT and clean up."""
    repo_dir = tmp_path / "many_files"
    repo_dir.mkdir()
    for i in range(5):
        (repo_dir / f"file_{i}.py").write_text(f"x = {i}\n", encoding="utf-8")

    monkeypatch.setattr(settings, "MAX_FILE_COUNT", 3)

    res = auth_client.post(
        "/api/v1/repositories/ingest/local",
        json={"name": f"too-many-{uuid.uuid4().hex[:6]}", "local_path": str(repo_dir)},
    )
    assert res.status_code == 422
    assert "maximum allowed limit" in res.json()["error"]["message"].lower()


def test_sec01_local_ingestion_enforces_cumulative_size_limit(
    auth_client: TestClient, tmp_path: Path, monkeypatch
):
    """Local ingestion must reject directories exceeding MAX_EXTRACTED_SIZE_BYTES."""
    repo_dir = tmp_path / "oversized_repo"
    repo_dir.mkdir()
    (repo_dir / "big1.py").write_text("A" * 2048, encoding="utf-8")
    (repo_dir / "big2.py").write_text("B" * 2048, encoding="utf-8")

    monkeypatch.setattr(settings, "MAX_EXTRACTED_SIZE_BYTES", 3000)

    res = auth_client.post(
        "/api/v1/repositories/ingest/local",
        json={"name": f"oversized-{uuid.uuid4().hex[:6]}", "local_path": str(repo_dir)},
    )
    assert res.status_code == 422
    assert "size" in res.json()["error"]["message"].lower()


def test_sec01_workspace_confinement_prevents_prefix_collision(tmp_path: Path, monkeypatch):
    """Tenant 'alice' must not access 'alice2' workspace via string prefix collision."""
    monkeypatch.setattr(settings, "WORKSPACE_ROOT", str(tmp_path))
    alice2_ws = get_repository_workspace("alice2", "repo1")
    alice2_ws.mkdir(parents=True, exist_ok=True)

    with pytest.raises(SecurityPolicyViolationError, match="another tenant"):
        validate_local_ingest_path(str(alice2_ws), user_id="alice")


# ==============================================================================
# TASK 2 — SEC-02: Admin Privilege Escalation & Authoritative DB Roles
# ==============================================================================


def test_sec02_public_registration_defaults_to_least_privileged_analyst(client: TestClient, db_session: Session):
    """Public registration must never grant admin role; defaults to 'analyst'."""
    email = f"new_practitioner_{uuid.uuid4().hex[:8]}@xerova.com"
    res = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "StrongPassword123!"},
    )
    assert res.status_code == 201
    data = res.json()
    assert data["user"]["role"] == "analyst"
    assert data["user"]["role"] != "admin"

    db_user = db_session.query(User).filter(User.email == email).first()
    assert db_user is not None
    assert db_user.role == "analyst"


def test_sec02_public_registration_rejects_admin_role_injection(client: TestClient, db_session: Session):
    """Supplying role='admin' during public registration must be rejected (422)."""
    email = f"attacker_admin_{uuid.uuid4().hex[:8]}@xerova.com"
    res = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "StrongPassword123!", "role": "admin"},
    )
    assert res.status_code == 422
    assert db_session.query(User).filter(User.email == email).first() is None


def test_sec02_public_registration_rejects_invalid_role_injection(client: TestClient, db_session: Session):
    """Supplying arbitrary invalid role during public registration must be rejected (422)."""
    email = f"attacker_invalid_{uuid.uuid4().hex[:8]}@xerova.com"
    res = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "StrongPassword123!", "role": "superadmin"},
    )
    assert res.status_code == 422
    assert db_session.query(User).filter(User.email == email).first() is None


def test_sec02_jwt_role_claim_cannot_escalate_viewer_to_admin(
    client: TestClient, create_test_user, db_session: Session
):
    """A JWT claiming role='admin' must NOT override a database 'viewer' role."""
    viewer = create_test_user(email=f"db_viewer_{uuid.uuid4().hex[:6]}@xerova.com", role="viewer")
    forged_role_token = create_access_token(
        {"sub": viewer.id, "email": viewer.email, "role": "admin"}
    )

    # Read endpoint succeeds, but /auth/me reports authoritative DB role 'viewer'
    me_res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {forged_role_token}"})
    assert me_res.status_code == 200
    assert me_res.json()["role"] == "viewer"

    # Mutating endpoint MUST be rejected with 403
    mut_res = client.post(
        "/api/v1/repositories",
        headers={"Authorization": f"Bearer {forged_role_token}"},
        json={"name": f"escalated-repo-{uuid.uuid4().hex[:6]}", "source_type": "git"},
    )
    assert mut_res.status_code == 403

    # Verify DB role was NOT mutated by get_current_user
    db_session.refresh(viewer)
    assert viewer.role == "viewer"


def test_sec02_database_role_downgrade_takes_effect_immediately(
    client: TestClient, create_test_user, db_session: Session
):
    """Downgrading a user from admin to viewer in the DB must immediately block mutations on existing JWTs."""
    user = create_test_user(email=f"downgrade_{uuid.uuid4().hex[:6]}@xerova.com", role="admin")
    admin_token = create_access_token({"sub": user.id, "email": user.email, "role": "admin"})

    # Initially succeeds as admin
    ok_res = client.post(
        "/api/v1/repositories",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"name": f"before-downgrade-{uuid.uuid4().hex[:6]}", "source_type": "git"},
    )
    assert ok_res.status_code == 201

    # Downgrade in DB to viewer
    user.role = "viewer"
    db_session.commit()

    # Same still-valid admin JWT must immediately be blocked
    blocked_res = client.post(
        "/api/v1/repositories",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"name": f"after-downgrade-{uuid.uuid4().hex[:6]}", "source_type": "git"},
    )
    assert blocked_res.status_code == 403


def test_sec02_invalid_database_role_rejected_fail_closed(
    client: TestClient, create_test_user, db_session: Session
):
    """If a user has an unknown/corrupted role in DB, auth must fail closed with 403."""
    user = create_test_user(email=f"corrupt_{uuid.uuid4().hex[:6]}@xerova.com", role="godmode")
    token = create_access_token({"sub": user.id, "email": user.email, "role": "admin"})

    res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 403


# ==============================================================================
# TASK 3 — SEC-03: No Production Startup Dev Seeding
# ==============================================================================


def test_sec03_main_module_has_no_startup_dev_seeding():
    """Verify backend/app/main.py no longer seeds hardcoded personal accounts on startup."""
    import app.main as main_mod

    assert not hasattr(main_mod, "seed_initial_dev_data")
    main_source = Path(main_mod.__file__).read_text(encoding="utf-8")
    assert "dhineshkumardhina@gmail.com" not in main_source
    assert "XerovaDevPass2026!" not in main_source


# ==============================================================================
# TASK 5 — INFRA-01: Docker Worker Production Startup Configuration
# ==============================================================================


def test_infra01_worker_compose_env_passes_production_validation():
    """Verify docker-compose.prod.yml passes required production env vars to worker without embedded secrets."""
    compose_path = Path(__file__).resolve().parent.parent / "docker-compose.prod.yml"
    compose_text = compose_path.read_text(encoding="utf-8")

    # Extract worker service block
    worker_idx = compose_text.index("  worker:")
    frontend_idx = compose_text.index("  frontend:")
    worker_block = compose_text[worker_idx:frontend_idx]

    assert "APP_ENV: production" in worker_block
    assert "SECRET_KEY: ${SECRET_KEY:?SECRET_KEY must be set in production}" in worker_block
    assert "CORS_ORIGINS: ${CORS_ORIGINS:-https://redmercury.xerova.com}" in worker_block
    assert 'SANDBOX_FAIL_CLOSED: "true"' in worker_block
    assert 'SANDBOX_ALLOW_HOST_FALLBACK: "false"' in worker_block
    assert "dev-insecure" not in worker_block

    # Simulate exact worker production environment variables -> Settings validation must succeed
    prod_worker_settings = Settings(
        _env_file=None,
        APP_ENV="production",
        DEBUG=False,
        DATABASE_URL="postgresql+psycopg://redmercury_admin:strong_db_pass@postgres:5432/redmercury_prod",
        SECRET_KEY="s" * 48,
        CORS_ORIGINS="https://redmercury.xerova.com",
        LOG_LEVEL="INFO",
        LOG_FORMAT_JSON=True,
        ALLOW_LOCAL_INGESTION_IN_PRODUCTION=False,
        SANDBOX_FAIL_CLOSED=True,
        SANDBOX_ALLOW_HOST_FALLBACK=False,
        WORKSPACE_ROOT="/sandbox/workspaces",
    )
    assert prod_worker_settings.is_production is True
    assert prod_worker_settings.SANDBOX_FAIL_CLOSED is True
    assert prod_worker_settings.sandbox_allow_host_fallback is False


def test_infra01_worker_fails_closed_when_secret_key_missing(monkeypatch):
    """Production worker configuration must raise ValueError when SECRET_KEY is missing."""
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(ValueError, match="SECRET_KEY"):
        Settings(
            _env_file=None,
            APP_ENV="production",
            DEBUG=False,
            DATABASE_URL="postgresql+psycopg://redmercury_admin:strong_db_pass@postgres:5432/redmercury_prod",
            CORS_ORIGINS="https://redmercury.xerova.com",
        )


def test_infra01_worker_process_exits_nonzero_without_mandatory_prod_config(tmp_path: Path):
    """Running python -m app.scanner.worker in production without SECRET_KEY must exit non-zero."""
    repo_root = Path(__file__).resolve().parent.parent
    env = os.environ.copy()
    env.pop("SECRET_KEY", None)
    env.update({
        "PYTHONPATH": str(repo_root / "backend"),
        "APP_ENV": "production",
        "DEBUG": "false",
        "DATABASE_URL": "postgresql+psycopg://user:pass@postgres:5432/redmercury",
        "CORS_ORIGINS": "https://redmercury.xerova.com",
    })
    # Run from tmp_path so local .env is not loaded
    proc = subprocess.run(
        [sys.executable, "-m", "app.scanner.worker", "--healthcheck"],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert proc.returncode != 0
    assert "SECRET_KEY" in (proc.stderr + proc.stdout)
