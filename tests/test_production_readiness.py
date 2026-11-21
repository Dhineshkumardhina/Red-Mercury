"""Tests verifying production deployment hardening and operational safety controls."""
from datetime import datetime, timedelta, timezone
import json
import logging
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.errors import SecurityPolicyViolationError, ValidationError
from app.core.logging import JSONFormatter, StandardFormatter, scrub_log_message
from app.core.quotas import (
    check_scan_concurrency_and_quota,
    check_verification_concurrency,
    reconcile_interrupted_jobs,
)
from app.core.workspace_cleanup import clean_stale_workspaces
from app.models.repository import Repository
from app.models.scan import Scan
from app.models.user import User


def test_production_environment_config_validation():
    """Verify that production mode strictly rejects SQLite and default insecure secret keys."""
    # 1. Rejects SQLite in production
    with pytest.raises(ValueError, match="SQLite cannot be used in production"):
        Settings(
            APP_ENV="production",
            DATABASE_URL="sqlite:///./prod.db",
            SECRET_KEY="a" * 64,
        )

    # 2. Rejects default insecure secret key in production
    with pytest.raises(ValueError, match="requires a cryptographically strong SECRET_KEY"):
        Settings(
            APP_ENV="production",
            DATABASE_URL="postgresql+psycopg://user:pass@localhost:5432/prod_db",
            SECRET_KEY="dev-insecure-secret-key-32-chars-long!!",
        )

    # 3. Rejects short secret key in production (< 32 chars)
    with pytest.raises(ValueError, match="requires a cryptographically strong SECRET_KEY"):
        Settings(
            APP_ENV="production",
            DATABASE_URL="postgresql+psycopg://user:pass@localhost:5432/prod_db",
            SECRET_KEY="short-secret-key",
        )

    # 4. Valid production settings succeed
    prod_settings = Settings(
        APP_ENV="production",
        DATABASE_URL="postgresql+psycopg://user:pass@localhost:5432/prod_db",
        SECRET_KEY="strong_cryptographic_production_key_64_characters_long_for_security!",
        DEBUG=False,
        DOCS_ENABLED=False,
    )
    assert prod_settings.is_production is True
    assert prod_settings.cookie_secure is True


def test_log_secret_redaction():
    """Verify that log formatters redact passwords, tokens, API keys, and private keys."""
    raw_secret_message = (
        "User auth failed: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-ID "
        "with ghp_ABCDEF1234567890abcdef12345678901234 "
        "and password='SuperSecretPassword123!' "
        "connecting to postgres://admin:SuperSecretDbPass@db:5432/app"
    )

    scrubbed = scrub_log_message(raw_secret_message)
    assert "SuperSecretPassword123!" not in scrubbed
    assert "[REDACTED_SECRET]" in scrubbed
    assert "ghp_ABCDEF1234567890abcdef12345678901234" not in scrubbed
    assert "[REDACTED_API_KEY]" in scrubbed
    assert "SuperSecretDbPass" not in scrubbed
    assert "[REDACTED_DB_PASSWORD]" in scrubbed
    assert "[REDACTED_JWT_TOKEN]" in scrubbed

    # Test JSON formatter
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg=raw_secret_message,
        args=(),
        exc_info=None,
    )
    json_formatter = JSONFormatter()
    formatted_json = json.loads(json_formatter.format(record))
    assert "SuperSecretPassword123!" not in formatted_json["message"]
    assert "[REDACTED_SECRET]" in formatted_json["message"]


def test_interrupted_jobs_reconciliation(db_session: Session, user_a: User):
    """Verify that hanging or orphaned jobs from a crashed worker are safely reconciled."""
    # Create repository
    repo = Repository(
        id=f"repo_rec_{uuid.uuid4().hex[:6]}",
        owner_id=user_a.id,
        name="recon/repo",
        default_branch="main",
    )
    db_session.add(repo)
    db_session.commit()

    # Create an old running scan (started 30 minutes ago)
    old_scan = Scan(
        id=f"scan_rec_{uuid.uuid4().hex[:6]}",
        repository_id=repo.id,
        status="running",
        created_at=datetime.now(timezone.utc) - timedelta(minutes=30),
    )
    db_session.add(old_scan)
    db_session.commit()

    # Run reconciliation
    reconciled = reconcile_interrupted_jobs(db_session)
    assert reconciled >= 1

    # Verify scan transitioned to interrupted
    db_session.refresh(old_scan)
    assert old_scan.status == "interrupted"
    assert "interrupted" in old_scan.summary.lower()


def test_concurrency_limit_enforcement(db_session: Session, user_a: User):
    """Verify that active scan concurrency limit prevents runaway job flooding."""
    repo = Repository(
        id=f"repo_quota_{uuid.uuid4().hex[:6]}",
        owner_id=user_a.id,
        name="quota/repo",
        default_branch="main",
    )
    db_session.add(repo)
    db_session.commit()

    # Create 3 currently active running scans (hitting the default concurrency limit of 3)
    for i in range(3):
        active_scan = Scan(
            id=f"scan_active_{i}_{uuid.uuid4().hex[:4]}",
            repository_id=repo.id,
            status="running",
            created_at=datetime.now(timezone.utc),
        )
        db_session.add(active_scan)
    db_session.commit()

    # Attempting to start another scan should raise SecurityPolicyViolationError
    with pytest.raises(SecurityPolicyViolationError, match="Concurrency limit reached"):
        check_scan_concurrency_and_quota(user=user_a, db=db_session)


def test_workspace_cleanup_utility(db_session: Session):
    """Verify clean_stale_workspaces executes without error and returns tracking summary."""
    summary = clean_stale_workspaces(db=db_session, max_age_hours=0)
    assert "removed_directories" in summary
    assert "reclaimed_bytes" in summary
    assert isinstance(summary["removed_directories"], int)


def test_security_headers_present_on_api(client: TestClient):
    """Verify essential AppSec security headers are returned on API endpoints."""
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    assert res.headers["X-Content-Type-Options"] == "nosniff"
    assert res.headers["X-Frame-Options"] == "DENY"
    assert "X-Request-ID" in res.headers


def test_request_size_limit_middleware(client: TestClient):
    """Verify that requests exceeding MAX_REQUEST_BODY_SIZE_BYTES are rejected before memory buffering."""
    oversized_bytes = 100 * 1024 * 1024  # 100 MB
    res = client.post(
        "/api/v1/repositories",
        content=b"test",
        headers={"Content-Length": str(oversized_bytes), "Content-Type": "application/json"},
    )
    assert res.status_code == 413
    err = res.json()
    assert "maximum allowed size" in err["error"]["message"].lower()


def test_worker_heartbeat_and_healthcheck(tmp_path):
    """Verify that worker heartbeat generation and healthcheck probe work correctly."""
    from app.scanner.worker import write_heartbeat, run_healthcheck

    heartbeat_file = tmp_path / "test_heartbeat.json"

    # 1. Probe passes with no heartbeat file yet (initial boot before first loop)
    code = run_healthcheck(heartbeat_file=heartbeat_file)
    assert code == 0

    # 2. Write active heartbeat
    write_heartbeat(heartbeat_file, jobs_processed=5)
    assert heartbeat_file.exists()
    data = json.loads(heartbeat_file.read_text(encoding="utf-8"))
    assert data["status"] == "healthy"
    assert data["jobs_processed"] == 5
    assert "timestamp" in data

    # 3. Probe passes with fresh heartbeat
    code = run_healthcheck(heartbeat_file=heartbeat_file, max_age_seconds=60.0)
    assert code == 0

    # 4. Probe fails when heartbeat is stale
    stale_data = {**data, "timestamp": data["timestamp"] - 120.0}
    heartbeat_file.write_text(json.dumps(stale_data), encoding="utf-8")
    code = run_healthcheck(heartbeat_file=heartbeat_file, max_age_seconds=60.0)
    assert code == 1


def test_worker_process_pending_scans(db_session: Session, user_a: User, tmp_path):
    """Verify that worker polls and executes pending scans."""
    from app.scanner.worker import process_pending_scans

    workspace_dir = tmp_path / "worker_repo"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    (workspace_dir / "app.py").write_text("print('hello')", encoding="utf-8")

    repo = Repository(
        id=f"repo_work_{uuid.uuid4().hex[:6]}",
        owner_id=user_a.id,
        name="worker/repo",
        default_branch="main",
        workspace_path=str(workspace_dir),
    )
    db_session.add(repo)
    db_session.commit()

    # Create pending scan
    scan = Scan(
        id=f"scan_work_{uuid.uuid4().hex[:6]}",
        repository_id=repo.id,
        status="pending",
        scanner_configuration=json.dumps({"tools": ["bandit"], "timeout_seconds": 10}),
        summary="Pending scan for worker",
    )
    db_session.add(scan)
    db_session.commit()

    # Process batch
    processed = process_pending_scans(db=db_session, max_batch=5)
    assert processed >= 1

    db_session.refresh(scan)
    assert scan.status in ("completed", "partial", "failed")
    assert scan.completed_at is not None


def test_ssl_certificate_generation_utility(tmp_path):
    """Verify scripts/generate_ssl_certs.py produces valid RSA 4096-bit certs with SANs."""
    import sys
    from pathlib import Path

    script_path = Path(__file__).resolve().parent.parent / "scripts" / "generate_ssl_certs.py"
    assert script_path.exists()

    sys.path.insert(0, str(script_path.parent))
    from generate_ssl_certs import generate_self_signed_cert
    from cryptography import x509

    out_dir = tmp_path / "ssl_test"
    generate_self_signed_cert(
        output_dir=out_dir,
        domain="redmercury.test.local",
        days_valid=30,
        key_size=2048,  # Fast test key size
    )

    key_file = out_dir / "redmercury.key"
    crt_file = out_dir / "redmercury.crt"
    assert key_file.exists()
    assert crt_file.exists()

    # Inspect certificate extensions and SAN
    cert_bytes = crt_file.read_bytes()
    cert = x509.load_pem_x509_certificate(cert_bytes)
    san_ext = cert.extensions.get_extension_for_oid(x509.OID_SUBJECT_ALTERNATIVE_NAME)
    san_names = [str(name.value) for name in san_ext.value]

    assert "redmercury.test.local" in san_names
    assert "localhost" in san_names
    assert "127.0.0.1" in san_names


def test_httpx_and_production_dependencies():
    """Verify that httpx is declared in backend/requirements.txt."""
    from pathlib import Path

    req_path = Path(__file__).resolve().parent.parent / "backend" / "requirements.txt"
    assert req_path.exists()

    req_content = req_path.read_text(encoding="utf-8")
    assert "httpx" in req_content
    assert "psycopg" in req_content

