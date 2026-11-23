"""Phase 4 Tests: Local Database Strategy, Redis-Free Durable Queue, Startup Recovery, Offline Boundaries, and Backup/Restore."""
import io
import json
from pathlib import Path
import sqlite3
from unittest.mock import patch
import zipfile

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import sessionmaker

from app.core.backup import (
    create_backup_archive,
    initialize_local_database,
    restore_backup_archive,
    stage_backup_restore,
    verify_backup_archive,
)
from app.core.config import settings
from app.core.errors import ValidationError
from app.core.jobs import (
    JobState,
    claim_next_durable_job,
    create_durable_job_with_outbox,
    reconcile_jobs_on_startup,
)
from app.models.audit import AuditEvent
from app.models.user import User

REPO_ROOT = Path(__file__).resolve().parent.parent
ALEMBIC_INI = REPO_ROOT / "backend" / "alembic.ini"


def _sqlite_wal_engine(db_path: Path):
    eng = create_engine(
        f"sqlite:///{db_path.as_posix()}",
        connect_args={"check_same_thread": False, "timeout": 15},
    )

    @event.listens_for(eng, "connect")
    def _pragmas(dbapi_conn, _rec):
        cur = dbapi_conn.cursor()
        try:
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA synchronous=NORMAL")
            cur.execute("PRAGMA busy_timeout=10000")
            cur.execute("PRAGMA foreign_keys=ON")
        finally:
            cur.close()

    return eng


def test_sqlite_full_alembic_upgrade_and_model_parity(tmp_path):
    """All Alembic migrations 0001->head must execute cleanly on SQLite and register every model table."""
    db_path = tmp_path / "alembic_parity.db"
    eng = _sqlite_wal_engine(db_path)
    try:
        cfg = Config(str(ALEMBIC_INI))
        cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path.as_posix()}")
        command.upgrade(cfg, "head")

        head_rev = ScriptDirectory.from_config(cfg).get_current_head()
        inspector = inspect(eng)
        tables = set(inspector.get_table_names())
        for expected in (
            "alembic_version",
            "users",
            "repositories",
            "scans",
            "security_findings",
            "durable_jobs",
            "job_outbox_events",
            "active_job_slots",
            "audit_events",
            "revoked_tokens",
            "refresh_token_sessions",
            "finding_analyses",
            "verification_runs",
            "github_integrations",
        ):
            assert expected in tables

        with eng.connect() as conn:
            rev = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
        assert rev == head_rev
    finally:
        eng.dispose()


def test_sqlite_durable_job_queue_retry_lease_reconciliation_without_redis(tmp_path, monkeypatch):
    """Durable jobs, atomic CAS claiming, lease expiry recovery, startup reconciliation, and audit logs must work on SQLite with zero Redis."""
    from datetime import datetime, timedelta, timezone

    monkeypatch.setattr(settings, "REDIS_URL", None)
    monkeypatch.setattr(settings, "JOB_MAX_ATTEMPTS", 3)

    db_path = tmp_path / "jobs_local.db"
    eng = _sqlite_wal_engine(db_path)
    try:
        initialize_local_database(engine_override=eng, alembic_ini_path=str(ALEMBIC_INI))
        SessionMaker = sessionmaker(autocommit=False, autoflush=False, bind=eng)

        with SessionMaker() as db:
            user = User(
                email="local-worker@redmercury.test",
                password_hash="x",
                account_status="active",
                role="developer",
            )
            db.add(user)
            db.commit()
            db.refresh(user)

            job, _outbox, created = create_durable_job_with_outbox(
                db=db,
                user=user,
                job_type="scan",
                resource_id="scan-res-1",
                repository_id=None,
                payload={"trigger_source": "manual"},
                idempotency_key="local-idem-1",
                reserve_slot=False,
            )
            db.commit()
            assert created is True
            assert job.status == JobState.QUEUED.value

            # Claim atomically without Redis hint
            claimed = claim_next_durable_job(db=db, worker_id="local-w1", lease_seconds=60, redis_client=None)
            assert claimed is not None
            assert claimed.status == JobState.RUNNING.value
            assert claimed.attempt_count == 1
            first_token = claimed.lease_token

            # Simulate worker crash / expired lease
            claimed.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
            db.commit()

            # Startup reconciliation recovers lease -> retrying and records AuditEvent
            summary = reconcile_jobs_on_startup(db=db, component="api", redis_client=None)
            assert summary["expired_leases_retried"] == 1

            db.expire_all()
            recovered = db.query(type(job)).filter_by(id=job.id).one()
            assert recovered.status == JobState.RETRYING.value
            recovered.next_retry_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            db.commit()

            reclaimed = claim_next_durable_job(db=db, worker_id="local-w2", lease_seconds=60, redis_client=None)
            assert reclaimed is not None
            assert reclaimed.attempt_count == 2
            assert reclaimed.lease_token != first_token

            audit_rows = db.query(AuditEvent).filter(AuditEvent.action == "JOB_RECONCILIATION_COMPLETED").all()
            assert len(audit_rows) >= 1
    finally:
        eng.dispose()


def test_first_run_and_interrupted_startup_recovery(tmp_path, monkeypatch):
    """First-run init must stamp Alembic head, clean leftover .tmp files, and recover cleanly on restart."""
    data_dir = tmp_path / "app_data"
    backups_dir = data_dir / "backups"
    backups_dir.mkdir(parents=True)
    stale_tmp = data_dir / "partial.tmp"
    stale_zip = backups_dir / "interrupted.tmp.zip"
    stale_tmp.write_text("incomplete", encoding="utf-8")
    stale_zip.write_text("incomplete", encoding="utf-8")

    db_path = data_dir / "redmercury.db"
    monkeypatch.setattr(settings, "REDMERCURY_DATA_DIR", str(data_dir))
    monkeypatch.setattr(settings, "DATABASE_URL", f"sqlite:///{db_path.as_posix()}")

    eng = _sqlite_wal_engine(db_path)
    try:
        summary1 = initialize_local_database(engine_override=eng, alembic_ini_path=str(ALEMBIC_INI))
        assert summary1["first_run"] is True
        assert summary1["cleaned_tmp_files"] == 2
        assert summary1["alembic_action"] == "stamped_head"
        assert not stale_tmp.exists()
        assert not stale_zip.exists()

        summary2 = initialize_local_database(engine_override=eng, alembic_ini_path=str(ALEMBIC_INI))
        assert summary2["first_run"] is False
        assert summary2["integrity"] == "ok"
        assert summary2["alembic_action"] == "none"
    finally:
        eng.dispose()


def test_capabilities_distinguish_offline_scanning_external_ai_github_and_docker(
    client_a: TestClient,
    monkeypatch,
):
    """Capabilities API must clearly distinguish local offline scanning from external AI, GitHub, and Docker."""
    monkeypatch.setattr(settings, "OFFLINE_MODE", True)
    monkeypatch.delenv("FORCE_ONLINE", raising=False)

    with patch("app.api.v1.endpoints.system.check_docker_availability", return_value=(False, "Docker Desktop stopped")):
        res = client_a.get("/api/v1/system/capabilities")

    assert res.status_code == 200
    body = res.json()
    caps = body["capabilities"]
    assert body["offline_mode"] is True
    assert body["background_queue"]["redis_required"] is False

    assert caps["offline_scanning"]["available"] is True
    assert caps["external_ai"]["available"] is False
    assert caps["external_ai"]["requires_external_api"] is True
    assert caps["external_ai"]["status"] == "disabled_offline"
    assert "fallback" in caps["external_ai"]["active_engine"]

    assert caps["github_integrations"]["available"] is False
    assert caps["github_integrations"]["requires_internet"] is True
    assert caps["docker_verification"]["available"] is False
    assert caps["docker_verification"]["fail_closed"] is True


def test_offline_mode_blocks_remote_desktop_git_clone(client_a: TestClient, monkeypatch):
    """In desktop Offline Mode, remote HTTPS Git cloning must fail clearly while ZIP/local scanning remain usable."""
    monkeypatch.setattr(settings, "APP_ENV", "desktop")
    monkeypatch.setattr(settings, "OFFLINE_MODE", True)
    monkeypatch.delenv("FORCE_ONLINE", raising=False)

    res = client_a.post(
        "/api/v1/repositories/ingest/git",
        json={"git_url": "https://github.com/xerova/sample.git", "name": "remote-repo"},
    )
    assert res.status_code == 403
    assert "offline mode" in res.json()["error"]["message"].lower()


def test_backup_create_verify_tamper_detection_and_restore(tmp_path, monkeypatch):
    """Backups must snapshot WAL SQLite DB + non-secret config, detect tampering, and restore staged/direct cleanly."""
    root_dir = tmp_path / "desktop_root"
    data_dir = root_dir / "data"
    cfg_dir = root_dir / "config"
    secrets_dir = root_dir / "secrets"
    data_dir.mkdir(parents=True)
    cfg_dir.mkdir(parents=True)
    secrets_dir.mkdir(parents=True)

    (cfg_dir / "app-config.json").write_text(json.dumps({"offlineMode": True, "preferredPort": 8001}), encoding="utf-8")
    (cfg_dir / "preferences.json").write_text(json.dumps({"zeroSecrets": True, "sandboxTimeout": 120}), encoding="utf-8")
    (secrets_dir / "desktop-keys.enc").write_bytes(b"super-secret-encrypted-blob")

    db_path = data_dir / "redmercury.db"
    monkeypatch.setattr(settings, "REDMERCURY_DATA_DIR", str(data_dir))
    monkeypatch.setattr(settings, "REDMERCURY_CONFIG_DIR", str(cfg_dir))
    monkeypatch.setattr(settings, "DATABASE_URL", f"sqlite:///{db_path.as_posix()}")

    eng = _sqlite_wal_engine(db_path)
    try:
        initialize_local_database(engine_override=eng, alembic_ini_path=str(ALEMBIC_INI))
        SessionMaker = sessionmaker(autocommit=False, autoflush=False, bind=eng)

        with SessionMaker() as db:
            db.add(
                User(
                    id="user-keep-1",
                    email="keep@redmercury.test",
                    password_hash="hash",
                    account_status="active",
                    role="admin",
                )
            )
            db.commit()

        created = create_backup_archive(db_path=db_path, config_dir=cfg_dir)
        archive_path = Path(created["path"])
        assert archive_path.is_file()
        assert created["includes_config"] is True
        assert created["excludes_secrets"] is True

        # Secrets must never enter archive
        with zipfile.ZipFile(archive_path, "r") as zf:
            names = zf.namelist()
            assert "database/redmercury.db" in names
            assert "config/app-config.json" in names
            assert "config/preferences.json" in names
            assert not any("secret" in n.lower() or "key" in n.lower() or ".env" in n.lower() for n in names)

        verified = verify_backup_archive(archive_path)
        assert verified["valid"] is True
        assert verified["db_integrity"] == "ok"

        # Tampered archive must be rejected cleanly
        tampered_path = tmp_path / "tampered.rmbkp"
        with zipfile.ZipFile(archive_path, "r") as zin, zipfile.ZipFile(tampered_path, "w") as zout:
            for item in zin.infolist():
                payload = zin.read(item.filename)
                if item.filename == "config/preferences.json":
                    payload = b'{"zeroSecrets": false}'
                zout.writestr(item, payload)
        with pytest.raises(ValidationError, match="Checksum"):
            verify_backup_archive(tampered_path)

        # Mutate live DB and config, then stage + apply via startup recovery
        with SessionMaker() as db:
            db.execute(text("DELETE FROM users WHERE id = 'user-keep-1'"))
            db.commit()
        (cfg_dir / "preferences.json").write_text(json.dumps({"zeroSecrets": False}), encoding="utf-8")

        staged = stage_backup_restore(archive_path, db_path=db_path)
        assert staged["status"] == "staged_for_restart"
        assert staged["pre_restore_backup"] is not None

        eng.dispose()
        init_res = initialize_local_database(engine_override=eng, alembic_ini_path=str(ALEMBIC_INI))
        assert init_res["restored_pending"] is True

        with SessionMaker() as db:
            restored_user = db.query(User).filter(User.id == "user-keep-1").first()
            assert restored_user is not None
            assert restored_user.email == "keep@redmercury.test"

        restored_prefs = json.loads((cfg_dir / "preferences.json").read_text(encoding="utf-8"))
        assert restored_prefs["zeroSecrets"] is True

        # Also test direct single-process restore API helper
        (cfg_dir / "preferences.json").write_text(json.dumps({"zeroSecrets": False}), encoding="utf-8")
        direct = restore_backup_archive(archive_path, engine_to_dispose=eng, db_path=db_path, config_dir=cfg_dir)
        assert direct["status"] == "restored"
        assert json.loads((cfg_dir / "preferences.json").read_text(encoding="utf-8"))["zeroSecrets"] is True
    finally:
        eng.dispose()
