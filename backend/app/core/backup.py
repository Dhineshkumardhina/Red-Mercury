"""Local Database Initialization, Integrity Verification, Backup & Recovery Engine (Phase 4).

Provides:
- Online, WAL-consistent SQLite snapshots via sqlite3.Connection.backup().
- Cryptographically verified (.rmbkp ZIP + SHA-256 manifest) configuration & database backups.
- Tamper-resistant archive validation (Zip Slip prevention, SHA-256 digest verification, SQLite PRAGMA integrity_check).
- Staged restart-safe restore (multi-process desktop safe) and direct restore (single-process/CLI safe).
- First-run & interrupted-startup database recovery with dynamic Alembic head resolution.
"""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote
import zipfile

from sqlalchemy import inspect as sa_inspect, text
from sqlalchemy.engine import Engine

from .config import settings
from .errors import ValidationError
from .logging import get_logger

logger = get_logger("redmercury.core.backup")

BACKUP_FORMAT_VERSION = "1.0"
SAFE_CONFIG_FILENAMES = ("app-config.json", "preferences.json")
ALLOWED_BACKUP_EXTENSION = ".rmbkp"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest().lower()


def resolve_sqlite_db_path(database_url: Optional[str] = None) -> Optional[Path]:
    """Return the local filesystem Path for a file-backed SQLite DATABASE_URL, or None."""
    url = (database_url or settings.DATABASE_URL or "").strip()
    if not url.startswith("sqlite:///"):
        return None
    raw_path = url[len("sqlite:///"):]
    if not raw_path or raw_path == ":memory:" or raw_path.startswith("file::memory:"):
        return None
    # Strip query string if any and decode SQLAlchemy URL percent-encoding (e.g. C%3A, %20)
    raw_path = unquote(raw_path.split("?", 1)[0])
    return Path(raw_path).resolve()


def resolve_config_dir(config_dir_override: Optional[Path] = None) -> Optional[Path]:
    """Resolve the non-secret desktop configuration directory when available."""
    if config_dir_override is not None:
        return Path(config_dir_override).resolve()
    env_cfg = (settings.REDMERCURY_CONFIG_DIR or os.environ.get("REDMERCURY_CONFIG_DIR") or "").strip()
    if env_cfg:
        return Path(env_cfg).resolve()
    if settings.REDMERCURY_DATA_DIR and str(settings.REDMERCURY_DATA_DIR).strip():
        candidate = Path(str(settings.REDMERCURY_DATA_DIR).strip()).resolve().parent / "config"
        if candidate.is_dir():
            return candidate
    return None


def resolve_backup_dir(
    backup_dir_override: Optional[Path] = None,
    db_path: Optional[Path] = None,
) -> Path:
    """Resolve and create the local backup storage directory with restrictive permissions."""
    if backup_dir_override is not None:
        target = Path(backup_dir_override).resolve()
    elif settings.REDMERCURY_DATA_DIR and str(settings.REDMERCURY_DATA_DIR).strip():
        target = Path(str(settings.REDMERCURY_DATA_DIR).strip()).resolve() / "backups"
    elif db_path is not None:
        target = db_path.parent / "backups"
    else:
        target = Path(settings.WORKSPACE_ROOT).resolve().parent / "backups"

    target.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        try:
            os.chmod(target, 0o700)
        except OSError:
            pass
    return target


def sanitize_backup_filename(filename: str) -> str:
    """Validate backup filename to block path traversal and enforce .rmbkp extension."""
    clean = os.path.basename((filename or "").strip())
    if not clean or clean in (".", "..") or "/" in filename or "\\" in filename or ".." in clean:
        raise ValidationError("Invalid backup filename.")
    if not clean.endswith(ALLOWED_BACKUP_EXTENSION):
        raise ValidationError(f"Backup archive must end with '{ALLOWED_BACKUP_EXTENSION}'.")
    return clean


def _find_alembic_ini(explicit_path: Optional[str] = None) -> Optional[Path]:
    candidates = []
    if explicit_path:
        candidates.append(Path(explicit_path))
    backend_dir = Path(__file__).resolve().parent.parent.parent
    candidates.extend([
        backend_dir / "alembic.ini",
        Path("backend/alembic.ini"),
        Path("alembic.ini"),
    ])
    for cand in candidates:
        if cand.is_file():
            return cand.resolve()
    return None


def cleanup_stale_startup_artifacts(data_dir: Optional[Path] = None, worker_temp_dir: Optional[Path] = None) -> int:
    """Remove leftover temporary staging files created during interrupted startup or backup writes."""
    removed = 0
    targets: List[Path] = []
    if data_dir and data_dir.is_dir():
        targets.append(data_dir)
        backups = data_dir / "backups"
        if backups.is_dir():
            targets.append(backups)
    if worker_temp_dir and worker_temp_dir.is_dir():
        targets.append(worker_temp_dir)

    for folder in targets:
        for item in folder.iterdir():
            if item.is_file() and (
                item.name.endswith(".tmp")
                or item.name.endswith(".tmp.zip")
                or item.name.endswith(".restore_tmp")
            ):
                try:
                    item.unlink(missing_ok=True)
                    removed += 1
                except OSError:
                    pass
    return removed


def verify_sqlite_file_integrity(db_path: Path, full_check: bool = False) -> Tuple[bool, str]:
    """Run SQLite PRAGMA quick_check / integrity_check on a SQLite database file."""
    if not db_path.is_file():
        return False, "SQLite database file does not exist."
    pragma_cmd = "PRAGMA integrity_check" if full_check else "PRAGMA quick_check"
    conn = sqlite3.connect(str(db_path), timeout=10.0)
    try:
        rows = conn.execute(pragma_cmd).fetchall()
        messages = [str(r[0]) for r in rows if r]
        ok = len(messages) == 1 and messages[0].lower() == "ok"
        return ok, "; ".join(messages) or "unknown"
    except sqlite3.DatabaseError as exc:
        return False, f"SQLite integrity check failed: {exc}"
    finally:
        conn.close()


def _read_alembic_revision_from_sqlite(db_path: Path) -> Optional[str]:
    if not db_path.is_file():
        return None
    conn = sqlite3.connect(str(db_path), timeout=5.0)
    try:
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='alembic_version'"
        )
        if not cur.fetchone():
            return None
        row = conn.execute("SELECT version_num FROM alembic_version LIMIT 1").fetchone()
        return str(row[0]) if row and row[0] else None
    except Exception:
        return None
    finally:
        conn.close()


def _sqlite_sidecar_paths(db_path: Path) -> List[Path]:
    return [
        Path(f"{db_path}-wal"),
        Path(f"{db_path}-shm"),
        Path(f"{db_path}-journal"),
    ]


def _remove_sqlite_sidecars(db_path: Path) -> None:
    for sidecar in _sqlite_sidecar_paths(db_path):
        if sidecar.exists():
            try:
                sidecar.unlink()
            except OSError:
                pass


def create_backup_archive(
    db_path: Optional[Path] = None,
    backup_dir: Optional[Path] = None,
    config_dir: Optional[Path] = None,
    prefix: str = "redmercury-backup",
    include_config: bool = True,
) -> Dict[str, Any]:
    """Create an atomic, WAL-consistent SQLite + non-secret config backup archive with SHA-256 manifest."""
    resolved_db = (db_path or resolve_sqlite_db_path())
    if resolved_db is None or not resolved_db.is_file():
        raise ValidationError(
            "Automated local backup currently requires an initialized file-backed SQLite database."
        )

    dest_dir = resolve_backup_dir(backup_dir_override=backup_dir, db_path=resolved_db)
    cfg_dir = resolve_config_dir(config_dir_override=config_dir)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    safe_prefix = "".join(c for c in prefix if c.isalnum() or c in ("-", "_")) or "redmercury-backup"
    archive_name = f"{safe_prefix}-{stamp}{ALLOWED_BACKUP_EXTENSION}"
    archive_path = dest_dir / archive_name
    counter = 1
    while archive_path.exists():
        archive_name = f"{safe_prefix}-{stamp}-{counter}{ALLOWED_BACKUP_EXTENSION}"
        archive_path = dest_dir / archive_name
        counter += 1

    with tempfile.TemporaryDirectory(dir=str(dest_dir)) as tmp_root_str:
        tmp_root = Path(tmp_root_str)
        snapshot_db = tmp_root / "redmercury.db"

        # Online atomic SQLite snapshot safe under active WAL connections
        src_conn = sqlite3.connect(str(resolved_db), timeout=15.0)
        dst_conn = sqlite3.connect(str(snapshot_db), timeout=15.0)
        try:
            src_conn.backup(dst_conn)
        finally:
            dst_conn.close()
            src_conn.close()

        ok_int, detail = verify_sqlite_file_integrity(snapshot_db, full_check=True)
        if not ok_int:
            raise ValidationError(f"Snapshot integrity verification failed: {detail}")

        alembic_rev = _read_alembic_revision_from_sqlite(snapshot_db)
        files_manifest: Dict[str, Dict[str, Any]] = {
            "database/redmercury.db": {
                "size": snapshot_db.stat().st_size,
                "sha256": _sha256_file(snapshot_db),
            }
        }

        copied_configs: List[Tuple[str, Path]] = []
        if include_config and cfg_dir and cfg_dir.is_dir():
            for cfg_name in SAFE_CONFIG_FILENAMES:
                src_cfg = cfg_dir / cfg_name
                if src_cfg.is_file():
                    arc_name = f"config/{cfg_name}"
                    copied_configs.append((arc_name, src_cfg))
                    files_manifest[arc_name] = {
                        "size": src_cfg.stat().st_size,
                        "sha256": _sha256_file(src_cfg),
                    }

        manifest: Dict[str, Any] = {
            "format_version": BACKUP_FORMAT_VERSION,
            "app_name": settings.APP_NAME,
            "app_version": settings.APP_VERSION,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "dialect": "sqlite",
            "alembic_revision": alembic_rev,
            "includes_config": bool(copied_configs),
            "excludes_secrets": True,
            "files": files_manifest,
        }

        tmp_zip = dest_dir / f".{archive_name}.tmp.zip"
        try:
            with zipfile.ZipFile(tmp_zip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
                zf.writestr("manifest.json", json.dumps(manifest, indent=2))
                zf.write(snapshot_db, "database/redmercury.db")
                for arc_name, src_cfg in copied_configs:
                    zf.write(src_cfg, arc_name)

            os.replace(tmp_zip, archive_path)
            if os.name == "posix":
                try:
                    os.chmod(archive_path, 0o600)
                except OSError:
                    pass
        finally:
            if tmp_zip.exists():
                tmp_zip.unlink(missing_ok=True)

    return {
        "filename": archive_name,
        "path": str(archive_path),
        "size_bytes": archive_path.stat().st_size,
        "sha256": _sha256_file(archive_path),
        "created_at": manifest["created_at"],
        "alembic_revision": alembic_rev,
        "includes_config": manifest["includes_config"],
        "excludes_secrets": True,
        "manifest": manifest,
    }


def _validate_zip_member_path(name: str) -> None:
    if not name or name.startswith("/") or name.startswith("\\") or ".." in name.replace("\\", "/").split("/"):
        raise ValidationError(f"Unsafe backup archive entry path rejected: '{name}'")
    if len(name) >= 2 and name[1] == ":":
        raise ValidationError(f"Drive-letter path rejected in backup archive: '{name}'")


def verify_backup_archive(archive_path: Path) -> Dict[str, Any]:
    """Cryptographically and structurally verify a backup archive before allowing inspection or restore."""
    if not archive_path.is_file():
        raise ValidationError(f"Backup archive not found: {archive_path.name}")

    try:
        with zipfile.ZipFile(archive_path, "r") as zf:
            names = zf.namelist()
            for info in zf.infolist():
                _validate_zip_member_path(info.filename)
                # Reject symlinks packed into zip metadata
                unix_mode = (info.external_attr >> 16) & 0o170000
                if unix_mode == 0o120000:
                    raise ValidationError(f"Symbolic link rejected in backup archive: '{info.filename}'")

            if "manifest.json" not in names:
                raise ValidationError("Backup archive is missing manifest.json.")

            try:
                manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
            except Exception as exc:
                raise ValidationError(f"Backup manifest.json is corrupted: {exc}") from exc

            if not isinstance(manifest, dict) or manifest.get("format_version") != BACKUP_FORMAT_VERSION:
                raise ValidationError("Unsupported or invalid backup format version.")

            manifest_files = manifest.get("files")
            if not isinstance(manifest_files, dict) or "database/redmercury.db" not in manifest_files:
                raise ValidationError("Backup manifest missing required database payload entry.")

            with tempfile.TemporaryDirectory() as tmp_dir_str:
                tmp_dir = Path(tmp_dir_str)
                for rel_path, meta in manifest_files.items():
                    _validate_zip_member_path(rel_path)
                    if rel_path not in names:
                        raise ValidationError(f"Backup missing expected payload '{rel_path}'.")
                    if not isinstance(meta, dict):
                        raise ValidationError(f"Malformed manifest entry for '{rel_path}'.")

                    extracted_path = tmp_dir / Path(rel_path).name
                    with zf.open(rel_path, "r") as src, open(extracted_path, "wb") as dst:
                        shutil.copyfileobj(src, dst)

                    actual_size = extracted_path.stat().st_size
                    actual_hash = _sha256_file(extracted_path)
                    if actual_size != meta.get("size") or actual_hash != str(meta.get("sha256", "")).lower():
                        raise ValidationError(
                            f"Checksum or size mismatch for '{rel_path}': archive may be corrupted or tampered."
                        )

                    if rel_path == "database/redmercury.db":
                        ok_db, detail = verify_sqlite_file_integrity(extracted_path, full_check=True)
                        if not ok_db:
                            raise ValidationError(f"Archived database failed SQLite integrity check: {detail}")

                        conn = sqlite3.connect(str(extracted_path), timeout=5.0)
                        try:
                            tables = {
                                str(r[0])
                                for r in conn.execute(
                                    "SELECT name FROM sqlite_master WHERE type='table'"
                                ).fetchall()
                            }
                        finally:
                            conn.close()
                        if "users" not in tables and "alembic_version" not in tables:
                            raise ValidationError("Archived SQLite file does not contain Red Mercury schema tables.")
    except zipfile.BadZipFile as exc:
        raise ValidationError(f"Invalid backup archive format: {exc}") from exc

    return {
        "valid": True,
        "filename": archive_path.name,
        "size_bytes": archive_path.stat().st_size,
        "sha256": _sha256_file(archive_path),
        "db_integrity": "ok",
        "manifest": manifest,
    }


def list_backup_archives(backup_dir: Optional[Path] = None, db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """List local .rmbkp archives sorted newest first with manifest metadata when valid."""
    target_dir = resolve_backup_dir(backup_dir_override=backup_dir, db_path=db_path or resolve_sqlite_db_path())
    items: List[Dict[str, Any]] = []
    for entry in sorted(target_dir.glob(f"*{ALLOWED_BACKUP_EXTENSION}"), key=lambda p: p.stat().st_mtime, reverse=True):
        if entry.name.startswith("pending_restore"):
            continue
        meta: Dict[str, Any] = {
            "filename": entry.name,
            "size_bytes": entry.stat().st_size,
            "modified_at": datetime.fromtimestamp(entry.stat().st_mtime, tz=timezone.utc).isoformat(),
            "alembic_revision": None,
            "includes_config": False,
            "valid_manifest": False,
        }
        try:
            with zipfile.ZipFile(entry, "r") as zf:
                if "manifest.json" in zf.namelist():
                    m = json.loads(zf.read("manifest.json").decode("utf-8"))
                    meta["created_at"] = m.get("created_at")
                    meta["alembic_revision"] = m.get("alembic_revision")
                    meta["includes_config"] = bool(m.get("includes_config"))
                    meta["app_version"] = m.get("app_version")
                    meta["valid_manifest"] = m.get("format_version") == BACKUP_FORMAT_VERSION
        except Exception:
            pass
        items.append(meta)
    return items


def _extract_and_apply_verified_archive(
    archive_path: Path,
    target_db_path: Path,
    target_config_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Apply a verified archive onto target SQLite DB and optional safe config files."""
    verification = verify_backup_archive(archive_path)
    target_db_path.parent.mkdir(parents=True, exist_ok=True)
    _remove_sqlite_sidecars(target_db_path)

    restored_configs: List[str] = []
    with tempfile.TemporaryDirectory(dir=str(target_db_path.parent)) as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        with zipfile.ZipFile(archive_path, "r") as zf:
            extracted_db = tmp_dir / "redmercury.db.restore_tmp"
            with zf.open("database/redmercury.db", "r") as src, open(extracted_db, "wb") as dst:
                shutil.copyfileobj(src, dst)

            src_conn = sqlite3.connect(str(extracted_db), timeout=15.0)
            dst_conn = sqlite3.connect(str(target_db_path), timeout=15.0)
            try:
                src_conn.backup(dst_conn)
            finally:
                dst_conn.close()
                src_conn.close()

            if target_config_dir is not None:
                target_config_dir.mkdir(parents=True, exist_ok=True)
                for cfg_name in SAFE_CONFIG_FILENAMES:
                    arc_name = f"config/{cfg_name}"
                    if arc_name in zf.namelist():
                        raw_bytes = zf.read(arc_name)
                        # Sanity-validate JSON config before overwriting local config
                        parsed = json.loads(raw_bytes.decode("utf-8"))
                        if isinstance(parsed, dict):
                            cfg_dest = target_config_dir / cfg_name
                            tmp_cfg = target_config_dir / f".{cfg_name}.tmp"
                            tmp_cfg.write_text(json.dumps(parsed, indent=2), encoding="utf-8")
                            os.replace(tmp_cfg, cfg_dest)
                            restored_configs.append(cfg_name)

    return {
        "restored_from": archive_path.name,
        "db_path": str(target_db_path),
        "restored_configs": restored_configs,
        "manifest": verification["manifest"],
    }


def stage_backup_restore(
    archive_path: Path,
    db_path: Optional[Path] = None,
    backup_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Verify backup integrity, save a pre-restore safety snapshot, and stage restore for next startup."""
    resolved_db = db_path or resolve_sqlite_db_path()
    if resolved_db is None:
        raise ValidationError("Restore requires a file-backed SQLite DATABASE_URL.")

    verification = verify_backup_archive(archive_path)
    dest_dir = resolve_backup_dir(backup_dir_override=backup_dir, db_path=resolved_db)

    pre_restore = None
    if resolved_db.is_file():
        pre_restore = create_backup_archive(
            db_path=resolved_db,
            backup_dir=dest_dir,
            prefix="pre-restore-safety",
        )

    pending_archive = dest_dir / f"pending_restore{ALLOWED_BACKUP_EXTENSION}"
    pending_meta = dest_dir / "pending_restore.json"
    tmp_pending = dest_dir / ".pending_restore.tmp.zip"
    shutil.copy2(archive_path, tmp_pending)
    os.replace(tmp_pending, pending_archive)

    meta_payload = {
        "staged_at": datetime.now(timezone.utc).isoformat(),
        "source_filename": archive_path.name,
        "archive_sha256": _sha256_file(pending_archive),
    }
    pending_meta.write_text(json.dumps(meta_payload, indent=2), encoding="utf-8")

    return {
        "status": "staged_for_restart",
        "requires_restart": True,
        "archive_filename": archive_path.name,
        "archive_sha256": verification["sha256"],
        "pre_restore_backup": pre_restore["filename"] if pre_restore else None,
        "manifest": verification["manifest"],
    }


def apply_pending_restore_if_present(
    target_db_path: Optional[Path] = None,
    target_config_dir: Optional[Path] = None,
    backup_dir: Optional[Path] = None,
) -> Optional[Dict[str, Any]]:
    """Apply a staged verified backup before FastAPI ORM sessions open."""
    resolved_db = target_db_path or resolve_sqlite_db_path()
    if resolved_db is None:
        return None
    dest_dir = resolve_backup_dir(backup_dir_override=backup_dir, db_path=resolved_db)
    pending_archive = dest_dir / f"pending_restore{ALLOWED_BACKUP_EXTENSION}"
    pending_meta = dest_dir / "pending_restore.json"

    if not pending_archive.is_file():
        if pending_meta.exists():
            pending_meta.unlink(missing_ok=True)
        return None

    try:
        if pending_meta.is_file():
            meta = json.loads(pending_meta.read_text(encoding="utf-8"))
            expected_hash = str(meta.get("archive_sha256") or "").lower()
            if expected_hash and _sha256_file(pending_archive) != expected_hash:
                raise ValidationError("Staged pending_restore archive checksum changed on disk; aborting restore.")

        cfg_dir = resolve_config_dir(config_dir_override=target_config_dir)
        result = _extract_and_apply_verified_archive(
            archive_path=pending_archive,
            target_db_path=resolved_db,
            target_config_dir=cfg_dir,
        )
        logger.info(f"Applied staged backup restore cleanly to {resolved_db}")
        return result
    finally:
        pending_archive.unlink(missing_ok=True)
        pending_meta.unlink(missing_ok=True)


def restore_backup_archive(
    archive_path: Path,
    engine_to_dispose: Optional[Engine] = None,
    db_path: Optional[Path] = None,
    backup_dir: Optional[Path] = None,
    config_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Validate and immediately restore a backup archive in-process after disposing DB pools."""
    resolved_db = db_path or resolve_sqlite_db_path()
    if resolved_db is None:
        raise ValidationError("Restore requires a file-backed SQLite DATABASE_URL.")

    dest_dir = resolve_backup_dir(backup_dir_override=backup_dir, db_path=resolved_db)
    verification = verify_backup_archive(archive_path)

    pre_restore = None
    if resolved_db.is_file():
        pre_restore = create_backup_archive(
            db_path=resolved_db,
            backup_dir=dest_dir,
            config_dir=config_dir,
            prefix="pre-restore-safety",
        )

    if engine_to_dispose is not None:
        engine_to_dispose.dispose()

    cfg_dir = resolve_config_dir(config_dir_override=config_dir)
    result = _extract_and_apply_verified_archive(
        archive_path=archive_path,
        target_db_path=resolved_db,
        target_config_dir=cfg_dir,
    )
    return {
        "status": "restored",
        "requires_restart": False,
        "archive_filename": archive_path.name,
        "archive_sha256": verification["sha256"],
        "pre_restore_backup": pre_restore["filename"] if pre_restore else None,
        "restored_configs": result["restored_configs"],
        "manifest": result["manifest"],
    }


def initialize_local_database(
    engine_override: Optional[Engine] = None,
    alembic_ini_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Run resilient first-run and crash-recovery initialization for the local SQLite database.

    Sequence:
    1. Ensure all SQLAlchemy models are registered cleanly on Base.metadata.
    2. Remove interrupted startup/backup .tmp files.
    3. Apply any staged verified restore bundle before opening ORM sessions.
    4. Verify SQLite file integrity if database already exists on disk.
    5. Create any missing schema tables and dynamically align/upgrade Alembic to head.
    """
    from ..db.base import Base
    from ..db.session import engine as default_engine
    try:
        from .. import models  # noqa: F401
    except (ImportError, ValueError):
        import app.models  # noqa: F401  Ensure every model table registers with Base.metadata

    active_engine = engine_override or default_engine
    dialect = active_engine.dialect.name
    summary: Dict[str, Any] = {
        "dialect": dialect,
        "first_run": False,
        "restored_pending": False,
        "alembic_revision": None,
        "alembic_action": "none",
        "integrity": "skipped",
    }

    if dialect != "sqlite":
        return summary

    db_url = active_engine.url.render_as_string(hide_password=False)
    db_path = resolve_sqlite_db_path(db_url)
    if db_path is not None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        summary["first_run"] = not db_path.exists()

    data_dir = Path(settings.REDMERCURY_DATA_DIR).resolve() if settings.REDMERCURY_DATA_DIR else (
        db_path.parent if db_path else None
    )
    worker_tmp = Path(os.environ["WORKER_TEMP_DIR"]).resolve() if os.environ.get("WORKER_TEMP_DIR") else None
    cleaned_tmp = cleanup_stale_startup_artifacts(data_dir=data_dir, worker_temp_dir=worker_tmp)
    summary["cleaned_tmp_files"] = cleaned_tmp

    if db_path is not None:
        pending_result = apply_pending_restore_if_present(target_db_path=db_path)
        if pending_result is not None:
            active_engine.dispose()
            summary["restored_pending"] = True
            summary["restored_from"] = pending_result["restored_from"]

        if db_path.is_file() and db_path.stat().st_size > 0:
            ok_int, detail = verify_sqlite_file_integrity(db_path, full_check=False)
            summary["integrity"] = detail
            if not ok_int:
                raise RuntimeError(f"Local database integrity check failed for {db_path}: {detail}")

    Base.metadata.create_all(bind=active_engine)

    ini_path = _find_alembic_ini(alembic_ini_path)
    if ini_path is not None:
        from alembic import command
        from alembic.config import Config
        from alembic.script import ScriptDirectory

        cfg = Config(str(ini_path))
        cfg.set_main_option("sqlalchemy.url", db_url.replace("%", "%%"))
        script_dir = ScriptDirectory.from_config(cfg)
        head_rev = script_dir.get_current_head()

        inspector = sa_inspect(active_engine)
        table_names = set(inspector.get_table_names())
        current_rev: Optional[str] = None
        if "alembic_version" in table_names:
            with active_engine.connect() as conn:
                row = conn.execute(text("SELECT version_num FROM alembic_version LIMIT 1")).fetchone()
                current_rev = str(row[0]) if row and row[0] else None

        if current_rev is None:
            command.stamp(cfg, "head")
            summary["alembic_action"] = "stamped_head"
            summary["alembic_revision"] = head_rev
        elif current_rev != head_rev:
            command.upgrade(cfg, "head")
            summary["alembic_action"] = f"upgraded:{current_rev}->{head_rev}"
            summary["alembic_revision"] = head_rev
        else:
            summary["alembic_revision"] = current_rev

    try:
        with active_engine.connect() as conn:
            conn.execute(text("PRAGMA wal_checkpoint(PASSIVE)"))
    except Exception:
        pass

    if db_path is not None and os.name == "posix":
        for p in [db_path, *_sqlite_sidecar_paths(db_path)]:
            if p.is_file():
                try:
                    os.chmod(p, 0o600)
                except OSError:
                    pass

    return summary
