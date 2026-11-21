"""Comprehensive cleanup script for Red Mercury.
Removes all dummy data, test artifacts, orphaned records, and temporary workspaces,
while ensuring the primary user account and database schema are in a clean state.
"""
import os
import shutil
import sqlite3
import sys
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
backend_path = WORKSPACE_ROOT / "backend"
sys.path.insert(0, str(backend_path))

try:
    from app.core.security import hash_password
    from app.core.config import settings
except ImportError:
    hash_password = None
    settings = None


def clean_primary_database(db_path: Path):
    """Clean all dummy/mock entities from primary database."""
    if not db_path.exists():
        print(f"[SKIP] Database {db_path} does not exist.")
        return

    print(f"[CLEAN] Purging dummy data from {db_path}...")
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    # Tables to clear of test/dummy data
    tables_to_clear = [
        "verification_evidence",
        "verification_runs",
        "fix_verifications",
        "finding_validations",
        "finding_analyses",
        "patch_proposals",
        "security_evidence",
        "security_findings",
        "pull_request_scans",
        "webhook_deliveries",
        "repository_github_links",
        "github_integrations",
        "scans",
        "repositories",
        "revoked_tokens",
        "audit_events",
    ]

    for table in tables_to_clear:
        try:
            cur.execute(f'DELETE FROM "{table}"')
        except sqlite3.OperationalError:
            pass  # Table might not exist yet

    # Remove non-primary users, keep dhineshkumardhina@gmail.com
    primary_email = "dhineshkumardhina@gmail.com"
    cur.execute(f"DELETE FROM users WHERE email != '{primary_email}'")

    # Ensure primary user exists with correct admin role
    existing = cur.execute(f"SELECT id, role FROM users WHERE email = '{primary_email}'").fetchone()
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")

    if not existing:
        pwd = settings.DEV_SEED_PASSWORD if settings else "XerovaDevPass2026!"
        pwd_hash = hash_password(pwd) if hash_password else "$2b$12$ib2Tg4zVku.0Fwuxh0Eycuud0H9DEgrcwSnnrbOlIVJTnY1pgh0da"
        cur.execute(
            """
            INSERT INTO users (id, email, password_hash, account_status, role, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            ("ade14bbe-e0f0-4c8e-beff-ff9f720fe288", primary_email, pwd_hash, "active", "admin", now, now)
        )
    else:
        # Update user to ensure active and admin
        cur.execute(f"UPDATE users SET role = 'admin', account_status = 'active', updated_at = '{now}' WHERE email = '{primary_email}'")

    conn.commit()

    # Print summary of remaining records
    print("  Remaining users:", cur.execute("SELECT id, email, role, account_status FROM users").fetchall())
    print("  Remaining repos:", cur.execute("SELECT count(*) FROM repositories").fetchone()[0])
    print("  Remaining findings:", cur.execute("SELECT count(*) FROM security_findings").fetchone()[0])
    print("  Remaining scans:", cur.execute("SELECT count(*) FROM scans").fetchone()[0])
    print("  Remaining verifications:", cur.execute("SELECT count(*) FROM verification_runs").fetchone()[0])
    conn.close()


def remove_stray_databases():
    """Remove secondary and test databases."""
    stray_dbs = [
        WORKSPACE_ROOT / "test_redmercury.db",
        WORKSPACE_ROOT / "backend" / "redmercury.db",
    ]
    for db in stray_dbs:
        if db.exists():
            try:
                db.unlink()
                print(f"[REMOVED] Stray database: {db.relative_to(WORKSPACE_ROOT)}")
            except Exception as exc:
                print(f"[WARN] Could not remove {db}: {exc}")


def clean_workspaces():
    """Clean leftover test workspaces in backend/data/workspaces."""
    ws_dir = WORKSPACE_ROOT / "backend" / "data" / "workspaces"
    if ws_dir.exists():
        count = 0
        for item in ws_dir.iterdir():
            if item.is_dir() and item.name != ".git":
                try:
                    shutil.rmtree(item, ignore_errors=True)
                    count += 1
                except Exception as exc:
                    print(f"[WARN] Could not remove workspace directory {item}: {exc}")
        print(f"[CLEANED] Removed {count} temporary workspace sandbox directories.")


def clean_temp_directories():
    """Remove empty temporary directories and zero-byte log files."""
    temp_dirs = [
        WORKSPACE_ROOT / "temp_ws",
        WORKSPACE_ROOT / "tmp_artifacts",
    ]
    for d in temp_dirs:
        if d.exists():
            try:
                shutil.rmtree(d, ignore_errors=True)
                print(f"[REMOVED] Temp directory: {d.relative_to(WORKSPACE_ROOT)}")
            except Exception as exc:
                print(f"[WARN] Could not remove {d}: {exc}")

    temp_files = [
        WORKSPACE_ROOT / "backend" / "error_backend.log",
        WORKSPACE_ROOT / "backend" / "out_backend.log",
        WORKSPACE_ROOT / "benchmark_baseline.json",
        WORKSPACE_ROOT / "benchmark_optimized.json",
        WORKSPACE_ROOT / "scripts" / "inspect_db.py",
    ]
    for f in temp_files:
        if f.exists():
            try:
                f.unlink()
                print(f"[REMOVED] Temp file: {f.relative_to(WORKSPACE_ROOT)}")
            except Exception as exc:
                print(f"[WARN] Could not remove {f}: {exc}")


if __name__ == "__main__":
    print("=" * 60)
    print(" Red Mercury - Cleanup Utility")
    print("=" * 60)
    clean_primary_database(WORKSPACE_ROOT / "redmercury.db")
    remove_stray_databases()
    clean_workspaces()
    clean_temp_directories()
    print("=" * 60)
    print(" Cleanup complete! Project is clean of all dummy/test artifacts.")
    print("=" * 60)
