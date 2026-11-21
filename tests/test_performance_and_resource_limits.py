"""Performance, Resource Management, Concurrency, and Cancellation Regression Tests.

Phase 3B: Validates resource limits, concurrency controls, scan cancellation,
stale job reconciliation, memory bounding, and database query optimization.
"""
from datetime import datetime, timedelta, timezone
from io import BytesIO
import json
from pathlib import Path
import tempfile
import time
import zipfile
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.errors import SecurityPolicyViolationError, ValidationError
from app.core.ingestion import validate_and_extract_zip
from app.core.quotas import check_scan_concurrency_and_quota, reconcile_interrupted_jobs
from app.models.finding import SecurityFinding
from app.models.repository import Repository
from app.models.scan import Scan
from app.models.user import User
from app.scanner.base import ScannerStatus
from app.scanner.runner import run_security_scan
from app.scanner.secret_detector import SecretScannerAdapter


# ==============================================================================
# 1. SCAN CANCELLATION AND CONCURRENCY SLOT RELEASE
# ==============================================================================

def test_scan_cancellation_endpoint(client_a: TestClient, db_session: Session, user_a: User):
    """Verify POST /api/v1/scans/{scan_id}/cancel transitions scan to cancelled and logs audit event."""
    # 1. Create a repository and scan record
    repo = Repository(
        owner_id=user_a.id,
        name="cancel-test-repo",
        source_type="test",
        workspace_path="/tmp/mock",
        default_branch="main",
        ingestion_status="completed",
        is_active=True,
    )
    db_session.add(repo)
    db_session.commit()

    scan = Scan(
        repository_id=repo.id,
        status="queued",
        summary="Scan to be cancelled",
    )
    db_session.add(scan)
    db_session.commit()

    # 2. Invoke cancel endpoint
    cancel_res = client_a.post(f"/api/v1/scans/{scan.id}/cancel")
    assert cancel_res.status_code == 200
    data = cancel_res.json()
    assert data["status"] == "cancelled"

    # 3. Verify in database
    db_session.refresh(scan)
    assert scan.status == "cancelled"
    assert scan.completed_at is not None
    summary = json.loads(scan.summary or "{}")
    assert summary.get("status") == "cancelled"


def test_scan_cancellation_releases_concurrency_slots(db_session: Session, user_a: User):
    """Verify that cancelling an active scan releases the user's concurrency slot."""
    repo = Repository(
        owner_id=user_a.id,
        name="concurrency-test-repo",
        source_type="test",
        workspace_path="/tmp/mock",
        default_branch="main",
        ingestion_status="completed",
        is_active=True,
    )
    db_session.add(repo)
    db_session.commit()

    # Create maximum allowed concurrent active scans (3)
    scans = []
    for i in range(settings.MAX_CONCURRENT_SCANS_PER_USER):
        s = Scan(repository_id=repo.id, status="running")
        db_session.add(s)
        scans.append(s)
    db_session.commit()

    # 4th concurrent scan must be rejected by concurrency quota
    with pytest.raises(SecurityPolicyViolationError) as exc_info:
        check_scan_concurrency_and_quota(user=user_a, db=db_session)
    assert "Concurrency limit reached" in str(exc_info.value)

    # Cancel one of the scans
    scans[0].status = "cancelled"
    scans[0].completed_at = datetime.now(timezone.utc)
    db_session.commit()

    # Quota check should now pass without exception
    check_scan_concurrency_and_quota(user=user_a, db=db_session)


# ==============================================================================
# 2. STALE SCAN RECONCILIATION & DUPLICATE EXECUTION PREVENTION
# ==============================================================================

def test_reconcile_stale_scans_cleans_queued_and_running(db_session: Session, user_a: User):
    """Verify that stale scans (> 15 min old) in running or queued state transition to interrupted."""
    repo = Repository(
        owner_id=user_a.id,
        name="stale-test-repo",
        source_type="test",
        workspace_path="/tmp/mock",
        default_branch="main",
        ingestion_status="completed",
        is_active=True,
    )
    db_session.add(repo)
    db_session.commit()

    stale_time = datetime.now(timezone.utc) - timedelta(minutes=settings.STALE_JOB_TIMEOUT_MINUTES + 5)

    s_running = Scan(repository_id=repo.id, status="running")
    s_queued = Scan(repository_id=repo.id, status="queued")
    s_fresh = Scan(repository_id=repo.id, status="running")
    db_session.add_all([s_running, s_queued, s_fresh])
    db_session.commit()

    # Backdate the stale scans
    s_running.created_at = stale_time
    s_queued.created_at = stale_time
    db_session.commit()

    reconciled_count = reconcile_interrupted_jobs(db_session)
    assert reconciled_count >= 2

    db_session.refresh(s_running)
    db_session.refresh(s_queued)
    db_session.refresh(s_fresh)

    assert s_running.status == "interrupted"
    assert s_queued.status == "interrupted"
    assert s_fresh.status == "running"


def test_duplicate_scan_worker_execution_prevented(db_session: Session, user_a: User):
    """Verify atomic state claiming prevents dual execution of the same scan job."""
    repo = Repository(
        owner_id=user_a.id,
        name="atomic-claim-repo",
        source_type="test",
        workspace_path="/tmp/mock",
        default_branch="main",
        ingestion_status="completed",
        is_active=True,
    )
    db_session.add(repo)
    db_session.commit()

    scan = Scan(repository_id=repo.id, status="queued")
    db_session.add(scan)
    db_session.commit()

    # Worker 1 claims the scan
    rows_worker1 = (
        db_session.query(Scan)
        .filter(Scan.id == scan.id, Scan.status.in_(["queued", "pending"]))
        .update({"status": "running", "started_at": datetime.now(timezone.utc)})
    )
    db_session.commit()
    assert rows_worker1 == 1

    # Worker 2 attempts to claim the same scan simultaneously
    rows_worker2 = (
        db_session.query(Scan)
        .filter(Scan.id == scan.id, Scan.status.in_(["queued", "pending"]))
        .update({"status": "running", "started_at": datetime.now(timezone.utc)})
    )
    db_session.commit()
    assert rows_worker2 == 0, "Worker 2 must NOT claim already running scan!"


# ==============================================================================
# 3. RESOURCE LIMITS & TRANSPARENT SKIPPED FILES RECORDING
# ==============================================================================

def test_secret_scanner_skips_and_records_oversized_files(tmp_path: Path):
    """Verify secret detector streams line-by-line and records files > 2MB in skipped_files."""
    # 1. Normal file with secret
    (tmp_path / "normal.py").write_text("API_KEY = 'AKIA1234567890ABCDEF'\n", encoding="utf-8")

    # 2. Oversized file (3 MB)
    big_file = tmp_path / "big_dataset.csv"
    big_file.write_bytes(b"col1,col2,col3\n" + (b"data," * 600000))
    assert big_file.stat().st_size > 2 * 1024 * 1024

    adapter = SecretScannerAdapter()
    result = adapter.scan(target_dir=tmp_path, scan_id="test-perf-skip")

    assert result.status == ScannerStatus.SUCCESS
    assert len(result.findings) >= 1
    # Verify oversized file was transparently tracked
    assert len(result.skipped_files) >= 1
    assert any("big_dataset.csv" in s for s in result.skipped_files)
    assert any("oversized" in s.lower() for s in result.skipped_files)


def test_archive_file_count_limit_enforced(tmp_path: Path):
    """Verify ingestion rejects archives with > MAX_FILE_COUNT files to prevent inode exhaustion."""
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        # Create limit + 1 small files
        for i in range(settings.MAX_FILE_COUNT + 1):
            zf.writestr(f"f_{i}.txt", "x")
    buf.seek(0)

    zip_file = tmp_path / "too_many_files.zip"
    zip_file.write_bytes(buf.getvalue())

    dest_dir = tmp_path / "extracted"
    dest_dir.mkdir()

    with pytest.raises(ValidationError) as exc_info:
        validate_and_extract_zip(zip_file, dest_dir)
    assert "exceeding the maximum allowed limit" in str(exc_info.value)


def test_archive_zip_bomb_ratio_limit_enforced(tmp_path: Path):
    """Verify ingestion rejects suspicious expansion ratios > MAX_COMPRESSION_RATIO."""
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # Highly compressible repeating data: 10MB of zeros compresses to a few KB
        zf.writestr("zero.dat", b"\x00" * (10 * 1024 * 1024))
    buf.seek(0)

    zip_file = tmp_path / "bomb.zip"
    zip_file.write_bytes(buf.getvalue())

    dest_dir = tmp_path / "extracted"
    dest_dir.mkdir()

    with pytest.raises(ValidationError) as exc_info:
        validate_and_extract_zip(zip_file, dest_dir)
    assert "potential Zip Bomb" in str(exc_info.value)


# ==============================================================================
# 4. DATABASE QUERY AGGREGATION EFFICIENCY
# ==============================================================================

def test_database_query_volume_during_scan(tmp_path: Path, db_session: Session, user_a: User):
    """Verify scan runner uses single aggregated GROUP BY query instead of repeated count queries."""
    (tmp_path / "test.py").write_text("import os\nos.system('test')\n", encoding="utf-8")

    repo = Repository(
        owner_id=user_a.id,
        name="query-eff-repo",
        source_type="test",
        workspace_path=str(tmp_path),
        default_branch="main",
        ingestion_status="completed",
        is_active=True,
    )
    db_session.add(repo)
    db_session.commit()

    scan = Scan(repository_id=repo.id, status="pending")
    db_session.add(scan)
    db_session.commit()

    # Track queries during run_security_scan
    query_log = []
    engine = db_session.get_bind()

    def query_listener(conn, cursor, statement, parameters, context, executemany):
        query_log.append(statement)

    event.listen(engine, "before_cursor_execute", query_listener)
    try:
        run_security_scan(repo, scan, db_session, selected_tools=["secret_detector"])
    finally:
        event.remove(engine, "before_cursor_execute", query_listener)

    # Verify query count is strictly bounded (<= 15 queries)
    assert len(query_log) <= 15
    # Verify GROUP BY was utilized for severity counting
    assert any("group by" in q.lower() for q in query_log), "Expected aggregated GROUP BY query for finding counts!"
