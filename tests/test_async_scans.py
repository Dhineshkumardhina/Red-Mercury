"""Automated Tests for Asynchronous Scan Processing and Status Polling.

Covers:
- POST /api/v1/scans returning HTTP 202 Accepted with queued state
- Synchronous query parameter ?sync=true returning HTTP 201 Created
- GET /api/v1/scans/{scan_id}/status real-time status polling
- Multi-tenant authorization (401 Unauthorized, 403 Forbidden for cross-tenant)
- Reconciliation of interrupted / stale running scans (preventing stuck jobs)
- Real scanner execution persistence without synthetic results
"""

from datetime import datetime, timezone, timedelta
from io import BytesIO
import zipfile
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.models.user import User
from app.models.repository import Repository
from app.models.scan import Scan
from app.core.quotas import reconcile_interrupted_jobs


def create_sample_zip() -> bytes:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        code = (
            "import os\n"
            "def run_command(cmd):\n"
            "    # Vulnerable to command injection\n"
            "    os.system(cmd)\n"
        )
        zf.writestr("app/vuln.py", code)
    buf.seek(0)
    return buf.getvalue()


def test_async_scan_returns_202_and_completes_in_background(client_a: TestClient):
    """POST /api/v1/scans should return 202 Accepted and be trackable via /status."""
    # 1. Ingest repository
    zip_bytes = create_sample_zip()
    upload_res = client_a.post(
        "/api/v1/repositories/ingest/upload",
        files={"file": ("test_async_repo.zip", zip_bytes, "application/zip")},
        data={"name": "async-test-project"},
    )
    assert upload_res.status_code == 201
    repo_id = upload_res.json()["id"]

    # 2. Trigger asynchronous scan
    scan_res = client_a.post(
        "/api/v1/scans",
        json={
            "repository_id": repo_id,
            "tools": ["bandit"],
            "timeout_seconds": 30,
            "summary": "Async scan validation run",
        },
    )
    assert scan_res.status_code == 202, f"Expected 202 Accepted, got: {scan_res.text}"
    scan_data = scan_res.json()
    assert "id" in scan_data
    assert scan_data["repository_id"] == repo_id
    assert scan_data["status"] == "queued"
    scan_id = scan_data["id"]

    # 3. Check status endpoint
    status_res = client_a.get(f"/api/v1/scans/{scan_id}/status")
    assert status_res.status_code == 200
    status_data = status_res.json()
    assert status_data["id"] == scan_id
    assert status_data["repository_id"] == repo_id
    assert status_data["status"] == "completed"
    assert status_data["is_complete"] is True
    assert status_data["total_findings"] >= 1

    # 4. Check full results endpoint
    results_res = client_a.get(f"/api/v1/scans/{scan_id}/results")
    assert results_res.status_code == 200
    results_data = results_res.json()
    assert results_data["status"] == "completed"
    assert results_data["total_findings"] >= 1
    assert len(results_data["scanners"]) >= 1


def test_sync_mode_parameter_returns_201_created(client_a: TestClient):
    """POST /api/v1/scans?sync=true should return 201 Created synchronously."""
    # Ingest repo
    zip_bytes = create_sample_zip()
    upload_res = client_a.post(
        "/api/v1/repositories/ingest/upload",
        files={"file": ("test_sync_repo.zip", zip_bytes, "application/zip")},
        data={"name": "sync-test-project"},
    )
    assert upload_res.status_code == 201
    repo_id = upload_res.json()["id"]

    # Trigger scan with sync=true
    scan_res = client_a.post(
        "/api/v1/scans?sync=true",
        json={
            "repository_id": repo_id,
            "tools": ["bandit"],
        },
    )
    assert scan_res.status_code == 201
    scan_data = scan_res.json()
    assert scan_data["status"] == "completed"


def test_scan_status_authorization_enforcement(client_a: TestClient, client_b: TestClient):
    """Scan status endpoint must strictly enforce tenant authorization."""
    # Alice creates a repo and triggers scan
    zip_bytes = create_sample_zip()
    upload_res = client_a.post(
        "/api/v1/repositories/ingest/upload",
        files={"file": ("auth_repo.zip", zip_bytes, "application/zip")},
        data={"name": "auth-isolation-project"},
    )
    assert upload_res.status_code == 201
    repo_id = upload_res.json()["id"]
    scan_res = client_a.post(
        "/api/v1/scans",
        json={"repository_id": repo_id, "tools": ["bandit"]},
    )
    assert scan_res.status_code in (201, 202)
    scan_id = scan_res.json()["id"]

    # 1. Anonymous request -> 401 Unauthorized
    anon_client = TestClient(app)
    anon_res = anon_client.get(f"/api/v1/scans/{scan_id}/status")
    assert anon_res.status_code == 401

    # 2. Bob (cross-tenant) -> 403 Forbidden
    bob_status_res = client_b.get(f"/api/v1/scans/{scan_id}/status")
    assert bob_status_res.status_code == 403
    assert bob_status_res.json()["error"]["code"] == "FORBIDDEN"

    # 3. Bob attempts to fetch results -> 403 Forbidden
    bob_results_res = client_b.get(f"/api/v1/scans/{scan_id}/results")
    assert bob_results_res.status_code == 403

    # 4. Non-existent scan -> 404 Not Found
    alice_404_res = client_a.get("/api/v1/scans/00000000-0000-0000-0000-000000000000/status")
    assert alice_404_res.status_code == 404


def test_stale_running_scans_reconciliation_cleans_deadlocks(db_session: Session, user_a: User):
    """Reconciliation must mark stale/orphaned running scans as interrupted."""
    repo = Repository(
        name="stale-repo-test",
        owner_id=user_a.id,
        is_active=True,
    )
    db_session.add(repo)
    db_session.commit()
    db_session.refresh(repo)

    # Create a stuck scan with created_at 2 hours ago in 'running' state
    two_hours_ago = datetime.now(timezone.utc) - timedelta(hours=2)
    stuck_scan = Scan(
        repository_id=repo.id,
        status="running",
        started_at=two_hours_ago,
        created_at=two_hours_ago,
        summary="Orphaned scanner process",
    )
    db_session.add(stuck_scan)
    db_session.commit()
    db_session.refresh(stuck_scan)

    # Run reconciliation
    reconciled_count = reconcile_interrupted_jobs(db=db_session)
    assert reconciled_count >= 1

    # Verify scan state transitioned from running to interrupted
    db_session.refresh(stuck_scan)
    assert stuck_scan.status == "interrupted"
    assert "interrupted" in (stuck_scan.summary or "").lower()
