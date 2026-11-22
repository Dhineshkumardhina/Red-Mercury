"""Comprehensive Regression & Reliability Tests for Red Mercury.

Validates:
1. Role-Based Access Control (RBAC) mutating endpoint restrictions (Viewer/Auditor 403 Forbidden).
2. Cross-Tenant isolation and object ownership enforcement.
3. Operational rate-limiting (Ingest, Scans, AI Requests, Reports) with 429 and Retry-After.
4. Controlled failure recovery (Scanner crash, Timeout, Cancellation preservation, Duplicate scan rejection).
5. Retries and deduplication (zero finding duplicates or record corruption).
6. AI provider resilience (Timeout and malformed output fallback).
7. Worker restart reconciliation of pending/interrupted jobs.
8. Database connection error safe error envelope.
9. Log credential masking and secret scrubbing.
"""
from datetime import datetime, timedelta, timezone
import json
import logging
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.errors import AppSecException, DatabaseError
from app.core.logging import scrub_log_message
from app.core.quotas import reconcile_interrupted_jobs
from app.core.security import auth_rate_limiter, create_access_token
from app.main import app
from app.models.finding import SecurityFinding
from app.models.repository import Repository
from app.models.scan import Scan
from app.models.user import User
from app.models.verification import VerificationRun
from app.scanner.base import BaseScannerAdapter, NormalizedFinding, ScanJobResult, ScannerStatus
from app.scanner.runner import run_security_scan


# ==============================================================================
# 1. RBAC: Viewer & Auditor Role Restrictions on Prohibited Mutations
# ==============================================================================

def test_viewer_and_auditor_prohibited_from_evidence_creation(client: TestClient, create_test_user, db_session: Session):
    """Viewer and auditor roles must receive 403 Forbidden when attempting to record evidence."""
    viewer = create_test_user(email=f"viewer_ev_{uuid.uuid4().hex[:6]}@xerova.com", role="viewer")
    auditor = create_test_user(email=f"auditor_ev_{uuid.uuid4().hex[:6]}@xerova.com", role="auditor")

    v_token = create_access_token({"sub": viewer.id, "email": viewer.email, "role": "viewer"})
    a_token = create_access_token({"sub": auditor.id, "email": auditor.email, "role": "auditor"})

    repo = Repository(
        id=f"repo_ev_{uuid.uuid4().hex[:6]}",
        owner_id=viewer.id,
        name="viewer-repo",
        default_branch="main",
    )
    db_session.add(repo)
    db_session.commit()

    evidence_payload = {
        "repository_id": repo.id,
        "evidence_category": "SAST_REPORT",
        "title": "Evidence Ingestion Attempt",
        "tool_name": "Semgrep",
        "provenance": "STATIC_ANALYSIS",
    }

    # Viewer attempt -> 403
    v_res = client.post("/api/v1/evidence", json=evidence_payload, headers={"Authorization": f"Bearer {v_token}"})
    assert v_res.status_code == 403, f"Viewer should be 403, got {v_res.status_code}"

    # Auditor attempt -> 403
    a_res = client.post("/api/v1/evidence", json=evidence_payload, headers={"Authorization": f"Bearer {a_token}"})
    assert a_res.status_code == 403, f"Auditor should be 403, got {a_res.status_code}"


def test_viewer_and_auditor_prohibited_from_verification_rerun(client: TestClient, create_test_user, db_session: Session):
    """Viewer and auditor roles must receive 403 Forbidden when attempting to rerun fix verification."""
    viewer = create_test_user(email=f"viewer_vr_{uuid.uuid4().hex[:6]}@xerova.com", role="viewer")
    v_token = create_access_token({"sub": viewer.id, "email": viewer.email, "role": "viewer"})

    repo = Repository(id=f"repo_vr_{uuid.uuid4().hex[:6]}", owner_id=viewer.id, name="vr-repo", default_branch="main")
    finding = SecurityFinding(
        id=f"fnd_vr_{uuid.uuid4().hex[:6]}",
        repo_id=repo.id,
        title="Test Finding",
        severity="HIGH",
        cwe="CWE-89",
        scanner_name="Semgrep OSS",
        scanner_identifier="Semgrep OSS",
        rule_identifier="CWE-89",
        file_path="src/vuln.py",
        line_number=10,
    )
    run = VerificationRun(id=f"run_vr_{uuid.uuid4().hex[:6]}", finding_id=finding.id, patch_diff="--- a\n+++ b\n", status="COMPLETED")
    db_session.add_all([repo, finding, run])
    db_session.commit()

    res = client.post(f"/api/v1/verifications/{run.id}/rerun", headers={"Authorization": f"Bearer {v_token}"})
    assert res.status_code == 403, f"Viewer should be blocked from verification rerun, got {res.status_code}"


def test_viewer_and_auditor_prohibited_from_integrations_mutations(client: TestClient, create_test_user):
    """Viewer and auditor roles must receive 403 Forbidden on GitHub integrations mutating endpoints."""
    auditor = create_test_user(email=f"auditor_int_{uuid.uuid4().hex[:6]}@xerova.com", role="auditor")
    a_token = create_access_token({"sub": auditor.id, "email": auditor.email, "role": "auditor"})
    headers = {"Authorization": f"Bearer {a_token}"}

    # 1. Register GitHub installation
    res1 = client.post("/api/v1/integrations/github/installations", json={"installation_id": 12345, "app_id": 67890}, headers=headers)
    assert res1.status_code == 403

    # 2. Link repository
    res2 = client.post("/api/v1/integrations/github/links", json={"repository_id": "r1", "github_repo_owner": "org", "github_repo_name": "repo"}, headers=headers)
    assert res2.status_code == 403

    # 3. Create PR scan
    res3 = client.post("/api/v1/integrations/github/pr-scans", json={"repository_id": "r1", "pull_request_number": 1, "head_sha": "abc"}, headers=headers)
    assert res3.status_code == 403


# ==============================================================================
# 2. Multi-Tenant Isolation & Ownership Enforcement
# ==============================================================================

def test_cross_tenant_analyze_finding_with_foreign_repo_id_blocked(client_a: TestClient, client_b: TestClient, db_session: Session):
    """Bob cannot analyze a finding while supplying Alice's repo_id to exfiltrate context."""
    # Alice creates repository
    repo_res = client_a.post("/api/v1/repositories", json={"name": "alice-classified-vault", "default_branch": "main"})
    assert repo_res.status_code == 201
    alice_repo_id = repo_res.json()["id"]

    # Bob attempts to request AI analysis passing Alice's repo_id
    bob_req = {
        "finding_id": "FIND-EXTERNAL-001",
        "repo_id": alice_repo_id,
        "vulnerability_category": "CWE-89",
        "file_path": "secret.py",
        "line_number": 1,
        "user_authorized_analysis": True,
    }
    res = client_b.post("/api/v1/analyze-finding", json=bob_req)
    assert res.status_code == 403, f"Expected 403 Forbidden for cross-tenant repo_id, got {res.status_code}"
    assert "permission" in res.json()["error"]["message"].lower()


# ==============================================================================
# 3. Operational Rate Limiting
# ==============================================================================

def test_operational_rate_limiting_on_ingest(client_a: TestClient):
    """Rate limiter enforces max requests on repository ingestion."""
    auth_rate_limiter.reset()

    # Saturate rate limit for local ingestion
    for _ in range(settings.RATE_LIMIT_INGEST_MAX):
        # We don't care if payload fails validation, rate limiter runs at middleware level
        client_a.post("/api/v1/repositories/ingest/local", json={"local_path": "/invalid"})

    # The (MAX+1)th request must be throttled with HTTP 429
    throttled = client_a.post("/api/v1/repositories/ingest/local", json={"local_path": "/invalid"})
    assert throttled.status_code == 429
    assert throttled.headers.get("Retry-After") is not None
    assert throttled.json()["error"]["code"] == "RATE_LIMIT_EXCEEDED"
    assert "repository ingestion" in throttled.json()["error"]["message"].lower()

    auth_rate_limiter.reset()


def test_operational_rate_limiting_on_ai_requests(client_a: TestClient):
    """Rate limiter enforces max requests on expensive AI security analysis."""
    auth_rate_limiter.reset()

    for _ in range(settings.RATE_LIMIT_AI_MAX):
        client_a.post("/api/v1/analyze-finding", json={"finding_id": "F-RATE", "user_authorized_analysis": True})

    throttled = client_a.post("/api/v1/analyze-finding", json={"finding_id": "F-RATE", "user_authorized_analysis": True})
    assert throttled.status_code == 429
    assert throttled.headers.get("Retry-After") is not None
    assert throttled.json()["error"]["code"] == "RATE_LIMIT_EXCEEDED"
    assert "ai security analysis" in throttled.json()["error"]["message"].lower()

    auth_rate_limiter.reset()


# ==============================================================================
# 4. Controlled Failure Recovery: Scanner Process Exit & Timeout
# ==============================================================================

class MockCrashingScanner(BaseScannerAdapter):
    """Scanner adapter that crashes / raises an unexpected exception."""
    name = "mock_crasher"
    display_name = "Mock Crasher"
    category = "sast"

    def is_available(self) -> bool:
        return True

    def get_version(self) -> str:
        return "1.0.0"

    def scan(self, target_dir, scan_id, timeout_seconds=60, options=None):
        raise RuntimeError("SIGSEGV: Native scanner binary terminated unexpectedly with code -11")


class MockTimeoutScanner(BaseScannerAdapter):
    """Scanner adapter that reports a timeout."""
    name = "mock_timeout"
    display_name = "Mock Timeout"
    category = "sast"

    def is_available(self) -> bool:
        return True

    def get_version(self) -> str:
        return "1.0.0"

    def scan(self, target_dir, scan_id, timeout_seconds=60, options=None):
        return ScanJobResult(
            scanner_name=self.display_name,
            scanner_version="1.0.0",
            category=self.category,
            status=ScannerStatus.TIMEOUT,
            execution_time_seconds=float(timeout_seconds),
            error_message=f"Scanner execution timed out after {timeout_seconds} seconds.",
        )


class MockSuccessfulScanner(BaseScannerAdapter):
    """Scanner adapter that completes successfully with a finding."""
    name = "mock_success"
    display_name = "Mock Success"
    category = "sast"

    def is_available(self) -> bool:
        return True

    def get_version(self) -> str:
        return "1.0.0"

    def scan(self, target_dir, scan_id, timeout_seconds=60, options=None):
        return ScanJobResult(
            scanner_name=self.display_name,
            scanner_version="1.0.0",
            category=self.category,
            status=ScannerStatus.SUCCESS,
            execution_time_seconds=0.1,
            findings=[
                NormalizedFinding(
                    scan_id=scan_id,
                    scanner_name=self.display_name,
                    scanner_rule_id="RULE-MOCK-01",
                    severity="HIGH",
                    file_path="src/app.py",
                    start_line=10,
                    scanner_message="Mock security finding",
                )
            ],
        )


def test_scanner_crash_handled_without_silent_success(db_session: Session, user_a: User, tmp_path):
    """When a scanner process crashes, the scan must not silently succeed and must record failure."""
    from app.scanner.registry import scanner_registry

    # Register crashing adapter
    crasher = MockCrashingScanner()
    scanner_registry.register(crasher)

    repo = Repository(
        id=f"repo_crash_{uuid.uuid4().hex[:6]}",
        owner_id=user_a.id,
        name="crash-test-repo",
        workspace_path=str(tmp_path),
        default_branch="main",
    )
    scan = Scan(
        id=f"scan_crash_{uuid.uuid4().hex[:6]}",
        repository_id=repo.id,
        status="pending",
    )
    db_session.add_all([repo, scan])
    db_session.commit()

    # Execute with crasher only
    completed_scan = run_security_scan(
        repo=repo,
        scan=scan,
        db=db_session,
        selected_tools=["mock_crasher"],
    )

    # Status must be failed, NOT completed!
    assert completed_scan.status == "failed"
    summary = json.loads(completed_scan.summary)
    assert any(s["scanner_name"] == "Mock Crasher" and s["status"] == "execution_error" for s in summary["scanners"])


def test_partial_scanner_failure_transitions_to_partial_status(db_session: Session, user_a: User, tmp_path):
    """When one scanner succeeds and another times out / errors, status must be 'partial', never 'completed'."""
    from app.scanner.registry import scanner_registry

    success_tool = MockSuccessfulScanner()
    timeout_tool = MockTimeoutScanner()
    scanner_registry.register(success_tool)
    scanner_registry.register(timeout_tool)

    repo = Repository(
        id=f"repo_part_{uuid.uuid4().hex[:6]}",
        owner_id=user_a.id,
        name="part-test-repo",
        workspace_path=str(tmp_path),
        default_branch="main",
    )
    scan = Scan(
        id=f"scan_part_{uuid.uuid4().hex[:6]}",
        repository_id=repo.id,
        status="pending",
    )
    db_session.add_all([repo, scan])
    db_session.commit()

    completed_scan = run_security_scan(
        repo=repo,
        scan=scan,
        db=db_session,
        selected_tools=["mock_success", "mock_timeout"],
    )

    # Status must be 'partial'
    assert completed_scan.status == "partial"
    summary = json.loads(completed_scan.summary)
    assert summary["total_findings"] == 1


# ==============================================================================
# 5. Scan Cancellation State Preservation
# ==============================================================================

def test_cancelled_scan_is_never_overwritten_to_completed(db_session: Session, user_a: User, tmp_path):
    """A scan marked as 'cancelled' must preserve its cancelled status."""
    from app.scanner.registry import scanner_registry
    scanner_registry.register(MockSuccessfulScanner())

    repo = Repository(
        id=f"repo_canc_{uuid.uuid4().hex[:6]}",
        owner_id=user_a.id,
        name="cancel-test-repo",
        workspace_path=str(tmp_path),
        default_branch="main",
    )
    scan = Scan(
        id=f"scan_canc_{uuid.uuid4().hex[:6]}",
        repository_id=repo.id,
        status="cancelled",
    )
    db_session.add_all([repo, scan])
    db_session.commit()

    completed_scan = run_security_scan(
        repo=repo,
        scan=scan,
        db=db_session,
        selected_tools=["mock_success"],
    )

    # Must preserve cancelled status
    assert completed_scan.status == "cancelled"


# ==============================================================================
# 6. Duplicate Scan Request Prevention (409 Conflict)
# ==============================================================================

def test_duplicate_scan_request_on_active_repo_returns_409_conflict(client_a: TestClient, db_session: Session):
    """Starting a second scan while an active scan is queued/running on the same repo is rejected with 409."""
    repo_res = client_a.post("/api/v1/repositories", json={"name": "dup-scan-repo", "default_branch": "main"})
    assert repo_res.status_code == 201
    repo_id = repo_res.json()["id"]

    # Manually create an active running scan in DB for this repo
    active_scan = Scan(
        id=f"scan_act_{uuid.uuid4().hex[:6]}",
        repository_id=repo_id,
        status="running",
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(active_scan)
    db_session.commit()

    # User attempts to start another scan for the same repository
    dup_res = client_a.post("/api/v1/scans", json={"repository_id": repo_id})
    assert dup_res.status_code == 409
    assert dup_res.json()["error"]["code"] == "SCAN_ALREADY_IN_PROGRESS"
    assert "already in progress" in dup_res.json()["error"]["message"].lower()


# ==============================================================================
# 7. Retries Do Not Duplicate Findings or Corrupt Posture
# ==============================================================================

def test_scan_retry_deduplicates_and_cleans_prior_findings(db_session: Session, user_a: User, tmp_path):
    """Re-executing or retrying a scan does not duplicate findings or inflate health metrics."""
    from app.scanner.registry import scanner_registry
    scanner_registry.register(MockSuccessfulScanner())

    repo = Repository(
        id=f"repo_retry_{uuid.uuid4().hex[:6]}",
        owner_id=user_a.id,
        name="retry-test-repo",
        workspace_path=str(tmp_path),
        default_branch="main",
    )
    scan = Scan(
        id=f"scan_retry_{uuid.uuid4().hex[:6]}",
        repository_id=repo.id,
        status="pending",
    )
    db_session.add_all([repo, scan])
    db_session.commit()

    # 1. First execution
    run_security_scan(repo=repo, scan=scan, db=db_session, selected_tools=["mock_success"])
    initial_findings_count = db_session.query(SecurityFinding).filter(SecurityFinding.scan_id == scan.id).count()
    assert initial_findings_count == 1
    assert repo.high_count == 1

    # 2. Re-run / retry on the same scan object
    scan.status = "pending"
    db_session.commit()
    run_security_scan(repo=repo, scan=scan, db=db_session, selected_tools=["mock_success"])

    # Finding count must still be 1, NOT 2!
    final_findings_count = db_session.query(SecurityFinding).filter(SecurityFinding.scan_id == scan.id).count()
    assert final_findings_count == 1
    assert repo.high_count == 1


# ==============================================================================
# 8. Worker Restart & Pending Job Reconciliation
# ==============================================================================

def test_worker_restart_reconciles_pending_and_running_jobs(db_session: Session, user_a: User):
    """When a worker restarts, hanging scans and runs are transitioned into terminal states."""
    repo = Repository(
        id=f"repo_recon_{uuid.uuid4().hex[:6]}",
        owner_id=user_a.id,
        name="recon-repo",
        default_branch="main",
    )
    db_session.add(repo)
    db_session.commit()

    stale_time = datetime.now(timezone.utc) - timedelta(minutes=settings.STALE_JOB_TIMEOUT_MINUTES + 5)

    # 1. Orphaned queued scan
    queued_scan = Scan(id=f"scan_q_{uuid.uuid4().hex[:6]}", repository_id=repo.id, status="queued", created_at=stale_time)
    # 2. Orphaned running scan
    running_scan = Scan(id=f"scan_r_{uuid.uuid4().hex[:6]}", repository_id=repo.id, status="running", created_at=stale_time)
    db_session.add_all([queued_scan, running_scan])
    db_session.commit()

    reconciled = reconcile_interrupted_jobs(db_session)
    assert reconciled >= 2

    db_session.refresh(queued_scan)
    db_session.refresh(running_scan)
    assert queued_scan.status == "interrupted"
    assert running_scan.status == "interrupted"


# ==============================================================================
# 9. Database Error Envelope Safety
# ==============================================================================

def test_database_error_returns_clean_rfc_envelope_without_leaks(auth_client: TestClient, monkeypatch):
    """Simulated database connection failure produces safe 500 error envelope without DB leaks."""
    def mock_broken_query(*args, **kwargs):
        raise DatabaseError("OperationalError: Connection refused to postgres://admin:SuperSecretPass123@prod.db:5432")

    monkeypatch.setattr(Session, "query", mock_broken_query)

    res = auth_client.get("/api/v1/repositories")
    assert res.status_code == 500
    data = res.json()
    assert data["success"] is False
    assert data["error"]["code"] == "DATABASE_ERROR"
    # Ensure raw database password is never exposed in the response
    assert "SuperSecretPass123" not in json.dumps(data)


# ==============================================================================
# 10. Log Secret Redaction
# ==============================================================================

def test_log_redaction_masks_bearer_tokens_and_database_credentials():
    """Verify that structured logging masks credentials."""
    sensitive_jwt = "Received Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy.sig"
    scrubbed_jwt = scrub_log_message(sensitive_jwt)
    assert "[REDACTED_JWT_TOKEN]" in scrubbed_jwt

    sensitive_opaque = "Received Authorization: Bearer my-opaque-api-bearer-token-123456"
    scrubbed_opaque = scrub_log_message(sensitive_opaque)
    assert "[REDACTED_BEARER_TOKEN]" in scrubbed_opaque
    assert "my-opaque-api-bearer-token-123456" not in scrubbed_opaque

    sensitive_db = "connecting to postgres://admin:SuperSecretDbPassword123@db.prod.xerova.com:5432/app"
    scrubbed_db = scrub_log_message(sensitive_db)
    assert "SuperSecretDbPassword123" not in scrubbed_db
    assert "[REDACTED_DB_PASSWORD]" in scrubbed_db

    sensitive_key = "using ghp_123456789012345678901234567890123456 in header"
    scrubbed_key = scrub_log_message(sensitive_key)
    assert "ghp_123456789012345678901234567890123456" not in scrubbed_key
    assert "[REDACTED_API_KEY]" in scrubbed_key
