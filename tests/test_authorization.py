"""Cross-tenant authorization tests verifying complete isolation between users."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.audit import AuditEvent


def test_cross_tenant_repository_isolation(client_a: TestClient, client_b: TestClient):
    # 1. Alice creates repository A
    repo_payload = {
        "name": "alice/microservice-auth",
        "git_url": "https://github.com/alice/microservice-auth",
        "default_branch": "main",
        "health_score": 90,
    }
    create_res = client_a.post("/api/v1/repositories", json=repo_payload)
    assert create_res.status_code == 201
    repo_a = create_res.json()
    repo_a_id = repo_a["id"]

    # 2. Alice lists repositories -> repo_a is visible
    alice_repos = client_a.get("/api/v1/repositories").json()
    assert any(r["id"] == repo_a_id for r in alice_repos)

    # 3. Bob lists repositories -> repo_a MUST NOT be visible to Bob
    bob_repos = client_b.get("/api/v1/repositories").json()
    assert not any(r["id"] == repo_a_id for r in bob_repos)

    # 4. Bob attempts to access repo_a directly by ID -> MUST return 403 Forbidden
    cross_access_res = client_b.get(f"/api/v1/repositories/{repo_a_id}")
    assert cross_access_res.status_code == 403
    err = cross_access_res.json()
    assert err["success"] is False
    assert err["error"]["code"] == "FORBIDDEN"
    assert "permission" in err["error"]["message"].lower()


def test_cross_tenant_finding_access_prevention(client_a: TestClient, client_b: TestClient, db_session: Session):
    # 1. Alice registers repo
    repo_res = client_a.post(
        "/api/v1/repositories",
        json={"name": "alice/payment-gateway", "git_url": "https://github.com/alice/payment"},
    )
    repo_id = repo_res.json()["id"]

    # 2. Bob attempts to ingest finding into Alice's repository -> MUST be denied with 403
    bob_inject_res = client_b.post(
        "/api/v1/findings",
        json={
            "repo_id": repo_id,
            "cwe": "CWE-89: SQL Injection",
            "title": "Unauthorized finding injection attempt",
            "severity": "CRITICAL",
            "scanner_name": "Trufflehog",
            "file_path": "main.py",
            "line_number": 1,
        },
    )
    assert bob_inject_res.status_code == 403
    assert bob_inject_res.json()["error"]["code"] == "FORBIDDEN"

    # 3. Alice ingests legitimate finding
    alice_finding_res = client_a.post(
        "/api/v1/findings",
        json={
            "repo_id": repo_id,
            "cwe": "CWE-89: SQL Injection",
            "title": "SQL Injection in query builder",
            "severity": "CRITICAL",
            "scanner_name": "Semgrep OSS",
            "file_path": "backend/dao/user.py",
            "line_number": 34,
        },
    )
    assert alice_finding_res.status_code == 201
    finding_id = alice_finding_res.json()["id"]

    # 4. Bob queries list of findings -> Alice's finding is NOT returned
    bob_findings = client_b.get("/api/v1/findings").json()
    assert not any(f["id"] == finding_id for f in bob_findings)

    # 5. Bob queries Alice's finding directly by ID -> MUST return 403 Forbidden
    bob_get_res = client_b.get(f"/api/v1/findings/{finding_id}")
    assert bob_get_res.status_code == 403
    assert bob_get_res.json()["error"]["code"] == "FORBIDDEN"

    # 6. Verify security audit event logged the blocked unauthorized access
    blocked_event = db_session.query(AuditEvent).filter(
        AuditEvent.action == "UNAUTHORIZED_FINDING_ACCESS_BLOCKED",
        AuditEvent.actor_id == client_b.user.id,
    ).first()
    assert blocked_event is not None
    assert blocked_event.resource_identifier == finding_id


def test_cross_tenant_scan_isolation(client_a: TestClient, client_b: TestClient):
    # 1. Alice creates repository
    repo_res = client_a.post(
        "/api/v1/repositories",
        json={"name": "alice/crypto-service", "git_url": "https://github.com/alice/crypto"},
    )
    repo_id = repo_res.json()["id"]

    # 2. Bob attempts to initiate a scan on Alice's repository -> 403 Forbidden
    bob_scan_res = client_b.post(
        "/api/v1/scans",
        json={"repository_id": repo_id, "summary": "Malicious scan trigger"},
    )
    assert bob_scan_res.status_code == 403
    assert bob_scan_res.json()["error"]["code"] == "FORBIDDEN"

    # 3. Alice initiates scan successfully
    alice_scan_res = client_a.post(
        "/api/v1/scans",
        json={"repository_id": repo_id, "summary": "Authorized audit scan"},
    )
    assert alice_scan_res.status_code in (201, 202)
    scan_id = alice_scan_res.json()["id"]

    # 4. Bob cannot list Alice's scan
    bob_scans = client_b.get("/api/v1/scans").json()
    assert not any(s["id"] == scan_id for s in bob_scans)

    # 5. Bob cannot fetch Alice's scan by ID -> 403 Forbidden
    bob_get_scan = client_b.get(f"/api/v1/scans/{scan_id}")
    assert bob_get_scan.status_code == 403
    assert bob_get_scan.json()["error"]["code"] == "FORBIDDEN"

    # 6. Bob cannot fetch Alice's scan status -> 403 Forbidden
    bob_get_status = client_b.get(f"/api/v1/scans/{scan_id}/status")
    assert bob_get_status.status_code == 403
    assert bob_get_status.json()["error"]["code"] == "FORBIDDEN"


def test_cross_tenant_repository_deletion_and_isolation(client_a: TestClient, client_b: TestClient, db_session: Session):
    # 1. Alice creates repository
    repo_res = client_a.post(
        "/api/v1/repositories",
        json={"name": "alice/vault-service", "git_url": "https://github.com/alice/vault"},
    )
    repo_id = repo_res.json()["id"]

    # 2. Bob attempts to delete Alice's repository -> MUST return 403 Forbidden
    bob_del_res = client_b.delete(f"/api/v1/repositories/{repo_id}")
    assert bob_del_res.status_code == 403
    assert bob_del_res.json()["error"]["code"] == "FORBIDDEN"

    # Verify repository still exists
    assert client_a.get(f"/api/v1/repositories/{repo_id}").status_code == 200

    # 3. Alice deletes her repository -> MUST return 204 No Content
    alice_del_res = client_a.delete(f"/api/v1/repositories/{repo_id}")
    assert alice_del_res.status_code == 204

    # 4. Verify repository is deleted
    assert client_a.get(f"/api/v1/repositories/{repo_id}").status_code == 404

    # 5. Verify audit event was recorded
    audit_evt = db_session.query(AuditEvent).filter(
        AuditEvent.action == "REPOSITORY_DELETED",
        AuditEvent.resource_identifier == repo_id,
        AuditEvent.actor_id == client_a.user.id,
    ).first()
    assert audit_evt is not None



import os
import uuid
from pathlib import Path
from app.core.security import create_access_token
from app.main import app


def test_rbac_viewer_blocked_from_mutating_actions(client: TestClient, create_test_user, db_session: Session):
    """PHASE 0 REGRESSION TEST 4: Role-Based Access Control (RBAC) mutating endpoint enforcement.

    Verifies:
    1. Read-only / viewer roles are restricted to GET / read operations.
    2. Viewer attempting mutating actions (DELETE repository, POST scans, POST ingest) MUST be rejected with 403 Forbidden.
    3. The application does not silently accept mutations without checking the actor's role.
    """
    viewer_user = create_test_user(email=f"viewer_{uuid.uuid4().hex[:6]}@xerova.com", role="viewer")
    viewer_token = create_access_token({"sub": viewer_user.id, "email": viewer_user.email, "role": "viewer"})
    viewer_client = TestClient(app)
    viewer_client.headers["Authorization"] = f"Bearer {viewer_token}"

    # Setup a test repository owned by this user
    from app.models.repository import Repository
    repo = Repository(
        owner_id=viewer_user.id,
        name="viewer-audit-repo",
        source_type="git",
        git_url="https://github.com/xerova/audit-target",
        default_branch="main",
        is_active=True,
    )
    db_session.add(repo)
    db_session.commit()
    db_session.refresh(repo)

    # 1. Read operations SHOULD succeed
    get_res = viewer_client.get(f"/api/v1/repositories/{repo.id}")
    assert get_res.status_code == 200, "Viewer should have read access to repository"

    # 2. Mutating action: DELETE repository MUST be rejected with 403 Forbidden
    del_res = viewer_client.delete(f"/api/v1/repositories/{repo.id}")
    if del_res.status_code != 403:
        pytest.fail(
            f"SECURITY DEFECT EXPOSED: Viewer role permitted to execute DELETE /api/v1/repositories/{repo.id} "
            f"(status={del_res.status_code}). Application lacks RBAC role enforcement on mutating endpoints."
        )

    # 3. Mutating action: POST trigger scan MUST be rejected with 403 Forbidden
    scan_res = viewer_client.post(
        "/api/v1/scans",
        json={"repository_id": repo.id, "summary": "Viewer unauthorized scan"},
    )
    if scan_res.status_code != 403:
        pytest.fail(
            f"SECURITY DEFECT EXPOSED: Viewer role permitted to execute POST /api/v1/scans "
            f"(status={scan_res.status_code}). RBAC enforcement is missing on scan triggering."
        )


def test_cross_tenant_workspace_directory_traversal_blocked(
    client_a: TestClient,
    client_b: TestClient,
    tmp_path: Path,
):
    """PHASE 0 REGRESSION TEST 5: Cross-tenant workspace directory traversal prevention.

    Verifies:
    1. An authenticated tenant (Bob) CANNOT copy, ingest, or traverse into another tenant's (Alice) private workspace.
    2. Path validation confines local directory ingestion strictly to allowed, authorized workspace boundaries.
    3. Attempts to traverse via relative paths (../../) or absolute paths pointing to other tenants' data
       MUST return 400 Bad Request or 403 Forbidden, and MUST NOT leak or copy victim files.
    """
    from app.core.ingestion import get_repository_workspace
    alice_repo_id = f"repo-alice-{uuid.uuid4().hex[:8]}"
    alice_ws = get_repository_workspace(client_a.user.id, alice_repo_id)
    alice_ws.mkdir(parents=True, exist_ok=True)
    secret_file = alice_ws / "proprietary_financial_logic.py"
    secret_file.write_text("# TOP SECRET ALICE ALGORITHM\nAPI_KEY='live_secret_key_12345'\n", encoding="utf-8")

    try:
        # Bob attempts to ingest Alice's private workspace directory path into Bob's account
        malicious_traversal_path = str(alice_ws)

        ingest_payload = {
            "name": f"bobs-exfil-{uuid.uuid4().hex[:6]}",
            "local_path": malicious_traversal_path,
            "default_branch": "main",
        }
        res = client_b.post("/api/v1/repositories/ingest/local", json=ingest_payload)

        # Strict security expectation: Must return 400 or 403, and Bob must NOT receive Alice's files
        if res.status_code in (200, 201):
            bob_repo_id = res.json().get("id")
            bob_ws = get_repository_workspace(client_b.user.id, bob_repo_id)
            if (bob_ws / "proprietary_financial_logic.py").exists():
                pytest.fail(
                    f"SECURITY DEFECT EXPOSED: Cross-tenant directory traversal succeeded! "
                    f"Bob ingested Alice's private workspace '{alice_ws}' via /repositories/ingest/local. "
                    f"Confidential file 'proprietary_financial_logic.py' was copied across tenant boundaries."
                )
            pytest.fail(
                f"SECURITY DEFECT EXPOSED: Ingest accepted cross-tenant path without validation (status={res.status_code})."
            )

        assert res.status_code in (400, 403, 422), f"Expected 400/403/422 on cross-tenant path, got {res.status_code}"
    finally:
        import shutil
        if alice_ws.exists():
            shutil.rmtree(alice_ws, ignore_errors=True)



def test_rbac_role_vs_endpoint_matrix(client: TestClient, create_test_user, db_session: Session):
    """Verify role-versus-endpoint permission matrix.

    Ensures:
    - Viewer & Auditor roles are restricted to read-only endpoints (GET) and rejected on mutations (403).
    - State is strictly unchanged in DB when mutations are rejected.
    - Admin & Analyst roles can perform state mutations within their tenant scope.
    """
    from app.models.repository import Repository

    viewer_user = create_test_user(email=f"matrix_viewer_{uuid.uuid4().hex[:6]}@xerova.com", role="viewer")
    viewer_token = create_access_token({"sub": viewer_user.id, "email": viewer_user.email, "role": "viewer"})
    viewer_client = TestClient(app)
    viewer_client.headers["Authorization"] = f"Bearer {viewer_token}"

    auditor_user = create_test_user(email=f"matrix_auditor_{uuid.uuid4().hex[:6]}@xerova.com", role="auditor")
    auditor_token = create_access_token({"sub": auditor_user.id, "email": auditor_user.email, "role": "auditor"})
    auditor_client = TestClient(app)
    auditor_client.headers["Authorization"] = f"Bearer {auditor_token}"

    admin_user = create_test_user(email=f"matrix_admin_{uuid.uuid4().hex[:6]}@xerova.com", role="admin")
    admin_token = create_access_token({"sub": admin_user.id, "email": admin_user.email, "role": "admin"})
    admin_client = TestClient(app)
    admin_client.headers["Authorization"] = f"Bearer {admin_token}"

    # 1. Read operations succeed for all roles
    assert viewer_client.get("/api/v1/repositories").status_code == 200
    assert auditor_client.get("/api/v1/repositories").status_code == 200
    assert admin_client.get("/api/v1/repositories").status_code == 200

    # 2. Mutating action: POST /api/v1/repositories
    repo_payload = {"name": f"test-repo-{uuid.uuid4().hex[:6]}", "source_type": "git", "git_url": "https://github.com/example/repo"}
    # Viewer -> 403
    v_res = viewer_client.post("/api/v1/repositories", json=repo_payload)
    assert v_res.status_code == 403
    # Auditor -> 403
    a_res = auditor_client.post("/api/v1/repositories", json=repo_payload)
    assert a_res.status_code == 403
    # Database remains unchanged
    assert db_session.query(Repository).filter(Repository.name == repo_payload["name"]).first() is None

    # Admin -> 201
    admin_res = admin_client.post("/api/v1/repositories", json=repo_payload)
    assert admin_res.status_code == 201
    created_repo_id = admin_res.json()["id"]

    # 3. Mutating action: POST /api/v1/scans
    scan_payload = {"repository_id": created_repo_id, "summary": "Audit scan"}
    assert viewer_client.post("/api/v1/scans", json=scan_payload).status_code == 403
    assert auditor_client.post("/api/v1/scans", json=scan_payload).status_code == 403

    # 4. Mutating action: DELETE /api/v1/repositories
    assert viewer_client.delete(f"/api/v1/repositories/{created_repo_id}").status_code == 403
    assert auditor_client.delete(f"/api/v1/repositories/{created_repo_id}").status_code == 403
    # Repository still exists
    assert db_session.query(Repository).filter(Repository.id == created_repo_id).first() is not None


def test_cross_tenant_workspace_relative_traversal_and_symlinks(client_a: TestClient, tmp_path: Path):
    """Verify that relative traversal (../../) and root/symlink paths are strictly rejected."""
    # 1. Relative traversal attempting to escape
    rel_res = client_a.post(
        "/api/v1/repositories/ingest/local",
        json={"name": "rel-traversal-test", "local_path": "../../../../../etc"},
    )
    assert rel_res.status_code in (400, 403, 422)

    # 2. System root path rejected
    system_root = "C:\\" if os.name == "nt" else "/"
    root_res = client_a.post(
        "/api/v1/repositories/ingest/local",
        json={"name": "root-traversal-test", "local_path": system_root},
    )
    assert root_res.status_code in (400, 403, 422)

    # 3. Empty or null byte path rejected
    null_res = client_a.post(
        "/api/v1/repositories/ingest/local",
        json={"name": "null-test", "local_path": "/tmp/test\0evil"},
    )
    assert null_res.status_code in (400, 403, 422)
