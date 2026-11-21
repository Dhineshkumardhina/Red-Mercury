# Red Mercury — Phase 0 Critical Security Regression Test Report

**Execution Timestamp:** 2026-10-28  
**Scope:** Phase 0 Critical Security Regression Suite Implementation and Validation  
**Target Architecture:** FastAPI, SQLAlchemy, SQLite/PostgreSQL, Docker/OCI Sandbox, JWT Authentication  
**Status:** **4 Critical Security Defects Conclusively Exposed; 1 Infrastructure Integration Test Skipped (No Live Daemon)**

---

## 1. Executive Summary

In accordance with findings established in `REDMERCURY_SEVEN_LAYER_AUDIT.md` and `REDMERCURY_TEST_GAP_AUDIT.md`, Phase 0 critical security regression tests were implemented across four core security modules:
1. **Network Boundary Security** (Git Ingestion DNS Rebinding / TOCTOU SSRF)
2. **Session Lifecycle & Revocation** (Server-Side JWT Invalidation on Logout)
3. **Execution Containment & Sandbox Limits** (Live Docker OOM, Fork-Bomb, Timeout, and Ephemeral Cleanup)
4. **Authorization & Privilege Boundaries** (Role-Based Access Control on Mutating Endpoints)
5. **Multi-Tenant Resource Confinement** (Cross-Tenant Workspace Directory Traversal in Local Folder Ingestion)

Following strict audit protocol:
- Application code was **not modified** to mask vulnerabilities.
- Existing security controls were **not weakened**.
- Tests were executed using safe, isolated, synthetic fixtures with zero host harm.
- Regression tests purposefully assert strict production security requirements, resulting in **4 explicit test failures exposing real platform vulnerabilities** and **1 graceful skip for container execution on hosts without an active Docker daemon**.

---

## 2. Inventory of Implemented Tests

| # | Test Name | Target File | Purpose | Execution Status |
|---|---|---|---|---|
| **1** | `test_git_clone_dns_rebinding_toctou_prevented` | [tests/test_ingestion.py](file:///c:/PROJECTS/dhina%20projects/Red Mercury%20AI/tests/test_ingestion.py) | Verifies that git clone cannot be hijacked via DNS rebinding (TOCTOU) between initial hostname resolution and actual git clone execution, preventing internal network / cloud metadata SSRF. | **FAILED** (Defect Exposed) |
| **2** | `test_jwt_bearer_token_revocation_on_logout` | [tests/test_auth.py](file:///c:/PROJECTS/dhina%20projects/Red Mercury%20AI/tests/test_auth.py) | Verifies that when a user logs out, their Bearer token is invalidated server-side and subsequent requests with the same token return HTTP 401 Unauthorized. | **FAILED** (Defect Exposed) |
| **3** | `test_live_docker_oom_and_fork_bomb_bounded` | [tests/test_sandbox.py](file:///c:/PROJECTS/dhina%20projects/Red Mercury%20AI/tests/test_sandbox.py) | Verifies memory limits (`--memory=48m`), process limits (`--pids-limit=16`), network isolation (`--network=none`), timeouts, and container cleanup under resource-exhaustion stress without host impact. | **SKIPPED** (Docker daemon unavailable) |
| **4** | `test_rbac_viewer_blocked_from_mutating_actions` | [tests/test_authorization.py](file:///c:/PROJECTS/dhina%20projects/Red Mercury%20AI/tests/test_authorization.py) | Verifies that read-only / viewer roles are strictly blocked from mutating repository state (e.g. `DELETE /api/v1/repositories/{id}`, `POST /api/v1/scans`) with HTTP 403 Forbidden. | **FAILED** (Defect Exposed) |
| **5** | `test_cross_tenant_workspace_directory_traversal_blocked` | [tests/test_authorization.py](file:///c:/PROJECTS/dhina%20projects/Red Mercury%20AI/tests/test_authorization.py) | Verifies that an authenticated tenant cannot ingest or traverse into another tenant's private workspace via relative paths (`../../`) or absolute workspace paths in `/repositories/ingest/local`. | **FAILED** (Defect Exposed) |

---

## 3. Files Created or Modified

| File | Status | Description |
|---|---|---|
| `tests/test_ingestion.py` | Modified | Appended `test_git_clone_dns_rebinding_toctou_prevented` to simulate DNS rebinding between `validate_git_url` and `clone_git_repository`. |
| `tests/test_auth.py` | Modified | Appended `test_jwt_bearer_token_revocation_on_logout` verifying token revocation on `/auth/logout`. |
| `tests/test_sandbox.py` | Modified | Appended `test_live_docker_oom_and_fork_bomb_bounded` bounded live container integration test. |
| `tests/test_authorization.py` | Modified | Appended `test_rbac_viewer_blocked_from_mutating_actions` and `test_cross_tenant_workspace_directory_traversal_blocked`. |
| `REDMERCURY_PHASE0_SECURITY_TEST_REPORT.md` | Created | Comprehensive Phase 0 report documenting execution outputs, defect proofs, required fixes, and remaining limitations. |

---

## 4. Actual Execution Results

### 4.1 Suite Execution Command
```bash
python -m pytest tests/test_ingestion.py tests/test_auth.py tests/test_sandbox.py tests/test_authorization.py -v
```

### 4.2 Pytest Summary Output
```
============================= test session starts =============================
platform win32 -- Python 3.14.7, pytest-9.1.1, pluggy-1.6.0 -- C:\Python314\python.exe
cachedir: .pytest_cache
rootdir: C:\PROJECTS\dhina projects\Red Mercury
plugins: anyio-4.15.1, platformdirs-4.13.0, asyncio-1.4.0
asyncio: mode=Mode.STRICT, debug=False
collected 48 items

tests/test_ingestion.py::test_normal_zip_archive_ingestion PASSED        [  2%]
tests/test_ingestion.py::test_path_traversal_zip_archive_rejected PASSED [  4%]
tests/test_ingestion.py::test_absolute_path_zip_archive_rejected PASSED  [  6%]
tests/test_ingestion.py::test_invalid_archive_not_a_zip PASSED           [  8%]
tests/test_ingestion.py::test_empty_archive_rejected PASSED              [ 10%]
tests/test_ingestion.py::test_oversized_archive_upload_rejected PASSED   [ 12%]
tests/test_ingestion.py::test_zip_bomb_expansion_ratio_rejected PASSED   [ 14%]
tests/test_ingestion.py::test_malicious_git_urls_ssrf_blocked PASSED     [ 16%]
tests/test_ingestion.py::test_cross_tenant_ingestion_status_blocked PASSED [ 18%]
tests/test_ingestion.py::test_git_branch_option_injection_rejected PASSED [ 20%]
tests/test_ingestion.py::test_unencrypted_http_git_rejected PASSED       [ 22%]
tests/test_ingestion.py::test_git_clone_dns_rebinding_toctou_prevented FAILED [ 25%]
tests/test_auth.py::test_user_registration_success PASSED                [ 27%]
tests/test_auth.py::test_user_registration_duplicate_email_fails PASSED  [ 29%]
tests/test_auth.py::test_user_registration_weak_password_fails PASSED    [ 31%]
tests/test_auth.py::test_user_login_success_bearer_and_cookie PASSED     [ 33%]
tests/test_auth.py::test_user_login_invalid_credentials_returns_401 PASSED [ 35%]
tests/test_auth.py::test_user_login_suspended_account_returns_403 PASSED [ 37%]
tests/test_auth.py::test_get_me_with_bearer_token PASSED                 [ 39%]
tests/test_auth.py::test_get_me_with_http_only_cookie PASSED             [ 41%]
tests/test_auth.py::test_expired_token_returns_401 PASSED                [ 43%]
tests/test_auth.py::test_logout_clears_cookie PASSED                     [ 45%]
tests/test_auth.py::test_jwt_bearer_token_revocation_on_logout FAILED    [ 47%]
tests/test_sandbox.py::test_hardened_container_command_arguments PASSED  [ 50%]
tests/test_sandbox.py::test_container_command_does_not_mount_docker_socket_or_host_secrets PASSED [ 52%]
tests/test_sandbox.py::test_fail_closed_when_docker_is_unavailable PASSED [ 54%]
tests/test_sandbox.py::test_runner_returns_error_outcome_on_fail_closed PASSED [ 56%]
tests/test_sandbox.py::test_production_strictly_forbids_host_fallback PASSED [ 58%]
tests/test_sandbox.py::test_development_allows_explicit_fallback PASSED  [ 60%]
tests/test_sandbox.py::test_sanitized_runner_env_strips_host_secrets PASSED [ 62%]
tests/test_sandbox.py::test_inspect_test_safety_detects_prohibited_system_calls PASSED [ 64%]
tests/test_sandbox.py::test_inspect_test_safety_allows_benign_tests PASSED [ 66%]
tests/test_sandbox.py::test_test_target_path_traversal_is_blocked PASSED [ 68%]
tests/test_sandbox.py::test_test_target_option_injection_is_blocked PASSED [ 70%]
tests/test_sandbox.py::test_terminate_process_tree_calls_docker_kill_and_rm PASSED [ 72%]
tests/test_sandbox.py::test_terminate_process_tree_terminates_host_process PASSED [ 75%]
tests/test_sandbox.py::test_check_docker_availability_handles_not_found PASSED [ 77%]
tests/test_sandbox.py::test_check_docker_availability_handles_timeout PASSED [ 79%]
tests/test_sandbox.py::test_real_docker_container_isolation SKIPPED      [ 81%]
tests/test_sandbox.py::test_timeout_handling_terminates_container_and_returns_timeout PASSED [ 83%]
tests/test_sandbox.py::test_disposable_workspace_cleanup PASSED          [ 85%]
tests/test_sandbox.py::test_live_docker_oom_and_fork_bomb_bounded SKIPPED [ 87%]
tests/test_authorization.py::test_cross_tenant_repository_isolation PASSED [ 89%]
tests/test_authorization.py::test_cross_tenant_finding_access_prevention PASSED [ 91%]
tests/test_authorization.py::test_cross_tenant_scan_isolation PASSED     [ 93%]
tests/test_authorization.py::test_cross_tenant_repository_deletion_and_isolation PASSED [ 95%]
tests/test_authorization.py::test_rbac_viewer_blocked_from_mutating_actions FAILED [ 97%]
tests/test_authorization.py::test_cross_tenant_workspace_directory_traversal_blocked FAILED [100%]

=========================== short test summary info ===========================
FAILED tests/test_ingestion.py::test_git_clone_dns_rebinding_toctou_prevented
FAILED tests/test_auth.py::test_jwt_bearer_token_revocation_on_logout
FAILED tests/test_authorization.py::test_rbac_viewer_blocked_from_mutating_actions
FAILED tests/test_authorization.py::test_cross_tenant_workspace_directory_traversal_blocked
============ 4 failed, 42 passed, 2 skipped, 11 warnings in 30.23s ============
```

---

## 5. Existing Security Defects Exposed

### Defect 1: Git Ingestion DNS Rebinding / TOCTOU SSRF Vulnerability
- **Test:** `test_git_clone_dns_rebinding_toctou_prevented` in `tests/test_ingestion.py`
- **Location:** `backend/app/core/ingestion.py:117-164` (`validate_git_url`) and `365-414` (`clone_git_repository`)
- **Root Cause:**
  `validate_git_url()` performs an upfront DNS resolution via `socket.getaddrinfo()` to verify that the IP is not private, loopback, or metadata (`169.254.169.254`). However, when `clone_git_repository()` subsequently executes `git clone --depth 1 ... <url>`, it passes the original unpinned hostname. Git performs an independent DNS lookup at connection time. An attacker configuring a DNS record with TTL=0 alternating between a public IP and `169.254.169.254` bypasses the initial check, allowing Git to connect directly to internal services or cloud metadata.
- **Test Assertion Failure:**
  ```
  AssertionError: SECURITY DEFECT EXPOSED: clone_git_repository executes git clone with an unpinned hostname.
  An attacker can bypass validate_git_url() via DNS rebinding / TOCTOU to target 169.254.169.254.
  ```

---

### Defect 2: Missing Server-Side JWT Token Revocation on Logout
- **Test:** `test_jwt_bearer_token_revocation_on_logout` in `tests/test_auth.py`
- **Location:** `backend/app/api/v1/endpoints/auth.py:191-220` (`logout`) and `backend/app/core/auth.py:101-128` (`get_current_user`)
- **Root Cause:**
  The `/api/v1/auth/logout` endpoint merely instructs the client browser to delete its HTTP-only cookie via `response.delete_cookie()`. The server retains **no state, blocklist, or revocation registry** (e.g., Redis or database token cache) tracking invalidated JWTs. An extracted Bearer token remains valid for authorization across all API endpoints until its nominal `exp` timestamp expires.
- **Test Assertion Failure:**
  ```
  AssertionError: SECURITY DEFECT EXPOSED: Server accepted Bearer token after logout (status=200).
  Server-side token revocation / deny-list is not implemented.
  ```

---

### Defect 3: Missing Role-Based Access Control (RBAC) on Mutating Endpoints
- **Test:** `test_rbac_viewer_blocked_from_mutating_actions` in `tests/test_authorization.py`
- **Location:** `backend/app/models/user.py` and `backend/app/api/v1/endpoints/repositories.py:270-320`
- **Root Cause:**
  The `User` model lacks a `role` field entirely, and endpoint dependencies only check `get_current_user`. The application checks resource ownership (`repo.owner_id == current_user.id`), but does **not enforce role tiers** (Admin vs. Maintainer vs. Viewer/Auditor). An account or token carrying read-only/auditor privileges is permitted to execute destructive and resource-intensive actions including `DELETE /api/v1/repositories/{id}` (returns HTTP 204) and `POST /api/v1/scans`.
- **Test Assertion Failure:**
  ```
  Failed: SECURITY DEFECT EXPOSED: Viewer role permitted to execute DELETE /api/v1/repositories/3dd76cd0-4f73-4d7e-81ab-91612632b6ed (status=204).
  Application lacks RBAC role enforcement on mutating endpoints.
  ```

---

### Defect 4: Cross-Tenant Workspace Directory Traversal in Local Folder Ingestion
- **Test:** `test_cross_tenant_workspace_directory_traversal_blocked` in `tests/test_authorization.py`
- **Location:** `backend/app/api/v1/endpoints/repositories.py:345-385` (`ingest_local_directory`)
- **Root Cause:**
  The endpoint takes `payload.local_path`, resolves it via `Path(payload.local_path).resolve()`, checks if it is a directory, and directly calls `shutil.copytree(local_dir, workspace_dir)`. There is **zero boundary validation or root containment check** to ensure `local_path` does not point to another tenant's private directory (`backend/data/workspaces/{other_user_id}/...`) or sensitive host filesystem locations. Authenticated Tenant B successfully ingested and copied Tenant A's private source code file `proprietary_financial_logic.py`.
- **Test Assertion Failure:**
  ```
  Failed: SECURITY DEFECT EXPOSED: Cross-tenant directory traversal succeeded!
  Bob ingested Alice's private workspace '...\backend\data\workspaces\ed000c11-131a-4b19-a9d5-435ea8db25bc\repo-alice-705d685b\source' via /repositories/ingest/local.
  Confidential file 'proprietary_financial_logic.py' was copied across tenant boundaries.
  ```

---

## 6. Tests Skipped and Reasons

| Test Name | File | Skip Reason |
|---|---|---|
| `test_real_docker_container_isolation` | `tests/test_sandbox.py` | Skipped dynamically via `@pytest.mark.skipif(not check_docker_availability()[0])`. The local Windows host environment does not have a live Docker Desktop daemon running. |
| `test_live_docker_oom_and_fork_bomb_bounded` | `tests/test_sandbox.py` | Skipped dynamically via `@pytest.mark.skipif(not check_docker_availability()[0])`. Requires a running Docker/OCI daemon to spin up ephemeral containers and test Linux cgroup limits (`--memory=48m`, `--pids-limit=16`). Note: The unit test `test_hardened_container_command_arguments` fully passed, confirming that command-line security bounding arguments are correctly constructed. |

---

## 7. Required Production Fixes

### 1. Fix for Git Ingestion DNS Rebinding (TOCTOU SSRF)
- **Design:** In `backend/app/core/ingestion.py`, prevent decoupled DNS resolution by either:
  1. Pinning the resolved validated IP into Git's transport configuration using `-c http.<url>.resolve=<host>:<port>:<validated_ip>`, or
  2. Routing Git clone requests through an internal egress proxy (e.g., Smokescreen / Squid) that enforces IP destination controls at TCP connection time and blocks private/link-local/metadata connections.
  3. Denying redirects (`-c http.followRedirects=false`).

### 2. Fix for JWT Token Invalidation on Logout
- **Design:** In `backend/app/core/auth.py` and `backend/app/api/v1/endpoints/auth.py`:
  1. Implement a server-side Token Deny-list (Redis with TTL equal to token expiration `settings.ACCESS_TOKEN_EXPIRE_MINUTES`, or a database `revoked_tokens` table).
  2. On `/auth/logout`, extract token `jti` (unique JWT ID) or the raw token signature, and persist it to the deny-list with remaining lifetime.
  3. In `get_current_user`, check the deny-list before granting authorization; reject revoked tokens with HTTP 401 Unauthorized.

### 3. Fix for Role-Based Access Control (RBAC) Mutating Endpoints
- **Design:** In `backend/app/models/user.py` and `backend/app/core/auth.py`:
  1. Add `role` column to `User` (`admin`, `maintainer`, `auditor`, `viewer`).
  2. Implement an RBAC dependency `require_role(["admin", "maintainer"])` for mutating endpoints (`DELETE /repositories/{id}`, `POST /scans`, `POST /verification/verify`).
  3. Ensure `viewer` and `auditor` roles are restricted strictly to read actions (`GET`).

### 4. Fix for Cross-Tenant Workspace Directory Traversal
- **Design:** In `backend/app/api/v1/endpoints/repositories.py`:
  1. Strictly bound `local_path` ingestion to a dedicated, operator-configured base ingest directory (e.g. `settings.LOCAL_INGEST_BASE_DIR`).
  2. Enforce `local_dir.resolve().is_relative_to(settings.LOCAL_INGEST_BASE_DIR)`.
  3. Specifically forbid paths containing `settings.WORKSPACE_BASE_DIR` or another user's ID, returning HTTP 403 Forbidden on boundary violations.

---

## 8. Remaining Limitations and Next Actions

1. **Host-Level Container Engine Verification:** Run `tests/test_sandbox.py` in a Linux CI or container-enabled runner to validate live cgroup OOM and PID exhaustion bounding.
2. **Phase 1 Remediation Planning:** With regression tests established and safely failing closed, proceed with isolated, backwards-compatible security patches for the 4 exposed defects in a dedicated remediation phase.

