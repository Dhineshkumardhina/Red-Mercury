# RED MERCURY — PHASE 1: CRITICAL SECURITY REMEDIATION REPORT

**Date:** 2026-11-21  
**Repository:** `https://github.com/Dhineshkumardhina/Red-Mercury`  
**Branch / Baseline:** `main` @ `b9df7b9`  
**Reference Audit:** [RED_MERCURY_PHASE0_COMPLETE_REPOSITORY_AUDIT.md](RED_MERCURY_PHASE0_COMPLETE_REPOSITORY_AUDIT.md)  
**Phase 1 Status:** **COMPLETE** (All 5 critical security/deployment blockers and directly related frontend authentication flaws remediated and verified with regression tests)

---

## 1. Executive Summary

Phase 1 executed targeted, surgical security remediations for all five **CRITICAL** blockers (`SEC-01`, `SEC-02`, `SEC-03`, `SEC-04`, `INFRA-01`) and directly related **HIGH** frontend/Electron security flaws (`SEC-08`, `SEC-09`, `SEC-10`) identified in the Phase 0 audit — without rebuilding the application, breaking existing architecture, or introducing new dependencies.

### Verification Summary
- **Backend (`pytest`):** **461 collected, 441 passed, 0 failed, 20 environment-skipped** (+19 new Phase 1 security regression tests).
- **Frontend (`vitest`):** **7 test files, 46 passed, 0 failed** (+5 new Phase 1 auth security regression tests).
- **Frontend TypeScript (`tsc --noEmit`):** **Passed (0 errors)**.
- **Electron (`node --test electron/security.test.cjs`):** **10 passed, 0 failed** (new Electron security regression suite).
- **Docker Compose Validation:** `docker compose -f docker-compose.prod.yml config -q` exited **0**. Live container startup could not be executed because the local Docker daemon is stopped (explicitly disclosed below).

---

## 2. Critical Vulnerability Remediation Matrix

| Finding ID | Severity | Vulnerability | Status | Verification Evidence |
| :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | **CRITICAL** | Unrestricted local filesystem ingestion in production, dead symlink check, symlink dereferencing, missing size/file quotas, prefix-collision confinement | **REMEDIATED & VERIFIED** | 9 new backend tests in `tests/test_phase1_security_remediation.py` (all passed) |
| **SEC-02** | **CRITICAL** | Admin privilege escalation via public `/auth/register`, missing strict role enum, JWT role claim overwriting authoritative ORM `user.role` | **REMEDIATED & VERIFIED** | 6 new backend tests in `tests/test_phase1_security_remediation.py` + updated DB-authoritative RBAC tests in `test_authorization.py` & `test_api_reliability_and_resilience.py` (all passed) |
| **SEC-03** | **CRITICAL** | Hardcoded credentials in frontend bundle, unconditional auto-login, `defaultTester` auth bypass fallback, startup dev seeding in `backend/app/main.py` | **REMEDIATED & VERIFIED** | 1 backend test (`test_sec03_main_module_has_no_startup_dev_seeding`) + 3 frontend tests in `frontend/src/__tests__/AuthSecurity.test.tsx` (all passed) |
| **SEC-08** | **HIGH** | Silent automatic user registration on any failed login with 8+ char password | **REMEDIATED & VERIFIED** | `AuthSecurity.test.tsx` (`does not silently call /api/v1/auth/register when login fails...`) (passed) |
| **SEC-09** | **HIGH** | `FindingsPage` refresh wiped active JWT (`setAuthToken(null)`) and triggered auto-relogin; logout session cleanup | **REMEDIATED & VERIFIED** | `AuthSecurity.test.tsx` (`FindingsPage refresh preserves active auth token...` + `logout invalidates active session...`) (passed) |
| **SEC-04** | **CRITICAL** | Arbitrary file read (path traversal) and uncaught `URIError` DoS crash in Electron static UI server | **REMEDIATED & VERIFIED** | 4 tests in `electron/security.test.cjs` (direct traversal, encoded/double-encoded traversal, malformed percent-encoding, legitimate SPA routes) (all passed) |
| **SEC-10** | **HIGH** | Electron renderer `sandbox: false`, missing `will-navigate` origin guard, unvalidated IPC sender & `shell.openExternal` URLs, Windows `shell: true` Python spawn, async `taskkill` | **REMEDIATED & VERIFIED** | 6 tests in `electron/security.test.cjs` (origin allowlist, external URL validation, port/arg injection, POSIX/Windows venv detection, synchronous termination, static `main.cjs` hardening assertions) (all passed) |
| **INFRA-01** | **CRITICAL** | `worker` service in `docker-compose.prod.yml` crash-loops under `APP_ENV=production` due to missing `SECRET_KEY` and `CORS_ORIGINS` | **REMEDIATED & VERIFIED** | `docker compose config -q` (exit 0) + 3 backend production config/process tests in `tests/test_phase1_security_remediation.py` (all passed; live Docker daemon unavailable) |

---

## 3. Detailed Security Verification Evidence & Before/After Behavior

### 3.1 `SEC-01` — Local Filesystem Ingestion Hardening
- **Original Vulnerability:** `POST /api/v1/repositories/ingest/local` was enabled in production, checked `target_dir.is_symlink()` *after* `Path.resolve()` (dead code), dereferenced internal symlinks via `shutil.copytree(..., symlinks=False)`, used prefix-collision-prone `str.startswith()` for workspace confinement, and enforced no file-count or byte-size limits.
- **Root Cause:** Missing production feature gate, missing explicit allowlist, symlink check placed after canonicalization, and use of `shutil.copytree` without bounded walking.
- **Modified Files:**
  - `backend/app/core/config.py`
  - `backend/app/core/ingestion.py`
  - `backend/app/api/v1/endpoints/repositories.py`
  - `.env.example`
- **Before / After Behavior:**
  - *Before:* Any authenticated user in production could ingest arbitrary host directories (including symlinks) with unbounded disk usage.
  - *After:* Local ingestion is **disabled in production by default** (`ALLOW_LOCAL_INGESTION_IN_PRODUCTION=False`, HTTP 403). Opting in requires a non-empty `LOCAL_INGESTION_ALLOWED_ROOTS` allowlist (enforced fail-closed in `Settings.validate_production_configuration()`). Symlinks are rejected **before** `Path.resolve()` across the path and its ancestors; `copy_local_directory_safely()` walks with `followlinks=False`, rejects any internal symlinked file/directory, enforces `MAX_FILE_COUNT`, `MAX_SINGLE_FILE_BYTES`, and cumulative `MAX_EXTRACTED_SIZE_BYTES` via 64 KiB chunked reads, and uses `Path.is_relative_to()` for workspace confinement. ZIP and Git ingestion remain intact.
- **Regression Tests Added (`tests/test_phase1_security_remediation.py`):**
  - `test_sec01_local_ingestion_blocked_in_production_by_default` — **PASSED**
  - `test_sec01_production_allow_local_ingestion_requires_non_empty_allowlist` — **PASSED**
  - `test_sec01_local_ingestion_enforces_explicit_allowlist` — **PASSED**
  - `test_sec01_local_ingestion_rejects_directory_traversal` — **PASSED**
  - `test_sec01_local_ingestion_rejects_symlink_before_resolve` — **PASSED**
  - `test_sec01_copy_local_directory_rejects_internal_symlink_without_dereferencing` — **PASSED**
  - `test_sec01_local_ingestion_enforces_max_file_count` — **PASSED**
  - `test_sec01_local_ingestion_enforces_cumulative_size_limit` — **PASSED**
  - `test_sec01_workspace_confinement_prevents_prefix_collision` — **PASSED**
- **Remaining Limitations:** On non-privileged Windows hosts, OS symlink creation requires administrator rights; symlink unit tests therefore exercise the exact `Path.is_symlink()` branches via deterministic monkeypatching.

---

### 3.2 `SEC-02` — Admin Privilege Escalation & Authoritative Database Roles
- **Original Vulnerability:** `UserRegister` exposed `role` defaulting to `"admin"`, allowing unauthenticated self-registration as an administrator or arbitrary role. `get_current_user()` mutated the SQLAlchemy-attached `user.role` directly from JWT `role` claims, ignoring DB role downgrades and allowing JWT role tampering.
- **Root Cause:** Public registration accepted privileged attributes, ORM/schema defaulted to `"admin"`, and authentication trusted client-held JWT role claims over the database.
- **Modified Files:**
  - `backend/app/schemas/auth.py`
  - `backend/app/models/user.py`
  - `backend/app/core/auth.py`
  - `backend/app/api/v1/endpoints/auth.py`
  - `tests/conftest.py`, `tests/test_authorization.py`, `tests/test_api_reliability_and_resilience.py` (aligned legacy RBAC test fixtures to set authoritative DB roles)
- **Before / After Behavior:**
  - *Before:* Public registration created `admin` users; JWT `role` claim overwrote `user.role` on the ORM instance.
  - *After:* Strict `UserRole` enum (`admin`, `maintainer`, `analyst`, `viewer`, `auditor`) enforced across schemas and auth dependencies. `UserRegister` removes `role` and explicitly rejects `role`, `roles`, `is_admin`, `is_superuser` with HTTP 422 while preserving backward compatibility for benign extra fields (e.g., `full_name`). Newly registered accounts always receive `role="analyst"` (least-privileged practitioner role). `get_current_user()` treats the database `user.role` as strictly authoritative, never overwrites it from JWT claims, and fails closed (`403`) on invalid DB roles. `require_role()` / `require_mutating_role()` default missing roles to `"viewer"`, never `"admin"`.
- **Regression Tests Added (`tests/test_phase1_security_remediation.py`):**
  - `test_sec02_public_registration_defaults_to_least_privileged_analyst` — **PASSED**
  - `test_sec02_public_registration_rejects_admin_role_injection` — **PASSED**
  - `test_sec02_public_registration_rejects_invalid_role_injection` — **PASSED**
  - `test_sec02_jwt_role_claim_cannot_escalate_viewer_to_admin` — **PASSED**
  - `test_sec02_database_role_downgrade_takes_effect_immediately` — **PASSED**
  - `test_sec02_invalid_database_role_rejected_fail_closed` — **PASSED**
- **Remaining Limitations:** Dedicated admin-only user-management endpoints (for promoting/demoting roles via API) are not yet implemented; role promotion currently occurs via database administration or future Phase 2 admin endpoints.

---

### 3.3 `SEC-03` / `SEC-08` / `SEC-09` — Frontend Authentication & Startup Seeding
- **Original Vulnerability:**
  - `SEC-03`: Frontend bundled hardcoded credentials, unconditionally attempted auto-login on mount, fell back to an authenticated `defaultTester` mock user on failure, pre-filled `LoginPage` inputs, and exposed a 1-click tester bypass. `backend/app/main.py` auto-seeded a hardcoded personal admin account on startup.
  - `SEC-08`: `AuthContext.login()` silently called `registerUser()` on any failed login when `password.length >= 8`.
  - `SEC-09`: `FindingsPage.loadData(true)` called `api.setAuthToken(null)` and `api.ensureAuthenticated(true)`, wiping active sessions on refresh.
- **Root Cause:** Developer convenience shortcuts left active in production frontend bundles and backend lifespan startup.
- **Modified Files:**
  - `frontend/src/context/AuthContext.tsx`
  - `frontend/src/services/api.ts`
  - `frontend/src/pages/LoginPage.tsx`
  - `frontend/src/pages/FindingsPage.tsx`
  - `frontend/src/pages/SettingsPage.tsx`
  - `backend/app/main.py`
- **Before / After Behavior:**
  - *Before:* Unauthenticated visitors were silently logged in or granted a mock `defaultTester` session; failed logins silently created accounts; refreshing Findings wiped the user's JWT.
  - *After:* All hardcoded credentials, `defaultTester`, `loginAsTester`, 1-click tester launch, and `seed_initial_dev_data()` in `main.py` are removed. `AuthContext` only restores sessions from an existing token verified via `GET /api/v1/auth/me` and leaves unauthenticated users redirected to `/login`. Failed logins return errors without calling `/auth/register`. `FindingsPage` refresh clears only the response micro-cache and retains the active JWT. Logout calls `POST /api/v1/auth/logout`, clears caches and token, and resets auth state.
- **Regression Tests Added:**
  - `tests/test_phase1_security_remediation.py::test_sec03_main_module_has_no_startup_dev_seeding` — **PASSED**
  - `frontend/src/__tests__/AuthSecurity.test.tsx` (5 tests: unauthenticated `/dashboard` block, empty `/login` form without 1-click bypass, no silent `/auth/register` on failed login, `FindingsPage` refresh preserves token, `logout` revokes & clears session) — **5/5 PASSED**
- **Remaining Limitations & Architectural Note (JWT `localStorage` vs `HttpOnly` Cookies):**
  - Per Phase 1 scope rules, the frontend continues to support the existing Bearer JWT flow (`localStorage`) alongside the backend's `HttpOnly` cookie cookie-setting on `/login` and `/register`. Migrating exclusively to `HttpOnly; Secure; SameSite=Lax` cookies requires updating cross-origin CORS credentials/cookie domain alignment between Cloudflare Workers and Railway plus CSRF verification on `/auth/logout`; this is scheduled as a dedicated Phase 2 architectural workstream.

---

### 3.4 `SEC-04` / `SEC-10` — Electron Desktop Security Hardening
- **Original Vulnerability:**
  - `SEC-04`: `startStaticUiServer` joined `distPath` with unguarded `decodeURI(reqPath)` without path containment, enabling arbitrary local file read (`/../...`) and uncaught `URIError` crashes.
  - `SEC-10`: `sandbox: false` disabled Chromium renderer sandboxing; no `will-navigate` origin guard; IPC handlers did not verify `event.senderFrame.url`; `shell:openExternal` lacked `new URL()` parsing; Python backend spawned with `shell: true` on Windows and terminated via async `exec('taskkill ...')`.
- **Root Cause:** Missing path-confinement and origin-validation primitives in `electron/main.cjs`.
- **Modified / Added Files:**
  - `electron/security.cjs` (new isolated security helper module)
  - `electron/main.cjs`
  - `electron/security.test.cjs` (new regression test suite)
- **Before / After Behavior:**
  - *Before:* Any path traversal read arbitrary files outside `frontend/dist`; malformed `%` crashed Electron; renderer ran unsandboxed; IPC and navigation lacked origin checks; Windows backend used `shell: true`.
  - *After:* `resolveStaticAssetPath()` safely decodes URIs (`400` on malformed encoding), rejects null bytes, backslashes, `..`, encoded/double-encoded traversal, and escaping symlinks (`403`), and enforces `resolvedPath.startsWith(resolvedDist + path.sep)` before serving assets with `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and CSP headers. Both `mainWindow` and `splashWindow` enforce `sandbox: true`, `contextIsolation: true`, `nodeIntegration: false`, and `webSecurity: true`. `will-navigate` and all 4 IPC handlers enforce trusted local origin checks; `shell:openExternal` and `setWindowOpenHandler` enforce strict `http:`/`https:` `URL` parsing. Backend spawns with `shell: false`, validated integer port (`1..65535`) and host, Windows + POSIX venv detection, and synchronous `execFileSync('taskkill', ...)` termination on Windows.
- **Regression Tests Added (`electron/security.test.cjs`):**
  - 10/10 tests executed via `node --test electron/security.test.cjs` — **10/10 PASSED** (146ms).
- **Remaining Limitations:** Tests verify all security primitives and static `main.cjs` posture without launching a full GUI Electron window (headless GUI automation via Playwright/Spectron is not installed).

---

### 3.5 `INFRA-01` — Docker Production Worker Configuration
- **Original Vulnerability:** `docker-compose.prod.yml` launched `worker` with `APP_ENV: production` without passing `SECRET_KEY` or `CORS_ORIGINS`, causing `Settings.validate_production_configuration()` to raise `ValueError` immediately on import and crash-loop the container.
- **Root Cause:** Incomplete environment variable propagation between `api` and `worker` services in `docker-compose.prod.yml`.
- **Modified Files:**
  - `docker-compose.prod.yml`
- **Before / After Behavior:**
  - *Before:* `redmercury_worker` failed production validation immediately on startup.
  - *After:* `worker` receives `SECRET_KEY: ${SECRET_KEY:?SECRET_KEY must be set in production}`, `CORS_ORIGINS: ${CORS_ORIGINS:-https://redmercury.xerova.com}`, `LOG_LEVEL`, `LOG_FORMAT_JSON: "true"`, `ALLOW_LOCAL_INGESTION_IN_PRODUCTION: "false"`, `SANDBOX_FAIL_CLOSED: "true"`, and `SANDBOX_ALLOW_HOST_FALLBACK: "false"` via environment substitution (zero hardcoded secrets). Production configuration validation remains strictly enabled and fail-closed.
- **Regression Tests Added (`tests/test_phase1_security_remediation.py`):**
  - `test_infra01_worker_compose_env_passes_production_validation` — **PASSED**
  - `test_infra01_worker_fails_closed_when_secret_key_missing` — **PASSED**
  - `test_infra01_worker_process_exits_nonzero_without_mandatory_prod_config` — **PASSED**
  - `docker compose -f docker-compose.prod.yml config -q` — **PASSED (exit 0)**
- **Remaining Limitations:** Live `docker compose up` execution of `worker` could not be performed because the Docker Desktop Linux Engine daemon is not running on this host (`docker info` exited non-zero).

---

## 4. Modified & Created File Inventory

### Modified Files
- `backend/app/core/config.py` — Added `ALLOW_LOCAL_INGESTION_IN_PRODUCTION`, `LOCAL_INGESTION_ALLOWED_ROOTS`, and fail-closed production validator check.
- `backend/app/core/ingestion.py` — Fixed workspace `is_relative_to()` confinement, hardened `validate_local_ingest_path()`, added `copy_local_directory_safely()`.
- `backend/app/api/v1/endpoints/repositories.py` — Switched `ingest_local_directory` from `shutil.copytree` to `copy_local_directory_safely`.
- `backend/app/schemas/auth.py` — Added `UserRole` enum, removed `role` from `UserRegister`, added validator rejecting privileged registration fields.
- `backend/app/models/user.py` — Changed default `User.role` from `"admin"` to `"analyst"`.
- `backend/app/core/auth.py` — Made DB authoritative for `user.role`, removed JWT role overwrite, enforced `VALID_ROLES` fail-closed checks.
- `backend/app/api/v1/endpoints/auth.py` — Hardcoded `DEFAULT_REGISTERED_ROLE` on registration and validated role on login.
- `backend/app/main.py` — Removed startup `seed_initial_dev_data()` and hardcoded personal credentials.
- `docker-compose.prod.yml` — Added mandatory production env vars and fail-closed sandbox settings to `worker`.
- `.env.example` — Documented `ALLOW_LOCAL_INGESTION_IN_PRODUCTION` and `LOCAL_INGESTION_ALLOWED_ROOTS`.
- `frontend/src/context/AuthContext.tsx` — Removed hardcoded credentials, `defaultTester`, `loginAsTester`, auto-login, and silent registration on failed login; wired `redmercury:session-expired` and clean logout.
- `frontend/src/services/api.ts` — Removed hardcoded credentials and auto-login POST from `ensureAuthenticated()` and 401 retry handler.
- `frontend/src/pages/LoginPage.tsx` — Cleared pre-filled credentials, removed 1-click tester launch and client-selectable role dropdown.
- `frontend/src/pages/FindingsPage.tsx` — Removed `api.setAuthToken(null)` and `ensureAuthenticated` from refresh handler.
- `frontend/src/pages/SettingsPage.tsx` — Removed hardcoded personal name/email fallbacks.
- `electron/main.cjs` — Enabled `sandbox: true`, `webSecurity: true`, `will-navigate` origin guard, IPC sender validation, `shell: false` Python spawn, safe static asset resolver, security headers, and synchronous backend termination.
- `tests/conftest.py`, `tests/test_authorization.py`, `tests/test_api_reliability_and_resilience.py` — Added `role` parameter to `create_test_user` fixture and updated legacy RBAC tests to set authoritative DB roles.

### Created Files
- `electron/security.cjs` — Isolated Electron security helpers (path containment, URI validation, origin & external URL validation, backend arg/port validation, synchronous termination).
- `electron/security.test.cjs` — Electron security regression test suite (10 tests).
- `tests/test_phase1_security_remediation.py` — Backend & worker Phase 1 security regression test suite (19 tests).
- `frontend/src/__tests__/AuthSecurity.test.tsx` — Frontend authentication security regression test suite (5 tests).
- `RED_MERCURY_PHASE1_SECURITY_REMEDIATION_REPORT.md` — This report.

---

## 5. Complete Test Execution Results

| Suite | Command | Collected | Passed | Failed | Skipped | Duration |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Backend (`pytest`)** | `python -m pytest tests/ -q --tb=short` | 461 | **441** | **0** | **20** | 155.50s |
| **Frontend (`vitest`)** | `npm --prefix frontend run test` | 46 | **46** | **0** | **0** | 12.55s |
| **Frontend TypeScript** | `npm --prefix frontend run lint` (`tsc --noEmit`) | — | **Pass** | **0** | — | — |
| **Electron (`node:test`)** | `node --test electron/security.test.cjs` | 10 | **10** | **0** | **0** | 0.15s |
| **Docker Compose Config** | `docker compose -f docker-compose.prod.yml config -q` | — | **Pass** | **0** | — | — |

**Disclosed Environment Skips (20 backend tests, unchanged from Phase 0):**
- 15 live Docker daemon tests (`test_live_docker_security_runtime.py`, `test_sandbox.py`) — Docker daemon not running on host.
- 3 live PostgreSQL tests (`test_postgresql_integration.py`) — PostgreSQL service / `TEST_POSTGRES_URL` unavailable on host.
- 1 Semgrep test (`test_scanners.py`) — Semgrep excluded on `win32`.
- 1 OS symlink test (`test_verification_security_hardening.py`) — requires Windows administrator privileges.

---

## 6. Remaining Risks & Phase 2 Recommendations

While all five Phase 0 **CRITICAL** blockers are now closed, the following **HIGH** and **MEDIUM** Phase 0 findings remain open for Phase 2 before any production release:

1. **Ingestion & SSRF Hardening (`SEC-05`, `SEC-06`, `SEC-15`):** Replace `shutil.copyfileobj` in ZIP extraction with byte-counted chunked streaming; enforce network-level egress isolation for `git clone` (remove invalid `-c http.resolve`); fix `clean_stale_workspaces()` and `delete_repository()` path validation.
2. **Distributed Rate Limiting, Session Architecture & Staging Parity (`SEC-07`, `SEC-16`, `SEC-17`):** Move rate limiting to Redis; parse rightmost untrusted `X-Forwarded-For`; throttle verification/validation/webhook/logout endpoints; validate tokens before revoking; add CSRF check on `/auth/logout`; evaluate & execute migration from `localStorage` JWT to `HttpOnly` cookies + refresh tokens; apply production security gates to `APP_ENV=staging`.
3. **Core Pipeline Bug Fixes (`SEC-12`, `REL-02`, `SEC-14`):** Verify GitHub webhook HMAC *before* recording `WebhookDelivery` and fix per-installation webhook secret lookup; fix `verification/service.py` `NormalizedFinding` attribute names; fix `validation/ai_assistant.py` Gemini client calls; fix `Path` import in `integrations/github/service.py`; implement `SARIF` branch in `generate_findings_report`; add cross-tenant FK checks on `POST /findings` and `POST /evidence`.
4. **Nginx, Worker Network & Supply Chain (`SEC-13`, `SEC-20`, `REL-01`):** Fix `nginx/frontend.conf` static asset header stripping and CSP; set `TRUSTED_PROXIES` for Docker bridge subnet; add `internal: true` to worker network; verify Gitleaks SHA-256 and pin Docker digests/GitHub Actions SHAs; unify async scan execution onto a single durable worker queue.
5. **Live Docker & PostgreSQL Verification:** Run the full test suite and `docker compose -f docker-compose.prod.yml up` against a live Linux Docker daemon and PostgreSQL 16 instance in CI before moving to a staging release.
