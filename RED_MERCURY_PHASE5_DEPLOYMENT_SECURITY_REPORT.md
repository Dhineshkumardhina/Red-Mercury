# RED MERCURY — PHASE 5: DEPLOYMENT BOUNDARY SECURITY, SSRF EGRESS ENFORCEMENT & SUPPLY-CHAIN HARDENING REPORT

**Repository:** `https://github.com/Dhineshkumardhina/Red-Mercury`  
**Branch:** `main`  
**Actual HEAD Commit:** `b9df7b9650e0ba431e8d32b19edf30ddd6f6289c` (`b9df7b9`)  
**Phase:** Phase 5 — Deployment Boundary Security, SSRF Egress Enforcement & Supply-Chain Hardening  
**Audit Date:** 2026-11-21  
**Target Findings Remediated:** `SEC-06` (Fail-Closed Git Egress Protection & Proxy Enforcement), `SEC-11` (Container & Runtime Boundary Verification), `SEC-13` (Nginx Security Header Inheritance & TLS/HSTS Enforcement), `SEC-19` (Analyzer Role Authorization & Streaming Request Body Size Enforcement), `SEC-20` (Content Security Policy Hardening, Gitleaks Supply-Chain SHA-256 Verification & Narrowed `.gitleaks.toml` Allowlists)  

---

## 1. Executive Summary

Phase 5 hardens Red Mercury's deployment perimeter, outbound Git network egress boundaries, reverse-proxy HTTP security header inheritance, Content Security Policy (CSP), third-party supply-chain integrity (Gitleaks binary SHA-256 verification, immutable Docker image `@sha256` digest pinning, and 40-character GitHub Actions commit SHA pinning), analyzer endpoint RBAC enforcement, and streaming ASGI request body size limits.

All Phase 1 through Phase 4 security controls were preserved without regression. Across the full verification matrix:
- **Backend Automated Test Suite (`pytest`):** `588 passed, 5 skipped, 0 failed` (out of 593 total tests), including **38 new Phase 5 tests** in `tests/test_phase5_deployment_security.py` and **32 live Docker sandbox security runtime tests** (`tests/test_live_docker_security_runtime.py` and `tests/test_sandbox.py`).
- **Frontend Test Suite (`vitest`):** `46 passed, 0 failed` across 7 test files.
- **Frontend TypeScript Verification (`tsc --noEmit`):** `0 errors`.
- **Electron Security Regression Suite (`node --test electron/security.test.cjs`):** `10 passed, 0 failed`.
- **Docker Compose Production Topology Validation (`docker compose -f docker-compose.prod.yml config -q`):** `exit code 0`.
- **Gitleaks Repository Scan (`.\bin\gitleaks.exe detect --no-git --config .gitleaks.toml --redact`):** `no leaks found` (`exit code 0`).

---

## 2. Baseline Repository State and Preserved Modifications

Before implementing Phase 5 changes, the working tree was inspected on branch `main` at HEAD commit `b9df7b9650e0ba431e8d32b19edf30ddd6f6289c`. All existing uncommitted modifications from Phases 1–4 were preserved intact:

| Phase | Preserved Files & Controls |
| :--- | :--- |
| **Phase 1** | `backend/app/core/ingestion.py` (`SEC-01` local ingestion production lock & allowlist), `backend/app/schemas/auth.py` & `backend/app/api/v1/endpoints/auth.py` (`SEC-02` public registration role stripping & `viewer` default), `backend/app/core/config.py` (`SEC-03` fail-closed `docker` sandbox mode), `electron/main.cjs` & `electron/security.cjs` (`SEC-04`/`SEC-10` custom `app://` protocol containment & origin guards), `Dockerfile.worker` (`SEC-11` non-root `10002:10002` worker execution). |
| **Phase 2** | `backend/app/core/ingestion.py` (`SEC-05` streaming ZIP extraction quotas, compression ratio enforcement, symlink/special-file rejection; `SEC-06` initial DNS/IP validation, HTTPS enforcement, redirect disabling, hook disabling), `backend/app/core/workspace_cleanup.py` (`SEC-15` confined deletion & ancestry checks). |
| **Phase 3** | `backend/app/core/auth.py`, `backend/app/core/security.py`, `backend/app/api/v1/endpoints/auth.py`, `backend/app/models/token.py`, `backend/alembic/versions/0013_add_refresh_token_sessions.py`, `frontend/src/services/api.ts`, `frontend/src/context/AuthContext.tsx` (`SEC-07` distributed Redis/Lua + memory fallback rate limiting & proxy trust; `SEC-16` HttpOnly cookie session architecture, refresh-token rotation & reuse revocation, double-submit CSRF protection; `SEC-17` staging parity with production security gates). |
| **Phase 4** | `backend/app/integrations/github/webhook.py` (`SEC-12` durable delivery replay prevention, raw body HMAC-SHA256 verification before JSON parse, safe queuing), `backend/app/api/v1/endpoints/{repositories,findings,evidence,analyzer}.py` & `backend/app/verification/service.py` (`SEC-14` cross-tenant ownership isolation & `require_mutating_role`), `backend/app/evidence/service.py`, `backend/app/validation/service.py`, `backend/app/analyzer/client.py` (`REL-02` pipeline integrity & Gemini `x-goog-api-key` header transport). |

---

## 3. Findings-to-Files Mapping

| Finding ID | Vulnerability / Gap Summary | Files Modified / Created in Phase 5 |
| :--- | :--- | :--- |
| **SEC-06** | Residual DNS rebinding / TOCTOU risk when Git clones directly without a mandatory egress proxy in strict environments; incomplete validation of `GIT_EGRESS_PROXY_URL`; lack of internal Docker network egress isolation. | `backend/app/core/config.py`, `backend/app/core/ingestion.py`, `backend/app/api/v1/endpoints/repositories.py`, `docker-compose.prod.yml`, `.env.example`, `tests/test_phase5_deployment_security.py` |
| **SEC-11** | Container & runtime boundary controls (`read_only: true`, `tmpfs`, `cap_drop: [ALL]`, `no-new-privileges:true`, non-root users, internal-only networks) across production services. | `docker-compose.prod.yml`, `Dockerfile.api`, `Dockerfile.worker`, `Dockerfile.frontend`, `tests/test_phase5_deployment_security.py` |
| **SEC-13** | Nginx `location` blocks with `add_header Cache-Control` silently dropped parent `server`-block security headers (`CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `COOP`, `CORP`); HSTS needed strict scoping to TLS-terminated servers. | `nginx/frontend.conf`, `nginx/production.conf`, `tests/test_phase5_deployment_security.py` |
| **SEC-19** | `POST /api/v1/analyze-finding` allowed read-only `viewer`/`auditor` users to trigger external AI analysis and persist `FindingAnalysis` rows; `RequestSizeLimitMiddleware` checked only the `Content-Length` header and could be bypassed via chunked transfer encoding. | `backend/app/api/v1/endpoints/analyzer.py`, `backend/app/core/security.py`, `tests/test_phase5_deployment_security.py` |
| **SEC-20** | Broad `connect-src 'self' http://* https://*` and `connect-src 'self' https:` wildcards in Nginx and Cloudflare `_headers` CSP; unverified `curl \| tar` Gitleaks binary download in `Dockerfile.worker` and CI workflows; overly broad `.gitleaks.toml` directory allowlists (`tests/`, `scripts/`, `reports/`, `benchmark/`); unpinned Docker base image tags and GitHub Action version tags. | `nginx/frontend.conf`, `nginx/production.conf`, `frontend/public/_headers`, `Dockerfile.api`, `Dockerfile.worker`, `Dockerfile.frontend`, `docker-compose.prod.yml`, `.github/workflows/ci.yml`, `.github/workflows/redmercury_pr_gate.yml`, `.github/workflows/redmercury-analysis.yml.example`, `.gitleaks.toml`, `backend/app/core/config.py`, `backend/app/core/ingestion.py`, `tests/test_phase5_deployment_security.py` |

---

## 4. SEC-06 Fail-Closed Git Egress Architecture

### Root Cause
In Phase 2, `validate_git_remote_url()` resolved target hostnames via `socket.getaddrinfo()` before invoking `git clone`. However, because `libcurl` inside the `git-remote-https` child process performs its own DNS resolution when connecting directly to the internet, a residual time-of-check/time-of-use (TOCTOU) DNS rebinding window existed unless all outbound Git traffic was forced through a dedicated egress proxy that enforces destination IP filtering at connection time. Furthermore, `GIT_EGRESS_PROXY_URL` was optional even in `production` and `staging`, and its value was not validated against loopback, metadata, link-local, or credential-bearing URLs.

### Remediation Implemented
1. **Strict Environment Fail-Closed Policy (`resolve_required_git_egress_proxy` in `backend/app/core/ingestion.py`):**
   - When `settings.is_strict_env` is `True` (`APP_ENV` in `{"production", "staging"}`), `resolve_required_git_egress_proxy()` requires `settings.GIT_EGRESS_PROXY_URL` to be configured and valid.
   - If `GIT_EGRESS_PROXY_URL` is unset or empty in `production` or `staging`, Git ingestion fails closed immediately with `SecurityPolicyViolationError` before creating any database record or spawning any `git` subprocess.
   - In `development` and `test` environments (`is_strict_env == False`), direct Git cloning remains available when `GIT_EGRESS_PROXY_URL` is unset (preserving existing URL/DNS/IP SSRF validations), while any configured `GIT_EGRESS_PROXY_URL` is still strictly validated.
2. **Comprehensive Proxy URL Validation (`validate_git_egress_proxy_url` in `backend/app/core/ingestion.py`):**
   - Rejects control characters, whitespace, non-`http`/`https` schemes, embedded credentials (`user:pass@`), missing hostnames, missing explicit ports, non-root paths, query strings, and URL fragments.
   - Rejects `localhost`, `.local`, `.internal`, and literal or DNS-resolved loopback (`127.0.0.0/8`, `::1`), unspecified (`0.0.0.0`), link-local/cloud metadata (`169.254.0.0/16`, `fe80::/10`), multicast, and reserved IP ranges.
   - Rejects RFC1918 private and CGNAT proxy addresses by default unless `ALLOW_PRIVATE_GIT_EGRESS_PROXY=True` (or the proxy hostname is explicitly listed in `APPROVED_GIT_EGRESS_PROXY_HOSTS` for internal corporate proxy deployments).
3. **Subprocess Environment Sanitization & Proxy Enforcement:**
   - `_build_sanitized_git_env()` strips `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, `GIT_SSH`, `GIT_SSH_COMMAND`, `GIT_PROXY_COMMAND`, `GIT_ASKPASS`, `GIT_CONFIG*`, and locks `GIT_ALLOW_PROTOCOL`, `GIT_TERMINAL_PROMPT=0`, `GIT_CONFIG_NOSYSTEM=1`, and `GIT_CONFIG_GLOBAL=os.devnull`.
   - `clone_git_repository()` passes `-c http.proxy=<validated_proxy>` and `-c https.proxy=<validated_proxy>` directly to `git clone`, with zero fallback to direct outbound network access if proxy validation fails.
   - `ingest_git_repository()` (`backend/app/api/v1/endpoints/repositories.py`) calls `resolve_required_git_egress_proxy()` at entry before creating a `Repository` row.
4. **Docker Network Boundary (`docker-compose.prod.yml`):**
   - `redmercury_internal` is configured with `internal: true`, blocking direct outbound internet access from internal containers (`db`, `redis`, `worker`, and internal `api` interface) while `redmercury_public` provides the controlled ingress boundary.

---

## 5. SEC-13 Nginx Security Header Inheritance and TLS/HSTS Analysis

### Root Cause
In Nginx, any `location` block that defines even a single `add_header` directive (such as `add_header Cache-Control "public, max-age=31536000, immutable";` on `/assets/` or `add_header Cache-Control "no-store, no-cache, must-revalidate";` on `/`) completely discards all `add_header` directives defined in the enclosing `server` block. As a result, static assets and SPA HTML responses served by `nginx/frontend.conf` were missing `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`, and `Cross-Origin-Resource-Policy`.

### Remediation Implemented
1. **`nginx/frontend.conf`:**
   - Added `server_tokens off;`.
   - Explicitly repeated the full set of required security headers (`X-Frame-Options "DENY"`, `X-Content-Type-Options "nosniff"`, `Referrer-Policy "strict-origin-when-cross-origin"`, `Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=()"`, `X-Permitted-Cross-Domain-Policies "none"`, `Cross-Origin-Opener-Policy "same-origin"`, `Cross-Origin-Resource-Policy "same-origin"`, and `Content-Security-Policy`) with the `always` flag inside every `location` block that defines `add_header Cache-Control` (`location /assets/` and `location /`).
   - Omitted `Strict-Transport-Security` from `nginx/frontend.conf` because it listens on internal plain HTTP (`listen 8080;`).
2. **`nginx/production.conf`:**
   - Added `server_tokens off;` and `limit_req_status 429;`.
   - Enforced `Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;` exclusively on the TLS-terminated (`listen 443 ssl http2;`) server block, while keeping the port 80 server block as a pure `301 https://$host$request_uri` redirect.
   - Added `Cross-Origin-Opener-Policy "same-origin" always;` and `Cross-Origin-Resource-Policy "same-origin" always;`, and confirmed no child `location` block overrides `add_header`.

---

## 6. SEC-20 Content Security Policy Hardening

### Root Cause
- `nginx/frontend.conf` and `nginx/production.conf` contained `connect-src 'self' http://* https://*;`, allowing browser scripts to exfiltrate data to any arbitrary HTTP or HTTPS host on the internet.
- `frontend/public/_headers` contained `connect-src 'self' https:;`, similarly permitting connections to any HTTPS origin.

### Remediation Implemented
All three frontend/proxy CSP definitions (`nginx/frontend.conf`, `nginx/production.conf`, and `frontend/public/_headers`) were hardened to remove wildcard schemes (`http://*`, `https://*`, and bare `https:`):
- **`nginx/frontend.conf` & `nginx/production.conf`:**
  ```text
  default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none';
  ```
- **`frontend/public/_headers`:**
  ```text
  default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: blob:; font-src 'self' https://fonts.gstatic.com data:; connect-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'
  ```
- **`backend/app/core/security.py` (`SecurityHeadersMiddleware`):**
  Preserved strict API CSP (`default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`).
- **Residual Note on `style-src 'unsafe-inline'`:** Retained intentionally for React/Vite inline component style attributes and dynamic UI styling; `script-src` is strictly `'self'` with no `'unsafe-inline'` or `'unsafe-eval'`.

---

## 7. SEC-20 Gitleaks Supply-Chain Verification and `.gitleaks.toml` Hardening

### Root Cause
1. `Dockerfile.worker` and `.github/workflows/ci.yml` piped `curl -sSfL .../gitleaks_8.18.2_linux_x64.tar.gz | tar -xz` directly into `/usr/local/bin` without verifying the archive's SHA-256 checksum.
2. `.gitleaks.toml` contained broad directory allowlist regexes (`'''(?i)^tests/'''`, `'''(?i)^scripts/'''`, `'''(?i)^reports/'''`, `'''(?i)^benchmark/'''`, `'''(?i)samples/'''`) that blinded Gitleaks to accidental secret commits anywhere inside those directories.

### Remediation Implemented
1. **Official Gitleaks v8.18.2 SHA-256 Checksum Verification:**
   - Verified upstream release digest for `gitleaks_8.18.2_linux_x64.tar.gz`:
     `6298c9235dfc9278c14b28afd9b7fa4e6f4a289cb1974bd27949fc1e9122bdee`
   - Updated `Dockerfile.worker` and `.github/workflows/ci.yml` to download the archive to `/tmp/gitleaks.tar.gz`, verify `echo "${GITLEAKS_SHA256}  /tmp/gitleaks.tar.gz" | sha256sum -c -`, and only extract after cryptographic verification succeeds.
   - Added `GITLEAKS_VERSION` and `GITLEAKS_LINUX_X64_SHA256` to `backend/app/core/config.py` and implemented `verify_artifact_sha256(artifact_path, expected_sha256)` in `backend/app/core/ingestion.py` using constant-time `hmac.compare_digest`.
2. **Narrowed `.gitleaks.toml` Allowlist:**
   - Removed broad `tests/`, `scripts/`, `reports/`, `benchmark/`, and `samples/` directory exclusions.
   - Scoped path allowlists exclusively to synthetic secret-detection fixture files (`tests/fixtures/`, `tests/test_git_history_secret_scanning.py`, `tests/test_scanners.py`, `tests/test_scanner_accuracy_benchmarks.py`, `tests/test_difficult_security_scenarios.py`, `tests/test_verification.py`, `tests/test_phase5_deployment_security.py`, `benchmark/datasets/`) and lockfiles.
   - Verified with `.\bin\gitleaks.exe detect --no-git --config .gitleaks.toml --redact` across the entire repository (`0 leaks found`, exit code `0`).

---

## 8. Docker Base Image Digest Pinning and Container Hardening

All mutable floating image tags in `Dockerfile.api`, `Dockerfile.worker`, `Dockerfile.frontend`, and `docker-compose.prod.yml` were pinned to verified upstream Docker Hub multi-arch OCI manifest digests (`@sha256:...`):

| File | Image & Tag | Pinned Immutable Digest |
| :--- | :--- | :--- |
| `Dockerfile.api` (builder & runtime) | `python:3.11-slim-bookworm` | `@sha256:a83ba18aef0f865b1a4a611c2cf460fe446f2795673bbb9fe43be570439e3b39` |
| `Dockerfile.worker` (builder & runtime) | `python:3.11-slim-bookworm` | `@sha256:a83ba18aef0f865b1a4a611c2cf460fe446f2795673bbb9fe43be570439e3b39` |
| `Dockerfile.frontend` (builder) | `node:20-alpine` | `@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293` |
| `Dockerfile.frontend` (runtime) | `nginx:1.27-alpine-slim` | `@sha256:b947b2630c97622793113555e13332eec85bdc7a0ac6ab697159af78942bb856` |
| `docker-compose.prod.yml` (`db`) | `postgres:16-alpine` | `@sha256:1d5b02d3a9941fbd52437db4107f8c52d6297dac553ca1e5c299ebb3756b4857` |
| `docker-compose.prod.yml` (`redis`) | `redis:7-alpine` | `@sha256:7f7d30b7fdd09467bac58198a1f166dd69789d348d4fe859cccb20e0cf287fbe` |
| `docker-compose.prod.yml` (`nginx`) | `nginx:1.27-alpine` | `@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10` |

In addition, `docker-compose.prod.yml` enforces:
- `cap_drop: [ALL]` and `security_opt: [no-new-privileges:true]` across `db`, `redis`, `api`, `worker`, and `nginx`.
- `read_only: true` with bounded `tmpfs` mounts on `redis`, `api`, `worker`, and `nginx`.
- `internal: true` on `redmercury_internal`.
- Zero Docker socket (`/var/run/docker.sock`) mounts in any container.

---

## 9. GitHub Actions Commit SHA Pinning

Every third-party GitHub Action across `.github/workflows/ci.yml`, `.github/workflows/redmercury_pr_gate.yml`, and `.github/workflows/redmercury-analysis.yml.example` was pinned to its verified 40-character upstream Git commit SHA:

| GitHub Action | Version Tag Comment | Pinned 40-Character Commit SHA |
| :--- | :--- | :--- |
| `actions/checkout` | `# v4` | `11d5960a326750d5838078e36cf38b85af677262` |
| `actions/setup-python` | `# v5` | `a26af69be951a213d495a4c3e4e4022e16d87065` |
| `actions/setup-node` | `# v4` | `49933ea5288caeca8642d1e84afbd3f7d6820020` |
| `actions/upload-artifact` | `# v4` | `ea165f8d65b6e75b540449e92b4886f43607fa02` |
| `actions/github-script` | `# v7` | `f28e40c7f34bde8b3046d885e986cb6290c5673b` |
| `docker/setup-buildx-action` | `# v3` | `8d2750c68a42422c14e847fe6c8ac0403b4cbd6f` |
| `docker/build-push-action` | `# v5` | `ca052bb54ab0790a636c9b5f226502c73d547a25` |

Additionally, in `.github/workflows/redmercury_pr_gate.yml`, direct shell interpolation of `${{ github.base_ref }}` was replaced with an environment variable (`BASE_REF: ${{ github.base_ref }}`) passed as `"origin/${BASE_REF}"` to prevent workflow script injection via crafted branch names.

---

## 10. SEC-19 Analyzer Authorization Hardening

- **File Modified:** `backend/app/api/v1/endpoints/analyzer.py`
- **Change:** Updated `POST /api/v1/analyze-finding` from `current_user: User = Depends(get_current_user)` to `current_user: User = Depends(require_mutating_role)`.
- **Security Guarantee:**
  - Unauthenticated callers receive `401 Unauthorized`.
  - Read-only `viewer` and `auditor` roles receive `403 Forbidden` and cannot trigger external Gemini LLM API calls or write `FindingAnalysis` rows to the database.
  - Authorized `analyst`, `maintainer`, and `admin` roles pass RBAC and remain subject to `verify_repository_ownership()` and `verify_finding_ownership()` tenant isolation checks.
  - `GET /api/v1/findings/{finding_id}/analyses` remains accessible to authenticated read roles (`viewer`, `auditor`, `analyst`, `maintainer`, `admin`) who own the finding (or `admin`).

---

## 11. SEC-19 Streaming Request Size Enforcement

- **File Modified:** `backend/app/core/security.py` (`RequestSizeLimitMiddleware`)
- **Root Cause:** Previously, `RequestSizeLimitMiddleware` only inspected the `Content-Length` HTTP header. A client using `Transfer-Encoding: chunked` (omitting `Content-Length`) or sending a forged small `Content-Length` header could stream an arbitrarily large request body into memory.
- **Remediation Implemented:**
  1. Validates `Content-Length` when present: negative or non-integer values are rejected immediately with `400 Bad Request` (`INVALID_CONTENT_LENGTH`), and values exceeding `settings.MAX_REQUEST_BODY_SIZE_BYTES` are rejected immediately with `413 Payload Too Large` (`PAYLOAD_TOO_LARGE`).
  2. Wraps the ASGI `request._receive` callable with a streaming byte counter (`received_bytes`) that accumulates `len(message.get("body", b""))` across every `http.request` chunk.
  3. If cumulative streamed bytes exceed `settings.MAX_REQUEST_BODY_SIZE_BYTES` at any chunk, raises `_RequestBodyTooLargeError` and returns a clean `413 Payload Too Large` JSON response while preserving `http.disconnect` cancellation propagation.

---

## 12. Phase 5 Security Test Matrix

Created `tests/test_phase5_deployment_security.py` containing **38 test cases** across all 15 required Task 8 categories:

| Category | Test Functions in `tests/test_phase5_deployment_security.py` | Verification Mode | Status |
| :--- | :--- | :--- | :--- |
| **1. Strict-mode Git ingestion rejection without egress proxy** | `test_phase5_01_strict_mode_git_ingestion_rejected_without_egress_proxy[production]`, `[staging]` | Unit + FastAPI `TestClient` | **PASS** |
| **2. Invalid `GIT_EGRESS_PROXY_URL` rejection** | `test_phase5_02_invalid_git_egress_proxy_urls_rejected[...]` (14 malformed/loopback/metadata/private/credential URLs) | Unit (mocked DNS) | **PASS** |
| **3. Non-strict development mode behavior** | `test_phase5_03_development_mode_allows_unconfigured_proxy_but_validates_if_set` | Unit | **PASS** |
| **4. Valid proxy acceptance & approved internal proxy host** | `test_phase5_04_valid_git_egress_proxy_url_accepted_and_private_opt_in` | Unit (mocked DNS) | **PASS** |
| **5. Git subprocess env sanitization & proxy routing** | `test_phase5_05_git_subprocess_env_sanitization_and_proxy_routing` | Unit (mocked subprocess) | **PASS** |
| **6. No direct Git fallback when proxy missing/invalid** | `test_phase5_06_no_direct_git_network_fallback_when_proxy_missing_or_invalid` | Unit (mocked subprocess) | **PASS** |
| **7. Nginx security header inheritance across location blocks** | `test_phase5_07_nginx_security_header_inheritance_preserved_across_locations` | Static config parser | **PASS** |
| **8. CSP policy verification (no wildcards)** | `test_phase5_08_csp_rejects_wildcards_across_nginx_cloudflare_and_backend` | Static config + `TestClient` | **PASS** |
| **9. Gitleaks SHA-256 checksum verification & mismatch failure** | `test_phase5_09_gitleaks_sha256_verification_and_mismatch_failure` | Unit + Dockerfile/CI check | **PASS** |
| **10. Missing checksum failure & narrowed `.gitleaks.toml`** | `test_phase5_10_missing_checksum_failure_and_narrowed_gitleaks_allowlist` | Unit + TOML inspection | **PASS** |
| **11. Docker base image `@sha256` digest pinning** | `test_phase5_11_docker_base_images_pinned_to_immutable_sha256_digests` | Static Dockerfile/Compose inspection | **PASS** |
| **12. GitHub Actions 40-char commit SHA pinning** | `test_phase5_12_github_actions_pinned_to_full_commit_shas` | Static workflow YAML inspection | **PASS** |
| **13. Analyzer role authorization (`viewer` 403, `analyst`/`admin` 200)** | `test_phase5_13_analyze_finding_enforces_mutating_role_rbac` | Integration (`TestClient` + SQLite) | **PASS** |
| **14. Streaming & chunked request body size enforcement** | `test_phase5_14_request_size_limit_middleware_streaming_and_chunked` | ASGI streaming unit test | **PASS** |
| **15. Phase 1–4 regression protection** | `test_phase5_15_phase1_to_phase4_security_controls_preserved` | Integration (`TestClient` + SQLite) | **PASS** |

---

## 13. Full Test Execution Results

All verification commands were executed in the workspace and their exact results recorded:

1. **Full Backend Test Suite (`python -m pytest tests/ -q --tb=short`):**
   - **Result:** `588 passed, 5 skipped in 241.23s (0:04:01)` (`exit code 0`).
   - **Phase 1–5 Security Suites Included:**
     - `tests/test_phase1_security_remediation.py`: `19 passed`
     - `tests/test_phase2_ingestion_ssrf_security.py`: `65 passed`
     - `tests/test_phase3_auth_session_ratelimit.py`: `21 passed`
     - `tests/test_phase4_core_pipeline_tenant_security.py`: `8 passed`
     - `tests/test_phase5_deployment_security.py`: `38 passed`
     - `tests/test_live_docker_security_runtime.py`: `13 passed` (executed live against Docker Engine `29.9.3`)
     - `tests/test_sandbox.py`: `19 passed` (executed live against Docker Engine `29.9.3`)
2. **Frontend Unit & Integration Test Suite (`npm --prefix frontend run test`):**
   - **Result:** `7 passed (7 test files), 46 passed (46 tests)` (`exit code 0`).
3. **Frontend TypeScript Compiler Check (`npm --prefix frontend run lint` / `tsc --noEmit`):**
   - **Result:** `0 errors` (`exit code 0`).
4. **Electron Security Regression Suite (`node --test electron/security.test.cjs`):**
   - **Result:** `10 passed, 0 failed` (`exit code 0`).
5. **Production Docker Compose Topology Validation (`docker compose -f docker-compose.prod.yml config -q`):**
   - **Result:** `COMPOSE_EXIT=0`.
6. **Gitleaks Secret Scan (`.\bin\gitleaks.exe detect --no-git --config .gitleaks.toml --redact`):**
   - **Result:** `scan completed in 25.5s — no leaks found` (`GITLEAKS_EXIT=0`).

---

## 14. Skipped Tests and Exact Reasons

Only 5 tests out of 593 backend tests were skipped:

| Test File | Skipped Count | Exact Reason |
| :--- | :---: | :--- |
| `tests/test_postgresql_integration.py` | 3 | `TEST_POSTGRESQL_URL` is not set and no local PostgreSQL 16 server is running on host port `5432`. |
| `tests/test_scanners.py` | 1 | Live Semgrep CLI execution is skipped on native `win32` because upstream Semgrep CLI is POSIX/Linux-only (runs inside the Linux worker container in Docker deployments). |
| `tests/test_verification_security_hardening.py` | 1 | `os.symlink` creation on Windows requires administrator `SeCreateSymbolicLinkPrivilege` when Developer Mode is not enabled. |

---

## 15. Environment Limitations

- **Live Docker Engine (`29.9.3`):** Operational during Phase 5 verification. Tagging the local worker image as `redmercury-worker:latest` enabled all 13 live Docker sandbox runtime security tests (`tests/test_live_docker_security_runtime.py`) and all 19 sandbox tests (`tests/test_sandbox.py`) to execute and pass against real containers.
- **Live PostgreSQL 16 / Redis 7 / Nginx Runtime:** While `docker-compose.prod.yml` syntax and schema were validated with `docker compose -f docker-compose.prod.yml config -q` and Nginx configuration directives were validated via automated AST/regex tests, a full live multi-container `docker compose -f docker-compose.prod.yml up` deployment stack (with live TLS certificates, an external forward egress proxy at `GIT_EGRESS_PROXY_URL`, PostgreSQL 16, and Redis 7) was not spun up per Project Rule 6 ("Do not perform real production deployments").

---

## 16. Remaining Risks

1. **External Egress Proxy Operation (`SEC-06`):** In `production` and `staging`, Red Mercury now fails closed unless `GIT_EGRESS_PROXY_URL` points to an operational HTTP/HTTPS forward proxy. The external proxy itself (e.g., Squid, Envoy, or Smokescreen) must be configured by infrastructure operators to deny connections to private/loopback/metadata IP ranges at the proxy socket layer to eliminate DNS rebinding at connection time.
2. **Inline Styles in Frontend CSP (`SEC-20`):** `style-src 'self' 'unsafe-inline' https://fonts.googleapis.com` remains required for React inline style props; however, `script-src 'self'`, `connect-src 'self'`, `object-src 'none'`, and `frame-ancestors 'none'` are strictly locked down.
3. **Live Multi-Container Compose Stack Verification:** Full runtime verification of `nginx/production.conf` with real TLS certificates, live PostgreSQL 16 migrations, and live Redis 7 Lua rate-limiting scripts remains a deployment-time gate.

---

## 17. Final Phase 5 Decision

**`CONDITIONALLY ACCEPTED`**

- **Justification:** All code, configuration, supply-chain pinning, fail-closed Git egress proxy enforcement, Nginx security header inheritance, CSP wildcard removal, Gitleaks SHA-256 verification, narrowed `.gitleaks.toml` allowlists, analyzer RBAC, and streaming request size limit controls required by Phase 5 Tasks 0–10 are implemented and verified with **588 passing backend tests (including 38 Phase 5 tests and 32 live Docker container sandbox tests), 46 passing frontend tests, 10 passing Electron security tests, clean TypeScript compilation, clean `docker compose config -q`, and a clean full-repo Gitleaks scan**. Conditional status reflects truthful disclosure that live multi-container production stack startup (PostgreSQL 16, Redis 7, Nginx TLS reverse proxy, and live external forward egress proxy) was validated via configuration and unit/integration tests rather than a live production deployment.
