# RED MERCURY — PHASE 3: AUTHENTICATION ARCHITECTURE, SESSION SECURITY & DISTRIBUTED RATE LIMITING REPORT

**Date:** 2026-11-21  
**Repository:** `https://github.com/Dhineshkumardhina/Red-Mercury`  
**Branch / Baseline Commit:** `main` @ `b9df7b9`  
**Reference Reports:**  
- [RED_MERCURY_PHASE0_COMPLETE_REPOSITORY_AUDIT.md](RED_MERCURY_PHASE0_COMPLETE_REPOSITORY_AUDIT.md)  
- [RED_MERCURY_PHASE1_SECURITY_REMEDIATION_REPORT.md](RED_MERCURY_PHASE1_SECURITY_REMEDIATION_REPORT.md)  
- [RED_MERCURY_PHASE2_INGESTION_SSRF_SECURITY_REPORT.md](RED_MERCURY_PHASE2_INGESTION_SSRF_SECURITY_REPORT.md)  
**Phase 3 Status:** **COMPLETE** (`SEC-07`, `SEC-16`, and `SEC-17` remediated and verified with backend, frontend, Electron, and Compose config tests; environmental limits for live Redis/Docker/PostgreSQL/browser disclosed)

---

## 1. Executive Summary

Phase 3 hardened Red Mercury's authentication, session lifecycle, CSRF protection, distributed rate limiting, and staging configuration parity without rebuilding the application or weakening any Phase 1 or Phase 2 controls.

### Key Architectural Upgrades
1. **Distributed Redis Rate Limiting & Secure Proxy IP Parsing (`SEC-07`):** Replaced process-local-only rate limiting with an atomic Redis sliding-window Lua implementation (`RedisRateLimiter` / `DistributedRateLimiter`) supporting multi-instance API deployments, configurable fail-open/fail-closed outage handling, CIDR-aware `TRUSTED_PROXIES`, **rightmost-untrusted `X-Forwarded-For`** parsing, canonical path normalization, and distinct per-endpoint quotas across login, registration, refresh, logout, ingestion, scans, verifications, AI validation, AI analysis, GitHub webhooks, and reports.
2. **HttpOnly Cookie Sessions, Short-Lived Access Tokens & Rotating Refresh Tokens (`SEC-16`):** Reduced default access-token lifetime from 24 hours to **15 minutes**, removed `localStorage` JWT persistence from the frontend, migrated all frontend requests to `credentials: 'include'`, implemented `POST /api/v1/auth/refresh` with **server-side refresh-token rotation**, **family-wide reuse/replay detection**, and **atomic concurrent-refresh race protection**, added double-submit `X-CSRF-Token` + Origin/Referer validation on all cookie-backed mutations (including `/refresh` and `/logout`), and prevented unauthenticated `revoked_tokens` DB bloat.
3. **Staging Security Parity (`SEC-17`):** Introduced `Settings.is_strict_env` (`production` and `staging`) so `APP_ENV=staging` enforces the exact same mandatory security gates as `production` (strong `SECRET_KEY`, PostgreSQL-only DB, strict CORS/Host allowlists, `DEBUG=False`, `Secure` cookies, HSTS, `TrustedHostMiddleware`, disabled `/docs`, fail-closed sandbox, local ingestion lockdown, and no `http://testserver` CSRF allowance).

---

## 2. `SEC-07` Remediation — Distributed Rate Limiting & Proxy Trust

- **Original Vulnerability:** `InMemoryRateLimiter` was process-local (ineffective across multiple API replicas); `get_client_ip()` returned leftmost `X-Forwarded-For[0]` (trivially spoofable by clients); `/verifications`, `/findings/{id}/validate`, `/integrations/github/webhook`, `/auth/refresh`, and `/auth/logout` were unthrottled; unauthenticated `POST /auth/logout` persisted arbitrary invalid strings in `revoked_tokens` with `expires_at=NULL`.
- **Root Cause:** No shared Redis state, leftmost `XFF` parsing, incomplete middleware route table, and missing JWT signature check before `RevokedToken` insertion.
- **Affected Files:** `backend/app/core/security.py`, `backend/app/core/config.py`, `backend/app/core/auth.py`, `backend/requirements.txt`, `docker-compose.prod.yml`, `.env.example`.
- **Implemented Remediation:**
  - Added `RedisRateLimiter` executing an atomic Lua sliding-window script (`ZREMRANGEBYSCORE` + `ZCARD` + `ZADD` + `PEXPIRE`) via `EVAL`, wrapped by `DistributedRateLimiter` with configurable `REDIS_URL` and `RATE_LIMIT_FAIL_OPEN` (fails closed in `docker-compose.prod.yml` via `RATE_LIMIT_FAIL_OPEN=false`, falls back to local sliding window when `RATE_LIMIT_FAIL_OPEN=true`).
  - Added `redis:7-alpine` service (`redmercury_redis`) to `docker-compose.prod.yml` and `redis>=5.0.0` to `backend/requirements.txt`.
  - Upgraded `get_client_ip()` with CIDR-aware `_is_trusted_proxy_ip()` and **right-to-left `X-Forwarded-For` traversal** returning the rightmost untrusted IP; untrusted peers have all proxy headers ignored.
  - Added `_normalize_rate_limit_path()` (`posixpath.normpath` + lowercase) to prevent alternate-path bypasses (`/api/v1/auth//login`, `/api/v1/auth/register/`).
  - Configured distinct per-endpoint limits:

| Endpoint / Operation | Config Setting | Default Limit (per 60s) | Scope |
| :--- | :--- | :---: | :--- |
| `POST /api/v1/auth/login` | `AUTH_RATE_LIMIT_LOGIN_MAX` | 10 (IP) + 10 (account) | IP + Email |
| `POST /api/v1/auth/register` | `AUTH_RATE_LIMIT_REGISTER_MAX` | 5 | Client IP |
| `POST /api/v1/auth/refresh` | `AUTH_RATE_LIMIT_REFRESH_MAX` | 30 | Client IP |
| `POST /api/v1/auth/logout` | `AUTH_RATE_LIMIT_LOGOUT_MAX` | 20 | Client IP |
| `POST /api/v1/repositories/ingest/*` | `RATE_LIMIT_INGEST_MAX` | 15 | Token hash / IP |
| `POST /api/v1/scans` | `RATE_LIMIT_SCAN_MAX` | 20 | Token hash / IP |
| `POST /api/v1/verifications` | `RATE_LIMIT_VERIFICATION_MAX` | 15 | Token hash / IP |
| `POST /api/v1/findings/{id}/validate` | `RATE_LIMIT_VALIDATION_MAX` | 25 | Token hash / IP |
| `POST /api/v1/analyze-finding` | `RATE_LIMIT_AI_MAX` | 30 | Token hash / IP |
| `POST /api/v1/integrations/github/webhook` | `RATE_LIMIT_WEBHOOK_MAX` | 60 | Client IP |
| `GET /api/v1/evidence/reports*` | `RATE_LIMIT_REPORTS_MAX` | 30 | Token hash / IP |

---

## 3. `SEC-16` Remediation — Secure HttpOnly Cookie Sessions & Refresh Rotation

- **Original Vulnerability:** 24-hour Bearer JWTs stored in `localStorage` (XSS-exfiltratable), unimplemented refresh tokens, missing `require`/`iss`/`typ` JWT validation, CSRF-unprotected `/auth/logout`, and `revoked_tokens` DB bloat from unvalidated tokens.
- **Root Cause:** SPA stored JWTs in `localStorage` and lacked a rotating refresh-token persistence model and double-submit CSRF flow.
- **Affected Files:** `backend/app/models/token.py`, `backend/alembic/versions/0013_add_refresh_token_sessions.py`, `backend/app/core/security.py`, `backend/app/core/auth.py`, `backend/app/api/v1/endpoints/auth.py`, `backend/app/core/config.py`, `backend/app/main.py`, `frontend/src/services/api.ts`, `frontend/src/context/AuthContext.tsx`.

### 3.1 Authentication Architecture — Before & After
- **Before:** Login returned a 24-hour JWT; frontend wrote it to `localStorage.setItem('redmercury_token', ...)`, attached `Authorization: Bearer ...`, and never sent `credentials: 'include'`. No refresh endpoint existed.
- **After:**
  - Login/register issue a **15-minute** access JWT (`iss="red-mercury"`, `typ="access"`, `jti`, `iat`, `exp`) in an `HttpOnly` cookie (`access_token`, `Path=/`), a **7-day** opaque rotating refresh token in an `HttpOnly` cookie (`refresh_token`, `Path=/api/v1/auth`), and a double-submit CSRF cookie (`rm_csrf_token`, `HttpOnly=False`, `Path=/`).
  - Frontend sends `credentials: 'include'` on every request, attaches `X-CSRF-Token` from `rm_csrf_token` on all state-changing methods, restores sessions via `GET /api/v1/auth/me`, and **never persists tokens to `localStorage`**.
  - Database remains strictly authoritative for `user.role` on every request and on every refresh rotation.

### 3.2 Refresh-Token Lifecycle (`RefreshTokenSession`)
1. **Issuance (`/login`, `/register`):** Generates 48-byte `secrets.token_urlsafe` opaque token, stores only its SHA-256 hash (`token_hash`) with a `family_id` UUID and `expires_at` in `refresh_token_sessions`.
2. **Rotation (`POST /api/v1/auth/refresh`):**
   - Validates CSRF (`Origin`/`Referer` + double-submit `X-CSRF-Token`).
   - Atomically claims the active row via conditional `UPDATE refresh_token_sessions SET revoked_at = :now, revoke_reason = 'rotated', replaced_by_hash = :new_hash WHERE id = :id AND revoked_at IS NULL` (`rowcount == 1` prevents concurrent refresh races!).
   - Reloads the `User` from the database, enforces `account_status == "active"` and valid authoritative DB `role`, and issues a fresh access cookie + rotated refresh cookie in the same `family_id`.
3. **Reuse / Replay Detection:** If an already-revoked refresh token is presented again, `rotate_refresh_token_session()` immediately revokes the **entire `family_id`**, records a `REFRESH_TOKEN_REUSE_DETECTED` audit event, clears cookies, and returns `401 Unauthorized`.
4. **Logout (`POST /api/v1/auth/logout`):** Enforces CSRF on cookie sessions, revokes valid access tokens (ignoring invalid/forged strings so `revoked_tokens` cannot be bloated), revokes the entire refresh `family_id`, and deletes `access_token`, `refresh_token`, and `rm_csrf_token` cookies.

### 3.3 CSRF Protection Architecture
- **Layer 1 (`SameSite`):** All auth cookies set `SameSite=Lax` by default (configurable to `Strict`, or `None` with `Secure=True` for cross-site deployments).
- **Layer 2 (`Origin` / `Referer` Allowlist):** `verify_csrf_origin()` verifies `Origin` or `Referer` against exact `CORS_ORIGINS` / same-origin, rejecting missing headers and disabling `http://testserver` in staging/production.
- **Layer 3 (Double-Submit Token):** Whenever `rm_csrf_token` cookie is present on a cookie-authenticated `POST`/`PUT`/`PATCH`/`DELETE` (including `/auth/refresh` and `/auth/logout`), `verify_csrf_origin()` requires a matching `X-CSRF-Token` header verified via `hmac.compare_digest`.

---

## 4. `SEC-17` Remediation — Staging Security Parity

- **Original Vulnerability:** `APP_ENV=staging` bypassed all production validators (`SECRET_KEY`, SQLite, wildcard/`null` CORS, `DEBUG`, CSRF/rate-limiting flags, local ingestion lockdown, `Secure` cookies, HSTS, `TrustedHostMiddleware`, `/docs` disablement, and `sandbox_allow_host_fallback`).
- **Implemented Remediation:** Added `Settings.is_strict_env` (`APP_ENV in ("production", "staging")`) and applied all 10 production security gates, `cookie_secure`, `sandbox_allow_host_fallback=False`, HSTS, `TrustedHostMiddleware`, disabled `/docs`, exact CORS origins (no localhost regex), `dev@xerova.com` blocking, local ingestion lockdown, and `http://testserver` CSRF removal across both `staging` and `production` — while preserving local `development` ergonomics.

---

## 5. Frontend Migration Details

- **`frontend/src/services/api.ts`:** Removed all `localStorage.getItem/setItem('redmercury_token')` calls; added `getCsrfToken()`, `credentials: 'include'` on all `fetch()` calls, automatic `X-CSRF-Token` attachment on mutating requests, `microCache` bypass for `/api/v1/auth/*`, and single-flight `refreshSession()` on 401 with `isRetry` guard (max 1 retry — zero infinite 401 loops, zero duplicate concurrent refreshes).
- **`frontend/src/context/AuthContext.tsx`:** Restores session strictly via `GET /api/v1/auth/me` (HttpOnly cookie); login/register rely on backend cookies and never store tokens in `localStorage`; logout calls `POST /api/v1/auth/logout`, clears caches, and resets state.

---

## 6. Modified & Created File Inventory

### Modified Files
- `backend/app/core/config.py` — Added `is_strict_env`, 15-min default `ACCESS_TOKEN_EXPIRE_MINUTES`, `REFRESH_COOKIE_NAME`, `CSRF_COOKIE_NAME`, `COOKIE_DOMAIN`, `REDIS_URL`, `RATE_LIMIT_FAIL_OPEN`, distinct per-endpoint rate-limit settings, and staging parity validation.
- `backend/app/models/token.py` — Added `RefreshTokenSession` model.
- `backend/app/core/security.py` — Added `iss`/`typ` JWT validation, `RedisRateLimiter` (atomic Lua), `DistributedRateLimiter`, CIDR + rightmost-untrusted `get_client_ip()`, canonical path normalization, expanded per-endpoint rate-limiting middleware, and staging HSTS parity.
- `backend/app/core/auth.py` — Added double-submit CSRF check, removed `http://testserver` in strict envs, validated tokens before revoking in `revoke_token()`, added `issue_refresh_token_session()`, `rotate_refresh_token_session()`, `revoke_refresh_token_family()`, and staging parity on `dev@xerova.com`.
- `backend/app/api/v1/endpoints/auth.py` — Added `_set_auth_cookies()`, `_clear_auth_cookies()`, `POST /api/v1/auth/refresh`, CSRF-protected `POST /api/v1/auth/logout` with family revocation, and staging parity.
- `backend/app/core/ingestion.py` — Extended local ingestion lockdown from `is_production` to `is_strict_env`.
- `backend/app/main.py` — Updated `HEAD_REVISION` to `0013_add_refresh_token_sessions` and applied `TrustedHostMiddleware`, disabled `/docs`, and strict CORS to `is_strict_env`.
- `backend/requirements.txt` — Added `redis>=5.0.0`.
- `docker-compose.prod.yml` — Added `redis:7-alpine` service and wired `REDIS_URL` + `RATE_LIMIT_FAIL_OPEN=false` to `api`.
- `.env.example` — Documented session TTLs, cookie settings, and Redis rate-limiting variables.
- `frontend/src/services/api.ts` & `frontend/src/context/AuthContext.tsx` — Migrated to HttpOnly cookie sessions, CSRF header, and single-flight refresh.
- `tests/test_auth.py`, `tests/test_migration_consistency.py`, `frontend/src/__tests__/App.test.tsx`, `frontend/src/__tests__/AuthSecurity.test.tsx` — Aligned with CSRF-protected logout, migration `0013`, and cookie-based frontend auth.

### Created Files
- `backend/alembic/versions/0013_add_refresh_token_sessions.py` — Linear Alembic migration creating `refresh_token_sessions`.
- `tests/test_phase3_auth_session_ratelimit.py` — 21 targeted backend regression tests covering `SEC-07`, `SEC-16`, and `SEC-17`.
- `RED_MERCURY_PHASE3_AUTH_SESSION_SECURITY_REPORT.md` — This report.

---

## 7. Test Execution Results & Verification Evidence

| Suite | Command | Collected | Passed | Failed | Skipped | Notes |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **Backend Full Suite** | `python -m pytest tests/ -q --tb=short` | 547 | **527** | **0** | **20** | Includes 21 new Phase 3 tests + migration `0013` schema-sync verification |
| **Frontend (`vitest`)** | `npm --prefix frontend run test` | 46 | **46** | **0** | **0** | Includes updated `AuthSecurity.test.tsx` verifying `credentials: 'include'`, zero `localStorage`, CSRF header, single-flight refresh & no 401 loop |
| **Frontend TypeScript** | `npm --prefix frontend run lint` (`tsc --noEmit`) | — | **Pass** | **0** | — | Clean build |
| **Electron (`node:test`)** | `node --test electron/security.test.cjs` | 10 | **10** | **0** | **0** | All Electron security controls intact |
| **Docker Compose Config** | `docker compose -f docker-compose.prod.yml config -q` | — | **Pass** | **0** | — | Validated with `redis` service + required env vars |

### Unit vs. Live Integration Disclosure
- **Unit & In-Process Integration Tested:** Atomic Redis sliding-window Lua behavior (simulated via thread-safe `AtomicFakeRedis`), multi-instance concurrency, `X-Forwarded-For` rightmost-untrusted & CIDR parsing, cookie attributes, refresh rotation, reuse detection, concurrent refresh race safety, CSRF rejection, logout family revocation, staging parity, Alembic `0013` schema sync, and React/Vitest cookie + single-flight refresh flows.
- **Unverified Live Infrastructure (Disclosed):**
  - Live Redis server (`redis:7-alpine`), live Docker daemon (15 skipped tests), and live PostgreSQL 16 (3 skipped tests) are not running on this Windows host.
  - Real browser cross-site cookie behavior (`SameSite=None; Secure` across Cloudflare Workers ↔ Railway) was not exercised in a live Chromium browser; deployment topology constraints are documented below.
  - 1 Semgrep test (`win32`) and 1 Windows admin symlink test remain skipped (unchanged from Phase 0–2).

---

## 8. Deployment Requirements & Cross-Origin Topology Notes

1. **Same-Site Deployment (Recommended — `docker-compose.prod.yml` / Nginx):** Frontend and API share the same origin (`https://redmercury.xerova.com`). Keep `COOKIE_SAMESITE=lax`, `REDIS_URL=redis://redis:6379/0`, `RATE_LIMIT_FAIL_OPEN=false`, and set `TRUSTED_PROXIES` to the Nginx/Docker bridge subnet (e.g., `172.16.0.0/12`).
2. **Split-Origin Deployment (Cloudflare Workers UI + Railway API):** If frontend and API reside on different eTLD+1 sites, browsers will not send `SameSite=Lax` cookies on cross-site `fetch()`. Operators must either:
   - *(Recommended)* Proxy `/api/*` under the frontend domain via Cloudflare Workers/Nginx so cookies remain first-party (`SameSite=Lax`), **or**
   - Set `COOKIE_SAMESITE=none` over HTTPS (`Secure=True`), configure exact `CORS_ORIGINS` (never `*`), and verify third-party cookie behavior in target browsers (Safari ITP / Chrome third-party cookie restrictions favor the first-party proxy topology).
3. **Database Migration:** Run `alembic upgrade head` (applies `0013_add_refresh_token_sessions`) before starting API replicas.

---

## 9. Remaining Risks & Phase 4 Recommendations

1. **Core Pipeline Bug Fixes & Cross-Tenant FK Checks (`SEC-12`, `SEC-14`, `REL-02`):** Verify GitHub webhook HMAC before recording `WebhookDelivery` and fix per-installation webhook secret storage; add cross-tenant FK checks on `POST /findings` and `POST /evidence`; fix `verification/service.py` `NormalizedFinding` attributes, `validation/ai_assistant.py` Gemini client calls, `integrations/github/service.py` `Path` import, and `SARIF` findings report export.
2. **Nginx, CSP & Supply Chain Hardening (`SEC-13`, `SEC-20`):** Fix `nginx/frontend.conf` static asset security header stripping and `connect-src`; verify Gitleaks SHA-256 in `Dockerfile.worker` and CI; pin Docker image digests and GitHub Actions SHAs.
3. **Live Integration CI:** Add Redis 7, PostgreSQL 16, and live Docker sandbox + Playwright E2E cookie-session tests to CI.
