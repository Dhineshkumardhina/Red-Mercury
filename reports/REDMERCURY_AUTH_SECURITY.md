# Red Mercury — Authentication, Authorization & Multi-User Data Isolation Audit & Hardening Report

**Audit Target:** Red Mercury Application Security Engine  
**Focus:** Authentication, Authorization, CSRF, Brute-Force Defense, Production Seed Isolation, Multi-Tenant Data Isolation, and IDOR Prevention  
**Date:** October 2026  
**Status:** **AUDITED, HARDENED & REGRESSION TESTED (60/60 Tests Passing)**

---

## 1. Executive Summary

A comprehensive application security audit of Red Mercury's authentication, authorization, session management, and multi-tenant data boundaries was conducted. The application's architecture was evaluated against OWASP ASVS Level 2/3 controls and NIST SP 800-63B guidelines.

Several high- and medium-severity security weaknesses were identified in development credential boundaries, rate-limiting IP resolution, login timing channels, cookie-based session CSRF defense, and cross-resource authorization consistency. 

All identified vulnerabilities have been remediated with defense-in-depth controls while fully preserving existing legitimate application workflows. A dedicated regression and security test suite (`tests/test_auth_security_hardening.py`) was implemented, bringing the automated authentication and multi-user test coverage to **60 passing tests**.

---

## 2. Confirmed Findings & Root Cause Analysis

### Finding 1: Production Seed Account Injection & Repository Hijacking Risk
- **Severity:** High
- **CWE:** CWE-1188 (Insecure Default Initialization of Resource), CWE-798 (Use of Hard-coded Credentials)
- **Description:** 
  The development seeding script (`scripts/seed_dev.py`) lacked any environment validation or guardrails. If executed in staging or production environments (e.g., via deployment entrypoint scripts or operator error), it would create or overwrite the development user `dev@xerova.com` with the static password `XerovaDevPass2026!`. Furthermore, line 31 of `scripts/seed_dev.py` explicitly reassigned **all** existing repositories in the database to `dev@xerova.com`, resulting in complete data hijacking.
  Additionally, the production authentication endpoint did not prohibit `dev@xerova.com` from logging in if the account existed in the database.
- **Remediation:**
  - Added an unconditional environment guard in `scripts/seed_dev.py` that immediately aborts with an exit code of `1` if `settings.is_production` is `True` or if `settings.APP_ENV not in ("development", "local_mock_dev")`.
  - Added active login enforcement in `backend/app/api/v1/endpoints/auth.py` that rejects login attempts for `dev@xerova.com` in production environments with `HTTP 401 Unauthorized` and logs a dedicated `LOGIN_BLOCKED_DEV_SEED_IN_PRODUCTION` audit event.
  - Added token validation in `backend/app/core/auth.py` ensuring that even if an old token for `dev@xerova.com` is presented in production, it is permanently rejected.

---

### Finding 2: Rate Limiting Bypass via IP Header Spoofing (`X-Forwarded-For`)
- **Severity:** Medium
- **CWE:** CWE-290 (Authentication Bypass by Spoofing), CWE-307 (Improper Restriction of Excessive Authentication Attempts)
- **Description:**
  `AuthRateLimitMiddleware` extracted client IPs via `request.headers.get("X-Forwarded-For", "").split(",")[0].strip()`. Any untrusted client connecting directly to the API could supply arbitrary values in the `X-Forwarded-For` header (e.g., rotating `X-Forwarded-For: 198.51.100.X` on each request) to completely bypass the sliding window rate limiter on `/api/v1/auth/login` and `/api/v1/auth/register`.
- **Remediation:**
  - Implemented `get_client_ip(request)` in `backend/app/core/security.py`. Direct peer IP (`request.client.host`) is strictly evaluated against `settings.TRUSTED_PROXIES` (`127.0.0.1`, `::1`, `localhost`, etc.).
  - `X-Forwarded-For` and `X-Real-IP` headers are only inspected when the request originates from a confirmed trusted reverse proxy. Untrusted direct client spoofing is ignored.

---

### Finding 3: Targeted Credential Stuffing & Single-Account Brute Force
- **Severity:** Medium
- **CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)
- **Description:**
  Rate limiting was exclusively keyed by client IP (`f"{path}:{client_ip}"`). Attackers utilizing distributed proxies, botnets, or mobile IPs could execute brute-force dictionary attacks against a specific user account without triggering the IP-based rate limit.
- **Remediation:**
  - Added account-level sliding window rate limiting in `backend/app/api/v1/endpoints/auth.py`. The system limits failed authentication attempts per normalized email identifier (`f"auth_account:{normalized_email}"`) to 10 attempts per 60-second window.
  - Excessive attempts trigger `HTTP 429 Too Many Requests` with a `RATE_LIMIT_EXCEEDED` code and record an audit event (`LOGIN_RATE_LIMITED_ACCOUNT`).

---

### Finding 4: Account Enumeration via Bcrypt Execution Timing Discrepancy
- **Severity:** Low / Information Leakage
- **CWE:** CWE-208 (Observable Timing Discrepancy), CWE-204 (Observable Response Discrepancy)
- **Description:**
  In `POST /api/v1/auth/login`, line 93 evaluated `if not user or not verify_password(user_in.password, user.password_hash):`. Due to Python's boolean short-circuiting, when an email did not exist in the database, `verify_password` (which runs CPU-intensive 12-round bcrypt taking ~150-250ms) was skipped entirely. Non-existent accounts returned within 1-2ms, while existing accounts took ~200ms. An attacker could measure latency to enumerate valid user emails.
- **Remediation:**
  - Introduced `DUMMY_BCRYPT_HASH = "$2b$12$K1H1qS0rWd7E6zY0kQ2eDuYpZkZ6V9E4rI0E2f7Y5W4Q1A3V8K6e2"`.
  - When a requested user account does not exist, `verify_password(user_in.password, DUMMY_BCRYPT_HASH)` is executed, ensuring uniform execution time and eliminating the timing side-channel.

---

### Finding 5: Cross-Site Request Forgery (CSRF) on Cookie-Based Sessions
- **Severity:** Medium
- **CWE:** CWE-352 (Cross-Site Request Forgery)
- **Description:**
  Red Mercury supports dual-mode authentication: Bearer tokens via `Authorization` header and session tokens via HTTP-only cookie (`COOKIE_NAME="access_token"`). While `SameSite=Lax` prevents cross-site POST requests in modern browsers, legacy browsers, subdomain compromise, or top-level navigation states could allow state-modifying requests without origin verification.
- **Remediation:**
  - Implemented `verify_csrf_origin(request)` in `backend/app/core/auth.py`.
  - For all state-modifying HTTP methods (`POST`, `PUT`, `DELETE`, `PATCH`) authenticated via cookies, the request `Origin` or `Referer` header is strictly checked against `settings.CORS_ORIGINS` and the server's base URL.
  - Requests originating from untrusted third-party sites or missing origin headers on cookie-authenticated mutations are rejected with `HTTP 403 Forbidden` (`FORBIDDEN`).
  - Bearer tokens sent in the `Authorization` header are inherently immune to browser cross-site form submissions and remain unaffected.

---

### Finding 6: Missing Host Header Injection Defense in Production
- **Severity:** Low
- **CWE:** CWE-644 (Improper Neutralization of HTTP Headers for Scripting Syntax), CWE-20 (Improper Input Validation)
- **Description:**
  The FastAPI application lacked `TrustedHostMiddleware`, allowing arbitrary `Host` headers to be accepted unless strictly filtered by an upstream proxy. In containerized or direct deployments, this exposed the app to cache poisoning or password reset link manipulation.
- **Remediation:**
  - Added `ALLOWED_HOSTS` configuration in `backend/app/core/config.py` with strict production validation prohibiting wildcards (`*`).
  - Added `TrustedHostMiddleware` in `backend/app/main.py` when `settings.is_production` is enabled.

---

### Finding 7: Inconsistent Ownership Helpers & Incomplete Audit Logging Across Entities
- **Severity:** Medium
- **CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key / IDOR), CWE-778 (Insufficient Logging)
- **Description:**
  While repository and finding endpoints used centralized ownership helpers (`verify_repository_ownership` and `verify_finding_ownership`), other entities had fragmented checks:
  - Scans (`/api/v1/scans/{scan_id}`) manually duplicated ownership queries across 3 separate endpoints.
  - Verification runs (`/api/v1/verifications/{id}`) queried runs and then manually called `verify_finding_ownership`.
  - Evidence retrieval (`/api/v1/evidence/{evidence_id}`) raised `SecurityPolicyViolationError` instead of `ForbiddenError` and did not log blocked access audit events.
- **Remediation:**
  - Implemented centralized, uniform ownership verification functions in `backend/app/core/auth.py`:
    - `verify_repository_ownership(repo_id, current_user, db)`
    - `verify_finding_ownership(finding_id, current_user, db)`
    - `verify_scan_ownership(scan_id, current_user, db)`
    - `verify_verification_run_ownership(run_id, current_user, db)`
    - `verify_evidence_ownership(evidence_id, current_user, db)`
  - Standardized error responses to `HTTP 403 Forbidden` with unified code `"FORBIDDEN"`.
  - Guaranteed that all blocked unauthorized access attempts write an immutable audit log entry (`UNAUTHORIZED_*_ACCESS_BLOCKED`) containing the unauthorized `actor_id` and the targeted `resource_identifier`.

---

## 3. Comprehensive Multi-User Data Isolation Matrix

Every endpoint involving customer data was audited and verified for strict multi-user tenant isolation:

| Category | Endpoint | HTTP Method | Multi-User Access Control Mechanism | Unauthorized Attempt Result |
| :--- | :--- | :--- | :--- | :--- |
| **Auth** | `/api/v1/auth/me` | `GET` | Scoped strictly to authenticated token subject (`sub`). | `401 Unauthorized` |
| **Repositories** | `/api/v1/repositories` | `GET` | Filtered strictly by `Repository.owner_id == current_user.id`. | Other users' repos excluded |
| **Repositories** | `/api/v1/repositories` | `POST` | Assigns `owner_id = current_user.id`. | Isolated to creator |
| **Repositories** | `/api/v1/repositories/ingest/upload` | `POST` | Assigns `owner_id = current_user.id`; workspace isolated under user directory. | Isolated to creator |
| **Repositories** | `/api/v1/repositories/ingest/git` | `POST` | Assigns `owner_id = current_user.id`; SSRF defense active. | Isolated to creator |
| **Repositories** | `/api/v1/repositories/{id}` | `GET` | `verify_repository_ownership` checks `owner_id == current_user.id`. | `403 Forbidden` |
| **Repositories** | `/api/v1/repositories/{id}/ingestion-status` | `GET` | `verify_repository_ownership` checks `owner_id == current_user.id`. | `403 Forbidden` |
| **Repositories** | `/api/v1/repositories/{id}` | `DELETE` | `verify_repository_ownership` checks `owner_id == current_user.id`. | `403 Forbidden` |
| **Findings** | `/api/v1/findings` | `GET` | Joined with `Repository` where `Repository.owner_id == current_user.id`. | Other users' findings excluded |
| **Findings** | `/api/v1/findings` | `POST` | `verify_repository_ownership` on target `repo_id`. | `403 Forbidden` |
| **Findings** | `/api/v1/findings/remediation-queue` | `GET` | Filtered by `Repository.owner_id == current_user.id`. | Other users' items excluded |
| **Findings** | `/api/v1/findings/{id}` | `GET` | `verify_finding_ownership` verifies repository owner matches user. | `403 Forbidden` |
| **Findings** | `/api/v1/findings/{id}/prioritization` | `GET` | `verify_finding_ownership` verifies repository owner matches user. | `403 Forbidden` |
| **Findings** | `/api/v1/findings/{id}/prioritize` | `POST` | `verify_finding_ownership` verifies repository owner matches user. | `403 Forbidden` |
| **Validation** | `/api/v1/findings/{id}/validate` | `POST` | `verify_finding_ownership` verifies repository owner matches user. | `403 Forbidden` |
| **Validation** | `/api/v1/findings/{id}/validation` | `GET` | `verify_finding_ownership` verifies repository owner matches user. | `403 Forbidden` |
| **Validation** | `/api/v1/findings/{id}/validations` | `GET` | `verify_finding_ownership` verifies repository owner matches user. | `403 Forbidden` |
| **Scans** | `/api/v1/scans` | `GET` | Joined with `Repository` where `Repository.owner_id == current_user.id`. | Other users' scans excluded |
| **Scans** | `/api/v1/scans` | `POST` | `verify_repository_ownership` on target `repository_id`. | `403 Forbidden` |
| **Scans** | `/api/v1/scans/{id}` | `GET` | `verify_scan_ownership` verifies scan belongs to user-owned repo. | `403 Forbidden` |
| **Scans** | `/api/v1/scans/{id}/status` | `GET` | `verify_scan_ownership` verifies scan belongs to user-owned repo. | `403 Forbidden` |
| **Scans** | `/api/v1/scans/{id}/results` | `GET` | `verify_scan_ownership` verifies scan belongs to user-owned repo. | `403 Forbidden` |
| **AI Analyst** | `/api/v1/analyze-finding` | `POST` | If `finding_id` exists, `verify_finding_ownership` enforces tenant access. | `403 Forbidden` |
| **AI Analyst** | `/api/v1/findings/{id}/analyses` | `GET` | `verify_finding_ownership` verifies repository owner matches user. | `403 Forbidden` |
| **Verifications**| `/api/v1/verifications` | `GET` | Joined with `Repository` where `Repository.owner_id == current_user.id`. | Other users' runs excluded |
| **Verifications**| `/api/v1/verifications` | `POST` | `verify_finding_ownership` on target `finding_id`. | `403 Forbidden` |
| **Verifications**| `/api/v1/verifications/{id}` | `GET` | `verify_verification_run_ownership` verifies finding and repo ownership. | `403 Forbidden` |
| **Verifications**| `/api/v1/verifications/{id}/rerun`| `POST` | `verify_verification_run_ownership` verifies finding and repo ownership. | `403 Forbidden` |
| **Verifications**| `/api/v1/verifications/{id}/approve-and-merge` | `POST` | `verify_verification_run_ownership` verifies finding and repo ownership. | `403 Forbidden` |
| **Evidence** | `/api/v1/evidence` | `GET` | `verify_repository_ownership` on query `repo_id`. | `403 Forbidden` |
| **Evidence** | `/api/v1/evidence` | `POST` | `verify_repository_ownership` on body `repository_id`. | `403 Forbidden` |
| **Evidence** | `/api/v1/evidence/{id}` | `GET` | `verify_evidence_ownership` verifies evidence repo owner matches user. | `403 Forbidden` |
| **Evidence** | `/api/v1/evidence/{id}/verify-integrity` | `GET` | `verify_evidence_ownership` verifies evidence repo owner matches user. | `403 Forbidden` |
| **Reports** | `/api/v1/evidence/reports/findings` | `GET` | `verify_repository_ownership` on query `repo_id`. | `403 Forbidden` |
| **Reports** | `/api/v1/evidence/reports/findings/download` | `GET` | `verify_repository_ownership` on query `repo_id`. | `403 Forbidden` |
| **Reports** | `/api/v1/evidence/reports/verification/{id}` | `GET` | `verify_verification_run_ownership` on `verification_run_id`. | `403 Forbidden` |
| **Reports** | `/api/v1/evidence/reports/verification/{id}/download` | `GET` | `verify_verification_run_ownership` on `verification_run_id`. | `403 Forbidden` |
| **Reports** | `/api/v1/evidence/verification-runs/{id}/verify-integrity` | `GET` | `verify_verification_run_ownership` on `verification_run_id`. | `403 Forbidden` |
| **GitHub** | `/api/v1/integrations/github/installations` | `GET`/`POST` | Scoped strictly to `current_user.id`. | `404 Not Found` for other users' IDs |
| **GitHub** | `/api/v1/integrations/github/repositories/link` | `POST` | Verifies repository ownership and installation ownership. | `403 Forbidden` |
| **GitHub** | `/api/v1/integrations/github/pr-scans/{id}` | `GET` | `verify_repository_ownership` on PR scan repository. | `403 Forbidden` |
| **GitHub** | `/api/v1/integrations/github/pr-scans/{id}/publish` | `POST` | `verify_repository_ownership` on PR scan repository. | `403 Forbidden` |
| **CI Gate** | `/api/v1/integrations/ci/evaluate` | `POST` | `verify_repository_ownership` on target `repository_id`. | `403 Forbidden` |

---

## 4. Information Leakage & Error Hygiene Verification

When unauthorized access is attempted, failed authorization responses were audited for information disclosure:

1. **Standardized Error Envelope:**
   Failed requests return unified error payloads:
   ```json
   {
     "success": false,
     "error": {
       "code": "FORBIDDEN",
       "message": "You do not have permission to access this resource.",
       "details": []
     },
     "request_id": "...",
     "timestamp": "..."
   }
   ```
2. **Zero Resource Data Leakage:**
   - Error messages **never** disclose repository names, owner email addresses, filesystem workspace paths, code excerpts, line numbers, or scanner rule IDs.
   - Cross-user ID modification tests confirmed that unauthenticated or unauthorized responses do not echo confidential data back to the caller.
3. **Audit Trail Accountability:**
   - Blocked authorization events are logged to the database `audit_events` table with:
     - `actor_id`: The unauthorized user attempting access.
     - `action`: Specific blocked action (`UNAUTHORIZED_REPO_ACCESS_BLOCKED`, `UNAUTHORIZED_FINDING_ACCESS_BLOCKED`, etc.).
     - `resource_identifier`: The target entity ID.
     - `resource_type`: The resource classification (`repository`, `finding`, `scan`, `verification_run`, `evidence`).

---

## 5. Automated Verification & Test Results

The hardening fixes were verified using two separate user accounts (`user_a` / `client_a` and `user_b` / `client_b`) across multiple dedicated test suites.

### Summary of Executed Test Suites:

| Suite Name | Scope | Tests Run | Result |
| :--- | :--- | :--- | :--- |
| `tests/test_auth_security_hardening.py` | Dev seed blocking, IP rate limit spoofing defense, account rate limiting, login timing attack mitigation, CSRF origin checks, cross-user IDOR access denial, sensitive info leakage defense, audit logging. | 17 | **17 PASSED** |
| `tests/test_auth.py` | Password hashing, token creation, session expiration, cookie attributes, invalid credentials, suspended accounts, logout. | 10 | **10 PASSED** |
| `tests/test_auth_and_authorization.py` | Unauthenticated 401 checks across 12 endpoints, token tampering, secret key validation, rate limiting, production config safety, webhook signatures. | 29 | **29 PASSED** |
| `tests/test_authorization.py` | Cross-tenant repository, finding, and scan isolation and deletion safety. | 4 | **4 PASSED** |
| **Total Authentication & Isolation Suite** | Full End-to-End Auth & Isolation | **60** | **60 PASSED (100%)** |
| **Frontend Vitest Suite** | Route guards, auth context, login/register forms, settings screens, API client token storage | 29 | **29 PASSED (100%)** |

---

## 6. Remaining Risks & Architectural Recommendations

While Red Mercury's authentication and authorization layer is now hardened against critical vulnerabilities, the following architectural considerations and future enhancements are documented:

1. **Stateless JWT Token Revocation:**
   - *Current State:* JWT access tokens are signed using `HS256` with a configured expiration (`settings.ACCESS_TOKEN_EXPIRE_MINUTES`). On logout, session cookies are deleted, but bearer tokens stored in client memory remain cryptographically valid until expiration.
   - *Recommendation:* Implement a distributed token revocation blocklist using Redis (storing `jti` claim on logout) or migrate to short-lived access tokens (15 minutes) paired with rotating refresh tokens stored in HTTP-only cookies.

2. **Distributed Rate Limiting:**
   - *Current State:* `InMemoryRateLimiter` uses in-process sliding windows protected by a thread lock. This provides protection for single-instance or sticky-session deployments.
   - *Recommendation:* In multi-pod containerized production deployments behind a cloud load balancer, integrate Redis-backed rate limiting (using token bucket or sliding-window log) to ensure rate limits are enforced cluster-wide.

3. **Multi-Factor Authentication (MFA / TOTP):**
   - *Current State:* Authentication relies on email and high-entropy passwords (bcrypt rounds 12).
   - *Recommendation:* Add RFC 6238 TOTP-based two-factor authentication for sensitive operator actions (e.g., repository deletion, GitHub integration credential access).

4. **Multi-User Team & Organization Access (RBAC):**
   - *Current State:* Data isolation is strictly 1:1 between individual user accounts (`owner_id == current_user.id`).
   - *Recommendation:* When introducing collaborative enterprise accounts, implement an `Organization` and `OrganizationMembership` schema supporting role-based access control (Admin, Security Engineer, Developer, Read-Only Auditor) while maintaining strict tenant boundary separation between distinct organizations.
