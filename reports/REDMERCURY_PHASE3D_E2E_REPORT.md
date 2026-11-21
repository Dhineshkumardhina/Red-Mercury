# Red Mercury — Phase 3D End-to-End User Journey & API Integration Report

**Date:** October 29, 2026  
**Auditor:** Antigravity Autonomous Security Engineer  
**Scope:** Full-Workflow User Journeys, Frontend Component & Integration Suites, API Client Interception, Multi-Tenant Security Boundaries, Fault Injection & Edge-Case States  
**Status:** Validated & Hardened  

---

## 1. Executive Summary & Testing Philosophy

Phase 3D subjected **Red Mercury** to comprehensive validation of the end-to-end user experience, tracing real operator actions from initial authentication, repository onboarding, and automated static vulnerability scanning through finding triage, fix verification, and compliance report export.

To provide genuine confidence without false assurances, testing was conducted across a dual-tier architecture:
1. **Real-Service Backend Integration Journey (`tests/test_e2e_user_journey.py`):**
   - Executed against the live FastAPI application runtime and isolated SQLite database without mocking application business logic, authorization middleware, password hashing (`bcrypt`), JWT token generation, or operational rate limiting.
   - Verified that all mutating actions enforce role-based boundaries (`analyst` vs `viewer`), prevent duplicate concurrent scans (`409 Conflict`), and enforce strict multi-tenant tenant isolation between separate accounts (User A vs User B).
2. **DOM-Level Frontend Journey & Resilience Suite (`frontend/src/__tests__/UserJourney.test.tsx`):**
   - Executed using Vitest, React Testing Library, and jsdom covering genuine React 19 component trees, React Router DOM v7 navigation, and global authentication context state.
   - Verified realistic user workflows: login rejection, dashboard KPI card rendering, scan initiation, polling progress states, finding detail inspection, fix verification review, and SARIF report generation.
3. **Browser Automation Assessment:**
   - Evaluated host browser availability (Google Chrome 122+ and Microsoft Edge installed on Windows host).
   - Documented the absence of a pre-configured headless browser driver (e.g. `@playwright/test`); external network package installation was evaluated in dry-run mode and omitted from the default offline pipeline to avoid unpinned network hangs.
   - In accordance with audit rules, this report clearly differentiates between live API integration tests, jsdom component-tree journeys, and simulated browser headless runs, without claiming complete native browser automation where simulated jsdom environments were employed.

---

## 2. User Journeys Tested

| Journey ID | Workflow Name | Operational Steps | Verification Method | Outcome |
| :--- | :--- | :--- | :--- | :--- |
| **UJ-01** | **Authentication & Session Lifecycle** | • Enter invalid password → receive `401 Unauthorized`.<br>• Enter valid credentials → receive Bearer token.<br>• Fetch authenticated profile via `/api/v1/auth/me`.<br>• Terminate session via `/api/v1/auth/logout`.<br>• Attempt subsequent access with revoked token → rejected (`401`). | Live FastAPI + TestClient & Vitest DOM | **PASSED** |
| **UJ-02** | **Repository Ingestion & Inventory** | • Access empty repository dashboard.<br>• Register authorized repository via `POST /api/v1/repositories`.<br>• Verify repository metadata, health score, and branch.<br>• Confirm repository appears in user inventory. | Live FastAPI + TestClient & Vitest DOM | **PASSED** |
| **UJ-03** | **Security Scan Execution & Progress** | • Open AppSec scan modal.<br>• Select target repository and SAST/Secret tools.<br>• Dispatch scan request (`POST /api/v1/scans` → `202 Accepted`).<br>• Poll scan progress through queued/running states until complete.<br>• Update repository health score and severity counters. | Live FastAPI + TestClient & Vitest DOM | **PASSED** |
| **UJ-04** | **Vulnerability & Finding Review** | • Query finding inventory filtered by repository.<br>• Validate severity badges (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).<br>• Open detailed finding view (`/findings/:id`).<br>• Verify code excerpt, CWE identifier, file path, and line numbers.<br>• Inspect associated cryptographic evidence payloads. | Live FastAPI + TestClient & Vitest DOM | **PASSED** |
| **UJ-05** | **Fix Verification Engine Workflow** | • Submit unified diff patch via `POST /api/v1/verifications`.<br>• Execute 5-step fix verification pipeline against isolated workspace.<br>• Verify status transitions (`VERIFIED_AGAINST_DEFINED_CHECKS` or `FAILED_VERIFICATION`).<br>• Inspect baseline vs patched hashes and test execution summaries. | Live FastAPI + TestClient & Vitest DOM | **PASSED** |
| **UJ-06** | **Compliance Artifact Generation & Export** | • Open compliance export interface.<br>• Request standardized SARIF 2.1.0 and JSON reports.<br>• Confirm `Content-Disposition: attachment` headers on download.<br>• Verify audit trail record logged in database. | Live FastAPI + TestClient & Vitest DOM | **PASSED** |
| **UJ-07** | **Multi-Tenant Cross-User Isolation** | • User A (Alice) provisions repository, scan, and findings.<br>• User B (Bob) attempts direct access to Alice's repository, scan, findings, and reports.<br>• System returns `403 Forbidden` or `404 Not Found`, preventing cross-tenant leakage. | Live FastAPI + TestClient | **PASSED** |
| **UJ-08** | **RBAC Least-Privilege Enforcement** | • User with `viewer` role attempts to create a repository, start a scan, or rerun a verification.<br>• Request aborted with `403 Forbidden` (`FORBIDDEN`). | Live FastAPI + TestClient | **PASSED** |
| **UJ-09** | **Operational Failure Resilience** | • Trigger duplicate concurrent scan on active repository → `409 Conflict` (`SCAN_ALREADY_IN_PROGRESS`).<br>• Exceed per-minute operation threshold → `429 Too Many Requests` with `Retry-After`.<br>• Scanner process failure → marks scan `failed`; never fabricates success. | Live FastAPI + TestClient & Vitest DOM | **PASSED** |

---

## 3. Browser & Environment Details

| Component | Specification / Environment Configuration |
| :--- | :--- |
| **Host Operating System** | Windows 11 (win32, x64) |
| **Backend Runtime** | Python 3.14.7, FastAPI 0.142.2, SQLAlchemy 2.1.3, SQLite 3 (isolated test DB) |
| **Frontend Framework** | React 19.0.0, Vite 6.4.4, React Router DOM 7.2.0, Tailwind CSS 4.0.9 |
| **DOM Testing Engine** | Vitest 3.2.7 with `jsdom` 26.0.0 and `@testing-library/react` 16.2.0 |
| **Host System Browsers** | • Google Chrome (`C:\Program Files\Google\Chrome\Application\chrome.exe`)<br>• Microsoft Edge (`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`) |
| **E2E Tooling Evaluation** | Evaluated `@playwright/test`; not included in initial package dependencies. Native browser binary downloads were intentionally omitted to maintain deterministic offline execution. Full DOM events, routing transitions, and API interception were comprehensively driven via React Testing Library + Vitest. |

---

## 4. API Endpoint Integration Results

The following endpoints were directly executed and verified during the end-to-end user journeys:

| HTTP Method | Route | Auth / Role Constraint | Observed Status | Behavior & Result |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/auth/login` | Public | `200 OK` / `401 Unauthorized` | Issues valid JWT access token on valid credentials; rejects bad passwords with `UNAUTHORIZED`. |
| `GET` | `/api/v1/auth/me` | Authenticated | `200 OK` / `401 Unauthorized` | Returns active user profile; rejects revoked/expired tokens with `SESSION_EXPIRED` or `UNAUTHORIZED`. |
| `POST` | `/api/v1/auth/logout` | Authenticated | `200 OK` | Blocklists the JWT token; subsequent requests fail immediately. |
| `GET` | `/api/v1/repositories` | Authenticated | `200 OK` | Returns strictly the repositories owned by the requesting user. |
| `POST` | `/api/v1/repositories` | `require_mutating_role` | `201 Created` / `403 Forbidden` | Allows analysts to create repositories; blocks viewers/auditors with 403. |
| `GET` | `/api/v1/repositories/{id}` | Authenticated | `200 OK` / `403/404` | Returns repository details for owner; returns 403/404 for cross-tenant access. |
| `POST` | `/api/v1/scans` | `require_mutating_role` | `202 Accepted` / `409 Conflict` | Starts background scan; returns 409 if a scan is already running on the repository. |
| `GET` | `/api/v1/scans/{id}` | Authenticated | `200 OK` | Returns real-time status (`queued`, `running`, `completed`, `failed`). |
| `GET` | `/api/v1/findings` | Authenticated | `200 OK` | Lists detected security findings with severity, CWE, scanner name, and file path. |
| `GET` | `/api/v1/findings/{id}` | Authenticated | `200 OK` | Returns granular finding details, line numbers, and confidence score. |
| `GET` | `/api/v1/evidence/{id}` | Authenticated | `200 OK` | Retrieves tamper-evident cryptographic evidence associated with finding. |
| `POST` | `/api/v1/verifications` | `require_mutating_role` | `200 OK` / `422 Unprocessable` | Executes patch parser and sandbox test verification pipeline on proposed patch. |
| `GET` | `/api/v1/verifications/{id}` | Authenticated | `200 OK` | Returns status (`VERIFIED_AGAINST_DEFINED_CHECKS`), reasons, and test summary. |
| `GET` | `/api/v1/evidence/reports/findings` | Authenticated | `200 OK` | Generates structured findings report formatted in SARIF 2.1.0 or JSON. |
| `GET` | `/api/v1/evidence/reports/findings/download` | Authenticated | `200 OK` | Returns file stream with `Content-Disposition: attachment; filename=...`. |

---

## 5. Screens and Routes Covered

| Route Path | Screen / View Component | Verification Highlights |
| :--- | :--- | :--- |
| `/login` | `LoginPage` | Verified 1-click test environment launch, credential validation, error message rendering on invalid input, and redirect to dashboard upon successful authentication. |
| `/register` | `RegisterPage` | Verified organization registration input fields, password length requirements, and workspace initialization. |
| `/landing` | `LandingPage` | Verified public marketing layout, quick-launch buttons, and navigation into the authentication console. |
| `/dashboard` | `DashboardPage` & `DashboardScreen` | Verified live KPI metrics, active repository cards, recent findings listing, scan execution trigger modal, and compliance export modal. |
| `/repositories` | `RepositoriesPage` | Verified inventory list, health score badges, search/filter inputs, and ingestion modal. |
| `/findings` | `FindingsPage` | Verified finding list, severity color coding, CWE filters, and direct navigation to detailed finding view. |
| `/findings/:id` | `FindingDetailPage` | Verified vulnerability breadcrumbs, code excerpt, AI Security Analyst card, contextual risk prioritization, and evidence review section. |
| `/verification` | `VerificationPage` & `FixVerificationScreen` | Verified verification run status badges, baseline vs patched git hashes, test regression summaries, and diff inspector modal. |
| `/evidence` | `EvidencePage` & `EvidenceCenterScreen` | Verified cryptographic evidence items, SHA-256 content hashes, and audit trail records. |
| `/settings` | `SettingsPage` | Verified security gate thresholds, AST taint verification toggles, and zero-secrets policy controls. |
| `/analyzer` | `AiSecurityAnalyzerScreen` | Verified AI security analysis workspace, interactive prompt simulation, and redaction safeguards. |

---

## 6. Failures Discovered and Fixed During Phase 3D

1. **Defensive Coercion in `PrioritizedRemediationQueueCard.tsx`:**
   - *Issue:* When `api.getRemediationQueue()` returned unexpected non-array data, `allItems.filter(...)` threw an unhandled `TypeError: allItems.filter is not a function`, crashing the dashboard.
   - *Fix:* Added defensive array coercion:
     ```tsx
     api.getRemediationQueue()
       .then(items => {
         setAllItems(Array.isArray(items) ? items : []);
         setError(null);
       })
     ```
2. **Missing Category Crash in `ScanModal.tsx`:**
   - *Issue:* At line 254, `tool.category.toLowerCase()` assumed every scanner tool object contains a populated `category` string. If a custom or third-party scanner lacked a category, it triggered an unhandled `TypeError: Cannot read properties of undefined (reading 'toLowerCase')`.
   - *Fix:* Implemented safe optional navigation:
     ```tsx
     const cat = tool.category ? tool.category.toLowerCase() : '';
     ```
3. **Scan Polling Interval Test Configuration:**
   - *Issue:* `ScanModal.tsx` hardcoded a static `1500ms` polling delay, creating asynchronous test flakiness and timeout failures during rapid automated validation.
   - *Fix:* Enabled configurable test polling:
     ```tsx
     const pollIntervalMs = (typeof window !== 'undefined' && (window as any).__SCAN_POLL_INTERVAL__) || 1500;
     ```
4. **Scan Failure Transparency (No Fabricated Success):**
   - *Issue:* Verified that when a scan triggers an error (e.g. missing repository workspace), the UI displays the exact server error message (`Repository workspace path is not set or inaccessible`) and never renders a false "Scan Completed" state.

---

## 7. Actual Test Counts

### Frontend Test Suite (Vitest + jsdom + React Testing Library)
- **`src/__tests__/UserJourney.test.tsx`:** 6 passed (100%)
- **`src/__tests__/App.test.tsx`:** 11 passed (100%)
- **`src/__tests__/Verification.test.tsx`:** 7 passed (100%)
- **`src/__tests__/AiAnalyst.test.tsx`:** 8 passed (100%)
- **`src/__tests__/EvidenceAndPrioritization.test.tsx`:** 3 passed (100%)
- **Total Frontend Tests:** **35 passed across 5 test suites (0 failures)**
- **Type Checking (`tsc --noEmit`):** Clean (0 errors)
- **Production Build (`vite build`):** Built in 3.40s with 0 errors

### Backend Test Suite (Pytest + FastAPI TestClient + SQLite)
- **`tests/test_e2e_user_journey.py`:** 8 passed (100%)
- **`tests/test_api_reliability_and_resilience.py`:** 14 passed (100%)
- **Full Backend Regression Suite:** **402 passed, 19 skipped (0 failures)** in 293.85s

### Tests Skipped and Reasons
- **19 Skipped Tests in Backend:**
  - `tests/test_live_docker_security_runtime.py` (13 tests): Skipped because a live, privileged Docker daemon with cgroups v2 is not active in this development environment.
  - `tests/test_postgresql_integration.py` (3 tests): Skipped because a dedicated live PostgreSQL instance was not configured in `TEST_DATABASE_URL` for local SQLite runs.
  - `tests/test_sandbox.py` (2 tests) & `tests/test_verification_security_hardening.py` (1 test): Skipped because optional Docker container runtimes were unavailable, falling back cleanly to host-isolated execution.

---

## 8. Remaining Untested Workflows & Recommendations

While the full user journey from login to report generation has been thoroughly validated through real API integration and comprehensive DOM component testing, the following operational areas should be prioritized for future phases:

1. **Native Headless Browser Automation (Playwright / Cypress):**
   - In a CI/CD environment with internet access, configure `@playwright/test` to run against packaged Chrome/Edge binaries for visual regression, screenshot comparison, and cross-browser CSS rendering.
2. **Live OAuth Roundtrips for GitHub App:**
   - Real GitHub OAuth code-exchange flows require live callback redirects and registered GitHub App client secrets. These were validated using simulated cryptographic signatures and API token mocks.
3. **Large File Streaming Over WebSocket:**
   - Real-time scanner log streaming currently relies on HTTP polling (`/api/v1/scans/{id}`). Transitioning to WebSocket/SSE for live sub-second stdout streaming under high concurrency should be benchmarked under simulated network throttling.

---

## 9. Conclusion

Red Mercury has successfully satisfied all Phase 3D requirements:
- The complete end-to-end user journey (Login → Dashboard → Repo Onboarding → Scan Execution → Finding Review → Fix Verification → Report Export → Logout) operates seamlessly across both backend API contracts and frontend UI components.
- Mutating endpoints, multi-tenant boundaries, and rate limits strictly repel unauthorized and cross-user actions.
- Partial failures, scanner crashes, and validation errors are transparently presented to the operator without fabricated results or suppressed errors.
