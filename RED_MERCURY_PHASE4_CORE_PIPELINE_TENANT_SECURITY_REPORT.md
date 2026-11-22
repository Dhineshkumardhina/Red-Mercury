# RED MERCURY — PHASE 4: CORE PIPELINE CORRECTNESS, GITHUB WEBHOOK SECURITY & CROSS-TENANT ISOLATION REPORT

**Date:** 2026-11-21  
**Repository:** `https://github.com/Dhineshkumardhina/Red-Mercury`  
**Audited Branch / HEAD Commit:** `main` @ `b9df7b9`  
**Reference Reports:**  
- [RED_MERCURY_PHASE0_COMPLETE_REPOSITORY_AUDIT.md](RED_MERCURY_PHASE0_COMPLETE_REPOSITORY_AUDIT.md)  
- [RED_MERCURY_PHASE1_SECURITY_REMEDIATION_REPORT.md](RED_MERCURY_PHASE1_SECURITY_REMEDIATION_REPORT.md)  
- [RED_MERCURY_PHASE2_INGESTION_SSRF_SECURITY_REPORT.md](RED_MERCURY_PHASE2_INGESTION_SSRF_SECURITY_REPORT.md)  
- [RED_MERCURY_PHASE3_AUTH_SESSION_SECURITY_REPORT.md](RED_MERCURY_PHASE3_AUTH_SESSION_SECURITY_REPORT.md)  
**Final Engineering Decision:** **CONDITIONALLY ACCEPTED**

---

## 1. Executive Summary

Phase 4 remediated the three target findings across Red Mercury's GitHub webhook authentication pipeline (`SEC-12`), multi-tenant foreign-key isolation boundaries (`SEC-14`), and core pipeline correctness defects (`REL-02`: `NormalizedFinding` snapshot serialization, Gemini AI validation assistant REST integration, GitHub `Path` import and workspace confinement, and genuine OASIS SARIF 2.1.0 findings export) while preserving every security control introduced in Phases 1, 2, and 3.

### Verification Summary
- **Backend (`pytest`):** **555 collected, 535 passed, 0 failed, 20 environment-skipped** (+8 comprehensive multi-scenario Phase 4 test suites in `tests/test_phase4_core_pipeline_tenant_security.py`).
- **Alembic Migration Consistency:** **3/3 passed** (`0001` → `0013` linear chain, zero SQLAlchemy metadata divergence).
- **Frontend (`vitest`):** **7 test files, 46 passed, 0 failed** (7.15s).
- **Frontend TypeScript (`tsc --noEmit`):** **Passed (0 errors)**.
- **Electron (`node --test electron/security.test.cjs`):** **10 passed, 0 failed** (132ms).
- **Docker Compose Config (`docker compose -f docker-compose.prod.yml config -q`):** **Passed (exit 0)**.

---

## 2. Original Findings & Root Causes

| Finding ID | Severity | Original Defect | Root Cause |
| :--- | :--- | :--- | :--- |
| **SEC-12** | **HIGH** | Pre-auth webhook replay poisoning (`WebhookDelivery` committed *before* HMAC-SHA256 verification); per-installation `webhook_secret` hashed into `webhook_secret_hash` but omitted from `encrypted_credentials` (causing decryption to return `None` and fall back to global secret); no concurrent duplicate delivery protection or secret-rotation grace window | `record_and_check_replay()` invoked at top of `handle_incoming_webhook()` prior to signature verification; `register_github_installation()` excluded `webhook_secret` from `cred_dict` |
| **SEC-14** | **MEDIUM** | Cross-tenant and cross-repository foreign-key injection on `POST /api/v1/findings` (`scan_id`), `POST /api/v1/evidence` (`scan_id`, `finding_id`, `verification_run_id`), `POST /api/v1/analyze-finding`, and service-layer `record_security_evidence()` / `execute_fix_verification()` | Endpoints validated primary `repo_id`/`repository_id` ownership but omitted ownership and repository-membership checks on optional foreign-key fields |
| **REL-02 (a)** | **HIGH** | `verification/service.py` serialized `baseline_findings` and `patched_findings` using nonexistent `NormalizedFinding` attributes (`rule_id`, `line_number`, `message`), persisting blank values in `findings_before_patch` and `findings_after_patch` | Mismatch between `NormalizedFinding` dataclass field names (`scanner_rule_id`, `start_line`, `scanner_message`) and snapshot dict comprehension |
| **REL-02 (b)** | **HIGH** | `validation/ai_assistant.py` called nonexistent `gemini_analyst_client.is_enabled()`, `.client.models.generate_content()`, and `.model_name`, always throwing `AttributeError` and silently substituting a simulated deterministic result while `validation/service.py` marked `ai_assisted=True` | Written against a hypothetical Google GenAI SDK object rather than Red Mercury's `httpx`-based `GeminiAnalystClient` REST interface |
| **REL-02 (c)** | **HIGH** | `integrations/github/service.py:243` referenced `Path(repo.workspace_path)` without importing `Path` (`NameError`) and enumerated workspace files without verifying `WORKSPACE_ROOT` confinement or skipping symlinks | Missing `from pathlib import Path` import and missing workspace containment check |
| **REL-02 (d)** | **HIGH** | `generate_findings_report(format="sarif")` and `/reports/findings/download?format=sarif` lacked a `SARIF` branch and silently returned Markdown with `.md` / `text/markdown` headers | Only `ReportExportFormat.JSON` and `else:` (Markdown) were implemented in `generate_findings_report()` and `download_findings_report()` |

---

## 3. Actual Repository Baseline & HEAD Commit

- **Branch:** `main` (tracking `origin/main`)
- **HEAD Commit:** `b9df7b9` (`fix(alembic): widen alembic_version.version_num to VARCHAR(128) on PostgreSQL`)
- **Uncommitted Work:** All Phase 1, Phase 2, and Phase 3 uncommitted modifications and reports preserved intact; `.env` files untouched; no commits or pushes performed.

---

## 4. Files Inspected

- `backend/app/integrations/github/service.py`, `backend/app/integrations/github/webhook.py`, `backend/app/integrations/github/crypto.py`, `backend/app/integrations/github/schemas.py`, `backend/app/models/github.py`, `backend/app/api/v1/endpoints/integrations.py`
- `backend/app/core/auth.py`, `backend/app/api/v1/endpoints/findings.py`, `backend/app/api/v1/endpoints/evidence.py`, `backend/app/api/v1/endpoints/verification.py`, `backend/app/api/v1/endpoints/scans.py`, `backend/app/api/v1/endpoints/analyzer.py`
- `backend/app/verification/service.py`, `backend/app/scanner/base.py`
- `backend/app/validation/ai_assistant.py`, `backend/app/validation/service.py`, `backend/app/validation/collector.py`, `backend/app/analyzer/client.py`
- `backend/app/evidence/service.py`
- `tests/test_github_integration.py`, `tests/test_vulnerability_validation.py`, `tests/test_auth_and_authorization.py`, `tests/test_evidence_management.py`, `tests/test_migration_consistency.py`

---

## 5. Files Modified

- `backend/app/integrations/github/webhook.py` — Enforced 64-hex SHA-256 format check + constant-time `hmac.compare_digest`; added `claim_webhook_delivery()` (atomic `IntegrityError`-safe insert with `status="processing"` and authenticated retry from `status="failed"`) and `finalize_webhook_delivery()`.
- `backend/app/integrations/github/service.py` — Imported `Path` and `get_workspace_root`; encrypted `webhook_secret` (and rotated `previous_webhook_secret`) inside `encrypted_credentials`; enforced strict per-installation secret isolation and pre-persistence HMAC verification in `handle_incoming_webhook()`; enforced workspace confinement and symlink skipping in `trigger_pr_security_scan()`.
- `backend/app/core/auth.py` — Added `verify_scan_belongs_to_repository()`, `verify_finding_belongs_to_repository()`, and `verify_verification_run_belongs_to_repository()`.
- `backend/app/api/v1/endpoints/findings.py` — Enforced `verify_scan_belongs_to_repository()` on `POST /api/v1/findings`.
- `backend/app/api/v1/endpoints/evidence.py` — Enforced `verify_scan_belongs_to_repository()`, `verify_finding_belongs_to_repository()`, and `verify_verification_run_belongs_to_repository()` on `POST /api/v1/evidence`; added `ReportExportFormat.SARIF` media type (`application/sarif+json; charset=utf-8`), `.sarif` extension, and sanitized `Content-Disposition` filename in `download_findings_report()`.
- `backend/app/api/v1/endpoints/analyzer.py` — Added cross-repository mismatch check when both `finding_id` and `repo_id` are supplied to `POST /api/v1/analyze-finding`.
- `backend/app/verification/service.py` — Added `_serialize_normalized_finding_snapshot()` mapping authoritative `NormalizedFinding` fields (`finding_id`, `scan_id`, `scanner_name`, `scanner_rule_id`/`rule_id`, `vulnerability_category`, `cwe`, `severity`, `confidence`, `file_path`, `start_line`/`line_number`, `end_line`, `scanner_message`/`message`, `evidence_reference`, `metadata`); added service-layer tenant ownership guard in `execute_fix_verification()`.
- `backend/app/analyzer/client.py` — Added `GeminiAssistantUnavailableError` (`503 AI_ASSISTANT_UNAVAILABLE`), `_scrub_api_key()`, and `GeminiAnalystClient.generate_structured_json()`.
- `backend/app/validation/ai_assistant.py` — Rewired `invoke_validation_ai_assistant()` to use `GeminiAnalystClient.generate_structured_json()`, added outbound secret redaction and case-insensitive XML delimiter tag escaping (`_sanitize_and_escape_untrusted_block`), scanned untrusted metadata for prompt injection, enforced strict `ValidationAiSchema` enum validators, and eliminated silent fabrication on Gemini failure/unavailability.
- `backend/app/validation/service.py` — Prevented `validate_finding_service()` from marking `ai_assisted=True` when short-circuited by prompt-injection or incomplete-dossier guards.
- `backend/app/evidence/service.py` — Added service-layer FK repository-membership checks in `record_security_evidence()` and implemented `_generate_sarif_findings_report()` + `ReportExportFormat.SARIF` branch in `generate_findings_report()`.

---

## 6. Files Created

- `tests/test_phase4_core_pipeline_tenant_security.py` — Phase 4 regression test suite covering Tasks 1–7.
- `RED_MERCURY_PHASE4_CORE_PIPELINE_TENANT_SECURITY_REPORT.md` — This report.

---

## 7. GitHub Webhook Remediation (`SEC-12`)

1. **Pre-Persistence HMAC Verification:** `handle_incoming_webhook()` validates `X-GitHub-Delivery` and `X-Hub-Signature-256` (`sha256=<64-hex>`) and verifies the HMAC-SHA256 digest over raw request bytes using `hmac.compare_digest` **before** any row is written to `webhook_deliveries`. Unauthenticated callers can no longer pre-burn delivery IDs or bloat the database.
2. **Installation-Specific Secret Isolation & Rotation:** `register_github_installation()` encrypts `webhook_secret` inside `encrypted_credentials` via Fernet. When an existing installation updates its secret, the prior secret is retained as `previous_webhook_secret` for zero-downtime secret rotation. Webhooks targeting an installation with a configured secret verify **exclusively** against that installation's active/rotated secrets and never fall back to another installation's secret or the global secret.
3. **Concurrency-Safe Idempotency & Failure Recovery:** `claim_webhook_delivery()` inserts `WebhookDelivery(status="processing")` inside an `IntegrityError`-guarded transaction so concurrent duplicate deliveries are deterministically rejected. On completion, status transitions to `"completed"`; on processing exception, status transitions to `"failed"`, allowing a subsequent authenticated retry to claim the failed row atomically.

---

## 8. Cross-Tenant Isolation Remediation (`SEC-14`)

- Added centralized helpers in `backend/app/core/auth.py` (`verify_scan_belongs_to_repository`, `verify_finding_belongs_to_repository`, `verify_verification_run_belongs_to_repository`) and service-layer guards in `record_security_evidence()` and `execute_fix_verification()`.
- Verified that:
  - Tenant A cannot create a finding referencing Tenant B's `scan_id` (`403`) or a `scan_id` from a different repository owned by Tenant A (`403`), nor a nonexistent `scan_id` (`404`).
  - Tenant A cannot attach evidence referencing Tenant B's `finding_id`, `scan_id`, or `verification_run_id` (`403`), nor mix FKs across repositories (`403`).
  - Direct service-layer calls to `record_security_evidence()` and `execute_fix_verification()` enforce the same tenant and repository boundaries.

---

## 9. `NormalizedFinding` Snapshot Correction (`REL-02`)

- `_serialize_normalized_finding_snapshot()` maps all authoritative `NormalizedFinding` fields (`finding_id`, `scan_id`, `scanner_name`, `scanner_rule_id`, `vulnerability_category`, `cwe`, `severity`, `confidence`, `file_path`, `start_line`, `end_line`, `scanner_message`, `evidence_reference`, `metadata`) while retaining backward-compatible keys (`rule_id`, `line_number`, `message`) so `findings_before_patch` and `findings_after_patch` snapshots are never empty.

---

## 10. Gemini AI Assistant Integration Correction (`REL-02`)

- Replaced broken `.is_enabled()` / `.client.models.generate_content()` / `.model_name` calls in `backend/app/validation/ai_assistant.py` with `GeminiAnalystClient.generate_structured_json()`.
- Added `_sanitize_and_escape_untrusted_block()` to redact secrets and escape `</untrusted_source_code>` / `</scanner_finding>` tags case-insensitively before any outbound request.
- Extended prompt-injection detection to scan `scanner_message`, `file_path`, and `rule_identifier` metadata in addition to `code_excerpt`.
- Enforced fail-closed behavior: when `OFFLINE_MODE=True`, `GEMINI_API_KEY` is missing, or Gemini returns 401/403/429/5xx, times out, fails network connection, or returns invalid JSON/schema, `GeminiAssistantUnavailableError` (`503 AI_ASSISTANT_UNAVAILABLE`) is raised with all API keys scrubbed — never fabricating a simulated AI validation result.

---

## 11. GitHub `Path` Import & Workspace Confinement Correction (`REL-02`)

- Added `from pathlib import Path` and `from ...core.ingestion import get_workspace_root` to `backend/app/integrations/github/service.py`.
- Hardened `trigger_pr_security_scan()` so that when `changed_files` is omitted, `repo.workspace_path` is checked for symlinks before `resolve()`, verified to reside strictly inside `get_workspace_root().resolve()` via `Path.is_relative_to()`, and walked while skipping any symlinked files.

---

## 12. Genuine SARIF 2.1.0 Implementation (`REL-02`)

- Implemented `_generate_sarif_findings_report()` in `backend/app/evidence/service.py` and wired `ReportExportFormat.SARIF` in both `generate_findings_report()` and `download_findings_report()`.
- Produces standards-compliant **OASIS SARIF 2.1.0** JSON (`version: "2.1.0"`, `$schema: ".../sarif-schema-2.1.0.json"`) with `tool.driver` metadata, deduplicated `rules`, severity-to-level mapping (`CRITICAL`/`HIGH` → `"error"`, `MEDIUM` → `"warning"`, `LOW`/`INFO` → `"note"`), `physicalLocation` with `artifactLocation` and `region.startLine` (gracefully omitting location when `file_path` is empty), deterministic SHA-256 `fingerprints` / `partialFingerprints`, and secret scrubbing via `sanitize_evidence_text()`.
- `GET /api/v1/evidence/reports/findings/download?format=sarif` returns `Content-Type: application/sarif+json; charset=utf-8` and `Content-Disposition: attachment; filename="findings_report_<safe_repo_id>.sarif"`.

---

## 13. Cross-Component Workflow Verification

Verified end-to-end in `test_rel02_sarif_210_findings_export_and_full_pipeline_consistency`:
`ZIP Repository Ingestion` → `Repository Persistence` → `Finding Persistence` → `Contextual Risk Prioritization` → `Deterministic Evidence Validation` → `NormalizedFinding Snapshot Serialization` → `Evidence Hash Integrity` → `SARIF 2.1.0 / JSON / Markdown Report Export & Download` → `Cross-Tenant 403 Enforcement`.

---

## 14. Regression Test Results

| Suite | Command | Collected | Passed | Failed | Skipped | Duration |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Backend Full Suite** | `python -m pytest tests/ -q --tb=short` (plus targeted re-run of fixed modules) | 555 | **535** | **0** | **20** | 163.98s |
| **Alembic Consistency** | `python -m pytest tests/test_migration_consistency.py -q --tb=short` | 3 | **3** | **0** | **0** | 1.41s |
| **Frontend (`vitest`)** | `npm --prefix frontend run test` | 46 | **46** | **0** | **0** | 7.15s |
| **Frontend TypeScript** | `npm --prefix frontend run lint` (`tsc --noEmit`) | — | **Pass** | **0** | — | — |
| **Electron (`node:test`)** | `node --test electron/security.test.cjs` | 10 | **10** | **0** | **0** | 0.13s |
| **Docker Compose Config** | `docker compose -f docker-compose.prod.yml config -q` | — | **Pass** | **0** | — | — |

---

## 15. Tests Skipped & Exact Reasons (20 Backend Skips)

1. **`tests/test_live_docker_security_runtime.py` (13 skipped) & `tests/test_sandbox.py` (2 skipped):** Docker Desktop Linux Engine daemon is not running on this Windows host (`npipe:////./pipe/dockerDesktopLinuxEngine` unavailable).
2. **`tests/test_postgresql_integration.py` (3 skipped):** Local PostgreSQL service / `TEST_POSTGRES_URL` is not configured on this host.
3. **`tests/test_scanners.py` (1 skipped):** Semgrep CLI is excluded on `win32` in `backend/requirements.txt`.
4. **`tests/test_verification_security_hardening.py` (1 skipped):** Creating OS filesystem symlinks on Windows requires elevated Administrator privileges.

---

## 16. Live vs. Mocked Integration Test Classification

- **Live In-Process Tested (SQLite + FastAPI TestClient + Vitest + Node):** Webhook HMAC verification, pre-persistence rejection, concurrent duplicate delivery locking, per-installation Fernet secret isolation & rotation, cross-tenant & cross-repository FK isolation, `NormalizedFinding` snapshot serialization, GitHub workspace path confinement, SARIF 2.1.0 / JSON / Markdown generation & download headers, Alembic `0001`–`0013` schema sync, HttpOnly cookie + CSRF + refresh rotation, and Electron security helpers.
- **Controlled Mocked Tested (No Live External Network Calls):** Gemini REST API calls (`httpx.Client.post` mocked for 200, invalid schema, empty candidates, timeout, 401, 429, network error, secret scrubbing), Redis Lua sliding-window rate limiter (`AtomicFakeRedis`), and Git DNS resolution / subprocess execution in SSRF tests.
- **Unverified Live External Infrastructure:** Live Docker daemon sandbox execution, live PostgreSQL 16 concurrency, live Redis 7 server, live GitHub App webhook delivery from `github.com`, and live Google Gemini API calls.

---

## 17. Remaining Vulnerabilities (Queued for Phase 5)

1. **`SEC-11` (HIGH):** Host-fallback test runner (`SANDBOX_ALLOW_HOST_FALLBACK=true` in local dev) uses bypassable AST inspection; strict environments already force `sandbox_allow_host_fallback=False`.
2. **`SEC-13` & `SEC-20` (HIGH/MEDIUM):** `nginx/frontend.conf` static-asset `add_header` inheritance drops server-level security headers and uses overly broad `connect-src`; `Dockerfile.worker` and CI download Gitleaks without SHA-256 checksum verification; `.gitleaks.toml` allowlists broad directories; Docker base images and GitHub Actions use mutable tags.
3. **`SEC-19` & `REL-01` (HIGH/MEDIUM):** Dual async scan execution (`BackgroundTasks` vs unwired `scanner/worker.py`), non-atomic scan quota checks, `POST /analyze-finding` using `get_current_user` instead of `require_mutating_role`, and chunked transfer encoding body-size bypass in `RequestSizeLimitMiddleware`.

---

## 18. Deployment Blockers

1. **Unresolved Phase 2 Deployment Blocker — API Service `git clone` Network Egress Isolation (`SEC-06`):**
   - While `worker` is isolated on `redmercury_worker_isolated` (`internal: true`), **Git repository cloning (`POST /api/v1/repositories/ingest/git`) executes inside the `api` service**, which sits on `redmercury_internal` (non-internal) and currently allows `GIT_EGRESS_PROXY_URL` to be optional (`${GIT_EGRESS_PROXY_URL:-}`).
   - Without a mandatory SSRF-filtering egress proxy (`GIT_EGRESS_PROXY_URL`, e.g., Smokescreen) AND host/cluster egress firewall rules blocking RFC1918, loopback, link-local, CGNAT, and cloud metadata (`169.254.169.254`) from the `api` container, connection-time DNS rebinding during `git clone` remains a deployment blocker.
2. **Live Infrastructure Gate:** Live Docker sandbox (`15` skipped tests), PostgreSQL 16 (`3` skipped tests), and Redis 7 rate limiting must be executed and verified in a Linux staging environment before production cutover.

---

## 19. Phase 5 Recommendations

1. **Enforce Fail-Closed `GIT_EGRESS_PROXY_URL` in Strict Environments:** Require `GIT_EGRESS_PROXY_URL` (or disable public Git ingestion by default in `is_strict_env` unless `GIT_EGRESS_PROXY_URL` is configured) and deploy an SSRF-filtering egress proxy container in `docker-compose.prod.yml`.
2. **Nginx, CSP & Supply-Chain Hardening (`SEC-13`, `SEC-20`):** Fix `nginx/frontend.conf` security header inheritance and `connect-src`; add SHA-256 verification for Gitleaks downloads; narrow `.gitleaks.toml` allowlists; pin Docker base image digests and GitHub Actions commit SHAs.
3. **Background Worker & Middleware Hardening (`REL-01`, `SEC-19`):** Unify async scan/verification execution onto atomic DB/Redis job claiming; enforce streaming byte limits on chunked requests in `RequestSizeLimitMiddleware`; require `require_mutating_role` on `POST /api/v1/analyze-finding`.

---

## 20. Final Engineering Decision

**Decision:** **CONDITIONALLY ACCEPTED**

**Rationale:** All Phase 4 code objectives (`SEC-12`, `SEC-14`, and all four `REL-02` defects) are implemented, verified by automated regression tests (`535` backend passed, `46` frontend passed, `10` Electron passed, `0` failures), and preserve all Phase 1–3 controls. Full production acceptance remains conditional on resolving the deployment-level `api` Git egress proxy/firewall requirement and executing the 20 environment-skipped Docker/PostgreSQL/Linux tests in CI/staging.
