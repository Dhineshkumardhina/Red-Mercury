# RED MERCURY — PHASE 0: COMPLETE REPOSITORY & ARCHITECTURE AUDIT

**Audit Date:** 2026-11-21  
**Repository:** `https://github.com/Dhineshkumardhina/Red-Mercury`  
**Local Audit Path:** `c:\PROJECTS\dhina projects\Red Mercury\Red Mercury`  
**Branch / Commit Audited:** `main` @ `b9df7b9` (`fix(alembic): widen alembic_version.version_num to VARCHAR(128) on PostgreSQL`)  
**Audit Mode:** Strictly Read-Only (No application source files modified, no dependencies installed, no Git state altered)  
**Overall Production Recommendation:** **NO-GO** (Ready for local development only; blocked for staging/production due to critical security, deployment, and functional defects)

---

## 1. Executive Summary

Red Mercury is an ambitious full-stack Application Security (AppSec) and Automated Fix Verification platform built on **FastAPI (Python 3.11+)**, **SQLAlchemy 2.0 / Alembic**, **React 19 / TypeScript / Vite / Tailwind CSS v4**, and **Electron 45**. The repository contains a substantial, genuinely engineered core: 48+ versioned REST endpoints, 17 SQLAlchemy ORM models across 12 linear Alembic migrations, real CLI scanner integrations (Bandit, pip-audit, Semgrep, Gitleaks), a well-designed Docker fail-closed fix-verification sandbox, cryptographic SHA-256 evidence hashing with tamper verification, and an automated test suite with **463 passing tests** (422 backend + 41 frontend, 0 failures, 20 environment-skipped).

However, this evidence-based Phase 0 audit uncovered **major gaps between documented claims and actual implementation**, as well as **critical security and operational blockers** that preclude production deployment:

1. **Critical Application Security Blockers:**
   - **Unrestricted Local Filesystem Ingestion (`F-01`, CRITICAL):** `POST /api/v1/repositories/ingest/local` remains active in production, has a dead symlink check (after `Path.resolve()`), dereferences symlinks via `shutil.copytree(..., symlinks=False)`, and lacks file/size quotas — allowing authenticated users to ingest sensitive host directories.
   - **Self-Registration Privilege Escalation (`F-02`, CRITICAL):** `POST /api/v1/auth/register` accepts and defaults to `role="admin"`, and `get_current_user()` mutates the ORM `user.role` directly from JWT claims.
   - **Hardcoded Personal Credentials & Unconditional Frontend Auto-Auth (`F-03`, CRITICAL):** `frontend/src/context/AuthContext.tsx` bundles cleartext credentials (`dhineshkumardhina@gmail.com` / `XerovaDevPass2026!`), auto-logs in unconditionally without a hostname check, and falls back to `isAuthenticated: true` (`defaultTester`) on failure. Backend production guards block `dev@xerova.com`, missing the actual seeded account.
   - **Arbitrary File Read & DoS in Electron Static Server (`F-04`, CRITICAL):** `electron/main.cjs` serves files via `path.join(distPath, decodeURI(reqPath))` with no path containment check and unguarded `decodeURI()`.
2. **Production Deployment Crash-Loop (`F-05`, CRITICAL):**
   - `docker-compose.prod.yml` runs `worker` with `APP_ENV: production` without passing `SECRET_KEY` or `CORS_ORIGINS`, causing `Settings.validate_production_configuration()` to raise `ValueError` immediately on container startup.
3. **Substantial README / Feature Overstatements:**
   - **EPSS Integration:** `NOT IMPLEMENTED` (zero references in `backend/app/`).
   - **CVSS v3.1 Scoring:** `PLACEHOLDER` (5-entry static severity-to-number map; no CVSS vector parser or math).
   - **AST Taint Trace Analysis:** `PLACEHOLDER` / `DOCUMENTATION ONLY` (Frontend `FindingDetailPage.tsx` renders a hardcoded static SQLi taint trace for every finding; backend `prioritization/evaluator.py` uses filename regexes; `backend/app/analyzer/` is the LLM client, not an AST taint engine).
   - **IAST & Pentest Scanners:** `PLACEHOLDER` (`iast_scanner.py` is 5 static regexes with zero runtime sensor; `pentest_scanner.py` never invokes Nuclei).
   - **AI Validation Assistant (`validation/ai_assistant.py`):** Broken for live Gemini calls (invokes nonexistent methods on `GeminiAnalystClient`, silently falling back on `AttributeError`), and `OFFLINE_MODE = True` disables Gemini globally by default.
   - **ML Experiments & Benchmark Integrity:** `ml_experiments/` has zero production backend integration, trains on 40 hand-crafted tabular rows, has a `NameError` (`Optional` not imported), and ties a 4-line rule baseline. `benchmark/baselines/ai_judge.py` never calls an LLM — it reads ground-truth `patch.patch_type` directly and adds fake `+250ms` latency, invalidating the reported McNemar `p=0.0001` significance claim.

---

## 2. Overall Project Status

| Lifecycle Stage | Verdict | Summary Rationale |
| :--- | :--- | :--- |
| **Local Development Ready** | **YES (with caveats)** | Backend (`pytest`: 422 passed, 20 skipped) and frontend (`vitest`: 41 passed, `tsc`: 0 errors) run cleanly. Minor friction from `8000` vs `8001` port mismatch in `README.md`. |
| **Docker Development Ready** | **PARTIAL** | `Dockerfile.api`, `Dockerfile.frontend`, and `Dockerfile.worker` are well-structured, but live Docker tests were skipped (daemon not running on host) and `worker` fails under `APP_ENV=production`. |
| **Staging Ready** | **NO** | `APP_ENV=staging` bypasses all production security gates (`config.py`), `.env.staging.example` is gitignored and ships a static `SECRET_KEY`, and critical auth/ingestion flaws remain open. |
| **Production Deployment Ready** | **NO (NO-GO)** | Blocked by 5 CRITICAL findings (unrestricted local ingest, admin self-registration, hardcoded frontend credentials/auto-auth, Electron path traversal, `docker-compose.prod.yml` worker crash-loop) plus HIGH security/reliability issues. |

---

## 3. Repository Structure Analysis

### 3.1 Git & Workspace State
- **Git Branches:** `main` (tracking `origin/main` at `b9df7b9`), `feat/security-auth`, `fix/backend-verification-and-deps`.
- **Worktrees:** Single primary worktree (`c:\PROJECTS\dhina projects\Red Mercury\Red Mercury`).
- **Working Tree Status:** Clean (`## main...origin/main`). Untracked runtime artifacts present locally (gitignored): `.env`, `.env.production`, `.env.production.example`, `.env.staging.example`, `redmercury.db`, `test_redmercury.db`, `bin/gitleaks.exe`, `ssl/redmercury.{crt,key}`, `backend/data/workspaces/*`, `frontend/.wrangler/state/*`.
- **Note on Gitignore Leakage:** `.gitignore:2-4` ignores `.env.*` and only negates `!.env.example`, causing `.env.production.example` and `.env.staging.example` to be **untracked in Git** despite being referenced in `README.md` and `docs/PRODUCTION_DEPLOYMENT_GUIDE.md`.

### 3.2 Complete Component Inventory

| Directory / Component | Responsibility | Key Files / Modules |
| :--- | :--- | :--- |
| **`backend/app/main.py`** | FastAPI ASGI entrypoint, lifespan hooks (`reconcile_interrupted_jobs`, dev seeding), middleware stack (CORS, TrustedHost, SecurityHeaders, RequestSizeLimit, AuthRateLimit), RFC Problem JSON exception handlers | `main.py` |
| **`backend/app/core/`** | Config/settings validation, JWT/bcrypt/CSRF/RBAC/tenant auth, in-memory rate limiting, audit logging, concurrency quotas, repository ingestion (ZIP/Git/Local), workspace cleanup, secret-scrubbing logging | `config.py`, `auth.py`, `security.py`, `audit.py`, `quotas.py`, `errors.py`, `logging.py`, `ingestion.py`, `workspace_cleanup.py` |
| **`backend/app/db/` & `models/`** | SQLAlchemy 2.0 engine/sessions (SQLite WAL + FK pragma / PostgreSQL pool), 17 ORM domain models | `base.py`, `session.py`, `user.py`, `token.py`, `repository.py`, `scan.py`, `finding.py`, `patch.py`, `verification.py`, `analysis.py`, `validation.py`, `audit.py`, `evidence.py`, `github.py` |
| **`backend/alembic/`** | Linear 12-revision schema migration chain (`0001`–`0012`) with PostgreSQL `alembic_version.version_num` `VARCHAR(128)` widening | `env.py`, `versions/0001_*.py` .. `0012_*.py` |
| **`backend/app/api/v1/`** | 11 versioned endpoint modules exposing ~59 route handlers | `router.py`, `endpoints/{auth,health,repositories,scans,findings,prioritization,validation,analyzer,verification,evidence,integrations}.py` |
| **`backend/app/schemas/`** | Pydantic v2 request/response schemas | `analyzer.py`, `auth.py`, `finding.py`, `health.py`, `patch.py`, `repository.py`, `scan.py`, `validation.py`, `verification.py` |
| **`backend/app/scanner/`** | Multi-scanner orchestration (`runner.py`), 17 registered adapters (`registry.py`), standalone polling daemon (`worker.py`) | `base.py`, `registry.py`, `runner.py`, `worker.py`, `bandit.py`, `pip_audit.py`, `semgrep.py`, `gitleaks.py`, `secret_detector.py`, `trivy_sca.py`, `dast_scanner.py`, `iast_scanner.py`, `pentest_scanner.py`, `owasp_scanner.py`, `iac_scanner.py`, `vuln_scanner.py`, `injection_scanner.py`, `api_security.py`, `supply_chain_scanner.py`, `license_compliance_scanner.py`, `container_base_scanner.py` |
| **`backend/app/prioritization/`** | Multi-factor contextual risk scoring (0–100), severe-finding floor protection, O(1) batch loader, remediation queue | `scoring.py`, `evaluator.py`, `service.py`, `schemas.py` |
| **`backend/app/validation/`** | Evidence dossier collector (bounded context, Python AST sink checks), 5 deterministic validation rules, broken Gemini assistant + deterministic fallback | `collector.py`, `rules.py`, `ai_assistant.py`, `service.py`, `enums.py` |
| **`backend/app/analyzer/`** | Gemini 2.5 Flash REST client, prompt-injection delimiter isolation, deterministic AppSec fallback engine, bounded context extractor | `client.py`, `prompts.py`, `fallback.py`, `context.py`, `service.py` |
| **`backend/app/verification/`** | Unified diff parser, atomic patch applier, disposable workspace + SHA-256 hashing, hardened Docker sandbox runner, pre/post regression comparator | `patch_parser.py`, `patch_applier.py`, `workspace.py`, `sandbox.py`, `runner.py`, `comparator.py`, `service.py` |
| **`backend/app/evidence/`** | Secret-scrubbing sanitizer, SHA-256 content hashing & tamper verification, JSON/Markdown/SARIF 2.1.0 report generators | `sanitizer.py`, `schemas.py`, `service.py` |
| **`backend/app/integrations/github/`** | Fernet credential encryption, least-privilege permission validator, GitHub PAT REST client, HMAC-SHA256 webhook handler, PR diff analyzer, Markdown publisher, CI gate evaluator | `client.py`, `crypto.py`, `permissions.py`, `pr_analyzer.py`, `publisher.py`, `schemas.py`, `service.py`, `webhook.py` |
| **`frontend/`** | React 19 SPA (11 pages, 26+ components), AuthContext, typed Fetch API client with micro-cache, local synthetic analyzer engine, Cloudflare Workers deployment config | `src/App.tsx`, `src/context/AuthContext.tsx`, `src/services/api.ts`, `src/pages/*`, `src/components/*`, `src/ai-security-analyzer/*`, `vite.config.ts`, `wrangler.jsonc`, `public/_headers` |
| **`electron/`** | Electron 45 Windows desktop wrapper: spawns local Uvicorn backend (`127.0.0.1:8001`), runs internal static UI + `/api/` proxy HTTP server, IPC bridge | `electron/main.cjs`, `electron/preload.cjs`, `Launch-Red-Mercury-Desktop.{bat,ps1}` |
| **`benchmark/` & `samples/`** | Fix-verification benchmark harness (7 synthetic + 4 toy CVE cases, 39 patches), 5 baselines, Wilson CI / McNemar metrics, sample SQLi repo | `benchmark/{runner,metrics,models,deduplicator,reporting}.py`, `benchmark/baselines/*`, `samples/sqli_auth_gateway/*` |
| **`ml_experiments/`** | Standalone scikit-learn LogisticRegression & DecisionTree experiment on 40 hand-crafted rows (`evidence_deficit_prediction`), serialized `.joblib` artifact | `ml_experiments/evidence_deficit_prediction/*`, `ml_experiments/models/*` |
| **`nginx/`, `Dockerfiles`, `railway.toml`** | Multi-stage Dockerfiles (`api`, `frontend`, `worker`), production Compose stack, Nginx TLS/reverse-proxy configs, Railway API build config | `Dockerfile.{api,frontend,worker}`, `docker-compose.prod.yml`, `nginx/{frontend,production}.conf`, `railway.toml`, `ssl/README.md` |
| **`.github/workflows/` & `scripts/`** | CI pipeline (`ci.yml`), PR security gate (`redmercury_pr_gate.yml`), standalone CLI gate (`ci_security_gate.py`), Windows PowerShell dev/test helpers, evaluation scripts | `.github/workflows/*`, `scripts/*` |
| **`docs/` & `reports/`** | 23 technical specification docs and 18 historical audit/phase reports | `docs/*.md`, `reports/*.md` |
| **`tests/` & `frontend/src/__tests__/`** | 45 pytest modules (442 tests) and 6 Vitest modules (41 tests) | `tests/test_*.py`, `frontend/src/__tests__/*.test.tsx` |

---

## 4. Technology Stack Verification

| Layer | README Claim | Verified Reality | Discrepancies |
| :--- | :--- | :--- | :--- |
| **Python / Backend** | Python 3.11+, FastAPI 0.115+, Pydantic v2, SQLAlchemy 2.0 | Verified (`backend/requirements.txt`: `fastapi>=0.115.0`, `pydantic>=2.8.0`, `sqlalchemy>=2.0.30`, `alembic>=1.13.0`, `psycopg[binary]>=3.1.0`, `pyjwt>=2.8.0`, `bcrypt>=4.1.0`, `cryptography>=42.0.0`). Tested on Python 3.14.7. | Unpinned `>=` ranges; no lockfile (`requirements.lock`/`uv.lock`). |
| **Frontend** | React 19, TypeScript 5.7, Vite 6, Tailwind CSS v4, Axios/Fetch | Verified (`frontend/package.json`: `react ^19.0.0`, `typescript ^5.7.3`, `vite ^6.2.0`, `tailwindcss ^4.0.9`, `react-router-dom ^7.2.0`, `vitest ^3.0.5`, `@cloudflare/vite-plugin ^1.70.1`). Uses native `fetch` (no Axios installed). | `tsconfig.json:18` sets `"strict": false`; README mentions Axios (`README.md:159,456`), actual client uses `fetch`. |
| **Desktop** | Electron Windows NSIS / Portable | Verified (`package.json`: `electron ^45.0.0`, `electron-builder ^26.15.3`). | Windows-only venv path lookup in `electron/main.cjs:192-199`. |
| **Database** | SQLite 3 (Dev) / PostgreSQL 16 (Prod), Alembic | Verified (`db/session.py`, 12 Alembic revisions, `postgres:16-alpine` in `docker-compose.prod.yml`). | Live PostgreSQL tests not run in CI (`ci.yml`) or locally (skipped). |
| **AI / ML** | Gemini 2.5 Flash + Fallback Ruleset | Gemini 2.5 Flash REST client exists (`analyzer/client.py`), but `OFFLINE_MODE=True` by default (`config.py:93`). `scikit-learn`/`joblib` are dev-only (`requirements-dev.txt`). | `validation/ai_assistant.py` Gemini call is broken (`AttributeError`). |
| **Security Scanners** | Bandit, pip-audit, Semgrep, Gitleaks | Verified in `requirements.txt` (`semgrep` excluded on `win32`) + `bin/gitleaks.exe` locally; 13 additional adapters registered in `registry.py` (mostly static regexes). | Several extra adapters (`iast_scanner`, `pentest_scanner`) are placeholders. |
| **Deployment** | Docker Compose + Nginx + Cloudflare Workers + Railway | Dockerfiles, Nginx configs, `railway.toml`, and `frontend/wrangler.jsonc` present. | `docker-compose.prod.yml` worker crashes on startup; Railway has no worker/Docker daemon for sandboxed verification. |

---

## 5. Feature Implementation Matrix

### 5.1 Security Scanning

| Capability | Classification | Evidence (Files, Classes, Functions, Endpoints, Tests) |
| :--- | :--- | :--- |
| **Bandit Integration** | **VERIFIED IMPLEMENTED** | `backend/app/scanner/bandit.py` (`BanditAdapter.scan`, `_get_executable_cmd`); `tests/test_scanners.py`, `tests/test_scanner_accuracy_benchmarks.py`. |
| **pip-audit Integration** | **VERIFIED IMPLEMENTED** | `backend/app/scanner/pip_audit.py` (`PipAuditAdapter.scan`, `--no-deps --disable-pip`, skips unpinned manifests); `tests/test_scanners.py`. |
| **Semgrep Integration** | **VERIFIED IMPLEMENTED** | `backend/app/scanner/semgrep.py` (`SemgrepAdapter.scan`, `--metrics=off`, graceful Windows/missing degradation); `tests/test_semgrep_graceful_degradation.py`, `tests/test_scanners.py` (1 skipped on Windows). |
| **Gitleaks Integration** | **VERIFIED IMPLEMENTED** | `backend/app/scanner/gitleaks.py` (`GitleaksAdapter.scan`, git & `--no-git` modes, secret redaction); `tests/test_git_history_secret_scanning.py`. |
| **Scanner Orchestration** | **VERIFIED IMPLEMENTED** | `backend/app/scanner/registry.py` (`ScannerRegistry`, 17 adapters), `backend/app/scanner/runner.py` (`run_security_scan`, `ThreadPoolExecutor(max_workers=4)`), `POST /api/v1/scans`; `tests/test_scanners.py`. |
| **Scanner Failure Handling** | **VERIFIED IMPLEMENTED** | `backend/app/scanner/runner.py:120-131,224-235` catches per-adapter crashes into `ScannerStatus.EXECUTION_ERROR` and sets scan status `partial`/`failed`/`completed`; `tests/test_semgrep_graceful_degradation.py`. |
| **Normalized Vulnerability Results** | **VERIFIED IMPLEMENTED** | `backend/app/scanner/base.py:107-130` (`NormalizedFinding`), persisted to `SecurityFinding` (`models/finding.py`); `GET /api/v1/scans/{scan_id}/results`. |
| **Extra Scanners (`iast`, `pentest`, `dast`, `trivy`, `iac`, `owasp`, `api`, etc.)** | **PARTIALLY IMPLEMENTED / PLACEHOLDER** | `iast_scanner.py` (PLACEHOLDER: 5 regexes, no runtime sensor), `pentest_scanner.py` (PLACEHOLDER: never calls Nuclei), `trivy_sca.py` (`is_available()` returns `... or True`, fallback checks unpinned lines only), `owasp_scanner.py` (multiline regex bug never matches), `api_security.py` (never invokes Schemathesis, ignores YAML specs). |

### 5.2 Risk Intelligence

| Capability | Classification | Evidence (Files, Classes, Functions, Endpoints, Tests) |
| :--- | :--- | :--- |
| **CVSS v3.1 Scoring** | **PLACEHOLDER** | `backend/app/prioritization/scoring.py:70-76,117` uses a 5-entry dict (`CRITICAL: 80.0` .. `INFORMATIONAL: 5.0`). No CVSS v3.1 vector parser or base/temporal/environmental math exists. |
| **EPSS Integration** | **NOT IMPLEMENTED** | Zero references to EPSS anywhere in `backend/app/`. |
| **Reachability Analysis** | **PLACEHOLDER** | `backend/app/prioritization/evaluator.py:27-35,286-293` classifies reachability purely via filename regexes (`TEST_PATH_PATTERNS`, `ENTRYPOINT_PATH_PATTERNS`, else `unproven`). No AST taint or call-graph analysis. |
| **Asset Criticality** | **PARTIALLY IMPLEMENTED** | `EnvironmentContext` (`prioritization/schemas.py:46-67`) and `calculate_contextual_risk_score` (`scoring.py:367-441`) apply additive modifiers via `POST /api/v1/findings/{id}/prioritize`, but `build_remediation_queue()` (`service.py:70-76`) never passes an `env_context`. |
| **Risk Prioritization** | **VERIFIED IMPLEMENTED** | `backend/app/prioritization/{scoring,evaluator,service}.py`; `GET /api/v1/prioritization/remediation-queue`, `GET /api/v1/findings/{id}/prioritization`; `tests/test_prioritization_engine.py`, `tests/test_risk_prioritization.py`. |
| **Vulnerability Deduplication** | **PARTIALLY IMPLEMENTED** | Intra-scan exact-key dedup `(file_path, start_line, scanner_rule_id, scanner_name)` in `scanner/runner.py:155`. **No cross-scanner deduplication** (overlapping findings from `bandit`/`injection_scanner`/`iac_scanner`/`vuln_scanner` are stored as duplicates). |

### 5.3 AI Security Analyst

| Capability | Classification | Evidence (Files, Classes, Functions, Endpoints, Tests) |
| :--- | :--- | :--- |
| **Gemini Integration** | **PARTIALLY IMPLEMENTED** | `backend/app/analyzer/client.py` (`GeminiAnalystClient.analyze_finding`) is a genuine REST client for `gemini-2.5-flash` (gated off by `OFFLINE_MODE=True` in `config.py:93`). However, `backend/app/validation/ai_assistant.py:96-100` calls nonexistent attributes on `GeminiAnalystClient` and always fails over via `AttributeError`. |
| **Deterministic Fallback Engine** | **VERIFIED IMPLEMENTED** | `backend/app/analyzer/fallback.py` (`generate_fallback_analysis`), `backend/app/validation/ai_assistant.py:113-137`, `frontend/src/ai-security-analyzer/syntheticEngine.ts`; `tests/test_analyst.py`. |
| **Prompt-Injection Protection** | **PARTIALLY IMPLEMENTED** | Delimiter isolation (`<untrusted_source_code>`) + regex detection in `analyzer/prompts.py:15-64` and `validation/collector.py:16-23`; `tests/test_ai_prompt_injection_resistance.py`. Weakened by case-sensitive `.replace()` tag breakout (`prompts.py:63-64`), unescaped interpolation in `validation/ai_assistant.py:45-58`, unscanned metadata fields, and no hard stop in `client.py`. |
| **Secret Redaction** | **VERIFIED IMPLEMENTED** | `backend/app/evidence/sanitizer.py:8-60` (`redact_secrets`), `backend/app/core/logging.py:10-27`, `backend/app/analyzer/context.py:109`. (Note: frontend `redactor.ts` has a stateful `/g` `lastIndex` bug.) |
| **Context Isolation** | **VERIFIED IMPLEMENTED** | `backend/app/analyzer/context.py` (`get_bounded_source_context`, clamps context to +/- 15 lines) and separate `system_instruction` in `client.py:83-85`. |
| **Bounded Patch Generation** | **NOT IMPLEMENTED** | `analyzer/prompts.py:48` explicitly forbids patch generation; `FindingAnalysisResponse` returns prose `suggested_remediation` only, not unified diff patches. User-supplied patches in `verification/patch_parser.py` enforce path bounds but no diff-size bounds. |
| **Regression Test Generation** | **PARTIALLY IMPLEMENTED** | `FindingAnalysisResponse.suggested_targeted_tests` returns advisory text descriptions (`analyzer/fallback.py`, `schemas/analyzer.py`), not executable generated pytest files. |

### 5.4 Automated Fix Verification

| Capability | Classification | Evidence (Files, Classes, Functions, Endpoints, Tests) |
| :--- | :--- | :--- |
| **Differential Scanner Execution** | **VERIFIED IMPLEMENTED** | `backend/app/verification/service.py:149-158,296-336` + `comparator.py:109-360` (6-state taxonomy); `POST /api/v1/verifications`; `tests/test_verification.py`, `tests/test_fix_verification_suite.py`. (Bug: `service.py:159-169,306-316` reads wrong attribute names on `NormalizedFinding`, storing blank `rule_id`/`message`/`line_number` in JSON snapshots.) |
| **Syntax Validation** | **NOT IMPLEMENTED** | No explicit `ast.parse` or `py_compile` syntax validation gate in `backend/app/verification/`. |
| **Compiler Checks** | **NOT IMPLEMENTED** | No compiler check (`tsc`, `go build`, `cargo check`, `javac`, etc.) in `backend/app/verification/`. |
| **Sandboxed Testing** | **VERIFIED IMPLEMENTED** (Docker) / **BLOCKED** (Local Verification) | `backend/app/verification/sandbox.py:132-298` implements hardened fail-closed Docker execution (`--network=none`, `--cap-drop=ALL`, `--read-only`, `--pids-limit`, non-root `10002:10002`). Live Docker tests (`test_live_docker_security_runtime.py`, 2 tests in `test_sandbox.py`) were **skipped** because Docker daemon was not running. Host fallback mode (`runner.py:38-114`) has bypassable AST safety checks. |
| **Regression Verification** | **VERIFIED IMPLEMENTED** | `backend/app/verification/comparator.py` (`compare_verification_findings`), `runner.py` (pre/post pytest execution); `tests/test_patch_atomicity_and_verification.py`. |
| **Failed Remediation Handling** | **VERIFIED IMPLEMENTED** | `backend/app/verification/service.py:456-499` enforces `FAILED_VERIFICATION` / `INCONCLUSIVE` states and rolls back failed patch writes atomically (`patch_applier.py:263-284`). |
| **Verification Evidence Generation** | **VERIFIED IMPLEMENTED** | `backend/app/verification/service.py:537-804` (`_finalize_and_persist_run`) writes `VerificationRun`, `VerificationEvidence`, 4 `SecurityEvidence` records, SHA-256 `integrity_hash`, and audit events; `tests/test_evidence_traceability.py`. |

### 5.5 Evidence and Reporting

| Capability | Classification | Evidence (Files, Classes, Functions, Endpoints, Tests) |
| :--- | :--- | :--- |
| **SHA-256 Evidence Hashing** | **VERIFIED IMPLEMENTED** | `backend/app/evidence/sanitizer.py:63-85` (`compute_content_hash`, `verify_content_hash`), `VerificationRun.integrity_hash`. |
| **Evidence Lifecycle** | **VERIFIED IMPLEMENTED** | `backend/app/evidence/service.py:38-100`, `models/evidence.py`, `api/v1/endpoints/evidence.py`; `tests/test_evidence_management.py`. |
| **SARIF 2.1.0 Exports** | **PARTIALLY IMPLEMENTED** | Implemented for verification runs (`evidence/service.py:378-501`, `_generate_sarif_verification_report`) and CLI gate (`scripts/ci_security_gate.py`). **Bug:** `generate_findings_report` (`evidence/service.py:239-366`) lacks a `SARIF` branch and silently returns Markdown when `format=sarif` is requested! |
| **JSON Exports** | **VERIFIED IMPLEMENTED** | `evidence/service.py` (`generate_findings_report`, `generate_verification_report`), `GET /api/v1/evidence/reports/*`. |
| **Markdown Exports** | **VERIFIED IMPLEMENTED** | `evidence/service.py` (`generate_findings_report`, `generate_verification_report`), `GET /api/v1/evidence/reports/*`. |
| **Evidence Integrity Verification** | **VERIFIED IMPLEMENTED** | `evidence/service.py:102-199` (`verify_evidence_record_integrity`, `verify_verification_run_integrity`), `GET /api/v1/evidence/{id}/verify-integrity`; `tests/test_evidence_management.py`. |

### 5.6 Enterprise Capabilities

| Capability | Classification | Evidence (Files, Classes, Functions, Endpoints, Tests) |
| :--- | :--- | :--- |
| **GitHub Integration** | **PARTIALLY IMPLEMENTED** | PAT auth, Fernet credential encryption (`crypto.py`), permission validation (`permissions.py`), PR commenting (`publisher.py`), and `tests/test_github_integration.py` work. **Gaps:** GitHub App RS256 JWT/installation-token flow is `NOT IMPLEMENTED`; webhook handler never triggers PR scans; per-installation webhook secret lookup is broken; `Path` `NameError` in `integrations/github/service.py:243`. |
| **Pull Request Security Gates** | **PARTIALLY IMPLEMENTED** | Standalone CLI (`scripts/ci_security_gate.py`) and `.github/workflows/redmercury_pr_gate.yml` evaluate `PASS`/`FAIL`/`INCOMPLETE` (exit `0`/`1`/`2`); `tests/test_ci_security_gate_cli.py`, `tests/test_ci_cd_release_gates.py`. **Gaps:** `ci_security_gate.py:272` ignores `backend/requirements.txt` and omits Gitleaks; `block_pr_on_critical` has no GitHub Check Runs/Status API; `run_pr_security_analysis` never checks out PR commit SHAs. |
| **Multi-Tenant Authorization** | **PARTIALLY IMPLEMENTED** | Ownership checks (`verify_repository_ownership`, `verify_finding_ownership`, `verify_scan_ownership`, `verify_verification_run_ownership`, `verify_evidence_ownership`) exist in `core/auth.py` and are tested (`tests/test_authorization.py`, `tests/test_auth_and_authorization.py`). **Gaps:** Cross-tenant FK reference injection on `POST /findings` (`scan_id`) and `POST /evidence` (`scan_id`, `finding_id`, `verification_run_id`); self-registration grants `role="admin"`. |
| **Usage Quotas** | **PARTIALLY IMPLEMENTED** | `backend/app/core/quotas.py` enforces concurrent scan/verification caps and daily/hourly quotas (`MAX_CONCURRENT_SCANS_PER_USER=2`, `MAX_SCANS_PER_DAY_PER_USER=50`), but checks are non-atomic read-then-insert queries vulnerable to concurrent race conditions. |
| **Asynchronous Scanning** | **PARTIALLY IMPLEMENTED** | `POST /api/v1/scans` returns `202 Accepted` and runs via in-process FastAPI `BackgroundTasks` (`scans.py:188-194`); `tests/test_async_scans.py`. Not backed by a durable queue; `scanner/worker.py` is an unwired parallel polling daemon that races with `scans.py` if both run. |
| **Interrupted-Job Recovery** | **PARTIALLY IMPLEMENTED** | `reconcile_interrupted_jobs()` (`core/quotas.py:87-146`) marks stale `running`/`queued` jobs as `interrupted` at startup, but only for jobs older than 15 minutes (`created_at <= now - 15m`), leaving recent crashes permanently stuck, and never runs periodically. |
| **Audit Logging** | **VERIFIED IMPLEMENTED** | `backend/app/core/audit.py` (`record_audit_event`) persists `AuditEvent` rows with secret redaction across auth, scan, verification, evidence, and GitHub operations. (Reliability note: commits/rolls back caller's shared DB session.) |

---

## 6. Backend Architecture Assessment

### Strengths
- Clean modular separation under `backend/app/` (`api/v1/endpoints`, `core`, `db`, `models`, `schemas`, `scanner`, `prioritization`, `validation`, `analyzer`, `verification`, `evidence`, `integrations/github`).
- Consistent RFC 7807/9457 `application/problem+json` error handling (`core/errors.py`) with `X-Request-ID` correlation (`core/security.py`).
- Parameterized SQLAlchemy 2.0 ORM queries throughout — **zero raw SQL injection vulnerabilities identified**.
- Strong baseline HTTP security headers (`CSP: default-src 'none'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `CORP: same-origin`, HSTS in production) and secret-scrubbing log filter (`core/logging.py`).
- Clean 12-step linear Alembic migration history with PostgreSQL `alembic_version.version_num` widened to `VARCHAR(128)` (`alembic/env.py:50-59`).

### Key Weaknesses
- **Dual/Conflicting Async Execution Models:** `scans.py` uses in-process FastAPI `BackgroundTasks`, while `scanner/worker.py` implements an independent DB polling daemon without atomic row locking (`SELECT ... FOR UPDATE`), creating race conditions and duplicate `VerificationRun` rows (`worker.py:231-238`).
- **Auth & RBAC Enforcement Flaws:** Self-registration defaults to `admin`, `get_current_user()` overwrites ORM `user.role` from JWT claims, `POST /analyze-finding` omits `require_mutating_role`, and `POST /auth/logout` lacks CSRF validation and auth/rate-limiting.
- **Database Transaction & Scalability Issues:** `record_audit_event()` commits/rolls back on the caller's shared SQLAlchemy session (`core/audit.py:34-66`); `GET /findings?priority=...` loads all rows into memory via `query.all()` (`findings.py:65`); `GET /verifications` has an N+1 query on `VerificationEvidence` (`verification.py:90-93,178-180`).
- **Model & Migration Rough Edges:** Duplicate alias columns on `SecurityFinding` (`models/finding.py:16-19,32-33`), nested `Column(Column(String(32)).type)` bug (`models/validation.py:40-41`), bare `op.drop_column` in migration `0012` (SQLite < 3.35), offline `--sql` incompatibility in `0011`/`0012`, and hardcoded `HEAD_REVISION` in `main.py:89`.

---

## 7. Frontend & Electron Desktop Architecture Assessment

### Frontend SPA (`frontend/`)
- **Architecture:** React 19 + React Router v7 (`HashRouter` on `file:`/Electron, `BrowserRouter` on web) + Vite 6 + Tailwind CSS v4 + `@cloudflare/vite-plugin`. Typed Fetch client (`src/services/api.ts`) with 2.5s `microCache`, `inFlightRequests` deduplication, abort/timeout handling, HTML SPA fallback detection, and `ApiError`.
- **Positive Controls:** Zero XSS sink usage (`dangerouslySetInnerHTML`, `innerHTML`, `eval`, `new Function`, `javascript:` URLs). Strong baseline security headers in `frontend/public/_headers` (HSTS preload, `X-Frame-Options: DENY`, `nosniff`, COOP/CORP).
- **Critical & High Flaws:**
  - **Hardcoded Credentials & Unconditional Auto-Auth (`AuthContext.tsx:30-38,72-93`, `LoginPage.tsx:9-10`):** Cleartext personal credentials shipped in production JS bundle; `initAuth` auto-logs in without hostname guard and falls back to `defaultTester` (`isAuthenticated: true`), defeating `AppLayout` auth gating.
  - **Silent Auto-Registration on Failed Login (`AuthContext.tsx:154-176`):** Any login failure with `password.length >= 8` silently calls `registerUser()`.
  - **JWT in `localStorage` + Session Wipe Bug (`api.ts:272-292`, `FindingsPage.tsx:70-81`):** Clicking Refresh on `FindingsPage` calls `api.setAuthToken(null)` then `ensureAuthenticated(true)`, wiping the active user's session or replacing it with the hardcoded dev user.
  - **Deceptive Mock/Synthetic Fallbacks:** `AiSecurityAnalyzerScreen.tsx:112-123` silently falls back to `syntheticEngine.ts` and shows `"Scan complete"`; `FindingDetailPage.tsx:362-385` renders a hardcoded SQLi AST taint trace for every finding; `SettingsPage.tsx:35-39,97-113` fakes save success and shows `"CONNECTED"` / `"PRODUCTION"` when `/health` fails; `FixVerificationScreen.tsx:390-393` falls back to fake SHA prefixes (`4b91f092`, `7c82a194`); `EvidencePage.tsx:81-82` claims a default audit bundle was downloaded when export fails.
  - **Functional & Config Bugs:** `"strict": false` in `tsconfig.json:18`; `err?.status` instead of `err.statusCode` in `FindingDetailPage.tsx:66` and `RepositoryDetailPage.tsx:105` (dead 401/403 handlers); Dashboard severity links use uppercase (`?severity=CRITICAL`) while `FindingsPage.tsx:188` compares lowercase (0 matches); `AiSecurityAnalyzerScreen.tsx:313` uses `window.location.href = '/verification'` (breaks Electron `HashRouter`); `ExportModal.tsx:87` prints stale `"REPO SHIELD AI"` branding; `redactor.ts` has a stateful `/g` `lastIndex` bug.

### Electron Desktop App (`electron/`)
- **Architecture:** Electron 45 spawns local FastAPI/Uvicorn (`127.0.0.1:8001`), runs an internal Node HTTP static server + `/api/` reverse proxy on an ephemeral `127.0.0.1` port, and exposes 4 IPC handlers via `preload.cjs` (`contextBridge`).
- **Security Posture:** `nodeIntegration: false` and `contextIsolation: true` are set properly, **but**:
  - **CRITICAL Path Traversal & DoS (`electron/main.cjs:296-319`):** `startStaticUiServer` joins `distPath` with unguarded `decodeURI(reqPath)` without verifying containment inside `distPath` — enabling arbitrary local file read and uncaught `URIError` crashes.
  - **HIGH Sandbox Disabled & Missing Navigation/IPC Controls (`main.cjs:346,381-386,417-448`):** `sandbox: false` is set unnecessarily; no `will-navigate` handler restricts in-window navigation; IPC handlers do not validate `event.senderFrame.url`; `shell:openExternal` lacks `new URL()` validation; internal HTTP server omits CSP/`nosniff` headers.
  - **HIGH Subprocess Spawn & Orphan Risk (`main.cjs:191-218,396-414`):** Spawns Python with `shell: process.platform === 'win32'` (fragile with spaces in paths and injection-prone if `PORT` is tainted), only searches Windows `.venv\Scripts\python.exe`, and uses async `exec('taskkill ...')` during quit (risking orphaned Uvicorn processes).

---

## 8. AI / ML Implementation & Benchmark Assessment

### 8.1 Clear Taxonomy: Deterministic vs. AI-Assisted vs. Actual ML

| Category | Actual Implementation | Production Runtime Status |
| :--- | :--- | :--- |
| **Deterministic Security Analysis (No AI/ML)** | `analyzer/fallback.py`, `validation/{collector,rules}.py`, `verification/*`, `prioritization/*`, `frontend/src/ai-security-analyzer/syntheticEngine.ts` | **Active (Default Path)** — handles 100% of requests under default `OFFLINE_MODE=True`. |
| **AI-Assisted Analysis (LLM / Gemini)** | `analyzer/client.py` (`GeminiAnalystClient`), `validation/ai_assistant.py` | **Disabled by default / Partially Broken** — `analyzer/client.py` works when `OFFLINE_MODE=False` + API key set; `validation/ai_assistant.py` always throws `AttributeError` and falls back deterministically. |
| **Actual ML-Based Prediction (Scikit-Learn)** | `ml_experiments/evidence_deficit_prediction/*`, `ml_experiments/models/evidence_deficit_model_v1.joblib` | **Not Used in Production** — zero imports or references in `backend/`. |

### 8.2 Verification of All 10 AI/ML Audit Criteria

1. **Gemini Calls Functional?** `analyzer/client.py:24-147` makes genuine HTTPS `POST` requests to `generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent` with `httpx`, retries, and timeouts, **but** is disabled by default (`OFFLINE_MODE=True` in `config.py:93`) and omits `response_schema` / explicit JSON keys in `prompts.py`. `validation/ai_assistant.py:96-100` is **broken** (calls nonexistent `.is_enabled()`, `.client.models.generate_content()`, `.model_name`).
2. **API Key Security?** Properly sent via `x-goog-api-key` header (not query string), never logged, absent from frontend, stripped from sandbox subprocesses (`verification/workspace.py:20`). Minor: cached at import time in module singleton.
3. **Deterministic Fallback?** Works reliably across `analyzer/fallback.py` (5 CWE categories + generic), `validation/ai_assistant.py`, and `syntheticEngine.ts`. Minor: inconsistent `confidence` formatting (`"0.90 (High)"` vs `"HIGH"` vs `'high'`).
4. **Constrained AI Fixes?** AI does not generate unified diffs at all (`prompts.py:48` prohibits it). User-supplied verification patches enforce strict path hygiene (`patch_parser.py`) but lack diff-size/hunk-count limits.
5. **Model Output Validation?** `client.py:148-209` parses JSON, builds Pydantic `FindingAnalysisResponse`, and clamps `exploitable_claim=False` when context is truncated or evidence is empty. Weaknesses: `confidence` is unconstrained `str`; non-dict JSON causes `AttributeError` aborting retries; frontend `schema.ts` omits element-type and `additionalProperties` checks.
6. **Prompt-Injection Defenses?** Regex detection + `<untrusted_source_code>` tags + separate `system_instruction`. **Bypasses:** case-sensitive `.replace("</untrusted_source_code>")` in `prompts.py:63-64` (bypassed by `</UNTRUSTED_SOURCE_CODE>`); zero escaping in `validation/ai_assistant.py:45-58`; `scanner_message`/`file_path` left unscanned outside delimiters; `client.py` still forwards detected injections to Gemini instead of short-circuiting.
7. **Patch Review Before Application?** Strictly human-in-the-loop: requires `user_authorized_analysis=True`, always sets `requires_human_review=True`, applies patches only in disposable scratch workspaces, and `POST /verifications/{id}/approve-and-merge` unconditionally blocks automated merges.
8. **ML Experiments Genuine?** `ml_experiments/evidence_deficit_prediction/train_and_evaluate.py` genuinely trains `LogisticRegression` and `DecisionTreeClassifier`, **but** has zero backend integration, trains on **40 hand-crafted tabular rows** (28 train / 12 test), has a runtime `NameError` (`Optional` missing on line 16/49), and hardcodes a false narrative claiming to beat the rule baseline (83.3%) when the actual rule baseline tied Logistic Regression at **91.7% accuracy / 0.909 F1** (`ml_investigation_report.md:97-99`).
9. **Benchmark Reproducibility & Integrity?** Deterministic JSON harness with SHA-256 deduplication (`benchmark/deduplicator.py`), **but** tiny synthetic datasets (7 synthetic cases + 4 ~20-line toy CVE reproductions = 39 patches; triage benchmark = 10 snippets). **Critical Integrity Defect:** `benchmark/baselines/ai_judge.py:33-88` (`B3_ai_judge`) never calls an LLM — it branches directly on ground-truth `patch.patch_type`, adds fake `+250ms` latency, and labels itself `"gpt-4o / claude-3.5-sonnet (simulated zero-shot judge)"`. `SastAloneBaseline` runs only Bandit even on custom non-Bandit rules (`RS-CRED-LEAK`).
10. **Evaluation Metrics Meaningful?** Formulas in `benchmark/metrics.py` (Wilson CI, McNemar) are mathematically sound, **but** conclusions are compromised by N=10/12/39 small-sample variance, invalid McNemar significance (`p=0.0001`) against the leaking `B3_ai_judge` strawman, `INCONCLUSIVE` on `NON_FIX` counted as True Negative (`metrics.py:133-139`), misleading "ML Evaluation" framing on deterministic pipelines, and a filter bug in `scripts/ml_evaluate_redmercury.py:589-590` producing `total: 0` for `dev_split_b4` and `held_out_split_b4`.

---

## 9. Security Audit Findings

### Critical Findings

| Finding ID | Severity | Description & Actual Evidence | Affected File Paths | Recommended Action |
| :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | **CRITICAL** | **Unrestricted Local Filesystem Ingestion & Symlink Dereferencing:** `POST /api/v1/repositories/ingest/local` is enabled in production. `validate_local_ingest_path()` uses a short denylist that permits `/app`, `/home`, `/tmp`, `C:\Users`, and the app directory (`.env`, DB). Line 363 checks `target_dir.is_symlink()` *after* `Path.resolve()` (dead code). `shutil.copytree(..., symlinks=False)` dereferences internal symlinks and has no file-count or byte-size limits. | `backend/app/api/v1/endpoints/repositories.py:341-434`, `backend/app/core/ingestion.py:343-397` | Disable `/ingest/local` when `settings.is_production` (or enforce an explicit config allowlist). Check `is_symlink()` prior to `resolve()`, reject symlinks during directory walk, and enforce `MAX_FILE_COUNT` and `MAX_EXTRACTED_SIZE_BYTES`. |
| **SEC-02** | **CRITICAL** | **Self-Registration Admin Privilege Escalation & Mutable ORM Role:** `UserRegister` accepts `role` defaulting to `"admin"`, and `register()` stores `role=user_in.role or "admin"` without enum validation. `get_current_user()` executes `user.role = token_role` on the attached SQLAlchemy `User` object, overriding DB role downgrades and risking persistence of stale JWT roles. | `backend/app/api/v1/endpoints/auth.py:26-46`, `backend/app/schemas/auth.py:9-12`, `backend/app/core/auth.py:197-201` | Remove `role` from `UserRegister`; assign least-privilege default (`analyst` or `viewer`); require admin-only endpoint for role changes. Never mutate ORM `user.role` from JWT claims. |
| **SEC-03** | **CRITICAL** | **Hardcoded Personal Credentials & Unconditional Frontend Auto-Authentication:** Cleartext credentials (`dhineshkumardhina@gmail.com` / `XerovaDevPass2026!`) are bundled into production frontend JS. `AuthContext.tsx` `initAuth` calls `loginWithCredentials()` unconditionally (no hostname guard) and sets `user = defaultTester` (`isAuthenticated: true`) on failure, neutralizing `AppLayout` auth gating. Backend prod blocklist only blocks `dev@xerova.com`, missing the actual seeded account (`main.py:32-51`). | `frontend/src/context/AuthContext.tsx:30-38,72-93,106-128`, `frontend/src/services/api.ts:383-386`, `frontend/src/pages/LoginPage.tsx:9-10,22`, `backend/app/main.py:32-51`, `backend/app/core/config.py:72`, `backend/app/core/auth.py:190,246` | Remove all hardcoded credentials, `defaultTester` fallback, and auto-login from frontend and `main.py`. Gate dev seeding strictly behind an explicit dev CLI tool. |
| **SEC-04** | **CRITICAL** | **Arbitrary Local File Read (Path Traversal) & DoS in Electron Static UI Server:** `startStaticUiServer` constructs `filePath = path.join(distPath, decodeURI(reqPath))` without verifying `path.resolve(filePath)` stays inside `path.resolve(distPath)`. Unguarded `decodeURI()` also throws an uncaught `URIError` on malformed percent-encoding, crashing Electron. | `electron/main.cjs:296-319` | Wrap `decodeURI` in `try/catch`, resolve path with `path.resolve(distPath, '.' + reqPath)`, and enforce `resolved.startsWith(path.resolve(distPath) + path.sep)` before `fs.readFile`. |

### High Findings

| Finding ID | Severity | Description & Actual Evidence | Affected File Paths | Recommended Action |
| :--- | :--- | :--- | :--- | :--- |
| **SEC-05** | **HIGH** | **ZIP Bomb / Unbounded Extraction Bypass:** `validate_and_extract_zip()` checks `member.file_size` and `member.compress_size` from untrusted ZIP headers, then calls unbounded `shutil.copyfileobj(source_stream, dest_stream)`. | `backend/app/core/ingestion.py:211-227,282-298` | Stream extraction in fixed chunks counting actual decompressed bytes per file and cumulatively; abort and delete partial files on overflow. |
| **SEC-06** | **HIGH** | **Ineffective SSRF DNS Rebinding Defense in Git Cloning:** `clone_git_repository()` passes `-c http.resolve=...` to `git`, which is not a valid Git config key and is silently ignored. `repositories.py:291-296` fails to forward `allow_private`; `POST /repositories` does not validate `git_url`. | `backend/app/core/ingestion.py:459-474`, `backend/app/api/v1/endpoints/repositories.py:78,256,291-296` | Enforce egress network isolation (firewall/proxy blocking RFC1918, link-local, metadata, CGNAT, IPv4-mapped IPv6) for `git clone`; validate `git_url` on `POST /repositories`. |
| **SEC-07** | **HIGH** | **Rate Limiting Gaps, IP Spoofing & Unauthenticated `revoked_tokens` DB Growth:** `InMemoryRateLimiter` is process-local; `get_client_ip()` trusts `X-Forwarded-For[0]` / `CF-Connecting-IP`; expensive routes (`/verifications`, `/validate`, `/pr-scans`, `/webhook`, `/logout`) are unthrottled; unauthenticated `POST /auth/logout` persists invalid Bearer strings with `expires_at=NULL` that cleanup never deletes. | `backend/app/core/security.py:142-310`, `backend/app/api/v1/endpoints/auth.py:192-224`, `backend/app/core/auth.py:154` | Move rate limiting to Redis in production; parse rightmost untrusted IP in `X-Forwarded-For`; throttle verification/validation/webhook/logout endpoints; only revoke tokens that pass `decode_access_token()`. |
| **SEC-08** | **HIGH** | **Silent Auto-Registration on Failed Login:** `AuthContext.login()` catches *any* login error and, if `password.length >= 8`, silently calls `registerUser(email, password)`. | `frontend/src/context/AuthContext.tsx:154-176` | Remove auto-registration from `login()`; keep registration strictly on `RegisterPage`. |
| **SEC-09** | **HIGH** | **JWT in `localStorage` & Session Hijack/Wipe on Findings Refresh:** Bearer JWT stored in `localStorage` (XSS-exfiltratable). Clicking Refresh in `FindingsPage.tsx:70-81` calls `api.setAuthToken(null)` + `ensureAuthenticated(true)`, wiping active user sessions or switching to the hardcoded dev account. | `frontend/src/services/api.ts:272-292`, `frontend/src/pages/FindingsPage.tsx:70-81` | Remove `setAuthToken(null)` from `FindingsPage.loadData`; migrate to `HttpOnly; Secure; SameSite=Lax` cookies with short-lived tokens. |
| **SEC-10** | **HIGH** | **Electron Hardening & Subprocess Risks:** `sandbox: false` set unnecessarily (`preload.cjs` works with `sandbox: true`); missing `will-navigate` allowlist; IPC handlers do not verify `event.senderFrame.url`; `shell:openExternal` lacks `new URL()` validation; backend Python spawned with `shell: true` on Windows; async `taskkill` risks orphan processes. | `electron/main.cjs:13,191-218,342-347,381-448` | Enable `sandbox: true`; add `will-navigate` allowlist; validate IPC sender frames & URLs; use `shell: false` with validated integer port; use `execFileSync` for Windows shutdown. |
| **SEC-11** | **HIGH** | **Host-Fallback Sandbox Escape Risk:** When `SANDBOX_ALLOW_HOST_FALLBACK=true` (used in CI & local dev), `inspect_test_safety()` only AST-scans `test*`/`conftest.py`/`setup.py` (ignoring imported app modules) and is bypassed via `importlib`, `getattr`, `os.execv`, or `builtins`. | `backend/app/verification/runner.py:38-114`, `backend/app/verification/sandbox.py:226-261` | Keep `SANDBOX_FAIL_CLOSED=True` and `SANDBOX_ALLOW_HOST_FALLBACK=False` strictly enforced in all non-local environments; run real Docker sandbox tests in CI. |
| **SEC-12** | **HIGH** | **Pre-Auth Webhook Replay Poisoning & Broken Per-Installation Secret:** `handle_incoming_webhook()` commits `WebhookDelivery` *before* verifying HMAC-SHA256 (unauthenticated DB fill / delivery-ID pre-burning). Per-installation `webhook_secret` is hashed rather than stored in `encrypted_credentials`, so decryption always returns `None`. | `backend/app/integrations/github/service.py:58-65,432,474-488` | Verify HMAC-SHA256 *before* persisting `WebhookDelivery`; store per-installation webhook secret encrypted in `encrypted_credentials` (or verify against global secret cleanly). |
| **SEC-13** | **HIGH** | **Nginx Header Stripping, Over-Permissive CSP & Unpinned Supply Chain:** `nginx/frontend.conf:25` drops all `server`-level security headers on static assets via `location`-level `add_header` and sets `connect-src 'self' http://* https://*`. `Dockerfile.worker` and `ci.yml` download Gitleaks without SHA-256 verification. `.gitleaks.toml` allowlists 5 entire directories (`tests/`, `scripts/`, `reports/`, `benchmark/`, `samples/`). All GitHub Actions and Docker base images use mutable tags. | `nginx/frontend.conf:16-27`, `nginx/production.conf:44,57-63`, `Dockerfile.worker:6-33`, `Dockerfile.api:9-26`, `.github/workflows/ci.yml`, `.gitleaks.toml:6-19` | Re-declare security headers in Nginx `location` blocks (or move `Cache-Control` via `map`); restrict `connect-src`; verify Gitleaks SHA-256; narrow `.gitleaks.toml` to specific fixture files; pin Docker digests and GitHub Action SHAs. |

### Medium Findings

| Finding ID | Severity | Description & Actual Evidence | Affected File Paths | Recommended Action |
| :--- | :--- | :--- | :--- | :--- |
| **SEC-14** | **MEDIUM** | **Cross-Tenant FK Reference Injection:** `POST /findings` checks `repo_id` ownership but not `scan_id`; `POST /evidence` checks `repository_id` but not `scan_id`, `verification_run_id`, or `finding_id`. | `backend/app/api/v1/endpoints/findings.py:115-161`, `backend/app/api/v1/endpoints/evidence.py:60-91` | Verify ownership and repository membership of every supplied optional FK ID. |
| **SEC-15** | **MEDIUM** | **Workspace Path Confinement & Stale Cleanup Bugs:** `startswith` prefix collision in `ingestion.py:97,378-380`; `delete_repository` calls `shutil.rmtree` without confinement check; `clean_stale_workspaces()` iterates user tenant dirs (`<root>/<user_id>`) and compares against nested `source` paths, risking deletion of active user workspaces. | `backend/app/core/ingestion.py:97,378-380`, `backend/app/api/v1/endpoints/repositories.py:491-492`, `backend/app/core/workspace_cleanup.py:46-70` | Use `Path.is_relative_to()` everywhere; validate `workspace_path` before `rmtree`; fix `clean_stale_workspaces()` to protect any dir containing an active scan path. |
| **SEC-16** | **MEDIUM** | **Session / JWT / Password Weaknesses:** 24h access tokens with unimplemented refresh tokens; JWT decode omits `require` claims & `iss`/`aud`; silent 72-byte bcrypt truncation vs 128-char schema; email enumeration (`422`) on `/auth/register`. | `backend/app/core/config.py:62-66`, `backend/app/core/security.py:20-67`, `backend/app/api/v1/endpoints/auth.py:35` | Enforce short-lived access tokens + refresh flow, JWT `require`/`iss`/`aud`, 72-byte password cap (or SHA-256 pre-hash), and uniform registration responses. |
| **SEC-17** | **MEDIUM** | **CSRF & Staging Security Bypass:** `verify_csrf_origin()` trusts `http://testserver` in production; `POST /auth/logout` omits CSRF check; `APP_ENV=staging` skips all production guards (CORS `null`, HSTS, TrustedHost, `cookie_secure`, `/docs`). | `backend/app/core/auth.py:47-102`, `backend/app/main.py:114-146`, `backend/app/core/config.py:187-262` | Restrict `testserver` to test/dev; enforce CSRF on `/logout`; apply production hardening to `staging` as well. |
| **SEC-18** | **MEDIUM** | **Prompt-Injection Bypasses & Unescaped Validation Prompt:** Case-sensitive `.replace("</untrusted_source_code>")` in `analyzer/prompts.py:63-64`; unescaped raw interpolation in `validation/ai_assistant.py:45-58`; `scanner_message`/`file_path` unscanned; `client.py` still sends injected content to Gemini. | `backend/app/analyzer/prompts.py:63-64`, `backend/app/analyzer/client.py:56`, `backend/app/validation/ai_assistant.py:45-58` | Use case-insensitive regex tag stripping, escape tags in `ai_assistant.py`, scan all untrusted metadata fields, and short-circuit or isolate on detected injection. |
| **SEC-19** | **MEDIUM** | **RBAC Inconsistency, Mass Assignment & Header Interpolation:** `POST /analyze-finding` uses `get_current_user` instead of `require_mutating_role`; `POST /repositories` accepts client-supplied `health_score`/counts; `Content-Disposition` interpolates raw IDs; `RequestSizeLimitMiddleware` bypassed by `Transfer-Encoding: chunked`. | `backend/app/api/v1/endpoints/analyzer.py:24`, `backend/app/api/v1/endpoints/repositories.py:73-87`, `backend/app/api/v1/endpoints/evidence.py:145,207`, `backend/app/core/security.py:116-139` | Require `require_mutating_role` on `/analyze-finding`; remove computed metrics from `RepositoryCreate`; sanitize `Content-Disposition` filenames; enforce chunked body limit. |
| **SEC-20** | **MEDIUM** | **Cloudflare `_headers` Over-Permissive `connect-src` & Worker Network Egress:** `frontend/public/_headers:2` permits `connect-src 'self' https: http://127.0.0.1:8001 http://localhost:8001`. `docker-compose.prod.yml` lacks `internal: true` on `redmercury_internal`, leaving worker egress unrestricted. `TRUSTED_PROXIES` is not set for Docker bridge IP, causing Nginx traffic to share one rate-limit bucket. | `frontend/public/_headers:2`, `docker-compose.prod.yml:1-5,51-59,96-97` | Lock `connect-src` to exact API origin; add `internal: true` to worker network; configure `TRUSTED_PROXIES` for Nginx container subnet. |

### Low / Informational Findings
- **SEC-21 (LOW):** `verify_verification_run_integrity` (`evidence/service.py:168`) uses `==` instead of `hmac.compare_digest`.
- **SEC-22 (LOW):** `Cache-Control: no-store` is only set on `/api/v1/auth/*`, not on sensitive findings/evidence endpoints (`core/security.py:94`).
- **SEC-23 (LOW):** `Dockerfile.api:50-60` grants runtime user write ownership of `/app/app` source code; `nginx` containers omit `server_tokens off;` and run as `root`.
- **SEC-24 (LOW):** `frontend/src/ai-security-analyzer/redactor.ts:37-46` has a stateful `/g` `lastIndex` bug and retains the first 4 characters of redacted secrets.
- **SEC-25 (INFO):** Dependency vulnerability audit (`pip-audit` / `npm audit`) was not executed against live advisories in this read-only offline audit, and `backend/requirements.txt` uses unpinned `>=` ranges without a lockfile.

---

## 10. Testing Results

### 10.1 Executed Test Suites (Non-Destructive, Observed Output)

| Suite | Command | Discovered | Passed | Failed | Skipped | Not Executable | Duration |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Backend (`pytest`)** | `python -m pytest tests/ -q --tb=short` (45 files) | 442 | **422** | **0** | **20** | 0 | 181.82s |
| **Frontend (`vitest`)** | `npm --prefix frontend run test` (6 files) | 41 | **41** | **0** | **0** | 0 | 10.36s |
| **Frontend TypeScript** | `npm --prefix frontend run lint` (`tsc --noEmit`) | — | **Pass** | **0 errors** | — | — | — |
| **Code Coverage** | Not available (`pytest-cov` / `@vitest/coverage-v8` not installed; Phase 0 forbids installing packages) | — | — | — | — | — | — |

### 10.2 Exact Breakdown of 20 Skipped Backend Tests
1. **`tests/test_live_docker_security_runtime.py` (13 skipped):** Live Docker daemon unavailable (`npipe:////./pipe/dockerDesktopLinuxEngine` not running).
2. **`tests/test_postgresql_integration.py` (3 skipped):** Live PostgreSQL instance unavailable (`TEST_POSTGRES_URL` not configured).
3. **`tests/test_sandbox.py` (2 skipped):** Live Docker daemon unavailable.
4. **`tests/test_scanners.py` (1 skipped):** Semgrep not installed on Windows (`requirements.txt` excludes Semgrep on `win32`).
5. **`tests/test_verification_security_hardening.py` (1 skipped):** Symlink creation requires Windows administrative privileges.

### 10.3 Missing Critical Test Scenarios & Test Quality Gaps
- **False-Positive Frontend Auth Test (`frontend/src/__tests__/App.test.tsx:252-261`):** Only passes because stubbed `fetch` returns HTTP 200 `{}`, bypassing both the auto-login success branch and the `defaultTester` catch fallback in `AuthContext.tsx`.
- **Zero Electron Tests:** No unit or security tests for `electron/main.cjs` or `electron/preload.cjs` (would have caught `SEC-04` path traversal and `decodeURI` crash).
- **Zero Frontend `services/api.ts` & `redactor.ts` Tests:** No unit tests for `ApiError`, 401/429 retry, `microCache`, host-gated auth, or secret redaction (`lastIndex` bug).
- **No CI Coverage of PostgreSQL or Live Docker Sandbox:** `.github/workflows/ci.yml:56-58` runs exclusively against SQLite with `SANDBOX_ALLOW_HOST_FALLBACK=true`.
- **No Regression Tests for Discovered Criticals:** Missing tests asserting `/ingest/local` is blocked in production, `/auth/register` cannot self-assign `admin`, `worker` boots under `APP_ENV=production`, `generate_findings_report(format="sarif")` returns valid SARIF JSON, and `validation/ai_assistant.py` invokes `GeminiAnalystClient` with valid method signatures.

---

## 11. Infrastructure & Deployment Assessment

| Area | Status | Evidence & Critical Findings |
| :--- | :--- | :--- |
| **Dockerfiles** | **NEEDS HARDENING** | `Dockerfile.api` & `Dockerfile.worker` use non-root users (`redmercury` UID 10001 / `worker` UID 10002), **but**: mutable base tags (`python:3.11-slim-bookworm`, `node:20-alpine`, `nginx:1.27-alpine`), unpinned `pip install`, unverified Gitleaks download (`Dockerfile.worker:6-33`), and `Dockerfile.api:78` runs `alembic upgrade head` inside container `CMD` (race condition on multi-replica boot). |
| **`docker-compose.prod.yml`** | **BROKEN (CRITICAL)** | **INFRA-01 (CRITICAL):** `worker` sets `APP_ENV: production` without `SECRET_KEY` or `CORS_ORIGINS`, causing immediate crash-loop in `config.py:194-231`. Missing `read_only: true` on `worker`; missing `cap_drop`/`no-new-privileges`/limits on `api`, `frontend`, `postgres`, `nginx`; `redmercury_internal` lacks `internal: true`; `TRUSTED_PROXIES` not configured for Nginx bridge IP. |
| **Nginx & SSL** | **NEEDS HARDENING** | `nginx/frontend.conf:25` strips all `server`-level security headers on static assets and sets `connect-src http://* https://*`. `nginx/production.conf` omits `server_tokens off;`, uses deprecated `listen 443 ssl http2;`, omits `limit_req_status 429;`, has a `50M` body limit vs FastAPI's `60MB`, and causes an HTTP→HTTPS redirect loop behind external TLS termination (`ssl/README.md`). |
| **Railway & Cloudflare Workers** | **INCOMPLETE** | `railway.toml` builds only `Dockerfile.api` (no worker service, no Docker daemon for fix verification sandbox). `config.py:42` hardcodes personal preview domain `red-mercury.dhineshkumardhina18.workers.dev`. `Dockerfile.frontend` copies Cloudflare's `wrangler.json` and `_headers` into Nginx webroot publicly. `VITE_API_BASE_URL` is undocumented. |
| **CI/CD Workflows** | **NEEDS HARDENING** | `.github/workflows/ci.yml` & `redmercury_pr_gate.yml` use unpinned Action tags (`@v4`/`@v5`/`@v7`), unverified Gitleaks download, over-broad `.gitleaks.toml` allowlists, and `ci_security_gate.py:272` skips `backend/requirements.txt` and Gitleaks. `redmercury-analysis.yml.example:56` has `${{ github.base_ref }}` shell interpolation. |

---

## 12. Reliability & Architecture Assessment

### Architectural Strengths
- Modular domain packaging (`scanner`, `prioritization`, `validation`, `analyzer`, `verification`, `evidence`, `integrations/github`).
- Fail-closed Docker sandbox design with thorough process-tree + container cleanup (`verification/sandbox.py`).
- Atomic in-memory patch dry-run and rollback on write failure (`verification/patch_applier.py`).
- O(1) 4-query batch context loader for prioritization (`prioritization/evaluator.py:145-259`).

### Architectural & Reliability Weaknesses

| Finding ID | Severity | Issue & Actual Evidence |
| :--- | :--- | :--- |
| **REL-01** | **HIGH** | **Background Job & Concurrency Architecture:** In-process `BackgroundTasks` (`scans.py:188-194`) loses in-flight scans on restart; non-atomic quota & duplicate-scan checks (`quotas.py:20-61`, `scans.py:130-137`) allow race bypasses; `cancel_scan` does not stop running subprocesses; `reconcile_interrupted_jobs` misses crashes < 15 minutes old and only runs at startup; `get_scan_status` omits `interrupted`/`cancelled` from `is_complete`. Unwired `scanner/worker.py` lacks atomic job claiming and duplicates `VerificationRun` rows (`worker.py:231-238`). |
| **REL-02** | **HIGH** | **Silent Runtime Bugs in Core Pipelines:** (1) `verification/service.py:159-169,306-316` reads nonexistent `NormalizedFinding` fields (`rule_id`, `line_number`, `message`), persisting empty findings snapshots; (2) `validation/ai_assistant.py:96-100` calls nonexistent `GeminiAnalystClient` methods (`AttributeError`); (3) `integrations/github/service.py:243` references unimported `Path` (`NameError`); (4) `evidence/service.py:239-366` returns Markdown when `SARIF` findings report is requested. |
| **REL-03** | **MEDIUM** | **Shared-Session Audit Commits & Missing Read-Endpoint Commits:** `record_audit_event()` (`core/audit.py:34-66`) commits/rolls back the caller's session, risking partial transactions; `evidence/service.py` audit writes on read endpoints rely on implicit commits. |
| **REL-04** | **MEDIUM** | **Scanner Duplication & Noise:** Overlapping static regex scanners (`iac_scanner`, `vuln_scanner`, `container_base_scanner`, `injection_scanner`, `owasp_scanner`) lack cross-scanner deduplication and contain dead/broken rules (`trivy_sca.py:175`, `owasp_scanner.py:62`). |
| **REL-05** | **MEDIUM** | **Deceptive UI Error Masking:** Multiple frontend screens (`AiSecurityAnalyzerScreen`, `SettingsPage`, `FindingDetailPage`, `FixVerificationScreen`, `EvidencePage`) mask backend errors or missing data with synthetic/hardcoded values instead of surfacing honest error/empty states. |

---

## 13. Documentation & Configuration Assessment

| Issue | Evidence | Impact |
| :--- | :--- | :--- |
| **Missing Tracked Env Templates** | `.gitignore:2-4` ignores `.env.production.example` and `.env.staging.example` (`git ls-files .env*` returns only `.env.example`), contradicting `README.md:273`. | Fresh clones cannot follow Docker production deployment instructions. |
| **Missing `LICENSE` File** | `README.md:474` links to `[LICENSE](LICENSE)`, which does not exist in the repo. | Broken link; unclear legal licensing terms. |
| **Port `8000` vs `8001` Contradiction** | `README.md:242-251,263` and `docs/API.md:3` specify port `8000`; `config.py:26`, `vite.config.ts:20`, `api.ts:494`, and PowerShell scripts use port `8001`. | Following `README.md` Quick Start breaks Vite dev proxy. |
| **Undocumented Critical Env Vars** | `OFFLINE_MODE` (defaults to `True`!), `ALLOWED_HOSTS`, `TRUSTED_PROXIES`, `ENCRYPTION_KEY`, `GITHUB_WEBHOOK_SECRET`, `CSRF_PROTECTION_ENABLED`, `SANDBOX_*`, `RATE_LIMIT_*`, `VITE_API_BASE_URL` missing from `.env.example` and `README.md`. | Users supplying `GEMINI_API_KEY` get silent offline fallback without knowing `OFFLINE_MODE=false` is required. |
| **Overstated Technical Claims** | `README.md` claims CVSS v3.1, EPSS, AST taint trace analysis (`analyzer/`), bounded AI diff patches, compiler checks, `appuser` container user, and SSL on `redmercury_frontend`. `reports/REDMERCURY_FINAL_READINESS_REPORT.md` declares high readiness while missing all CRITICAL findings above. | Misleads operators, reviewers, and enterprise buyers. |
| **Stale Docs & Broken Local Links** | Hardcoded `file:///c:/PROJECTS/dhina%20projects/Red Mercury%20AI/...` links in `docs/PRODUCTION_DEPLOYMENT_GUIDE.md`, `docs/VERIFICATION.md`, and `reports/`; `docs/API.md` omits most endpoints; `docs/AI_ANALYST.md` cites `gemini-1.5-flash`; `docs/DATABASE_MIGRATIONS.md` lists only `0001`. | Broken references across all non-author machines. |

---

## 14. Critical Missing Components

1. **Production-Safe Auth & Identity Lifecycle:** Removal of hardcoded credentials/auto-auth, non-admin registration default, DB-authoritative RBAC, short-lived access tokens + refresh tokens, and HttpOnly cookie session flow.
2. **Distributed Infrastructure Primitives:** Redis-backed rate limiting and a durable background job queue (Celery/RQ/Arq or properly locked Postgres queue worker) replacing in-process `BackgroundTasks`.
3. **Real Egress Isolation for Git Ingestion & Worker:** Network-level egress firewall (`internal: true` + egress proxy blocking private/metadata IPs) rather than invalid `git -c http.resolve`.
4. **Syntax & Compiler Gates in Fix Verification:** Explicit `py_compile`/`ast.parse` (and language-appropriate compiler checks) before declaring fixes verified.
5. **Cross-Scanner Deduplication & Honest Risk Modeling:** Either implement real CVSS v3.1 vector parsing and EPSS lookup, or remove those claims and document the actual deterministic factor model accurately.
6. **GitHub App Auth & Webhook-to-Scan Wiring:** RS256 JWT installation token exchange, Check Runs API for `block_pr_on_critical`, and wiring `pull_request` webhooks to `trigger_pr_security_scan`.
7. **Automated PostgreSQL, Docker Sandbox, and Electron CI Testing:** Real Postgres + Docker sandbox + Electron security test jobs in `.github/workflows/ci.yml`.

---

## 15. Prioritized Remediation Roadmap

### Priority 0 — Immediate Security & Crash Blockers (Must Fix Before Any Deployment)
1. **Fix `SEC-01`:** Disable `/api/v1/repositories/ingest/local` in production; fix symlink check before `resolve()`, block symlink dereferencing, enforce size/count limits.
2. **Fix `SEC-02`:** Remove `role` from `UserRegister` (default to `analyst`/`viewer`); stop overwriting ORM `user.role` from JWT in `get_current_user()`.
3. **Fix `SEC-03` & `SEC-08` & `SEC-09`:** Purge hardcoded credentials (`dhineshkumardhina@gmail.com` / `XerovaDevPass2026!`) and `defaultTester` auto-auth from frontend and backend `main.py`; remove silent auto-registration in `AuthContext.login()`; remove `setAuthToken(null)` in `FindingsPage.loadData`.
4. **Fix `SEC-04` & `SEC-10`:** Add strict `path.resolve` containment and `try/catch` around `decodeURI` in `electron/main.cjs`; enable `sandbox: true`, `will-navigate` allowlist, IPC origin validation, and `shell: false` for Python spawn.
5. **Fix `INFRA-01`:** Pass `SECRET_KEY` and `CORS_ORIGINS` (or decouple worker config validation) in `docker-compose.prod.yml` so `worker` boots cleanly.

### Priority 1 — High Security, Reliability & Correctness Fixes
6. **Fix `SEC-05` & `SEC-06`:** Stream-bounded ZIP extraction; egress-isolated `git clone` (remove invalid `-c http.resolve`).
7. **Fix `SEC-07` & `SEC-17`:** Redis rate limiting; rightmost untrusted `X-Forwarded-For`; throttle verification/validation/webhook/logout; validate token before revoking; enforce CSRF on `/logout`; harden `APP_ENV=staging`.
8. **Fix `SEC-12` & `REL-02`:** Verify webhook HMAC *before* persisting `WebhookDelivery`; fix per-installation webhook secret storage; fix `verification/service.py` `NormalizedFinding` attribute names; fix `validation/ai_assistant.py` Gemini client calls; fix `Path` import in `integrations/github/service.py:243`; implement `SARIF` branch in `generate_findings_report`.
9. **Fix `SEC-13` & `SEC-20`:** Fix Nginx header inheritance and CSP in `nginx/frontend.conf` and `frontend/public/_headers`; set `TRUSTED_PROXIES` for Docker Nginx; add `internal: true` to worker network; verify Gitleaks SHA-256; pin Docker digests and GitHub Actions SHAs; narrow `.gitleaks.toml`.

### Priority 2 — Architectural Reliability, Honesty & Quality
10. **Fix `REL-01` & `SEC-14`/`SEC-15`:** Unify async scan execution onto a single durable worker queue with atomic job claiming and periodic stale-job reconciliation; fix cross-tenant FK checks and `clean_stale_workspaces()`.
11. **Fix `SEC-18` & `REL-05`:** Harden prompt-injection escaping (case-insensitive, metadata scanning, `ai_assistant.py` escaping); remove deceptive synthetic/hardcoded fallbacks from frontend screens (`FindingDetailPage`, `SettingsPage`, `AiSecurityAnalyzerScreen`, `FixVerificationScreen`, `EvidencePage`).
12. **Clean Up Scanners, Benchmarks & Docs:** Remove/label placeholder scanners (`iast_scanner`, `pentest_scanner`); remove simulated `B3_ai_judge` from benchmark claims; track `.env.production.example`/`.env.staging.example` in Git; add `LICENSE`; reconcile `README.md` and `docs/` with actual implementation (ports, env vars, features).

---

## 16. Recommended Phase 1 Scope

**Phase 1 Goal: Security Hardening, Critical Bug Elimination & Staging Readiness**

Keep Phase 1 tightly scoped and verifiable (no new features, no architectural rewrites):
1. **Auth, RBAC & Frontend Auth Cleanup:** Remediate `SEC-02`, `SEC-03`, `SEC-08`, `SEC-09`, `SEC-14`, `SEC-17`.
2. **Ingestion & Electron Security Hardening:** Remediate `SEC-01`, `SEC-04`, `SEC-05`, `SEC-06`, `SEC-10`, `SEC-15`.
3. **Core Pipeline Bug Fixes:** Remediate `REL-02` (verification attribute mapping, validation Gemini client call, GitHub `Path` import & webhook HMAC order, findings SARIF export) and `INFRA-01` (`docker-compose.prod.yml` worker startup + Nginx headers + `TRUSTED_PROXIES`).
4. **Honest UI & Documentation Sync:** Remove hardcoded fake taint traces/health telemetry in frontend; untrack/fix `.gitignore` for `.env.*.example`; align `README.md` port (`8001`), `OFFLINE_MODE`, and feature claims with reality.
5. **Phase 1 Verification Gate:** Add targeted regression tests for every remediated CRITICAL/HIGH finding and run CI against PostgreSQL + Docker sandbox.

---

## 17. Evidence and Verification References

- **Git State:** `git status -sb` (`## main...origin/main`), `git log -n 10 --oneline` (HEAD `b9df7b9`), `git ls-files .env* *.db* bin/ ssl/ backend/data/ frontend/.wrangler/`.
- **Backend Tests:** `python -m pytest tests/ -q --tb=short` — **442 collected, 422 passed, 0 failed, 20 skipped** (181.82s, Python 3.14.7, pytest 9.1.1).
- **Frontend Tests & Type Check:** `npm --prefix frontend run lint` (`tsc --noEmit` — 0 errors); `npm --prefix frontend run test` (`vitest run` — **6 files, 41 passed, 0 failed**, 10.36s).
- **Environment Constraints Disclosed:**
  - Live Docker daemon not running on audit host (15 Docker/sandbox tests skipped).
  - Live PostgreSQL instance not running / `TEST_POSTGRES_URL` unset (3 Postgres tests skipped).
  - Semgrep not installed on Windows (1 test skipped); Windows non-admin symlink test skipped (1 test).
  - Coverage plugins (`pytest-cov`, `@vitest/coverage-v8`) not installed (coverage % not measurable without installing dependencies).
  - Live Gemini API calls and live GitHub API calls were not executed (read-only audit without modifying env/secrets).
  - `.env` and `.env.production` contents were intentionally not read or disclosed.

---

## 18. Final Assessment & Scoring

### Scoring Methodology
Each dimension is scored on a **0–100 scale** based strictly on verified repository evidence (code inspection + non-destructive test execution):
- **90–100:** Production-grade, verified end-to-end, minimal/no high-severity gaps.
- **75–89:** Solid implementation with minor/medium gaps addressable without structural changes.
- **55–74:** Meaningful working core, but undermined by significant bugs, incomplete integrations, or high-severity gaps.
- **35–54:** Major security, reliability, or completeness blockers preventing safe deployment.
- **0–34:** Non-functional, placeholder-dominated, or critically unsafe.

### Dimension Scores

| Dimension | Score (0–100) | Evidence-Based Justification |
| :--- | :---: | :--- |
| **Functional Completeness** | **62 / 100** | Core scanning (Bandit, pip-audit, Semgrep, Gitleaks), deterministic prioritization, validation, Docker fix verification, and SHA-256 evidence work well. Penalized for unimplemented EPSS/CVSS v3.1/compiler checks/GitHub App/webhook auto-scan, placeholder IAST/Pentest scanners, broken findings SARIF export, and broken `validation/ai_assistant.py`. |
| **Backend Quality** | **68 / 100** | Clean modular FastAPI/SQLAlchemy/Alembic design, parameterized ORM queries, RFC Problem JSON, strong headers/logging. Penalized for critical auth/ingestion defects, unwired/racing `worker.py` vs `BackgroundTasks`, shared-session audit commits, and silent attribute/`NameError` bugs. |
| **Frontend Quality** | **54 / 100** | Clean React 19 / Tailwind v4 architecture, zero XSS sinks, passing Vitest & `tsc` checks. Heavily penalized for hardcoded credentials/auto-auth, silent auto-registration, `FindingsPage` session wipe, pervasive synthetic/hardcoded UI fallbacks, `strict: false`, and Electron path traversal + disabled sandbox. |
| **Application Security** | **38 / 100** | Strong foundational pieces (Docker fail-closed sandbox, secret scrubbing, parameterized ORM, Fernet crypto, HMAC webhook math), **but** severely compromised by 4 CRITICAL vulnerabilities (unrestricted local ingest, admin self-registration, hardcoded frontend creds/auto-auth, Electron arbitrary file read) and 9 HIGH findings. |
| **AI Integration** | **48 / 100** | Functional Gemini REST client (with secure header auth & solid deterministic fallback) and strict human-in-the-loop patch policy. Penalized for `OFFLINE_MODE=True` default, broken `validation/ai_assistant.py`, prompt-injection tag-breakout/unescaped-prompt flaws, disconnected toy ML experiment, and simulated/leaking `B3_ai_judge` benchmark baseline. |
| **Testing Maturity** | **70 / 100** | Strong volume and pass rate (463 passing tests, 0 failures) across auth, API, scanners, verification, evidence, and prompt injection. Penalized for zero Electron tests, zero frontend `api.ts`/`redactor.ts` tests, false-positive frontend auth test, no CI PostgreSQL/Docker sandbox coverage, and missing coverage tooling. |
| **Infrastructure Maturity** | **42 / 100** | Multi-stage non-root Dockerfiles and Nginx TLS configs exist, but `docker-compose.prod.yml` worker crash-loops on boot, `TRUSTED_PROXIES` breaks rate limiting, Nginx strips headers on static assets, `alembic upgrade head` races on multi-replica boot, and CI/Docker supply chain artifacts are unpinned/unverified. |
| **Documentation Quality** | **55 / 100** | Extensive `docs/` and `reports/` coverage, but marred by significant drift: `8000` vs `8001` port conflict, gitignored `.env.*.example`, missing `LICENSE`, undocumented `OFFLINE_MODE`, broken local Windows `file:///` links, and overstated README/readiness claims. |
| **Production Readiness** | **32 / 100** | High internal test pass counts and historical readiness reports (`reports/REDMERCURY_FINAL_READINESS_REPORT.md`) **do not equate to production readiness**. The system cannot be safely deployed to production until all P0 security and infrastructure blockers are resolved and verified against live PostgreSQL and Docker sandbox environments. |

### Overall Recommendation

> **RECOMMENDATION: NO-GO**
>
> Red Mercury has a genuinely capable engineering foundation for local AppSec workflows and automated fix verification, but it is **NOT ready for staging or production deployment**. Resolve the Priority 0 security blockers (`SEC-01` through `SEC-04`, `SEC-08`, `SEC-09`, `SEC-10`) and the production worker crash-loop (`INFRA-01`) in Phase 1, then re-verify with live PostgreSQL and Docker sandbox test runs before reconsidering a staging release.
