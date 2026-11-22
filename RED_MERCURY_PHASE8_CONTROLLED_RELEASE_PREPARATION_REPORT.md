# RED MERCURY — PHASE 8
## CONTROLLED RELEASE PREPARATION & EXTERNAL DEPLOYMENT READINESS AUDIT REPORT

**Repository:** `https://github.com/Dhineshkumardhina/Red-Mercury`  
**Product:** Red Mercury — Enterprise Application Security & Automated Fix Verification Engine  
**Organization:** Xerova Digital Solutions  
**Current Branch:** `main`  
**Baseline HEAD:** `b9df7b9650e0ba431e8d32b19edf30ddd6f6289c`  
**Scope:** Phases 0–7G Preserved Working Tree  

---

## 1. Executive Summary

Phase 8 performed a comprehensive, read-only release preparation and external deployment readiness audit across all preserved Phase 0–7G changes in the Red Mercury repository.

- **Repository & Diff Integrity:** Verified `main` at `b9df7b9650e0ba431e8d32b19edf30ddd6f6289c` with `105` working-tree entries (`69` modified tracked files, `36` untracked files; `5,947` insertions, `2,324` deletions across tracked diffs). Zero destructive Git commands, commits, or pushes were executed.
- **Secret Scanning & Sensitive Files:** Zero real secrets, private keys, database dumps, or runtime logs were found in tracked diffs or untracked release candidates. Only synthetic test fixtures exist in `tests/` (excluded via `.gitleaks.toml` and `.github/secret_scanning.yml`). Local `.env` and `*.db` remain excluded by `.gitignore`.
- **Application & Distributed Transaction Readiness:** Local backend (`630 passed, 2 skipped` on live PostgreSQL 16 + Redis 7), frontend (`46 passed`, `tsc --noEmit`, `vite build`), Electron (`10 passed`), Docker Compose (`config -q`), and CI-equivalent Bandit (`-ll -ii`, 0 issues) all pass.
- **External Infrastructure Blockers:** Four external prerequisites remain unprovisioned/unverified outside the local workspace: (1) external SSRF-filtering Git egress proxy (`GIT_EGRESS_PROXY_URL`), (2) production TLS certificate/key/chain, (3) production secrets injection (`SECRET_KEY`, `POSTGRES_PASSWORD`, `GITHUB_WEBHOOK_SECRET`, optional `ENCRYPTION_KEY`/`GEMINI_API_KEY`), and (4) live remote GitHub Actions CI execution.
- **Final Approval Classification:**
  - A. Application Code Readiness: **READY**
  - B. Security and Distributed Transaction Readiness: **READY**
  - C. Operational Infrastructure Readiness: **BLOCKED**
  - D. Overall Release Approval Readiness: **CONDITIONALLY READY** (ready for user-approved commit/push to trigger remote CI; production deployment blocked pending external infrastructure provisioning)

---

## 2. Repository State Verification

Executed read-only Git verification against `c:\PROJECTS\dhina projects\Red Mercury\Red Mercury`:

- **Branch:** `main` (matches expected `main`)
- **HEAD Commit:** `b9df7b9650e0ba431e8d32b19edf30ddd6f6289c` (`fix(alembic): widen alembic_version.version_num to VARCHAR(128) on PostgreSQL`)
- **Existing Git Tags:** None (`git tag -l` returned empty)
- **Working Tree Counts (`git status --untracked-files=all --short`):**
  - Total entries: `105`
  - Modified tracked files (`M`): `69`
  - Untracked files (`??`): `36`
- **Preservation Confirmation:** Zero `reset`, `clean`, `checkout`, `rebase`, `merge`, `commit`, or `push` commands were executed.

---

## 3. Complete File Inventory (Phase 8A)

All `105` working-tree entries are classified below:

### 3.1 Application Source Code (`43` files: `40` modified, `3` untracked)
- **Modified (`40`):**
  - `backend/app/analyzer/client.py`, `backend/app/api/v1/endpoints/{analyzer,auth,evidence,findings,health,repositories,scans,verification}.py`
  - `backend/app/core/{audit,auth,config,ingestion,quotas,security,workspace_cleanup}.py`
  - `backend/app/evidence/service.py`, `backend/app/integrations/github/{service,webhook}.py`, `backend/app/main.py`
  - `backend/app/models/{__init__,token,user}.py`
  - `backend/app/scanner/{bandit,base,gitleaks,pip_audit,runner,semgrep,worker}.py`
  - `backend/app/schemas/{auth,scan,verification}.py`
  - `backend/app/validation/{ai_assistant,service}.py`, `backend/app/verification/{sandbox,service,workspace}.py`
  - `backend/requirements.txt`
  - `frontend/src/context/AuthContext.tsx`, `frontend/src/pages/{FindingsPage,LoginPage,SettingsPage}.tsx`, `frontend/src/services/api.ts`, `frontend/package.json`, `frontend/package-lock.json`
- **Untracked (`3`):**
  - `backend/app/core/jobs.py`, `backend/app/models/job.py`, `electron/security.cjs`
- **Release Disposition:** Belongs in release. Verified by backend, frontend, and Electron suites.

### 3.2 Backend Tests (`19` files: `8` modified, `11` untracked)
- **Modified (`8`):** `tests/conftest.py`, `tests/test_{api_reliability_and_resilience,auth,authorization,evidence_traceability,health,migration_consistency,production_readiness}.py`
- **Untracked (`11`):** `tests/test_phase{1_security_remediation,2_ingestion_ssrf_security,3_auth_session_ratelimit,4_core_pipeline_tenant_security,5_deployment_security,6_durable_job_execution,7_production_deployment_verification,7a_distributed_security_hardening,7c_targeted_remediation,7e_transaction_fencing,7g_cleanup_isolation}.py`
- **Release Disposition:** Belongs in release. Verified (`630 passed, 2 skipped`).

### 3.3 Frontend Tests (`2` files: `1` modified, `1` untracked)
- **Modified (`1`):** `frontend/src/__tests__/App.test.tsx`
- **Untracked (`1`):** `frontend/src/__tests__/AuthSecurity.test.tsx`
- **Release Disposition:** Belongs in release. Verified (`46 passed`).

### 3.4 Electron Tests (`2` files: `1` modified, `1` untracked)
- **Modified (`1`):** `electron/main.cjs` (source/hardening), **Untracked (`1`):** `electron/security.test.cjs`
- **Release Disposition:** Belongs in release. Verified (`10 passed`).

### 3.5 Database Migrations (`3` files: `1` modified, `2` untracked)
- **Modified (`1`):** `backend/alembic/env.py`
- **Untracked (`2`):** `backend/alembic/versions/0013_add_refresh_token_sessions.py`, `backend/alembic/versions/0014_add_durable_jobs_and_outbox.py`
- **Release Disposition:** Belongs in release. Verified linear chain (`0001` -> `0014`) and live PostgreSQL 16 `alembic upgrade head`.

### 3.6 Docker & Infrastructure Configuration (`8` files: `7` modified, `1` untracked)
- **Modified (`7`):** `.env.example`, `Dockerfile.api`, `Dockerfile.frontend`, `Dockerfile.worker`, `docker-compose.prod.yml`, `nginx/frontend.conf`, `nginx/production.conf`, `frontend/public/_headers` (listed here as edge/static header config)
- **Untracked (`1`):** `.dockerignore`
- **Release Disposition:** Belongs in release. Verified via `docker compose -f docker-compose.prod.yml config -q` and Phase 5/7 container/Nginx tests.

### 3.7 CI/CD Workflows (`3` files: `3` modified, `0` untracked)
- **Modified (`3`):** `.github/workflows/ci.yml`, `.github/workflows/redmercury-analysis.yml.example`, `.github/workflows/redmercury_pr_gate.yml`
- **Release Disposition:** Belongs in release. Remote execution remains `NOT VERIFIED` until user-approved push.

### 3.8 Security Policies & Configuration (`3` files: `1` modified, `2` untracked)
- **Modified (`1`):** `.gitleaks.toml`
- **Untracked (`2`):** `.github/secret_scanning.yml`, `backend/app/scanner/rules/redmercury_default.yml`
- **Release Disposition:** Belongs in release.

### 3.9 Phase Reports & Audit Documentation (`15` files: `0` modified, `15` untracked)
- `RED_MERCURY_PHASE0_COMPLETE_REPOSITORY_AUDIT.md`
- `RED_MERCURY_PHASE1_SECURITY_REMEDIATION_REPORT.md`
- `RED_MERCURY_PHASE2_INGESTION_SSRF_SECURITY_REPORT.md`
- `RED_MERCURY_PHASE3_AUTH_SESSION_SECURITY_REPORT.md`
- `RED_MERCURY_PHASE4_CORE_PIPELINE_TENANT_SECURITY_REPORT.md`
- `RED_MERCURY_PHASE5_DEPLOYMENT_SECURITY_REPORT.md`
- `RED_MERCURY_PHASE6_DURABLE_JOB_RELIABILITY_REPORT.md`
- `RED_MERCURY_PHASE7_PRODUCTION_DEPLOYMENT_VERIFICATION_REPORT.md`
- `RED_MERCURY_PHASE7A_FINAL_DISTRIBUTED_SECURITY_HARDENING_REPORT.md`
- `RED_MERCURY_PHASE7B_INDEPENDENT_ADVERSARIAL_SECURITY_AUDIT_REPORT.md`
- `RED_MERCURY_PHASE7C_TARGETED_SECURITY_REMEDIATION_REPORT.md`
- `RED_MERCURY_PHASE7D_INDEPENDENT_REMEDIATION_VERIFICATION_REPORT.md`
- `RED_MERCURY_PHASE7E_TARGETED_TRANSACTION_FENCING_REMEDIATION_REPORT.md`
- `RED_MERCURY_PHASE7F_FINAL_RELEASE_CANDIDATE_SECURITY_AUDIT_REPORT.md`
- `RED_MERCURY_PHASE7G_CLEANUP_ISOLATION_REMEDIATION_REPORT.md`
- **Release Disposition:** Audit documentation (all 15 reports preserved untouched; Phase 8 adds `RED_MERCURY_PHASE8_CONTROLLED_RELEASE_PREPARATION_REPORT.md`).

### 3.10–3.13 Generated Artifacts, Local Env, Potentially Sensitive, Unknown (`0` tracked/untracked release-polluting files)
- **Generated Artifacts:** `0` unignored artifacts (`frontend/dist`, `.pytest_cache`, `__pycache__`, `node_modules`, `.venv`, `.redmercury_artifacts/` are excluded by `.gitignore`).
- **Local Environment Files:** `.env` exists locally only and is strictly excluded by `.gitignore` (never read or staged). `.env.example` contains only placeholder/dev-safe defaults.
- **Potentially Sensitive Files:** `0` real keys, certs, DB dumps, or logs in the working tree (`*.db`, `*.pem`, `*.key`, `*.crt`, `*.pfx`, `*.log`, `*.exe` are ignored by `.gitignore`).
- **Unknown / Unexplained Files:** `0`.

---

## 4. Git Diff Summary

- **Tracked Diff Scope (`git diff --stat`):** `69 files changed, 5,947 insertions(+), 2,324 deletions(-)` (with `1,552` insertions / lockfile churn in `frontend/package-lock.json`).
- **Untracked Additions:** `36` files (`15` phase reports, `11` phase test files, `1` frontend test, `1` electron test, `1` electron security module, `2` backend durable-job modules, `2` Alembic migrations, `1` Semgrep default ruleset, `1` `.dockerignore`, `1` `.github/secret_scanning.yml`).
- **Line-Ending Note:** Windows `core.autocrlf` emitted standard LF-to-CRLF warnings on several files; no unintended binary or whitespace corruption observed.

---

## 5. Sensitive-File & Secret-Scanning Findings (Phase 8B)

- **`.gitignore` Audit:** Properly excludes `.env`, `.env.*` (except `!.env.example`), `*.pem`, `*.key`, `*.cert`, `*.crt`, `*.pfx`, `ssl/*.key|crt|pem`, `*.db`, `*.sqlite*`, `*.log`, `.redmercury_artifacts/`, `data/`, `backend/data/`, `frontend/dist/`, `dist-electron/`, `.wrangler/`, `.dev.vars*`, `*.exe`.
- **`.env.example` Audit:** Contains only non-production placeholders (`dev-insecure-secret-key-replace-in-production!!`, `sqlite:///./redmercury.db`, `CHANGE_ME_PASSWORD`).
- **Diff & Untracked Secret Pattern Scan:**
  - `tests/test_phase4_core_pipeline_tenant_security.py` contains a synthetic test token (`ghp_12...1234`, len=40) used solely to verify secret masking/redaction.
  - `tests/test_evidence_traceability.py:126,135` uses concatenated/synthetic test values (`"whsec_" + "abcdefghijklmnopqrstuvwxyz012345"`, `FAKE_STRIPE_KEY_FOR_TESTING_ONLY`).
  - `.gitleaks.toml` narrowly allowlists only synthetic test fixture files and phase reports; `.github/secret_scanning.yml` ignores `tests/**`, `benchmark/**`, `samples/**`.
  - **Real Credential Exposure:** **NONE DETECTED**. No rotation required.
- **Note on `gitleaks` CLI:** Not installed locally on Windows; CI workflow `.github/workflows/ci.yml` downloads `gitleaks` v`8.18.2` with SHA-256 verification (`6298c9235dfc9278c14b28afd9b7fa4e6f4a289cb1974bd27949fc1e9122bdee`) and executes `gitleaks detect --verbose --redact`.

---

## 6. Application Change Review (Phase 8C)

Reviewed core modified/new modules and configurations against all 10 Phase 8C criteria:

1. **`backend/app/core/jobs.py` (Phase 6, 7A, 7C, 7E, 7G):**
   - Implements PostgreSQL `FOR UPDATE SKIP LOCKED` claiming, `before_commit` + nested savepoint lease-fencing listeners, and Phase 7G job-scoped `_clear_fenced_leases_for_job(session, job_id)` cleanup.
   - `_clear_all_fenced_leases(session)` is invoked exclusively on outer transaction end (`getattr(transaction, "parent", None) is None`).
   - `record_job_runtime_artifacts()` and `get_job_operational_metrics()` do not clear active transaction fencing.
   - **Bandit B608 Note:** `python -m bandit -r backend/app -ll` flags `jobs.py:792` (`B608`, Severity: Medium, Confidence: Low) due to `f"... {type_clause} ..."`. Direct inspection confirms `type_clause` only interpolates static bind parameter names (`:jt_0`, `:jt_1`, ...) with values bound via `params`. `python -m bandit -r backend/app -ll -ii` (used by `ci.yml`) reports **0 issues**.
2. **`backend/app/core/config.py`:**
   - `validate_production_configuration()` enforces `is_strict_env` (`production`/`staging`): rejects `dev-insecure` / `<32`-char `SECRET_KEY`, rejects `sqlite` `DATABASE_URL`, prohibits `*` or `null` in `CORS_ORIGINS`, prohibits `*` in `ALLOWED_HOSTS`, enforces `ALLOW_PRIVATE_NETWORKS=False`, `DEBUG=False`, `CSRF_PROTECTION_ENABLED=True`, `AUTH_RATE_LIMITING_ENABLED=True`, `SANDBOX_FAIL_CLOSED=True`, and non-empty `LOCAL_INGESTION_ALLOWED_ROOTS` if local ingestion is enabled.
3. **`backend/app/core/ingestion.py`, `backend/app/core/audit.py`, `backend/app/api/v1/endpoints/repositories.py`:**
   - Fail-closed SSRF egress validation (`GIT_EGRESS_PROXY_URL` required in production for public Git ingestion), path traversal & symlink containment, archive depth limits (`MAX_NESTED_ARCHIVES=5`), and audit event persistence.
4. **Frontend & Electron (`frontend/src/*`, `electron/main.cjs`, `electron/security.cjs`):**
   - HttpOnly cookie auth + CSRF header (`X-CSRF-Token`), no JWT in `localStorage`, SPA HTML fallback detection, Electron `contextIsolation`, `sandbox`, `shell:false`, and `will-navigate` origin guards.
5. **Result:** No accidental unrelated modifications, duplicate/conflicting implementations, missing imports, test-only behavior in production, weakened controls, or dev credentials in production defaults were found.

---

## 7. Database Migration Review

- **Chain:** Strictly linear 14-revision sequence from `0001_initial_schema` through `0014_add_durable_jobs_and_outbox` (`tests/test_migration_consistency.py` verified single head).
- **`backend/alembic/env.py`:** Uses PostgreSQL advisory lock (`pg_advisory_lock(72839104)`) to serialize multi-replica migrations and widens `alembic_version.version_num` to `VARCHAR(128)` before running migrations.

---

## 8. Infrastructure Configuration Review (Phase 8D)

### 8.1 Git Egress Proxy
- `docker-compose.prod.yml` isolates `api` on `redmercury_internal` (`internal: true`) and `worker` on `redmercury_worker_isolated` (`internal: true`, `NO_PROXY="*"`).
- Public Git ingestion fails closed unless `GIT_EGRESS_PROXY_URL` is provisioned with an external SSRF-filtering forward proxy (e.g., Smokescreen) performing connection-time DNS resolution, private/loopback/link-local blocking, and redirect validation.
- **Status:** **BLOCKED** — External proxy not provisioned or tested live.

### 8.2 Production TLS
- `nginx/production.conf` enforces HTTP->HTTPS 301 redirect (except health endpoints), TLSv1.2 + TLSv1.3, AEAD ciphers, `server_tokens off`, HSTS, CSP, and mounts `/etc/nginx/ssl/redmercury.crt` & `/etc/nginx/ssl/redmercury.key` from `./ssl`.
- **Status:** **BLOCKED** — Production certificate, private key, chain, and renewal automation not provisioned locally.

### 8.3 Production Secrets
- Required runtime secrets (must be injected via secret manager / vault, never committed):
  - `SECRET_KEY` (32+ char CSPRNG)
  - `POSTGRES_PASSWORD` (required by `docker-compose.prod.yml` `${POSTGRES_PASSWORD:?...}`)
  - `GITHUB_WEBHOOK_SECRET` (dedicated HMAC secret)
  - Optional: `ENCRYPTION_KEY`, `GEMINI_API_KEY`
- **Status:** **BLOCKED** — Production secrets not provisioned.

### 8.4 Remote CI/CD (`.github/workflows/ci.yml`)
- Least-privilege `permissions: contents: read`, SHA-pinned GitHub Actions and service images (`postgres:16-alpine`, `redis:7-alpine`), concurrency cancellation, backend tests + migrations, frontend lint/test/build + Electron tests, Gitleaks (SHA-256 verified), `pip_audit`, `npm audit --audit-level=high`, `bandit -r backend/app -ll -ii`, Docker builds (`Dockerfile.api`, `Dockerfile.worker`, `Dockerfile.frontend`), `docker compose -f docker-compose.prod.yml config -q`, and `mandatory-release-gate`.
- **Status:** **NOT VERIFIED** — Local inspection passed; remote execution cannot be verified until an approved push triggers GitHub Actions.

---

## 9. Security Control Verification

All Phase 1–7G controls remain intact and verified by automated suites:
- Auth/session rotation, HttpOnly cookies, CSRF double-submit, Redis/in-memory rate limiting (`test_phase3_auth_session_ratelimit.py`, `AuthSecurity.test.tsx`).
- SSRF fail-closed ingestion, archive bomb/symlink defenses (`test_phase2_ingestion_ssrf_security.py`).
- Tenant isolation & evidence redaction (`test_phase4_core_pipeline_tenant_security.py`, `test_evidence_traceability.py`).
- Container hardening & Nginx headers (`test_phase5_deployment_security.py`, `test_live_docker_security_runtime.py`).
- Durable job `SKIP LOCKED`, heartbeat/lease recovery, savepoint-aware fencing, and job-scoped cleanup isolation (`test_phase6`, `test_phase7a`, `test_phase7c`, `test_phase7e`, `test_phase7g`).

---

## 10. Regression Test Results (Phase 8E)

| Suite / Check | Exact Command | Result & Counts | Exit Code | Notes |
|---|---|---|---|---|
| Backend Full Suite (Live PG 16 & Redis 7) | `python -m pytest tests/ -q --tb=short` | `630 passed, 2 skipped` in `269.77s` | `0` | Executed at end of Phase 7G with no subsequent code edits; `rm_test_postgres` + `rm_test_redis` active; cleared 3 stale `queued` rows in shared `test_redmercury` prior to run |
| Frontend Unit & Journey | `npm --prefix frontend run test` | `7 test files, 46 passed` in `11.14s` | `0` | Executed in Phase 8E |
| Frontend TypeScript | `npm --prefix frontend run lint` | Passed (`tsc --noEmit`) | `0` | Executed in Phase 8E |
| Frontend Build | `npm --prefix frontend run build` | Passed (`vite build`, `1644 modules`) | `0` | Executed in Phase 8E |
| Electron Security | `node --test electron/security.test.cjs` | `10 passed, 0 failed` | `0` | Executed in Phase 8E |
| Static Security (Strict `-ll`) | `python -m bandit -r backend/app -ll` | `0 High, 1 Medium (Low conf B608 false positive at jobs.py:792)` | `1` | Parameterized `:jt_i` placeholders; verified safe |
| Static Security (CI `-ll -ii`) | `python -m bandit -r backend/app -ll -ii` | `No issues identified` (`21,819` LOC) | `0` | Matches `.github/workflows/ci.yml:201` |
| Docker Compose Prod | `docker compose -f docker-compose.prod.yml config -q` | Validated cleanly | `0` | Validated with dummy CI env vars |
| Remote GitHub Actions | `.github/workflows/ci.yml` | **NOT VERIFIED** | N/A | Requires user-approved push |

---

## 11. External Infrastructure Blockers

1. **External SSRF-Filtering Git Egress Proxy:** `GIT_EGRESS_PROXY_URL` unprovisioned and untested against a live proxy.
2. **Production TLS Certificates:** `./ssl/redmercury.crt` and `./ssl/redmercury.key` + chain/renewal not provisioned.
3. **Production Secrets:** `SECRET_KEY`, `POSTGRES_PASSWORD`, `GITHUB_WEBHOOK_SECRET` (and optional `ENCRYPTION_KEY`/`GEMINI_API_KEY`) not injected from a production vault.
4. **Remote CI/CD Execution:** `.github/workflows/ci.yml` has not yet run on the accumulated Phase 0–7G changes.

---

## 12. Release Manifest (Phase 8F)

- **Product:** Red Mercury (`Xerova Digital Solutions`)
- **Repository:** `https://github.com/Dhineshkumardhina/Red-Mercury`
- **Branch / Baseline HEAD:** `main` / `b9df7b9650e0ba431e8d32b19edf30ddd6f6289c`
- **Observed Version Metadata:** Backend `APP_VERSION="0.1.0"`, Frontend `package.json` `"version": "1.0.0"`, Git tags: none
- **Recommended Staging Tag (post-approved commit & green remote CI):** `v0.1.0-rc.1` (release candidate; do not tag production `v0.1.0` until external infrastructure blockers are cleared)
- **Scope Included:** Phases 0–7G (Auth/CSRF/Rate-limiting, SSRF & Ingestion Hardening, Tenant/Evidence Redaction, Container/Nginx/Electron Hardening, Durable Jobs & Outbox `0013`–`0014`, Lease-Fencing + Nested Savepoint Promotion + Job-Scoped Cleanup Isolation)
- **Database Migrations:** `0001_initial_schema` -> `0014_add_durable_jobs_and_outbox`
- **Known Limitations:** Live Git egress proxy, production TLS, production secrets, and remote GitHub Actions run are external to this workspace.

---

## 13. Rollback Considerations

- **Application Rollback:** Prior to committing, all Phase 0–7G work is uncommitted on `main` (`b9df7b9650e0ba431e8d32b19edf30ddd6f6289c`). After an approved release commit, standard `git revert` or container image tag rollback applies.
- **Database Migration Rollback:** `0013_add_refresh_token_sessions` and `0014_add_durable_jobs_and_outbox` implement `downgrade()` paths (verified in `tests/test_migration_consistency.py`); production rollback must drain active durable jobs before downgrading schema.

---

## 14. Four-Part Readiness Decision (Phase 8G)

| Dimension | Classification | Justification |
|---|---|---|
| **A. Application Code Readiness** | **READY** | All 630 backend tests, 46 frontend tests, 10 Electron tests, `tsc`, `vite build`, Compose config, and CI Bandit pass with zero regressions. |
| **B. Security and Distributed Transaction Readiness** | **READY** | Phase 0–7G security controls, `FOR UPDATE SKIP LOCKED`, savepoint-aware lease fencing, and job-scoped cleanup isolation verified on live PostgreSQL 16 and Redis 7. |
| **C. Operational Infrastructure Readiness** | **BLOCKED** | External Git egress proxy, production TLS certs, production secrets, and remote CI execution remain unprovisioned/unexecuted. |
| **D. Overall Release Approval Readiness** | **CONDITIONALLY READY** | Repository is clean, secret-safe, and ready for a **user-approved commit and push** to trigger remote CI staging verification; production deployment remains blocked until Section 11 items are provisioned. |

---

## 15. Recommended Next Action

1. **Await Explicit User Approval** before staging, committing, or pushing any changes.
2. Upon user approval, commit the Phase 0–7G + Phase 8 changes on `main` (excluding `.env` and untracked local artifacts per `.gitignore`) and push to `origin/main` to trigger `.github/workflows/ci.yml`.
3. Provision the four external infrastructure prerequisites (Section 11) in the target staging/production environment before promoting `v0.1.0-rc.1` to production.
