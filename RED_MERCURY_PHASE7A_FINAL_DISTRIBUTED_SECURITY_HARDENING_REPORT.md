# RED MERCURY — PHASE 7A
# FINAL DISTRIBUTED SECURITY HARDENING & DEPLOYMENT GATE VERIFICATION REPORT

**Repository:** `https://github.com/Dhineshkumardhina/Red-Mercury`  
**Product:** Red Mercury — Enterprise Application Security & Automated Fix Verification Engine  
**Organization:** Xerova Digital Solutions  
**Baseline:** Phase 7 Working Tree (`main` @ `b9df7b9650e0ba431e8d32b19edf30ddd6f6289c`)  
**Phase:** Phase 7A — Final Distributed Security Hardening & Deployment Gate Verification  
**Audit Date:** 2026-11-22  

---

## 1. Actual Branch and HEAD

- **Git Branch:** `main`
- **Actual HEAD Commit:** `b9df7b9650e0ba431e8d32b19edf30ddd6f6289c` (`b9df7b9`)
- **Preservation Verification:** All modifications, security controls, migrations, and reports from Phases 0 through 7 were preserved intact. No files were reset, discarded, committed, or pushed. No `.env` or secret values were read or exposed.

---

## 2. Initial and Final Working-Tree Status

### Initial Working-Tree Status (Start of Phase 7A)
- **Modified Tracked Files (`57` files):** `.env.example`, `.github/workflows/ci.yml`, `.github/workflows/redmercury-analysis.yml.example`, `.github/workflows/redmercury_pr_gate.yml`, `.gitleaks.toml`, `Dockerfile.api`, `Dockerfile.frontend`, `Dockerfile.worker`, `backend/alembic/env.py`, `backend/app/analyzer/client.py`, `backend/app/api/v1/endpoints/{analyzer,auth,evidence,findings,health,repositories,scans,verification}.py`, `backend/app/core/{auth,config,ingestion,quotas,security,workspace_cleanup}.py`, `backend/app/evidence/service.py`, `backend/app/integrations/github/{service,webhook}.py`, `backend/app/main.py`, `backend/app/models/{__init__,token,user}.py`, `backend/app/scanner/{bandit,base,gitleaks,pip_audit,runner,semgrep,worker}.py`, `backend/app/schemas/{auth,scan,verification}.py`, `backend/app/validation/{ai_assistant,service}.py`, `backend/app/verification/{sandbox,service}.py`, `backend/requirements.txt`, `docker-compose.prod.yml`, `electron/main.cjs`, `frontend/package-lock.json`, `frontend/package.json`, `frontend/public/_headers`, `frontend/src/__tests__/App.test.tsx`, `frontend/src/context/AuthContext.tsx`, `frontend/src/pages/{FindingsPage,LoginPage,SettingsPage}.tsx`, `frontend/src/services/api.ts`, `nginx/{frontend,production}.conf`, `tests/{conftest,test_api_reliability_and_resilience,test_auth,test_authorization,test_evidence_traceability,test_health,test_migration_consistency}.py`.
- **Untracked Files (`23` entries):** `.dockerignore`, `.github/secret_scanning.yml`, `RED_MERCURY_PHASE0..7_*.md`, `backend/alembic/versions/0013_add_refresh_token_sessions.py`, `backend/alembic/versions/0014_add_durable_jobs_and_outbox.py`, `backend/app/core/jobs.py`, `backend/app/models/job.py`, `backend/app/scanner/rules/`, `electron/security.cjs`, `electron/security.test.cjs`, `frontend/src/__tests__/AuthSecurity.test.tsx`, `tests/test_phase1..7_*.py`.

### Final Working-Tree Status (End of Phase 7A)
- All Phase 0–7 modifications preserved, plus Phase 7A additions:
  - Modified: [backend/app/core/jobs.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/jobs.py), [backend/app/core/audit.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/audit.py), [backend/app/scanner/runner.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/scanner/runner.py), [backend/app/verification/service.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/verification/service.py), [backend/app/verification/workspace.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/verification/workspace.py), [backend/app/verification/sandbox.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/verification/sandbox.py), [backend/app/core/ingestion.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/ingestion.py), [backend/app/api/v1/endpoints/repositories.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/api/v1/endpoints/repositories.py), [.github/workflows/ci.yml](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/.github/workflows/ci.yml).
  - Created: [tests/test_phase7a_distributed_security_hardening.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/tests/test_phase7a_distributed_security_hardening.py), [RED_MERCURY_PHASE7A_FINAL_DISTRIBUTED_SECURITY_HARDENING_REPORT.md](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/RED_MERCURY_PHASE7A_FINAL_DISTRIBUTED_SECURITY_HARDENING_REPORT.md).

---

## 3. Files Inspected

- [backend/app/core/jobs.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/jobs.py)
- [backend/app/core/audit.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/audit.py)
- [backend/app/scanner/runner.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/scanner/runner.py)
- [backend/app/scanner/base.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/scanner/base.py)
- [backend/app/scanner/bandit.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/scanner/bandit.py)
- [backend/app/verification/service.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/verification/service.py)
- [backend/app/verification/sandbox.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/verification/sandbox.py)
- [backend/app/verification/workspace.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/verification/workspace.py)
- [backend/app/core/ingestion.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/ingestion.py)
- [backend/app/api/v1/endpoints/repositories.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/api/v1/endpoints/repositories.py)
- [docker-compose.prod.yml](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/docker-compose.prod.yml)
- [.github/workflows/ci.yml](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/.github/workflows/ci.yml)

---

## 4. Lease-Fencing Race Analysis (Section 2)

### Vulnerability Identified in Phase 7 Baseline
An independent code audit of `assert_active_worker_lease_or_abort()`, `run_security_scan()`, `_finalize_and_persist_run()`, and `record_audit_event()` revealed three concrete race windows:
1. **Non-Locking `SELECT` Before `COMMIT`:** `assert_active_worker_lease_or_abort()` executed a plain `SELECT status, worker_id, lease_token, lease_expires_at FROM durable_jobs WHERE id = :jid`. A plain `SELECT` does not acquire a row-level lock or fence the subsequent `db.commit()`. If Worker A validated its lease via `assert_active_worker_lease_or_abort()` and then paused (e.g., GC pause, OS scheduling delay, or network latency) immediately before `db.commit()` while its lease expired and Worker B recovered and claimed the job with a new `lease_token`, Worker A's subsequent `db.commit()` would still succeed and commit stale business data.
2. **Split Transactions for Findings Deletion & Audit Events:**
   - In `run_security_scan()`, `db.query(SecurityFinding).filter(...).delete()` was committed in an early separate transaction before scanner execution, and `record_audit_event()` committed in its own transaction before the final `db.commit()`.
   - In `_finalize_and_persist_run()`, `VerificationRun` / `SecurityEvidence` / `VerificationEvidence` were committed first, and `record_audit_event()` was called afterward in a second separate transaction.
   - In `record_audit_event()` ([backend/app/core/audit.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/audit.py#L63-L66)), `except Exception:` caught and swallowed all exceptions without re-raising `StaleWorkerLeaseError`.

### Remediation Implemented
1. **Transaction-Level Atomic Lease Fencing at `before_commit` ([backend/app/core/jobs.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/jobs.py#L1443-L1498)):**
   - `assert_active_worker_lease_or_abort()` binds the verified `(job_id, worker_id, lease_token)` tuple to `db.info["_fenced_job_lease"]`.
   - Registered a SQLAlchemy `@event.listens_for(Session, "before_commit")` listener (`_enforce_lease_fencing_before_commit(session: Session)`). At the exact moment `session.commit()` is invoked—inside the same database transaction immediately before PostgreSQL emits `COMMIT`—the listener executes an atomic row-locking conditional `UPDATE`:
     ```sql
     UPDATE durable_jobs
     SET heartbeat_at = :now
     WHERE id = :jid
       AND status = 'running'
       AND worker_id = :wid
       AND lease_token = :tok
       AND lease_expires_at > :now
     ```
   - If the lease expired or was reassigned to Worker B during the pause between `assert_active_worker_lease_or_abort()` and `session.commit()`, `res.rowcount` is `0`, and `_enforce_lease_fencing_before_commit` immediately raises `StaleWorkerLeaseError`, aborting the commit and rolling back the entire transaction.
   - If `res.rowcount == 1`, PostgreSQL holds an exclusive row lock (`FOR UPDATE` via the `UPDATE`) on `durable_jobs WHERE id = :jid` until the transaction's `COMMIT` finishes immediately thereafter, preventing any concurrent recovery or Worker B claim from racing with the commit.
2. **Single Atomic Business-Data Transaction ([backend/app/scanner/runner.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/scanner/runner.py#L218-L310), [backend/app/verification/service.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/verification/service.py#L860-L905)):**
   - Consolidated all business-data mutations (`SecurityFinding`, `SecurityEvidence`, `VerificationEvidence`, `Scan.status`, `Repository` posture counts, `VerificationRun.status`, and `AuditEvent`) into a single atomic transaction committed once at the end of `run_security_scan()` and `_finalize_and_persist_run()`.

---

## 5. Real PostgreSQL Concurrency Test Results (Section 2)

Executed against live **PostgreSQL 16.13** (`127.0.0.1:5432/test_redmercury`) using two independent SQLAlchemy sessions (`db_a` and `db_b`):

| Test Case | Exact 6-Step Sequence Reproduced | Verified Outcome on PostgreSQL 16 |
| :--- | :--- | :--- |
| **`test_phase7a_sec2_postgres_concurrent_lease_fencing_blocks_stale_scan_commit`** | 1. Worker A claims scan job (`token_a`).<br>2. Worker A runs Bandit & validates lease.<br>3. Worker A pauses in `pre_commit_hook` immediately before committing.<br>4. Lease expires on `db_b`.<br>5. Worker B recovers & claims job with `token_b != token_a`.<br>6. Worker A resumes and calls `db_a.commit()`. | **PASSED:** Worker A's `db_a.commit()` raised `StaleWorkerLeaseError`. Zero `SecurityFinding` rows, zero `AuditEvent(action="SCAN_COMPLETED")` rows, and zero stale `Scan.status` changes were committed by Worker A. |
| **`test_phase7a_sec2_postgres_concurrent_lease_fencing_blocks_stale_verification_commit`** | 1. Worker A claims verification job (`token_a`).<br>2. Worker A runs patch verification & validates lease.<br>3. Worker A pauses in `pre_commit_hook` immediately before committing.<br>4. Lease expires on `db_b`.<br>5. Worker B recovers & claims job with `token_b != token_a`.<br>6. Worker A resumes and calls `db_a.commit()`. | **PASSED:** Worker A's `db_a.commit()` raised `StaleWorkerLeaseError`. Zero `SecurityEvidence`, zero `VerificationEvidence`, zero `AuditEvent(action="verification.run_completed")`, and zero stale `VerificationRun.status` updates were committed by Worker A. |

---

## 6. Worker Crash-During-Cancellation Results (Section 3)

### Gap Identified in Phase 7 Baseline
Previously, `JobExecutionTracker` tracked child subprocesses (`_processes`), Docker sandbox containers (`_containers`), and disposable temp workspaces (`_temp_workspaces`) only in the worker's in-process memory. If a worker crashed unexpectedly while a job was in `"cancelling"`, its in-memory tracker was lost; when the lease expired, `recover_expired_job_leases()` transitioned the job to `"cancelled"` and released `ActiveJobSlot` without terminating or verifying orphaned child processes, Docker sandbox containers, or disposable temp workspaces.

### Remediation Implemented ([backend/app/core/jobs.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/jobs.py#L1180-L1710))
1. **Durable Runtime Artifact Ledger (`record_job_runtime_artifacts`):**
   - Whenever `JobExecutionTracker.register_process()`, `register_container()`, or `register_temp_workspace()` is called (including auto-registration in `create_verification_workspace()` and Docker container labeling `--label=redmercury.job_id=<job_id>` in `build_container_run_command()`), the active child PIDs, `redmercury-sbx-*` container names, and disposable workspace paths are persisted into `DurableJob.payload_json["_runtime_artifacts"]`.
2. **Targeted Orphan Reaping & Process/Container Verification (`reap_and_verify_orphaned_job_resources`):**
   - Targets **only** the child PIDs, `^redmercury-sbx-[a-zA-Z0-9_\-]+$` container names (plus containers labeled `redmercury.job_id=<job.id>`), and confined disposable temp workspaces (`redmercury_verify_*`, `rm_verify_*`, `rm_p6_cancel_ws_*`, `rm_p7a_cancel_ws_*`) belonging to the expired job—never executing broad process killing or broad `docker rm`.
   - After attempting cleanup, inspects the OS process table (`_is_pid_running`) and Docker container state (`_is_container_running`).
3. **Fail-Closed Concurrency Slot Retention in `recover_expired_job_leases()`:**
   - If `verified_stopped` is `False` (any recorded child process or sandbox container is still running), `recover_expired_job_leases()` **refuses** to transition the job to terminal `"cancelled"` and **refuses** to delete the `ActiveJobSlot`, keeping the job in `"cancelling"` with `stats["deferred_active"] += 1` and recording the active PIDs/containers in `error_detail`.

---

## 7. Orphan Process and Container Verification (Section 3)

Executed in `test_phase7a_sec3_worker_crash_during_cancellation_reaps_orphans_and_guards_slot` using live **PostgreSQL 16.13**, a real Python child subprocess, and a real **Docker 29.9.3** container (`redmercury-worker:latest`):

1. **Fail-Closed Verification (`kill_orphans=False`):** While child PID and container `redmercury-sbx-*` remained running, `recover_expired_job_leases(db, kill_orphans=False)` returned `deferred_active = 1`, `cancelled = 0`, kept `job.status == "cancelling"`, and retained `ActiveJobSlot` (`count == 1`).
2. **Active Orphan Reaping (`kill_orphans=True`):** `recover_expired_job_leases(db, kill_orphans=True)` terminated the orphaned child process tree, stopped and removed the orphaned Docker sandbox container, and deleted the disposable temp workspace.
3. **Post-Recovery Inspection:**
   - OS Process Table (`_is_pid_running(child_pid)`): **`False`** (process terminated).
   - Docker Container List (`_is_container_running(container_name)`): **`False`** (container stopped and removed).
   - Disposable Workspace (`disposable_ws.exists()`): **`False`** (cleaned).
   - Persistent Repository Workspace (`repo.workspace_path / "app.py"`): **`True`** (preserved intact).
   - Prior `SecurityEvidence` and `AuditEvent` history: **`100% intact`**.
   - Job & Slot Finalization: `job.status == "cancelled"`, `scan.status == "cancelled"`, `ActiveJobSlot` count `== 0`.

---

## 8. Git Execution-Location Analysis (Section 4)

### Complete Execution Trace
1. **HTTP Entrypoints:**
   - `POST /api/v1/repositories/ingest/git` $\rightarrow$ `ingest_git_repository()` ([backend/app/api/v1/endpoints/repositories.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/api/v1/endpoints/repositories.py#L250-L353))
   - `POST /api/v1/repositories/{repo_id}/clone` $\rightarrow$ `clone_registered_git_repository()` ([backend/app/api/v1/endpoints/repositories.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/api/v1/endpoints/repositories.py#L356-L426))
2. **Execution Process:**
   - Both endpoints execute **synchronously inside the `api` service container (`redmercury_api`, UID/GID `10001:10001`)**. Git ingestion does **not** run inside the `worker` container.
3. **Subprocess Call Chain inside `api`:**
   - `resolve_required_git_egress_proxy()` $\rightarrow$ `validate_git_url()` $\rightarrow$ `clone_git_repository()` $\rightarrow$ `_run_git_command(cmd=["git", ...], env=git_env)` ([backend/app/core/ingestion.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/ingestion.py#L1127-L1285)).

---

## 9. Network Egress Verification (Section 4)

1. **`api` Container Network Boundary in [docker-compose.prod.yml](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/docker-compose.prod.yml#L1-L115):**
   - `redmercury_api` is attached **exclusively** to `redmercury_internal`:
     ```yaml
     networks:
       redmercury_internal:
         driver: bridge
         internal: true
     ```
   - It is **not** attached to `redmercury_public` (only `nginx` is attached to `redmercury_public`). Because `redmercury_internal` is declared `internal: true`, Docker Engine drops all direct outbound packets from `redmercury_api` to the external internet or host default gateway at the container network boundary.
2. **Proxy & Connection-Time DNS Rebinding Protections ([backend/app/core/ingestion.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/ingestion.py#L961-L1220)):**
   - **Fail-Closed in Strict Environments:** In `production` and `staging`, if `GIT_EGRESS_PROXY_URL` is unset, `resolve_required_git_egress_proxy()` rejects the request with `403 SecurityPolicyViolationError` before any DNS lookup or `git` subprocess is spawned.
   - **Mandatory Proxy Flag & Env Binding:** When `GIT_EGRESS_PROXY_URL` is set, `clone_git_repository()` passes `-c http.proxy=<proxy> -c https.proxy=<proxy>` to `git` AND `_build_sanitized_git_env()` sets `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy`, and `NO_PROXY=""` / `no_proxy=""` after stripping all ambient environment proxy overrides.
   - **Connection-Time DNS Rebinding Pinning (`http.curloptResolve`):** When running in direct development mode without an external proxy, `clone_git_repository()` resolves and validates all IPv4/IPv6 addresses for the target host and passes `-c http.curloptResolve=<host>:<port>:<validated_ips>` to `git`, pinning the pre-validated IP address in `libcurl` so `git-remote-https` does not perform a second unvalidated DNS lookup vulnerable to TOCTOU DNS rebinding.
   - **Redirect & Protocol Lockdown:** `-c http.followRedirects=false`, `-c protocol.allow=never`, `-c protocol.https.allow=always`, `-c protocol.file.allow=never`, `-c core.symlinks=false`, `-c core.hooksPath=/dev/null`.
   - **Infrastructure Blocker Documented:** No live external forward-proxy appliance container (e.g., Smokescreen/Squid/Envoy) is bundled in `docker-compose.prod.yml`; therefore, no live proxy appliance test was fabricated, and `production`/`staging` remain strictly fail-closed until an external proxy is supplied via `GIT_EGRESS_PROXY_URL`.

---

## 10. Outbox and Cancellation Recovery (Section 5)

Verified in `test_phase7a_sec5_outbox_and_cancellation_fault_matrix_on_live_postgres_and_redis` on live **PostgreSQL 16.13** and live **Redis 7.4.8**:

| Fault / Concurrency Scenario | Verified Behavior |
| :--- | :--- |
| **1. API restart after DB commit before Redis dispatch** | `reconcile_jobs_on_startup(component="api")` discovers pending `JobOutboxEvent` rows, pushes to live Redis 7, and marks `status="dispatched"`. |
| **2. Duplicate outbox dispatch** | When duplicate messages for `job1` are pushed to Redis, 3 concurrent workers calling `claim_next_durable_job()` result in **exactly 1 worker** claiming `job1` (`FOR UPDATE SKIP LOCKED` + atomic CAS). |
| **3. Redis outage during dispatch** | `dispatch_outbox_events()` catches `ConnectionError`, increments `dispatch_attempts`, and leaves job `queued` and outbox `pending` for recovery. |
| **4. Redis outage during cancellation** | `cancel_durable_job()` commits `"cancelling"` / `"cancelled"` authoritatively in PostgreSQL even when Redis `setex` raises `ConnectionError`. |
| **5. Worker restart during cancellation** | `reconcile_jobs_on_startup(component="worker")` reaps/verifies zero active orphans on expired `"cancelling"` job, finalizes to `"cancelled"`, and releases `ActiveJobSlot`. |
| **6. Multiple simultaneous cancellation requests** | 4 concurrent threads calling `cancel_durable_job()` on `job1` all converge deterministically without error or double slot release. |
| **7. Cancellation after lease expiration** | Calling `cancel_durable_job()` on a job whose lease has already expired transitions directly to `"cancelled"` and releases the slot. |
| **8. Duplicate cancellation acknowledgement** | Calling `acknowledge_job_cancellation()` repeatedly on an already-cancelled job is idempotent, never overwrites terminal states, and blocks stale `complete_claimed_job()` with `StaleWorkerLeaseError`. |

---

## 11. CI/CD Verification (Section 6)

Audited [.github/workflows/ci.yml](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/.github/workflows/ci.yml) and verified in `test_phase7a_sec6_cicd_workflow_and_scoped_cve_verification`:

- **PostgreSQL 16 & Redis 7 Service Readiness:** Configured with digest-pinned images (`postgres:16-alpine@sha256:1d5b02d...`, `redis:7-alpine@sha256:7f7d30b...`) and `--health-cmd` probes (`pg_isready`, `redis-cli ping`).
- **Worker Image Build Ordering:** `docker build -f Dockerfile.worker -t redmercury-worker:latest .` executes at Step 4 of `backend-tests`, strictly before `pytest tests/` at Step 7.
- **Node 22 & Linux Lockfile Reproducibility:** All Node setup steps use `node-version: 22` matching `Dockerfile.frontend` (`node:22-alpine`), verified locally via `npm ci` inside a clean `node:22-alpine` Linux container.
- **Scoped CVE Exception:** `python -m pip_audit -r backend/requirements.txt --desc on --ignore-vuln CVE-2026-132276` contains exactly one `--ignore-vuln` flag (for `wcmatch~=8.5.1` upper-bounded `<9.0` by upstream `semgrep`), with no `|| true` or `continue-on-error` bypass.
- **Remote Execution Status:** Because repository push is not authorized under Phase 7A Section 6 & 9 rules, all CI steps were verified locally in equivalent Linux containers and host runners; **the remote GitHub-hosted workflow execution remains unverified until these local changes are committed and pushed to GitHub.**

---

## 12. Exact Regression Test Counts (Section 7)

| Test Suite / Gate | Command Executed | Total | Passed | Skipped | Failed |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Full Backend Pytest Suite** (with live PostgreSQL 16, Redis 7, Docker) | `python -m pytest tests/ -q --tb=short` | **623** | **621** | **2** | **0** |
| **Phase 7A Distributed Security Hardening Suite** | `python -m pytest tests/test_phase7a_distributed_security_hardening.py -v` | **6** | **6** | **0** | **0** |
| **Phase 7 Production Deployment Verification Suite** | `python -m pytest tests/test_phase7_production_deployment_verification.py -v` | **8** | **8** | **0** | **0** |
| **Phase 6 Durable Job Execution Suite** | `python -m pytest tests/test_phase6_durable_job_execution.py -v` | **16** | **16** | **0** | **0** |
| **Frontend Vitest Unit & Security Suite** | `npm --prefix frontend run test` | **46** (7 files) | **46** | **0** | **0** |
| **Frontend TypeScript Typecheck Gate** | `npm --prefix frontend run lint` (`tsc --noEmit`) | **1** | **1** | **0** | **0** |
| **Frontend Production Bundle Build** | `npm --prefix frontend run build` (`vite build`) | **1** | **1** | **0** | **0** |
| **Electron Desktop Security Suite** | `node --test electron/security.test.cjs` | **10** | **10** | **0** | **0** |
| **Production Docker Compose Validation** | `docker compose -f docker-compose.prod.yml config -q` | **1** | **1** | **0** | **0** |

---

## 13. Live Versus Mocked Test Matrix

| Verification Area | Execution Mode | Real Infrastructure Used | Mocked / Simulated Elements |
| :--- | :--- | :--- | :--- |
| **Two-Session Lease-Fencing Race (Scan & Verification)** | **Live Infrastructure** | Live PostgreSQL 16.13 (`rm_test_postgres`), real Bandit SAST execution, two independent SQLAlchemy sessions | `pre_commit_hook` callback used to deterministically pause Worker A immediately before `db_a.commit()` |
| **Worker Crash During Cancellation & Orphan Reaping** | **Live Infrastructure** | Live PostgreSQL 16.13, real OS child subprocess (`python.exe`), live Docker 29.9.3 sandbox container (`redmercury-worker:latest`), real filesystem temp & repo directories | Unregistered Worker A's in-process tracker to simulate abrupt worker process termination before cancellation ack |
| **Outbox & Cancellation Fault Matrix** | **Live Infrastructure + Fault Injection** | Live PostgreSQL 16.13 + Live Redis 7.4.8 (`rm_test_redis`) | `_FailingRedis` proxy injected only for the specific Redis outage sub-steps (`rpush` / `setex` `ConnectionError`) |
| **Browser Auth, HttpOnly Cookies, CSRF, Multi-Tab Rotation** | **Live Infrastructure** | Live Uvicorn/FastAPI server + Live Headless Google Chrome via CDP WebSocket | None |
| **Nginx HTTP & TLS 1.2/1.3 Security Headers** | **Live Infrastructure** | Live `redmercury-frontend:test` & `nginx:1.27-alpine` Docker containers | Ephemeral self-signed RSA-2048 X.509 cert for local TLS handshake |
| **Alembic `0013 -> 0014` & `pg_dump` / `psql` Restore** | **Live Infrastructure** | Live PostgreSQL 16.13 (`pg_dump` & `psql` inside container) | None |
| **Git Egress Proxy & DNS Rebinding Pinning** | **Static + Unit/API Verification** | FastAPI `TestClient`, YAML topology parser | `_run_git_command` & `socket.getaddrinfo` monkeypatched to inspect generated `git` CLI flags (`-c http.curloptResolve`, `-c http.proxy`) without external internet clone |
| **CI/CD Workflow Gate Inspection** | **Static + Local Container Equivalence** | Local `node:22-alpine`, `python:3.12-slim`, and Docker builds | Remote GitHub-hosted runner execution not triggered (no `git push` per rules) |

---

## 14. Remaining Infrastructure Blockers

1. **External SSRF-Filtering Forward Proxy Appliance (`GIT_EGRESS_PROXY_URL`):**
   - `docker-compose.prod.yml` does not bundle a pre-configured forward-proxy container (such as Smokescreen, Squid, or Envoy) dual-homed on `redmercury_internal` and `redmercury_public`. Until the deployment environment provisions this proxy and sets `GIT_EGRESS_PROXY_URL`, public Git repository ingestion in `production` and `staging` remains fail-closed (`403 Forbidden`), while ZIP upload ingestion operates normally.
2. **Remote GitHub Actions Workflow Run:**
   - All four root causes of the failing GitHub Actions checks on commit `b9df7b9` have been fixed and verified locally, but the remote GitHub Actions UI will continue to display the old `b9df7b9` status until the working-tree changes are committed and pushed.

---

## 15. Production Deployment Blockers

- **Zero code-level or distributed-concurrency blockers remain.**
- **Operational Pre-Deployment Steps Required by Operator:**
  1. Provision an SSRF-filtering forward proxy reachable from `redmercury_internal` and set `GIT_EGRESS_PROXY_URL` in production environment variables (if public Git URL cloning is required in production).
  2. Supply production TLS certificates at `./ssl/redmercury.crt` and `./ssl/redmercury.key` and strong secrets (`SECRET_KEY`, `POSTGRES_PASSWORD`, `GITHUB_WEBHOOK_SECRET`).
  3. Commit and push the verified working tree to `main` to execute the remote GitHub Actions release gate.

---

## 16. Final Decision

**CONDITIONALLY ACCEPTED**

*(All distributed lease-fencing, worker crash-during-cancellation, orphan process/container reaping, outbox/cancellation recovery, and local CI/CD release gates are proven and passing at 100%; full unconditional acceptance is conditioned solely on operator provisioning of the external `GIT_EGRESS_PROXY_URL` proxy appliance in production and pushing the working tree to execute the remote GitHub-hosted workflow.)*
