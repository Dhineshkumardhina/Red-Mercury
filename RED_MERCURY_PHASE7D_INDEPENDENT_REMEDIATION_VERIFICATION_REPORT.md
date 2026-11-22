# RED MERCURY — PHASE 7D
# INDEPENDENT REMEDIATION VERIFICATION & RELEASE CANDIDATE SECURITY AUDIT REPORT

**Repository:** `https://github.com/Dhineshkumardhina/Red-Mercury`  
**Product:** Red Mercury — Enterprise Application Security & Automated Fix Verification Engine  
**Organization:** Xerova Digital Solutions  
**Audited Branch:** `main`  
**HEAD Commit:** `b9df7b9650e0ba431e8d32b19edf30ddd6f6289c` (`b9df7b9`)  
**Previous Phases:** Phase 7A, Phase 7B, Phase 7C  
**Phase:** Phase 7D — Independent Remediation Verification & Release Candidate Security Audit (Audit-Only)  
**Audit Date:** 2026-11-22  

---

## 1. Executive Summary

Phase 7D performed an independent, audit-only adversarial verification of every Phase 7C remediation (`P7B-F01` through `P7B-F08`) against live **PostgreSQL 16.13**, live **Redis 7.4.8**, live **Docker 29.9.3** containers (`postgres:16-alpine`, `nginx:1.27-alpine`, `redmercury-worker:latest`), and the full multi-layer test suite.

### Key Audit Conclusions
1. **Verified Remediated Findings:** `P7B-F02` (Process Identity & Orphan Recovery), `P7B-F03` (Outbox Concurrency & Crash Consistency), `P7B-F05` (Per-Tenant Daily Quota Advisory Locking & Transactional Audit), `P7B-F06` (Nginx API CSP vs SPA CSP & Container `cap_drop: ALL`), `P7B-F07` (Concurrent Alembic Advisory Lock), and `P7B-F08` (SQLite Artifact Persistence Semantics) are all **VERIFIED REMEDIATED**.
2. **Partially Verified Finding:** `P7B-F04` (Git SSRF Boundary) is **PARTIALLY VERIFIED** — local SSRF validation, proxy DNS deferral, protocol/redirect lockdown, and internal network confinement are verified, while live external forward-proxy (`GIT_EGRESS_PROXY_URL`) verification remains unexecuted until an external proxy appliance is provisioned.
3. **New Finding Discovered by Phase 7D Critical Test (`P7D-F01` — P2 Moderate):**
   - Executing the Section 2 Critical Test (outer transaction fences Job A $\rightarrow$ nested savepoint fences Job B $\rightarrow$ savepoint rolls back $\rightarrow$ outer transaction commits) against live PostgreSQL 16 proved that SQLAlchemy's `@event.listens_for(Session, "after_rollback")` fires on **nested savepoint rollbacks** as well as outer rollbacks, clearing `session.info["_fenced_job_leases"]` (`AFTER_SP_ROLLBACK: 0`) and dropping outer-transaction fencing for Job A. Marked `P7B-F01` as **PARTIALLY VERIFIED** and logged **P7D-F01 (P2)**.

---

## 2. Repository Integrity

- **Git Branch & HEAD:** `main` @ `b9df7b9650e0ba431e8d32b19edf30ddd6f6289c`
- **Audit-Only Compliance:** Zero application source files, migrations, Dockerfiles, or existing test suites were modified during Phase 7D. Zero Phase 0–7C reports were overwritten. Zero commits, pushes, deployments, or secret exposures occurred.

---

## 3. Independent Verification Methodology

Phase 7D verified each Phase 7C claim via independent live-database, live-broker, and live-container probes rather than relying on Phase 7C's own test assertions:
1. **F01 Nested Savepoint Probe (Live PostgreSQL 16):** Executed the exact 8-step outer/savepoint/rollback/commit sequence directly against `test_redmercury` (`rm_test_postgres`).
2. **F03 Crash Consistency Probe (Live PostgreSQL 16 + Live Redis 7):** Injected a crash inside `dispatch_outbox_events()` *after* Redis `RPUSH` succeeded and *before* PostgreSQL `COMMIT`, then verified recovery and duplicate-message claiming across two independent worker claims.
3. **F06 Live Container Capability Boot (`postgres:16-alpine` & `nginx:1.27-alpine`):** Booted live containers with exact `docker-compose.prod.yml` `--cap-drop=ALL` and `--cap-add=...` flags and verified readiness probes (`pg_isready`, HTTPS TLS responses).

---

## 4. F01–F08 Verification Results

| Phase 7B ID | Phase 7D Classification | Independent Verification Evidence |
| :--- | :---: | :--- |
| **P7B-F01** | **PARTIALLY VERIFIED** | Outer-transaction `before_commit` fencing, `after_commit` cleanup, full `rollback()` cleanup, multi-job fencing, and session reuse all work as designed. **However**, the live PostgreSQL 16 Critical Test revealed **P7D-F01** (savepoint rollback triggers `after_rollback` and clears outer Job A's fence). |
| **P7B-F02** | **VERIFIED REMEDIATED** | Verified `hostname` + `PID` + `start_time` + `job_id` prevents PID-reuse termination, cross-container namespace collisions, and spoofed container names (`rm_test_postgres`). See Section 5 (`P7D-F02` INFO note on cross-container `api` vs `worker` visibility). |
| **P7B-F03** | **VERIFIED REMEDIATED** | Verified `FOR UPDATE SKIP LOCKED` prevents concurrent outbox dispatchers from pushing duplicate messages, and verified crash-before-commit preserves at-least-once delivery + exactly-once durable job execution (Section 6). |
| **P7B-F04** | **PARTIALLY VERIFIED** | Verified IPv4/IPv6/loopback/metadata/redirect/protocol blocks, `redmercury_internal` (`internal: true`) confinement, and proxy DNS deferral (`allow_proxy_dns_resolution=True`). Production live proxy test unexecuted (no external proxy appliance provisioned). |
| **P7B-F05** | **VERIFIED REMEDIATED** | Verified `pg_advisory_xact_lock(hashtext(:uid))` serializes same-tenant daily quota checks without FK deadlocks on `users`, and `record_audit_event(..., commit=False, raise_on_error=True)` rolls back atomically with repository actions. `hashtext()` 32-bit hash collisions can only serialize two unrelated tenants briefly (performance-only, zero security impact). |
| **P7B-F06** | **VERIFIED REMEDIATED** | Verified live `postgres:16-alpine` boots and passes `pg_isready` (`PG_CAP_DROP_READY`) with `--cap-drop=ALL --cap-add=CHOWN,SETUID,SETGID,DAC_OVERRIDE,FOWNER`, and live `nginx:1.27-alpine` serves `default-src 'none'; frame-ancestors 'none'` on `/api/*` and `default-src 'self'` on `/` with `--cap-drop=ALL`. |
| **P7B-F07** | **VERIFIED REMEDIATED** | Verified 3 concurrent `alembic upgrade head` OS processes serialize cleanly via `pg_advisory_lock(72839104)` and release `pg_advisory_unlock(72839104)` in `finally:`. |
| **P7B-F08** | **VERIFIED REMEDIATED** | Confirmed `record_job_runtime_artifacts()` skips autonomous `session_factory` writes only when `db is None` AND bound to SQLite (single-process dev mode where in-memory `JobExecutionTracker` owns artifacts); PostgreSQL production workers always persist artifacts. |

---

## 5. New Findings Discovered in Phase 7D

### Finding P7D-F01 (`P2` — Moderate): `after_rollback` Listener Clears Outer-Transaction Fenced Leases on Nested Savepoint Rollback
1. **Affected File & Function:** [backend/app/core/jobs.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/jobs.py#L1498-L1505) (`_clear_fenced_leases_after_rollback`).
2. **Root Cause:** SQLAlchemy emits `after_rollback(session)` for **both** full transaction rollbacks and nested `SAVEPOINT` (`session.begin_nested()`) rollbacks. `_clear_fenced_leases_after_rollback` unconditionally executes `session.info.pop("_fenced_job_leases", None)`.
3. **Live Reproduction Evidence (PostgreSQL 16.13):**
   Executed the Section 2 Critical Test:
   ```text
   AFTER_FENCE_A: 1
   AFTER_FENCE_B_IN_SP: 2
   AFTER_SP_ROLLBACK: 0
   OUTER_COMMIT_SUCCEEDED
   ```
   Rolling back the inner savepoint cleared Job A's outer-transaction fence (`AFTER_SP_ROLLBACK: 0`), allowing the outer transaction to commit even though Job B's savepoint rolled back.
4. **Exploitation / Trigger Conditions:** Any code path that calls `assert_active_worker_lease_or_abort()` for Job A in an outer transaction, enters a nested `with db.begin_nested():` savepoint that catches an exception and rolls back (e.g., an `IntegrityError` retry savepoint), and then commits the outer transaction.
5. **Potential Impact:** Loss of `before_commit` lease-fencing protection for the outer transaction's fenced job(s) after an inner savepoint rollback.
6. **Recommended Remediation:** Replace `after_commit` / `after_rollback` with `@event.listens_for(Session, "after_transaction_end")` checking `if transaction.parent is None:` (or tracking `(transaction, (job_id, worker_id, lease_token))` per `SessionTransaction` so rolling back a nested savepoint pops only leases added inside that savepoint and leaves outer-transaction leases intact).
7. **Regression Test Requirements:** Run the exact 8-step Critical Test asserting `len(db.info["_fenced_job_leases"]) == 1` (Job A preserved, Job B removed) after savepoint rollback, and verify outer commit fails with `StaleWorkerLeaseError` if Job A is stolen while succeeding if Job B is stolen.

### Finding P7D-F02 (`INFO` — Hardening Note): Cross-Container Sandbox Visibility
- In `docker-compose.prod.yml`, `api` (`redmercury_api`) has no Docker socket (by security design) and runs in a different PID namespace from `worker` (`redmercury_worker`). Consequently, when `worker` crashes, `api`'s startup reconciliation cleanly skips `worker`'s PIDs (`entry_host != current_host`), and container-level cleanup relies on `worker` restarting (which destroys `worker`'s PID namespace) and/or `worker`'s `reconcile_jobs_on_startup()`.

---

## 6. Crash Consistency Results (F03 Live Probe)

Executed against live **PostgreSQL 16.13** (`rm_test_postgres`) and live **Redis 7.4.8** (`rm_test_redis`):
```text
AFTER_CRASH_QLEN: 1 OUTBOX_STATUS: pending
AFTER_DISPATCH2_COUNT: 1 QLEN: 2 OUTBOX_STATUS: dispatched
CLAIMED_FIRST: 5aa4bc57-ab93-4a5f-b3a9-2a6ea6e04be4 CLAIMED_SECOND: None QLEN_LEFT: 0
```
- **Delivery Guarantee:** **At-least-once Redis wake-up delivery** (crash between `RPUSH` and PostgreSQL `COMMIT` leaves the outbox row `pending`, causing Dispatcher 2 to publish a second wake-up message: `QLEN: 2`).
- **Execution Guarantee:** **Exactly-once durable job execution** (`claim_next_durable_job()` uses PostgreSQL `FOR UPDATE SKIP LOCKED` + atomic CAS on `status IN ('queued', 'retrying')`, so Worker 1 claims `5aa4bc57-...` and Worker 2 receives `None` on the duplicate message).

---

## 7. Live-Versus-Mocked Verification Matrix

| Verification Target | Mode | Real Infrastructure | Mocked / Simulated |
| :--- | :--- | :--- | :--- |
| **F01 Nested Savepoint Rollback Critical Test** | **Live Infrastructure** | Live PostgreSQL 16.13 (`rm_test_postgres`) | None |
| **F03 Outbox Crash-Before-Commit Consistency** | **Live Infrastructure** | Live PostgreSQL 16.13 + Live Redis 7.4.8 | `db1.commit` monkeypatched in probe to simulate crash after `RPUSH` |
| **F06 `postgres:16-alpine` `cap_drop: ALL` Boot** | **Live Container** | Live Docker `postgres:16-alpine` with `cap_drop=ALL` + minimal `cap_add` | None |
| **F06 `nginx:1.27-alpine` Route-Specific CSP** | **Live Container** | Live Docker `nginx:1.27-alpine` with `cap_drop=ALL` + TLS | Ephemeral self-signed X.509 cert |
| **F07 Concurrent Multi-Process Alembic Advisory Lock** | **Live Infrastructure** | Live PostgreSQL 16.13 + 3 OS `alembic` subprocesses | None |
| **F04 External `GIT_EGRESS_PROXY_URL` Appliance** | **Unverified Live** | Local SSRF & network boundary rules verified | No live external forward-proxy appliance provisioned |

---

## 8. Complete Regression Results (Phase 7C Baseline Unmodified)

- **Backend Pytest Suite (`pytest tests/ -q`):** **`628 passed, 2 skipped, 0 failed`** (`630` collected; 2 POSIX-only tests skipped on Windows)
- **Phase 7C Remediation Suite (`test_phase7c_targeted_remediation.py`):** **`7 passed, 0 skipped, 0 failed`**
- **Phase 7A Distributed Hardening Suite (`test_phase7a_distributed_security_hardening.py`):** **`6 passed, 0 skipped, 0 failed`**
- **Frontend (`vitest run`, `tsc --noEmit`, `vite build`):** **`46 passed, 0 failed`**, `0` TS errors, clean production bundle
- **Electron (`node --test electron/security.test.cjs`):** **`10 passed, 0 failed`**
- **Bandit AST Scan (`bandit -r backend/app -ll -ii -q`):** **`0` Medium/High findings (`exit code 0`)**
- **Docker Compose (`docker compose -f docker-compose.prod.yml config -q`):** **`exit code 0`**

---

## 9. External Infrastructure Dependencies & 10. Remaining Vulnerabilities

1. **Remaining Vulnerabilities:**
   - **P7D-F01 (`P2` — Moderate):** `_clear_fenced_leases_after_rollback` clears outer-transaction fenced leases when an inner `begin_nested()` savepoint rolls back.
   - **P7B-F04 (Proxy-Dependent):** Connection-time DNS SSRF filtering in proxy mode depends on deploying an SSRF-filtering forward proxy (`GIT_EGRESS_PROXY_URL`).
2. **External Infrastructure Dependencies:**
   - SSRF-filtering forward proxy (`GIT_EGRESS_PROXY_URL`) reachable from `redmercury_internal` (fail-closed `403` in `production`/`staging` until set).
   - Production TLS certificates (`./ssl/redmercury.crt`, `./ssl/redmercury.key`) and production secrets (`SECRET_KEY`, `POSTGRES_PASSWORD`, `GITHUB_WEBHOOK_SECRET`).
   - Remote GitHub Actions workflow execution upon `git push`.

---

## 11. Release Candidate Recommendation & 12. Recommended Next Phase

- **Final Decision:** **CONDITIONALLY ACCEPTED**
- **Recommended Next Step:** Authorize a minimal, single-function patch for **P7D-F01** (`after_transaction_end` transaction-scoped lease cleanup in [backend/app/core/jobs.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/jobs.py)) with the 8-step nested savepoint regression test, then commit and push to `main` to verify the remote GitHub Actions CI release gate.
