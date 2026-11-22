# RED MERCURY — PHASE 7F
# INDEPENDENT FINAL RELEASE-CANDIDATE SECURITY AUDIT & PRODUCTION ACCEPTANCE VERIFICATION REPORT

**Repository:** `https://github.com/Dhineshkumardhina/Red-Mercury`  
**Product:** Red Mercury — Enterprise Application Security & Automated Fix Verification Engine  
**Organization:** Xerova Digital Solutions  
**Audited Branch:** `main`  
**Verified HEAD Commit:** `b9df7b9650e0ba431e8d32b19edf30ddd6f6289c` (`b9df7b9`)  
**Scope:** Independent Final Release-Candidate Audit & Verification across Phases 0–7E (Audit-Only)  
**Audit Date:** 2026-11-22  

---

## 1. Executive Summary

Phase 7F conducted an independent, audit-only release-candidate verification of the complete Red Mercury Phases 0–7E working tree against live **PostgreSQL 16.13**, live **Redis 7.4.8**, live **Docker 29.9.3** containers, live **Headless Chromium**, and the full multi-layer test and static-analysis suites.

### Release-Candidate Verdict
- **Application Code & Distributed Transaction Readiness:** **VERIFIED** (`629 passed, 2 skipped, 0 failed` backend; `46 passed` frontend; `10 passed` Electron; `0` Bandit medium/high findings; `exit code 0` Compose config). All Critical/High/Moderate security and distributed-transaction findings from Phases 0–7E—including **P7D-F01** (nested savepoint rollback lease fencing)—are verified remediated.
- **Operational Production Readiness:** **CONDITIONALLY ACCEPTED** — external infrastructure prerequisites (`GIT_EGRESS_PROXY_URL` SSRF-filtering forward-proxy appliance, production TLS certificates, production secrets, and remote GitHub Actions CI run upon push) remain outside the local repository and must be provisioned by the operator before live cutover.

---

## 2. Repository and Git State

- **Branch:** `main`
- **HEAD Commit:** `b9df7b9650e0ba431e8d32b19edf30ddd6f6289c` (matches expected baseline)
- **Preservation Integrity:** Zero code edits, zero migrations altered, zero tests weakened, zero previous reports overwritten, zero Git commits/pushes/resets/cleans executed, and zero secrets exposed.

---

## 3. Phase 7E Independent Verification

Independently inspected [backend/app/core/jobs.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/jobs.py#L1467-L1593) and [tests/test_phase7e_transaction_fencing.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/tests/test_phase7e_transaction_fencing.py):
- **Integer-Keyed Transaction Ownership:** Leases are stored in `db.info["_fenced_leases_by_tx"]` keyed by `id(owning_tx)` (`int`), holding **zero** references to `SessionTransaction` objects (eliminating memory leaks) and cleared on outer transaction completion (`transaction.parent is None`).
- **Savepoint Rollback Isolation:** `after_transaction_end` discards `by_tx.pop(id(transaction), None)` when a nested savepoint rolls back, leaving `transaction.parent`'s outer leases intact.
- **Savepoint Commit Promotion:** When a nested savepoint commits (`before_commit` marks `id(active_tx)` in `_committed_fenced_tx_ids`), `after_transaction_end` promotes its leases into `by_tx[id(transaction.parent)]` and defers the PostgreSQL row-locking `UPDATE durable_jobs` check until outer `COMMIT`.
- **Exception Safety:** If `before_commit` raises `StaleWorkerLeaseError`, SQLAlchemy aborts the commit and the caller's `db.rollback()` triggers `after_transaction_end` (`transaction.parent is None`), clearing all fencing state cleanly for session reuse.

---

## 4. Explicit Cleanup Safety Assessment (Mandatory Investigation B)

Inspected all `10` call sites of `_clear_all_fenced_leases()` in [backend/app/core/jobs.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/jobs.py):
- Lines `851` (`renew_job_lease`), `923` (`complete_claimed_job`), `978` (`fail_claimed_job`), `1116` (`release_claimed_job_on_shutdown`), `1575` (`_cleanup_fenced_leases_on_transaction_end`), `1700` (`record_job_runtime_artifacts`), `2048` (`acknowledge_job_cancellation`), `2113` (`cancel_durable_job`), `2220` (`recover_expired_job_leases`), and `2783`.
- **Independent Live Probe Result:**
  ```text
  INV_B_BEFORE_HELPER: 1
  INV_B_AFTER_HELPER_ON_SAME_SESSION: 0
  ```
  Invoking `recover_expired_job_leases(db=db)` (or `renew_job_lease(db=db, ...)` / `cancel_durable_job(db=db, ...)`) on the **same** uncommitted business session `db` clears `_fenced_job_leases` and commits `db`.
- **Why Not Exploitable in Production Code Paths:**
  - In `execute_claimed_durable_job()` and `JobHeartbeatMonitor`, `renew_job_lease`, `recover_expired_job_leases`, and `cancel_durable_job` always operate on their **own dedicated session** (`session_factory()` or FastAPI request `db`), while `complete_claimed_job` / `fail_claimed_job` run **after** the business transaction has finished.
  - Logged as **P7F-F01 (Low)** recommending per-`job_id` cleanup and avoiding `_clear_all_fenced_leases(sess)` inside `record_job_runtime_artifacts()`.

---

## 5. Transaction Lifecycle Results (Mandatory Investigation C — Live PostgreSQL 16)

All scenarios **A–J** were verified against live **PostgreSQL 16.13** (`rm_test_postgres`):

| Scenario | Verified Behaviour on Live PostgreSQL 16 | Status |
| :--- | :--- | :---: |
| **A. Outer Job A + nested Job B + nested rollback** | Job A preserved; Job B removed; outer commit fenced | **PASSED** |
| **B. Outer Job A + nested Job B + nested commit + outer rollback** | Job B promoted (`INV_C_AFTER_NESTED_COMMIT: 2`); outer rollback clears all (`False False`) | **PASSED** |
| **C. Outer Job A + nested Job B + nested commit + outer commit** | Both Job A and Job B checked atomically at outer commit; state cleared | **PASSED** |
| **D. Two nested savepoints: SP1 committed, SP2 rolled back** | SP1 promoted to outer; SP2 discarded | **PASSED** |
| **E. Multiple nested savepoints (commit/rollback combinations)** | Exact per-savepoint ownership maintained | **PASSED** |
| **F. Outer rollback following successful nested promotion** | All `_fenced_job_leases` and `_fenced_leases_by_tx` cleared | **PASSED** |
| **G. Stale outer lease after nested rollback** | Outer commit raises `StaleWorkerLeaseError`; 0 rows committed | **PASSED** |
| **H. Stale promoted nested lease before outer commit** | Outer commit raises `StaleWorkerLeaseError` (`INV_C_STALE_PROMOTED_REJECTED_OK`) | **PASSED** |
| **I. Session reuse after commit, rollback, nested rollback, StaleWorkerLeaseError** | Zero stale state inherited | **PASSED** |
| **J. Concurrent lease takeover across independent PostgreSQL sessions** | Session B recovery + claim rejects Session A commit atomically | **PASSED** |

---

## 6. Distributed Job Execution Assurance (Step 3)

1. **Notification Delivery (`At-Least-Once`):** Redis `RPUSH` wake-ups are dispatched via the transactional outbox (`FOR UPDATE SKIP LOCKED`). A crash between `RPUSH` and PostgreSQL `COMMIT` results in **at-least-once** Redis delivery (explicitly NOT claimed as exactly-once delivery).
2. **Durable Job Claiming (`Atomic Single-Winner`):** `claim_durable_job_by_id()` uses PostgreSQL `FOR UPDATE SKIP LOCKED` + atomic CAS on `status IN ('queued', 'retrying')`, guaranteeing only one worker claims a given attempt even under duplicate Redis messages.
3. **Business Side Effects (`Lease-Fenced Single-Transaction`):**
   - `run_security_scan()` and `_finalize_and_persist_run()` stage all findings, evidence, status updates, and `AuditEvent` rows inside one transaction fenced by `before_commit` (`UPDATE durable_jobs ... WHERE status='running' AND worker_id=:wid AND lease_token=:tok AND lease_expires_at > :now`).
   - Stale workers are blocked at the PostgreSQL commit boundary (`StaleWorkerLeaseError`). On worker crash before commit, PostgreSQL rolls back all uncommitted business writes cleanly before recovery retries the job.

---

## 7. Phase 7B and 7D Finding Reconciliation

| Finding ID | Description | Phase 7F Final Classification |
| :--- | :--- | :---: |
| **P7B-F01** | Session lease metadata lifecycle | **VERIFIED REMEDIATED** |
| **P7B-F02** | Process identity (`hostname + PID + start_time + job_id`) & orphan cleanup | **VERIFIED REMEDIATED** |
| **P7B-F03** | Outbox concurrent dispatch (`FOR UPDATE SKIP LOCKED`) | **VERIFIED REMEDIATED** |
| **P7B-F04** | Git ingestion SSRF protection & external proxy | **PARTIALLY VERIFIED** *(local SSRF/fail-closed verified; live external proxy appliance not provisioned)* |
| **P7B-F05** | Per-tenant daily quota advisory lock & transactional audit | **VERIFIED REMEDIATED** |
| **P7B-F06** | Route-specific API CSP (`default-src 'none'`) & container `cap_drop: ALL` | **VERIFIED REMEDIATED** |
| **P7B-F07** | Concurrent Alembic migrations (`pg_advisory_lock(72839104)`) | **VERIFIED REMEDIATED** |
| **P7B-F08** | SQLite runtime artifact persistence semantics | **VERIFIED REMEDIATED** |
| **P7D-F01** | Nested savepoint rollback fencing defect | **VERIFIED REMEDIATED** |

---

## 8. Application Security Findings Summary (Step 5)

Reviewed across all 22 required security domains:
- **Authentication, Session & CSRF/CORS:** `HttpOnly` JWT `access_token` + rotating `refresh_token` (`Path=/api/v1/auth`) + `rm_csrf_token`/`X-CSRF-Token` double-submit + strict `CORS_ORIGINS` allowlist in prod/staging (verified live via Headless Chromium CDP).
- **Tenant Isolation & Authorization:** Repository, scan, finding, evidence, and verification queries scope by `owner_id == current_user.id`; durable workers revalidate tenant ownership from authoritative PostgreSQL rows (never trusting Redis).
- **Ingestion (ZIP, Local, Git):** Zip Slip, symlink-before-`resolve()`, Zip Bomb ratio/size/file-count caps, production local-ingest lockdown, Git protocol/redirect/env hardening, and IPv4/IPv6/CGNAT/ULA/metadata SSRF blocking verified.
- **Sandbox & Containers:** `--network none`, `--cap-drop ALL`, `--read-only`, `--no-new-privileges:true`, `--pids-limit 64`, `--cpus 1.0`, `--memory 512m`, non-root `10001`/`10002`, zero `docker.sock` mounts.
- **Webhook & Secrets:** HMAC-SHA256 signature + replay ledger (`WebhookDelivery`), log/evidence secret redaction, and `0` Medium/High Bandit AST findings.

---

## 9. Infrastructure Readiness Matrix (Step 6)

| Infrastructure Requirement | Status | Evidence Basis |
| :--- | :---: | :--- |
| **1. External SSRF-filtering forward proxy** | **Not Provisioned / Not Tested** | No Squid/Smokescreen container in repo; **Production Blocker** for public Git cloning |
| **2. `GIT_EGRESS_PROXY_URL` fail-closed enforcement** | **Locally Verified** | Returns `403 SecurityPolicyViolationError` in `production`/`staging` when unset |
| **3. Production TLS certificates (`./ssl/redmercury.*`)** | **Not Provisioned** | Verified live Nginx TLS 1.2/1.3 using ephemeral self-signed RSA-2048 cert only |
| **4. Production secrets (`SECRET_KEY`, `POSTGRES_PASSWORD`, etc.)** | **Implemented in Code / Not Provisioned** | Fail-closed validation in `Settings` & `docker-compose.prod.yml`; operator must inject at deploy |
| **5. Docker production network isolation (`internal: true`)** | **Implemented in Code & Compose Validated** | `redmercury_internal` & `redmercury_worker_isolated` declared `internal: true` |
| **6. PostgreSQL 16 backups & recovery** | **Live Infrastructure Verified** | `pg_dump` / `psql` restore + Alembic `0001 -> 0014` verified on live `postgres:16-alpine` |
| **7. Redis 7 failure & recovery behaviour** | **Live Infrastructure Verified** | Outbox & cancellation fault matrix verified on live `redis:7-alpine` |
| **8. Health & job observability probes** | **Live Infrastructure Verified** | `/live`, `/ready`, `/api/v1/health/live`, `/api/v1/health/ready`, `/api/v1/health/jobs` |
| **9. Worker crash recovery & orphan reaping** | **Live Infrastructure Verified** | Verified on live PostgreSQL 16, OS child processes, and Docker `redmercury-worker:latest` |
| **10. Structured JSON logging & correlation IDs** | **Locally Verified** | `X-Request-ID` propagation & secret scrubbing verified |
| **11. Remote GitHub Actions CI** | **Locally Verified / Not Executed Remotely** | `node:22-alpine`, `pip_audit`, `postgres:16-alpine`, `redis:7-alpine`, `Bandit` verified locally; awaiting `git push` |

---

## 10. Full Regression Results (Step 7)

All suites executed cleanly in Phase 7F with live PostgreSQL 16, Redis 7, and Docker active:

| Command | Exit Code | Passed | Failed | Skipped |
| :--- | :---: | :---: | :---: | :---: |
| `python -m pytest tests/ -q --tb=short` *(includes 7E, 7C, 7A, 7, 6, Live Docker, Postgres 16)* | **`0`** | **`629`** | **`0`** | **`2`** *(POSIX-only tests on Windows)* |
| `npm --prefix frontend run test` (`vitest run`) | **`0`** | **`46`** | **`0`** | **`0`** |
| `npm --prefix frontend run lint` (`tsc --noEmit`) | **`0`** | **`1`** | **`0`** | **`0`** |
| `npm --prefix frontend run build` (`vite build`) | **`0`** | **`1`** | **`0`** | **`0`** |
| `node --test electron/security.test.cjs` | **`0`** | **`10`** | **`0`** | **`0`** |
| `python -m bandit -r backend/app -ll -ii -q` | **`0`** | **`0` issues** | **`0`** | **`0`** |
| `docker compose -f docker-compose.prod.yml config -q` | **`0`** | **`1`** | **`0`** | **`0`** |

---

## 11. New Findings (Step 8)

- **Finding P7F-F01 (`Low` — Explicit Session-Wide Cleanup Scope in `_clear_all_fenced_leases`):**
  - **Affected File & Function:** [backend/app/core/jobs.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/jobs.py#L1501) (`_clear_all_fenced_leases()` called at lines `851, 923, 978, 1116, 1700, 2048, 2113, 2220`).
  - **Root Cause:** `_clear_all_fenced_leases(db)` pops all entries from `_fenced_leases_by_tx` and `_fenced_job_leases` on `db`.
  - **Exploitability & Impact:** **Not exploitable** in current production code paths because lifecycle helpers run on isolated sessions (`JobHeartbeatMonitor` / FastAPI request `db`) or after business writes finish (`complete_claimed_job` / `fail_claimed_job`). Calling `recover_expired_job_leases(db=worker_db)` or `record_job_runtime_artifacts(db=worker_db)` mid-transaction on an uncommitted worker session would clear that session's active fence (`INV_B_AFTER_HELPER_ON_SAME_SESSION: 0`).
  - **Recommended Minimal Remediation:** Not required before production; as future hardening, clear only the specific `job_id` being transitioned and omit `_clear_all_fenced_leases(sess)` inside `record_job_runtime_artifacts()`.

---

## 12. Residual Risks & 13. Production Deployment Blockers

1. **External SSRF-Filtering Forward Proxy (`GIT_EGRESS_PROXY_URL`):** Remains a **Production Blocker** if public Git URL cloning is enabled in production (application remains fail-closed `403` until provisioned and verified against the live proxy appliance).
2. **Production TLS & Secrets:** Operator must provision `./ssl/redmercury.crt`, `./ssl/redmercury.key`, `SECRET_KEY`, `POSTGRES_PASSWORD`, and `GITHUB_WEBHOOK_SECRET`.
3. **Remote GitHub Actions CI:** Operator must commit and push the verified working tree to `main` to observe the remote GitHub-hosted workflow pass.

---

## 14. Final Release-Candidate Decision

**CONDITIONALLY ACCEPTED**

- **Code & Distributed Systems Readiness:** Application security, multi-tenant isolation, PostgreSQL transaction-scoped lease fencing, outbox crash recovery, and container hardening are **verified ready**.
- **Operational Production Readiness:** Conditioned on provisioning the external `GIT_EGRESS_PROXY_URL` proxy appliance, production TLS/secrets, and executing the remote GitHub Actions CI run upon push.

---

## 15. Exact Recommended Next Action

1. **Commit and push** the verified Phase 1–7F working tree to `main` (or a release branch) to execute and confirm the remote GitHub Actions CI release gate (`Red Mercury CI - Test, Lint, Security Audit & Release Gate`).
2. **Provision** an SSRF-filtering forward proxy (e.g., Smokescreen) on the deployment network, configure `GIT_EGRESS_PROXY_URL`, supply production TLS certificates and secrets, and run a smoke test of `POST /api/v1/repositories/ingest/git` against the live proxy in staging before production cutover.
