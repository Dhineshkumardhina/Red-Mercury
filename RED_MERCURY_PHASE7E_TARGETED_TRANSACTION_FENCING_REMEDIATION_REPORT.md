# RED MERCURY — PHASE 7E
# TARGETED P7D-F01 REMEDIATION & INDEPENDENT TRANSACTION INTEGRITY VERIFICATION REPORT

**Repository:** `https://github.com/Dhineshkumardhina/Red-Mercury`  
**Product:** Red Mercury — Enterprise Application Security & Automated Fix Verification Engine  
**Organization:** Xerova Digital Solutions  
**Branch:** `main`  
**HEAD Commit:** `b9df7b9650e0ba431e8d32b19edf30ddd6f6289c` (`b9df7b9`)  
**Previous Phases:** Phase 7A, Phase 7B, Phase 7C, Phase 7D  
**Phase:** Phase 7E — Targeted P7D-F01 Remediation & Independent Transaction Integrity Verification  
**Completion Date:** 2026-11-22  

---

## 1. Executive Summary

Phase 7E remediated **P7D-F01** (identified in Phase 7D) in [backend/app/core/jobs.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/jobs.py), replacing coarse `after_commit` / `after_rollback` session-wide clearing of `_fenced_job_leases` with `SessionTransaction`-scoped lease ownership tracked via `before_commit` and `after_transaction_end`.

Independent reproduction against live **PostgreSQL 16.13** (`rm_test_postgres`) confirmed that the original Phase 7D savepoint-rollback failure is completely eliminated, and all **9 mandatory regression scenarios (`Test A`–`Test I`)** plus the full multi-layer regression suite (`629 passed, 2 skipped, 0 failed` backend; `46 passed` frontend; `10 passed` Electron; `0` Bandit medium/high findings; `exit code 0` Compose config) passed without regression.

---

## 2. Original P7D-F01 Description & 3. Root Cause

- **Affected File:** [backend/app/core/jobs.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/jobs.py) (`_clear_fenced_leases_after_rollback`).
- **Root Cause:** SQLAlchemy fires `after_rollback(session)` for **both** outer transaction rollbacks and nested `SAVEPOINT` (`session.begin_nested()`) rollbacks. Unconditionally executing `session.info.pop("_fenced_job_leases", None)` inside `after_rollback` wiped outer-transaction lease registrations whenever an inner savepoint rolled back.

---

## 4. SQLAlchemy Lifecycle Investigation (`SQLAlchemy 2.1.3`)

Executed an independent SQLAlchemy `SessionTransaction` probe to verify exact event ordering:
1. **Nested Savepoint Rollback (`with s.begin_nested(): raise ...`):**
   - `after_rollback` fires with `s.get_transaction() == outer_tx`.
   - `after_transaction_end(sess, tx)` fires with `tx == sp_tx` (`tx.nested=True`, `tx.parent == outer_tx`, `tx.is_active=False`).
   - `after_soft_rollback(sess, prev_tx)` fires with `prev_tx == sp_tx`.
2. **Nested Savepoint Commit (`with s.begin_nested():` clean exit):**
   - `before_commit` fires with `sess.in_nested_transaction() == True`.
   - `after_commit` fires.
   - `after_transaction_end(sess, tx)` fires with `tx == sp2_tx` (`tx.nested=True`, `tx.parent == outer_tx`).
3. **Outer Transaction Commit (`s.commit()`):**
   - `before_commit` fires with `sess.in_nested_transaction() == False`.
   - `after_commit` fires.
   - `after_transaction_end(sess, tx)` fires with `tx == outer_tx` (`tx.nested=False`, `tx.parent=None`).

---

## 5. Chosen Remediation Design & 7. Transaction Ownership Model

Implemented in [backend/app/core/jobs.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/jobs.py#L1467-L1593):
1. **Transaction-Scoped Ownership (`_fenced_leases_by_tx`):**
   - `assert_active_worker_lease_or_abort()` determines the owning transaction (`owning_tx = db.get_nested_transaction() or db.get_transaction()`) and stores the lease tuple `(job_id, worker_id, lease_token)` keyed by `id(owning_tx)` (an integer, retaining **zero** `SessionTransaction` object references and preventing memory leaks).
   - `_sync_flat_fenced_leases(session)` keeps `session.info["_fenced_job_leases"]` synchronized as the union of all active transaction sets.
2. **Commit Marking & Outer Fence Enforcement (`before_commit`):**
   - Records `id(active_tx)` in `session.info["_committed_fenced_tx_ids"]`.
   - If `session.in_nested_transaction()` is `True`, defers the PostgreSQL row-locking `UPDATE durable_jobs` check until the outer transaction commits (preserving savepoint leases via promotion).
   - On outer commit, executes the atomic conditional `UPDATE durable_jobs SET heartbeat_at = :now WHERE id = :jid AND status = 'running' AND worker_id = :wid AND lease_token = :tok AND lease_expires_at > :now` for every fenced job in `sorted(fenced_set)`.
3. **Exact Cleanup & Promotion (`after_transaction_end`):**
   - If `transaction.parent is None` (outer transaction ended — commit or rollback): clears `_fenced_leases_by_tx`, `_fenced_job_leases`, and `_committed_fenced_tx_ids` via `_clear_all_fenced_leases(session)`.
   - If `transaction.parent is not None` (nested savepoint ended):
     - Pops `id(transaction)` from `_fenced_leases_by_tx`.
     - If `id(transaction)` was marked committed in `before_commit`, promotes its leases into `by_tx[id(transaction.parent)]`.
     - Otherwise (savepoint rolled back), discards **only** that savepoint's leases while leaving `transaction.parent`'s leases intact.
4. **Explicit Lifecycle Clearing (`_clear_all_fenced_leases(db)`):**
   - Updated `renew_job_lease()`, `complete_claimed_job()`, `fail_claimed_job()`, `release_claimed_job_on_shutdown()`, `acknowledge_job_cancellation()`, `cancel_durable_job()`, `recover_expired_job_leases()`, and `record_job_runtime_artifacts()` to call `_clear_all_fenced_leases(db)` before committing durable-job state transitions.

---

## 6. Exact Files Modified / Created

- **Modified:** [backend/app/core/jobs.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/jobs.py) — Transaction-scoped `_fenced_leases_by_tx`, `before_commit`, and `after_transaction_end` cleanup/promotion.
- **Created:** [tests/test_phase7e_transaction_fencing.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/tests/test_phase7e_transaction_fencing.py) — All 9 mandatory scenarios (`Test A`–`Test I`) + lifecycle logging on live PostgreSQL 16.
- **Created:** [RED_MERCURY_PHASE7E_TARGETED_TRANSACTION_FENCING_REMEDIATION_REPORT.md](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/RED_MERCURY_PHASE7E_TARGETED_TRANSACTION_FENCING_REMEDIATION_REPORT.md) — This report.

---

## 8. Before / After Event Lifecycle Evidence (Independent Probe on Live PostgreSQL 16)

| Step | Phase 7D (Before Fix) | Phase 7E (After Fix) |
| :--- | :--- | :--- |
| 1. Fence Job A in outer tx | `AFTER_FENCE_A: 1` | `AFTER_FENCE_A: 1` |
| 2. Fence Job B in nested savepoint | `AFTER_FENCE_B_IN_SP: 2` | `AFTER_FENCE_B_IN_SP: 2` |
| 3. Roll back nested savepoint | `AFTER_SP_ROLLBACK: 0` *(Job A lost!)* | `AFTER_SP_ROLLBACK: 1 jobA_present= True jobB_present= False` |
| 4. Steal Job A & commit outer tx | `OUTER_COMMIT_SUCCEEDED` *(Bypassed!)* | `OUTER_COMMIT: Correctly fenced (StaleWorkerLeaseError raised)` |

---

## 9. All Nine Regression Scenarios & 10. Live PostgreSQL Verification Details

Executed in `test_phase7e_all_nine_transaction_fencing_scenarios_on_live_postgres` against live **PostgreSQL 16.13** (`rm_test_postgres`):

| Scenario | Description | Result |
| :--- | :--- | :---: |
| **Test A** | Outer lease survives nested savepoint rollback; Job B removed; outer commit succeeds | **PASSED** |
| **Test B** | Outer lease stolen during nested rollback $\rightarrow$ outer commit raises `StaleWorkerLeaseError`, 0 rows committed | **PASSED** |
| **Test C** | Nested lease stolen after savepoint rollback $\rightarrow$ outer commit succeeds cleanly (Job B no longer fenced) | **PASSED** |
| **Test D** | Successful nested savepoint promotes Job B to outer tx $\rightarrow$ stealing Job B rejects outer commit | **PASSED** |
| **Test E** | Multiple nested savepoints (SP1 Job B commits, SP2 Job C rolls back) $\rightarrow$ Job A + B survive, C removed | **PASSED** |
| **Test F** | Full outer rollback clears `_fenced_job_leases` and `_fenced_leases_by_tx` completely | **PASSED** |
| **Test G** | Session reuse after commit, full rollback, nested rollback, and `StaleWorkerLeaseError` | **PASSED** |
| **Test H & I** | Multiple fenced jobs + concurrent lease takeover across two PostgreSQL sessions via `claim_durable_job_by_id` | **PASSED** |

---

## 11. Full Regression Results & 12. Comparison with Phase 7D Baseline

| Suite / Gate | Phase 7D Baseline | Phase 7E Result |
| :--- | :--- | :--- |
| **Phase 7E Transaction Fencing Suite (`test_phase7e_transaction_fencing.py`)** | N/A | **`1 passed, 0 skipped, 0 failed`** |
| **Phase 7C Targeted Remediation Suite (`test_phase7c_targeted_remediation.py`)** | `7 passed` | **`7 passed, 0 skipped, 0 failed`** |
| **Phase 7A Distributed Security Suite (`test_phase7a_distributed_security_hardening.py`)** | `6 passed` | **`6 passed, 0 skipped, 0 failed`** |
| **Phase 7 Production Verification (`test_phase7_production_deployment_verification.py`)** | `8 passed` | **`8 passed, 0 skipped, 0 failed`** |
| **Phase 6 Durable Job Suite (`test_phase6_durable_job_execution.py`)** | `16 passed` | **`16 passed, 0 skipped, 0 failed`** |
| **Complete Backend Pytest Suite (`python -m pytest tests/ -q --tb=short`)** | `628 passed, 2 skipped` | **`629 passed, 2 skipped, 0 failed`** (`631` total) |
| **Frontend Vitest (`npm --prefix frontend run test`)** | `46 passed` | **`46 passed, 0 failed`** |
| **Frontend TypeScript (`npm --prefix frontend run lint`)** | `0` errors | **`0` errors** |
| **Frontend Build (`npm --prefix frontend run build`)** | `exit code 0` | **`exit code 0`** |
| **Electron Security Tests (`node --test electron/security.test.cjs`)** | `10 passed` | **`10 passed, 0 failed`** |
| **Bandit AST Security Scan (`bandit -r backend/app -ll -ii -q`)** | `exit code 0` | **`0` Medium/High issues (`exit code 0`)** |
| **Docker Compose (`docker compose -f docker-compose.prod.yml config -q`)** | `exit code 0` | **`exit code 0`** |

---

## 13. Remaining Limitations

1. **External SSRF-Filtering Forward Proxy (`GIT_EGRESS_PROXY_URL`):** No external proxy appliance (e.g., Smokescreen/Squid) is bundled locally; `production` and `staging` remain fail-closed (`403`) until configured.
2. **Remote GitHub Actions CI Run:** Locally verified (`node:22-alpine`, `pip_audit`, `postgres:16-alpine`, `redis:7-alpine`, `Bandit`), awaiting commit/push to verify the remote GitHub-hosted workflow run.

---

## 14. Git Branch, HEAD & 15. No-Commit / No-Push Confirmation

- **Branch:** `main`
- **HEAD:** `b9df7b9650e0ba431e8d32b19edf30ddd6f6289c`
- **Confirmation:** Zero `git commit`, `git push`, `git merge`, `git reset`, `git clean`, or deployment operations were executed. All Phase 0–7D modifications and reports remain intact.

---

### P7D-F01 Classification & Final Security Recommendation

- **P7D-F01 Classification:** **VERIFIED REMEDIATED**
- **Final Recommendation:** **CONDITIONALLY ACCEPTED** *(all code-level and distributed-transaction security defects across Phases 0–7E are remediated and verified against live PostgreSQL 16, Redis 7, Docker, Nginx, and headless Chromium; unconditional production acceptance awaits operator provisioning of the external `GIT_EGRESS_PROXY_URL` proxy appliance and pushing the verified working tree to `main` to run the remote GitHub Actions CI gate).*
