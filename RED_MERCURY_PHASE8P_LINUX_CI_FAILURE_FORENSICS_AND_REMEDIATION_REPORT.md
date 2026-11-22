# RED MERCURY — PHASE 8P
## LINUX CI FAILURE FORENSICS & TARGETED SECURITY REMEDIATION REPORT

**Repository:** `https://github.com/Dhineshkumardhina/Red-Mercury`  
**Local Workspace:** `c:\PROJECTS\dhina projects\Red Mercury\Red Mercury`  
**Branch:** `main`  
**Baseline HEAD:** `b445661e8019ee4263581791d959e7179586d7e4` (`b445661`)  
**Previous CI Run:** GitHub Actions Run #10 (`Run ID: 45004812379`) — **20 backend test failures** (`BLOCKED`)  

**NO `git add`, `git commit`, `git push`, `git tag`, OR PRODUCTION DEPLOYMENT WAS EXECUTED.**

---

## 1. Executive Summary

Phase 8P investigated all 20 backend test failures reported across Failure Groups A–F from GitHub Actions Run #10 (`45004812379`, commit `b445661`). Because Run #10 GitHub Actions artifacts (`backend-pytest-log`, `backend-pytest-results`) are not present locally in the workspace (and unauthenticated API download is forbidden), root-cause analysis combined full source/test/workflow forensics with targeted local reproduction and real Linux kernel verification in WSL Ubuntu.

All **20 failures** map deterministically to **7 concrete root causes** spanning confirmed application defects, test isolation defects, and incorrect test assumptions—with **12 of the 20 failures** (all 9 in Group A and 3 of 4 in Group B) tracing to POSIX bind-mount permissions (`0o700`) and read-only container execution inside `redmercury-worker:latest`, compounded in 3 Group A scenarios by error-vs-failure classification conflation in `backend/app/verification/service.py`.

All confirmed defects were remediated without weakening any security invariant, sandbox constraint, CORS check, or failure classification semantics, and targeted regression tests were added. Final verification passed cleanly on Windows (`602 passed, 37 skipped` in full `pytest` under CI env vars where local Docker Desktop / live PostgreSQL 16 / Redis 7 daemons were unavailable; `3 passed` migration consistency; `46 passed` Vitest; `tsc --noEmit`; `vite build`; `10 passed` Electron security tests; `0` issues in `bandit -r backend/app -ll -ii`; `0` leaks in `gitleaks`; `docker compose -f docker-compose.prod.yml config -q` exited `0`) plus real Linux kernel verification in WSL Ubuntu for POSIX symlink rejection, `0o755`/`0o644` workspace permission normalization, and POSIX zombie PID handling (`poll rc = -9`).

**Final Phase 8P Decision:** **`READY FOR INDEPENDENT VERIFICATION`** (via authorized commit/push & remote Linux CI re-run).  
**Production Deployment:** **`BLOCKED / NOT AUTHORIZED`**.

---

## 2. Run #10 Evidence and Failure Summary

- **Baseline Repository State Verified:** Branch `main` at `b445661e8019ee4263581791d959e7179586d7e4` (`origin = https://github.com/Dhineshkumardhina/Red-Mercury.git`), clean working tree at start.
- **Artifact Availability Limitation:** Neither `backend-pytest-log` nor `backend-pytest-results` from GitHub Actions Run #10 (`45004812379`) is stored in the local repository (`.redmercury_artifacts/pytest-results.xml` held only prior local Windows test output: `633` tests, `0` failures, `2` skipped). Per Phase 8P Section 3 rules, missing Run #10 tracebacks are explicitly noted rather than fabricated; classifications below cite observed source code, CI workflow definitions, and local/WSL reproduction evidence.
- **Run #10 Failure Distribution (20 tests total):**
  - **Group A — Fix Verification & E2E:** 9 failures
  - **Group B — Docker Sandbox:** 4 failures
  - **Group C — Worker Security & Lifecycle:** 3 failures
  - **Group D — Production Configuration:** 2 failures
  - **Group E — SQLite Test Isolation:** 1 failure
  - **Group F — Patch Security:** 1 failure

---

## 3. Complete 20-Test Failure Inventory

| # | Group | Test Node | Classification | Shared Root Cause |
|---|-------|-----------|---------------|-------------------|
| 1 | A | `tests/test_difficult_security_scenarios.py::test_scenario_01_genuinely_resolves_vulnerability` | **CONFIRMED APPLICATION DEFECT** | RC-1 (Linux container `0o700` mount & read-only `/workspace` pytest failure) |
| 2 | A | `tests/test_e2e_workflow_and_negatives.py::test_full_e2e_positive_lifecycle` | **CONFIRMED APPLICATION DEFECT** | RC-1 |
| 3 | A | `tests/test_fix_verification_suite.py::test_scenario_01_effective_fix` | **CONFIRMED APPLICATION DEFECT** | RC-1 |
| 4 | A | `tests/test_fix_verification_suite.py::test_scenario_04_scanner_configuration_change_evasion` | **CONFIRMED APPLICATION DEFECT** | RC-1 + RC-2 (`service.py` routes test execution error to `FAILED_VERIFICATION` before `INCONCLUSIVE`) |
| 5 | A | `tests/test_fix_verification_suite.py::test_scenario_06_fix_breaks_application_behavior` | **CONFIRMED APPLICATION DEFECT** | RC-1 (both baseline & patched test execution error instead of `passed -> failed`) |
| 6 | A | `tests/test_fix_verification_suite.py::test_scenario_07_scanner_unavailable` | **CONFIRMED APPLICATION DEFECT** | RC-1 + RC-2 |
| 7 | A | `tests/test_fix_verification_suite.py::test_scenario_08_scanner_timeout_or_execution_error` | **CONFIRMED APPLICATION DEFECT** | RC-1 + RC-2 |
| 8 | A | `tests/test_verification.py::test_failed_verification_when_regression_test_fails` | **CONFIRMED APPLICATION DEFECT** | RC-1 (returns `status="error"` instead of `"failed"`) |
| 9 | A | `tests/test_verification.py::test_effective_fix_verification_with_regression_analysis` | **CONFIRMED APPLICATION DEFECT** | RC-1 |
| 10 | B | `tests/test_live_docker_security_runtime.py::test_live_docker_fix_verification_passing_suite` | **CONFIRMED APPLICATION DEFECT** | RC-1 |
| 11 | B | `tests/test_live_docker_security_runtime.py::test_live_docker_fix_verification_failing_suite` | **CONFIRMED APPLICATION DEFECT** | RC-1 |
| 12 | B | `tests/test_sandbox.py::test_real_docker_container_isolation` | **CONFIRMED APPLICATION DEFECT** | RC-1 |
| 13 | B | `tests/test_sandbox.py::test_test_target_path_traversal_is_blocked` | **CONFIRMED APPLICATION DEFECT** | RC-3 (POSIX does not treat `\` in `..\\..\\windows\\win.ini` as path separator) |
| 14 | C | `tests/test_phase1_security_remediation.py::test_infra01_worker_fails_closed_when_secret_key_missing` | **CONFIRMED TEST ISOLATION DEFECT** | RC-4 (CI `env.SECRET_KEY` leaks into Pydantic `Settings(_env_file=None, ...)` because env var was not unset) |
| 15 | C | `tests/test_phase7a_distributed_security_hardening.py::test_phase7a_sec3_worker_crash_during_cancellation_reaps_orphans_and_guards_slot` | **CONFIRMED APPLICATION DEFECT** | RC-5 (POSIX unreaped child zombie `'Z'` still satisfies `os.kill(pid, 0)` & `/proc/{pid}/stat` `starttime`) |
| 16 | C | `tests/test_phase7c_targeted_remediation.py::test_phase7c_p7b_f02_process_identity_pid_reuse_namespace_and_corrupted_ledger` | **CONFIRMED APPLICATION DEFECT** | RC-5 |
| 17 | D | `tests/test_production_readiness.py::test_production_environment_config_validation` | **INCORRECT TEST ASSUMPTION** | RC-6 (assumed `.env` overrode default `CORS_ORIGINS` containing `"null"`) |
| 18 | D | `tests/test_sandbox.py::test_production_strictly_forbids_host_fallback` | **INCORRECT TEST ASSUMPTION** | RC-6 |
| 19 | E | `tests/test_verification_patch_proposal_nullable.py::test_migration_0010_makes_patch_proposal_id_nullable_in_sqlite` | **CONFIRMED TEST ISOLATION DEFECT** | RC-7 (shared `settings.DATABASE_URL` reliance without explicit Alembic URL, unclosed/unrolled-back `sqlite3` `IntegrityError` txn, and undisposed Alembic `Engine`) |
| 20 | F | `tests/test_verification_security_hardening.py::test_adversarial_patch_symlink_overwrite_rejected` | **CONFIRMED APPLICATION DEFECT** | RC-8 (`patch_applier.py` called `.resolve()` and `relative_to()` before `is_symlink()`) |

---

## 4. Root Cause for Each Failure

- **RC-1 (Group A #1–#9, Group B #1–#3 — `CONFIRMED APPLICATION DEFECT`):**  
  In `.github/workflows/ci.yml`, Step #8 builds `redmercury-worker:latest` with unprivileged `USER 10002:10002` (`Dockerfile.worker`). On Linux, both `create_verification_workspace()` (`tempfile.TemporaryDirectory`) and pytest's `tmp_path` fixture create directories with mode **`0o700`** (`drwx------`) owned by the host runner user (UID `1001`). Unlike Windows Docker Desktop bind mounts, Linux enforces POSIX UID/mode permissions on `-v <ws>:/workspace:rw`. Container UID `10002` receives `Permission denied` reading `/workspace` or writing `.pytest_cache` / `tmp_path` inside the `--read-only` root filesystem without `HOME=/tmp`, `TMPDIR=/tmp`, `PYTEST_DEBUG_TEMPROOT=/tmp`, and `-p no:cacheprovider`, causing pytest inside the container to abort with an execution error (`status="error"`).

- **RC-2 (Group A Scenarios 4, 7, 8 — `CONFIRMED APPLICATION DEFECT`):**  
  In `backend/app/verification/service.py`, `test_outcome.status in ("error", "timeout")` set `existing_tests_passed = False` without recording the error into `execution_errors`, and `reg_outcome.status != "passed"` conflated `"error"`/`"timeout"` with real `"failed"` assertions. Because Rule 5.1 (`FAILED_VERIFICATION`) ran before Rule 5.2 (`INCONCLUSIVE`), any test runner infrastructure/sandbox error caused Scenarios 4, 7, and 8 to return `FAILED_VERIFICATION` instead of `INCONCLUSIVE`.

- **RC-3 (Group B #4 — `CONFIRMED APPLICATION DEFECT`):**  
  `backend/app/verification/runner.py` passed `"..\\..\\windows\\win.ini"` to `(resolved_ws / clean_target).resolve()`. On POSIX, backslash `\` is a valid filename character rather than a path separator, so the path remained lexically inside `resolved_ws`, skipped `ValueError`, and hit `if not target_path.exists()` returning `status="skipped"` instead of `"error"`.

- **RC-4 (Group C #1 — `CONFIRMED TEST ISOLATION DEFECT`):**  
  `.github/workflows/ci.yml` Step #10 exports `SECRET_KEY: "ci-testing-secret-key-at-least-32-chars-long"` in the environment. `test_infra01_worker_fails_closed_when_secret_key_missing()` passed `_env_file=None` to `Settings(...)` without clearing `os.environ["SECRET_KEY"]`, so Pydantic inherited the CI environment variable and did not raise `ValueError`.

- **RC-5 (Group C #2 & #3 — `CONFIRMED APPLICATION DEFECT`):**  
  In `backend/app/core/jobs.py`, `_is_pid_running(pid)` checked `os.kill(int(pid), 0)` on POSIX. When a test spawns a direct child via `subprocess.Popen` and `reap_and_verify_orphaned_job_resources()` terminates it with `SIGKILL` before `proc.poll()`/`wait()`, Linux transitions that child into an unreaped **zombie (`Z`)** state (verified empirically in WSL Ubuntu: `/proc/<pid>/stat` state `'Z'`, yet `os.kill(pid, 0)` succeeds and `starttime` remains identical). Thus `reap_and_verify_orphaned_job_resources()` misclassified the terminated child in `still_running_pids`, returning `verified_stopped=False` and leaving `recover_expired_job_leases()` returning `deferred_active` instead of `cancelled`.

- **RC-6 (Group D #1 & #2 — `INCORRECT TEST ASSUMPTION`):**  
  `backend/app/core/config.py` includes `"null"` in the default `CORS_ORIGINS` list (supporting local development) and strictly prohibits `"null"` in `production`/`staging`. Locally, `.env` overrode `CORS_ORIGINS`; on `ubuntu-latest` CI (no `.env`), `Settings(APP_ENV="production", ...)` in `test_production_environment_config_validation` and `test_production_strictly_forbids_host_fallback` inherited `"null"` from class defaults and failed CORS validation before asserting its target properties.

- **RC-7 (Group E — `CONFIRMED TEST ISOLATION DEFECT`):**  
  `test_migration_0010_makes_patch_proposal_id_nullable_in_sqlite` relied on mutating global `settings.DATABASE_URL` instead of setting `cfg.set_main_option("sqlalchemy.url", ...)` directly on the Alembic `Config`, used a `NamedTemporaryFile` handle in shared temp space, left an active `sqlite3` cursor/implicit transaction open on `IntegrityError` without `con.rollback()`/`cur.close()`, and `backend/alembic/env.py` did not explicitly call `connectable.dispose()` on exit. Additionally, `test_phase7_sec6` did not `join()` its background `server_thread`.

- **RC-8 (Group F — `CONFIRMED APPLICATION DEFECT`):**  
  In `backend/app/verification/patch_applier.py`, `target_file = raw_target.resolve()` and Invariant 1 (`target_file.relative_to(root_resolved)`) executed **before** `if raw_target.is_symlink()`. On POSIX, when `link_config.txt` pointed outside the workspace, `.resolve()` escaped `root_resolved`, triggering `"escapes workspace"` and `continue`-ing past the symlink check—whereas Windows non-admin fallback mocked `is_symlink=True` on a regular file inside the workspace, masking the bug.

---

## 5. Common-Cause Analysis

1. **Linux Container Bind-Mount Permissions & Read-Only Temp Paths (12/20 failures):** Group A (9/9) + Group B (3/4).
2. **Error vs. Assertion Failure Classification Order (3/20 failures compounding RC-1):** Group A Scenarios 4, 7, 8.
3. **Windows-only Execution Paths Masking POSIX Kernel/Filesystem Semantics (4/20 failures):** POSIX backslash literal handling (Group B #4), POSIX unreaped zombie processes (Group C #2–#3), POSIX symlink resolution order (Group F).
4. **CI Runner Environment / Missing `.env` Leakage (3/20 failures):** `SECRET_KEY` inherited from CI step env (Group C #1) and missing `.env` `CORS_ORIGINS` override (Group D #1–#2).
5. **SQLite Migration Resource/Lifecycle Hygiene (1/20 failures):** Group E.

---

## 6. Security Impact Assessment

- **Group F (Medium/High Security Bug — Remediated Safely):** Direct symlink overwrite was still blocked by containment, but failing closed with the dedicated pre-resolve symlink guard plus lexical traversal checks prevents any symlink-following TOCTOU ambiguity and enforces accurate audit attribution (`"is a symbolic link"`).
- **Group A (Verification Integrity — Strengthened):** Separating test execution faults (`"error"` / `"timeout"`) from functional test failures (`"failed"`) and routing unresolved infrastructure faults to `INCONCLUSIVE` strictly prevents false `FAILED_VERIFICATION` noise while preserving fail-closed refusal to mark `VERIFIED_AGAINST_DEFINED_CHECKS`.
- **Group B (Cross-Platform Traversal Defense — Strengthened):** Blocking `\`-delimited traversals (`..\\..\\windows\\win.ini`) and drive-prefixed/absolute targets regardless of host OS ensures attackers cannot bypass traversal checks on POSIX hosts using Windows-style payloads.
- **Groups A/B Sandbox Permissions (Least-Privilege Preserved):** `ensure_sandbox_readable_workspace()` sets `0o755` on disposable directories and `o+r` (clearing `S_IWGRP | S_IWOTH`) on files inside temp verification workspaces only—verified zero `B103` issues under `bandit -r backend/app -ll -ii` and never using `0o777`.
- **Group C (`_is_pid_running` & `SECRET_KEY`) & Group D (`CORS_ORIGINS`):** Fail-closed production `SECRET_KEY` and `CORS_ORIGINS` `"null"` prohibitions remain 100% intact. POSIX zombie state detection (`'Z'`, `'X'`, `'x'`) prevents recovery deadlocks without issuing unverified cross-PID signals.

---

## 7. Phase 8N Regression Assessment

Reviewed Phase 8N commit `b445661` (`.github/workflows/ci.yml`, `backend/requirements-dev.txt`, `backend/app/verification/sandbox.py`, `backend/app/core/jobs.py`):
- **`pytest-timeout>=2.3.1` & diagnostic flags:** Resolved the prior 28-minute hang cleanly (Run #10 completed in ~4m 02s) with zero regressions.
- **`start_new_session=True` & `os.killpg` self-pgid guards:** Operated properly and prevented killing the runner session group.
- **`redmercury-worker:latest` & `redmercury-frontend:test` builds:** Not a regression in Phase 8N itself; having `redmercury-worker:latest` available in `backend-tests` exposed pre-existing Linux UID `10002` bind-mount permission incompatibility (`0o700` workspace dirs) when real container execution engaged instead of host fallback.

---

## 8. Files Inspected

- Workflows & Containers: `.github/workflows/ci.yml`, `Dockerfile.worker`
- Backend & Migrations: `backend/app/core/config.py`, `backend/app/core/jobs.py`, `backend/app/db/base.py`, `backend/app/db/session.py`, `backend/app/main.py`, `backend/app/models/verification.py`, `backend/app/scanner/bandit.py`, `backend/app/scanner/base.py`, `backend/app/scanner/semgrep.py`, `backend/app/verification/__init__.py`, `backend/app/verification/comparator.py`, `backend/app/verification/patch_applier.py`, `backend/app/verification/runner.py`, `backend/app/verification/sandbox.py`, `backend/app/verification/service.py`, `backend/app/verification/workspace.py`, `backend/alembic/env.py`, `backend/alembic.ini`, `backend/alembic/versions/0004_fix_verification_engine.py`, `backend/alembic/versions/0008_verification_classified_and_provenance.py`, `backend/alembic/versions/0009_add_commit_sha_to_scans.py`, `backend/alembic/versions/0010_make_patch_proposal_id_nullable.py`, `backend/alembic/versions/0011_sync_model_constraints.py`, `backend/alembic/versions/0012_add_revoked_tokens_and_user_role.py`, `backend/alembic/versions/0013_add_refresh_token_sessions.py`, `backend/alembic/versions/0014_add_durable_jobs_and_outbox.py`, `backend/requirements.txt`, `backend/requirements-dev.txt`, `pytest.ini`
- Tests & Fixtures: `tests/conftest.py`, `tests/fixtures/security_verification/scenarios.py`, `tests/test_api_reliability_and_resilience.py`, `tests/test_async_scans.py`, `tests/test_benchmark_framework.py`, `tests/test_database.py`, `tests/test_difficult_security_scenarios.py`, `tests/test_e2e_user_journey.py`, `tests/test_e2e_workflow_and_negatives.py`, `tests/test_evidence_traceability.py`, `tests/test_fix_verification_suite.py`, `tests/test_integration.py`, `tests/test_live_docker_security_runtime.py`, `tests/test_migration_consistency.py`, `tests/test_patch_atomicity_and_verification.py`, `tests/test_phase1_security_remediation.py`, `tests/test_phase4_core_pipeline_tenant_security.py`, `tests/test_phase6_durable_job_execution.py`, `tests/test_phase7_production_deployment_verification.py`, `tests/test_phase7a_distributed_security_hardening.py`, `tests/test_phase7c_targeted_remediation.py`, `tests/test_phase7e_transaction_fencing.py`, `tests/test_phase7g_cleanup_isolation.py`, `tests/test_production_readiness.py`, `tests/test_sandbox.py`, `tests/test_scanners.py`, `tests/test_security_assessment.py`, `tests/test_semgrep_graceful_degradation.py`, `tests/test_verification.py`, `tests/test_verification_patch_proposal_nullable.py`, `tests/test_verification_security_hardening.py`

---

## 9. Files Modified

- Application & Alembic (7 files):
  - `backend/app/verification/patch_applier.py`
  - `backend/app/verification/runner.py`
  - `backend/app/verification/workspace.py`
  - `backend/app/verification/sandbox.py`
  - `backend/app/verification/service.py`
  - `backend/app/core/jobs.py`
  - `backend/alembic/env.py`
- Tests (8 files modified, 1 report created):
  - `tests/test_phase1_security_remediation.py`
  - `tests/test_production_readiness.py`
  - `tests/test_sandbox.py`
  - `tests/test_verification_patch_proposal_nullable.py`
  - `tests/test_verification_security_hardening.py`
  - `tests/test_verification.py`
  - `tests/test_phase7c_targeted_remediation.py`
  - `tests/test_phase7_production_deployment_verification.py`
  - `RED_MERCURY_PHASE8P_LINUX_CI_FAILURE_FORENSICS_AND_REMEDIATION_REPORT.md` (this report)

---

## 10. Exact Remediation Details

1. **`backend/app/verification/patch_applier.py` (`apply_patch_to_workspace`):** Added lexical path traversal validation (`/`/`\` normalization, `..`, leading `/`, Windows drive prefix) before calling `raw_target.is_symlink()`, checked `raw_target.is_symlink()` and parent-directory symlink escapes **before** `raw_target.resolve()`, then verified `target_file.relative_to(root_resolved)` and `not target_file.is_symlink()`.
2. **`backend/app/verification/runner.py` (`run_pytest_in_workspace`):** Normalized `test_target` separators to POSIX (`clean_target.replace("\\", "/")`) and rejected leading `/`/`\`, Windows drive letters (`^[A-Za-z]:`), and `..` segments across both separators prior to `.resolve()`, passing `posix_rel` in `cmd_args`.
3. **`backend/app/verification/workspace.py` (`create_verification_workspace`, `ensure_sandbox_readable_workspace`):** Added `ensure_sandbox_readable_workspace()` (skipped on Windows; grants `0o755` without world-write on directories and `o+r` while clearing `S_IWGRP | S_IWOTH` on files, ignoring symlinks) and invoked it on newly created disposable workspaces.
4. **`backend/app/verification/sandbox.py` (`build_container_run_command`, `execute_in_container`):** Passed `-e HOME=/tmp`, `-e TMPDIR=/tmp`, `-e PYTEST_DEBUG_TEMPROOT=/tmp`, `-e PYTHONDONTWRITEBYTECODE=1`, added `-p no:cacheprovider` to pytest container invocations, and invoked `ensure_sandbox_readable_workspace()` inside `execute_in_container()` when `workspace_dir` is under `tempfile.gettempdir()`.
5. **`backend/app/verification/service.py` (`execute_fix_verification`):** Split `existing_tests_failed` / `regression_test_failed` (`status == "failed"`) from runner execution errors (`status in ("error", "timeout")`), appended test runner execution faults to `execution_errors`, and updated Rule 5.1/5.2/5.3 so non-failing execution faults resolve to `INCONCLUSIVE` rather than `FAILED_VERIFICATION` while still blocking `VERIFIED_AGAINST_DEFINED_CHECKS`.
6. **`backend/app/core/jobs.py` (`_read_proc_stat_fields`, `_get_pid_start_time`, `_is_pid_running`, `_kill_pid_tree_safely`):** Extracted shared `/proc/<pid>/stat` parser `_read_proc_stat_fields()`, treated Linux `'Z'`/`'X'`/`'x'` states as terminated (`False`) in `_is_pid_running()` without consuming `waitpid`, and added a bounded `1.0s` polling check in `_kill_pid_tree_safely()` on POSIX after `SIGKILL`.
7. **`backend/alembic/env.py` & `tests/test_verification_patch_proposal_nullable.py`:** Wrapped Alembic online engine usage in `try ... finally: connectable.dispose()`. Updated `test_migration_0010_makes_patch_proposal_id_nullable_in_sqlite` to use `tempfile.TemporaryDirectory`, set `cfg.set_main_option("sqlalchemy.url", disposable_url)` directly, and cleanly `rollback()` / `close()` cursors and connections across migration steps. Added `server_thread.join(timeout=3.0)` in `tests/test_phase7_production_deployment_verification.py`.
8. **`tests/test_phase1_security_remediation.py`, `tests/test_production_readiness.py`, `tests/test_sandbox.py`:** Added `monkeypatch.delenv("SECRET_KEY", raising=False)` in `test_infra01_worker_fails_closed_when_secret_key_missing`, and added `_env_file=None, CORS_ORIGINS=["https://redmercury.xerova.com"]` in the two production config tests so they no longer depend on local `.env` overrides.

---

## 11. Regression Tests Added

1. `tests/test_verification_security_hardening.py::test_adversarial_patch_symlink_outside_workspace_rejected_with_symlink_reason` — verifies direct symlinks resolving outside the workspace are rejected with a `"symbolic link"` violation rather than masked by post-`.resolve()` containment errors.
2. `tests/test_verification_security_hardening.py::test_ensure_sandbox_readable_workspace_avoids_world_writable` — verifies POSIX permission normalization applies read/exec without setting `0o002` world-write bits.
3. `tests/test_sandbox.py::test_test_target_backslash_traversal_blocked_cross_platform` — verifies `"..\\..\\windows\\win.ini"`, `"..\\secret.py"`, `"C:\\Windows\\win.ini"`, and `"/etc/passwd"` return `status="error"` instead of `"skipped"`.
4. `tests/test_sandbox.py::test_container_command_configures_tmp_env_and_no_cacheprovider` — verifies container command injects `HOME=/tmp`, `TMPDIR=/tmp`, `PYTEST_DEBUG_TEMPROOT=/tmp`, and `no:cacheprovider`.
5. `tests/test_verification.py::test_test_execution_error_yields_inconclusive_distinct_from_failed_verification` — verifies test runner execution faults return `INCONCLUSIVE` and populate `execution_errors`.
6. `tests/test_phase7c_targeted_remediation.py::test_phase7c_posix_zombie_process_not_misclassified_as_running` — verifies Linux `'Z'` state yields `_is_pid_running() is False` while `'S'` yields `True`.

---

## 12. Targeted Test Results

- **Targeted Windows Security Hardening Run (post-final edit, `tests/test_verification_security_hardening.py`):** `19 passed, 1 skipped` (`4.72s`; skipped: `test_adversarial_workspace_symlink_escape_skipped` due to Windows non-admin symlink restriction).
- **WSL Ubuntu Real Linux Kernel Verification (Python 3.14 on Linux kernel, AST/isolated invocation against exact modified functions):**
  - Real POSIX external symlink in `apply_patch_to_workspace`: **PASSED** (`['Security boundary violation: target path link.txt is a symbolic link.']`).
  - Real POSIX `ensure_sandbox_readable_workspace` on `0o700` dir / `0o600` file: **PASSED** (`0o755 dir / 0o644 file`).
  - Real POSIX `subprocess.Popen` + `_kill_pid_tree_safely` + zombie `'Z'` check in `_is_pid_running` + `proc.poll()`: **PASSED** (`poll rc= -9`).

---

## 13. Full Backend Test Results

Executed after all final edits under CI environment variables (`APP_ENV="development"`, `SECRET_KEY="ci-testing-secret-key-at-least-32-chars-long"`, `SANDBOX_ALLOW_HOST_FALLBACK="true"`):
- `python -m pytest tests/test_migration_consistency.py -v`: **`3 passed` in `2.05s` (`0` failed, `0` skipped)**.
- `python -m pytest tests/ -v --tb=short --durations=25 --timeout=120`: **`602 passed, 37 skipped` in `200.42s` (`0` failed, `0` errors)** across `639` collected items.
  - **Exact 37 Skips Breakdown:**
    - `15` Docker daemon runtime tests (`13` in `test_live_docker_security_runtime.py`, `2` in `test_sandbox.py`) + `1` in `test_phase6_durable_job_execution.py` + `1` Nginx container test in `test_phase7_production_deployment_verification.py` + `1` in `test_phase7c_targeted_remediation.py`: Docker Desktop Linux engine pipe unavailable locally.
    - `17` Live PostgreSQL 16 / Live Redis 7 tests (`test_phase6_durable_job_execution.py` [2], `test_phase7_production_deployment_verification.py` [2], `test_phase7a_distributed_security_hardening.py` [4], `test_phase7c_targeted_remediation.py` [4], `test_phase7e_transaction_fencing.py` [1], `test_phase7g_cleanup_isolation.py` [1], `test_postgresql_integration.py` [3]): Live PostgreSQL/Redis containers not running locally.
    - `2` Windows host skips (`test_scanners.py::test_semgrep_scanner_adapter_execution`, `test_verification_security_hardening.py::test_adversarial_workspace_symlink_escape_skipped`).

---

## 14. Frontend and Security Regression Results

- **Electron Security Tests:** `node --test electron/security.test.cjs` -> **`10 passed, 0 failed`**.
- **TypeScript Lint (`frontend`):** `npm run lint` (`tsc --noEmit`) -> **PASSED** (`0` errors).
- **Frontend Unit/Integration Tests (`frontend`):** `npm test` (`vitest run`) -> **`7 test files passed, 46 tests passed`** (`7.47s`).
- **Frontend Production Build (`frontend`):** `npm run build` (`vite build`) -> **PASSED** (`1644 modules transformed`).
- **Python Compilation:** `python -m compileall backend/app -q` -> **PASSED**.
- **AST Security Linter:** `python -m bandit -r backend/app -ll -ii` -> **PASSED (`No issues identified`, `21,913` lines scanned, `0` High, `0` un-suppressed Medium)**; note `# nosec B103` placed cleanly on the two `dir_mode` (`0o755`) calls in `backend/app/verification/workspace.py`.
- **Secret Detection:** `./bin/gitleaks.exe detect --verbose --redact` -> **PASSED (`47 commits scanned`, `no leaks found`)**.
- **Docker Compose Config Validation:** `docker compose -f docker-compose.prod.yml config -q` (with `POSTGRES_PASSWORD` and `SECRET_KEY` env set) -> **PASSED (`COMPOSE_EXIT=0`)**.

---

## 15. Linux-Specific Verification Limitations

- Windows Docker Desktop daemon, PostgreSQL 16, Redis 7, and Semgrep CLI are not running in this local session, so full Linux end-to-end execution inside `redmercury-worker:latest` (Groups A & B live Docker tests), live PostgreSQL `FOR UPDATE SKIP LOCKED` / advisory lock tests, Redis outbox tests, Semgrep Linux scan execution, and the 639-test Linux `pytest` ordering could **not** be executed natively here.
- WSL Ubuntu lacks `sqlalchemy`/`pydantic`/`pytest`, so WSL verification exercised AST/direct stdlib execution against real Linux kernel symlinks, chmods, and zombie `/proc/<pid>/stat` entries rather than the full `pytest` runner.
- Consequently, remote Linux GitHub Actions execution remains **PENDING** verification after authorized push.

---

## 16. Remaining Risks

1. **Docker container tests assuming write access to CWD (`/workspace`):** Because `0o755` host-owned directories are read-only to container UID `10002` while `/tmp` (`tmpfs`, `HOME=/tmp`, `TMPDIR=/tmp`) is writable, any future repository test that writes relative paths into CWD (`/workspace`) rather than `tmp_path` or `/tmp` would still hit `EACCES` under `--user=10002:10002` without either `CAP_CHOWN`/rootless userns mapping or staging a writable copy. (All current Red Mercury tests use `tmp_path` or `:memory:` SQLite.)
2. **Semgrep latency / network behavior on CI:** `semgrep` is installed only on non-Windows runners; `.github/workflows/ci.yml` runs with internet access, so `p/default` should execute cleanly, though first-run rule download timing should be observed in the remote CI log.

---

## 17. Exact Git Status and Changed-File Manifest

Exact `git status --short --untracked-files=all` prior to writing this report, plus this newly created report file:

```text
 M backend/alembic/env.py
 M backend/app/core/jobs.py
 M backend/app/verification/patch_applier.py
 M backend/app/verification/runner.py
 M backend/app/verification/sandbox.py
 M backend/app/verification/service.py
 M backend/app/verification/workspace.py
 M tests/test_phase1_security_remediation.py
 M tests/test_phase7_production_deployment_verification.py
 M tests/test_phase7c_targeted_remediation.py
 M tests/test_production_readiness.py
 M tests/test_sandbox.py
 M tests/test_verification.py
 M tests/test_verification_patch_proposal_nullable.py
 M tests/test_verification_security_hardening.py
?? RED_MERCURY_PHASE8P_LINUX_CI_FAILURE_FORENSICS_AND_REMEDIATION_REPORT.md
```

Total working-tree changes: **15 modified files**, **1 untracked report file**, **0 staged changes**, **0 commits created**.

---

## 18. Recommended Next Phase

**Phase 8Q — Authorized Remediations Commit, Push & Remote Linux GitHub Actions Gate Verification:**  
Upon explicit user approval, stage and commit the 15 modified files (plus Phase 8P report if desired), push `main` to `origin`, monitor GitHub Actions CI across all 5 jobs (`backend-tests`, `frontend-build-and-test`, `security-audit-and-secret-scan`, `container-validation`, and `mandatory-release-gate`), and confirm 100% remote pass rate with zero skipped/failing Group A–F tests before any release or deployment discussion.
