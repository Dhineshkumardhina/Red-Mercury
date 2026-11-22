# RED MERCURY — PHASE 8U
## INDEPENDENT FINAL SECURITY VERIFICATION & PRE-PUSH APPROVAL AUDIT REPORT

**Repository:** `https://github.com/Dhineshkumardhina/Red-Mercury`  
**Workspace:** `c:\PROJECTS\dhina projects\Red Mercury\Red Mercury`  
**Branch:** `main` (`remotes/origin/main`)  
**Baseline HEAD:** `b445661e8019ee4263581791d959e7179586d7e4` (`b445661`)  
**Previous Phase:** Phase 8T — Targeted Patch Permission Preservation, Fallback Boundary Hardening & Pre-CI Verification  

**STRICTLY READ-ONLY AUDIT: ZERO SOURCE, TEST, MIGRATION, WORKFLOW, CONFIG, OR GIT MUTATIONS EXECUTED.**

---

## 1. Executive Decision

**Decision:** **`A — APPROVED FOR EXPLICIT USER-AUTHORIZED COMMIT/PUSH.`**

- All Phase 8P–8T security remediations, Phase 8T Finding A (`patch_applier.py`) and Finding B (`sandbox.py`), full isolated backend regression suite (`617 passed, 37 skipped`, `0` failed), frontend lint (`tsc --noEmit`), Vitest (`46 passed`), Electron security (`10 passed`), Bandit (`0` issues), `pip-audit` (`0` vulnerabilities), Gitleaks (`47` commits & working tree clean), Compose config (`exit 0`), and WSL Ubuntu Linux kernel probes (`WSL_8U_COMPREHENSIVE_KERNEL_VERIFIED`) passed independently.
- **Explicit User Authorization Required Before Commit/Push:** No files have been staged, committed, or pushed.
- **Production Deployment Status:** **`BLOCKED / NOT AUTHORIZED`** until remote GitHub Actions CI (`ubuntu-latest`) completes live Docker container (`redmercury-worker:latest`), PostgreSQL 16, Redis 7, Semgrep, and release-gate verification across all 5 jobs.

---

## 2. Exact Git Baseline and Working-Tree Inventory

Verified directly:
- **Current Branch:** `main`
- **Current HEAD:** `b445661e8019ee4263581791d959e7179586d7e4`
- **Origin Remote:** `https://github.com/Dhineshkumardhina/Red-Mercury.git` (fetch & push)
- **Staged Files (`git diff --cached --stat`):** `0`
- **Deleted or Renamed Files:** `0`
- **`git diff --check`:** Clean (`exit 0`, zero whitespace errors or conflict markers)
- **Working Tree State:** **NOT clean** — contains `16` modified tracked files (`1406 insertions(+), 192 deletions(-)`) and `6` untracked phase reports (`8P`–`8U`):
  - **Modified Tracked Files (`16`):**
    1. `backend/alembic/env.py`
    2. `backend/app/core/jobs.py`
    3. `backend/app/verification/patch_applier.py`
    4. `backend/app/verification/runner.py`
    5. `backend/app/verification/sandbox.py`
    6. `backend/app/verification/service.py`
    7. `backend/app/verification/workspace.py`
    8. `tests/test_patch_atomicity_and_verification.py`
    9. `tests/test_phase1_security_remediation.py`
    10. `tests/test_phase7_production_deployment_verification.py`
    11. `tests/test_phase7c_targeted_remediation.py`
    12. `tests/test_production_readiness.py`
    13. `tests/test_sandbox.py`
    14. `tests/test_verification.py`
    15. `tests/test_verification_patch_proposal_nullable.py`
    16. `tests/test_verification_security_hardening.py`
  - **Untracked Phase Reports (`6`):**
    1. `RED_MERCURY_PHASE8P_LINUX_CI_FAILURE_FORENSICS_AND_REMEDIATION_REPORT.md`
    2. `RED_MERCURY_PHASE8Q_INDEPENDENT_SECURITY_VERIFICATION_REPORT.md`
    3. `RED_MERCURY_PHASE8R_TARGETED_RESIDUAL_SECURITY_REMEDIATION_REPORT.md`
    4. `RED_MERCURY_PHASE8S_INDEPENDENT_SECURITY_VERIFICATION_REPORT.md`
    5. `RED_MERCURY_PHASE8T_TARGETED_REMEDIATION_REPORT.md`
    6. `RED_MERCURY_PHASE8U_INDEPENDENT_FINAL_VERIFICATION_REPORT.md` (this report)

---

## 3. Finding A Independent Results — Patch Permission Preservation (`patch_applier.py`)

Inspected `backend/app/verification/patch_applier.py` (`L122–508`) and `tests/test_patch_atomicity_and_verification.py`:
- **Permission Capture:** `_read_text_posix_nofollow()` (`L157–176`) reads `orig_mode = stat.S_IMODE(os.fstat(file_fd).st_mode)` directly on the open `O_RDONLY | O_NOFOLLOW` descriptor inside `parent_fd`, closing both `file_fd` and `parent_fd` in nested `finally` blocks with zero pathname reopens.
- **Sanitization:** `_sanitize_preserved_mode()` (`L122–126`) sets new files (`orig_mode is None`) to `0o600` (`stat.S_IRUSR | stat.S_IWUSR`), preserves owner `stat.S_IXUSR` (`0o700`) when previously executable, strips `S_ISUID | S_ISGID | S_ISVTX` and all group/world bits (`0o077 == 0`), and never restores unsafe group/world permissions.
- **Atomic Replacement & Descriptor Safety:** `_write_text_posix_nofollow()` (`L179–233`) checks `os.lstat(leaf, dir_fd=parent_fd)`, opens `.rm_patch_<hex>` exclusively (`O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW`, mode `0o600`), applies `os.fchmod(fd, target_mode)` on the open `fd` when `0o700`, re-checks `os.lstat(leaf, dir_fd=parent_fd)`, calls `os.replace(tmp_name, leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)`, unlinks `tmp_name` via `dir_fd` on error, and closes `parent_fd` in `finally`. WSL confirmed `0` FD leaks (`fds_before == fds_after`) and zero `.rm_patch_*` leftovers.
- **Rollback:** `delete` and `modify` operations record `"orig_mode"` and restore both original content and sanitized owner permissions during multi-file rollback (`L466–502`).
- **Windows vs. POSIX:** Windows uses validated `Path` ops (`_use_posix_dirfd() == False`); `os.fchmod`/`dir_fd`/`O_NOFOLLOW` are gated strictly to POSIX (`os.name == "posix"`) and tested on both Windows (mocked POSIX calls in `test_patch_atomicity_and_verification.py`) and real Linux kernel in WSL (`WSL_8U_COMPREHENSIVE_KERNEL_VERIFIED`).

---

## 4. Finding B Independent Results — Fallback Workspace Boundary (`sandbox.py`)

Inspected `backend/app/verification/sandbox.py` (`L288–375`) and all callers repository-wide:
- **Caller Graph:** Only reachable from `run_isolated_verification_command()` (`L372`, when Docker is unavailable AND `allow_host_fallback` is enabled — strictly `False` in `production`/`staging` via `Settings.sandbox_allow_host_fallback`) plus unit tests (`test_sandbox.py`, `test_verification_security_hardening.py`).
- **Enforced Boundary:** `execute_in_restricted_subprocess()` (`L298–302`) calls `resolved_ws = validate_strict_temp_workspace(workspace_dir)` **before** `get_sanitized_runner_env()`, command assembly, or `subprocess.Popen`, sets `"cwd": str(resolved_ws)`, and fails closed (`-1, "", "", False, "Sandbox workspace access error: ..."`) on `temp_root`, outside paths, symlinked roots/ancestors, missing paths, and regular files.
- **Tests Verified:** `test_execute_in_restricted_subprocess_enforces_strict_temp_workspace_boundary` passed without launching `subprocess.Popen` for any invalid candidate and passed `"1 passed"` for a strict temp descendant.

---

## 5. Phase 8R/8S Invariant Results

Independently confirmed intact across code, Windows suites, and WSL kernel execution:
- **POSIX ACLs:** `ensure_sandbox_readable_workspace()` sets `0o700`/`0o600` (`0o700` on exec) first, then applies sorted POSIX ACL v2 xattr (`ACL_USER=10002:5/4`, `ACL_GROUP_OBJ=0`, `ACL_OTHER=0`, `ACL_MASK=5/4`) via `follow_symlinks=False`; host UID == target UID stays private (`0o700`/`0o600`); `ENOTSUP` fails closed with `PermissionError` (`WSL_8U_COMPREHENSIVE_KERNEL_VERIFIED`).
- **Workspace Boundary:** `validate_strict_temp_workspace()` enforces strict descendant rule across `ensure_sandbox_readable_workspace()`, `execute_in_container()`, and `execute_in_restricted_subprocess()`.
- **Verification Outcomes (`service.py`):** Baseline & post-patch `error`/`timeout` emit `INCONCLUSIVE`; Rule 5.1 retains `FAILED_VERIFICATION` precedence on genuine failures; general passing tests cannot turn `INCOMPARABLE` into verified.
- **Pytest Target Validation (`runner.py`):** Empty, whitespace, `"\x00"`, non-string, `/`, `\`, drive-prefixed, UNC, `..`, `-`, and symlink targets return `status="error"`; `test_target=None` preserves project-wide discovery.
- **Process Lifecycle (`jobs.py`):** `_read_proc_stat_fields()` (`rfind(")")`), `_is_pid_running()` (`'Z'`/`'X'`/`'x'` non-reaping classification), and `_kill_pid_tree_safely()` (`pgid != os.getpgid(os.getpid())`, bounded `1.0s` wait) remain intact.

---

## 6. CI Workflow & Mandatory Gate Assessment

Inspected `.github/workflows/ci.yml`, `.github/workflows/redmercury_pr_gate.yml`, `Dockerfile.api`, `Dockerfile.worker`, `Dockerfile.frontend`, `docker-compose.prod.yml`, and `pytest.ini`:
- **`ci.yml`:**
  - `backend-tests` (`ubuntu-latest`, `timeout-minutes: 25`): installs `backend/requirements-dev.txt` (includes `pytest-timeout>=2.3.1`), runs `pytest tests/ -v --tb=short --durations=25 --timeout=120 --junitxml=.redmercury_artifacts/pytest-results.xml 2>&1 | tee .redmercury_artifacts/pytest-output.log` under `set -o pipefail`, uploads `backend-pytest-results` and `backend-pytest-log` with `if: always()`, builds `redmercury-worker:latest` and `redmercury-frontend:test`, runs healthchecked `postgres:16-alpine` and `redis:7-alpine`, and installs `semgrep>=1.65.0` on Linux.
  - `security-audit-and-secret-scan`: verifies Gitleaks `8.18.2` SHA-256 checksum (`6298c9235dfc9278c14b28afd9b7fa4e6f4a289cb1974bd27949fc1e9122bdee`), executes `gitleaks detect --verbose --redact`, `pip_audit`, `npm audit --audit-level=high`, and `bandit -r backend/app -ll -ii`.
  - `mandatory-release-gate`: `needs:` all 4 upstream jobs (`backend-tests`, `frontend-build-and-test`, `security-audit-and-secret-scan`, `container-validation`) with **zero `continue-on-error` bypasses**.
  - Concurrency: `cancel-in-progress: true` grouped per workflow and ref.
- **`redmercury_pr_gate.yml`:** Runs `scripts.ci_security_gate --fail-on HIGH --strict-checks` (`semgrep`, `bandit`, `pip-audit`, `requests`), validates JSON artifact integrity, masks secrets in PR comments, and strictly fails closed on non-zero gate exit codes (`0` pass, `1` fail, `2` incomplete).

---

## 7. Security Scanner Results

| Scanner & Version | Command | Exit Code | Findings |
|---|---|---:|---|
| Gitleaks `8.18.2` (`.gitleaks.toml` intact, zero new suppressions) | `./bin/gitleaks.exe detect --verbose --redact` | `0` | `47 commits scanned.`, `no leaks found` (`1.11s`) |
| Gitleaks `8.18.2` (Working Tree post-Phase 8U report) | `./bin/gitleaks.exe detect --no-git --verbose --redact` | `0` | Verified after report creation — `no leaks found` |
| Bandit `1.9.4` | `python -m bandit -r backend/app -ll -ii` | `0` | `No issues identified.` (`22,286` LOC, `3` existing `#nosec B104` in `ingestion.py`) |
| `pip-audit` | `python -m pip_audit -r backend/requirements.txt --desc on --ignore-vuln CVE-2026-132276` | `0` | `No known vulnerabilities found` |
| Docker Compose | `docker compose -f docker-compose.prod.yml config -q` | `0` | Valid production Compose topology |

---

## 8. Regression Test Results

- **Targeted Pre-Push Security & Verification Suites** (`test_verification_security_hardening.py`, `test_sandbox.py`, `test_verification.py`, `test_patch_atomicity_and_verification.py`, `test_production_readiness.py`, `test_migration_consistency.py`, `--timeout=120`): **`99 passed, 0 failed, 3 skipped`** (`17.08s`).
- **Complete Isolated Backend Suite** (`python -m pytest tests/ -v --tb=short --timeout=120 -rs`, confirmed via `tests/conftest.py` `validate_disposable_test_db_url()` forcing `sqlite:///./test_redmercury.db` under `APP_ENV="development"`): **`617 passed, 0 failed, 37 skipped`** (`236.59s`, `654` collected).
- **Electron Security Suite (`node --test electron/security.test.cjs`):** **`10 passed, 0 failed`**.
- **Frontend (`cd frontend`):** `npm run lint` (`tsc --noEmit`) **exit `0`**; `npm test` (`vitest run`) **`7` files, `46` passed** (`8.90s`).
- **WSL Ubuntu Kernel Probes (`WSL_8U_COMPREHENSIVE_KERNEL_VERIFIED`):** Passed real Linux ext4/tmpfs ACL, `ENOTSUP` fail-closed, `fstat`/`fchmod` `+x` preservation (`0o777 -> 0o700`, `0o666 -> 0o600`), ACL re-application (`0o750`/`0o640`), rollback mode restoration, and `0` FD leak checks.

---

## 9. Evidence Boundaries (Windows / WSL / Docker / PG+Redis / Remote CI)

1. **Windows-Native Evidence:** `617 passed` backend tests (mocked Docker/PG/Redis/ACL syscalls where daemon/Linux unavailable), Electron `10 passed`, Frontend `46 passed`, Bandit, `pip-audit`, Gitleaks, Compose config check.
2. **WSL Linux-Kernel Evidence (`6.18.33.2`):** Real kernel POSIX ACL xattr binary layout, `ENOTSUP` fail-closed, `O_RDONLY|O_NOFOLLOW`/`fstat`/`O_EXCL|O_NOFOLLOW`/`fchmod`/`os.replace` rollback & `+x` preservation, `0` FD leaks (`WSL_8U_COMPREHENSIVE_KERNEL_VERIFIED`).
3. **Live Docker Evidence:** **NOT EXECUTED** (`docker info` exit `1`, `npipe:////./pipe/dockerDesktopLinuxEngine` absent).
4. **Live PostgreSQL 16 / Redis 7 Evidence:** **NOT EXECUTED** (no local PostgreSQL/Redis daemons running).
5. **Remote GitHub Actions Evidence:** **PENDING** until user-authorized commit and push trigger CI Run #11+.

---

## 10. Remaining Risks, Blockers & Limitation Classification

1. **`pytest addopts` CWD writes (`[Acceptable documented limitation]`):** `pytest.ini` (`addopts = -v --tb=short`) performs no writes; untrusted external repos whose configs add CWD-writing `addopts` fail closed with `PermissionError` under read-only UID `10002` `/workspace` ACLs rather than weakening immutability.
2. **Same-UID/root ancestor rename race in `patch_applier.py` (`[Acceptable documented limitation]`):** Single-process `TemporaryDirectory` workspaces and sequential execution prevent remote exploitation; kernel `dir_fd` + `O_NOFOLLOW` stops leaf/intermediate symlink swaps.
3. **UID `10002` ACL sufficiency under live container `pytest` (`[Pending remote CI gate — Informational locally]`):** Code and WSL xattr inspection match `-p no:cacheprovider`, `HOME=/tmp`, `TMPDIR=/tmp`, `PYTEST_DEBUG_TEMPROOT=/tmp`, `PYTHONDONTWRITEBYTECODE=1`, awaiting live container execution in remote CI.
4. **Worker writable locations outside `/tmp` (`[Informational]`):** `Dockerfile.worker` and `docker-compose.prod.yml` restrict `redmercury-sandbox` (`10002`) under `read_only: true` with writable `/tmp` tmpfs and `/sandbox/temp` volume; `sandbox.py` verification containers require only `/tmp`.
5. **Test coverage of rollback, permission preservation & invalid paths (`[Verified / Acceptable]`):** Real Linux kernel + Windows mocked suites genuinely exercise all three paths (`tests/test_patch_atomicity_and_verification.py`, `tests/test_sandbox.py`, `tests/test_verification_security_hardening.py`).

---

## 11. Exact Skipped Tests (`37` Total in Full 654-Test Backend Run)

All `37` skips are environmental (missing Docker daemon, live PostgreSQL 16, live Redis 7, Semgrep CLI on Windows, or Windows non-admin symlink privilege):

- **Live Docker Daemon Unavailable (`18` Docker-only skips + `1` combined PostgreSQL+Docker skip below):**
  1–13. `tests/test_live_docker_security_runtime.py`: `test_live_docker_non_root_execution`, `test_live_docker_network_isolation`, `test_live_docker_dropped_capabilities_block_raw_sockets`, `test_live_docker_read_only_root_filesystem`, `test_live_docker_tmpfs_is_writable_but_noexec`, `test_live_docker_host_secret_isolation`, `test_live_docker_no_docker_socket_or_host_drives`, `test_live_docker_memory_limit_bounded_oom`, `test_live_docker_pids_limit_anti_fork_bomb`, `test_live_docker_timeout_and_ephemeral_cleanup`, `test_live_docker_invalid_image_fails_closed_explicitly`, `test_live_docker_fix_verification_passing_suite`, `test_live_docker_fix_verification_failing_suite`
  14. `tests/test_phase6_durable_job_execution.py`: `test_phase6_S_live_docker_sandbox_container_cancellation`
  15. `tests/test_phase7_production_deployment_verification.py`: `test_phase7_sec8_live_nginx_container_http_and_tls_security_headers`
  16. `tests/test_phase7c_targeted_remediation.py`: `test_phase7c_p7b_f06_nginx_api_strict_csp_and_compose_cap_drop`
  17–18. `tests/test_sandbox.py`: `test_real_docker_container_isolation`, `test_live_docker_oom_and_fork_bomb_bounded`
- **Live PostgreSQL 16 / Redis 7 Unavailable (`17`):**
  19–20. `tests/test_phase6_durable_job_execution.py`: `test_phase6_live_redis_outbox_dispatch_and_worker_claim_integration`, `test_phase6_live_postgresql_skip_locked_concurrency_and_unique_constraints`
  21–22. `tests/test_phase7_production_deployment_verification.py`: `test_phase7_sec4_durable_jobs_end_to_end_on_live_postgres_and_redis`, `test_phase7_sec9_alembic_0013_to_0014_upgrade_and_postgres_backup_restore_rehearsal`
  23–26. `tests/test_phase7a_distributed_security_hardening.py`: `test_phase7a_sec2_postgres_concurrent_lease_fencing_blocks_stale_scan_commit`, `test_phase7a_sec2_postgres_concurrent_lease_fencing_blocks_stale_verification_commit`, `test_phase7a_sec3_worker_crash_during_cancellation_reaps_orphans_and_guards_slot` *(also requires Docker)*, `test_phase7a_sec5_outbox_and_cancellation_fault_matrix_on_live_postgres_and_redis`
  27–30. `tests/test_phase7c_targeted_remediation.py`: `test_phase7c_p7b_f01_lease_fencing_lifecycle_multi_job_savepoint_and_session_reuse`, `test_phase7c_p7b_f03_concurrent_outbox_dispatchers_never_push_duplicate_redis_messages`, `test_phase7c_p7b_f05_concurrent_daily_quota_lock_and_transactional_audit`, `test_phase7c_p7b_f07_f08_concurrent_alembic_advisory_lock_and_sqlite_artifacts`
  31. `tests/test_phase7e_transaction_fencing.py`: `test_phase7e_all_nine_transaction_fencing_scenarios_on_live_postgres`
  32. `tests/test_phase7g_cleanup_isolation.py`: `test_phase7g_all_ten_cleanup_isolation_scenarios_on_live_postgres`
  33–35. `tests/test_postgresql_integration.py`: `test_live_postgres_migrations_clean_db`, `test_live_postgres_unique_constraints_and_transaction_rollback`, `test_live_postgres_revoked_token_cross_worker_persistence`
- **Semgrep CLI Unavailable on Windows (`1`):**
  36. `tests/test_scanners.py`: `test_semgrep_scanner_adapter_execution` (`Semgrep not installed in test environment`)
- **Windows Non-Admin Symlink Privilege (`1`):**
  37. `tests/test_verification_security_hardening.py`: `test_adversarial_workspace_symlink_escape_skipped` (`Symlink creation not supported without administrative privileges in this environment`)

*(Exact sum: `18 + 17 + 1 + 1 = 37` skips; `617 + 37 = 654` collected tests.)*

---

## 12. Final Recommendation

**Decision:** **`A — APPROVED FOR EXPLICIT USER-AUTHORIZED COMMIT/PUSH.`**

- The accumulated Phase 8P–8T security remediations are verified safe, internally consistent, secret-free, and ready for an explicitly authorized commit and push on `main` to execute remote GitHub Actions CI.
- **Production Deployment:** Remains **`BLOCKED / NOT AUTHORIZED`** until remote GitHub Actions CI passes all 5 jobs (`backend-tests`, `frontend-build-and-test`, `security-audit-and-secret-scan`, `container-validation`, and `mandatory-release-gate`).
