# RED MERCURY — PHASE 8R
## TARGETED RESIDUAL SECURITY REMEDIATION & REGRESSION VERIFICATION REPORT

**Repository:** `https://github.com/Dhineshkumardhina/Red-Mercury`  
**Workspace:** `c:\PROJECTS\dhina projects\Red Mercury\Red Mercury`  
**Branch:** `main` (`remotes/origin/main`)  
**Baseline HEAD:** `b445661e8019ee4263581791d959e7179586d7e4` (`b445661`)  
**Previous Phase:** Phase 8Q — Independent Security Verification & Pre-Push Integrity Audit  

**NO STAGING, COMMITTING, PUSHING, TAGGING, REBASING, RESETTING, OR PRODUCTION DEPLOYMENT EXECUTED.**

---

## 1. Executive Summary

Phase 8R performed narrowly scoped security remediation and regression verification for all residual findings identified in Phase 8Q (`RC-1`, `RC-2`, `RC-3`, `RC-6`) together with a focused security review and POSIX kernel hardening of `RC-8`, preserving all existing architecture, migrations, and security invariants.

All target backend suites (`153 passed, 3 skipped` + `13 passed, 8 skipped`), Bandit (`0` issues across `22,246` lines), Gitleaks (`47` commits & working tree clean), Docker Compose validation (`exit 0`), Electron (`10 passed`), Frontend (`tsc --noEmit`, `46` Vitest tests, Vite `1644`-module build), and WSL Ubuntu POSIX kernel checks passed cleanly. Live Docker container isolation, PostgreSQL 16, Redis 7, and Semgrep CLI remain unverified locally pending remote GitHub Actions CI.

---

## 2. Original Phase 8Q Findings

1. **`RC-1` (`workspace.py`, `sandbox.py`):** `ensure_sandbox_readable_workspace()` applied `0o755`/`0o644` (`o+rx` / `o+r`), exposing temporary cloned workspaces to other local OS users on multi-user Linux hosts, and `execute_in_container()` accepted `resolved_ws == temp_root` rather than strictly requiring a descendant of `temp_root`.
2. **`RC-2` (`service.py`):** `execute_fix_verification()` recorded `base_test_outcome` without appending baseline `error`/`timeout` statuses to `execution_errors`, permitting a subsequent passing post-patch run to emit `VERIFIED_AGAINST_DEFINED_CHECKS`.
3. **`RC-3` (`runner.py`):** `run_pytest_in_workspace()` used truthiness `if test_target:` so `""` fell back to project-wide test discovery, `"   "` collapsed to `""` (`cmd_args=["--", ""]`), and null-byte targets (`"tests/\x00evil.py"`) returned `"skipped"` instead of `"error"`.
4. **`RC-6` (`test_production_readiness.py`, `test_sandbox.py`):** Earlier subcases in `test_production_environment_config_validation()` (`L28–48`) and `test_development_allows_explicit_fallback()` (`L180`) omitted `_env_file=None` and environment variable scrubbing.
5. **`RC-8` (`patch_applier.py`):** Pre-`.resolve()` symlink validation stopped deterministic escapes under single-process sequential execution, while Phase 1 -> Phase 2 lacked POSIX `dir_fd` + `O_NOFOLLOW` + `O_EXCL` atomic write primitives against concurrent workspace writers.

---

## 3. Exact Root Cause of Each Addressed Finding

- **`RC-1` (Workspace Confidentiality):** Using world-readable `chmod 0o755`/`0o644` to traverse across host UID (`1001` on GitHub Actions) and container UID (`10002`) granted read/traverse bits (`S_IROTH | S_IXOTH`) to all local accounts instead of UID-scoped POSIX ACLs (`ACL_USER=10002`, `ACL_OTHER=0`).
- **`RC-1` (Temp Root Boundary):** Equality `resolved_ws == temp_root` in `sandbox.py:220` permitted passing `/tmp` / `tempfile.gettempdir()` itself to recursive permission modification and mount construction.
- **`RC-2` (Baseline Error Propagation):** Missing `if base_test_outcome.status in ("error", "timeout"):` check in `service.py` left `execution_errors` empty when baseline execution faulted or timed out.
- **`RC-3` (Target Validation):** Truthy guard `if test_target:` ignored empty strings, allowed whitespace-only targets after `.strip()`, and did not explicitly reject `"\x00"` or `"//"` before `.exists()` checked disk.
- **`RC-6` (Test Env Leakage):** Missing `monkeypatch.delenv(...)` and `_env_file=None` on individual `Settings(...)` test instantiations allowed host `.env` or CI shell variables to influence validation behavior.
- **`RC-8` (Phase 1 -> Phase 2 Atomicity Window):** Re-opening paths by path string via `Path.write_text`/`Path.unlink` re-walked pathname components on POSIX rather than holding a pinned directory descriptor (`dir_fd`) with `O_NOFOLLOW` and exclusive `O_EXCL` temp-file atomic `os.replace`.

---

## 4. Files Modified

All modifications remain strictly scoped within verification security modules and their regression test suites:

- `backend/app/verification/workspace.py`
- `backend/app/verification/sandbox.py`
- `backend/app/verification/service.py`
- `backend/app/verification/runner.py`
- `backend/app/verification/patch_applier.py`
- `tests/test_verification_security_hardening.py`
- `tests/test_sandbox.py`
- `tests/test_production_readiness.py`
- `tests/test_verification.py`

*(Plus pre-existing Phase 8P edits preserved intact on `backend/alembic/env.py`, `backend/app/core/jobs.py`, `tests/test_phase1_security_remediation.py`, `tests/test_phase7_production_deployment_verification.py`, `tests/test_phase7c_targeted_remediation.py`, `tests/test_verification_patch_proposal_nullable.py`, and report `RED_MERCURY_PHASE8Q_INDEPENDENT_SECURITY_VERIFICATION_REPORT.md`.)*

---

## 5. Implementation Details

### `RC-1` — Private Workspace Access & Temporary-Root Boundary (`workspace.py`, `sandbox.py`)
- Added `parse_sandbox_uid()` and `validate_strict_temp_workspace()` in `workspace.py`:
  - Rejects `workspace_dir.is_symlink()`, non-existent/non-directory paths (`resolve(strict=True)`), `resolved_ws == temp_root`, `temp_root not in resolved_ws.parents`, and intermediate symlink ancestors below `temp_root`.
- Replaced `0o755`/`0o644` world-readable `chmod` in `ensure_sandbox_readable_workspace()` with `_apply_scoped_posix_permissions()`:
  - Enforces private base permissions (`0o700` on dirs, `0o600` or `0o700` on executable files; zero `0o077` bits).
  - If `os.getuid() == target_uid` (e.g., running directly as `redmercury-sandbox` UID `10002`), retains owner-only `0o700`/`0o600` without ACLs.
  - Otherwise sets a minimal POSIX ACL v2 `system.posix_acl_access` xattr via `os.setxattr(..., follow_symlinks=False)` (or `setfacl --no-dereference` if `os.setxattr` is absent) granting read/exec **only** to `target_uid` (`ACL_USER=10002`), with `ACL_GROUP_OBJ=0` and `ACL_OTHER=0`.
  - Verifies `(os.lstat(path).st_mode & stat.S_IRWXO) == 0` on POSIX and **fails closed** with `PermissionError` if ACL setup fails — zero fallback to `0o755`/`0o644`/`0o777`.
  - Preserves Windows early return (`if platform.system() == "Windows": return`).
- Updated `execute_in_container()` in `sandbox.py` to call `validate_strict_temp_workspace(workspace_dir)` and `ensure_sandbox_readable_workspace(..., sandbox_uid=parse_sandbox_uid(config.user))` inside a fail-closed exception handler returning `(-1, "", "", False, "Sandbox workspace access error: ...")` before `build_container_run_command()` or `Popen`.

### `RC-2` — Baseline Execution Error Classification (`service.py`)
- Updated `execute_fix_verification()` baseline unit test handling (`L279-L296`) so `base_test_outcome.status in ("error", "timeout")` appends `"Baseline test execution encountered <status>: <error_message>"` to both `execution_errors` and `reasons` and includes error details in `VerificationEvidence.evidence_reference`.
- Trace outcome:
  - Baseline `timeout` / `error` + post-patch `passed` -> `INCONCLUSIVE` (Rule 5.2 triggered by `execution_errors`).
  - Baseline `error` + post-patch genuine assertion `failed` -> `FAILED_VERIFICATION` (Rule 5.1 precedence) with both failure evidence and `execution_errors` preserved.

### `RC-3` — Test Target Validation (`runner.py`)
- Changed `if test_target:` to `if test_target is not None:` and enforced validation prior to path resolution and subprocess launch:
  - Rejects non-string, empty (`""`), and whitespace-only (`"   \t\n"`) targets (`status="error"`).
  - Rejects null bytes (`"\x00"`), leading `-` option injections, `/` and `\` rooted paths, UNC paths (`\\`, `//`), Windows drive prefixes (`^[A-Za-z]:`), `..` segments across `/` or `\`, and symlink targets (`status="error"`) with generic non-leaking messages.
  - Preserves `test_target=None` project-wide test discovery and valid relative test targets (`["--", "/".join(target_parts)]`).

### `RC-6` — Test Environment Isolation (`test_production_readiness.py`, `test_sandbox.py`)
- Updated `test_production_environment_config_validation`, `test_production_strictly_forbids_host_fallback`, and `test_development_allows_explicit_fallback` to clear relevant configuration env vars via `monkeypatch.delenv(..., raising=False)`, pass `_env_file=None` to all `Settings(...)` calls, and provide explicit valid production configuration (`CORS_ORIGINS=["https://redmercury.xerova.com"]`, `DEBUG=False`, `DOCS_ENABLED=False`), preserving all production security validators including explicit `"null"` CORS rejection.

### `RC-8` — Symlink TOCTOU Review & Narrow Hardening (`patch_applier.py`)
- **Sequential & Ownership Assessment:**
  1. Untrusted code never executes concurrently inside `apply_patch_to_workspace()`: baseline container runs terminate via `proc.communicate()` / `terminate_process_tree()` before Step 3 patch application, and post-patch execution starts only after Step 3 completes.
  2. Each `create_verification_workspace()` allocates an isolated `TemporaryDirectory(prefix="redmercury_verify_")`, and durable job leases (`worker.py` / `jobs.py`) prevent duplicate workers claiming the same verification job.
  3. On POSIX, workspaces are owned by the host worker UID with `other::---` and UID `10002` granted read-only ACL (`rx`/`r`, zero write access), blocking container modification.
  4. Single-process sequential execution is a pipeline invariant of `execute_fix_verification()`, not enforced by OS advisory locking across external same-UID callers.
- **Narrowly Scoped POSIX Hardening Implemented:**
  - Added `_open_parent_dir_fd()`, `_read_text_posix_nofollow()`, `_write_text_posix_nofollow()`, and `_unlink_posix_nofollow()` gated on `os.name == "posix" and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY")`.
  - Phase 1 reads use `O_RDONLY | O_NOFOLLOW` relative to pinned `dir_fd` (`O_DIRECTORY | O_NOFOLLOW` per ancestor component).
  - Phase 2 creates/modifies/rollbacks check `os.lstat(leaf, dir_fd=parent_fd)`, write to an exclusive temp file (`O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW`, `0o600`), and swap atomically via `os.replace(..., src_dir_fd=parent_fd, dst_dir_fd=parent_fd)`.

---

## 6. Security Trade-Offs

- **Native POSIX ACL `system.posix_acl_access` vs. `chmod 0o755`/`0o644` vs. Container UID Remapping:** Setting `ACL_USER=10002` with `ACL_OTHER=0` removes multi-user world-read exposure without modifying the hardened `--user=10002:10002` container contract or `Dockerfile.worker` identity, and `os.setxattr` avoids runtime dependency on the `setfacl` binary (absent in minimal Ubuntu/WSL images). Trade-off: filesystems that disable POSIX ACLs (e.g., 9p/drvfs) fail closed rather than exposing files globally, and Docker daemons configured with `userns-remap` require matching the remapped host UID.
- **No Unbounded Ancestor Rename Lock in `patch_applier.py`:** `dir_fd` + `O_NOFOLLOW` eliminates symlink-target races at each opened component and file leaf cleanly across POSIX while preserving Windows behavior, without rewriting repository staging around OS file locks or multi-user IPC.

---

## 7. Regression Tests Added / Updated

- `tests/test_verification_security_hardening.py`:
  - `test_ensure_sandbox_readable_workspace_uses_scoped_acl_without_world_access`
  - `test_ensure_sandbox_readable_workspace_owner_uid_match_stays_private`
  - `test_ensure_sandbox_readable_workspace_fails_closed_when_acl_unavailable`
  - `test_temp_root_boundary_rejects_temp_root_and_outside_paths`
  - `test_patch_applier_posix_nofollow_rejects_phase2_symlink_swap`
- `tests/test_sandbox.py`:
  - `test_execute_in_container_rejects_temp_root_without_chmod`
  - `test_runner_rejects_all_malformed_test_targets_and_preserves_valid` (`""`, whitespace, `"\x00"`, `/etc/passwd`, `\Windows\...`, `C:\...`, `C:...`, `\\server\...`, `//server/...`, `../../...`, `..\..\...`, mixed traversal, plus valid relative preservation)
  - Isolated `test_production_strictly_forbids_host_fallback` & `test_development_allows_explicit_fallback`
- `tests/test_production_readiness.py`:
  - Isolated all 5 cases of `test_production_environment_config_validation` (`SQLite`, weak secret, short secret, `"null"` CORS, valid prod config)
- `tests/test_verification.py`:
  - `test_baseline_and_postpatch_error_or_timeout_yields_inconclusive` (4 parametrized cases: baseline timeout + pass, baseline error + pass, pass + post-patch timeout, pass + post-patch error)
  - `test_genuine_assertion_failure_with_infrastructure_error_preserves_both_and_fails`
  - `test_valid_baseline_and_valid_postpatch_pass_yields_verified`

---

## 8. Full Test & Verification Results (Phase 8R Post-Edit)

All pytest runs executed with `--timeout=120`, `APP_ENV="development"`, `SECRET_KEY="ci-testing-secret-key-at-least-32-chars-long"`, `SANDBOX_ALLOW_HOST_FALLBACK="true"`.

| Check / Suite | Passed | Failed | Skipped | Status / Notes |
|---|---:|---:|---:|---|
| `python -m compileall backend/app -q` | Exit `0` | 0 | 0 | All backend Python bytecode valid |
| Backend Batch 1 (`test_migration_consistency.py`, `test_verification_security_hardening.py`, `test_sandbox.py`, `test_verification.py`, `test_fix_verification_suite.py`, `test_difficult_security_scenarios.py`, `test_e2e_workflow_and_negatives.py`, `test_production_readiness.py`, `test_phase1_security_remediation.py`, `test_patch_atomicity_and_verification.py`, `test_security_assessment.py`) | 153 | 0 | 3 | **3 skipped:** `test_adversarial_workspace_symlink_escape_skipped` (Win non-admin symlink), `test_real_docker_container_isolation` & `test_live_docker_oom_and_fork_bomb_bounded` (Docker daemon unavailable). Scenarios ran under `SANDBOX_ALLOW_HOST_FALLBACK=true`. |
| Backend Batch 2 (`test_phase7c_targeted_remediation.py`, `test_verification_patch_proposal_nullable.py`, `test_phase7_production_deployment_verification.py`) | 13 | 0 | 8 | **8 skipped (env unavailable):** Live PG16/Redis7 (`p7b_f01/03/05/07`, `phase7_sec4`), Live Docker/Nginx (`p7b_f06`, `phase7_sec8`, `phase7_sec9`) |
| `node --test electron/security.test.cjs` | 10 | 0 | 0 | Electron IPC & traversal security passed |
| `npm run lint` (`frontend`) | Exit `0` | 0 | 0 | `tsc --noEmit` clean |
| `npm test` (`frontend` Vitest, 7 files) | 46 | 0 | 0 | Clean pass |
| `npm run build` (`frontend` Vite) | Exit `0` | 0 | 0 | `1644` modules bundled |
| `docker compose -f docker-compose.prod.yml config -q` | Exit `0` | 0 | 0 | Valid compose schema (`POSTGRES_PASSWORD` & `SECRET_KEY` set) |
| WSL Ubuntu POSIX Kernel Probes | Passed | 0 | 0 | Real kernel check: POSIX ACL (`ACL_USER=10002`, `ACL_OTHER=0`, `(st_mode & 0o007) == 0`), `validate_strict_temp_workspace` rejections, and `_read/_write/_unlink_posix_nofollow` symlink rejections (`WSL_POSIX_8R_KERNEL_VERIFICATION_PASSED`) |
| Live Docker (`redmercury-worker:latest`), PG16, Redis 7, Semgrep CLI | — | — | **Not Executed** | Local Docker daemon, PG16, Redis 7, and Semgrep CLI unavailable on Windows host |

---

## 9. Finding Classification Matrix & Windows/Linux Boundaries

| Finding | Classification | Verification Scope |
|---|---|---|
| **RC-1:** Private workspace POSIX ACL + strict `temp_root` descendant boundary | **PARTIALLY REMEDIATED** | Verified in Windows unit suites + real Linux ext4/tmpfs ACL syscalls in WSL Ubuntu; **live Docker UID `10002` container bind-mount execution remains unverified locally until CI runs** |
| **RC-2:** Baseline `error`/`timeout` classification & failure/error preservation | **VERIFIED REMEDIATED** | Code inspected (`service.py`) + all 6 regression tests passed |
| **RC-3:** Malformed, empty, whitespace, null-byte, UNC, drive & traversal target rejection | **VERIFIED REMEDIATED** | Code inspected (`runner.py`) + all 13 malformed vectors + valid target passed |
| **RC-6:** Production config test env isolation (`_env_file=None` + `delenv`) | **VERIFIED REMEDIATED** | Code inspected (`test_production_readiness.py`, `test_sandbox.py`) + tests passed with zero relaxed assertions |
| **RC-8:** Symlink TOCTOU review + POSIX `dir_fd` / `O_NOFOLLOW` / `O_EXCL` atomic write | **PARTIALLY REMEDIATED** | Real Linux kernel `O_NOFOLLOW`/`lstat` checks verified in WSL + mocked Phase 2 swap test passed; concurrent same-UID ancestor directory renames remain architectural limitation |

---

## 10. Remaining Vulnerabilities & Limitations

1. **Unverified Live Container ACL End-to-End Execution:** Bind-mounted access inside live `--user=10002:10002` `redmercury-worker:latest` containers with host POSIX ACLs awaits remote GitHub Actions CI (`ubuntu-latest`).
2. **`RC-8` Same-UID / Root Ancestor Rename Window:** `dir_fd` + `O_NOFOLLOW` prevents symlink substitution on file opens and final `os.replace`, whereas an external process sharing the worker's OS UID racing ancestor directory renames between open calls is outside single-process workspace guarantees.
3. **Host Temp Directory ACL Prerequisite:** Linux worker hosts must store temp verification workspaces on a POSIX-ACL-enabled filesystem (`ext4`, `xfs`, `tmpfs` with `acl`); otherwise `ensure_sandbox_readable_workspace()` fails closed cleanly.

---

## 11. Gitleaks and Bandit Results

- **Bandit (`python -m bandit -r backend/app -ll -ii`):** `No issues identified.` across `22,246` lines scanned (`0` High, `0` un-suppressed Medium, `#nosec` count `3` — `workspace.py` `B103` suppressions eliminated).
- **Gitleaks History (`./bin/gitleaks.exe detect --verbose --redact`):** `47 commits scanned.`, `no leaks found`.
- **Gitleaks Working Tree (`./bin/gitleaks.exe detect --no-git --verbose --redact`):** Re-verified after all Phase 8R edits — `no leaks found`.

---

## 12. Exact Git Integrity Status

- **Current Branch:** `main`
- **HEAD Commit:** `b445661e8019ee4263581791d959e7179586d7e4` (unchanged)
- **Origin Remote:** `https://github.com/Dhineshkumardhina/Red-Mercury.git`
- **Staged Files:** `0` (`git diff --cached --stat` empty)
- **`git diff --check`:** Clean (exit `0`)

---

## 13. Exact Uncommitted Manifest

**Modified Tracked Files (`15`):**
- `backend/alembic/env.py`
- `backend/app/core/jobs.py`
- `backend/app/verification/patch_applier.py`
- `backend/app/verification/runner.py`
- `backend/app/verification/sandbox.py`
- `backend/app/verification/service.py`
- `backend/app/verification/workspace.py`
- `tests/test_phase1_security_remediation.py`
- `tests/test_phase7_production_deployment_verification.py`
- `tests/test_phase7c_targeted_remediation.py`
- `tests/test_production_readiness.py`
- `tests/test_sandbox.py`
- `tests/test_verification.py`
- `tests/test_verification_patch_proposal_nullable.py`
- `tests/test_verification_security_hardening.py`

**Untracked Report Files (`3`):**
- `RED_MERCURY_PHASE8P_LINUX_CI_FAILURE_FORENSICS_AND_REMEDIATION_REPORT.md`
- `RED_MERCURY_PHASE8Q_INDEPENDENT_SECURITY_VERIFICATION_REPORT.md`
- `RED_MERCURY_PHASE8R_TARGETED_RESIDUAL_SECURITY_REMEDIATION_REPORT.md`

---

## 14. Final Recommendation & Decision

**Decision:** **`B. CONDITIONALLY READY — DOCUMENTED LIMITATIONS REMAIN`**

- **Remote CI Readiness:** Ready for user-authorized staging, commit, and push of `main` so GitHub Actions Linux CI can verify `backend-tests` (including live Docker container isolation under UID `10002` POSIX ACLs, PostgreSQL 16, Redis 7, and Semgrep), `frontend-build-and-test`, `security-audit-and-secret-scan`, `container-validation`, and `mandatory-release-gate`.
- **Production Deployment:** **`BLOCKED / NOT AUTHORIZED`** until remote GitHub Actions CI passes all 5 jobs.
