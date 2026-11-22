# RED MERCURY — PHASE 8T
## TARGETED PATCH PERMISSION PRESERVATION, FALLBACK BOUNDARY HARDENING & PRE-CI VERIFICATION REPORT

**Repository:** `https://github.com/Dhineshkumardhina/Red-Mercury`  
**Workspace:** `c:\PROJECTS\dhina projects\Red Mercury\Red Mercury`  
**Branch:** `main` (`remotes/origin/main`)  
**Baseline HEAD:** `b445661e8019ee4263581791d959e7179586d7e4` (`b445661`)  
**Previous Phase:** Phase 8S — Independent POSIX ACL, Container Compatibility & Security Verification  

**NO STAGING, COMMITTING, PUSHING, TAGGING, REBASING, RESETTING, OR PRODUCTION DEPLOYMENT EXECUTED.**

---

## 1. Executive Summary

Phase 8T remediated both remaining actionable Low-severity engineering findings flagged in Phase 8S while preserving all Phase 8R/8S security invariants:
1. **Finding A (`patch_applier.py`):** Replaced fixed `0o600` POSIX replacement modes with descriptor-relative `os.fstat(file_fd)` permission capture and `os.fchmod(fd, target_mode)` on the private temp descriptor before `os.replace()`, preserving owner `+x` (`S_IXUSR`) across modifications and rollbacks while stripping unsafe group/world write and special bits (`0o700` / `0o600`).
2. **Finding B (`sandbox.py`):** Added strict `validate_strict_temp_workspace(workspace_dir)` enforcement inside `execute_in_restricted_subprocess()` before constructing `Popen`, failing closed on `temp_root`, outside paths, symlinks, nonexistent dirs, and regular files.

All targeted backend suites (`99 passed, 3 skipped`), compileall, Bandit (`0` issues across `22,286` lines), Compose config validation (`exit 0`), Gitleaks (`47` commits & working tree clean), Electron (`10 passed`), Frontend lint/Vitest (`7` files / `46` passed), and WSL Ubuntu real Linux kernel probes (`WSL_8T_KERNEL_VERIFICATION_PASSED`, `WSL_8T_MULTIFILE_ROLLBACK_PERM_VERIFIED`) passed cleanly. Live Docker container isolation, PostgreSQL 16, Redis 7, and Semgrep CLI remain unverified locally pending remote GitHub Actions CI.

---

## 2. Baseline Git Integrity

- **Current Branch:** `main`
- **Baseline HEAD:** `b445661e8019ee4263581791d959e7179586d7e4` (matches expected baseline cleanly)
- **Origin Remote:** `https://github.com/Dhineshkumardhina/Red-Mercury.git` (fetch & push)
- **Staged Files (`git diff --cached --stat`):** `0`
- **Deleted or Renamed Files:** `0`
- **`git diff --check`:** Clean (`exit 0`)

---

## 3. Files Modified

Modified in Phase 8T:
- `backend/app/verification/patch_applier.py`
- `backend/app/verification/sandbox.py`
- `tests/test_patch_atomicity_and_verification.py`
- `tests/test_sandbox.py`

Created Report:
- `RED_MERCURY_PHASE8T_TARGETED_REMEDIATION_REPORT.md`

*(Pre-existing Phase 8P/8R edits across `backend/alembic/env.py`, `backend/app/core/jobs.py`, `backend/app/verification/runner.py`, `backend/app/verification/service.py`, `backend/app/verification/workspace.py`, the remaining test files, and Phase 8P–8S reports are preserved intact.)*

---

## 4. Finding A Implementation & Tests (`patch_applier.py`)

### Implementation Details
- Added `_sanitize_preserved_mode(orig_mode: Optional[int]) -> int`:
  - Returns `0o600` for newly created files (`orig_mode is None`).
  - For existing modified/deleted files, preserves `stat.S_IXUSR` when originally set (`0o700`) and clears `S_ISUID | S_ISGID | S_ISVTX` plus all group/world bits (`0o077 == 0`), guaranteeing neither unsafe group/world writes nor world-readable exposure.
- Updated `_read_text_posix_nofollow()` (`L157-176`) to return `(content, sha256_hex, orig_mode)` where `orig_mode = stat.S_IMODE(os.fstat(file_fd).st_mode)` is captured directly from the already-opened `O_NOFOLLOW` descriptor without reopening any path.
- Updated `_write_text_posix_nofollow()` (`L179-231`):
  - Always creates `.rm_patch_<hex>` exclusively (`O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW`) with private mode `0o600`.
  - After writing bytes, if `target_mode != 0o600` (`0o700`), calls `os.fchmod(fd, target_mode)` on the open file descriptor `fd` **before** `os.close(fd)` and **before** `os.replace(..., src_dir_fd=parent_fd, dst_dir_fd=parent_fd)`.
  - Preserves `os.lstat(leaf, dir_fd=parent_fd)` symlink checks and atomic `.rm_patch_*` cleanup on any exception (including `os.replace` failure).
- Stored `"orig_mode"` in `planned_operations` (both POSIX `fstat` and Windows `stat(follow_symlinks=False)`) and passed `file_mode=plan["orig_mode"]` through Phase 2 `modify` and Phase 2 rollback (`delete` / `modify`).

### Regression Tests Added (`tests/test_patch_atomicity_and_verification.py`)
- `test_patch_applier_preserves_executable_and_strips_unsafe_modes_posix`: Verifies `_sanitize_preserved_mode()` (`0o600`, `0o644->0o600`, `0o777->0o700`, `0o4755->0o700`), descriptor-relative `fstat` capture, private `0o600` temp creation followed by `os.fchmod(fd, 0o700)` before `os.replace`, and non-exec preservation without extra `fchmod`.
- `test_patch_applier_atomic_replace_failure_and_rollback_restore_permissions`: Tests multi-file patch rollback on replacement failure, verifying original content and `S_IXUSR` executable semantics are restored cleanly with zero `.rm_patch_*` leftovers (on POSIX natively and with mocked POSIX `dir_fd` calls on Windows).

---

## 5. Finding B Implementation & Tests (`sandbox.py`)

### Caller Trace
- Searched every call site of `execute_in_restricted_subprocess()` across `backend/` and `tests/`:
  1. `backend/app/verification/sandbox.py:366` (`run_isolated_verification_command()` fallback step 3 — blocked in production/staging because `settings.sandbox_allow_host_fallback` always returns `False` when `is_strict_env` is `True`).
  2. `tests/test_verification_security_hardening.py:268` (direct unit test passing `tmp_path`).
  3. `tests/test_sandbox.py:129` (mocked assertion verifying it is NOT invoked under fail-closed).

### Implementation Details
- Added independent workspace validation at entry to `execute_in_restricted_subprocess()` (`L298-L302`):
  - Calls `resolved_ws = validate_strict_temp_workspace(workspace_dir)` inside `try ... except Exception:` and fails closed returning `(-1, "", "", False, f"Sandbox workspace access error: {exc}")` before environment assembly or `subprocess.Popen`.
  - Sets `popen_kwargs["cwd"] = str(resolved_ws)`.

### Regression Test Added (`tests/test_sandbox.py`)
- `test_execute_in_restricted_subprocess_enforces_strict_temp_workspace_boundary`: Verifies `temp_root` itself, outside paths, missing directories, regular files, symlinked workspace roots, and symlinked intermediate ancestors all fail closed with `-1` and `"Sandbox workspace access error:"` without invoking `subprocess.Popen`, while valid strict temp descendants execute cleanly (`0`, `"1 passed"`).

---

## 6. Phase 8R/8S Invariant Regression Results

Verified preserved without regression:
- Scoped POSIX ACLs for UID `10002` (`system.posix_acl_access`, `ACL_USER=10002:5/4`, `ACL_GROUP_OBJ=0`, `ACL_OTHER=0`, `ACL_MASK=5/4`) re-verified in WSL after `patch_applier` modifications (`st_mode`: `0o750` exec, `0o640` non-exec).
- Zero world-readable fallback and fail-closed `PermissionError` on ACL error (`ENOTSUP`).
- Strict temporary workspace boundary enforcement across both `execute_in_container()` and `execute_in_restricted_subprocess()`.
- Baseline and post-patch verification error/timeout classification (`INCONCLUSIVE` vs `FAILED_VERIFICATION`).
- Malformed pytest target rejection (`""`, whitespace, null bytes, UNC, drives, traversal, option injection, symlinks, non-strings).
- POSIX `dir_fd` + `O_NOFOLLOW` + `O_EXCL` atomic replacement with zero FD/temp leaks and `PGID` termination guards.

---

## 7. Windows / Linux Verification Boundaries

- **Verified on Windows (`win32`, Python `3.14.7`):** Backend compileall, targeted pytest suites (`99 passed, 3 skipped`), Bandit, Gitleaks, Compose config check, Electron security suite, Frontend `tsc --noEmit` & Vitest.
- **Verified on Real Linux Kernel (`WSL Ubuntu`, Kernel `6.18.33.2-microsoft-standard-WSL2`, Python `3.14.4`):**
  - `_read_text_posix_nofollow` + `_write_text_posix_nofollow` executable preservation (`0o777 -> 0o700`), non-exec privacy (`0o666 -> 0o600`), simulated `os.replace` failure preserving original content & mode with zero `.rm_patch_*` leftovers, followed by `ensure_sandbox_readable_workspace(..., 10002)` yielding `0o750` / `0o640` with exact `ACL_USER=10002` (`5` exec) & `ACL_OTHER=0`.
  - End-to-end `apply_patch_to_workspace()` multi-file rollback restoring both `run.sh` content and executable mode `(m & S_IXUSR) != 0 and (m & 0o077) == 0` (`WSL_8T_MULTIFILE_ROLLBACK_PERM_VERIFIED`).
  - `validate_strict_temp_workspace()` rejections on `temp_root`, outside dir, and regular file (`/etc/passwd`).
- **WSL Probes Are NOT Live Docker Verification:** Container execution under Docker daemon remains unverified locally.

---

## 8. Docker Verification Status

**NOT VERIFIED LOCALLY.** Docker Desktop Linux Engine (`npipe:////./pipe/dockerDesktopLinuxEngine`) was unavailable locally during Phase 8T; live container bind-mount execution with `redmercury-worker:latest` (alongside PostgreSQL 16, Redis 7, and Semgrep CLI) awaits remote GitHub Actions CI on `ubuntu-latest`.

---

## 9. Gitleaks and Bandit Results

- **Bandit (`python -m bandit -r backend/app -ll -ii`):** `No issues identified.` across `22,286` lines scanned (`0` High, `0` un-suppressed Medium, `3` justified `#nosec B104` entries in `ingestion.py`).
- **Gitleaks History (`./bin/gitleaks.exe detect --verbose --redact`):** `47 commits scanned.`, `no leaks found`.
- **Gitleaks Working Tree (`./bin/gitleaks.exe detect --no-git --verbose --redact`):** Scanned after Phase 8T edits and report creation — `no leaks found`.

---

## 10. Remaining Vulnerabilities & Limitations

1. **Unverified Live Container / PG16 / Redis 7 / Semgrep Execution:** Full remote CI verification on `ubuntu-latest` remains pending user authorization to stage, commit, and push `main`.
2. **Pytest `addopts` CWD Compatibility (`sandbox.py:212`, Low):** Untrusted repositories specifying CWD-writing `addopts` in `pytest.ini`/`pyproject.toml` will fail closed with `PermissionError` against read-only UID `10002` `/workspace`.
3. **Same-UID Ancestor Rename Window (`patch_applier.py`, Informational):** Pre-`openat` / between-step ancestor directory renames by same-UID or root processes are architectural boundaries outside sequential single-owner temp workspaces.

---

## 11. Exact Test Counts & Skipped Tests

| Check | Passed | Failed | Skipped | Exact Skipped / Notes |
|---|---:|---:|---:|---|
| `python -m compileall backend/app -q` | Exit `0` | 0 | 0 | All backend Python files |
| `python -m pytest tests/test_verification_security_hardening.py tests/test_sandbox.py tests/test_verification.py tests/test_patch_atomicity_and_verification.py tests/test_production_readiness.py tests/test_migration_consistency.py -v --tb=short --timeout=120` | 99 | 0 | 3 | `test_adversarial_workspace_symlink_escape_skipped` (Windows non-admin symlink creation blocked), `test_real_docker_container_isolation` & `test_live_docker_oom_and_fork_bomb_bounded` (Live Docker daemon unavailable locally) |
| WSL Ubuntu Kernel Probes (`WSL_8T_KERNEL_VERIFICATION_PASSED` + `WSL_8T_MULTIFILE_ROLLBACK_PERM_VERIFIED`) | Passed | 0 | 0 | Native Linux POSIX xattr, `fstat`/`fchmod`/`O_NOFOLLOW`/`os.replace` rollback, and boundary checks |
| `node --test electron/security.test.cjs` | 10 | 0 | 0 | Electron path & IPC security |
| `npm run lint` (`frontend`) | Exit `0` | 0 | 0 | `tsc --noEmit` |
| `npm test` (`frontend` Vitest, 7 files) | 46 | 0 | 0 | `Duration 10.10s` |
| `docker compose -f docker-compose.prod.yml config -q` | Exit `0` | 0 | 0 | `COMPOSE_EXIT=0` |
| Live Docker, PG16, Redis 7, Semgrep | — | — | Not Executed | Unavailable on Windows host |

---

## 12. Final Recommendation

**Decision:** **`A — READY FOR INDEPENDENT FINAL VERIFICATION.`**

- All Phase 8T objectives (`Finding A` executable-permission preservation across atomic patch/rollback and `Finding B` fallback temporary-workspace enforcement) are implemented and verified across Windows and WSL Linux kernel checks.
- **Production Deployment:** **`BLOCKED / NOT AUTHORIZED`** until user-authorized commit/push runs remote GitHub Actions CI and passes all 5 jobs cleanly.
