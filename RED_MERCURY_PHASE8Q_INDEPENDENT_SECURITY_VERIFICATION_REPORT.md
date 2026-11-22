# RED MERCURY — PHASE 8Q
## INDEPENDENT SECURITY VERIFICATION & PRE-PUSH INTEGRITY AUDIT REPORT

**Repository:** `https://github.com/Dhineshkumardhina/Red-Mercury`  
**Local Workspace:** `c:\PROJECTS\dhina projects\Red Mercury\Red Mercury`  
**Branch:** `main`  
**Baseline HEAD:** `b445661e8019ee4263581791d959e7179586d7e4` (`b445661`)  
**Previous Phase:** Phase 8P — Linux CI Failure Forensics & Targeted Security Remediation  

**AUDIT-ONLY VERIFICATION: ZERO SOURCE, TEST, MIGRATION, WORKFLOW, OR GIT HISTORY MUTATIONS PERFORMED.**

---

## 1. Executive Summary

An independent, adversarial pre-push security and regression audit was conducted across all Phase 8P changes (`15` tracked modified files, `+376/-127` lines, plus `RED_MERCURY_PHASE8P_LINUX_CI_FAILURE_FORENSICS_AND_REMEDIATION_REPORT.md`).

All eight root-cause remediations (`RC-1` through `RC-8`) and the Phase 8N CI pipeline (`b445661`) were inspected directly in source code and exercised across Windows regression suites, Bandit AST analysis, Gitleaks history and working-tree scans, Docker Compose config validation, Electron/Frontend test and build pipelines, and real Linux kernel probes in WSL Ubuntu.

No blocking regressions or weakened security controls were found:
- Cross-platform traversal blocking (`RC-3`), environment secret isolation (`RC-4`), POSIX zombie state detection (`RC-5`), production CORS/`SECRET_KEY` lockdown (`RC-6`), Alembic engine disposal and SQLite test cleanup (`RC-7`), and pre-`.resolve()` symlink rejection (`RC-8`) behave securely on inspected code paths and real Linux kernel checks in WSL Ubuntu.
- **Specific non-blocking findings remain:**
  1. **`RC-1` Multi-User Confidentiality Exposure & `temp_root` Guard Boundary (`PARTIALLY REMEDIATED` / Low–Medium):** `ensure_sandbox_readable_workspace()` applies `0o755` (`rwxr-xr-x`) on directories and `0o644` (`rw-r--r--`) on files to accommodate unprivileged container UID `10002`, exposing temporary cloned repository files to any other local OS account on shared multi-user hosts until workspace cleanup; additionally `execute_in_container()` permits `resolved_ws == temp_root` instead of strictly `temp_root in resolved_ws.parents`.
  2. **`RC-8` Symlink TOCTOU Window (`PARTIALLY REMEDIATED` / Low–Medium under sequential worker model):** Checking `raw_target.is_symlink()` before `raw_target.resolve()` eliminates the deterministic bypass on external POSIX symlinks, but Phase 1–to–Phase 2 still lacks `dir_fd` / `O_NOFOLLOW` / `O_EXCL` race-resistant file opens if concurrent workspace mutation occurs.
  3. **`RC-3` Malformed Whitespace / Null-Byte Edge Cases (`PARTIALLY REMEDIATED` / Low):** `test_target="   "` (`clean_target == ""`) falls through to `cmd_args = ["--", ""]`, and `"tests/\x00evil.py"` returns `status="skipped"` rather than `"error"`.
  4. **Local Daemon Unavailability (`UNVERIFIED` locally):** Live Docker daemon (`redmercury-worker:latest`, `redmercury-frontend:test`), PostgreSQL 16, Redis 7, and Semgrep CLI were unavailable on the Windows host during this session, leaving live Linux container execution of Groups A & B pending remote GitHub Actions verification.

---

## 2. Repository Integrity

Verified directly via `git`:
- **Current Branch:** `main` (`remotes/origin/main`)
- **HEAD Commit:** `b445661e8019ee4263581791d959e7179586d7e4` (matches expected baseline `b445661`, `ci(backend): add pytest-timeout diagnostics, frontend test image & POSIX pgid guards`)
- **Origin Remote:** `https://github.com/Dhineshkumardhina/Red-Mercury.git` (fetch & push)
- **Staged Files (`git diff --cached --stat`):** `0` files staged
- **Modified Tracked Files (`15`):**
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
- **Diff Summary:** `15 files changed, 376 insertions(+), 127 deletions(-)`; `0` deleted or renamed files.
- **Untracked Files (`2` reports, excluding temporary artifacts):**
  - `RED_MERCURY_PHASE8P_LINUX_CI_FAILURE_FORENSICS_AND_REMEDIATION_REPORT.md`
  - `RED_MERCURY_PHASE8Q_INDEPENDENT_SECURITY_VERIFICATION_REPORT.md` (this audit report)
- **Git History:** Preserved untouched (`git reset`, `commit`, `rebase`, `clean` not executed).

---

## 3. RC-1 Through RC-8 Independent Findings

### RC-1 — Linux Workspace Permission Security (`workspace.py`, `sandbox.py`, `Dockerfile.worker`, `.github/workflows/ci.yml`)
- **Workspace Creation & Original Permissions:** `create_verification_workspace()` creates `tempfile.TemporaryDirectory(prefix="redmercury_verify_")` (`0o700` on Linux, owned by host user e.g. UID `1001` on GitHub Actions `ubuntu-latest`), copies files via `safe_copy_source_tree()` (skipping `.git`, `__pycache__`, and escaping symlinks), and calls `ensure_sandbox_readable_workspace()`. Direct `run_pytest_in_workspace(tmp_path)` callers rely on pytest's `0o700` `tmp_path`.
- **Container Access vs. Confidentiality:** `Dockerfile.worker` runs as `redmercury-sandbox` (`UID/GID 10002:10002`), and `build_container_run_command()` mounts `-v {ws_mount_path}:/workspace:rw` with `--user=10002:10002`, `--read-only`, `--tmpfs=/tmp:rw,noexec,nosuid,size=64m`, `--cap-drop=ALL`, `--security-opt=no-new-privileges:true`, `--network=none`. Because UID `10002` != host UID `1001`, `0o700` denied container access on Linux.
- **Symlink & Traversal Safety in `ensure_sandbox_readable_workspace()`:** Verified `if platform.system() == "Windows"`, `if workspace_dir.is_symlink(): return`, `os.walk(..., followlinks=False)`, `if d_path.is_symlink(): dirs.remove(d); continue`, `if f_path.is_symlink(): continue`, and `f_path.stat(follow_symlinks=False)`. Does **not** follow symlinks or set world-writable bits (`&( ~(S_IWGRP | S_IWOTH) )`, `dir_mode = 0o755`, files `0o644` / `o+r`).
- **Two Residual Defects Identified:**
  1. **Multi-User Confidentiality Exposure (`0o755` / `0o644`):** On single-tenant ephemeral CI runners (`ubuntu-latest`) this exposes nothing externally, but on shared multi-user Linux hosts it makes cloned repository source files readable by other local OS users until `ws.cleanup()` runs (and pytest `tmp_path` is not restored after container exit). Also container UID `10002` has read-only effective access to host-owned `0o755` `/workspace`, requiring `HOME=/tmp`, `TMPDIR=/tmp`, `PYTEST_DEBUG_TEMPROOT=/tmp`, and `-p no:cacheprovider` to redirect writes to `--tmpfs /tmp`.
  2. **Excessive Equality Condition in `sandbox.py:220`:** `if resolved_ws == temp_root or temp_root in resolved_ws.parents:` allows `resolved_ws == temp_root` (if a caller directly passed `TMPDIR`/`/tmp`, it would walk and chmod the temp root directory itself). Should strictly require `temp_root in resolved_ws.parents`.
- **Least-Privilege Alternatives Evaluated (Not Implemented):** POSIX ACLs (`setfacl -m u:10002:rx` without setting `o+r`/`o+x`), matching host worker UID/GID to `10002` inside a worker container (`Dockerfile.worker`), Docker user-namespace remapping (`userns-remap`), or container-native staging under a `0o700` parent bind mount owned inside the worker namespace.

### RC-2 — Verification Status Classification (`backend/app/verification/service.py`)
Traced `execute_fix_verification()` lines 267–593 across all nine required cases:
- **Case A (Existing tests pass + regression test passes):** `existing_tests_passed=True`, `existing_tests_failed=False`, `regression_test_executed=True`, `regression_test_passed=True`, `regression_test_failed=False`, `execution_errors=[]` -> Rule 5.3 -> **`VERIFIED_AGAINST_DEFINED_CHECKS`**.
- **Case B (Existing tests genuinely fail):** `existing_tests_failed=True` (with or without baseline `"passed"` regression) -> Rule 5.1 -> **`FAILED_VERIFICATION`**.
- **Case C (Targeted regression test genuinely fails):** `reg_outcome.status == "failed"` sets `regression_test_failed=True` -> Rule 5.1 -> **`FAILED_VERIFICATION`**.
- **Case D (`status == "error"`) & Case E (`status == "timeout"`):** Post-patch `test_outcome.status in ("error", "timeout")` or `reg_outcome.status != "passed"` appends error strings to `execution_errors` and leaves `*_failed = False` -> Rule 5.2 -> **`INCONCLUSIVE`** (blocked from Rule 5.3 by `existing_tests_passed=False` and `len(execution_errors) == 0`). *Residual edge case:* Baseline `base_test_outcome` (`line 268`) `status in ("error", "timeout")` is stored in `baseline_test_results` without appending to `execution_errors`; if baseline timed out but post-patch later passed cleanly, `existing_tests_passed` would still evaluate `True`.
- **Cases F & G (Scanner unavailable / fails):** Appends to `execution_errors` and yields `INCOMPARABLE` -> Rule 5.2 -> **`INCONCLUSIVE`**.
- **Case H (Scanner finding disappears without regression test):** If reproduced in baseline (`RESOLVED_BY_DEFINED_CHECKS`), returns `VERIFIED_AGAINST_DEFINED_CHECKS` with mandatory `missing_evidence` axiom warning; if not reproduced in baseline (`INCOMPARABLE`), Rule 5.2 returns **`INCONCLUSIVE`**.
- **Case I (Genuine failure + execution error simultaneously):** Rule 5.1 (`FAILED_VERIFICATION`) takes precedence over Rule 5.2 (`INCONCLUSIVE`), while `execution_errors` preserves the error details.

### RC-3 — Cross-Platform Path Traversal (`backend/app/verification/runner.py`)
Tested directly against `run_pytest_in_workspace()` (Windows) and POSIX `Path` check logic (WSL Ubuntu):
- `../secret.py`, `..\secret.py`, `..\..\windows\win.ini`, `C:\Windows\win.ini`, `/etc/passwd`, `tests/..\../secret.py`, `tests/sub/../../../secret.py`, and `\\server\share\test.py`: **8/8 rejected** with `status="error"` and `"Path traversal detected in test target: ..."`.
- Note normalization replaces `\` with `/` (`posix_rel = clean_target.replace("\\", "/")`), then checks `clean_target.startswith(("/", "\\"))`, `re.match(r"^[A-Za-z]:", clean_target)`, `".." in target_parts`, and `(resolved_ws / posix_rel).resolve().relative_to(resolved_ws)`—so traversal is rejected **before** `.resolve()` and never normalizes into a valid target.
- **Two Minor Malformed-Input Edge Cases Found Independently:**
  1. `test_target="   "` (`clean_target == ""` after `.strip()`): Bypasses traversal/existence checks (`(resolved_ws / "").exists()` is `True`) and runs `inspect_test_safety` on the entire workspace with `cmd_args = ["--", ""]` instead of rejecting empty targets.
  2. `test_target="tests/\x00evil.py"`: Returns `status="skipped"` (non-existent path in Python 3.14) rather than explicit `status="error"` null-byte rejection (unlike `patch_applier.py:145`).

### RC-4 — Environment Isolation (`tests/test_phase1_security_remediation.py`)
- Confirmed `test_infra01_worker_fails_closed_when_secret_key_missing(monkeypatch)` calls `monkeypatch.delenv("SECRET_KEY", raising=False)` and passes `_env_file=None`, forcing `Settings(...)` to raise `ValueError` even when CI exports `SECRET_KEY="ci-testing-secret-key-at-least-32-chars-long"`.
- Cross-checked all other `Settings(...)` instantiations across `tests/` (`test_auth_and_authorization.py`, `test_ci_cd_release_gates.py`, `test_postgresql_integration.py`, `test_phase3_auth_session_ratelimit.py`, `test_security_hardening_extra.py`): none rely on missing `SECRET_KEY` without explicit kwargs/process clean env, though several other `Settings(...)` calls omit `_env_file=None` and rely on explicit kwargs overriding `.env`.

### RC-5 — POSIX Process and Zombie Handling (`backend/app/core/jobs.py`)
- `_read_proc_stat_fields(pid)` uses `raw.rfind(")")` + `raw[rparen + 2:].split()`, accurately handling `comm` process names containing spaces and parentheses (verified in WSL Ubuntu on `"12345 (my (weird) proc) Z ..."` -> state `'Z'`, `starttime = '987654'`).
- `_is_pid_running(pid)` runs `os.kill(int(pid), 0)` then inspects `fields[0] in ("Z", "X", "x")`, returning `False` for irreversibly dead Linux zombie (`Z`) and dead (`X`/`x`) entries **without** consuming `os.waitpid()`, allowing parent callers (`proc.poll()`) to observe the exit code (`-9`). Properly distinguishes "no longer actively executing" from "reaped from process table". A live running/sleeping process (`R`/`S`/`D`) never enters `Z`/`X`/`x`, so active workers are never misclassified as terminated.
- Note minor race behavior: if a process terminates and is completely reaped *between* `os.kill(pid, 0)` and `_read_proc_stat_fields(pid)`, `_read_proc_stat_fields` returns `None` and `_is_pid_running` conservatively returns `True` until the next poll (`ProcessLookupError` -> `False`).
- `_kill_pid_tree_safely(pid)` preserves the `if pgid != os.getpgid(os.getpid()):` self-group safety guard and adds a bounded `1.0s` poll (`0.02s` steps) on POSIX, avoiding indefinite hangs if a child blocks in kernel `D`-state while `reap_and_verify_orphaned_job_resources()` continues fail-closed slot protection using `(hostname, start_time, job_id)` identity checks. Windows `taskkill /F /T` path is preserved cleanly.

### RC-6 — Production Configuration (`config.py`, `test_production_readiness.py`, `test_sandbox.py`)
- Verified `backend/app/core/config.py:261-315` retains full `production`/`staging` lockdown (`"null"` CORS rejection, wildcard CORS/hosts rejection, SQLite rejection, weak/default `SECRET_KEY` rejection, `DEBUG=False`, `SANDBOX_ALLOW_HOST_FALLBACK=False`).
- Verified `test_production_environment_config_validation` (`line 51`) and `test_production_strictly_forbids_host_fallback` (`line 164`) pass `_env_file=None` and `CORS_ORIGINS=["https://redmercury.xerova.com"]`, preventing local `.env` from masking missing configuration while preserving all security assertions.
- *Minor observation:* Subcases 1–3 of `test_production_environment_config_validation` (`lines 28–48`) and `test_development_allows_explicit_fallback` (`test_sandbox.py:180`) still omit `_env_file=None`; adding `_env_file=None` uniformly is cleaner.

### RC-7 — Alembic and SQLite Lifecycle (`alembic/env.py`, `test_verification_patch_proposal_nullable.py`, `test_phase7_production_deployment_verification.py`)
- `backend/alembic/env.py` uses `pool.NullPool` and wraps `with connectable.connect()` in `try: ... finally: connectable.dispose()` (PostgreSQL advisory lock `72839104` unlock intact).
- `test_migration_0010_makes_patch_proposal_id_nullable_in_sqlite` now uses an isolated `tempfile.TemporaryDirectory`, sets `cfg.set_main_option("sqlalchemy.url", disposable_url)` directly alongside restoring `settings.DATABASE_URL`/`os.environ["DATABASE_URL"]` in `finally`, and explicitly executes `con.rollback(); cur.close(); con.close()` after the `sqlite3.IntegrityError` check before running subsequent Alembic commands.
- `test_phase7_sec6` now joins `server_thread.join(timeout=3.0)` in `finally`.
- *Minor note:* `test_migration_0010` restores `settings.DATABASE_URL` cleanly and never touches shared `redmercury.db` or `test_redmercury.db`.

### RC-8 — Symlink and Patch Application Security (`backend/app/verification/patch_applier.py`)
Reviewed lines 140–295 thoroughly:
- **Path & Symlink Validation Order:** Null bytes (`"\0"`), lexical escape (`norm_rel.startswith("/")`, drive prefixes `norm_rel[1] == ":"`, `".." in rel_parts`), direct symlink targets (`raw_target.is_symlink()`), and ancestor escaping symlinks (`curr = raw_target.parent`) are all checked **prior to** `target_file = raw_target.resolve()`, followed by post-resolve `target_file.relative_to(root_resolved)` and `not target_file.is_symlink()`. Both external (`ws/ext_link.txt -> /tmp/ext.txt`) and internal (`ws/in_link.txt -> ws/in_file.txt`) POSIX symlinks were verified rejected with `"is a symbolic link"` in WSL Ubuntu.
- **Internal Parent Symlink Quirk:** Lines 165–173 only reject *escaping* parent symlinks (`relative_to` raises `ValueError`); an existing parent symlink pointing *inside* `root_resolved` is permitted and resolved via `raw_target.resolve()`.
- **TOCTOU Assessment (Explicit Audit Result):**
  - Between Phase 1 validation (`L158–L189`) and Phase 2 atomic execution (`L261–L270`), `patch_applier.py` uses resolved `Path` objects (`target.parent.mkdir(...)`, `target.write_text(...)`, `target.unlink()`) without file locking, `dir_fd` directory-descriptor pinning, `os.O_NOFOLLOW`, or `O_EXCL` atomic temp-file + `os.replace`.
  - Under the current **single-process synchronous verification model** (where `apply_patch_to_workspace()` runs in an isolated `TemporaryDirectory` *before* container launch, and `0o755`/`0o644` does not grant write access to other unprivileged local users), remote untrusted code cannot race Phase 1 -> Phase 2.
  - **However**, if another same-UID process, root process, or shared writable workspace writer modifies the tree concurrently between Phase 1 and Phase 2, **TOCTOU symlink replacement is NOT prevented**. True POSIX race resistance requires component-wise `os.open(..., os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=...)` traversal and `O_NOFOLLOW | O_EXCL` temp-file writes with `os.replace(..., dst_dir_fd=parent_fd)`.

---

## 4. Security Implications & Assessment Matrix

| Finding | Severity | Evidence | Status | Remaining Risk |
|---|---|---|---|---|
| **RC-1:** Container UID `10002` bind-mount permissions & `temp_root` check | Medium | `workspace.py:262-295`, `sandbox.py:195-221`, WSL `0o755`/`0o644` check | **PARTIALLY REMEDIATED** | `0o755`/`0o644` exposes temp workspace contents to other local users on multi-user hosts; `sandbox.py:220` allows `resolved_ws == temp_root`; live container tests skipped locally |
| **RC-2:** Verification status error vs. assertion failure separation | Low | `service.py:442-593`, `test_verification.py:1067-1097` | **VERIFIED REMEDIATED** | Baseline `test_outcome` timeout/error (`L268`) not appended to `execution_errors`; `INCOMPARABLE` can still be overridden by passing regression test |
| **RC-3:** Cross-platform backslash/drive traversal blocking | Low | `runner.py:219-249`, 8/8 traversal probes (Win + WSL) | **PARTIALLY REMEDIATED** | `"   "` whitespace falls through to `cmd_args=["--", ""]`; `"\x00"` returns `"skipped"` rather than `"error"` |
| **RC-4:** `test_infra01` `SECRET_KEY` env leakage | Low | `test_phase1_security_remediation.py:375-385` | **VERIFIED REMEDIATED** | Sibling `Settings(...)` tests in `test_production_readiness.py` (`L28-48`) / `test_sandbox.py:180` omit `_env_file=None` |
| **RC-5:** POSIX zombie `'Z'`/`'X'`/`'x'` classification & `SIGINT`/`SIGKILL` polling | Low | `jobs.py:1626-1815`, WSL zombie probe (`poll rc=-9`) | **VERIFIED REMEDIATED** | Brief window between `os.kill(pid, 0)` and `/proc/<pid>/stat` read conservatively treats disappearing PID as `True` for one cycle |
| **RC-6:** Production `CORS_ORIGINS` lockdown & test defaults | Low | `config.py:280-289`, `test_production_readiness.py:51`, `test_sandbox.py:164` | **VERIFIED REMEDIATED** | Subcases 1–3 (`test_production_readiness.py:28-48`) omit `_env_file=None` |
| **RC-7:** Alembic `NullPool` disposal & SQLite migration test isolation | Low | `alembic/env.py:51-85`, `test_verification_patch_proposal_nullable.py:187-262` | **VERIFIED REMEDIATED** | Live Linux CI multi-suite run order pending remote GitHub Actions verification |
| **RC-8:** Patch symlink pre-resolve validation & TOCTOU posture | Medium | `patch_applier.py:149-191,255-272`, WSL external/internal symlink tests | **PARTIALLY REMEDIATED** | Pre-resolve symlink bypass is fixed; Phase 1–to–Phase 2 lacks `dir_fd` + `O_NOFOLLOW` race protection under concurrent writers |

---

## 5. Cross-Platform Verification

- **Windows (`win32`, Python `3.14.7`):** Executed directly across unit, API, security, migration, Bandit, Gitleaks, Electron, and frontend suites.
- **Linux (`WSL Ubuntu`, Python `3.14` kernel check):** Verified real Linux behavior for `RC-3` (all 8 traversal/backslash/UNC/drive/absolute vectors rejected as `"error"`), `RC-5` (`/proc/<pid>/stat` `rfind(")")` space/paren `comm` parsing and zombie `'Z'` state handling with `proc.poll() == -9`), and `RC-8` (both external and internal POSIX symlinks rejected pre-`.resolve()` with `"is a symbolic link"`).
- **Unavailable Locally (Pending Remote CI):** Live Docker Desktop daemon (`npipe:////./pipe/dockerDesktopLinuxEngine` absent), live PostgreSQL 16, live Redis 7, and Semgrep CLI on Linux. **None of these unavailable integration tests are claimed as passed.**

---

## 6. Regression Test Results (Observed in Phase 8Q)

All commands executed under CI-equivalent test variables (`APP_ENV="development"`, `SECRET_KEY="ci-testing-secret-key-at-least-32-chars-long"`, `SANDBOX_ALLOW_HOST_FALLBACK="true"`):

| Check Command | Scope | Passed | Failed | Skipped | Not Executed / Env Unavailable |
|---|---|---:|---:|---:|---|
| `python -m pytest tests/test_migration_consistency.py -v` | Migration linearity, schema diff, disposable DB | 3 | 0 | 0 | — |
| `python -m pytest tests/test_verification_security_hardening.py test_sandbox.py test_verification.py test_phase7c_targeted_remediation.py test_production_readiness.py test_phase1_security_remediation.py test_verification_patch_proposal_nullable.py -v --tb=short --timeout=120` | RC-1 through RC-8 targeted & security suites | 100 | 0 | 8 | 8 skipped: 3 Docker (`test_real_docker_container_isolation`, `test_live_docker_oom_and_fork_bomb_bounded`, `test_phase7c_p7b_f06`), 4 PG/Redis (`test_phase7c_p7b_f01/03/05/07`), 1 Win symlink (`test_adversarial_workspace_symlink_escape_skipped`) |
| `python -m pytest tests/test_fix_verification_suite.py test_difficult_security_scenarios.py test_e2e_workflow_and_negatives.py -v --tb=short --timeout=120` | Group A scenario & E2E verification suites (host fallback) | 27 | 0 | 0 | Live container sandbox path (`redmercury-worker:latest`) unavailable locally |
| `npm run lint` (`frontend`) | TypeScript `tsc --noEmit` | Passed | 0 | 0 | — |
| `npm test` (`frontend`) | Vitest (`7` files) | 46 | 0 | 0 | — |
| `npm run build` (`frontend`) | Vite production bundle (`1644` modules) | Passed | 0 | 0 | — |
| `node --test electron/security.test.cjs` | Electron path traversal & IPC security | 10 | 0 | 0 | — |
| `python -m bandit -r backend/app -ll -ii` | Backend AST linter (`21,913` lines) | 0 issues | 0 | — | 3 justified `#nosec` annotations (`2x B103` in `workspace.py`, `B104` in `ingestion.py`) |
| `./bin/gitleaks.exe detect --verbose --redact` | Git history (`47` commits) | 0 leaks | 0 | — | — |
| `./bin/gitleaks.exe detect --no-git --verbose --redact` | Working tree (incl. unstaged edits & untracked reports) | 0 leaks | 0 | — | — |
| `docker compose -f docker-compose.prod.yml config -q` | Compose interpolation (`POSTGRES_PASSWORD` & `SECRET_KEY` set) | Exit `0` | 0 | — | — |
| WSL Ubuntu POSIX Kernel Verification | `RC-3`, `RC-5`, `RC-8` direct/AST POSIX checks | Passed | 0 | 0 | Full Linux `pytest` runner / live Docker / PG16 / Redis 7 / Semgrep pending remote CI |

*Note on complete backend suite:* Not re-run redundantly in full during Phase 8Q since targeted suites (`127` tests passed, `8` skipped, plus `3` migration consistency) covered every modified file and test suite; the prior Phase 8P post-edit complete backend run measured `602 passed, 37 skipped` (`0` failed) across `639` items with identical code state.

---

## 7. CI Workflow Assessment (`.github/workflows/ci.yml` — Phase 8N Integrity)

Inspected `.github/workflows/ci.yml`:
- `pytest-timeout>=2.3.1` is declared in `backend/requirements-dev.txt`, which CI installs via `pip install -r backend/requirements-dev.txt` (`L66`).
- Step #10 invokes `python -m pytest tests/ -v --tb=short --durations=25 --timeout=120 --junitxml=.redmercury_artifacts/pytest-results.xml 2>&1 | tee .redmercury_artifacts/pytest-output.log` under `set -o pipefail` (`timeout: 120.0s` confirmed operational locally).
- Both `backend-pytest-results` and `backend-pytest-log` uploads use `if: always()` (`L97-113`), preserving diagnostics on failure.
- Both `redmercury-worker:latest` (`L70`) and `redmercury-frontend:test` (`L74`) are built inside `backend-tests`, PostgreSQL 16 and Redis 7 service containers have explicit healthchecks (`L28-50`), `concurrency.cancel-in-progress: true` and `timeout-minutes: 25` remain intact, and `mandatory-release-gate` blocks on all 4 upstream jobs (`L268-292`).
- Phase 8N POSIX `start_new_session=True` and `os.killpg` self-pgid guards are safe and did not regress CI.

---

## 8. Remaining Vulnerabilities and Uncertainties

1. **Multi-User Host Confidentiality (`workspace.py` `0o755`/`0o644`):** Source files staged in temp verification workspaces are world-readable to other local OS accounts on shared multi-tenant hosts for the lifetime of the workspace.
2. **Symlink TOCTOU Window (`patch_applier.py`):** Same-UID or concurrent workspace writers are not blocked by `dir_fd`/`O_NOFOLLOW` during Phase 1 -> Phase 2 patch application.
3. **`sandbox.py:220` `temp_root` Boundary:** Checking `resolved_ws == temp_root` should be removed so only subdirectories inside `temp_root.parents` are ever chmodded.
4. **Live Linux Docker / Postgres 16 / Redis 7 / Semgrep Gap:** Full remote execution of `backend-tests` on `ubuntu-latest` with live containers and Semgrep remains unverified until authorized push triggers CI Run #11+.

---

## 9. Exact Changed-File Manifest & Secret Status

- **Branch / Baseline HEAD:** `main` / `b445661e8019ee4263581791d959e7179586d7e4` (history untouched)
- **Modified Files (`15`):**
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
- **Untracked Files (`2`):**
  - `RED_MERCURY_PHASE8P_LINUX_CI_FAILURE_FORENSICS_AND_REMEDIATION_REPORT.md`
  - `RED_MERCURY_PHASE8Q_INDEPENDENT_SECURITY_VERIFICATION_REPORT.md`
- **Staged Files:** `0`
- **Diff Stats (tracked):** `15 files changed, 376 insertions(+), 127 deletions(-)`
- **Exclusions Check:** No `.env`, `test_redmercury.db`, `redmercury.db`, `.redmercury_artifacts/`, or temp artifacts are included in the proposed commit manifest (`0` generated/secret files in working tree changes).
- **Secret Scan Status:** Gitleaks clean across both Git history (`47` commits) and full working tree (`no leaks found`).

---

## 10. Recommended Targeted Remediation (Optional / Hardening Follow-ups)

None of the following were modified during audit-only Phase 8Q; recommended cleanly if desired before or after remote CI verification:
1. **`backend/app/verification/sandbox.py:220`:** Tighten condition from `resolved_ws == temp_root or temp_root in resolved_ws.parents` to `temp_root in resolved_ws.parents`.
2. **`backend/app/verification/runner.py:210-231`:** Return `status="error"` explicitly if `not clean_target` (whitespace-only `test_target`) or `"\0" in clean_target`.
3. **Long-Term Container Workspace Hardening (`RC-1` & `RC-8`):** Prefer POSIX ACLs (`u:10002:rx` without `o+r`) or matching host worker UID to `10002` inside dedicated worker pods/containers, and upgrade `patch_applier.py` Phase 2 writes to `dir_fd` + `os.O_NOFOLLOW` + atomic `os.replace`.

---

## 11. Final Release-Readiness Decision

**Decision:** **`B. CONDITIONALLY READY — SPECIFIC NON-BLOCKING FINDINGS REMAIN`**

- **Safe for User-Approved Commit & Push to Run Remote Linux CI:** Yes — subject to user acknowledgment of the non-blocking hardening items (`0o755`/`0o644` multi-user temp confidentiality note, `sandbox.py` `resolved_ws == temp_root` boundary, `runner.py` whitespace/null-byte `test_target` edge cases, and sequential-only TOCTOU boundary in `patch_applier.py`).
- **Production Deployment:** **`BLOCKED / NOT AUTHORIZED`** until remote GitHub Actions Linux CI passes all 5 jobs (`backend-tests` with live Docker, PostgreSQL 16, Redis 7, Semgrep, `frontend-build-and-test`, `security-audit-and-secret-scan`, `container-validation`, and `mandatory-release-gate`).
