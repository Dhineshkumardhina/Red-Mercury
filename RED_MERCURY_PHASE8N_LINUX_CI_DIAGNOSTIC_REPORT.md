# RED MERCURY — PHASE 8N
## LINUX CI DIAGNOSTIC INSTRUMENTATION & BOUNDED TEST EXECUTION REPORT

**Repository:** `https://github.com/Dhineshkumardhina/Red-Mercury`  
**Local Repository:** `C:\PROJECTS\dhina projects\Red Mercury\Red Mercury`  
**Current Branch:** `main`  
**HEAD:** `fd034441461118769000dc8fc3dbf4875a0a35de` (`fd03444`)  
**Target Workflow / Job:** `.github/workflows/ci.yml` → `Backend Tests & Migration Consistency` (Previous Run `44995999107`, Job `137127047387`)  

**NO COMMIT, PUSH, TAG, RELEASE, OR DEPLOYMENT WAS PERFORMED.**

---

## 1. Executive Summary

Phase 8N inspected the unresolved remote backend CI cancellation from Phases 8L–8M (`Run 44995999107`, `Job 137127047387`) and applied minimal, non-weakening diagnostic instrumentation plus two verified Linux/CI fixes:

1. **Bounded Per-Test Execution & Diagnostics ([`backend/requirements-dev.txt`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/requirements-dev.txt), [`.github/workflows/ci.yml`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/.github/workflows/ci.yml)):** Added `pytest-timeout>=2.3.1` and updated the CI pytest invocation to `python -m pytest tests/ -v --tb=short --durations=25 --timeout=120 --junitxml=.redmercury_artifacts/pytest-results.xml 2>&1 | tee .redmercury_artifacts/pytest-output.log` (under `set -o pipefail`), plus a separate `backend-pytest-log` diagnostic artifact upload (`if: always()`, `if-no-files-found: warn`).
2. **Cross-Runner Docker Image Availability ([`.github/workflows/ci.yml`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/.github/workflows/ci.yml)):** Built `redmercury-frontend:test` (`Dockerfile.frontend`) directly inside `backend-tests` alongside `redmercury-worker:latest`, closing the cross-job Docker daemon gap required by `test_phase7_sec8_live_nginx_container_http_and_tls_security_headers`.
3. **POSIX Process-Group Safety ([`backend/app/verification/sandbox.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/verification/sandbox.py), [`backend/app/core/jobs.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/jobs.py)):** Added `start_new_session=True` on non-Windows `Popen` spawns in `execute_in_container()` and `execute_in_restricted_subprocess()`, and guarded `os.killpg(pgid, signal.SIGKILL)` with `if pgid != os.getpgid(os.getpid()):` in both `terminate_process_tree()` and `JobExecutionTracker._kill_process_tree()`.

Because remote GitHub Actions logs remain unretrieved and WSL Ubuntu has no project virtualenv (`No module named pytest`), the exact original stalling test node in Run `44995999107` remains **`UNRESOLVED`** pending an authorized push to re-run remote CI. **Production deployment remains BLOCKED.**

---

## 2. Starting Branch and HEAD

- **Branch:** `main`
- **HEAD:** `fd034441461118769000dc8fc3dbf4875a0a35de` (`fd03444`)

---

## 3. Initial Working-Tree Status

Prior to Phase 8N edits:
- `?? RED_MERCURY_PHASE8L_REMOTE_CI_VERIFICATION_REPORT.md`
- `?? RED_MERCURY_PHASE8M_BACKEND_CI_TIMEOUT_FORENSICS_REPORT.md`
- Clean across all tracked files (`0` modified tracked files).

---

## 4. Files Inspected

- [`.github/workflows/ci.yml`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/.github/workflows/ci.yml)
- [`pytest.ini`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/pytest.ini)
- [`backend/requirements.txt`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/requirements.txt) & [`backend/requirements-dev.txt`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/requirements-dev.txt)
- [`tests/conftest.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/tests/conftest.py)
- [`backend/app/scanner/semgrep.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/scanner/semgrep.py) & [`backend/app/scanner/base.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/scanner/base.py)
- [`backend/app/verification/sandbox.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/verification/sandbox.py) & [`backend/app/verification/workspace.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/verification/workspace.py)
- [`backend/app/core/jobs.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/jobs.py)
- [`tests/test_phase6_durable_job_execution.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/tests/test_phase6_durable_job_execution.py), [`tests/test_phase7_production_deployment_verification.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/tests/test_phase7_production_deployment_verification.py), [`tests/test_phase7a_distributed_security_hardening.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/tests/test_phase7a_distributed_security_hardening.py), [`tests/test_verification_security_hardening.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/tests/test_verification_security_hardening.py), [`tests/test_scanners.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/tests/test_scanners.py)

---

## 5. Files Modified

1. [`backend/requirements-dev.txt`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/requirements-dev.txt) — Added `pytest-timeout>=2.3.1`.
2. [`.github/workflows/ci.yml`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/.github/workflows/ci.yml) — Added `redmercury-frontend:test` Docker build in `backend-tests`, added `--timeout=120 --durations=25 -v` + `set -o pipefail` + `tee .redmercury_artifacts/pytest-output.log`, and added `Upload Backend Diagnostic Log Artifact` (`if: always()`, `if-no-files-found: warn`).
3. [`backend/app/verification/sandbox.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/verification/sandbox.py) — Set `start_new_session=True` on POSIX for `execute_in_container()` & `execute_in_restricted_subprocess()`, and guarded `os.killpg()` in `terminate_process_tree()`.
4. [`backend/app/core/jobs.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/jobs.py) — Guarded `os.killpg()` in `JobExecutionTracker._kill_process_tree()` with `if pgid != os.getpgid(os.getpid()):`.
5. New report: [`RED_MERCURY_PHASE8N_LINUX_CI_DIAGNOSTIC_REPORT.md`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/RED_MERCURY_PHASE8N_LINUX_CI_DIAGNOSTIC_REPORT.md).

---

## 6. Exact Diagnostic Instrumentation Changes

- **Pytest Command (`.github/workflows/ci.yml`):**
  ```bash
  mkdir -p .redmercury_artifacts
  set -o pipefail
  python -m pytest tests/ -v --tb=short --durations=25 --timeout=120 --junitxml=.redmercury_artifacts/pytest-results.xml 2>&1 | tee .redmercury_artifacts/pytest-output.log
  ```
- **Invariant Preservation (`tests/test_phase7a_distributed_security_hardening.py`):** Preserved `"pytest tests/ "` substring, `"--junitxml=.redmercury_artifacts/pytest-results.xml"` flag, `build_idx < pytest_idx` ordering, and exact `.redmercury_artifacts/pytest-results.xml` upload path.

---

## 7. `pytest-timeout` Dependency and Configuration Details

- **Added Constraint:** `pytest-timeout>=2.3.1` in `backend/requirements-dev.txt` (verified installing `pytest-timeout 2.3.1` cleanly alongside `pytest 9.1.1`; no dependency conflicts on Python 3.11+ or 3.14).
- **Timeout Bound Justification (`120s`):** Full local `--durations=25` profiling showed the slowest test completes in `8.32s` (`test_full_e2e_positive_lifecycle`), and Docker sandbox/Postgres tests complete in `<=7.16s`. `120s` gives `>14x` headroom while ensuring any hung test fails deterministically rather than exhausting the 25-minute job budget.
- **Mechanism & Limitations:**
  - On Linux CI (`ubuntu-latest`), `pytest-timeout` defaults to `method = signal` (`SIGALRM` in main thread). It interrupts blocked Python/C/socket calls and runs `finally:` cleanup, though un-registered background threads/child processes require explicit teardown in `finally:`.
  - On Windows (where `SIGALRM` is unavailable), `pytest-timeout` automatically selects `method = thread` (`timeout: 120.0s, timeout method: thread, timeout func_only: False` observed locally).

---

## 8. Artifact Upload Behavior

- `.redmercury_artifacts` is created before `pytest` starts (`mkdir -p .redmercury_artifacts`).
- `set -o pipefail` guarantees `pytest`'s non-zero exit code is never masked by `tee`.
- Both `Upload Backend Test Results Artifact` (`path: .redmercury_artifacts/pytest-results.xml`) and `Upload Backend Diagnostic Log Artifact` (`path: .redmercury_artifacts/pytest-output.log`) use `if: always()` and `if-no-files-found: warn`, leaving security audit reports untouched.
- **Limitation:** If a GitHub runner is forcefully terminated at job timeout, post-step `if: always()` uploads still do not run (as observed in Run `44995999107`). Bounded `--timeout=120` is what allows `pytest` to exit normally before job timeout so artifacts upload.

---

## 9. Semgrep Investigation

- Installed on Linux via `semgrep>=1.65.0; sys_platform != "win32"` in `backend/requirements.txt` (skipped on Windows).
- [`backend/app/scanner/semgrep.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/scanner/semgrep.py) passes `--disable-version-check` and `--metrics=off`, substitutes `_LOCAL_DEFAULT_RULESET` when `settings.OFFLINE_MODE` (`True` by default), and invokes [`run_scanner_subprocess()`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/scanner/base.py#L84) with `start_new_session=True` and `timeout_seconds=60` (calling `JobExecutionTracker._kill_process_tree(proc)` on `TimeoutExpired`).
- Cannot verify Linux Semgrep runtime locally without Linux venv / authenticated CI logs. Semgrep remains enabled.

---

## 10. Chromium / CDP Investigation

- Inspected `test_phase7_sec6_real_chromium_browser_auth_cookies_csrf_rotation_and_cors` in [`tests/test_phase7_production_deployment_verification.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/tests/test_phase7_production_deployment_verification.py#L578-L849):
  - Discovers Chrome/Chromium/Edge; skips cleanly if absent.
  - Launches `--headless=new` without weakening sandbox flags (no `--no-sandbox`), polls CDP WebSocket (`40 * 0.15s = 6s`), runs `node` WebSocket verification (`timeout=30`), sets `server.should_exit = True`, terminates/kills `chrome_proc` with `wait(timeout=5)`, and unlinks temp script.
  - Sandbox settings and all auth/cookie/CSRF/CORS/rotation assertions preserved intact.

---

## 11. Docker Image Availability Investigation

- **Gap Found:** In `.github/workflows/ci.yml`, `container-validation` built `redmercury-frontend:test` on its own isolated runner, while `backend-tests` only built `redmercury-worker:latest`. Because separate GitHub Actions jobs use separate Docker daemons, `tests/test_phase7_production_deployment_verification.py` line 905 (`docker run ... redmercury-frontend:test`) lacked a local `redmercury-frontend:test` image inside `backend-tests`.
- **Fix Applied:** Added `Build Frontend Container Image for Live Nginx Security Header Tests` (`docker build -f Dockerfile.frontend -t redmercury-frontend:test .`) in `backend-tests` right after building `redmercury-worker:latest`. `nginx:1.27-alpine@...` is pulled cleanly from Docker Hub by `test_phase7_sec8` (with `timeout=20` and `docker rm -f` cleanup).

---

## 12. PostgreSQL and Redis Investigation

- `.github/workflows/ci.yml` starts healthy `postgres:16-alpine` (`127.0.0.1:5432/test_redmercury`) and `redis:7-alpine` (`127.0.0.1:6379/15`) service containers before `backend-tests` steps.
- Tests run sequentially (`pytest.ini` uses no `-n` parallelism). Phase 6 `SKIP LOCKED` concurrency creates/drops an ephemeral per-test DB (`rm_test_p6_<uuid>`); Phase 7/7A/7C/7E/7G tests run sequentially against `test_redmercury`. All live PostgreSQL and Redis tests preserved.

---

## 13. Linux Subprocess Cleanup Investigation

- **Gap Found:** Unlike `backend/app/scanner/base.py:127` and `backend/app/core/ingestion.py:1063`, neither `execute_in_container()` nor `execute_in_restricted_subprocess()` in [`backend/app/verification/sandbox.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/verification/sandbox.py) passed `start_new_session=True` on POSIX, and both `terminate_process_tree()` (`sandbox.py`) and `JobExecutionTracker._kill_process_tree()` (`jobs.py`) called `os.killpg(pgid, signal.SIGKILL)` without checking `pgid != os.getpgid(os.getpid())`.
- **Fix Applied:** Added POSIX `start_new_session=True` in both `sandbox.py` subprocess launchers and added `if pgid != os.getpgid(os.getpid()):` before `os.killpg()` in both `sandbox.py` and `jobs.py` (matching `_kill_pid_tree_safely()`). Prevents `os.killpg` from ever signaling the parent pytest/worker process group if a child shares its pgid.

---

## 14. Tests Executed with Exact Results

### Windows Local Verification (Post-Final-Edit, Live Docker Postgres 16 + Redis 7)
- **Migration Consistency (`python -m pytest tests/test_migration_consistency.py -v`):** **`3 passed in 1.65s`**, exit `0`.
- **Full Backend Suite (`python -m pytest tests/ -v --tb=short --durations=25 --timeout=120 --junitxml=.redmercury_artifacts/pytest-results.xml`):** **`631 passed, 2 skipped in 236.22s (0:03:56)`**, exit `0`. Slowest test: `8.32s` (`test_full_e2e_positive_lifecycle`).
- **Frontend Vitest (`npm --prefix frontend run test`):** **`7 test files, 46 passed`** (`16.61s`), exit `0`.
- **TypeScript (`npm --prefix frontend run lint`):** Passed (`tsc --noEmit`), exit `0`.
- **Frontend Build (`npm --prefix frontend run build`):** Passed (`vite build`, `1644 modules`, `4.66s`), exit `0`.
- **Electron (`node --test electron/security.test.cjs`):** **`10 passed, 0 failed`** (`158.79ms`), exit `0`.
- **Bandit (`python -m bandit -r backend/app -ll -ii`):** **`No issues identified`** (`21,827` LOC), exit `0`.
- **Docker Compose (`docker compose -f docker-compose.prod.yml config -q`):** Validated cleanly, exit `0`.
- **Gitleaks v8.18.2 (`gitleaks.exe detect --no-git --source <release_copy> --config .gitleaks.toml --verbose --redact`):** **`no leaks found`** (`593ms`), exit `0`.

### WSL / Linux & Remote GitHub Actions
- **WSL Ubuntu (`wsl -d Ubuntu -- bash -lc "python3 -m pytest --version"`):** Failed (`No module named pytest`) — local Linux execution **`NOT VERIFIED`**.
- **Remote GitHub Actions (`.github/workflows/ci.yml`):** Not re-run (no push performed) — Phase 8N workflow updates **`NOT VERIFIED REMOTELY`**.

---

## 15. Windows vs. Linux Verification Distinction

All passing runtime checks in Section 14 ran on Windows (`win32`, Python `3.14.7`) with Docker Desktop containers. Linux CI behavior (`ubuntu-latest`, Python `3.11`, installed `semgrep>=1.65.0`, POSIX `start_new_session` / `SIGALRM` / `os.killpg`, Ubuntu AppArmor Chromium, and CI service containers) is **not** verified until an approved commit/push runs `.github/workflows/ci.yml` remotely.

---

## 16. Remaining Uncertainties

1. Exact pytest test node that stalled inside Run `44995999107` / Job `137127047387` (HTTP `403` without GitHub auth; `gh` CLI unavailable).
2. Actual Linux runtime and pass/timeout behavior of Semgrep and Chromium CDP on `ubuntu-latest` under `--timeout=120`.

---

## 17. Security Impact Assessment

Zero security controls were weakened: production fail-closed policies, CSRF/cookie rotation, tenant isolation, SSRF egress controls, Docker `cap_drop`/`--network none`/read-only rootfs, Chromium sandboxing, Bandit (`-ll -ii`), Gitleaks, and `mandatory-release-gate` remain fully intact. Guarding `os.killpg()` and adding `start_new_session=True` strengthens POSIX process-tree containment.

---

## 18. Git Status After Modifications

- `main` at `fd034441461118769000dc8fc3dbf4875a0a35de`
- Modified tracked (`4`): `.github/workflows/ci.yml`, `backend/app/core/jobs.py`, `backend/app/verification/sandbox.py`, `backend/requirements-dev.txt`
- Untracked (`3`): `RED_MERCURY_PHASE8L_REMOTE_CI_VERIFICATION_REPORT.md`, `RED_MERCURY_PHASE8M_BACKEND_CI_TIMEOUT_FORENSICS_REPORT.md`, `RED_MERCURY_PHASE8N_LINUX_CI_DIAGNOSTIC_REPORT.md`

---

## 19. Safety Confirmation

**Explicit Confirmation:** **NO `git add`, `git commit`, `git push`, `git tag`, `git reset`, `git clean`, RELEASE, OR PRODUCTION DEPLOYMENT OCCURRED.**

---

## 20. Next Recommended Phase & Release Decision

- **Release Decision:** **PRODUCTION RELEASE GATE REMAINS BLOCKED** (pending green remote GitHub Actions execution including `backend-tests` and `mandatory-release-gate`, plus external SSRF-filtering Git egress proxy, `GIT_EGRESS_PROXY_URL`, production TLS certificates/renewal, production vault secret injection, and required external VAPT/attestation).
- **Next Recommended Phase:** **Phase 8O — User-Approved Commit/Push of Phase 8N Diagnostics & Authenticated Remote CI Verification**, to obtain exact Linux CI results (`pytest-results.xml` and `pytest-output.log`) and verify whether any Linux-specific test still fails or times out within `--timeout=120`.
