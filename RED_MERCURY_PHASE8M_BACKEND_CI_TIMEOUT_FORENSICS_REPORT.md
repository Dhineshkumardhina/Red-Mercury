# RED MERCURY — PHASE 8M
## BACKEND CI TIMEOUT FORENSICS & LINUX TEST ISOLATION AUDIT REPORT

---

### A. Executive Summary

- **Overall Release Gate Decision:** **`UNRESOLVED — AUTHENTICATED LOGS OR LINUX REPRODUCTION REQUIRED.`**
- **Root Cause Classification:** **`UNRESOLVED`** *(Severity: **P1 — Critical Release-Blocking CI Gate Failure**)*
- **Production Deployment Decision:** **`BLOCKED — NOT AUTHORIZED / NOT PERFORMED.`**
- **Repository:** `https://github.com/Dhineshkumardhina/Red-Mercury`
- **Branch / Verified Commit:** `main` / `fd034441461118769000dc8fc3dbf4875a0a35de` (`fd03444`)
- **Target GitHub Actions Run:** `44995999107` (Run #9, `.github/workflows/ci.yml`)
- **Target Job:** `137127047387` (`Backend Tests & Migration Consistency`, conclusion: `cancelled`)
- **Forensic Audit Timestamp:** `2026-11-22T07:27:30Z` – `2026-11-22T08:17:04Z` (`2026-11-22T13:01` – `13:47+05:30`)

Phase 8M performed a strictly read-only forensic investigation of the cancelled remote backend CI job `137127047387` from Phase 8L. No application code, tests, workflows, migrations, or Git history were modified, committed, pushed, or deployed. While public GitHub REST metadata confirms that Steps #1–#8 succeeded and Step #9 (`Run Backend Pytest Suite`) ran from `06:58:44Z` until runner cancellation at `07:27:06Z` (`30m 00s` total job runtime vs `timeout-minutes: 25`), raw job logs could not be retrieved because `gh` CLI is not installed locally and unauthenticated GitHub REST API `/logs` requests return `403 Forbidden`. Consequently, naming the exact pytest test node inside Step #9 cannot be proven from logs and remains honestly classified as `UNRESOLVED`.

---

### B. Authenticated Log Retrieval

- **GitHub CLI Availability (`gh --version`):** Not installed (`gh` binary absent on host).
- **Authentication Status (`gh auth status`):** Unavailable.
- **Unauthenticated REST Log Endpoint (`GET /repos/Dhineshkumardhina/Red-Mercury/actions/jobs/137127047387/logs`):** Returned **`403 Forbidden`** (GitHub requires authenticated `actions:read` credentials to download raw Actions logs even for public repositories).
- **Accessible Public Evidence Used:**
  - Public GitHub REST API metadata for Run `44995999107`, Job `137127047387`, peer jobs `137127047241` / `137127047398` / `137127047415` / `137134002063`, and prior Runs `#1`–`#8`.
  - Complete local repository inspection (`.github/workflows/ci.yml`, `pytest.ini`, `tests/conftest.py`, `backend/requirements*.txt`, and test files).
  - Local live-Postgres/Redis `--durations=30` profiling runs.
- **Evidence Limitation:** Because raw logs of Step #9 could not be retrieved without authentication, items 1–3 of §3 (`last completed pytest test`, `exact test executing at cancellation`, and `last meaningful pytest stdout`) are **UNVERIFIED** from CI logs. No credential bypass was attempted.

---

### C. Timeout Configuration

Inspected [`.github/workflows/ci.yml`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/.github/workflows/ci.yml) and [`pytest.ini`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/pytest.ini):

- **Workflow-Level Timeout:** None configured.
- **Job-Level Timeout (`backend-tests`):** **`timeout-minutes: 25`** (line 25 of `.github/workflows/ci.yml`).
- **Step-Level Timeout (`Step #9`):** None configured (`pytest-timeout` is also not in `backend/requirements.txt` or `backend/requirements-dev.txt`).
- **Concurrency Setting:** `concurrency: { group: ci-${{ github.workflow }}-${{ github.ref }}, cancel-in-progress: true }`.
- **Runner Configuration:** `runs-on: ubuntu-latest` (`GitHub Actions 1000001643`), `services:` `postgres:16-alpine` + `redis:7-alpine`.
- **Test Command & Pytest Flags:**
  - `.github/workflows/ci.yml`: `python -m pytest tests/ --tb=short --junitxml=.redmercury_artifacts/pytest-results.xml`
  - `pytest.ini`: `addopts = -v --tb=short`, `asyncio_mode = auto`, sequential execution (no `-n` / `pytest-xdist`).
- **Observed Execution Timestamps (Run `44995999107`, `run_attempt: 1`):**
  - Run / Job Created: `2026-11-22T06:57:04Z`
  - Job `137127047387` Started: `2026-11-22T06:57:06Z`
  - Step #9 Started: `2026-11-22T06:58:44Z`
  - Job `137127047387` Completed (`cancelled`): `2026-11-22T07:27:06Z` (`30m 00s` total; `28m 22s` inside Step #9).
- **Explanation of `25m` vs. `30m 00s` Discrepancy:**
  - Manual cancellation and concurrency preemption are ruled out: `fd03444` remained HEAD on `main` (`git rev-list --left-right --count HEAD...origin/main` = `0 0`) and `run_attempt` remained `1`.
  - *(Inferred from GitHub Actions runner timeout semantics + exact `06:57:06Z → 07:27:06Z` `1800s` elapsed duration)*: At `25m` (`~07:22:06Z`), GitHub Actions initiated timeout cancellation of job `137127047387`; when the active `pytest` / subprocess tree inside Step #9 did not exit promptly upon cancellation signal, GitHub Actions waited its **5-minute cancellation grace window** (`25m + 5m = 30m 00s`) before forcefully terminating the runner at `07:27:06Z` — which also explains why Step #10 (`if: always()` upload) remained `pending` rather than executing. *(Contrast Run #8 `44908969212`, where `backend-tests` cancelled cleanly at `25m 00s` exact: `13:30:37Z → 13:55:37Z`.)*

---

### D. Backend Test Inventory

Collected locally via `python -m pytest --collect-only -q tests/`: **`633 tests collected in 28.83s`** (no `pytest-xdist` parallelism configured).

| Dependency / Category | Affected Test Files (Observed via Source Scan) | Notes |
|---|---|---|
| **Windows Skips (`2`)** | `tests/test_scanners.py::test_semgrep_scanner_adapter_execution`, `tests/test_verification_security_hardening.py::test_adversarial_workspace_symlink_escape_skipped` | Both execute on Linux CI (`semgrep` installed via `sys_platform != "win32"`; POSIX symlinks supported) |
| **Docker Containers (`9` files)** | `test_live_docker_security_runtime.py`, `test_sandbox.py`, `test_phase1_*`, `test_phase2_*`, `test_phase5_*`, `test_phase6_*`, `test_phase7_*`, `test_phase7a_*`, `test_phase7c_*` | CI Step #6 builds `redmercury-worker:latest` prior to pytest; `test_phase7_sec8` also pulls/runs `redmercury-frontend:test` / `nginx:1.27-alpine` |
| **Live PostgreSQL 16 (`TEST_POSTGRES_URL`)** | `test_phase6_durable_job_execution.py` (ephemeral DB `rm_test_p6_*`), `test_phase7_*`, `test_phase7a_*`, `test_phase7c_*`, `test_phase7e_*`, `test_phase7g_*`, `test_postgresql_integration.py` | CI provides `postgres:16-alpine` service on `127.0.0.1:5432/test_redmercury`; executed sequentially |
| **Live Redis 7 (`TEST_REDIS_URL`)** | `test_phase3_*`, `test_phase5_*`, `test_phase6_*`, `test_phase7_*`, `test_phase7a_*`, `test_phase7c_*` | CI provides `redis:7-alpine` service on `127.0.0.1:6379/15` |
| **Headless Chromium / CDP (`1`)** | `tests/test_phase7_production_deployment_verification.py::test_phase7_sec6_real_chromium_browser_auth_cookies_csrf_rotation_and_cors` | Launches local Chromium/Chrome binary with `--headless=new` (without `--no-sandbox`) + `uvicorn.Server` thread + `node` WebSocket script (`timeout=30`) |
| **Subprocesses / `Popen`** | `test_phase6_*`, `test_phase7*`, `test_sandbox.py`, `test_verification_security_hardening.py`, `test_scanners.py`, `test_ingestion.py`, `test_git_history_secret_scanning.py`, `test_ci_*` | Includes scanner CLIs (`bandit`, `pip_audit`, `semgrep`), Git, Python worker children, and Nginx containers |

---

### E. Failure Evidence

- **Observed Completed Steps in Job `137127047387` (`06:57:06Z` → `06:58:44Z`):**
  - Step #1 `Set up job`: `success` (`06:57:07Z`)
  - Step #2 `Initialize containers` (`postgres:16-alpine`, `redis:7-alpine`): `success` (`06:57:07Z → 06:57:22Z`)
  - Step #3 `Checkout repository`: `success` (`06:57:22Z → 06:57:23Z`)
  - Step #4 `Set up Python 3.11`: `success` (`06:57:23Z → 06:57:24Z`)
  - Step #5 `Install Backend Dependencies & Scanners`: `success` (`06:57:24Z → 06:57:50Z`)
  - Step #6 `Build Worker Sandbox Image for Live Container Isolation Tests`: `success` (`06:57:50Z → 06:58:41Z`)
  - Step #7 `Verify Python Syntax and Compilation`: `success` (`06:58:41Z`)
  - Step #8 `Verify Alembic Migration Linear Ordering`: `success` (`06:58:41Z → 06:58:44Z`)
- **Stalled Step:** Step #9 `Run Backend Pytest Suite (...)` started at `06:58:44Z`, remained `in_progress`, and job terminated at `07:27:06Z` (`cancelled`), leaving Step #10 pending (`None`).
- **Last Completed Pytest Test / Suspected Stalled Test in CI:** **`UNVERIFIED`** (raw Step #9 stdout unavailable due to HTTP 403 without GitHub auth).
- **Local Duration Profiling (`python -m pytest tests/ -q --tb=short --durations=30` against live Docker Postgres 16 + Redis 7 + Docker Engine):**
  - **Clean Run (`task-1543`, 1st completion at `07:38:28Z`):** `631 passed, 2 skipped in 252.97s (0:04:12)` (`PROF_EXIT=0`). Top slowest tests:
    - `10.50s` `test_e2e_workflow_and_negatives.py::test_full_e2e_positive_lifecycle`
    - `7.89s`, `7.85s`, `7.81s`, `7.65s`, `7.30s`, `6.74s`, `5.26s`, `4.25s`, `3.55s` `test_fix_verification_suite.py` scenarios `01`–`09`
    - `4.33s` `test_scanners.py::test_full_scan_pipeline_and_results_api`
    - `4.32s` `test_scanner_accuracy_benchmarks.py::test_bandit_sast_accuracy_benchmark`
    - `4.24s` `test_verification_security_hardening.py::test_worker_processes_pending_verifications_in_sandbox`
    - `4.00s` `test_phase7_sec6_real_chromium_browser_auth_cookies_csrf_rotation_and_cors`
    - `3.99s` `test_phase7a_sec3_worker_crash_during_cancellation_reaps_orphans_and_guards_slot`
  - **Concurrent/Disconnection Failure Mode Also Observed Locally:**
    1. When `task-1527` overlapped briefly with `task-1542` on `test_redmercury.db`, shared SQLite reset caused `8 failed, 5 errors`.
    2. When Docker Desktop stopped `rm_test_postgres` mid-run after module-import DB probing succeeded, `psycopg` connection timeouts inflated every live PostgreSQL test to `130.00s`–`260.02s` (`21 failed, 610 passed, 2 skipped in 2361.64s (0:39:21)`).

---

### F. Linux Environment Assessment

Key differences on GitHub Actions `ubuntu-latest` (cannot be reproduced cleanly on Windows without authenticated CI logs or Ubuntu Linux CI instrumentation):

1. **Linux-Active Semgrep (`backend/requirements.txt` line 24):** `semgrep>=1.65.0; sys_platform != "win32"` installs Semgrep exclusively on Linux. On Windows, `SemgrepScannerAdapter.is_available()` returns `False` (`TOOL_NOT_INSTALLED`). On Linux CI, every multi-scanner scan / `SemgrepScannerAdapter.scan()` spawns `semgrep scan --json --config ... --disable-version-check --metrics=off` (`timeout=60s` per call). *(Hypothesis only — unconfirmed without raw Step #9 log).*
2. **Docker Sandbox & Image Differences (`test_phase7_sec8` / `redmercury-worker:latest`):** Step #6 builds `redmercury-worker:latest` cleanly (`51s`), and Docker works natively on `ubuntu-latest`. Note `test_phase7_sec8` pulls/uses `redmercury-frontend:test` (which is built in a *separate* job `container-validation`, NOT `backend-tests`, unless pulled/absent -> `docker run` fallback or fail-fast error). Meanwhile `test_phase7_sec9` runs `docker exec rm_test_postgres pg_dump ...` (`timeout=15`), which exits non-zero cleanly when Postgres runs as a CI service container.
3. **Headless Chromium (`test_phase7_sec6`):** Launches Chromium without `--no-sandbox`; on Ubuntu 24.04 AppArmor, `cdp` startup either skips/fails within `timeout=30` (`40 * 0.15s = 6s` CDP wait + `timeout=30` node script) or requires diagnostic verification in Linux CI logs.
4. **PostgreSQL & Redis Service Containers:** Initialized in `15s` (`Step #2: success`). Unlike our local Docker restart outage, CI service containers stay running for the job lifetime; per Phase 8I, tests share `TEST_POSTGRES_URL` sequentially (`pytest.ini` has no `-n` parallelism).
5. **Subprocess / Signal Cleanup:** In `test_phase7a_sec3` (`sleep(120)` child PID + Docker container) and `test_verification_security_hardening.py` (`test_execution_timeout_kills_process_tree`), non-Windows uses `start_new_session=True` / `os.killpg` instead of Windows `CREATE_NEW_PROCESS_GROUP`. If a child process ignores `SIGINT`/`SIGTERM` when GitHub hits `25m`, it explains the extra `5m` termination grace window to `30m 00s`.

---

### G. Root Cause Classification

- **Classification:** **`UNRESOLVED`**
- **Severity:** **`P1`** *(Release-blocking functional/CI gate failure: `Backend Tests & Migration Consistency` cancelled on timeout in both Run #8 and Run #9, skipping `Mandatory Production Release Gate`)*
- **Supporting Evidence:**
  - *Observed fact:* Run `44995999107` Step #9 ran `06:58:44Z → 07:27:06Z` (`28m 22s` in Step #9; `30m 00s` total job runtime) before concluding `cancelled`, whereas local Windows + Docker Postgres 16 + Redis 7 completed `631 passed, 2 skipped` in `4m 12s` (`252.97s`).
  - *Missing evidence:* Raw Step #9 console logs returned HTTP `403 Forbidden` unauthenticated and `gh` CLI is absent, preventing identification of the exact test node(s) where Linux CI stalled or exceeded 25 minutes.

---

### H. Minimal Remediation Plan (For Later Authorized Implementation Phase)

Do not modify code/workflows during Phase 8M; propose the following minimal, two-stage authorized plan:

1. **Stage 1 — Immediate Evidence Capture (No Security Weakening):**
   - Have the repository owner download Job `137127047387` logs from GitHub Actions (`Run 44995999107`), **or** authorize a minimal workflow diagnostic update in [`.github/workflows/ci.yml`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/.github/workflows/ci.yml) + [`backend/requirements-dev.txt`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/requirements-dev.txt):
     - Add `pytest-timeout>=2.3.1` to `backend/requirements-dev.txt`.
     - Update `.github/workflows/ci.yml` Step #9 to run:
       `python -m pytest tests/ -v --tb=short --durations=25 --timeout=120 --junitxml=.redmercury_artifacts/pytest-results.xml`
       so any hanging Linux-specific test fails deterministically in ≤120s instead of burning 25–30 minutes until runner kill, allowing Step #10 (`if: always()`) to upload `.redmercury_artifacts/pytest-results.xml`.
2. **Stage 2 — Targeted Root-Cause Fix (Driven by Stage 1 Output):**
   - Once the exact stalling/slow Linux test(s) are identified from authenticated logs or `--timeout=120` output, remediate only the offending fixture, Linux subprocess/Semgrep/Chromium/Docker handling, or shard long-running integration suites without disabling any security test, sandbox check, or mandatory gate.
3. **Security Impact & Regression Verification:**
   - Adding diagnostic timeout enforcement + duration telemetry preserves 100% of test assertions, keeps `mandatory-release-gate` strict, and makes CI fail-fast rather than hanging silently.

---

### I. Release Gate Decision

**`UNRESOLVED — AUTHENTICATED LOGS OR LINUX REPRODUCTION REQUIRED.`**

- Local Windows regression (`631 passed, 2 skipped` in `4m 12s`) does **not** override or substitute for remote Linux CI completion.
- Remote CI Jobs `137127047241` (Frontend/Electron), `137127047398` (Docker/Compose), and `137127047415` (Gitleaks/`pip-audit`/`npm audit`/Bandit) passed on `fd03444`, while `137127047387` (`Backend Tests & Migration Consistency`) concluded `cancelled` at `30m 00s`.

**PRODUCTION DEPLOYMENT: BLOCKED / NOT AUTHORIZED / NOT PERFORMED.** *(Remains blocked on green remote CI completion plus external Git egress proxy, `GIT_EGRESS_PROXY_URL`, production TLS certificates/renewal, production vault secret injection, and external VAPT/attestation.)*
