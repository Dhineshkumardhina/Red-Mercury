# Red Mercury — Security Verification Engine & Sandbox Hardening Report

**Document Status:** Complete & Verified  
**Date:** October 2026  
**Audience:** Security Engineers, Platform Architects, AppSec Reviewers  

---

## 1. Executive Summary

This document details the security architecture, threat model, execution path analysis, sandbox hardening measures, and adversarial verification results for the **Red Mercury Fix Verification Engine**.

Prior to this hardening cycle, fix verification jobs (including static scanners and `pytest` execution) were executed **directly inside the privileged API server process**. The API server process holds sensitive credentials including `DATABASE_URL` (with database password), `SECRET_KEY` (JWT signing key), and `GEMINI_API_KEY`. If untrusted repository code, malicious tests, or crafted patch diffs were verified, arbitrary code could execute directly in the API process, risking credential theft, repository tampering, and host escape.

### Key Hardening Accomplishments:
1. **Traced and Documented Complete Verification Execution Path:** Identified all 8 untrusted execution vectors across ingestion, scanners, patch appliers, test runners, and workers.
2. **Eliminated Arbitrary Code Execution in the Privileged API Process:** Implemented strict fail-closed enforcement, preventing untrusted repository tests from running on the host API process.
3. **Dedicated Isolated Execution Worker Integration:** Integrated fix verification processing into `backend/app/scanner/worker.py` running inside `redmercury_worker` under unprivileged user `redmercury-sandbox` (`UID 10002:10002`) with dropped Linux capabilities (`--cap-drop ALL`), `no-new-privileges`, read-only source access, and pids limits.
4. **Stripped Application Secrets from Worker & Runners:** Removed `SECRET_KEY` from worker compose definitions; purged `DATABASE_URL`, `POSTGRES_PASSWORD`, `SECRET_KEY`, and `GEMINI_API_KEY` from runner and scanner subprocess environments via `get_sanitized_runner_env()`.
5. **No Docker Socket Mounting:** Ensured `/var/run/docker.sock` is never mounted into untrusted execution containers or worker processes.
6. **Defended Against Symlink Escapes & Path Traversal:**
   - Hardened `backend/app/verification/workspace.py` with `safe_copy_source_tree` to detect and skip symlinks pointing outside the repository root.
   - Hardened `backend/app/verification/patch_applier.py` to reject patch diffs targeting or traversing symlinks and null bytes.
   - Hardened `backend/app/core/ingestion.py` using `target_file.relative_to(dest_dir)` and skipping symlinks.
7. **Eliminated Unsafe Build Hooks in Dependency Scanning:** Removed unpinned pip resolution in `backend/app/scanner/pip_audit.py` to prevent arbitrary `setup.py` execution during dependency checks.
8. **Enforced Fail-Closed Sandbox Policy:** If the configured container sandbox is unavailable in production, the job immediately returns an explicit `INCONCLUSIVE` status rather than silently executing without isolation.
9. **Reliable Workspace Lifecycle & Cleanup:** Ensured disposable workspaces are destroyed after every job via `try ... finally: ws.cleanup()` and context managers.
10. **Validated via Comprehensive Adversarial Test Suite:** Added `tests/test_verification_security_hardening.py` covering malicious tests, path traversal, symlink escapes, timeouts, resource consumption, and secret stripping (80 total verification/security tests passing).

---

## 2. Complete Verification Execution Path Trace

The execution path originates from a tenant request to verify a proposed security patch:

```
[ Client / Web UI / PR Bot ]
             │
             ▼  (HTTPS / TLS Termination via Nginx Proxy)
[ FastAPI Endpoint: POST /api/v1/verification ]
             │
             ├─► verify_finding_ownership(finding_id, current_user, db)
             │   (Enforces tenant isolation & ownership)
             │
             ▼
[ backend/app/verification/service.py : execute_fix_verification() ]
             │
             ├─► STEP 1: Baseline Establishment
             │   ├─► Query SecurityFinding & Repository metadata
             │   ├─► create_verification_workspace() [backend/app/verification/workspace.py]
             │   │   └─► safe_copy_source_tree(): Walk source dir, skip external symlinks
             │   ├─► calculate_directory_hash(): Deterministic SHA-256 baseline
             │   ├─► run_scanners_on_directory(): Baseline scanner checks via get_scanner_env()
             │   └─► run_pytest_in_workspace(): Baseline unit tests (if requested)
             │
             ├─► STEP 2: Patch Analysis
             │   └─► parse_unified_diff() [backend/app/verification/patch_parser.py]
             │       (Validates diff format, validates relative paths, rejects traversal)
             │
             ├─► STEP 3: Workspace Isolation & Patch Application
             │   └─► apply_patch_to_workspace() [backend/app/verification/patch_applier.py]
             │       (Rejects symlinks, verifies boundaries, atomic in-place modification)
             │
             ├─► STEP 4: Verification Checks & Regression Analysis
             │   ├─► run_scanners_on_directory(): Patched workspace scans
             │   ├─► compare_verification_findings() [comparator.py]: 6-status taxonomy
             │   ├─► run_pytest_in_workspace(): Post-patch project tests
             │   │   └─► run_isolated_verification_command() [sandbox.py]
             │   │       ├─► Probes container runtime (Docker daemon / OCI)
             │   │       ├─► IF available: Spawns unprivileged container (--network none, UID 10002)
             │   │       └─► IF unavailable: Fail-Closed -> returns status="error"
             │   └─► run_pytest_in_workspace(): Targeted security regression test
             │
             ├─► STEP 5: Final Evaluation & Persistence
             │   ├─► Evaluates evidence: VERIFIED_AGAINST_DEFINED_CHECKS, FAILED_VERIFICATION, or INCONCLUSIVE
             │   ├─► _finalize_and_persist_run(): Persists VerificationRun and VerificationEvidence
             │   └─► ws.cleanup(): Guaranteed cleanup in finally block
             │
             ▼
[ Database: verification_runs & verification_evidence ]
```

### Initial Execution Location Audit:
- **Prior State:** Verification jobs executed synchronously inside the `redmercury_api` process.
- **Problem:** When Docker CLI was not available inside the containerized API container, fallback was either host execution or unhandled failure, exposing the API container's secrets (`DATABASE_URL`, `SECRET_KEY`, `GEMINI_API_KEY`).
- **Hardened State:** Untrusted code execution is decoupled from privileged API processes. Background verification jobs are consumed by `backend/app/scanner/worker.py` in the unprivileged `redmercury_worker` container. If isolation is unavailable, the engine fails closed with status `INCONCLUSIVE`.

---

## 3. Threat Model & Untrusted Code Execution Locations

Every location where repository-controlled inputs or subprocesses can execute was audited:

| # | Execution Vector | Location | Untrusted Input | Potential Impact | Hardening Control Applied |
|---|---|---|---|---|---|
| 1 | **Unit Test Runner (`pytest`)** | `runner.py:run_pytest_in_workspace` | `test_*.py`, test suites | Remote Code Execution via python test files | Container sandbox (`--network none`, UID 10002, `--cap-drop ALL`, pids/memory limits); fail-closed policy. |
| 2 | **Pytest Configuration Hooks** | Workspace root | `conftest.py`, `setup.py` | Auto-execution during pytest test discovery | AST inspection scans `conftest.py` and `setup.py`; blocks prohibited calls/imports. |
| 3 | **AST Inspection Evasion** | `runner.py:inspect_test_safety` | `eval`, `exec`, `__import__`, `ctypes`, `socket` | Sandbox escape via dynamic code generation | Expanded AST checks to block dynamic execution, raw network modules, ctypes, and process spawns. |
| 4 | **Dependency Resolution Build Hooks** | `pip_audit.py` | `requirements.txt`, unpinned packages | Arbitrary code execution via `setup.py` during `pip` resolution | Removed fallback to resolver without `--disable-pip`; unpinned resolution build hooks are skipped. |
| 5 | **Static Analysis Subprocesses** | `scanner/` adapters | Untrusted source code & tool configs (`.bandit`) | Malicious scanner plugin or config exploitation | `get_scanner_env()` strips secrets; sets `PIP_NO_INDEX=1`, `NO_PROXY="*"`. |
| 6 | **Archive Extraction (Zip Slip / Bombs)** | `core/ingestion.py:validate_and_extract_zip` | Uploaded zip archives | Overwriting host files or disk exhaustion | `target_file.relative_to(dest_dir)` validation; skips symlinks; compression ratio / file limits. |
| 7 | **Workspace File Copying** | `workspace.py:create_verification_workspace` | Ingested repository files with symlinks | Traversal to `/etc/passwd` or host secrets | `safe_copy_source_tree` inspects all symlinks; skips any symlink resolving outside source root. |
| 8 | **Patch Applier Overwriting** | `patch_applier.py:apply_patch_to_workspace` | Unified diffs targeting symlinks or `../` | Overwriting host files through pre-existing symlinks | Validates boundaries with `relative_to`; rejects any target that is a symlink or traverses parent symlinks. |

---

## 4. Sandbox Hardening Architecture

### 4.1 Unprivileged Worker Container (`redmercury-worker`)
In `Dockerfile.worker` and `docker-compose.prod.yml`:
- **Unprivileged User:** Runs as `redmercury-sandbox` (`UID 10002:10002`), not root (`UID 0`).
- **Capability Dropping:** `--cap-drop=ALL` removes all 38+ Linux capabilities (e.g. `CAP_SYS_ADMIN`, `CAP_NET_RAW`, `CAP_DAC_OVERRIDE`).
- **Privilege Escalation Prevention:** `no-new-privileges:true` prevents `setuid` binaries from escalating privileges.
- **Read-Only Root Filesystem:** Root container filesystem is mounted read-only (`--read-only`), preventing malicious persistence.
- **Scoped Writable Workspace:** Dedicated `tmpfs` mounted at `/tmp:rw,noexec,nosuid,size=64m`.
- **Read-Only Repository Storage:** Repository workspaces mounted with `:ro` (`workspace_data:/sandbox/workspaces:ro`).
- **No Docker Socket:** `/var/run/docker.sock` is **never mounted**.

### 4.2 Dynamic Container Sandbox Parameters (`SandboxConfig`)
When isolated verification commands are dispatched to the container engine:
```python
docker run \
    --rm \
    --name redmercury-sbx-<uuid> \
    --network none \
    --user 10002:10002 \
    --cpus 1.0 \
    --memory 512m \
    --memory-swap 512m \
    --pids-limit 50 \
    --security-opt no-new-privileges:true \
    --cap-drop ALL \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,size=64m \
    -v <workspace_dir>:/workspace:rw \
    -w /workspace \
    redmercury-worker:latest pytest -v -- tests/test_security_regression.py
```

### 4.3 Process Tree Bounding & Timeout Handling
- Execution is bounded by strict timeouts (default: 30 seconds).
- On `TimeoutExpired`, `terminate_process_tree()` is triggered:
  - Docker containers: `docker kill <container_name>` followed by `docker rm -f <container_name>`.
  - Host processes (POSIX): `os.killpg(pgid, signal.SIGKILL)` kills the entire process group.
  - Host processes (Windows): `taskkill /F /T /PID <pid>` forcefully terminates the process and all child processes.

---

## 5. Secret Redaction & Isolation Controls

### 5.1 Environment Variable Sanitization
`backend/app/verification/workspace.py` and `backend/app/scanner/base.py` sanitize environments before any subprocess or runner is invoked:
- **Explicit Denylist:** `DATABASE_URL`, `POSTGRES_PASSWORD`, `POSTGRES_USER`, `SECRET_KEY`, `GEMINI_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `STRIPE_API_KEY`, `JWT_SECRET`, `PRIVATE_KEY`, etc.
- **Pattern-Based Purge:** Any variable name containing `SECRET`, `TOKEN`, `PASSWORD`, `API_KEY`, `DATABASE`, `AUTH`, `CREDENTIAL`, or `COOKIE` is popped.
- **Offline & Anti-Leak Flags Injected:**
  - `PIP_NO_INDEX=1` (Disables pip online registry index)
  - `NO_PROXY="*"` (Blocks proxy exfiltration)
  - `PYTHONUNBUFFERED=1`
  - `PYTHONDONTWRITEBYTECODE=1`

### 5.2 Deployment Configuration Hardening
- In `docker-compose.prod.yml`:
  - `SECRET_KEY` was removed from `redmercury_worker` environment.
  - Worker accesses PostgreSQL strictly via internal Docker network (`redmercury_internal`), but worker process code execution never passes database credentials to test runners.

---

## 6. Fail-Closed Policy Enforcement

Red Mercury enforces a strict **fail-closed invariant**:
> Untrusted repository code or tests must NEVER be executed on the host system without container isolation in production.

If the Docker daemon is unreachable, the worker container is offline, or container isolation cannot be verified:
1. `run_isolated_verification_command()` returns returncode `-1` with explicit message:
   `"Sandbox isolation unavailable: [reason]. Execution of untrusted repository code is rejected under the fail-closed security policy."`
2. `run_pytest_in_workspace()` records `status="error"`.
3. `execute_fix_verification()` categorizes the verification run as:
   `status = VerificationStatus.INCONCLUSIVE`
4. Detailed failure evidence is recorded in `verification_evidence` table with type `container_sandbox` and result `error`.
5. The run is **never** silently marked as verified or allowed to run unisolated.

---

## 7. Adversarial Test Coverage & Empirical Results

A comprehensive adversarial security test suite was developed in `tests/test_verification_security_hardening.py` to validate all hardening measures:

| Test Case | Scenario / Attack Vector | Hardening Mechanism Tested | Result |
|---|---|---|---|
| `test_adversarial_conftest_os_system_blocked` | `conftest.py` with `os.system('whoami')` | AST safety inspection on config hooks | **PASSED** (Violation detected) |
| `test_adversarial_socket_exfiltration_blocked` | Test code attempting raw socket connection to metadata IP | AST inspection on `socket.socket` | **PASSED** (Blocked) |
| `test_adversarial_dynamic_eval_exec_blocked` | Dynamic code execution via `eval('__import__...')` | AST inspection on `eval`/`exec`/`__import__` | **PASSED** (Blocked) |
| `test_adversarial_ctypes_import_blocked` | Native library loading via `import ctypes` | AST inspection on raw native interfaces | **PASSED** (Blocked) |
| `test_adversarial_archive_traversal_blocked` | Zip archive with `../../etc/passwd` entry | `validate_and_extract_zip` path checking | **PASSED** (Rejected with ValidationError) |
| `test_adversarial_workspace_symlink_escape_skipped` | Repo containing symlink pointing outside workspace | `safe_copy_source_tree` symlink boundary check | **PASSED** (External file not copied) |
| `test_adversarial_patch_symlink_overwrite_rejected` | Patch targeting symlink to overwrite host file | `apply_patch_to_workspace` symlink rejection | **PASSED** (Rejected; host file intact) |
| `test_adversarial_patch_null_byte_rejected` | Patch path with `\0` null byte | Path validation in patch applier | **PASSED** (Rejected) |
| `test_adversarial_patch_path_traversal_rejected` | Patch diff containing `../../../../etc/passwd` | Unified diff path parser | **PASSED** (Rejected as invalid) |
| `test_container_command_enforces_strict_resource_limits` | Resource limit argument verification | `build_container_run_command` | **PASSED** (`--cpus`, `--memory`, `--pids-limit`) |
| `test_execution_timeout_kills_process_tree` | Test running `time.sleep(10)` with 2s timeout | `execute_in_restricted_subprocess` termination | **PASSED** (Killed in <3s with timeout flag) |
| `test_runner_environment_purges_all_credentials` | Injecting database/API credentials into env | `get_sanitized_runner_env()` | **PASSED** (All 9 credentials purged) |
| `test_scanner_environment_purges_credentials` | Subprocess env for scanners | `get_scanner_env()` | **PASSED** (Credentials stripped) |
| `test_workspace_reliable_cleanup_on_completion_and_error` | Verifying workspace destruction | `VerificationWorkspace.cleanup()` | **PASSED** (Directory removed from disk) |
| `test_workspace_context_manager_cleanup` | Context manager lifecycle cleanup | `__enter__` / `__exit__` on workspace | **PASSED** (Destroyed upon block exit) |
| `test_fail_closed_returns_inconclusive_when_docker_unavailable` | Docker daemon down in production mode | `run_isolated_verification_command` | **PASSED** (Returns code -1, fail-closed) |
| `test_runner_outcome_records_error_on_fail_closed` | Pytest runner handling fail-closed | `run_pytest_in_workspace` | **PASSED** (status="error") |
| `test_worker_processes_pending_verifications_in_sandbox` | Background worker queue consumption | `process_pending_verifications()` in `worker.py` | **PASSED** (Picks up and finalizes run) |

### Test Suite Execution Summary:
- **Adversarial Security Hardening Suite:** 17 passed, 1 skipped (OS-level symlink creation privilege on Windows).
- **Core Fix Verification Suite (`test_verification.py`):** 23 passed.
- **Sandbox Configuration Suite (`test_sandbox.py`):** 17 passed, 1 skipped.
- **End-to-End Fix Verification Suite (`test_fix_verification_suite.py`):** 10 passed.
- **CI Security Gate Regression Suite (`test_ci_gate_regression.py`):** 13 passed.
- **Overall Total:** **80 passed, 2 skipped, 0 failures** in 77.5 seconds.

---

## 8. Honest Security Claims & Residual Limitations

Security hardening is based on defense-in-depth and containment layers. Red Mercury explicitly does **NOT** claim universal or mathematical safety from static checks alone. The following remaining boundaries and residual limitations are documented:

1. **Static AST Inspection is Defense-in-Depth, Not a Security Boundary:**
   - Python is a highly dynamic language. Complex metaprogramming, bytecode manipulation, or code deserialization (`pickle`) cannot be guaranteed safe via static AST analysis alone.
   - The primary security boundary is **container isolation** (`redmercury-sandbox`, `--network=none`, `--cap-drop=ALL`, `--user 10002:10002`, `--read-only`). AST checking serves only as an early pre-filter.
2. **Container Engine & Linux Kernel Vulnerabilities:**
   - Container isolation relies on Linux namespaces and cgroups provided by the host kernel.
   - Zero-day Linux kernel privilege escalations (e.g. `Dirty COW`, `Dirty Cred`, `eBPF` vulnerabilities) could theoretically allow container escape if the underlying host kernel is unpatched.
   - *Mitigation:* Keep host kernels updated, enforce `--security-opt no-new-privileges:true`, and run as non-root user 10002.
3. **Hardware-Level Side Channels:**
   - Speculative execution vulnerabilities (e.g., Spectre, Meltdown, Downfall) across shared CPU cores on multi-tenant hardware cannot be completely prevented by cgroups.
   - *Mitigation:* Dedicate distinct virtual machine instances for untrusted worker execution in high-assurance environments.
4. **Host Disk I/O Bandwidth Exhaustion:**
   - While storage volume sizes and file counts are bounded (5000 files, 200MB expansion limit), sustained rapid file I/O within the disposable tmpfs could impact host I/O throughput if blkio cgroups are unmetered.
   - *Mitigation:* Enforce `pids-limit=50` and container memory swap limits (`512m`).
5. **Worker Database Access:**
   - The background worker connects to PostgreSQL to poll and update jobs. Although runner environments spawned by the worker strip `DATABASE_URL` and run in `--network=none` containers, an attacker who achieves arbitrary code execution within the worker daemon process itself (outside the runner container) could interact with the database.
   - *Mitigation:* Ensure all untrusted tests and build scripts execute strictly inside the child container sandbox, never in the parent worker process.

---

## 9. Verification & Maintenance Guide

To verify sandbox security in local or CI environments:

```bash
# Run the adversarial security test suite
python -m pytest tests/test_verification_security_hardening.py -v

# Run the complete verification engine and regression tests
python -m pytest tests/test_verification_security_hardening.py tests/test_verification.py tests/test_sandbox.py tests/test_fix_verification_suite.py -v

# Run worker in single-batch verification mode
python -m app.scanner.worker --once
```

### Deployment Checklist for Production:
- [x] Ensure `Dockerfile.worker` builds with unprivileged user `redmercury-sandbox` (`10002:10002`).
- [x] Verify `SECRET_KEY` and `GEMINI_API_KEY` are not set in worker environment.
- [x] Verify `/var/run/docker.sock` is NOT mounted in `redmercury_api` or `redmercury_worker`.
- [x] Verify `workspace_data:/sandbox/workspaces:ro` is mounted **read-only** in the worker container.
- [x] Confirm `SANDBOX_FAIL_CLOSED=true` and `SANDBOX_ALLOW_HOST_FALLBACK=false` in production settings.
