# REDMERCURY PHASE 3A — DOCKER SANDBOX SECURITY RUNTIME VALIDATION REPORT

**Audit Date:** October 28, 2026  
**Auditor / Engineering Lead:** AI Security Specialist & Lead Systems Architect  
**Target Environment:** Red Mercury Verification & Security Worker Engine  
**Docker Engine Runtime:** Docker v29.8.2 on Linux WSL2 (6.18.0-37-amd64)  
**Execution Context:** Real-time container execution against live Docker daemon  
**Phase Verdict:** **PASS (Fully Verified)**

---

## 1. Executive Summary

In Phase 3A, Red Mercury underwent **live runtime security validation** of its Docker-based sandbox execution engine (`backend/app/verification/sandbox.py`), runner module (`backend/app/verification/runner.py`), and verification orchestration pipeline (`backend/app/verification/service.py`).

Unlike mock-based or simulated tests, all Phase 3A security invariants were validated against an active Docker daemon (v29.8.2) hosting the dedicated worker image `redmercury-worker:latest`. Every test executed bounded, non-destructive synthetic workloads designed to verify non-root isolation, network lockdown, capability dropping, read-only root filesystems, restricted writable scratch space (`tmpfs`), host secret non-inheritance, memory/process exhaustion bounding, timeout enforcement, container lifecycle purging, and fail-closed handling under execution errors.

### Overall Phase Status: **PASS**
* **Live Docker Security Runtime Tests:** **13 passed, 0 failed, 0 skipped** (100% against live daemon).
* **Full Backend Regression Suite:** **387 passed, 0 failed, 4 skipped** (disposable PostgreSQL skips when external db unavailable).
* **Frontend Test Suite:** **29 passed, 0 failed** (Vitest).
* **Frontend Production Build:** **Clean compile (Vite v6.4.4)**.

---

## 2. Files Inspected and Changed

| File Path | Change Type | Reason & Security Significance |
| :--- | :--- | :--- |
| `backend/app/verification/sandbox.py` | Production Fix | Added `-e PYTHONPATH=/workspace` and `-o pythonpath=.` to container execution arguments. Ensures unprivileged container processes can cleanly import workspace code (e.g. `src`) without requiring root permissions, dirty filesystem modifications, or host path mounting. |
| `backend/app/verification/runner.py` | Production Fix | 1. Upgraded pytest summary line parser from fragile `output.split().find()` to robust regular expression extraction (`re.findall(r'(\d+)\s+failed', output)`), preventing misclassification of failed tests as runtime errors.<br>2. Fixed container startup and execution error classification (`exit code in (125, 126, 127) or (passed==0 and failed==0 and returncode!=0)`) to return explicit `status="error"`, guaranteeing failed container execution can never be reported as verified. |
| `tests/test_sandbox.py` | Regression Fix | Updated live test fixture `test_real_docker_container_isolation` to use the built `redmercury-worker:latest` image and assert exact passing outcomes (`status == "passed"`, `passed_count == 1`). |
| `tests/test_live_docker_security_runtime.py` | New Suite | Created 13 dedicated live Docker runtime tests validating every security invariant directly against the active Docker engine. |

---

## 3. Effective Runtime Security Controls

The runtime configuration enforced for every sandbox container invocation adheres strictly to the principle of least privilege and complete isolation:

```mermaid
flowchart TD
    Host["Host Operating System (Windows / Linux)"] -->|Subprocess (Sanitized Env)| DockerCLI["Docker CLI Client"]
    DockerCLI -->|Named Pipe / Socket| DockerDaemon["Docker Daemon (v29.8.2)"]
    DockerDaemon -->|Spawns Ephemeral Container| SandboxContainer["redmercury-worker Container"]
    
    subgraph SandboxBoundary["Hardened Sandbox Boundary"]
        SandboxContainer --> User["UID=10002, GID=10002 (Non-Root)"]
        SandboxContainer --> Net["Network: --network=none (Isolated)"]
        SandboxContainer --> Caps["Capabilities: --cap-drop=ALL"]
        SandboxContainer --> SecOpt["--security-opt=no-new-privileges:true"]
        SandboxContainer --> RootFS["Root FS: --read-only"]
        SandboxContainer --> TmpFS["/tmp: rw,noexec,nosuid,size=64m"]
        SandboxContainer --> Limits["Resources: --cpus=1.0, --memory=512m, --pids-limit=50"]
        SandboxContainer --> Mount["Single Mount: -v /workspace:rw (No Host Root/Socket)"]
    end
```

### Verified Security Controls:
1. **Non-Root User Execution (`--user=10002:10002`):**
   * Process runs as unprivileged user `redmercury-sandbox` (UID 10002, GID 10002).
   * Verified: `UID=0` (root) is completely absent.
2. **Total Network Isolation (`--network=none`):**
   * Outbound TCP/UDP connections to external, private, and loopback endpoints are rejected at the kernel layer with `OSError: [Errno 101] Network is unreachable`.
   * Completely mitigates Server-Side Request Forgery (SSRF) and data exfiltration.
3. **Linux Capability Dropping (`--cap-drop=ALL`):**
   * All POSIX capabilities are stripped from the container process table.
   * Verified: Raw socket creation (`AF_INET`, `SOCK_RAW`) fails immediately with `PermissionError: [Errno 1] Operation not permitted`.
4. **Privilege Escalation Prevention (`--security-opt=no-new-privileges:true`):**
   * Child processes cannot gain additional privileges through `setuid`/`setgid` binaries.
5. **Read-Only Root Filesystem (`--read-only`):**
   * Root directories (`/bin`, `/etc`, `/usr`, `/lib`, `/var`) are mounted read-only.
   * Verified: Attempting to write an exploit payload to `/bin/exploit_binary` raises `OSError: [Errno 30] Read-only file system`.
6. **Restricted Scratch Space (`--tmpfs=/tmp:rw,noexec,nosuid,size=64m`):**
   * `/tmp` is allocated as a bounded 64MB RAM tmpfs.
   * Benchmarked: Writing temporary scratch data succeeds, but executing binaries or shell scripts from `/tmp` is blocked by the kernel with `Permission denied` (`noexec`).
7. **Resource Quotas & Bounding:**
   * `--memory=512m` (with `--memory-swap=512m`): Memory exhaustion is bounded; attempts to allocate memory beyond limits trigger Linux OOM termination without impacting the host OS.
   * `--pids-limit=50`: Fork-bomb attempts are capped; process creation throws `BlockingIOError: [Errno 11] Resource temporarily unavailable`.
   * `--cpus=1.0`: CPU starvation attacks are constrained by the CFS scheduler.
8. **Host Filesystem and Secret Isolation:**
   * Host directories (`C:\`, `/`, `/host`) and Docker socket (`/var/run/docker.sock`) are **NEVER** mounted.
   * Host environment variables (`SECRET_KEY`, `GEMINI_API_KEY`, `AWS_SECRET_ACCESS_KEY`, `DATABASE_URL`, `GITHUB_TOKEN`) are completely stripped by `get_sanitized_runner_env()` and are absent from container `os.environ`.
9. **Ephemeral Lifecycle & Timeout Cleanup:**
   * Container execution is bounded by `SandboxConfig.timeout_seconds`.
   * On timeout or process exit, `terminate_process_tree` issues `docker kill` and `docker rm -f`. Verified that zero lingering containers remain in `docker ps -a`.
10. **Fail-Closed Policy & Explicit Error Reporting:**
    * Non-existent container images, missing Docker daemons, or unexecutable binaries return `status="error"` with explicit diagnostic messages. They are never reported as clean or passed verifications.

---

## 4. Test Results: Live Docker vs. Mocked Execution

To maintain absolute test integrity, live runtime results are strictly separated from mocked unit tests:

| Test Suite / Area | Execution Mode | Items Executed | Passed | Failed | Skipped | Status |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| `tests/test_live_docker_security_runtime.py` | **Live Docker Daemon** | 13 | 13 | 0 | 0 | **PASS** |
| `tests/test_sandbox.py` (Live Items) | **Live Docker Daemon** | 2 | 2 | 0 | 0 | **PASS** |
| `tests/test_sandbox.py` (Mock/Unit Items) | Mocked Subprocess / Unit | 17 | 17 | 0 | 0 | **PASS** |
| `tests/test_fix_verification_suite.py` | **Live Docker Sandbox** | 10 | 10 | 0 | 0 | **PASS** |
| `tests/test_e2e_workflow_and_negatives.py` | **Live Docker Sandbox** | 7 | 7 | 0 | 0 | **PASS** |
| `tests/test_verification.py` | **Live Docker Sandbox** | 23 | 23 | 0 | 0 | **PASS** |
| All other backend security & scanner suites | Host / Mock / SQLite | 319 | 315 | 0 | 4 | **PASS** |
| **Total Backend Pytest Suite** | **Combined Live + Unit** | **391** | **387** | **0** | **4** | **PASS** |
| Frontend Suite (Vitest) | JSDOM / Browser Mock | 29 | 29 | 0 | 0 | **PASS** |

### Breakdown of the 13 Live Docker Runtime Tests:
1. `test_live_docker_non_root_execution`: Verified container runs under UID 10002, GID 10002.
2. `test_live_docker_network_isolation`: Verified `--network=none` raises `OSError: Network is unreachable`.
3. `test_live_docker_dropped_capabilities_block_raw_sockets`: Verified `CAP_NET_RAW` dropping raises `PermissionError: Operation not permitted`.
4. `test_live_docker_read_only_root_filesystem`: Verified writing to `/bin` raises `OSError: Read-only file system`.
5. `test_live_docker_tmpfs_is_writable_but_noexec`: Verified scratch writes succeed, but script execution from `/tmp` is denied.
6. `test_live_docker_host_secret_isolation`: Verified host secrets (`SECRET_KEY`, `GEMINI_API_KEY`, etc.) are not present in container environment.
7. `test_live_docker_no_docker_socket_or_host_drives`: Verified `/var/run/docker.sock` does not exist inside container.
8. `test_live_docker_memory_limit_bounded_oom`: Verified 32MB constrained container terminates bounded allocation safely.
9. `test_live_docker_pids_limit_anti_fork_bomb`: Verified process spawning is bounded at PID limit without starving host.
10. `test_live_docker_timeout_and_ephemeral_cleanup`: Verified hanging job is killed at timeout limit and container is purged.
11. `test_live_docker_invalid_image_fails_closed_explicitly`: Verified invalid image name produces `status="error"`, never `"passed"`.
12. `test_live_docker_fix_verification_passing_suite`: Verified end-to-end fix verification reports `status="passed"`.
13. `test_live_docker_fix_verification_failing_suite`: Verified regression test failure reports `status="failed"`.

---

## 5. Remaining Security Limitations & Operational Considerations

1. **Host-Fallback Guard in Production:**
   In development mode (`ENVIRONMENT=development`), `SANDBOX_ALLOW_HOST_FALLBACK=True` may be enabled for headless unit testing without Docker. However, `Settings.sandbox_allow_host_fallback` is hardcoded to return `False` when `ENVIRONMENT=production`. In production, if the Docker daemon or worker container is unavailable, fix verification **fails closed** immediately.
2. **Worker Container Image Pre-warming:**
   The production deployment manifest should ensure `redmercury-worker:latest` is pre-pulled or built in the host image cache to avoid pull latency during real-time user-initiated fix verification requests.
3. **Disposable PostgreSQL Infrastructure:**
   The 4 skipped PostgreSQL integration tests require an active PostgreSQL service instance (`postgresql://user:pass@localhost:5432/redmercury`). They skip gracefully with a clear message and do not conceal any defects.

---

## 6. Conclusion & Recommendation

Phase 3A runtime validation has confirmed that Red Mercury's fix verification and scanner sandbox engine is robust, unprivileged, network-isolated, resource-bounded, and strictly fail-closed. 

All 387 automated backend tests and 29 frontend tests pass without failures or regressions.

**Phase 3A Status:** **PASSED**  
**Recommended Next Step:** Proceed to production deployment containerization, CI/CD pipeline integration, or Phase 3B performance and concurrency stress testing.

