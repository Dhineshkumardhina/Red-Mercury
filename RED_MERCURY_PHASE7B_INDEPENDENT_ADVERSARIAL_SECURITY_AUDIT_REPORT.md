# RED MERCURY — PHASE 7B
# INDEPENDENT ADVERSARIAL SECURITY AUDIT & DISTRIBUTED SYSTEMS ASSURANCE REPORT

**Repository:** `https://github.com/Dhineshkumardhina/Red-Mercury`  
**Product:** Red Mercury — Enterprise Application Security & Automated Fix Verification Engine  
**Organization:** Xerova Digital Solutions  
**Audited Branch:** `main`  
**Audited HEAD Commit:** `b9df7b9650e0ba431e8d32b19edf30ddd6f6289c` (`b9df7b9`)  
**Baseline:** Phase 7A Working Tree (All Phase 0–7A modifications preserved intact)  
**Phase:** Phase 7B — Independent Adversarial Security Audit & Distributed Systems Assurance (Audit-Only)  
**Audit Date:** 2026-11-22  

---

## 1. Repository Preservation Verification

In strict compliance with Section 1 and Section 9 of Phase 7B, this engagement was executed as a **non-destructive, audit-only review**:

1. **Git Branch & HEAD Commit:**
   - Branch: `main`
   - HEAD: `b9df7b9650e0ba431e8d32b19edf30ddd6f6289c`
2. **Working-Tree Preservation:**
   - All `60` modified tracked files and `25` untracked files/directories from Phases 0–7A were preserved without alteration.
   - Zero existing source files, test files, migrations, Dockerfiles, or previous phase reports (`RED_MERCURY_PHASE0..7A_*.md`) were modified, reset, or overwritten during Phase 7B.
   - Zero `.env` files, credentials, API keys, or secrets were read, printed, or exposed.
   - Zero Git commits, pushes, merges, or external network deployments were executed.

---

## 2. Files Inspected

Every line of the target distributed execution, security, ingestion, audit, container, and CI/CD modules was independently inspected against the actual working-tree source code:

| Category | File Inspected | Lines Inspected | Primary Audit Focus |
| :--- | :--- | :--- | :--- |
| **Distributed Job Engine** | [backend/app/core/jobs.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/jobs.py) | `1–2660` | State machine, outbox, quota slots, `FOR UPDATE SKIP LOCKED`, `before_commit` lease fencing, orphan reaping, cancellation recovery |
| **Worker Daemon** | [backend/app/scanner/worker.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/scanner/worker.py) | `1–499` | Polling loop, orphan backfill, SIGTERM lease release, heartbeat file |
| **Scan Orchestrator** | [backend/app/scanner/runner.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/scanner/runner.py) | `1–331` | Lease-fenced findings deletion/insertion, posture calculation, scan status & audit persistence |
| **Scanner Subprocess Base** | [backend/app/scanner/base.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/scanner/base.py) | `1–251` | `run_scanner_subprocess()`, process group isolation, environment sanitization |
| **Verification Service** | [backend/app/verification/service.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/verification/service.py) | `1–945` | 5-step verification lifecycle, `_finalize_and_persist_run()`, evidence & audit persistence |
| **Verification Sandbox** | [backend/app/verification/sandbox.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/verification/sandbox.py) | `1–345` | `check_docker_availability()`, `build_container_run_command()`, container labels, fail-closed policy |
| **Verification Workspace** | [backend/app/verification/workspace.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/verification/workspace.py) | `1–258` | Disposable temp directory lifecycle, symlink skipping, tracker registration |
| **Audit Ledger** | [backend/app/core/audit.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/audit.py) | `1–68` | `record_audit_event()`, metadata redaction, commit & exception semantics |
| **Ingestion & SSRF Engine** | [backend/app/core/ingestion.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/ingestion.py) | `1–1287` | `is_ip_blocked()`, `validate_git_url()`, `validate_git_egress_proxy_url()`, `clone_git_repository()`, `http.curloptResolve` |
| **Repository Endpoints** | [backend/app/api/v1/endpoints/repositories.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/api/v1/endpoints/repositories.py) | `1–571` | `/ingest/upload`, `/ingest/git`, `/{repo_id}/clone`, `/ingest/local`, `DELETE /{repo_id}` |
| **Database Models & Migration** | [backend/app/models/job.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/models/job.py), [0014_add_durable_jobs_and_outbox.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/alembic/versions/0014_add_durable_jobs_and_outbox.py) | `1–195` | `durable_jobs`, `job_outbox_events`, `active_job_slots` constraints and indexes |
| **Containers & Topology** | [docker-compose.prod.yml](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/docker-compose.prod.yml), [Dockerfile.api](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/Dockerfile.api), [Dockerfile.worker](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/Dockerfile.worker), [Dockerfile.frontend](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/Dockerfile.frontend), [nginx/production.conf](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/nginx/production.conf) | All lines | Network segmentation, capabilities, read-only rootfs, TLS/CSP header inheritance |
| **CI/CD Pipelines** | [.github/workflows/ci.yml](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/.github/workflows/ci.yml), [.github/secret_scanning.yml](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/.github/secret_scanning.yml) | `1–278` | Service health checks, action SHA pinning, Gitleaks SHA-256 verification, `pip_audit` exception scope |

---

## 3. Audit Methodology

Rather than assuming passing tests imply absence of vulnerabilities, Phase 7B applied an adversarial failure-mode methodology across six dimensions:

1. **Transaction & Session State Lifecycle Analysis:** Traced SQLAlchemy `Session` state (`session.info`, savepoints, rollbacks, connection pooling, and PostgreSQL `READ COMMITTED` snapshot semantics) across normal, errored, and reused session paths.
2. **Cross-Namespace & OS Process Table Analysis:** Challenged how PIDs, container names, and temporary filesystem paths behave when workers and recovery sweeps run in separate containers/PID namespaces or after OS PID recycling.
3. **Dual-Write & Concurrent Sweep Analysis:** Evaluated every query in the outbox dispatcher, lease claimer, quota allocator, and crash-recovery sweep for missing row-level locks (`FOR UPDATE SKIP LOCKED`) or compare-and-swap (CAS) gaps.
4. **Network & Protocol Boundary Analysis:** Separated application-layer URL/DNS validation from OS/container network routing (`redmercury_internal: internal: true`) and libcurl (`git-remote-https`) connection-time behavior.
5. **Audit Atomicity Analysis:** Checked every call site of `record_audit_event()` vs. direct `AuditEvent` insertion to determine whether security-relevant actions can commit without an audit trail or vice versa.
6. **Container & Supply-Chain Boundary Analysis:** Evaluated every service in `docker-compose.prod.yml`, every `Dockerfile.*`, `nginx/production.conf`, and `.github/workflows/ci.yml` for privilege inconsistencies, unhashed dependency installation, or header overrides.

---

## 4. Independent Findings Summary

No **P0 (Critical)** or **P1 (High)** exploitable vulnerabilities were found in the Phase 7A implementation. However, the adversarial audit identified **four P2 (Moderate)** distributed-systems/security edge cases, **two P3 (Low)** consistency gaps, and **two INFO** hardening recommendations:

| Finding ID | Severity | Title | Affected Component |
| :--- | :---: | :--- | :--- |
| **P7B-F01** | **P2** | `session.info["_fenced_job_lease"]` persists across `session.rollback()` and `session.commit()` without an `after_rollback` / `after_commit` cleanup hook and holds only a single job tuple | `backend/app/core/jobs.py` (`assert_active_worker_lease_or_abort`, `_enforce_lease_fencing_before_commit`) |
| **P7B-F02** | **P2** | Orphaned PID tracking records raw integer PIDs without worker hostname/container namespace ID or process start-time fingerprint (PID reuse & cross-container namespace risk) | `backend/app/core/jobs.py` (`record_job_runtime_artifacts`, `_is_pid_running`, `_kill_pid_tree_safely`, `reap_and_verify_orphaned_job_resources`) |
| **P7B-F03** | **P2** | `dispatch_outbox_events()` queries `status == "pending"` without `FOR UPDATE SKIP LOCKED`, allowing concurrent outbox recovery sweeps to push duplicate Redis notifications | `backend/app/core/jobs.py` (`dispatch_outbox_events`, `recover_undispatched_outbox_events`) |
| **P7B-F04** | **P2** | Git ingestion executes synchronously in the `api` worker process (up to `2 x 60s` on branch fallback) and performs local pre-proxy DNS resolution (`socket.getaddrinfo`) even when `GIT_EGRESS_PROXY_URL` is configured | `backend/app/api/v1/endpoints/repositories.py`, `backend/app/core/ingestion.py` (`validate_git_url`, `clone_git_repository`) |
| **P7B-F05** | **P3** | 24-hour daily scan quota `COUNT(*)` check in `reserve_atomic_job_slot()` is non-locking, and standalone `record_audit_event()` commits autonomously while swallowing non-lease exceptions | `backend/app/core/jobs.py` (`reserve_atomic_job_slot`), `backend/app/core/audit.py` (`record_audit_event`) |
| **P7B-F06** | **P3** | `nginx/production.conf` global SPA `Content-Security-Policy` replaces FastAPI's stricter `default-src 'none'` CSP on `/api/` responses, and `postgres`/`nginx` services omit `cap_drop: [ALL]` in `docker-compose.prod.yml` | `nginx/production.conf`, `docker-compose.prod.yml` |
| **P7B-F07** | **INFO** | `Dockerfile.api` runs `alembic upgrade head` in container `CMD` without a PostgreSQL advisory lock, and Python `requirements.txt` uses `>=` bounds without `--require-hashes` | `Dockerfile.api`, `Dockerfile.worker`, `backend/requirements.txt` |
| **P7B-F08** | **INFO** | `record_job_runtime_artifacts()` skips autonomous session persistence on SQLite when `db is None`, relying on in-process memory tracking during single-process SQLite development | `backend/app/core/jobs.py` (`record_job_runtime_artifacts`) |

---

## 5. Detailed Adversarial Findings & Section-by-Section Analysis

### 5.1 Distributed Transaction & Lease-Fencing Analysis (Section 2)

#### What Is Proven Solid
- **PostgreSQL `READ COMMITTED` Atomic Fencing at `before_commit`:**
  In [backend/app/core/jobs.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/jobs.py#L1455-L1496), `_enforce_lease_fencing_before_commit(session: Session)` executes inside the active transaction immediately before SQLAlchemy emits `COMMIT`:
  ```sql
  UPDATE durable_jobs
  SET heartbeat_at = :now
  WHERE id = :jid
    AND status = 'running'
    AND worker_id = :wid
    AND lease_token = :tok
    AND lease_expires_at > :now
  ```
  Under PostgreSQL's default `READ COMMITTED` isolation level, an `UPDATE` statement evaluates its `WHERE` clause against the latest committed tuple version (waiting if another transaction currently holds a row lock on that tuple, and re-evaluating the `WHERE` predicate after the lock holder commits).
  - If Worker B (or `recover_expired_job_leases()`) has already committed a lease recovery or reassignment (`lease_token != :tok` or `status != 'running'`), `res.rowcount` is deterministically `0`, raising `StaleWorkerLeaseError` and aborting Worker A's commit.
  - If Worker A's `UPDATE` matches (`res.rowcount == 1`), PostgreSQL acquires an exclusive row lock on `durable_jobs WHERE id = :jid` for the remainder of Worker A's commit phase, blocking any concurrent recovery or claim until Worker A's transaction commits.
- **Single-Transaction Business-Data Consolidation:**
  In [backend/app/scanner/runner.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/scanner/runner.py#L219-L310) (`run_security_scan`) and [backend/app/verification/service.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/verification/service.py#L860-L905) (`_finalize_and_persist_run`), all business entities (`SecurityFinding`, `SecurityEvidence`, `VerificationEvidence`, `Scan.status`, `Repository` posture counts, `VerificationRun.status`, and `AuditEvent`) are flushed and committed in one transaction gated by `_enforce_lease_fencing_before_commit`.

#### Identified Weakness — Finding P7B-F01 (`P2`)
1. **Exact Affected File & Function:** [backend/app/core/jobs.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/jobs.py#L1447-L1496) (`assert_active_worker_lease_or_abort()` and `_enforce_lease_fencing_before_commit()`).
2. **Root Cause:**
   - `session.info` is a dictionary attached to the `Session` instance for its entire lifetime (not cleared automatically by SQLAlchemy upon `session.rollback()` or `session.commit()`).
   - While `complete_claimed_job()`, `fail_claimed_job()`, `acknowledge_job_cancellation()`, `cancel_durable_job()`, `recover_expired_job_leases()`, `release_claimed_job_on_shutdown()`, and `renew_job_lease()` explicitly execute `db.info.pop("_fenced_job_lease", None)`, there is no `after_rollback` or `after_commit` event listener clearing `session.info["_fenced_job_lease"]`.
   - Furthermore, `session.info["_fenced_job_lease"]` stores a single 3-tuple `(job_id, worker_id, lease_token)` rather than a set of tuples.
3. **Reproduction Evidence (Verified Live):**
   Executed against the live codebase:
   ```text
   AFTER_ROLLBACK_FENCE_STILL_PRESENT: True
   ```
   After `s.rollback()`, `s.info["_fenced_job_lease"]` remained populated with `('nonexistent-job', 'worker-a', 'tok-a')`.
4. **Exploitation / Trigger Conditions:**
   - If a caller catches `StaleWorkerLeaseError`, rolls back `db`, and reuses the same `Session` object `db` to perform a subsequent non-fenced database commit without calling one of the lifecycle pop helpers, `_enforce_lease_fencing_before_commit` will fire again with the stale `_fenced_job_lease` tuple and abort the unrelated commit.
   - If a single transaction ever called `assert_active_worker_lease_or_abort()` for two different fenced jobs before committing, only the second job's lease would be verified at `before_commit`.
5. **Potential Impact:** Spurious `StaleWorkerLeaseError` on reused SQLAlchemy sessions after rollback, or incomplete fencing if a single transaction ever batched multiple fenced jobs.
6. **Recommended Remediation:**
   - Store `session.info.setdefault("_fenced_job_leases", set()).add((job_id, worker_id, lease_token))` and iterate over all tuples in `_enforce_lease_fencing_before_commit`.
   - Register `@event.listens_for(Session, "after_rollback")` and `@event.listens_for(Session, "after_commit")` listeners to clear `session.info.pop("_fenced_job_leases", None)`.
7. **Regression Test Requirements:** Test that a `Session` rolled back after `StaleWorkerLeaseError` has its fencing metadata automatically cleared on `after_rollback`, and that a transaction touching two distinct fenced jobs verifies both leases on `before_commit`.

---

### 5.2 Worker Crash and Orphan Recovery Analysis (Section 3)

#### What Is Proven Solid
- **Container Ownership & Name Spoofing Prevention ([backend/app/core/jobs.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/jobs.py#L1614-L1701)):**
  - Every container name read from `payload_json["_runtime_artifacts"]["containers"]` or discovered via `docker ps -a --filter label=redmercury.job_id=<job.id>` is validated against `_SAFE_SANDBOX_CONTAINER_RE = re.compile(r"^redmercury-sbx-[a-zA-Z0-9_\-]+$")` and invoked with `shell=False` (`["docker", "kill", cname]`, `["docker", "rm", "-f", cname]`). A corrupted or malicious `payload_json` containing `"containers": ["redmercury_postgres", "rm_test_redis", "--all"]` is rejected by `_SAFE_SANDBOX_CONTAINER_RE` and cannot stop infrastructure containers.
- **Disposable Workspace Confinement & Symlink Protection ([backend/app/core/jobs.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/jobs.py#L1270-L1308)):**
  - `cleanup_temp_workspaces()` resolves each candidate path, rejects symlinks (`resolved.is_symlink()`), requires an explicit disposable prefix (`("redmercury_verify_", "rm_verify_", "rm_p6_cancel_ws_", "rm_p7a_cancel_ws_")`), and enforces `resolved != root and resolved.is_relative_to(root)` inside `tempfile.gettempdir()` or `WORKER_TEMP_DIR`. Persistent repository workspaces under `WORKSPACE_ROOT` (`data/workspaces/<tenant>/<repo>/source`) cannot match the prefix or root and are never deleted.
- **Fail-Closed Concurrency Slot Retention ([backend/app/core/jobs.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/jobs.py#L2022-L2048)):**
  - When `reap_and_verify_orphaned_job_resources()` returns `verified_stopped = False`, `recover_expired_job_leases()` refuses to mark the job `"cancelled"` (or retry/fail it) and retains the `ActiveJobSlot`.

#### Identified Weakness — Finding P7B-F02 (`P2`)
1. **Exact Affected File & Function:** [backend/app/core/jobs.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/jobs.py#L1498-L1612) (`record_job_runtime_artifacts()`, `_is_pid_running()`, `_kill_pid_tree_safely()`, `reap_and_verify_orphaned_job_resources()`).
2. **Root Cause:**
   - `_runtime_artifacts["child_pids"]` stores bare integer PIDs (`[int(p) for p in child_pids]`) without recording:
     1. The **host/container identity** (`socket.gethostname()`) where the PID was spawned.
     2. The **process start timestamp / command identity** (`/proc/<pid>/stat` field 22 start time or executable name).
3. **Reproduction / Exploitation Conditions:**
   - **Condition 1 (Multi-Container PID Namespace Mismatch):** In `docker-compose.prod.yml`, `api` (`redmercury_api`) and `worker` (`redmercury_worker`) run in separate Linux PID namespaces. Both `api` and `worker` call `reconcile_jobs_on_startup()` -> `recover_expired_job_leases()`. If `worker` crashes after recording `child_pids: [25]`, and `api` runs `recover_expired_job_leases()`, `api` checks `_is_pid_running(25)` and runs `_kill_pid_tree_safely(25)` inside **`api`'s own PID namespace**, not `worker`'s PID namespace!
   - **Condition 2 (OS PID Recycling on Same Host):** On a single host/container where PIDs wrap around (e.g. `pids: 100` in `docker-compose.prod.yml` or default Linux `pid_max = 32768`), if a child scanner process exits right before the worker crashes and the OS kernel assigns the same integer PID to a new child process of another worker thread before the lease expires (`60s`), `_kill_pid_tree_safely(pid)` has no creation-time fingerprint to distinguish the new process from the old one.
4. **Potential Impact:**
   - Cross-container recovery in `api` could signal an active process with the same numeric PID inside `api` (if owned by the same UID, though `api` runs as UID `10001` and `worker` runs as UID `10002`), or if PID 25 in `api` is owned by root (e.g. `tini` PID 1 or similar), `os.kill(pid, 0)` raises `PermissionError`, which `_is_pid_running()` at line 1581 treats as `return True`! That would cause `api`'s `recover_expired_job_leases()` to believe the orphaned process is still running and permanently defer recovery (`deferred_active`)!
5. **Recommended Remediation:**
   - Store structured child process descriptors in `_runtime_artifacts["child_processes"]`:
     `{"hostname": socket.gethostname(), "pid": int(proc.pid), "start_time": _get_pid_start_time(proc.pid)}`.
   - In `reap_and_verify_orphaned_job_resources()`:
     - If `entry["hostname"] != socket.gethostname()`, do not call local `os.kill()` on a remote container's PID namespace (if the remote worker container restarted, its container PID namespace was destroyed with it).
     - Before signaling a local PID, verify `_get_pid_start_time(pid) == entry["start_time"]`.
6. **Regression Test Requirements:** Test that `reap_and_verify_orphaned_job_resources()` ignores PIDs recorded under a different `hostname` or with a mismatched `start_time` fingerprint.

---

### 5.3 Outbox and Cancellation Consistency Analysis (Section 4)

#### What Is Proven Solid
- **Duplicate Message Delivery & Concurrent Claiming ([backend/app/core/jobs.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/jobs.py#L649-L734)):**
  - Redis is used strictly as an untrusted wake-up hint (`pop_job_from_redis_queue()`). `claim_durable_job_by_id()` executes `SELECT id, started_at FROM durable_jobs WHERE id = :job_id AND status IN ('queued', 'retrying') ... FOR UPDATE SKIP LOCKED` on PostgreSQL followed by an atomic conditional `UPDATE` checking `status IN ('queued', 'retrying')`. Duplicate Redis messages cannot cause duplicate execution.
- **Cancellation Handshake & Terminal-State Immutability ([backend/app/core/jobs.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/jobs.py#L111-L114)):**
  - `VALID_JOB_STATE_TRANSITIONS` defines empty target sets (`set()`) for `COMPLETED`, `FAILED`, and `CANCELLED`. Once a job reaches a terminal state, `cancel_durable_job()`, `complete_claimed_job()`, and `fail_claimed_job()` cannot overwrite it.
  - When a running job has an active remote worker lease (`has_live_remote_lease`), `cancel_durable_job()` transitions it to `"cancelling"` and preserves the `ActiveJobSlot` until either the worker calls `acknowledge_job_cancellation()` or the lease expires and `recover_expired_job_leases()` verifies zero running orphans.

#### Identified Weakness — Finding P7B-F03 (`P2`)
1. **Exact Affected File & Function:** [backend/app/core/jobs.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/jobs.py#L221-L305) (`dispatch_outbox_events()`, `recover_undispatched_outbox_events()`).
2. **Root Cause:**
   - `dispatch_outbox_events()` selects pending events via a non-locking query:
     ```python
     pending_events = query.order_by(JobOutboxEvent.created_at.asc()).limit(limit).all()
     ```
     and then loops over `pending_events`, calling `client.rpush(...)` and `event.status = "dispatched"; db.commit()` without a `FOR UPDATE SKIP LOCKED` lock or conditional `UPDATE job_outbox_events SET status = 'dispatched' WHERE id = :id AND status = 'pending'`.
3. **Exploitation / Trigger Conditions & Impact:**
   - If two worker processes run `recover_undispatched_outbox_events()` simultaneously after a Redis outage (or an API thread runs `dispatch_outbox_events(job_id=...)` while a worker sweep is running), both select the same `pending` outbox row and both push the notification to Redis.
   - Because `claim_durable_job_by_id()` is atomic and idempotent, this does **not** cause duplicate job execution, but it creates redundant Redis queue entries and race-prone `dispatch_attempts` increments.
4. **Recommended Remediation:** On PostgreSQL, add `.with_for_update(skip_locked=True)` to the `JobOutboxEvent` query in `dispatch_outbox_events()`, or atomically claim the outbox row via `UPDATE job_outbox_events SET status = 'dispatched' WHERE id = :id AND status = 'pending'` before/around dispatch.
5. **Regression Test Requirements:** Concurrent outbox sweep test verifying that `client.rpush` is invoked exactly once per `JobOutboxEvent` across 4 parallel `recover_undispatched_outbox_events()` threads on live PostgreSQL 16.

---

### 5.4 Git SSRF and Network Boundary Analysis (Section 5)

#### Static vs. Live Verification Distinction
- **Verified Statically & via Unit/API Tests:**
  - `is_ip_blocked()` blocks IPv4 loopback (`127.0.0.0/8`), RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local/metadata (`169.254.0.0/16`), CGNAT (`100.64.0.0/10`), multicast, and IPv6 loopback (`::1`), link-local (`fe80::/10`), ULA (`fc00::/7`), site-local (`fec0::/10`), IPv4-mapped IPv6 (`::ffff:0:0/96`), 6to4, and Teredo addresses.
  - `validate_git_url()` rejects non-HTTPS schemes (when `allow_private=False`), embedded URL credentials, single-label internal hostnames, and remote-helper prefixes (`ext::`, `fd::`).
  - `clone_git_repository()` passes `-c protocol.allow=never -c protocol.https.allow=always -c protocol.file.allow=never -c http.followRedirects=false -c core.symlinks=false -c submodule.recurse=false --no-recurse-submodules` and strips all ambient proxy/SSH/config environment variables via `_build_sanitized_git_env()`.
  - `docker-compose.prod.yml` attaches `api` (`redmercury_api`, where Git executes) exclusively to `redmercury_internal` (`internal: true`), blocking direct container-to-internet routing at the Docker bridge firewall.
- **Not Verified Against a Live Forward-Proxy Appliance:**
  - No external forward-proxy container (Smokescreen/Squid/Envoy) was provisioned or connected to during Phase 7B.

#### Identified Weakness — Finding P7B-F04 (`P2`)
1. **Exact Affected Files & Functions:**
   - [backend/app/api/v1/endpoints/repositories.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/api/v1/endpoints/repositories.py#L250-L426) (`ingest_git_repository()`, `clone_registered_git_repository()`)
   - [backend/app/core/ingestion.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/ingestion.py#L253-L268) (`validate_git_url()`) and [backend/app/core/ingestion.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/ingestion.py#L1209-L1230) (`clone_git_repository()`)
2. **Root Cause:**
   - **Pre-Proxy Local DNS Resolution Dependency:** In `validate_git_url()` (lines 253–268), `socket.getaddrinfo(hostname, port)` is always executed locally inside the `api` container—even when `GIT_EGRESS_PROXY_URL` is configured. On an isolated internal Docker network (`redmercury_internal: internal: true`) where external DNS resolution is disabled or restricted to the forward-proxy appliance, local `socket.getaddrinfo()` for `github.com` will fail with `DNS resolution failed` before `git clone -c http.proxy=...` is even invoked. Conversely, if external DNS is reachable from `api`, an attacker-controlled DNS server could return a benign public IP during `validate_git_url()` in `api` and a rebinding IP (`127.0.0.1` or `169.254.169.254`) when the external proxy resolves the hostname during HTTP `CONNECT`—meaning DNS-rebinding defense in proxy mode relies on the external proxy appliance itself enforcing SSRF IP filtering (e.g. Smokescreen).
   - **Synchronous API Worker Blocking & 2x Timeout on Branch Fallback:** Git cloning runs synchronously inside the `api` Uvicorn/Gunicorn worker process rather than as an asynchronous durable job. If `--branch` fails with `"remote branch ... not found"`, lines 1212–1230 retry `git clone` with a second full `timeout` (`2 x 60s = 120s`), which can exhaust Gunicorn's `--timeout 120` worker timeout and tie up API workers under concurrent clone requests.
3. **Recommended Remediation:**
   - Move Git repository cloning to a durable background job (`job_type="git_clone"`) or bound the total wall-clock timeout across primary + fallback clone attempts to `< 60s`.
   - Document as a mandatory deployment requirement that the `GIT_EGRESS_PROXY_URL` appliance MUST be an SSRF-filtering proxy (such as Stripe Smokescreen) that blocks private/loopback/link-local/metadata IPs at connection time.

---

### 5.5 Audit Ledger and Transactional Integrity Analysis (Section 6)

#### What Is Proven Solid
- **Worker Scan & Verification Audit Atomicity:**
  - In Phase 7A, `run_security_scan()` ([backend/app/scanner/runner.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/scanner/runner.py#L280-L310)) and `_finalize_and_persist_run()` ([backend/app/verification/service.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/verification/service.py#L862-L902)) were updated to instantiate `AuditEvent` directly on `db` within the same lease-fenced transaction as `SecurityFinding`, `SecurityEvidence`, `VerificationEvidence`, `Scan`, and `VerificationRun`. If the transaction rolls back (e.g. on `StaleWorkerLeaseError`), both the business data and the `AuditEvent` roll back atomically.
- **Historical Evidence Immutability:**
  - `SecurityEvidence` records are append-only with SHA-256 `content_hash` verification; retries or cancellations of subsequent jobs do not delete prior `SecurityEvidence` or `AuditEvent` rows.

#### Identified Weakness — Finding P7B-F05 (`P3`)
1. **Exact Affected Files & Functions:**
   - [backend/app/core/audit.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/audit.py#L34-L66) (`record_audit_event()`)
   - [backend/app/core/jobs.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/jobs.py#L411-L429) (`reserve_atomic_job_slot()`)
2. **Root Cause & Impact:**
   - **Autonomous Commit & Swallowed Errors in `record_audit_event()`:** API endpoints outside the worker (`repositories.py`, `auth.py`, `scans.py`) commit their primary database change (`db.commit()`) first and then call `record_audit_event(db, ...)`, which performs a second `db.commit()` and catches `Exception` (logging the error and returning `None`). Thus, if the database connection drops between the primary commit and `record_audit_event()`, the API operation succeeds without its audit record.
   - **Non-Locked 24-Hour Daily Quota Count:** In `reserve_atomic_job_slot()`, the concurrent slot limit (`MAX_CONCURRENT_SCANS_PER_USER`) is enforced by a hard database `UniqueConstraint` (`uq_active_job_slots_tenant_type_slot`), but the 24-hour rolling quota (`MAX_DAILY_SCANS_PER_USER = 50`) uses a non-locking `SELECT COUNT(*)` on `scans`. Under concurrent requests near `49/50`, up to `MAX_CONCURRENT_SCANS_PER_USER` requests can pass the daily count check simultaneously.
3. **Recommended Remediation:** Add an optional `commit: bool = True` parameter to `record_audit_event()` so API endpoints can stage the `AuditEvent` before their single `db.commit()`, and acquire a row-level lock on `User` (`db.query(User).filter(User.id == user.id).with_for_update().first()`) on PostgreSQL inside `reserve_atomic_job_slot()` before checking `daily_scans_count`.

---

### 5.6 CI/CD and Container Security Analysis (Section 7)

#### What Is Proven Solid
- **GitHub Actions Pinning & Least Privilege ([.github/workflows/ci.yml](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/.github/workflows/ci.yml)):**
  - Top-level and job-level `permissions: contents: read`.
  - Every third-party action (`actions/checkout`, `actions/setup-python`, `actions/setup-node`, `actions/upload-artifact`, `docker/setup-buildx-action`, `docker/build-push-action`) is pinned to an immutable full-length 40-char commit SHA.
  - Gitleaks `v8.18.2` binary tarball is verified with `sha256sum -c -` against `6298c9235dfc9278c14b28afd9b7fa4e6f4a289cb1974bd27949fc1e9122bdee` before extraction.
  - `pip_audit` exception is strictly scoped to a single `--ignore-vuln CVE-2026-132276` (for `wcmatch~=8.5.1` upper-bounded `<9.0` by upstream Semgrep) with no `|| true` or `continue-on-error`.

#### Identified Weaknesses — Findings P7B-F06 (`P3`) & P7B-F07 (`INFO`)
1. **Finding P7B-F06 (`P3` — Nginx API CSP Override & Compose `cap_drop` Parity):**
   - In [nginx/production.conf](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/nginx/production.conf#L69-L82), `proxy_hide_header Content-Security-Policy;` strips FastAPI's strict API CSP (`default-src 'none'; frame-ancestors 'none'`) and replaces it with the server-level SPA CSP (`default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' ...`) on `/api/` responses. While JSON API responses with `X-Content-Type-Options: nosniff` are not rendered as HTML documents, keeping `default-src 'none'; frame-ancestors 'none'` on `/api/` location blocks is stronger defense-in-depth.
   - In [docker-compose.prod.yml](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/docker-compose.prod.yml), `postgres` and `nginx` do not declare `cap_drop: [ALL]` (unlike `redis`, `api`, `worker`, and `frontend`).
2. **Finding P7B-F07 (`INFO` — Multi-Replica Alembic Startup Race & Unhashed `pip install`):**
   - In [Dockerfile.api](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/Dockerfile.api#L79), `CMD` runs `alembic upgrade head && exec gunicorn ...`. If multiple `api` container replicas start simultaneously against a fresh PostgreSQL database, concurrent `alembic upgrade head` processes can race unless serialized via a PostgreSQL advisory lock (`pg_advisory_lock`) in `backend/alembic/env.py` or a dedicated migration init job.
   - In `Dockerfile.api` and `Dockerfile.worker`, `pip install -r requirements.txt` uses `>=` version constraints without `--require-hashes`.

---

## 6. Tests Executed During Phase 7B

No existing tests were weakened or modified. The following verification runs were executed against the unmodified Phase 7A codebase:

| Verification Run | Target / Command | Result |
| :--- | :--- | :--- |
| **Adversarial Session Rollback Probe** | Python probe verifying `session.info['_fenced_job_lease']` retention across `session.rollback()` (Finding **P7B-F01**) | Confirmed `AFTER_ROLLBACK_FENCE_STILL_PRESENT: True` |
| **Phase 7A Distributed Security Hardening Suite** (Live Postgres 16, Redis 7, Docker) | `pytest tests/test_phase7a_distributed_security_hardening.py` | **6 / 6 PASSED** |
| **Phase 7 Production Deployment Verification Suite** (Live Postgres 16, Redis 7, Nginx HTTP+TLS, Headless Chromium) | `pytest tests/test_phase7_production_deployment_verification.py` | **8 / 8 PASSED** |
| **Phase 6 Durable Job Suite** (Live Postgres 16, Redis 7, Docker) | `pytest tests/test_phase6_durable_job_execution.py` | **16 / 16 PASSED** |
| **Live Docker Security Runtime Suite** | `pytest tests/test_live_docker_security_runtime.py` | **13 / 13 PASSED** |
| **PostgreSQL 16 Live Integration Suite** | `pytest tests/test_postgresql_integration.py` | **8 / 8 PASSED** |
| **Full Repository Regression Baseline** | Backend (`623` tests), Frontend Vitest (`46` tests), TypeScript (`tsc --noEmit`), Vite Build, Electron (`10` tests), Compose Config | **`621 passed, 2 skipped, 0 failed`** (Backend) / **`46 passed`** (Frontend) / **`10 passed`** (Electron) / **`0` errors** |

---

## 7. Live Versus Mocked Verification Matrix

| Component / Security Control | Live Infrastructure Verified | Mocked / Simulated / Static Elements |
| :--- | :--- | :--- |
| **PostgreSQL `before_commit` Lease-Fencing Race** | **Live PostgreSQL 16.13** (`rm_test_postgres`) with two concurrent sessions (`db_a`, `db_b`) and real Bandit scan / patch verification | Deterministic `pre_commit_hook` pause callback |
| **Worker Crash During Cancellation & Orphan Cleanup** | **Live PostgreSQL 16.13 + Live Docker 29.9.3 (`redmercury-worker:latest`) + Real OS Child Process** | In-process tracker unregistered to simulate abrupt worker crash |
| **Transactional Outbox & Redis Fault Recovery** | **Live PostgreSQL 16.13 + Live Redis 7.4.8 (`rm_test_redis`)** | `_FailingRedis` proxy used only to inject `ConnectionError` during outage steps |
| **Browser Cookie (`HttpOnly`), CSRF & Multi-Tab Rotation** | **Live FastAPI/Uvicorn Server + Live Headless Google Chrome via CDP WebSocket** | None |
| **Nginx Reverse Proxy Security Headers & TLS 1.2/1.3** | **Live `redmercury-frontend:test` & `nginx:1.27-alpine` Containers** | Ephemeral self-signed RSA-2048 X.509 certificate |
| **Git Egress Proxy & `http.curloptResolve` Pinning** | **Static Code Audit + FastAPI `TestClient` + YAML Topology Inspection** | **No live external forward-proxy appliance (`GIT_EGRESS_PROXY_URL`) was provisioned** |
| **GitHub Actions CI Workflow (`.github/workflows/ci.yml`)** | **Local Linux Container (`node:22-alpine`, `python:3.12-slim`) & Host Equivalence** | **Remote GitHub-hosted runner execution not triggered (no `git push` performed)** |

---

## 8. Outstanding Vulnerabilities & Recommended Remediation Priorities

| Priority | Finding ID | Severity | Recommended Action (Upon User Authorization) |
| :---: | :---: | :---: | :--- |
| **1** | **P7B-F02** | **P2** | Record `(hostname, pid, start_time)` in `_runtime_artifacts["child_pids"]` and verify `hostname == socket.gethostname()` and `start_time` before probing/killing PIDs in `reap_and_verify_orphaned_job_resources()`. |
| **2** | **P7B-F01** | **P2** | Clear `session.info.pop("_fenced_job_lease", None)` automatically in `@event.listens_for(Session, "after_rollback")` and `@event.listens_for(Session, "after_commit")`, and support a set of fenced leases per transaction. |
| **3** | **P7B-F03** | **P2** | Add `.with_for_update(skip_locked=True)` on PostgreSQL when selecting pending `JobOutboxEvent` rows in `dispatch_outbox_events()`. |
| **4** | **P7B-F04** | **P2** | Skip local `socket.getaddrinfo()` in `validate_git_url()` when routing through a trusted SSRF-filtering `GIT_EGRESS_PROXY_URL` on an isolated internal network (letting the SSRF-filtering proxy resolve and validate DNS at connection time), and bound total Git clone timeout across branch fallback. |
| **5** | **P7B-F05** | **P3** | Lock the `User` row (`FOR UPDATE`) during the 24-hour daily scan quota check in `reserve_atomic_job_slot()` and stage `AuditEvent` records before `db.commit()` in API endpoints. |
| **6** | **P7B-F06 / F07** | **P3 / INFO** | Preserve `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` on `/api/` location blocks in `nginx/production.conf`, and acquire a PostgreSQL advisory lock in `backend/alembic/env.py` during `alembic upgrade head`. |

---

## 9. Infrastructure Dependencies

1. **SSRF-Filtering Egress Proxy (`GIT_EGRESS_PROXY_URL`):** Mandatory in `production` and `staging` whenever public Git URL cloning is enabled. Must enforce destination IP filtering (blocking RFC1918, loopback, link-local, CGNAT, IPv6 ULA/link-local, and cloud metadata IPs) at connection time.
2. **PostgreSQL 16 & Redis 7:** Required in production for row-level `FOR UPDATE SKIP LOCKED` job claiming, transactional outbox dispatch, and distributed rate limiting.
3. **Production TLS Certificates & Secrets:** `./ssl/redmercury.crt`, `./ssl/redmercury.key`, `SECRET_KEY` ($\ge 32$ chars high entropy), `POSTGRES_PASSWORD`, and `GITHUB_WEBHOOK_SECRET`.

---

## 10. Final Security Acceptance Decision

**CONDITIONALLY ACCEPTED**

### Rationale
1. **Zero P0 or P1 Vulnerabilities:** Core multi-tenant isolation, HttpOnly/CSRF session security, ZIP/local ingestion confinement, Docker sandbox isolation (`--network none`, `--cap-drop ALL`, `--read-only`, `--pids-limit 64`), PostgreSQL `before_commit` lease fencing, and fail-closed cancellation slot retention are verified against live PostgreSQL 16, live Redis 7, live Docker containers, and real headless Chromium.
2. **Conditions for Unconditional Production Acceptance:**
   - Authorize and apply the targeted fixes for **P7B-F01**, **P7B-F02**, **P7B-F03**, and **P7B-F04** identified in this audit.
   - Provision the external SSRF-filtering forward proxy (`GIT_EGRESS_PROXY_URL`) in the staging/production environment.
   - Commit and push the verified working tree to execute the remote GitHub Actions CI release gate.
