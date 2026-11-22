# RED MERCURY — PHASE 2: REPOSITORY INGESTION, ZIP EXTRACTION & SSRF SECURITY HARDENING REPORT

**Date:** 2026-11-21  
**Repository:** `https://github.com/Dhineshkumardhina/Red-Mercury`  
**Branch / Baseline Commit:** `main` @ `b9df7b9`  
**Reference Audits:**  
- [RED_MERCURY_PHASE0_COMPLETE_REPOSITORY_AUDIT.md](RED_MERCURY_PHASE0_COMPLETE_REPOSITORY_AUDIT.md)  
- [RED_MERCURY_PHASE1_SECURITY_REMEDIATION_REPORT.md](RED_MERCURY_PHASE1_SECURITY_REMEDIATION_REPORT.md)  
**Phase 2 Status:** **COMPLETE** (All three target findings `SEC-05`, `SEC-06`, and `SEC-15` remediated and verified with regression tests; deployment-level network egress controls explicitly documented)

---

## 1. Executive Summary

Phase 2 performed targeted security hardening across Red Mercury's repository ingestion, ZIP extraction, Git cloning SSRF defenses, and workspace lifecycle/deletion subsystems — without rebuilding the application, breaking existing ingestion workflows, or weakening any Phase 1 controls.

### Verification Summary
- **Backend (`pytest`):** **526 collected, 506 passed, 0 failed, 20 environment-skipped** (+65 new Phase 2 security regression test cases in `tests/test_phase2_ingestion_ssrf_security.py`).
- **Frontend (`vitest`):** **7 test files, 46 passed, 0 failed** (7.60s).
- **Frontend TypeScript (`tsc --noEmit`):** **Passed (0 errors)**.
- **Electron (`node --test electron/security.test.cjs`):** **10 passed, 0 failed** (134ms).
- **Docker Compose Config (`docker compose -f docker-compose.prod.yml config -q`):** **Passed (exit 0)** with required production env vars (`POSTGRES_PASSWORD`, `SECRET_KEY`). Live container startup and PostgreSQL integration tests could not run because Docker Desktop Linux Engine and PostgreSQL are not running on this host (explicitly disclosed below).

---

## 2. Original Findings & Findings-to-Files Mapping

| Finding ID | Severity | Original Vulnerability | Root Cause | Affected Source Files |
| :--- | :--- | :--- | :--- | :--- |
| **SEC-05** | **HIGH** | Unbounded ZIP extraction (`shutil.copyfileobj`) trusting forged ZIP header sizes; skipped symlinks/oversized files silently instead of rejecting; no duplicate-entry or nested-archive limits; missing partial-extraction cleanup; uncaught `BadZipFile`/`zlib.error` 500s | Header-only pre-validation combined with unbounded stream copy and missing failure cleanup | `backend/app/core/ingestion.py`, `backend/app/core/config.py`, `backend/app/api/v1/endpoints/repositories.py` |
| **SEC-06** | **HIGH** | Invalid Git flag `-c http.resolve=...` silently ignored by Git; `is_ip_blocked()` missed IPv4-mapped IPv6 (`::ffff:...`), 6to4, Teredo, CGNAT (`100.64.0.0/10`), and additional metadata IPs; `validate_git_url()` missed single-label internal hostnames, `.internal`/`.local` suffixes, local filesystem paths, and `ext::` remote helpers; `repositories.py` omitted `allow_private` forwarding and skipped `git_url` validation on `POST /repositories`; worker lacked `internal: true` network isolation | Reliance on non-existent Git config option, incomplete IP/hostname normalization, unsanitized Git subprocess environment, and unrestricted worker bridge network | `backend/app/core/ingestion.py`, `backend/app/core/config.py`, `backend/app/api/v1/endpoints/repositories.py`, `docker-compose.prod.yml`, `.env.example` |
| **SEC-15** | **MEDIUM** | `delete_repository()` called raw `shutil.rmtree(workspace, ignore_errors=True)` with zero containment, symlink, or active-scan checks; `clean_stale_workspaces()` used raw relative `Path(settings.WORKSPACE_ROOT)`, iterated tenant directories (`<root>/<user_id>`) instead of repo directories, compared them against nested `.../source` paths (never matching active scans), and followed symlinks via `glob("**/*")` | Missing canonical containment/ownership verification before recursive deletion and mismatched path granularity in stale-workspace GC | `backend/app/core/workspace_cleanup.py`, `backend/app/api/v1/endpoints/repositories.py` |

---

## 3. Before / After Security Behavior

### 3.1 `SEC-05` — Secure ZIP Extraction
- **Before:** `validate_and_extract_zip()` trusted `member.file_size` headers and extracted via unbounded `shutil.copyfileobj()`, silently skipped symlinks and oversized files, permitted duplicate entries and arbitrary nested archives, left partial files on disk after mid-archive failures, and allowed malformed ZIP exceptions to bubble as HTTP 500.
- **After:**
  - Streams every entry in **64 KiB fixed chunks** (`source_stream.read(65536)`), enforcing **actual bytes written** against `MAX_SINGLE_FILE_BYTES`, `MAX_EXTRACTED_SIZE_BYTES`, and actual expansion ratio against `MAX_COMPRESSION_RATIO` (never trusting archive headers alone).
  - Normalizes backslashes to forward slashes first and rejects `../`, `..\`, absolute paths, Windows drive letters / NTFS ADS (`:`), null bytes, control chars, trailing dots/spaces, and Windows reserved device names.
  - Rejects POSIX symlinks, FIFOs, char/block devices, sockets, and Windows reparse points with `SecurityPolicyViolationError` (`403`).
  - Rejects duplicate normalized file entries (case-insensitive key) and encrypted ZIP entries with `ValidationError` (`422`).
  - Enforces `MAX_NESTED_ARCHIVES` (default `5`) while never extracting excluded archive binaries.
  - Wraps extraction in failure-safe cleanup (`shutil.rmtree(dest_dir)` on any exception) and converts `BadZipFile`/`LargeZipFile`/`zlib.error`/`EOFError`/`RuntimeError` into clean `ValidationError` (`422`).

### 3.2 `SEC-06` — SSRF & Git Ingestion Hardening
- **Before:** `clone_git_repository()` passed invalid `-c http.resolve=...` and `-c http.<url>.resolve=...`, inherited host `GIT_SSH_COMMAND`/`HTTP_PROXY` environment variables, did not enforce post-clone symlink or size quotas, did not terminate process trees on timeout, did not forward `allow_private` from `repositories.py`, did not validate `git_url` on `POST /repositories`, and left `worker` on the non-internal `redmercury_internal` Docker network.
- **After:**
  - **Removed invalid `-c http.resolve`** and `-c http.<url>.resolve`.
  - Hardened `is_ip_blocked()` to unwrap IPv4-mapped IPv6 (`::ffff:x.x.x.x`), 6to4, and Teredo addresses, and explicitly block loopback, RFC1918, link-local, CGNAT (`100.64.0.0/10`), multicast, reserved, unspecified, IPv6 ULA (`fc00::/7`), IPv6 site-local (`fec0::/10`), and cloud metadata IPs (`169.254.169.254`, `169.254.170.2`, `100.100.100.200`, `fd00:ec2::254`).
  - Hardened `validate_git_url()` to reject local paths (`/`, `\`, `C:\`, `./`), Git remote-helper syntax (`ext::`, `fd::`, `::`), non-HTTPS schemes (`file://`, `ssh://`, `git://`, `ftp://`, `http://`), embedded credentials, single-label internal hostnames (`postgres`, `redis`), `.localhost`/`.local`/`.internal`/`.home.arpa` suffixes, metadata hostnames, and any multi-homed DNS record containing a blocked IPv4 or IPv6 address.
  - Added `git_url` validation on `POST /api/v1/repositories` and forwarded `allow_private=settings.ALLOW_PRIVATE_NETWORKS` in `ingest_git_repository()`.
  - Hardened Git subprocess invocation: `shell=False`, explicit `cwd`, valid Git flags (`core.hooksPath=<os.devnull>`, `core.symlinks=false`, `protocol.file.allow=never`, `protocol.allow=never`, `protocol.https.allow=always`, `http.followRedirects=false`, `submodule.recurse=false`, `--no-recurse-submodules`, `--depth 1`, `--single-branch`, `--`), sanitized environment (`GIT_ALLOW_PROTOCOL=https`, `GIT_TERMINAL_PROMPT=0`, `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=<os.devnull>`, stripped `GIT_SSH*`/`HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`), optional valid `-c http.proxy=<GIT_EGRESS_PROXY_URL>` for SSRF-filtering egress proxies, reliable subprocess tree termination (`taskkill /T /F` on Windows, `os.killpg(..., SIGKILL)` on POSIX), post-clone symlink rejection & size/file-count quotas, and guaranteed `dest_dir` cleanup on failure/timeout.
  - Isolated `worker` onto a dedicated `redmercury_worker_isolated` (`internal: true`) network in `docker-compose.prod.yml` so the scanner worker has zero external egress routing.

### 3.3 `SEC-15` — Workspace Cleanup & Deletion Safety
- **Before:** `delete_repository()` blindly executed `shutil.rmtree(workspace, ignore_errors=True)` without containment, symlink, or active-scan validation. `clean_stale_workspaces()` iterated tenant-level directories (`<root>/<user_id>`) against nested `.../source` scan paths, risking deletion of active user repositories, and followed symlinks via `glob("**/*")`.
- **After:**
  - Introduced `validate_workspace_deletion_path()` and `safe_delete_workspace_dir()` enforcing:
    1. Rejection of empty/null-byte/`..` paths and symlinks BEFORE `resolve()`.
    2. Strict containment within `get_workspace_root().resolve()` and (when `owner_id` is supplied) within `<workspace_root>/<safe_owner>` via `Path.is_relative_to()` (immune to `alice` vs `alice2` prefix collisions; refuses deletion of workspace root or tenant root).
    3. Active scan protection (`running`/`pending`/`queued`) before deleting a repository workspace.
    4. Symlink-safe bottom-up deletion (`os.walk(..., topdown=False, followlinks=False)`) that never follows symlinks, idempotent handling of missing directories, and structured `WORKSPACE_PURGED` audit logging.
  - Hardened `clean_stale_workspaces()` to resolve `get_workspace_root()`, inspect repo-level folders (`<root>/<tenant>/<repo>`), protect all active `Repository`, `Scan`, and `VerificationRun` paths via `is_relative_to()`, reject symlinks in both temp and workspace directories, and use symlink-safe deletion.

---

## 4. Modified & Created File Inventory

### Modified Files
- `backend/app/core/config.py` — Added `MAX_NESTED_ARCHIVES` (default `5`) and `GIT_EGRESS_PROXY_URL` (optional SSRF-filtering proxy URL).
- `backend/app/core/ingestion.py` — Hardened `is_ip_blocked()`, `validate_git_url()`, `validate_and_extract_zip()`, and `clone_git_repository()`; added `_is_zip_entry_symlink_or_special()`, `_normalize_and_validate_zip_member_path()`, `_build_sanitized_git_env()`, `_terminate_subprocess_tree()`, `_run_git_command()`, and `_enforce_cloned_directory_limits()`.
- `backend/app/core/workspace_cleanup.py` — Added `validate_workspace_deletion_path()`, `safe_delete_workspace_dir()`, `_safe_rmtree_no_symlinks()`, `_collect_protected_workspace_paths()`, `_is_path_protected()`; hardened `clean_stale_workspaces()`.
- `backend/app/api/v1/endpoints/repositories.py` — Added `validate_git_url()` check to `create_repository()`, forwarded `allow_private` in `ingest_git_repository()`, and replaced raw `shutil.rmtree()` in `delete_repository()` with `safe_delete_workspace_dir()`.
- `docker-compose.prod.yml` — Added `redmercury_worker_isolated` (`internal: true`) network for `worker` + `postgres` and forwarded optional `GIT_EGRESS_PROXY_URL` to `api`.
- `.env.example` — Documented `MAX_NESTED_ARCHIVES` and `GIT_EGRESS_PROXY_URL`.

### Created Files
- `tests/test_phase2_ingestion_ssrf_security.py` — 65 targeted Phase 2 regression test cases covering `SEC-05`, `SEC-06`, and `SEC-15`.
- `RED_MERCURY_PHASE2_INGESTION_SSRF_SECURITY_REPORT.md` — This report.

---

## 5. Test Execution Results & Control Verification Matrix

### 5.1 Actual Commands Executed & Observed Results

| Suite | Command | Collected | Passed | Failed | Skipped | Duration |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Backend (`pytest`)** | `python -m pytest tests/ -q --tb=short` | 526 | **506** | **0** | **20** | 156.48s |
| **Frontend (`vitest`)** | `npm --prefix frontend run test` | 46 | **46** | **0** | **0** | 7.60s |
| **Frontend TypeScript** | `npm --prefix frontend run lint` (`tsc --noEmit`) | — | **Pass** | **0** | — | — |
| **Electron (`node:test`)** | `node --test electron/security.test.cjs` | 10 | **10** | **0** | **0** | 0.13s |
| **Docker Compose Config** | `docker compose -f docker-compose.prod.yml config -q` (with `POSTGRES_PASSWORD` & `SECRET_KEY`) | — | **Pass** | **0** | — | — |

**Disclosed Environment Skips (20 backend tests — NOT claimed as passed):**
- 15 live Docker daemon tests (`test_live_docker_security_runtime.py`, `test_sandbox.py`) — Docker Desktop Linux Engine daemon not running on host.
- 3 live PostgreSQL tests (`test_postgresql_integration.py`) — PostgreSQL service / `TEST_POSTGRES_URL` unavailable on host.
- 1 Semgrep test (`test_scanners.py`) — Semgrep excluded on `win32`.
- 1 OS symlink test (`test_verification_security_hardening.py`) — Windows symlink creation requires administrator privileges.

### 5.2 Control Verification Classification

| Control Category | Verification Level | Evidence |
| :--- | :--- | :--- |
| ZIP chunked byte accounting, forged-header overflow, traversal/Windows/symlink/duplicate/nested-archive/malformed rejection & partial cleanup | **Unit-Tested & API Integration-Tested** | `test_phase2_ingestion_ssrf_security.py` (20 cases) + `test_ingestion.py` (12 cases) |
| Git IPv4/IPv6/IPv4-mapped/CGNAT/metadata blocking, protocol/local-path/remote-helper rejection, `POST /repositories` validation, invalid `http.resolve` removal, sanitized env, timeout tree-kill & cleanup | **Unit-Tested & Mocked-Network Integration-Tested** | `test_phase2_ingestion_ssrf_security.py` (40 cases) + `test_ingestion.py` |
| Workspace deletion confinement, prefix-collision immunity, symlink rejection, cross-tenant `403`, active-scan `422`, stale orphan cleanup | **Unit-Tested & API/DB Integration-Tested** | `test_phase2_ingestion_ssrf_security.py` (5 cases) + `test_production_readiness.py` + `test_authorization.py` |
| Worker `redmercury_worker_isolated` (`internal: true`) network config | **Static Config-Validated (Deployment-Level Runtime Unverified)** | `docker compose -f docker-compose.prod.yml config -q` + `test_sec06_worker_compose_network_is_internal_isolated`; live container runtime unverified (Docker daemon unavailable) |
| Connection-time DNS rebinding immunity for `api` Git cloning | **Deployment-Level Control Required (Not Fully Eliminable in App Layer Alone)** | Requires configuring `GIT_EGRESS_PROXY_URL` pointing to an SSRF-filtering egress proxy (e.g., Smokescreen) or host/cluster egress firewall |

---

## 6. SSRF Threat Model (`SEC-06`)

### Attack Vectors Mitigated in Application Layer
1. **Direct IP & IPv6 Transition Bypasses:** Loopback (`127.0.0.0/8`, `::1`), RFC1918 (`10/8`, `172.16/12`, `192.168/16`), CGNAT (`100.64.0.0/10`), link-local (`169.254/16`, `fe80::/10`), IPv6 ULA (`fc00::/7`), cloud metadata (`169.254.169.254`, `169.254.170.2`, `100.100.100.200`, `fd00:ec2::254`), and IPv4-mapped/6to4/Teredo IPv6 addresses are blocked before `git` is ever spawned.
2. **Protocol Smuggling & Local Cloning:** `file://`, `ssh://`, `git://`, `ftp://`, `http://`, local paths (`/etc/...`, `C:\...`, `./...`), and Git remote helpers (`ext::...`) are rejected in `validate_git_url()` and blocked at Git runtime via `GIT_ALLOW_PROTOCOL=https` and `-c protocol.file.allow=never -c protocol.allow=never -c protocol.https.allow=always`.
3. **HTTP Redirect SSRF:** Blocked via `-c http.followRedirects=false`.
4. **Malicious Git Repo Payloads:** Submodule recursion disabled (`-c submodule.recurse=false --no-recurse-submodules`), hooks disabled (`-c core.hooksPath=<os.devnull>`), symlinks disabled (`-c core.symlinks=false`), `.git` deleted immediately post-clone, and cloned directory validated for symlinks and size/file-count quotas.
5. **Subprocess & Env Injection:** `shell=False`, `--` separator before URL, strict branch regex, stripped `GIT_SSH*`/`HTTP_PROXY*` env vars, and process-tree kill on timeout.

### Residual Threat Requiring Deployment-Level Enforcement
- **Connection-Time DNS Rebinding (TOCTOU):** Because `git` (via libcurl) performs its own DNS lookup after Python's `validate_git_url()` check, an attacker controlling a short-TTL (`TTL=0`) authoritative DNS server could return a public IP to Python and a private/metadata IP to `git` milliseconds later. Previously, `-c http.resolve=...` gave a **false sense of security** because Git ignores that key.
- **Required Production Mitigation:** Route `api` outbound Git traffic through a dedicated SSRF-filtering egress proxy via `GIT_EGRESS_PROXY_URL` (e.g., Stripe Smokescreen or Squid with RFC1918/metadata/CGNAT ACLs) and enforce Kubernetes `NetworkPolicy` / cloud security group egress rules blocking private/link-local/metadata CIDRs from the `api` container.

---

## 7. ZIP Extraction Security Analysis (`SEC-05`)

- **Streaming Byte Accounting:** `validate_and_extract_zip()` reads in 64 KiB chunks and increments `file_bytes_written` and `actual_total_bytes` on every chunk before writing to disk. Even if an attacker forges `ZipInfo.file_size` to `10` bytes, exceeding `MAX_SINGLE_FILE_BYTES`, `MAX_EXTRACTED_SIZE_BYTES`, or `MAX_COMPRESSION_RATIO` aborts extraction immediately and deletes `dest_dir`.
- **Cross-Platform Path Safety:** Normalizing `\` to `/` before segment splitting closes Windows backslash traversal on Linux hosts and rejects `C:\...`, `C:...`, NTFS Alternate Data Streams (`:`), trailing dots/spaces, Windows device names (`CON`, `NUL`, etc.), control characters, and null bytes.
- **Symlink & Duplicate Hygiene:** Symlinks, FIFOs, devices, sockets, and Windows reparse points raise `SecurityPolicyViolationError`. Case-insensitive duplicate path detection prevents file shadowing/overwrite attacks.
- **Cross-Component Consistency:** Local ingestion (`copy_local_directory_safely`), ZIP ingestion (`validate_and_extract_zip`), and Git ingestion (`_enforce_cloned_directory_limits`) now enforce consistent security boundaries: zero symlinks, `MAX_FILE_COUNT`, `MAX_SINGLE_FILE_BYTES`, `MAX_EXTRACTED_SIZE_BYTES`, `Path.is_relative_to()` workspace confinement, and failure-safe cleanup.

---

## 8. Workspace Deletion Security Analysis (`SEC-15`)

- **Confinement & Ownership:** `validate_workspace_deletion_path()` checks for `..` and symlinks BEFORE `resolve()`, then requires `resolved_target.is_relative_to(workspace_root)` and (for tenant deletions) `resolved_target.is_relative_to(workspace_root / safe_owner)`, while explicitly rejecting deletion of `workspace_root` or the tenant root itself.
- **TOCTOU & Symlink Race Reduction:** `_safe_rmtree_no_symlinks()` walks bottom-up with `os.walk(..., topdown=False, followlinks=False)`, verifies boundary containment on every directory, and unlinks symlinks directly without dereferencing them.
- **Active Job Protection:** `delete_repository()` refuses deletion (`422`) when a `Scan` is `running`/`pending`/`queued`. `clean_stale_workspaces()` protects all active `Repository`, `Scan`, and `VerificationRun` paths using bidirectional `is_relative_to()` checks at repo-directory granularity (`<root>/<tenant>/<repo>`).

---

## 9. Remaining Risks & Deployment-Level Requirements

1. **Network-Level SSRF Egress Proxy (`api` service):** Operators deploying in cloud/VPC environments MUST configure `GIT_EGRESS_PROXY_URL` to an SSRF-filtering proxy (blocking RFC1918, loopback, link-local, CGNAT, IMDS `169.254.169.254`) and enforce host/cluster egress firewall rules.
2. **Live Docker & PostgreSQL Verification:** The 15 Docker sandbox tests and 3 PostgreSQL integration tests remain skipped on this Windows host due to missing local daemons; they MUST be executed in a Linux CI environment with Docker and PostgreSQL 16 prior to staging/production promotion.
3. **Symlink Race Window on Non-`openat` Filesystems:** While `os.walk(..., followlinks=False)` and pre-resolve symlink checks dramatically reduce symlink TOCTOU risk, full OS-level `O_NOFOLLOW`/`dir_fd` deletion is POSIX-specific and should be evaluated if Red Mercury runs on multi-writer shared NFS volumes.

---

## 10. Phase 3 Recommendations

1. **Rate Limiting, Session & Staging Parity (`SEC-07`, `SEC-16`, `SEC-17`):** Move rate limiting to Redis; fix `X-Forwarded-For` rightmost untrusted IP parsing; validate tokens before revoking in `/auth/logout` and add CSRF protection on `/auth/logout`; apply production security gates to `APP_ENV=staging`; plan `localStorage` → `HttpOnly` cookie session migration.
2. **Core Pipeline Bug Fixes & Cross-Tenant FK Checks (`SEC-12`, `SEC-14`, `REL-02`):** Verify GitHub webhook HMAC before recording `WebhookDelivery`; add cross-tenant FK ownership checks on `POST /findings` and `POST /evidence`; fix `verification/service.py` `NormalizedFinding` attributes, `validation/ai_assistant.py` Gemini client calls, `integrations/github/service.py` `Path` import, and `SARIF` findings export.
3. **Nginx & Supply Chain Hardening (`SEC-13`, `SEC-20`):** Fix `nginx/frontend.conf` static asset header inheritance and CSP; verify Gitleaks SHA-256 in `Dockerfile.worker` and CI; pin Docker image digests and GitHub Actions SHAs; configure `TRUSTED_PROXIES` for Docker bridge subnets.
