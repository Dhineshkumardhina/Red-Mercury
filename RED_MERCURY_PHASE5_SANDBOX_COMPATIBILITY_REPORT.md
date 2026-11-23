# RED MERCURY — PHASE 5
# CROSS-PLATFORM SECURE DOCKER VERIFICATION REPORT

**Organization:** Xerova Digital Solutions  
**Project:** Red Mercury  
**Target Platforms:** Windows 10/11 (`x64`, Docker Desktop WSL2), macOS Intel (`x64`), macOS Apple Silicon (`arm64`)  

---

## 1. Executive Summary

Phase 5 integrated Red Mercury's hardened Docker verification pipeline across Windows and macOS desktop environments while preserving every mandatory container isolation control (`--network=none`, `--cap-drop=ALL`, `--read-only`, `--pids-limit<=50`, `--memory<=512m`, `--cpus<=1.0`, `--user=10002:10002`, `--security-opt=no-new-privileges:true`) and keeping the Electron renderer completely isolated from Docker sockets and CLI execution.

---

## 2. Requirements Implementation Matrix

| # | Requirement | Implemented Control | Location |
|---|---|---|---|
| 1 | **Detect Docker installation** | Resolves `PATH` (`shutil.which`) plus `%LOCALAPPDATA%\Programs\DockerDesktop\resources\bin\docker.exe`, `C:\Program Files\Docker\...`, `/opt/homebrew/bin/docker`, `/usr/local/bin/docker`, `/Applications/Docker.app/...` and captures `docker --version` | [`resolve_docker_binary`](backend/app/verification/sandbox.py), [`detect_docker_installation`](backend/app/verification/sandbox.py) |
| 2 | **Detect Docker daemon availability** | Probes `ServerVersion`, `OSType`, `Architecture`, `OperatingSystem`, and `Driver`; classifies backend (`wsl2`, `docker_desktop_mac`, `linux_native`) and rejects non-Linux container engines (`OSType != linux`) | [`detect_docker_daemon`](backend/app/verification/sandbox.py) |
| 3 | **Detect supported architecture** | Normalizes `x86_64`/`AMD64` -> `amd64` and `aarch64`/`arm64` -> `arm64`, validating against `{"amd64", "arm64"}` | [`detect_supported_architecture`](backend/app/verification/sandbox.py) |
| 4 | **Check worker image availability** | Inspects `redmercury-worker:latest` JSON metadata (`Os == linux`, supported arch, non-root `User` in `10002:10002` / `redmercury-sandbox`) | [`inspect_worker_image`](backend/app/verification/sandbox.py) |
| 5 | **Build/retrieve approved worker image** | Builds exclusively from Red Mercury's approved multi-arch `Dockerfile.worker` (also staged alongside packaged desktop backend) via scoped `POST /api/v1/system/sandbox/build-worker-image` | [`build_approved_worker_image`](backend/app/verification/sandbox.py), [`Dockerfile.worker`](Dockerfile.worker), [`prepare_desktop_bundle.py`](scripts/prepare_desktop_bundle.py) |
| 6 | **Validate image digest** | Verifies image `Id` / `RepoDigests` against `SANDBOX_APPROVED_IMAGE_DIGEST` or locally pinned `<data_dir>/sandbox_approved_image.json`; rejects mismatches fail-closed | [`inspect_worker_image`](backend/app/verification/sandbox.py), [`config.py`](backend/app/core/config.py) |
| 7 | **Verify sandbox configuration** | Enforces all 8 invariants programmatically before container spawn; refuses launch (`code=-1`) if any flag is weakened | [`verify_sandbox_configuration`](backend/app/verification/sandbox.py) |
| 8 | **Execute verification** | Mounts normalized isolated workspace (`format_docker_volume_mount_path`), runs AST safety inspection + `docker run` with stripped host environment (`get_sanitized_runner_env`) | [`execute_in_container`](backend/app/verification/sandbox.py), [`run_pytest_in_workspace`](backend/app/verification/runner.py) |
| 9 | **Collect results** | Maps passed/failed/timeout/error outcomes cleanly; daemon/sandbox faults force `INCONCLUSIVE` or `FAILED_VERIFICATION`, never `"passed"` | [`execute_fix_verification`](backend/app/verification/service.py) |
| 10 | **Clean up temporary resources** | Issues `docker kill` + `docker rm -f` + host process-tree termination and removes disposable temporary workspaces in `finally:` blocks | [`terminate_process_tree`](backend/app/verification/sandbox.py), [`workspace.py`](backend/app/verification/workspace.py) |

---

## 3. Security Invariants & Docker Access Architecture

- **No Direct Renderer / Project Control:** The Electron preload API ([`electron/preload.cjs`](electron/preload.cjs)) exposes zero Docker IPC channels. The React frontend interacts strictly with authenticated FastAPI endpoints (`GET /api/v1/system/sandbox/status` and `POST /api/v1/system/sandbox/build-worker-image`) that accept **no user-supplied Dockerfiles, image tags, flags, or mount paths**.
- **Enforced Runtime Container Flags:**
  - `--network=none`
  - `--cap-drop=ALL`
  - `--read-only` (paired with scoped `--tmpfs=/tmp:rw,noexec,nosuid,size=64m`)
  - `--pids-limit=50` (rejected if `<= 0` or `> 50`)
  - `--memory=512m` + `--memory-swap=512m` (rejected if `> 512 MiB`)
  - `--cpus=1.0` (rejected if `<= 0` or `> 1.0`)
  - `--user=10002:10002` (rejected if root or mismatch)
  - `--security-opt=no-new-privileges:true`
- **Failure Handling:** When Docker Desktop is stopped, absent, using Windows-native containers instead of WSL2 Linux containers, or missing/tampered worker image digest, [`run_isolated_verification_command()`](backend/app/verification/sandbox.py) fails closed (`sandbox_allow_host_fallback == False` in `APP_ENV=desktop`), returning `error` -> `INCONCLUSIVE` without ever passing unexecuted verification checks, while static/secret/SCA scanning continues functioning normally.

---

## 4. Platform Compatibility Details

### 4.1 Windows 10/11 (`x64`, Docker Desktop WSL2)
- **CLI Discovery:** Added per-user `%LOCALAPPDATA%\Programs\DockerDesktop\resources\bin\docker.exe` lookup alongside `C:\Program Files\Docker\Docker\resources\bin\docker.exe`, verified on this workstation (`Docker version 29.9.3, build 5457199`).
- **Volume Mount Paths:** `format_docker_volume_mount_path()` resolves workspace temp paths, rejects UNC network paths (`\\server\share`), and formats forward-slash drive paths (`C:/Users/...:/workspace:rw`) compatible with Docker Desktop WSL2.
- **Permissions:** Skips POSIX ACL setup cleanly while enforcing strict temp-root confinement and secret stripping in `get_sanitized_runner_env()`.

### 4.2 macOS Intel (`x64`) and Apple Silicon (`arm64`)
- **CLI Discovery:** Falls back cleanly beyond Finder's minimal GUI `PATH` to `/opt/homebrew/bin/docker` (Apple Silicon), `/usr/local/bin/docker` (Intel), and `/Applications/Docker.app/Contents/Resources/bin/docker`.
- **Multi-Arch Worker Image (`Dockerfile.worker`):** Updated Gitleaks installation to use `ARG TARGETARCH` selecting SHA-256 verified binaries for both `amd64` (`6298c9235dfc9278c14b28afd9b7fa4e6f4a289cb1974bd27949fc1e9122bdee`) and `arm64` (`4df25683f95b9e1dbb8cc71dac74d10067b8aba221e7f991e01cafa05bcbd030`).
- **macOS Volume Mounts & Permissions:** `Path.resolve()` normalizes `/var` -> `/private/var` and `/tmp` -> `/private/tmp` for Docker Desktop VirtioFS / gRPC-FUSE sharing, and `ensure_sandbox_readable_workspace()` enforces `0o700` / `0o600` owner-only permissions on Darwin without attempting Linux `xattr` / `setfacl`.

---

## 5. Actual Test Results by Platform

### 5.1 Windows 10/11 (`x64`) — Observed Locally
1. **Live Host Docker Diagnostic Probe (`python -c "from app.verification.sandbox import get_sandbox_diagnostics; ..."`):**
   - `installation.installed`: `true` (`C:\Users\Dhina\AppData\Local\Programs\DockerDesktop\resources\bin\docker.EXE`, `Docker version 29.9.3, build 5457199`)
   - `architecture`: `host_platform: "Windows"`, `daemon_architecture: "amd64"`, `supported: true`
   - `daemon.available`: `false` — Docker Desktop Linux engine pipe (`npipe:////./pipe/dockerDesktopLinuxEngine`) was **not running** on this workstation at test time (`ready: false`, `fail_closed: true`).
2. **Backend Phase 5, Sandbox & Cross-Phase Regression Suites:**
   - Command: `python -m pytest tests/test_phase5_cross_platform_sandbox.py tests/test_sandbox.py tests/test_verification_security_hardening.py tests/test_phase4_local_services.py tests/test_phase3_desktop_packaging.py tests/test_phase2_desktop_mode.py -v`
   - Result: **67 passed, 3 skipped in 11.05s**
   - *Skipped tests:* `test_real_docker_container_isolation` and `test_live_docker_oom_and_fork_bomb_bounded` (skipped because Docker Desktop WSL2 engine was stopped on host), and `test_adversarial_workspace_symlink_escape_skipped` (POSIX/Linux host check).
   - Verified fail-closed behavior in desktop mode when Docker is unavailable: `run_pytest_in_workspace()` returned `status="error"` (`INCONCLUSIVE`), never `"passed"`.
3. **Electron & Frontend Suites (After Final Edits):**
   - `node --test electron/security.test.cjs`: **15/15 passed** (`626.6ms`)
   - `npm --prefix frontend run lint` (`tsc --noEmit`): **0 errors**
   - `npm --prefix frontend run test` (`vitest run`): **7/7 files, 46/46 passed**
   - `npm run build:desktop` (`vite build`): **Built cleanly (`4.12s`)**

### 5.2 macOS Intel (`x64`) & Apple Silicon (`arm64`) — Observed & Pending Hardware Status
1. **Validated on Windows Host via Simulated Darwin/Daemon Unit Tests:**
   - `test_detect_docker_installation_supports_windows_appdata_and_macos_paths`: **PASSED** (verifies `/Applications/Docker.app/Contents/Resources/bin/docker` and `/opt/homebrew/bin/docker` resolution)
   - `test_detect_docker_daemon_and_architecture_windows_wsl2_and_macos`: **PASSED** (verifies `Darwin` + `arm64` / `aarch64` daemon classification)
   - `test_validate_worker_image_digest_and_user_enforcement`: **PASSED** (verifies `arm64` Linux image inspection, non-root `10002:10002` enforcement, and SHA-256 digest mismatch rejection)
   - `test_dockerfile_worker_supports_multi_arch_amd64_and_arm64`: **PASSED** (verifies `ARG TARGETARCH` and pinned SHA-256 checksums for both `amd64` and `arm64`)
   - `test_darwin_workspace_permissions_enforces_owner_only_without_acl`: **PASSED** (verifies `0o700` / `0o600` owner-only isolation under `platform.system() == "Darwin"`)
2. **Remaining Hardware Gap:**
   - **Live container execution (`docker build` + `docker run` with `--network=none`, `--read-only`, `--cap-drop=ALL`, `--user=10002:10002`) has NOT yet been executed on physical macOS Intel (`x64`) or Apple Silicon (`arm64`) hardware or macOS runners with Docker Desktop running**, nor with WSL2 daemon started live on Windows. Full end-to-end live container smoke tests should be executed on both started Windows WSL2 Docker Desktop and physical macOS Intel/ARM64 hosts.

---

## 6. Git Status
No files were staged, committed, or pushed (`git status --short` verified).
