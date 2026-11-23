# RED MERCURY — PHASE 1: CROSS-PLATFORM DESKTOP ARCHITECTURE AUDIT

**Project:** Red Mercury — Enterprise Application Security & Automated Fix Verification Engine  
**Organization:** Xerova Digital Solutions  
**Repository:** `https://github.com/Dhineshkumardhina/Red-Mercury`  
**Audited Commit (`HEAD`):** `c1fa7b1` (`fix(ci): restrict Linux Chromium fallback to GitHub Actions and fix POSIX ACL test spy`)  
**Target Platforms:** Windows 10/11 (`x64`) & macOS (Intel `x64` + Apple Silicon `arm64`)  
**Target Monthly Infrastructure Cost:** ₹0  
**Audit Date:** `2026-11-23`  
**Audit Mode:** Strictly **READ-ONLY** inspection (zero source edits, zero package installs, zero DB mutations, zero Git operations, zero cloud provisioning).

---

## Executive Decision: **`CONDITIONAL GO`**

Red Mercury can be transformed into a standalone, zero-infrastructure-cost (₹0/month) cross-platform desktop security IDE (comparable in polish and self-contained execution to Google Antigravity IDE) **by extending the existing Electron, React, and FastAPI implementation—without rebuilding or redesigning the product**.

However, **immediate distribution is blocked** until concrete packaging, runtime-bundling, macOS lifecycle/ACL compatibility, worker-process orchestration, and `userData` persistence gaps identified in this audit are resolved in Phases 2+.

---

## 1. Existing Architecture

Red Mercury currently operates as a hybrid **web/cloud-container stack** with an **early-stage Windows-oriented Electron wrapper**:

| Layer | Technology & Entrypoints | Current Behavior & Role |
| :--- | :--- | :--- |
| **Desktop Shell** | Electron `45.0.0`, `electron-builder` `26.15.3` ([`package.json`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/package.json), [`electron/main.cjs`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/electron/main.cjs), [`electron/preload.cjs`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/electron/preload.cjs), [`electron/security.cjs`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/electron/security.cjs)) | Launches splash `BrowserWindow`, spawns `python -m uvicorn app.main:app` on `127.0.0.1:8001`, starts an ephemeral-port static HTTP + `/api/` reverse-proxy server (`127.0.0.1:0`), and loads the React SPA in a sandboxed `BrowserWindow`. |
| **Frontend UI** | React `19.0.0`, TypeScript `5.7.3`, Vite `6.2.0`, Tailwind CSS `4.0.9`, React Router `7.2.0` ([`frontend/package.json`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/frontend/package.json), [`frontend/src/App.tsx`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/frontend/src/App.tsx)) | Single-page AppSec console covering Dashboard, Repositories (ZIP upload, local folder, HTTPS Git clone), Findings, Fix Verification, Patch Analyzer, Evidence Center, and Settings. |
| **Backend API** | FastAPI `>=0.115.0`, Uvicorn, SQLAlchemy `2.0+`, Alembic `0001`–`0014` ([`backend/app/main.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/main.py), [`backend/app/core/config.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/config.py)) | REST API (`/api/v1/*`), HttpOnly JWT + rotating refresh cookies + CSRF double-submit protection, durable job/outbox state machine, scanner orchestration, and offline-capable deterministic AI Security Analyst fallback. |
| **Worker & Sandboxing** | [`backend/app/scanner/worker.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/scanner/worker.py), [`backend/app/verification/sandbox.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/verification/sandbox.py) | Durable background consumer (`DurableJob`) + fail-closed Docker verification runner spawning ephemeral `--network=none --cap-drop=ALL --read-only --user=10002:10002` `redmercury-worker:latest` containers. |
| **Database & Cache** | SQLite WAL (dev) / PostgreSQL 16 (prod), Redis 7 (optional) ([`backend/app/db/session.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/db/session.py), [`docker-compose.prod.yml`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/docker-compose.prod.yml)) | SQLite works in dev/local mode with WAL pragmas; Redis is optional (falls back to `InMemoryRateLimiter` and DB-polled durable jobs). |
| **Launch Scripts** | [`Launch-Red-Mercury-Desktop.ps1`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/Launch-Red-Mercury-Desktop.ps1), [`Launch-Red-Mercury-Desktop.bat`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/Launch-Red-Mercury-Desktop.bat) | Developer-machine launchers requiring pre-installed `python` and `node` in system `PATH`. |

### Frontend Feature & Browser-Assumption Audit
Inspected [`frontend/src/main.tsx`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/frontend/src/main.tsx), [`frontend/src/App.tsx`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/frontend/src/App.tsx), [`frontend/src/services/api.ts`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/frontend/src/services/api.ts), [`frontend/src/context/AuthContext.tsx`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/frontend/src/context/AuthContext.tsx), and all primary screens/modals:

1. **Routing & Hard Reload Bug:** [`main.tsx`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/frontend/src/main.tsx#L6-L10) switches to `HashRouter` when `window.electronAPI?.isElectron` is truthy. However, [`AiSecurityAnalyzerScreen.tsx`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/frontend/src/components/analyzer/AiSecurityAnalyzerScreen.tsx#L313) executes `window.location.href = '/verification'`, bypassing `HashRouter`, forcing a full Electron browser reload (and failing completely under `file://`). It must use `useNavigate()`.
2. **Hardcoded Backend Port & Cross-Origin Bypass:** [`api.ts`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/frontend/src/services/api.ts#L383-L390) returns `'http://127.0.0.1:8001'` whenever `window.electronAPI?.isElectron` is true, bypassing the same-origin `/api/` reverse proxy in [`electron/main.cjs`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/electron/main.cjs#L283-L308). If port `8001` is dynamically reassigned (recommended) or busy, the frontend fails. Also [`api.ts`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/frontend/src/services/api.ts#L452-L454) enforces a **20-second `AbortController` timeout** on every request, which aborts synchronous scans/verifications.
3. **External Google Fonts Blocked by CSP & Offline Mode:** [`frontend/index.html`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/frontend/index.html#L12-L15) fetches `Geist`, `Geist Mono`, `Inter`, and `Material Symbols Outlined` from `https://fonts.googleapis.com` / `fonts.gstatic.com`. Electron's CSP ([`main.cjs`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/electron/main.cjs#L337)) permits only `style-src 'self' 'unsafe-inline'; font-src 'self' data:`. While `material-symbols-outlined.woff2` is locally bundled in `frontend/public/fonts/`, `Geist`, `Geist Mono`, and `Inter` are not bundled locally.
4. **Report Exports & Legacy Branding:** [`ExportModal.tsx`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/frontend/src/components/modals/ExportModal.tsx#L124-L132) and [`EvidencePage.tsx`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/frontend/src/pages/EvidencePage.tsx#L70-L78) trigger browser `<a download>` via `URL.createObjectURL(blob)` instead of a native OS Save dialog (`dialog.showSaveDialog` via IPC) or Electron `will-download` management. `ExportModal.tsx:87` also contains a stale header (`REPO SHIELD AI — SECURITY AUDIT REPORT`).
5. **Ephemeral Settings & Audit History:** [`SettingsPage.tsx`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/frontend/src/pages/SettingsPage.tsx#L8-L39) stores governance toggles (`strictAstTaint`, `zeroSecrets`, `autoMergeSafe`, `notifyOnCritical`, `sandboxTimeout`) in component `useState` only—clicking **Save Settings** does not persist to backend or disk. Additionally, while backend [`audit.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/audit.py) persists `AuditEvent` rows to the database, [`api/v1/router.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/api/v1/router.py) has no dedicated `/audit-events` query endpoint for an Audit History UI view (only verification runs and evidence records are queryable).
6. **Cloudflare Vite Plugin in Desktop Builds:** [`frontend/vite.config.ts`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/frontend/vite.config.ts#L10) runs `@cloudflare/vite-plugin` (`cloudflare()`) during `npm run build`, which is unnecessary for Electron desktop bundles and should be gated behind a target flag (e.g., `VITE_TARGET=desktop`).

---

## 2. Existing Electron Implementation Status

**Verdict: NOT Production-Ready** (strong security baseline in `security.cjs`, but broken for standalone packaged distribution).

### What Is Already Strong
- **Renderer Hardening ([`main.cjs`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/electron/main.cjs#L364-L370), [`preload.cjs`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/electron/preload.cjs)):** `nodeIntegration: false`, `contextIsolation: true`, `sandbox: true`, `webSecurity: true`, minimal `contextBridge` API (`isElectron`, `selectDirectory`, `getAppInfo`, `checkBackend`, `openExternal`).
- **IPC & Navigation Guards ([`main.cjs`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/electron/main.cjs#L38-L43), [`security.cjs`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/electron/security.cjs)):** `assertTrustedIpcSender(event)` validates `event.senderFrame.url` against `getTrustedAppOrigins()`; `will-navigate` blocks external navigation; `setWindowOpenHandler` enforces `isSafeExternalUrl` (`http:`/`https:` only); `resolveStaticAssetPath` blocks traversal, double-encoding, null bytes, and symlink escapes; `spawn` uses `shell: false`.
- **Security Test Suite ([`electron/security.test.cjs`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/electron/security.test.cjs)):** Verified `10/10` tests passing (`node --test electron/security.test.cjs`, 240.8ms) covering `SEC-04` and `SEC-10`.

### Critical Electron Gaps Blocking Production
1. **Broken ASAR Packaging Layout ([`package.json`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/package.json#L37-L50), [`main.cjs`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/electron/main.cjs#L213-L217)):**
   - `electron-builder` defaults to `asar: true`, packing `frontend/dist`, `backend`, and `build` into `resources/app.asar`.
   - `main.cjs` resolves `path.join(process.resourcesPath, 'app')`—which does not exist as a directory when `asar: true`! Moreover, Python (`uvicorn`) cannot execute `backend/app` from inside an `.asar` archive.
   - `build.files` omits `bin/**/*` (so `bin/gitleaks.exe` is missing from packaged builds) and fails to exclude `backend/data`, `backend/__pycache__`, `backend/.pytest_cache`, and `*.db` artifacts.
2. **No Bundled Python Runtime:** `detectPythonExecutable()` in [`security.cjs`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/electron/security.cjs#L57-L75) only checks `rootDir/.venv` / `rootDir/venv` and then falls back to `python` / `python3` on system `PATH`. Packaged end-user installations without Python or project `.venv` fail silently (`startBackend()` catches/logs error, `waitForBackend()` times out after 21s, UI loads into `CONNECTION_REFUSED`).
3. **macOS Dock Reopen Bug ([`main.cjs`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/electron/main.cjs#L489-L505)):** `window-all-closed` invokes `terminateBackend()` **before** `if (process.platform !== 'darwin') app.quit()`. On macOS, closing the window keeps the app in the Dock while killing `backendProcess` and `uiServer`; clicking the Dock icon fires `activate` -> `createMainWindow()`, reopening the UI with a dead backend.
4. **No Worker Process Supervision or Crash Recovery:** Electron spawns only `uvicorn`, not `python -m app.scanner.worker`, and has no restart/error-dialog policy if the backend crashes or fails startup.
5. **Fixed Port `8001` & Blind Service Adoption ([`main.cjs`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/electron/main.cjs#L22,L204-L209)):** If any service responds `200` on `127.0.0.1:8001/api/v1/health`, Electron adopts it instead of managing an isolated instance-owned process on an ephemeral port (`127.0.0.1:0` or dynamically probed free port).

---

## 3. Windows Compatibility Assessment (Windows 10/11 `x64`)

| Area | Current Status | Findings & Required Actions |
| :--- | :--- | :--- |
| **Electron Packaging** | Partial | [`package.json`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/package.json#L51-L74) configures `nsis` (`oneClick: false`, `allowToChangeInstallationDirectory: true`, shortcuts) and `portable` for `x64` with `build/icon.ico`. Must switch backend/binaries/runtime to `extraResources` and exclude dev artifacts. |
| **Native Python Deps** | Compatible (except Semgrep) | `fastapi`, `uvicorn[standard]`, `pydantic`, `sqlalchemy`, `alembic`, `psycopg[binary]`, `pyjwt`, `bcrypt`, `cryptography`, `redis`, `bandit`, `pip-audit`, `httpx` ship `win_amd64` wheels. **`semgrep` is excluded on Windows** (`sys_platform != "win32"` in [`backend/requirements.txt`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/requirements.txt#L24)) and returns `TOOL_NOT_INSTALLED` unless routed through Docker/WSL2. |
| **Local Binaries (`bin/`)** | Present, Unpackaged | `bin/gitleaks.exe` (`v8.18.2`, 7.2 MB) exists in [`bin/`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/bin) and [`resolve_tool_binary`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/scanner/base.py#L56-L81) searches `<project_root>/bin`. Must be placed in `resources/bin/win32-x64/gitleaks.exe` via `extraResources` and resolved via env/path in packaged mode. |
| **Process Management** | Compatible | [`security.cjs`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/electron/security.cjs#L227-L242) and [`sandbox.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/verification/sandbox.py#L132-L140) use `taskkill /pid <pid> /T /F` + `CREATE_NEW_PROCESS_GROUP`. Note: Electron should ensure backend/worker launch with `windowsHide: true` to avoid flashing console windows. |
| **Docker Desktop Integration** | Compatible (with WSL2 path caveat) | [`sandbox.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/verification/sandbox.py#L166) normalizes `\` to `/` for `-v <ws>:/workspace:rw` and [`workspace.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/verification/workspace.py#L422) skips POSIX ACLs on Windows. Works with Docker Desktop WSL2 backend when temp workspaces reside under shared Windows user drives (`%LOCALAPPDATA%\Temp`). |
| **Filesystem Permissions & Installer** | **Broken in Packaged Mode** | Default `DATABASE_URL="sqlite:///./redmercury.db"` and `WORKSPACE_ROOT="data/workspaces"` write inside the install directory (`C:\Program Files\Red Mercury\...`), which fails with `PermissionError` for standard users. Must relocate all mutable state to `%APPDATA%\Red Mercury`. |
| **Code Signing** | Missing | Unsigned NSIS/portable `.exe` triggers Windows Defender SmartScreen warnings. Budget-dependent (₹0 target vs OV/EV Authenticode cert or Azure Trusted Signing). |

---

## 4. macOS Compatibility Assessment (Intel `x64` & Apple Silicon `arm64`)

| Area | Current Status | Findings & Required Actions |
| :--- | :--- | :--- |
| **Electron Packaging** | **Missing** | [`package.json`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/package.json#L37-L75) has **no `mac` or `dmg` config**, no `.icns` icon (only `build/icon.ico` and `build/icon.png`), and no `entitlements.mac.plist`. Must configure dual-arch (`x64` + `arm64`) or universal builds with arch-specific Python + binary resources. |
| **Fix Verification Workspace ACLs** | **CRITICAL BLOCKER** | [`workspace.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/verification/workspace.py#L365-L423) skips `Windows` only, then attempts Linux `os.setxattr("system.posix_acl_access")` or `setfacl` on `Darwin`. Neither exists on macOS, causing **every verification run (`create_verification_workspace` & `execute_in_container`) to fail with `PermissionError`**. Furthermore, Docker Desktop on macOS uses VirtioFS/gRPC-FUSE in a Linux VM—container `--user 10002:10002` against `0o700` macOS UID-`501` mounts causes `EACCES` inside the VM unless UID mapping or VirtioFS-compatible permissions/container UID alignment is handled safely. |
| **macOS GUI `PATH` & Docker Discovery** | **Broken when launched from Finder** | Apps launched from `/Applications` on macOS do not inherit shell `$PATH` (`~/.zshrc`). `docker` (`/usr/local/bin/docker`, `/opt/homebrew/bin/docker`, `/Applications/Docker.app/Contents/Resources/bin/docker`) and `git` must be explicitly probed across standard macOS binary paths. |
| **Native Python & Scanners** | Better than Windows | `semgrep` provides macOS `arm64` and `x86_64` wheels (`sys_platform != "win32"`). However, `bin/` currently has only `gitleaks.exe`—macOS requires `gitleaks` `darwin_amd64` and `darwin_arm64` binaries with SHA-256 verification. |
| **POSIX Process Termination** | Incomplete | [`security.cjs`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/electron/security.cjs#L244-L249) sends `SIGTERM` only to the direct Python PID, not its process group (`detached: true` + `process.kill(-pid, 'SIGTERM')` with `SIGKILL` escalation), risking orphaned Uvicorn/scanner subprocesses. |
| **macOS Permissions (TCC)** | Needs UX Handling | Accessing user project folders in `~/Desktop`, `~/Documents`, `~/Downloads`, or external volumes triggers macOS TCC prompts. Using Electron's native `dialog.showOpenDialog` grants user-selected access cleanly; background rescans of those folders should handle TCC `EPERM` gracefully. |
| **Gatekeeper, Signing & Notarization** | Missing (Cost Constraint) | Unsigned `.app`/`.dmg` downloads trigger Gatekeeper quarantine blocks on macOS (`"cannot be opened because the developer cannot be verified"`). Production public distribution requires Apple Developer ID signing (`$99/yr`), Hardened Runtime (`com.apple.security.cs.allow-unsigned-executable-memory` / `disable-library-validation` if loading Python C-extensions), and `notarytool` stapling. |

---

## 5. Backend Packaging Strategy

**Recommendation:** Bundle an **isolated, arch-specific relocatable Python 3.11+ runtime** (via `python-build-standalone` + pre-installed wheels into a clean site-packages directory, **or** PyInstaller `--onedir` binaries for `redmercury-api` and `redmercury-worker`) inside `electron-builder` `extraResources`.

### Why Relocatable `python-build-standalone` (Recommended Primary) vs PyInstaller
- **Why `python-build-standalone` `--onedir` venv is preferred:**
  1. Preserves existing dynamic imports (`alembic` migrations `0001`–`0014`, `uvicorn`, `bandit` plugins, `pip_audit`, `semgrep` on macOS, `sys.executable -m bandit` / `sys.executable -m pip_audit` subprocess invocations in [`bandit.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/scanner/bandit.py#L66) and [`pip_audit.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/scanner/pip_audit.py#L38)) **without** breaking `sys.executable` subprocess calls or hidden-import hooks.
  2. Allows spawning **two cleanly decoupled managed processes** from one bundled runtime:
     - **Process 1 (`api`):** `python -m uvicorn app.main:app --app-dir <resources>/backend --host 127.0.0.1 --port <free_port>`
     - **Process 2 (`worker`):** `python -m app.scanner.worker --interval 1.0 --concurrency 2`
  3. Avoids false-positive Windows Defender / macOS Gatekeeper heuristics common with single-file PyInstaller bootloaders.

### Required Backend Runtime & Lifecycle Changes
1. **Dedicated `APP_ENV="desktop"` Profile ([`config.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/config.py)):**
   - Currently `APP_ENV="production"` (`is_strict_env`) forbids SQLite, requires PostgreSQL, sets `cookie_secure=True`, disables `/docs`, and disables `_drain_local_auto_job_if_eligible()`.
   - Introduce `APP_ENV="desktop"` (`is_desktop_env`):
     - Permits local SQLite WAL in `REDMERCURY_DATA_DIR`.
     - Keeps CSRF protection, rate limiting, `SECRET_KEY >= 32 chars` (auto-generated by Electron main and stored via `safeStorage` / `0600` key file in `userData`), `DOCS_ENABLED=false`, `OFFLINE_MODE=true` by default, and **blocks `dev@xerova.com` seed login** (preventing dev backdoors in shipped binaries).
     - Enables `ALLOW_LOCAL_INGESTION` strictly for paths explicitly allowlisted/selected by the user via Electron main-process `dialog.showOpenDialog` (or dynamically registered in an IPC-authenticated session allowlist).
2. **Decouple Long-Running Jobs from HTTP Handlers:**
   - Electron main process should supervise **both** FastAPI (`api`) and `app.scanner.worker` (`worker`) with `JOB_DISPATCH_MODE="queue_only"` (DB-backed durable queue, no Redis needed).
   - Update [`verification.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/api/v1/endpoints/verification.py#L142-L155) and frontend [`VerificationPage.tsx`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/frontend/src/pages/VerificationPage.tsx) / `NewVerificationModal.tsx` to enqueue (`?async=true`) and poll status just like [`ScanModal.tsx`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/frontend/src/components/modals/ScanModal.tsx#L125-L140), preventing 20s `AbortController` timeouts and Uvicorn single-worker stalls.
3. **Writable Data Directory Injection:**
   - Electron passes `REDMERCURY_DATA_DIR=<app.getPath('userData')>/data`, `DATABASE_URL=sqlite:///<userData>/data/redmercury.db`, `WORKSPACE_ROOT=<userData>/data/workspaces`, `WORKER_TEMP_DIR=<userData>/data/worker_tmp`, `TMPDIR=<userData>/data/verify_tmp` (strictly user-owned & non-symlinked for `validate_strict_temp_workspace()`), and `REDMERCURY_BIN_DIR=<resources>/bin/<platform-arch>`.
4. **Instance Isolation & Health Auth:**
   - Dynamically allocate an ephemeral free localhost port for FastAPI, launch with an ephemeral per-session `REDMERCURY_IPC_TOKEN` header/handshake on `/api/v1/health` (or verify child PID health), and never adopt arbitrary external listeners on `8001`.

---

## 6. Database Strategy

**Decision:** **Retain SQLite (WAL mode) as the zero-config embedded desktop database** and **omit Redis in desktop mode**, while keeping PostgreSQL 16 + Redis 7 untouched for multi-user server/Docker deployments.

### Compatibility Verification (Observed in Codebase)
- **Alembic Migrations (`0001`–`0014`):** All 14 migrations use dialect-neutral SQLAlchemy column types (`String`, `Text`, `Integer`, `Boolean`, `DateTime(timezone=True)`) and `op.batch_alter_table(...)` for SQLite table alterations. Zero PostgreSQL-only types (`JSONB`, `ARRAY`, `UUID`, `INET`) exist.
- **Durable Jobs (`core/jobs.py`):** Already implements cross-dialect atomic Compare-And-Swap (`UPDATE ... WHERE status IN ('queued','retrying')`) alongside PostgreSQL `FOR UPDATE SKIP LOCKED` and `pg_advisory_xact_lock`.
- **Rate Limiting (`core/security.py`):** `DistributedRateLimiter` automatically uses thread-safe `InMemoryRateLimiter` when `REDIS_URL` is unset.
- **Outbox & Queue (`core/jobs.py`):** `dispatch_outbox_events()` and `claim_next_durable_job()` treat Redis strictly as an optional O(1) notification hint and fall back to authoritative SQLite/DB polling when `REDIS_URL` is `None`.

### Required SQLite Hardening for Desktop
1. **Concurrency (`busy_timeout`):** [`backend/app/db/session.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/db/session.py#L20-L32) sets `PRAGMA journal_mode=WAL`, `PRAGMA synchronous=NORMAL`, and `PRAGMA foreign_keys=ON`, but **does not set `PRAGMA busy_timeout`**. With concurrent `api` + `worker` processes writing to SQLite, `PRAGMA busy_timeout=10000` (10s) and `timeout=15` in `connect_args` are mandatory to prevent `database is locked` errors.
2. **Alembic Auto-Upgrade Path Resolution:** [`backend/app/main.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/main.py#L49-L72) searches relative paths for `alembic.ini` and runs `command.upgrade(cfg, "head")` only if `alembic_version` already exists (`stamp` if absent). For desktop upgrades across app versions, **always** run `alembic upgrade head` cleanly before worker startup (passing explicit `script_location` inside `resources/backend/alembic`) and take an automatic pre-migration SQLite `.backup()` snapshot!
3. **Safe Backup & Restore:** Because WAL mode splits uncommitted pages into `redmercury.db-wal`, implement backup/export via Python `sqlite3.Connection.backup()` (plus optional encrypted/zipped workspace snapshot) rather than raw file copy.
4. **Single-User vs Multi-User Model:** Retain existing `users`, `owner_id`, `AuditEvent`, and RBAC tables so schemas remain 100% compatible with server PostgreSQL exports/migrations. Support seamless **Local Operator Workspace** UX (auto-created local admin/analyst profile or local OS-keychain-unlocked session on first launch, with optional multi-user mode toggle) rather than forcing a cloud-style login/register wall on every desktop launch unless enterprise auth is enabled.

---

## 7. Docker Integration Strategy

**Core Requirement:** Preserve fail-closed isolated execution (`--network=none --cap-drop=ALL --read-only --pids-limit=50`) with **zero** Docker socket exposure in Electron, frontend, or FastAPI API.

### Desktop Strategy
1. **Tiered Capability Model (Graceful Detection, Zero Forced Failures):**
   - **Static Scanning (`SAST`, `SCA`, `Secrets`, `IaC`, `AI Analyst`):** Runs 100% natively without Docker on both Windows and macOS.
   - **Dynamic Fix Verification (`pytest` / `sandbox.py`):** Probes local container runtime (`docker` CLI—supporting Docker Desktop on Windows/macOS, and optionally Podman/OrbStack/Colima on macOS/Linux) via [`check_docker_availability()`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/verification/sandbox.py#L59-L96).
   - **When Docker is NOT installed/running:** UI surfaces a clear desktop status indicator ("Sandbox Runtime: Offline — Static checks active; start Docker Desktop to enable isolated Fix Verification") with a 1-click "Check / Initialize Sandbox Image" action, while `SANDBOX_FAIL_CLOSED=true` remains strictly enforced (never executing untrusted repo code on the host).
2. **Automatic Sandbox Image Provisioning (`redmercury-worker:latest`):**
   - Currently users must manually run `docker build -f Dockerfile.worker -t redmercury-worker:latest .`.
   - Desktop should bundle `Dockerfile.worker` + minimal worker build context (or build/load `redmercury-worker:latest` via a Worker/Setup action) **matching host CPU architecture** (`linux/amd64` on Windows/Intel Mac, `linux/arm64` on Apple Silicon).
3. **macOS VirtioFS & `workspace.py` Fix:**
   - Replace the Linux-only `os.setxattr` / `setfacl` hard failure in [`workspace.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/verification/workspace.py#L348-L452) with platform-aware handling:
     - On **Linux**, keep strict UID `10002` POSIX ACLs (`os.setxattr` / `setfacl`, `0o007 == 0`).
     - On **Windows** and **macOS** (where Docker Desktop runs containers inside a Hyper-V/WSL2 or Apple Virtualization/VirtioFS VM that maps host user file ownership and ignores host Linux UID `10002` ACLs), enforce owner-only host permissions (`0o700`/`0o600` on macOS) and align the container sandbox user/mount permissions with Docker Desktop's VirtioFS file-sharing semantics so `--user` inside the Linux VM can read `/workspace` without weakening `--network=none --cap-drop=ALL --read-only`.
4. **Windows Semgrep Option:** Since `semgrep` has no native Windows Python wheel, optionally run Semgrep inside the hardened `--network=none` `redmercury-worker` container when Docker Desktop is available on Windows (or via WSL2), while keeping native Semgrep on macOS.

---

## 8. Infrastructure Cost Analysis (Target: ₹0/month)

| Component / Feature | Runs Locally (₹0/mo)? | External / Paid Dependency | Offline Capability |
| :--- | :--- | :--- | :--- |
| **Desktop UI + Electron Shell** | **Yes (₹0)** | None (drop Cloudflare Worker deployment requirement for desktop) | **100% Offline** (once Google Fonts CDN links in `index.html` are bundled locally) |
| **FastAPI API + Durable Worker** | **Yes (₹0)** | None | **100% Offline** |
| **SQLite WAL + In-Memory Limiter** | **Yes (₹0)** | None (replaces hosted Postgres + Redis) | **100% Offline** |
| **SAST / Secrets / Manifest SCA** (`bandit`, `gitleaks`, built-ins, `semgrep` macOS) | **Yes (₹0)** | None | **100% Offline** (`--disable-version-check --metrics=off`, local `redmercury_default.yml` ruleset) |
| **`pip-audit` Advisory Lookup** | Partial | Queries PyPI/OSV over HTTPS (`pip_audit.py`) | Needs optional bundled/cached OSV vulnerability DB or graceful offline skip |
| **Fix Verification Sandbox** | **Yes (₹0)** via local Docker Desktop (Personal/Edu/Small Biz) or Podman/OrbStack/Colima | Large-enterprise Docker Desktop seats require Docker paid subscription | **100% Offline** once `redmercury-worker:latest` image is built/loaded |
| **AI Security Analyst** | **Yes (₹0)** via deterministic fallback ([`fallback.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/analyzer/fallback.py)) | Optional `GEMINI_API_KEY` (`OFFLINE_MODE=false`) — user BYOK or paid quota | **100% Offline** in default `OFFLINE_MODE=true`; online when BYOK Gemini enabled |
| **Public Git Clone & GitHub PR Integration** | Local `git` CLI | Requires internet + GitHub App/PAT | **Online only** (ZIP upload & Local Folder work 100% offline) |
| **Distribution & Signing** *(Non-monthly)* | GitHub Releases hosting (**₹0**) | Apple Developer (`$99/yr` notarization) & Windows Authenticode (`~$200–$400/yr`) | N/A (release pipeline only; unsigned builds work internally with OS warnings) |

---

## 9. Security Gaps

| ID | Severity | Location | Gap Description & Mitigation |
| :--- | :--- | :--- | :--- |
| **SEC-D1** | **High** | [`electron/main.cjs:204-209`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/electron/main.cjs#L204-L209) | **Blind Backend Adoption on Port `8001`:** `startBackend()` adopts any healthy listener on `127.0.0.1:8001` without verifying ownership or instance secret. **Fix:** Bind backend to a dynamically allocated ephemeral port and authenticate startup via per-launch `REDMERCURY_IPC_TOKEN`. |
| **SEC-D2** | **High** | [`backend/app/core/config.py:62,251`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/config.py#L62) | **Weak Default `SECRET_KEY` & Dev Seed in Non-Strict Mode:** Running desktop under `APP_ENV=development` leaves `dev-insecure-secret-key-...` and `dev@xerova.com` enabled; running under `APP_ENV=production` crashes SQLite startup. **Fix:** Add `APP_ENV=desktop` validating a random per-install `SECRET_KEY`/`ENCRYPTION_KEY` (stored via Electron `safeStorage` or `0600` file) and disabling `dev@xerova.com`. |
| **SEC-D3** | **High** | [`backend/app/core/ingestion.py:618-687`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/ingestion.py#L618-L687) | **Unbounded Local Folder Ingestion in Desktop Mode:** In `development`, `LOCAL_INGESTION_ALLOWED_ROOTS` is empty, allowing any API caller with a valid cookie/token to ingest arbitrary readable host directories (outside `/Windows`, `/etc`, etc.). **Fix:** In `desktop` mode, require user-selected paths approved through Electron `dialog:openDirectory` IPC (main process passes/authorizes selected path or writes ephemeral signed path token). |
| **SEC-D4** | **Medium** | [`electron/main.cjs:336-338`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/electron/main.cjs#L336-L338), [`frontend/src/services/api.ts:385`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/frontend/src/services/api.ts#L385) | **Split Origin & CSP Mismatch:** Frontend bypasses `uiServer` reverse proxy to hit `:8001` directly while `index.html` attempts external Google Fonts blocked by CSP. **Fix:** Route all frontend API calls to same-origin `/api/...` via `uiServer` and tighten CSP `connect-src 'self'`, `font-src 'self'`, `style-src 'self' 'unsafe-inline'`. |
| **SEC-D5** | **Medium** | [`electron/main.cjs:62-76,178`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/electron/main.cjs#L62-L76) | **Splash Window Missing Navigation/Open Guards & Electron Fuses:** `splashWindow` lacks `will-navigate`/`setWindowOpenHandler` handlers; packaged Electron binary lacks `@electron/fuses` lockdown (`RunAsNode=false`, `EnableNodeCliInspectArguments=false`). |
| **SEC-D6** | **Medium** | [`electron/security.cjs:244-249`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/electron/security.cjs#L244-L249) | **Orphan Subprocesses on macOS/POSIX Exit:** `proc.kill('SIGTERM')` does not kill the backend process group on macOS/Linux, potentially leaving orphaned Uvicorn/scanner/worker processes holding DB locks or files. |
| **SEC-D7** | **Low** | [`backend/app/core/config.py:129`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/config.py#L129), [`scripts/download_gitleaks.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/scripts/download_gitleaks.py) | **Missing SHA-256 Verification on Desktop Binary Downloads:** `download_gitleaks.py` downloads `gitleaks_8.18.2_windows_x64.zip` without verifying SHA-256 (unlike `Dockerfile.worker` which pins SHA-256). Enforce pinned SHA-256 checks for Windows `x64`, macOS `amd64`, and macOS `arm64` binaries during build/packaging. |

---

## 10. Dependencies Requiring Changes

| Package / Asset | Current State | Required Change for Cross-Platform Desktop |
| :--- | :--- | :--- |
| **`electron` / `electron-builder`** (`package.json`) | `^45.0.0` / `^26.15.3`, Windows-only `build` config, default `asar: true` | Pin exact versions, add `asarUnpack` or move backend/runtime/binaries to `extraResources`, add `mac` (`dmg`, `zip`, `x64`, `arm64`, entitlements, `icon.icns`), add `@electron/fuses` post-pack hook, remove `backend/data` & caches from bundle. |
| **Python Runtime** (new build artifact) | Assumes host `python` / `.venv` on `PATH` | Bundle relocatable `python-build-standalone` 3.11+ per target (`win32-x64`, `darwin-x64`, `darwin-arm64`) with pre-installed `backend/requirements.txt` deps. |
| **`semgrep`** (`backend/requirements.txt:24`) | `semgrep>=1.65.0; sys_platform != "win32"` | Keep native wheel in macOS (`x64`/`arm64`) bundles; on Windows, integrate containerized Semgrep fallback via `redmercury-worker` Docker image when Docker is available. |
| **`gitleaks`** (`bin/gitleaks.exe`, `scripts/download_gitleaks.py`) | Only Windows `x64` binary in `bin/`, unverified download script | Add SHA-256-verified fetch/bundling for `win32-x64`, `darwin-x64`, and `darwin-arm64` into `resources/bin/<platform>-<arch>/`. |
| **Google Fonts** (`frontend/index.html`) | External `<link>` to `fonts.googleapis.com` | Bundle `Geist`, `Geist Mono`, and `Inter` `.woff2` files locally in `frontend/public/fonts/` (matching existing `material-symbols-outlined.woff2`) and remove external `<link>` tags for 100% offline & CSP compliance. |
| **`@cloudflare/vite-plugin`** (`frontend/vite.config.ts`) | Unconditionally loaded in `vite build` | Conditionally disable `cloudflare()` when building for Electron desktop (`VITE_TARGET=desktop`). |
| **`build/icon.icns`** (`build/`) | Only `icon.ico` and `icon.png` exist | Generate `build/icon.icns` (and multi-resolution `512x512`/`1024x1024` PNGs) for macOS `.app` and `.dmg`. |

---

## 11. Exact Implementation Roadmap

### Phase 2 — Core Desktop Runtime, Packaging & Storage Separation
1. **Desktop Config & Storage (`backend/app/core/config.py`, `db/session.py`, `core/ingestion.py`):**
   - Add `APP_ENV="desktop"` mode supporting SQLite WAL (`PRAGMA busy_timeout=10000`), `userData`-backed `REDMERCURY_DATA_DIR`, disabled `dev@xerova.com`, auto-persisted random `SECRET_KEY`/`ENCRYPTION_KEY`, and IPC-approved local folder allowlisting.
   - Fix `main.py` Alembic `script_location` resolution for packaged `resources/backend/alembic` and add automatic pre-migration SQLite `.backup()`.
2. **Electron Process Supervision & Security (`electron/main.cjs`, `electron/security.cjs`, `electron/preload.cjs`):**
   - Allocate ephemeral localhost ports for both `uiServer` and FastAPI backend (`REDMERCURY_IPC_TOKEN` health handshake; remove blind adoption of `:8001`).
   - Supervise **both** FastAPI (`uvicorn`) and `python -m app.scanner.worker` (`JOB_DISPATCH_MODE=queue_only`, `windowsHide: true`, POSIX `detached: true` process-group termination).
   - Fix macOS `window-all-closed` vs `activate` lifecycle so closing a window keeps backend/worker alive in the Dock and quits cleanly on `before-quit` (`Cmd+Q`).
   - Add macOS standard Application Menu (`Copy`, `Paste`, `Reload` disabled in prod, `Quit`), native Save As IPC for report exports, splash window navigation guards, and `@electron/fuses`.
3. **Frontend Desktop Alignment (`frontend/`):**
   - Replace `window.location.href = '/verification'` in `AiSecurityAnalyzerScreen.tsx` with `useNavigate()`.
   - Route `api.ts` through same-origin `/api/...` via `uiServer` (eliminating hardcoded `:8001` and cross-origin requests), and convert `verification.py` UI triggers to async enqueue + status polling (avoiding 20s `AbortController` timeouts).
   - Bundle `Geist`, `Geist Mono`, and `Inter` fonts locally; gate `@cloudflare/vite-plugin` out of desktop builds; persist Settings via backend config endpoint; expose Audit History view; fix stale `REPO SHIELD AI` label in `ExportModal.tsx`.

### Phase 3 — Cross-Platform Packaging, Scanners & Docker Verification
1. **Bundled Python & Binary Pipeline (`scripts/`, `package.json`):**
   - Create reproducible build script fetching SHA-256-verified `python-build-standalone` (`win32-x64`, `darwin-x64`, `darwin-arm64`) + `gitleaks` binaries and installing `backend/requirements.txt` offline into `build/runtime/<platform>-<arch>`.
   - Restructure `electron-builder` config in `package.json` to ship `frontend/dist` inside ASAR and place `backend/`, `runtime/`, and `bin/` in `extraResources` (with `build/icon.icns` and `entitlements.mac.plist` for macOS).
2. **macOS & Cross-Platform Sandbox Fixes (`backend/app/verification/`):**
   - Update `workspace.py` (`ensure_sandbox_readable_workspace`) to enforce strict `0o700`/`0o600` owner permissions on macOS/VirtioFS instead of failing on Linux `os.setxattr`/`setfacl`, while preserving UID `10002` POSIX ACLs on Linux.
   - Add macOS GUI `PATH` probing (`/opt/homebrew/bin`, `/usr/local/bin`, `/Applications/Docker.app/Contents/Resources/bin`) for `docker` and `git`.
   - Add UI Sandbox Status + 1-click local `redmercury-worker:latest` image build/verify flow (for `amd64` and `arm64`).

### Phase 4 — IDE UX Polish, Offline Robustness & Release Hardening
1. **Antigravity-Style Desktop Experience:**
   - Optional local single-operator auto-unlock mode (backed by Electron `safeStorage` + local DB user) while keeping full multi-user/audit schema intact.
   - Integrated System Health / Engine Status bar (API, Worker, SQLite, Docker Sandbox, Offline/BYOK AI status) and native folder picker as default repository workflow.
2. **Signing, Notarization & Auto-Update (Optional when certificates are budgeted):**
   - Configure GitHub Actions matrix (`windows-latest`, `macos-14` `arm64`, `macos-13` `x64`) for unsigned/ad-hoc internal builds at ₹0, with hooks ready for Windows Authenticode & Apple `notarytool` when commercial certificates are provisioned.

---

## 12. Platform-Specific Testing Requirements

| Platform | Required Automated & Manual Verification Matrix |
| :--- | :--- |
| **Cross-Platform (Electron & Backend)** | - Preserve and expand `node --test electron/security.test.cjs` (`10/10` passing baseline): add tests for ephemeral port/token handshake, POSIX process-group kill, macOS `darwin` `window-all-closed`/`activate` lifecycle, and IPC save-dialog path validation.<br>- Run backend `pytest tests/` against `APP_ENV=desktop` with SQLite WAL + concurrent `worker` process (`busy_timeout` contention test + Alembic `0001`->`0014` fresh DB & upgrade test).<br>- Run frontend `vitest` + `tsc --noEmit` verifying zero external network calls in `OFFLINE_MODE=true` (CSP violation test). |
| **Windows 10 / 11 (`x64`)** | - Install packaged NSIS `.exe` into `C:\Program Files\Red Mercury` as a **non-admin standard user** (or install + launch as standard user) and verify SQLite DB + workspaces write cleanly to `%APPDATA%\Red Mercury`.<br>- Verify portable `.exe` launch without system Python or Node installed on a clean Windows VM.<br>- Verify `gitleaks.exe`, `bandit`, `trivy_sca` manifest fallback, local folder ingestion, ZIP upload, report Save As, and Task Manager cleanup (zero orphan `python.exe` / `uvicorn` processes on exit).<br>- Verify Docker Desktop (WSL2) Fix Verification (`SANDBOX_BACKEND=docker`) + fail-closed message when Docker Desktop is stopped. |
| **macOS (`x64` Intel & `arm64` Apple Silicon)** | - Launch `.app` directly from `/Applications` via **Finder** (testing stripped GUI `$PATH`) on both `arm64` and `x64` macOS.<br>- Verify TCC permission flow when selecting folders in `~/Desktop` / `~/Documents`.<br>- Verify Dock close (`Cmd+W`) + Dock icon reopen (`activate`) keeps backend/worker alive, and `Cmd+Q` terminates the entire Python process tree.<br>- Verify `semgrep`, `gitleaks`, `bandit` native execution and Docker Desktop / VirtioFS Fix Verification (`redmercury-worker:latest` built for matching `arm64`/`amd64` arch). |

---

## 13. Risks and Blockers

| Priority | Risk / Blocker | Impact | Mitigation |
| :--- | :--- | :--- | :--- |
| **P0 (Blocker)** | **ASAR Packaging & Missing Bundled Python (`package.json`, `main.cjs`)** | Packaged `.exe`/`.app` fails to start backend on every end-user machine without dev tools. | Move `backend/` to `extraResources` + bundle `python-build-standalone` per OS/arch. |
| **P0 (Blocker)** | **Writable Paths Inside Read-Only App Bundle (`config.py`, `ingestion.py`)** | `sqlite:///./redmercury.db` and `data/workspaces` fail with `PermissionError` in `Program Files` / `/Applications`. | Redirect all mutable data to Electron `app.getPath('userData')` via env vars. |
| **P0 (Blocker)** | **macOS Verification Failure in `workspace.py` (`setxattr`/`setfacl`)** | Fix Verification fails 100% of the time on macOS with `PermissionError`. | Add VirtioFS-aware macOS permission branch in `workspace.py` while preserving Linux ACLs and fail-closed isolation. |
| **P0 (Blocker)** | **macOS Lifecycle Bug & Missing `mac` Build Config (`main.cjs`, `package.json`)** | Closing window on macOS kills backend while app stays open; cannot build `.dmg`/`.app`. | Fix `window-all-closed` / `before-quit` split and add `mac` (`x64`/`arm64`) `electron-builder` config + `.icns`. |
| **P1 (High)** | **Synchronous Scan/Verification Blocking & 20s Frontend Timeout** | Scans/verifications >20s fail with `REQUEST_ABORTED` and freeze API server. | Supervise `app.scanner.worker` alongside API (`queue_only`) and make verification async-polled. |
| **P1 (High)** | **Windows Native Semgrep Absence & Offline `pip-audit` Lookup** | Semgrep unavailable natively on Windows; `pip-audit` fails offline without local OSV DB. | Document/add Docker-wrapped Semgrep on Windows; provide graceful offline notice or cached OSV DB for `pip-audit`. |
| **P2 (Medium)** | **OS Gatekeeper & SmartScreen Warnings Under ₹0 Budget** | Unsigned downloads show OS security warnings on macOS Gatekeeper and Windows SmartScreen. | Document internal bypass for ₹0 pilot builds; budget Apple Developer (`$99/yr`) + Authenticode (`~$200–$400/yr`) prior to public GA release. |
| **P2 (Medium)** | **Bundle Size (~250–450 MB per installer)** | Bundled Electron + Chromium + Python 3.11 + scanners (`semgrep`/`bandit`/`gitleaks`) increases download size. | Strip test/cache/`__pycache__`/`.pyc` files from `extraResources` and ship per-arch builds rather than fat multi-arch Windows+Mac blobs. |

---

## Final Gate Decision

### **`CONDITIONAL GO` FOR CROSS-PLATFORM DESKTOP IMPLEMENTATION**

- **Why not `NO-GO`:** All architectural foundations—sandboxed Electron preload/IPC (`10/10` security tests passing), React SPA, FastAPI REST backend, SQLite WAL + 14 dialect-neutral Alembic migrations, Redis-optional durable jobs + in-memory rate limiter, offline deterministic AI Security Analyst, and fail-closed Docker sandbox—are **already compatible** with a zero-cost (`₹0/month`) standalone desktop architecture without rewriting the product.
- **Conditions Required Before Release (`GO` for Packaging/Beta):** Complete Phase 2 (`APP_ENV=desktop`, `userData` storage relocation, bundled Python + `worker` supervision, same-origin API routing, local fonts, macOS lifecycle fix) and Phase 3 (per-arch `extraResources` + `gitleaks` SHA-256 binaries, macOS `workspace.py` VirtioFS fix, GUI `PATH` Docker discovery, and full Windows + macOS VM verification).
