# RED MERCURY — PHASE 2: SECURE ELECTRON DESKTOP INTEGRATION REPORT

**Project:** Red Mercury — Enterprise Application Security & Automated Fix Verification Engine  
**Organization:** Xerova Digital Solutions  
**Target Platforms:** Windows 10/11 (`x64`), macOS Intel (`x64`), macOS Apple Silicon (`arm64`)  
**Date:** `2026-11-23`  
**Git Policy:** Uncommitted working tree changes only (**zero `git add`, `git commit`, or `git push` executed**).

---

## 1. Changed & Added Files

| File | Change Summary |
| :--- | :--- |
| [`electron/security.cjs`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/electron/security.cjs) | Added IPC channel allowlists (`ALLOWED_IPC_INVOKE_CHANNELS`, `ALLOWED_IPC_EVENT_CHANNELS`), `findAvailableLocalPort` conflict resolution, `BackendSupervisor` (API + Worker orchestration, IPC token health handshake, bounded crash recovery, process-tree termination), `resolveDesktopStoragePaths`, `loadOrCreateEncryptedDesktopKeys` (`safeStorage`), `validateSaveReportPayload`, `sanitizeUserPreferences`, and `scrubLogText`. |
| [`electron/main.cjs`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/electron/main.cjs) | Integrated `BackendSupervisor`, `safeStorage`-backed `userData` storage, encrypted key provisioning, allowlisted `registerSecureIpcHandler` wrappers, native `dialog:saveReport` and `preferences:get`/`preferences:set` handlers, `splashWindow` navigation/window-open hardening, macOS `darwin` Dock lifecycle (`window-all-closed` / `activate` / `before-quit`) + Application Menu, and dynamic `/api/` reverse proxying. |
| [`electron/preload.cjs`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/electron/preload.cjs) | Extended `contextBridge` `electronAPI` with explicit methods (`saveReport`, `getBackendStatus`, `restartBackend`, `onBackendStatus`, `getPreferences`, `savePreferences`) with zero raw `ipcRenderer` or Node exposure. |
| [`electron/security.test.cjs`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/electron/security.test.cjs) | Expanded suite from 10 to **15 tests** covering port conflict fallback, IPC allowlisting, renderer isolation, encrypted `safeStorage` persistence, backend startup, worker launch, crash recovery, and shutdown. |
| [`backend/app/core/config.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/config.py) | Added `APP_ENV="desktop"` (`is_desktop_env`, `is_dev_seed_blocked`), `REDMERCURY_DATA_DIR`, `REDMERCURY_LOG_DIR`, and `REDMERCURY_IPC_TOKEN`; enforced strong `SECRET_KEY`, `127.0.0.1`/`localhost` binding, `DEBUG=False`, `CSRF_PROTECTION_ENABLED=True`, `SANDBOX_FAIL_CLOSED=True`, and `sandbox_allow_host_fallback=False` in desktop mode. |
| [`backend/app/core/logging.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/logging.py) | Added optional secret-scrubbed `RotatingFileHandler` (`REDMERCURY_LOG_DIR`, 5 MB x 3 backups, `0o700` dir / `0o600` file on POSIX). |
| [`backend/app/db/session.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/db/session.py) | Added SQLite `timeout=15` and `PRAGMA busy_timeout=10000` for concurrent API + Worker WAL transactions. |
| [`backend/app/core/auth.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/auth.py) | Blocked `dev@xerova.com` seed credentials across `is_dev_seed_blocked` (`production`, `staging`, and `desktop`). |
| [`backend/app/api/v1/endpoints/auth.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/api/v1/endpoints/auth.py) | Blocked `dev@xerova.com` login in `is_dev_seed_blocked` (`production`, `staging`, and `desktop`). |
| [`backend/app/core/security.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/security.py) | Added constant-time `X-RedMercury-IPC-Token` verification on `/api/v1/health`, returning `X-RedMercury-IPC-Verified: true` exclusively to Electron main without echoing secrets. |
| [`backend/app/api/v1/endpoints/audit.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/api/v1/endpoints/audit.py) *(New)* | Added authenticated `GET /api/v1/audit` endpoint returning actor-scoped `AuditEvent` records persisted in SQLite. |
| [`backend/app/api/v1/router.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/api/v1/router.py) | Mounted `/api/v1/audit`. |
| [`backend/app/main.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/main.py) | Passed `REDMERCURY_LOG_DIR` to `setup_logging()`, disabled Swagger/OpenAPI docs in `desktop` mode, and enabled `TrustedHostMiddleware` in `desktop` mode. |
| [`frontend/src/types/electron.d.ts`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/frontend/src/types/electron.d.ts) | Added TypeScript definitions for `BackendSupervisorStatus`, `DesktopUserPreferences`, and new `electronAPI` methods. |
| [`frontend/src/services/api.ts`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/frontend/src/services/api.ts) | Switched Electron API requests to same-origin `/api/...` (through `uiServer` reverse proxy), removed direct `:8001` bypass in Electron, improved engine-unavailable messages, and added 120s timeouts for uploads/ingestion. |
| [`frontend/src/components/analyzer/AiSecurityAnalyzerScreen.tsx`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/frontend/src/components/analyzer/AiSecurityAnalyzerScreen.tsx) | Replaced `window.location.href = '/verification'` with React Router `UNSAFE_NavigationContext` navigation (preserving `HashRouter` state and standalone test compatibility). |
| [`frontend/src/components/modals/ExportModal.tsx`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/frontend/src/components/modals/ExportModal.tsx) | Integrated native `window.electronAPI.saveReport` Save As dialog (with Blob fallback for browsers) and updated stale `REPO SHIELD AI` header to `RED MERCURY`. |
| [`frontend/src/pages/EvidencePage.tsx`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/frontend/src/pages/EvidencePage.tsx) | Integrated native `window.electronAPI.saveReport` for Markdown/JSON evidence report exports. |
| [`frontend/src/pages/SettingsPage.tsx`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/frontend/src/pages/SettingsPage.tsx) | Persisted governance preferences via Electron IPC (`preferences:get` / `preferences:set`) with browser `localStorage` fallback; added Desktop Engine status & restart control. |
| [`frontend/src/components/layout/AppLayout.tsx`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/frontend/src/components/layout/AppLayout.tsx) | Added real-time `backend:status` banner surfacing restarting/error states with a 1-click **Restart Engine** action. |
| [`frontend/vite.config.ts`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/frontend/vite.config.ts) | Gated `@cloudflare/vite-plugin` off when `VITE_TARGET=desktop`. |
| [`package.json`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/package.json) | Added `build:desktop` & `desktop:test` scripts, updated `desktop:build`/`desktop:dist`/`desktop:portable`, added `bin/**/*` & `asarUnpack` rules, and excluded `backend/data`, `__pycache__`, `.pytest_cache`, and `*.db*`. |
| [`tests/test_phase2_desktop_mode.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/tests/test_phase2_desktop_mode.py) *(New)* | Added pytest coverage for `APP_ENV="desktop"`, `REDMERCURY_DATA_DIR`, secret-scrubbed `RotatingFileHandler`, `X-RedMercury-IPC-Verified`, and `GET /api/v1/audit`. |

---

## 2. Desktop Architecture

```text
+-----------------------------------------------------------------------------+
| Electron Main Process (electron/main.cjs)                                   |
|                                                                             |
|  1. OS Storage (app.getPath('userData'))                                    |
|     - data/redmercury.db (SQLite WAL: scans, findings, verifications,       |
|                           audit_events, users)                              |
|     - data/workspaces/   (isolated repo extractions)                        |
|     - config/app-config.json & config/preferences.json                      |
|     - logs/electron.log & logs/backend.log (secret-scrubbed rotating logs)  |
|     - secrets/desktop-keys.enc (safeStorage encrypted SECRET_KEY/ENCRYPTION)|
|                                                                             |
|  2. Internal Same-Origin UI + Proxy Server (http://127.0.0.1:<ephemeral>)   |
|     - /        -> frontend/dist (strict path containment + CSP)             |
|     - /api/*   -> reverse-proxied to http://127.0.0.1:<supervisor.port>     |
|                                                                             |
|  3. BackendSupervisor (electron/security.cjs)                               |
|     - Allocates free 127.0.0.1 port (automatic fallback on EADDRINUSE)      |
|     - Spawns FastAPI API: python -m uvicorn app.main:app --host 127.0.0.1   |
|     - Verifies ownership via X-RedMercury-IPC-Token -> X-RedMercury-IPC-Verified |
|     - Spawns Durable Worker: python -m app.scanner.worker                   |
|     - Polls health (10s) & performs bounded crash recovery (max 3/60s)      |
+------------------------------------+----------------------------------------+
                                     | IPC (contextBridge + allowlist)
                                     v
+-----------------------------------------------------------------------------+
| Sandboxed Renderer Process (sandbox: true, nodeIntegration: false)          |
|  - React SPA (HashRouter, same-origin /api/* fetch with HttpOnly + CSRF)    |
|  - Native Directory Picker, Native Save Report, Persisted Preferences,      |
|    Engine Status Banner & Restart Control                                   |
+-----------------------------------------------------------------------------+
```

---

## 3. IPC Security Controls

- **Renderer Isolation:** Both `mainWindow` and `splashWindow` enforce `nodeIntegration: false`, `contextIsolation: true`, `sandbox: true`, and `webSecurity: true`. Both windows enforce `will-navigate` containment and `setWindowOpenHandler` restrictions.
- **Explicit Allowlist (`ALLOWED_IPC_INVOKE_CHANNELS`):** Only `dialog:openDirectory`, `dialog:saveReport`, `app:getInfo`, `app:checkBackend`, `app:getBackendStatus`, `app:restartBackend`, `preferences:get`, `preferences:set`, and `shell:openExternal` can be registered or invoked; `backend:status` is the sole allowlisted push event.
- **Sender Origin & Input Validation:** Every handler uses `registerSecureIpcHandler()` which validates `event.senderFrame.url` via `assertTrustedIpcSender(event)`. `dialog:saveReport` enforces allowed formats (`sarif`, `json`, `markdown`, `md`, `txt`), basename sanitization, and a 25 MB limit; `preferences:set` strictly allowlists boolean/integer governance settings; `shell:openExternal` accepts only `http:`/`https:` URLs.
- **Zero Host Shell / Docker Exposure:** `spawn` runs with `shell: false`, `windowsHide: true`, and explicit argument arrays. The renderer has zero IPC access to arbitrary filesystem reads, shell execution, or Docker commands.

---

## 4. Backend Lifecycle & Application Storage

1. **Startup & Port Conflict Resolution:** `BackendSupervisor.start()` binds a temporary probe socket on `127.0.0.1` (default `8001`); if `EADDRINUSE` or `EACCES` occurs, it transparently allocates a free ephemeral localhost port and spawns `uvicorn` with `--host 127.0.0.1 --port <allocated>` (`shell: false`).
2. **Readiness & Instance Verification:** Polls `GET /api/v1/health` with `X-RedMercury-IPC-Token` and requires HTTP `200` plus `X-RedMercury-IPC-Verified: true`, preventing blind adoption of unrelated localhost services. Early child exits abort polling immediately and surface scrubbed diagnostics.
3. **Worker Supervision & Crash Recovery:** Launches `python -m app.scanner.worker` alongside FastAPI (`JOB_DISPATCH_MODE=queue_only`). A 10-second monitor triggers bounded crash recovery (up to 3 restarts in 60s), broadcasting `backend:status` updates to the UI (`starting` -> `running` -> `restarting` -> `error`).
4. **Shutdown & macOS Lifecycle:** On `before-quit` (all OSes) and `window-all-closed` (`process.platform !== 'darwin'`), `BackendSupervisor.stop()` synchronously terminates Worker and API process trees (`taskkill /pid <pid> /T /F` on Windows; `process.kill(-pid, 'SIGTERM')` on POSIX). On macOS, closing all windows leaves the engine alive in the Dock and reopens cleanly on `activate`.
5. **Encrypted Key Storage:** `SECRET_KEY` and `ENCRYPTION_KEY` are generated randomly per installation, encrypted via Electron `safeStorage` (DPAPI on Windows, Keychain on macOS) into `<userData>/secrets/desktop-keys.enc`, decrypted only in main-process memory, and injected to child processes via environment variables.

---

## 5. Validation & Test Results

All test suites ran **after the final code edits** and passed completely:

| Suite | Command | Scope & Result |
| :--- | :--- | :--- |
| **Electron Security & Phase 2 Tests** | `node --test electron/security.test.cjs` | **`15/15` passed** (606.1 ms) — static path traversal (`SEC-04`), trusted origins & URLs (`SEC-10`), localhost-only port/arg checks, Windows/POSIX tree kill, port conflict fallback, IPC allowlist & validation, renderer isolation, `safeStorage` encryption, `BackendSupervisor` startup/worker/shutdown/crash recovery. |
| **Frontend TypeScript Check** | `npm --prefix frontend run lint` | **Passed** (`tsc --noEmit`, 0 errors). |
| **Frontend Unit & Journey Suite** | `npm --prefix frontend run test` | **`7/7` test files, `46/46` passed** (9.14 s) — `TestSelector`, `AiAnalyst`, `EvidenceAndPrioritization`, `AuthSecurity`, `App`, `Verification`, `UserJourney`. |
| **Desktop Production Build** | `npm run build:desktop` | **Passed** (5.58 s) — clean Vite desktop bundle in `frontend/dist` without Cloudflare plugin artifacts. |
| **Backend Desktop & Security Regression Suite** | `python -m pytest tests/test_phase2_desktop_mode.py tests/test_health.py tests/test_auth_security_hardening.py tests/test_phase5_deployment_security.py -v` | **`62/62` passed** (16.94 s) — desktop config/SQLite/localhost enforcement, scrubbed rotating logs, IPC health header verification, `/api/v1/audit`, health probes, auth/CSRF hardening, and Phase 5 deployment security. |

---

## 6. Remaining Blockers (Targeted for Phase 3 Packaging & macOS Hardening)

1. **Bundled Python Runtime (`win32-x64`, `darwin-x64`, `darwin-arm64`):** `detectPythonExecutable()` already prioritizes `resources/runtime/<platform>-<arch>/`, but packaging a self-contained relocatable Python 3.11+ runtime + wheels and multi-platform `gitleaks` binaries into `electron-builder` `extraResources` remains to be automated in Phase 3.
2. **macOS Fix Verification Workspace Permissions ([`workspace.py`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/verification/workspace.py)):** `ensure_sandbox_readable_workspace()` still targets Linux `os.setxattr`/`setfacl` on non-Windows POSIX hosts; macOS VirtioFS compatibility + macOS GUI `$PATH` discovery for `docker`/`git` and `mac` (`dmg`/`zip`, `.icns`, entitlements) packaging config are required before macOS GA builds.
3. **Offline Fonts (`Geist` / `Geist Mono` / `Inter`):** [`frontend/index.html`](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/frontend/index.html) still references external Google Fonts stylesheets (blocked by strict offline CSP; falls back to system fonts until `.woff2` files are bundled locally alongside `material-symbols-outlined.woff2`).
4. **Code Signing & Notarization:** Windows Authenticode and Apple Developer ID signing/notarization certificates are not yet configured (unsigned builds will show SmartScreen/Gatekeeper warnings on public downloads).
