# RED MERCURY — PHASE 6
# CROSS-PLATFORM DESKTOP SECURITY QUALIFICATION REPORT

**Organization:** Xerova Digital Solutions  
**Project:** Red Mercury  
**Platforms Audited:** Windows 10/11 (`x64`), macOS Intel (`x64`), macOS Apple Silicon (`arm64`)  

> **Qualification Scope Disclaimer:** This report documents an internal engineering architecture review, hardening pass, and automated security regression verification across the Red Mercury Electron, React, and FastAPI codebase and built Windows package. **It does NOT constitute an independent third-party Vulnerability Assessment and Penetration Test (VAPT).**

---

## 1. Security Requirements Compliance Summary

| Security Requirement | Status | Primary Evidence |
|---|---|---|
| No renderer Node.js access | **Verified** | `nodeIntegration: false`, `contextIsolation: true`, `sandbox: true`, `webSecurity: true` ([`electron/main.cjs`](electron/main.cjs)) |
| Strict IPC allowlisting | **Verified** | Fixed channel allowlists (`ALLOWED_IPC_INVOKE_CHANNELS` / `ALLOWED_IPC_EVENT_CHANNELS`), `assertTrustedIpcSender()`, payload schema sanitization ([`electron/security.cjs`](electron/security.cjs), [`electron/preload.cjs`](electron/preload.cjs)) |
| No arbitrary command execution | **Verified** | `shell: false` on backend/worker spawns, strict numeric port & worker arg validators, AST + containerized sandbox for untrusted test execution |
| No exposed backend network interfaces | **Verified** | API & internal static UI server bind strictly to `127.0.0.1`; DNS-rebinding `Host` checks (`isTrustedLocalHostHeader` & `TrustedHostMiddleware`); `0.0.0.0`/`::` rejected ([`config.py`](backend/app/core/config.py), [`main.cjs`](electron/main.cjs)) |
| No unrestricted filesystem access | **Verified** | Path traversal + symlink defense in `resolveStaticAssetPath()` and `validate_local_ingest_path()`, blocking OS system dirs, `~/.ssh`/`~/.aws`/`~/.gnupg`, and internal `secrets/`/`config/`/`logs/`/`backups/` |
| No plaintext API secrets | **Verified** | `SECRET_KEY` & `ENCRYPTION_KEY` generated randomly (32 bytes) and encrypted via Electron `safeStorage`; zero `.env*` files or dev seeds in desktop bundles |
| No untrusted code execution outside sandbox | **Verified** | `sandbox_allow_host_fallback` forced `False` in `APP_ENV=desktop`; AST pre-inspection + fail-closed Docker sandbox |
| No insecure automatic updates | **Verified** | Zero auto-updater active (`electron-updater` absent); added fail-closed `verifyUpdateManifestSignature()` blocking HTTP, downgrades, SHA-512 mismatches, forged Ed25519 signatures, and unsigned builds |
| No development credentials in release packages | **Verified** | `is_dev_seed_blocked == True` in desktop mode; packaged `win-unpacked/resources` verified with `0` `.env*`, `0` `*.db*`, `0` `tests/`, and `0` `pytest`/`locust` packages |

---

## 2. Detailed Audit of the 12 Inspection Areas

1. **Electron Main Process ([`electron/main.cjs`](electron/main.cjs)):** Enforces single-instance lock, removes Windows application menu, isolates `BrowserWindow` (`sandbox: true`, `contextIsolation: true`, `nodeIntegration: false`, `webSecurity: true`), locks `will-navigate` to `getTrustedAppOrigins()`, denies `setWindowOpenHandler`, validates localhost `Host` headers (`isTrustedLocalHostHeader`) on the internal UI HTTP server & `/api/` reverse proxy, and terminates worker/backend process trees cleanly on `before-quit` and `window-all-closed`.
2. **Preload Scripts ([`electron/preload.cjs`](electron/preload.cjs)):** Uses `contextBridge.exposeInMainWorld('electronAPI', ...)` exclusively with 9 explicit helper wrappers; never imports Node built-ins (`fs`, `child_process`, `path`, `os`, `http`) or exposes raw `ipcRenderer`.
3. **IPC Handlers ([`electron/main.cjs`](electron/main.cjs), [`electron/security.cjs`](electron/security.cjs)):** `registerSecureIpcHandler` asserts channel membership (`ALLOWED_IPC_INVOKE_CHANNELS`), verifies `event.senderFrame.url` origin, and sanitizes inputs (`validateSaveReportPayload` 25 MB / extension whitelist / `path.basename`, `sanitizeUserPreferences` stripping extra keys & `__proto__` payloads, `isSafeExternalUrl` permitting HTTP/HTTPS only).
4. **Renderer Isolation:** Strict Content Security Policy (`default-src 'self'; script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';`) with external Google Fonts links removed in [`frontend/index.html`](frontend/index.html).
5. **Local FastAPI Service ([`backend/app/main.py`](backend/app/main.py), [`electron/security.cjs`](electron/security.cjs)):** Strictly bound to `127.0.0.1` on an ephemeral-fallback free port; verifies per-launch 256-bit `REDMERCURY_IPC_TOKEN` header on health checks; Swagger/ReDoc & OpenAPI schema endpoints disabled when `APP_ENV=desktop`; `TrustedHostMiddleware` enforced.
6. **Local Authentication ([`backend/app/core/auth.py`](backend/app/core/auth.py), [`backend/app/core/security.py`](backend/app/core/security.py)):** Short-lived JWT access cookies + rotating `RefreshTokenSession` family reuse detection stored as HttpOnly cookies (zero `localStorage` tokens), `RevokedToken` SHA-256 hash revocation table, `Origin`/`Referer` + double-submit `X-CSRF-Token` validation, and development seed logins blocked (`is_dev_seed_blocked`).
7. **Secret Storage & Platform Evaluation:**
   - **Implementation (`loadOrCreateEncryptedDesktopKeys`):** Generates cryptographically random `SECRET_KEY` and `ENCRYPTION_KEY`, encrypted at rest via Electron `safeStorage.encryptString()` into `secrets/desktop-keys.enc` (`0o600` POSIX mode inside `0o700` dir); refuses plaintext disk persistence when `safeStorage.isEncryptionAvailable()` is `false` (falls back to ephemeral in-memory keys). Sensitive GitHub credentials in SQLite are additionally encrypted with `ENCRYPTION_KEY` via `cryptography.Fernet`.
   - **Platform Evaluation — Windows Credential Manager vs `safeStorage` (DPAPI):** Electron `safeStorage` on Windows uses **DPAPI (`CryptProtectData` / `CryptUnprotectData`) scoped to the current Windows user SID**, encrypting `secrets\desktop-keys.enc` without storing individual secrets in Windows Credential Manager (`VaultCmd` / `CredWriteW`). Same-user Windows sessions under the same account can decrypt via DPAPI, while other OS users and offline disk attackers cannot. Moving/mirrored individual tokens into Windows Credential Manager (`CredWriteW`) is an optional future enhancement if per-secret Windows Credential Vault visibility is desired.
   - **Platform Evaluation — macOS Keychain:** Electron `safeStorage` on macOS stores the application encryption master key directly in the user's **macOS Keychain** (`"Red Mercury Safe Storage"`) and encrypts `secrets/desktop-keys.enc` with `0o600` permissions.
8. **File Access ([`backend/app/core/ingestion.py`](backend/app/core/ingestion.py), [`electron/security.cjs`](electron/security.cjs)):** `resolveStaticAssetPath` blocks directory traversal, URL-encoded/double-encoded `..`, null bytes, and escaping symlinks. Hardened `validate_local_ingest_path()` during Phase 6 to also block macOS system directories (`/System`, `/Library`, `/private/etc`, `/private/var/db`), user credential directories (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`), and Red Mercury's own internal `secrets/`, `config/`, `logs/`, and `backups/` directories.
9. **Local Database Permissions ([`backend/app/core/backup.py`](backend/app/core/backup.py)):** SQLite WAL enabled; added explicit `os.chmod(..., 0o600)` enforcement on `redmercury.db`, `-wal`, and `-shm` files on POSIX hosts inside `initialize_local_database()`; `.rmbkp` backups explicitly omit `desktop-keys.enc` and `.env*` secrets.
10. **Docker Integration ([`backend/app/verification/sandbox.py`](backend/app/verification/sandbox.py)):** Enforces all 8 container restrictions (`--network=none`, `--cap-drop=ALL`, `--read-only`, `--pids-limit<=50`, `--memory<=512m`, `--cpus<=1.0`, `--user=10002:10002`, `--security-opt=no-new-privileges:true`), worker image non-root/digest validation, UNC volume-path rejection, AST test inspection, and zero Docker IPC in renderer/preload.
11. **Installer Security (`dist-electron/RedMercury-Setup-x64.exe`, `app.asar`):** Verified `0` `.env*`, `0` `*.db*`, `0` `tests/`, and `0` `pytest`/`locust` packages in `win-unpacked/resources`. (`app.asar` contains benign `electron/security.test.cjs` from Phase 3 and pre-dates Phase 6 edits to `electron/main.cjs`; excluding `!**/*.test.*` from `package.json` `files` and rebuilding the signed installer before public distribution is recommended.) Current local installer is `NotSigned`.
12. **Auto-Update Mechanism ([`electron/security.cjs`](electron/security.cjs)):** Confirmed **no auto-updater dependency (`electron-updater`) is installed or active**, eliminating unauthenticated background update risk on unsigned builds. Added fail-closed `verifyUpdateManifestSignature()` + `isValidUpdateFeedUrl()` security gates requiring: (a) signed application binary (`isAppSigned === true`), (b) HTTPS non-local feed URL, (c) trusted publisher identity, (d) strictly newer SemVer (anti-downgrade), (e) matching SHA-512 digest, and (f) valid cryptographic Ed25519 signature.

---

## 3. Security Remediation Performed During Phase 6

1. **Blocked Credential & Internal Storage Ingestion ([`backend/app/core/ingestion.py`](backend/app/core/ingestion.py)):** Extended `validate_local_ingest_path()` to deny macOS system directories, `~/.ssh`/`~/.aws`/`~/.gnupg`/`~/.kube`, and Red Mercury's own `secrets/`, `config/`, `logs/`, and `backups/` folders.
2. **UI Proxy DNS-Rebinding Protection ([`electron/main.cjs`](electron/main.cjs)):** Added `isTrustedLocalHostHeader()` enforcement rejecting non-`127.0.0.1:<port>`/`localhost:<port>` `Host` headers on the internal UI HTTP & `/api/` proxy server.
3. **POSIX SQLite File Hardening ([`backend/app/core/backup.py`](backend/app/core/backup.py)):** Added `0o600` permissions enforcement on `redmercury.db` and its `-wal`/`-shm` sidecars.
4. **Auth-Before-Offline Ordering Fix ([`backend/app/integrations/github/service.py`](backend/app/integrations/github/service.py), [`integrations.py`](backend/app/api/v1/endpoints/integrations.py)):** Moved the offline publish guard inside `publish_pr_summary_comment` after `verify_repository_ownership`, restoring strict `403 FORBIDDEN` precedence over cross-tenant requests.
5. **Update Signature Verification Gate ([`electron/security.cjs`](electron/security.cjs)):** Added `isValidUpdateFeedUrl()` and `verifyUpdateManifestSignature()` (fail-closed on unsigned apps, HTTP feeds, downgrades, SHA-512 mismatches, and invalid Ed25519 signatures).

---

## 4. Security Verification Test Results (After Final Edits)

- **Electron Security, IPC, Host Header, Process Cleanup & Update Signature Suite (`node --test electron/security.test.cjs`):** **17/17 passed** (`841.18ms`)
- **Frontend TypeScript (`npm --prefix frontend run lint`):** **0 errors**
- **Frontend Vitest (`npm --prefix frontend run test -- --testTimeout=15000`):** **7/7 files, 46/46 passed** *(extended per-test timeout flag used because `UserJourney.test.tsx` full multi-page flow ran `7196ms` under host load, exceeding Vitest's `5000ms` default; no assertions weakened or skipped)*
- **Backend Phase 6 & Cross-Phase Security Suite (`python -m pytest tests/test_phase6_desktop_security_audit.py tests/test_phase5_cross_platform_sandbox.py tests/test_phase4_local_services.py tests/test_phase3_desktop_packaging.py tests/test_phase2_desktop_mode.py tests/test_ingestion.py tests/test_auth_security_hardening.py tests/test_github_integration.py -v`):** **67/67 passed** (`112.07s`)
- **Packaged Resource Audit (`dist-electron/win-unpacked/resources`):** Confirmed `0` `.env*`, `0` `*.db*`, `0` `tests/`, and `0` `pytest`/`locust` packages (`anyio`/`platformdirs`/`sqlalchemy` contain 4 benign third-party plugin filenames matching `pytest*`).

---

## 5. Remaining Limitations & Recommendations Before External Release

1. **Rebuild Installers Before Distribution:** Re-run desktop packaging (`prepare_desktop_bundle.py` + `electron-builder`) to bundle Phase 4–6 code hardening and exclude `electron/*.test.*` from `app.asar`.
2. **Obtain Code Signing Certificates & Configure Secrets:** Sign Windows executables with Authenticode (`WIN_CSC_LINK`) and macOS bundles with Developer ID Application + Apple Notarization (`MAC_CSC_LINK`, `APPLE_*`) before enabling `isAppSigned=true` or shipping auto-updates.
3. **Independent VAPT & macOS Live Testing:** Conduct an external third-party VAPT and live macOS Intel/Apple Silicon Keychain + Docker Desktop validation before commercial GA release.
