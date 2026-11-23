# RED MERCURY — PHASE 7
# DESKTOP RELEASE QUALIFICATION REPORT

**Organization:** Xerova Digital Solutions  
**Product:** Red Mercury Desktop (`com.xerova.redmercury`)  
**Version:** `1.0.0`  
**Qualification Date:** 2026-11-23  

---

## 1. Release Gate Decisions

| Platform / Target | Decision | Rationale |
|---|---|---|
| **Windows (`x64`)** | **CONDITIONAL GO (Internal Evaluation)** / **HOLD for Public GA** | `RedMercury-Setup-x64.exe` built cleanly (`142.93 MB`), installed/upgraded/uninstalled on Windows 11 (`10.0.26300`), and passed live GUI startup, FastAPI + worker startup, login, ZIP import, scanning, fix generation, fail-closed verification, and SARIF/Markdown export. **Blocked for public GA** until Authenticode signing (`WIN_CSC_LINK`), live Docker Desktop WSL2 container execution, and Windows 10 `x64` hardware/VM verification are completed. |
| **macOS Intel (`x64`)** | **NO-GO / HOLD** | Packaging config, `.icns`, entitlements, notarization hook, and `.github/workflows/desktop-release.yml` (`macos-13`) exist and unit tests pass, **but `RedMercury-macOS-x64.dmg` has NOT yet been built or installed on macOS hardware/CI runners.** |
| **macOS Apple Silicon (`arm64`)** | **NO-GO / HOLD** | Packaging config, `.icns`, entitlements, notarization hook, multi-arch `Dockerfile.worker`, and `.github/workflows/desktop-release.yml` (`macos-14`) exist and unit tests pass, **but `RedMercury-macOS-arm64.dmg` has NOT yet been built or installed on macOS hardware/CI runners.** |

---

## 2. Release Artifacts Inventory

| Platform | Artifact Filename | Size | SHA-256 | Signing Status | Build State |
|---|---|---|---|---|---|
| Windows `x64` | `dist-electron/RedMercury-Setup-x64.exe` | `149,877,952 bytes` (`142.93 MB`) | `FDBBFBE80B7B4F2DCB44ACEFAE5D5D73DE4D945C5FB6A67B036E777EFF63D13F` | `NotSigned` | **Built & Verified on Windows 11 `x64`** |
| macOS Intel `x64` | `RedMercury-macOS-x64.dmg` | — | — | Unsigned (hooks ready) | **Not Built Here — Requires `macos-13` Runner** |
| macOS Silicon `arm64` | `RedMercury-macOS-arm64.dmg` | — | — | Unsigned (hooks ready) | **Not Built Here — Requires `macos-14` Runner** |

---

## 3. Windows Test Matrix

**Test Host Observed:** `Microsoft Windows 11 Home Single Language`, Version `10.0.26300`, Architecture `64-bit`.

| Matrix Item | Windows 11 `x64` Result | Windows 10 `x64` Result | Observed Evidence |
|---|---|---|---|
| **Fresh Installation** | **PASS** | *Not Tested Locally (No Win10 host)* | `RedMercury-Setup-x64.exe /S` exited `0`; created `Red Mercury.exe`, `resources/runtime/python.exe` (`3.12.16`), `resources/bin/gitleaks.exe` (`8.18.2`), `Uninstall Red Mercury.exe`, Start Menu & Desktop shortcuts. |
| **Application Startup** | **PASS** | *Not Tested Locally* | Launched `Red Mercury.exe` cleanly (`GUI_ALIVE=True`), internal UI server answered `HTTP 200` on `127.0.0.1` with strict CSP header (`HAS_CSP=True`). |
| **Backend Startup** | **PASS** | *Not Tested Locally* | Supervised FastAPI (`127.0.0.1:8001`, `[desktop]`, SQLite + Alembic stamped `0014_add_durable_jobs_and_outbox`) returned `HTTP 200` on `/api/v1/health`; durable worker `app.scanner.worker` launched with `backend/` on `PYTHONPATH`. |
| **Login** | **PASS** | *Not Tested Locally* | Live `/api/v1/auth/register` (`201`, rejecting privileged `role` field) + `/api/v1/auth/login` (`200`, HttpOnly cookies + CSRF token). |
| **Project Import** | **PASS** | *Not Tested Locally* | Live `/api/v1/repositories/ingest/upload` ZIP ingestion succeeded (`201`) in offline desktop mode. |
| **Vulnerability Scanning** | **PASS** | *Not Tested Locally* | Live `/api/v1/scans` (`bandit`, `gitleaks`, `secret_detector`) detected `5` findings on sample vulnerable repository. |
| **Fix Generation** | **PASS** | *Not Tested Locally* | Live `/api/v1/analyze-finding` returned structured remediation and explicitly reported `redmercury-deterministic-fallback-v1.0` in Offline Mode. |
| **Docker Verification** | **PASS (Fail-Closed)** / *Live Container Skipped* | *Not Tested Locally* | Host Docker Desktop CLI `29.9.3` detected (`amd64`), daemon stopped -> live `/api/v1/verifications` returned `INCONCLUSIVE` honestly (never falsely passed). Live container execution remains pending active WSL2 daemon. |
| **Report Export** | **PASS** | *Not Tested Locally* | Live `/api/v1/evidence/reports/findings` generated SARIF (`11,481` chars) & Markdown (`8,649` chars) reports; `/api/v1/audit` returned `7` audit events. |
| **Application Shutdown** | **PARTIAL / UNIT-VERIFIED** | *Not Tested Locally* | Graceful Electron `before-quit` / `BackendSupervisor.stop()` + `taskkill /T /F` tested cleanly in unit suite & `ORPHANS_AFTER_EXIT=0` on install run; note forced external `taskkill` of parent EXE in standalone probe left 1 child process (`ORPHAN_AFTER_KILL=1`, cleaned manually). |
| **Upgrade** | **PASS** | *Not Tested Locally* | Re-running `RedMercury-Setup-x64.exe /S` over existing install exited `0`; SQLite database persisted cleanly (`DB_PRESERVED=True`). |
| **Uninstallation** | **PASS** | *Not Tested Locally* | `Uninstall Red Mercury.exe /S` removed Start Menu shortcut (`Red Mercury.lnk`) and Desktop shortcut (`Red Mercury.lnk`) while preserving user data. |

---

## 4. macOS Test Matrix

**Test Host Status:** No physical Intel (`x64`) or Apple Silicon (`arm64`) macOS runner was available locally; live installation and execution on macOS remain **untested** and gated on `.github/workflows/desktop-release.yml`.

| Matrix Item | Intel macOS (`x64`) | Apple Silicon macOS (`arm64`) | Status Basis |
|---|---|---|---|
| **Fresh Installation (`.dmg`)** | **NOT RUN** | **NOT RUN** | Requires `macos-13` / `macos-14` runner build of `RedMercury-macOS-*.dmg`. |
| **Application Startup** | **NOT RUN** | **NOT RUN** | macOS menu, Keychain `safeStorage`, and DMG drag-install unverified on hardware. |
| **Backend Startup** | **NOT RUN** | **NOT RUN** | Unix `runtime/bin/python3` detection verified in unit tests; unverified in live `.app`. |
| **Login** | **NOT RUN** | **NOT RUN** | Shared React/FastAPI cookie/CSRF auth passes on Windows & tests; unverified on macOS WebKit/Chromium bundle. |
| **Project Import** | **NOT RUN** | **NOT RUN** | Path confinement hardened for `/System`, `/Library`, `~/.ssh`; live `.app` folder picker unverified on macOS. |
| **Vulnerability Scanning** | **NOT RUN** | **NOT RUN** | Pinned SHA-256 URLs for `gitleaks_8.18.2_darwin_x64/arm64` & `python-build-standalone` configured; unexecuted on macOS. |
| **Fix Generation** | **NOT RUN** | **NOT RUN** | Shared offline fallback engine verified on Windows; unverified on macOS bundle. |
| **Docker Verification** | **NOT RUN** | **NOT RUN** | Darwin GUI binary paths, `0o700`/`0o600` workspace perms, & multi-arch `Dockerfile.worker` tested via mocks only. |
| **Report Export** | **NOT RUN** | **NOT RUN** | Shared UI & FastAPI export endpoints verified on Windows; unverified on macOS. |
| **Application Shutdown** | **NOT RUN** | **NOT RUN** | POSIX `-pid` `SIGTERM` group cleanup unit-tested (`electron/security.test.cjs`). |
| **Upgrade** | **NOT RUN** | **NOT RUN** | macOS `~/Library/Application Support/red-mercury` persistence outside `/Applications/Red Mercury.app`. |
| **Uninstallation** | **NOT RUN** | **NOT RUN** | Documented manual `/Applications/Red Mercury.app` removal; unverified on macOS. |

---

## 5. Automated Regression Summary (After Final Code Edits)

- `node --test electron/security.test.cjs`: **17/17 passed** (`672.32ms`)
- `npm --prefix frontend run lint` (`tsc --noEmit`): **0 errors**
- `npm --prefix frontend run test -- --testTimeout=15000`: **7/7 files, 46/46 passed** (`12.47s`)
- `python -m pytest tests/test_phase2_desktop_mode.py tests/test_phase3_desktop_packaging.py tests/test_phase4_local_services.py tests/test_phase5_cross_platform_sandbox.py tests/test_phase6_desktop_security_audit.py -v`: **25/25 passed** (`4.58s`)
- Git working tree verified clean of any unapproved commits or pushes.
