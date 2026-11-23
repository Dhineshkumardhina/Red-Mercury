# RED MERCURY — PHASE 3
# WINDOWS AND MACOS DESKTOP DISTRIBUTION REPORT

**Organization:** Xerova Digital Solutions  
**Project:** Red Mercury  
**Packaging Tool:** `electron` `45.0.0` + `electron-builder` `26.15.3`  
**Version:** `1.0.0` (`com.xerova.redmercury`)  

---

## 1. Executive Summary

Phase 3 packaged Red Mercury into a reproducible, self-contained Windows x64 NSIS desktop installer (`RedMercury-Setup-x64.exe`) and completed cross-platform macOS (`x64` and `arm64`) `.dmg` / `.app` packaging, entitlements, notarization hooks, and CI release workflows.

**Honest Build & Signing Status:**
- **Windows x64 (`win32-x64`):** Built locally, verified resource hygiene, smoke-tested bundled Python 3.12.16 + Gitleaks `8.18.2`, and validated silent NSIS install and shortcut/registry uninstallation on Windows. **Signing status: `NotSigned`** (no Authenticode certificate supplied).
- **macOS (`darwin-x64`, `darwin-arm64`):** Packaging configuration (`package.json`), cross-arch bundle staging (`scripts/prepare_desktop_bundle.py`), `.icns` icon (`build/icon.icns`), Hardened Runtime entitlements (`build/entitlements.mac.plist`), conditional notarization hook (`build/notarize.cjs`), Darwin workspace/Docker runtime adaptations, and GitHub Actions macOS build jobs (`.github/workflows/desktop-release.yml`) are implemented. **macOS `.dmg` builds were NOT executed locally because this workstation is Windows x64; macOS installer generation requires running the `build-macos` CI job on `macos-13` (`x64`) and `macos-14` (`arm64`) runners.**

---

## 2. Installer Filenames, Architectures & Package Sizes

| Target Platform | Architecture | Artifact Filename | Build Status | Package Size | SHA-256 |
|---|---|---|---|---|---|
| Windows 10 / 11 | `x64` | `dist-electron/RedMercury-Setup-x64.exe` | **Built & Validated Locally** | `149,862,067 bytes` (`142.92 MB`) | `A1EEC6349B3E916E9F0D7E7859E852AE8ACDBCDB6FC88C618B77FC35430917E2` |
| Windows Unpacked | `x64` | `dist-electron/win-unpacked/` | **Built & Validated Locally** | `488.97 MB` | — |
| macOS Intel | `x64` | `RedMercury-macOS-x64.dmg` (and `.zip`) | Configured for `macos-13` CI runner | Pending CI execution | Pending CI execution |
| macOS Apple Silicon | `arm64` | `RedMercury-macOS-arm64.dmg` (and `.zip`) | Configured for `macos-14` CI runner | Pending CI execution | Pending CI execution |

---

## 3. Packaging Engineering Changes

### 3.1 Relocatable Runtime & Clean Backend Staging (`scripts/prepare_desktop_bundle.py`)
- Replaced host-coupled virtualenv assumptions with pinned `python-build-standalone` (`20261110`, `cpython-3.12.16+20261110`, `install_only_stripped`) verified by SHA-256 per architecture:
  - `win32-x64`: `355ee61b8207b91574491b1c6dc9b0ebb4408fc56bfafe498f3ef439314b52dc`
  - `darwin-x64`: `b78a4c479f1964ec484880bee567568266f68da102269fb93a05fe8716b45f91`
  - `darwin-arm64`: `2f11b8aa3726bdbd87dd9eb76568412faddf4f47e26913fa45d6a2e424972acd`
- Bundles pinned `gitleaks` `v8.18.2` per target architecture with SHA-256 verification.
- Installs strictly `backend/requirements.txt` into the staged standalone runtime, strips `__pycache__` / `*.pyc`, and fails if `pytest`, `locust`, or `pytest-asyncio` are present.
- Copies `backend/` cleanly into `build/staging/active/backend` while excluding `.env*`, `*.db*`, `*.sqlite*`, `data/`, `tests/`, `requirements-dev.txt`, `pyproject.toml`, `__pycache__/`, and `.pytest_cache/`, with a post-copy assertion confirming zero `.env*` or `*.db*` leakage.

### 3.2 Icons, NSIS, Entitlements & Electron Builder Config
- [`scripts/generate_app_icon.py`](scripts/generate_app_icon.py): Generates `build/icon.png` (512x512), multi-resolution `build/icon.ico` (16–256px), and Apple `build/icon.icns` (`ic07`, `ic08`, `ic09`, `ic10` PNG chunks).
- [`build/installer.nsh`](build/installer.nsh): Terminates running `Red Mercury.exe` processes during upgrades/uninstall (`customInit` / `customUnInit`) and preserves `%APPDATA%\Red Mercury` across upgrades and default uninstall (`deleteAppDataOnUninstall: false`).
- [`build/entitlements.mac.plist`](build/entitlements.mac.plist): Configures macOS Hardened Runtime (`allow-jit`, `allow-unsigned-executable-memory`, `disable-library-validation` for bundled Python C-extensions, `network.client`, `network.server`, `files.user-selected.read-write`).
- [`build/notarize.cjs`](build/notarize.cjs): Electron Builder `afterSign` hook that cleanly skips notarization when Apple Developer credentials (`APPLE_API_KEY` / `APPLE_ID`) are absent, and invokes `xcrun notarytool` + `stapler` when provided.
- [`package.json`](package.json): Configures `extraResources` (`backend`, `runtime`, `bin`), `nsis` (`RedMercury-Setup-${arch}.${ext}`, Start Menu & Desktop shortcuts, per-user install with directory selection), `mac` (`RedMercury-macOS-${arch}.${ext}`, `dmg` + `zip`, `x64` + `arm64`), and drag-to-`/Applications` DMG layout.

### 3.3 Cross-Platform Runtime Compatibility Fixes
- [`electron/main.cjs`](electron/main.cjs): Passes `REDMERCURY_BIN_DIR` (`path.join(rootDir, 'bin')`) into the supervised backend environment.
- [`backend/app/scanner/base.py`](backend/app/scanner/base.py): Adds `REDMERCURY_BIN_DIR` and `os.path.dirname(sys.executable)` to `get_scanner_search_paths()` so bundled `gitleaks`, `bandit`, and `pip-audit` resolve reliably on both Windows and macOS `.app` bundles.
- [`backend/app/verification/workspace.py`](backend/app/verification/workspace.py): Adds a `platform.system() == "Darwin"` owner-only (`0o700` / `0o600`, symlink-skipping) branch for macOS Docker Desktop mounts while preserving strict Linux POSIX ACL behavior.
- [`backend/app/verification/sandbox.py`](backend/app/verification/sandbox.py): Adds `resolve_docker_binary()` fallback lookup (`/opt/homebrew/bin/docker`, `/usr/local/bin/docker`, `/Applications/Docker.app/Contents/Resources/bin/docker`, and Windows default path) when Finder/GUI-launched apps omit Docker from `PATH`.
- [`frontend/index.html`](frontend/index.html): Removed external Google Fonts `<link>` tags so the desktop UI operates cleanly under offline CSP restrictions.
- [`.github/workflows/desktop-release.yml`](.github/workflows/desktop-release.yml): Multi-OS CI workflow (`windows-latest`, `macos-13`, `macos-14`) with least-privilege permissions, bundle leakage checks, and SHA-256 artifact generation.

---

## 4. Build Logs (Observed Locally)

### 4.1 Icon Generation & Windows Staging (`scripts/generate_app_icon.py` + `scripts/prepare_desktop_bundle.py --target win32-x64`)
```text
Generated PNG icon: C:\PROJECTS\dhina projects\Red Mercury\Red Mercury\build\icon.png
Generated Windows ICO icon: C:\PROJECTS\dhina projects\Red Mercury\Red Mercury\build\icon.ico
Generated macOS ICNS icon: C:\PROJECTS\dhina projects\Red Mercury\Red Mercury\build\icon.icns
[bundle] Downloading https://github.com/astral-sh/python-build-standalone/releases/download/20261110/cpython-3.12.16%2B20261110-x86_64-pc-windows-msvc-install_only_stripped.tar.gz...
[bundle] Verified SHA-256 for python-win32-x64-20261110.tar.gz: 355ee61b8207b91574491b1c6dc9b0ebb4408fc56bfafe498f3ef439314b52dc
[bundle] Installing production Python requirements into C:\PROJECTS\dhina projects\Red Mercury\Red Mercury\build\staging\win32-x64\runtime...
Ignoring semgrep: markers 'sys_platform != "win32"' don't match your environment
...
Successfully installed ... fastapi-0.165.0 ... uvicorn-0.54.0 ... sqlalchemy-2.1.9 ... alembic-1.20.1 ... bandit-1.9.4 ... pip-audit-2.10.1 ...
[bundle] Verified production Python runtime ready at C:\PROJECTS\dhina projects\Red Mercury\Red Mercury\build\staging\win32-x64\runtime
[bundle] Downloading https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_windows_x64.zip...
[bundle] Verified SHA-256 for gitleaks-8.18.2-win32-x64.zip: aa19543417c668b15e89b3357413099d81a75029a8ebbaec5034b7c8cc33c7e5
[bundle] Verified gitleaks.exe placed at C:\PROJECTS\dhina projects\Red Mercury\Red Mercury\build\staging\win32-x64\bin\gitleaks.exe
[bundle] Clean backend staged at C:\PROJECTS\dhina projects\Red Mercury\Red Mercury\build\staging\win32-x64\backend
[bundle] Active staging synchronized at C:\PROJECTS\dhina projects\Red Mercury\Red Mercury\build\staging\active for target win32-x64
```

### 4.2 Frontend Desktop Build & Electron Builder NSIS Packaging (`npm run build:desktop` + `electron-builder --win nsis --x64`)
```text
> vite build
vite v6.4.5 building for production...
✓ 1644 modules transformed.
dist/index.html                   1.28 kB │ gzip:   0.55 kB
dist/assets/index-C60KWnKO.css   61.33 kB │ gzip:  11.19 kB
dist/assets/ui-D7BtIW54.js       24.55 kB │ gzip:   5.08 kB
dist/assets/vendor-JCugeQTP.js   52.99 kB │ gzip:  18.50 kB
dist/assets/index-BRLv93hi.js   541.14 kB │ gzip: 136.01 kB
✓ built in 3.73s
  • electron-builder  version=26.15.3 os=10.0.26300
  • packaging       platform=win32 arch=x64 electron=45.0.0 appOutDir=dist-electron\win-unpacked
  • building        target=nsis file=dist-electron\RedMercury-Setup-x64.exe archs=x64 oneClick=false perMachine=false
  • building block map  blockMapFile=dist-electron\RedMercury-Setup-x64.exe.blockmap
```

---

## 5. Signing Status

- **Windows (`RedMercury-Setup-x64.exe`):** `Get-AuthenticodeSignature` confirmed **`Status=NotSigned`**, **`Subject=<empty>`**. `electron-builder` invoked `signtool` pass-through only; without `CSC_LINK` / `WIN_CSC_LINK`, executables remain unsigned. Ready for future Authenticode signing via `CSC_LINK` + `CSC_KEY_PASSWORD` (or Azure Trusted Signing) in CI.
- **macOS (`RedMercury-macOS-x64.dmg`, `RedMercury-macOS-arm64.dmg`):** Unsigned by default. Ready for Developer ID Application certificate (`CSC_LINK` / `MAC_CSC_LINK`) and Apple notarization (`APPLE_API_KEY`, `APPLE_API_KEY_ID`, `APPLE_API_ISSUER` or `APPLE_ID` + `APPLE_APP_SPECIFIC_PASSWORD` + `APPLE_TEAM_ID`) via `build/notarize.cjs`.

---

## 6. Installation & Runtime Validation (Windows x64)

- **Resource Hygiene Scan (`dist-electron/win-unpacked/resources`):** `RESOURCE_LEAKS=0` (zero `.env*`, `*.db*`, `tests/`, `data/`, `__pycache__/`, or `.pytest_cache/` files bundled).
- **Bundled Python + FastAPI Smoke Test:** `dist-electron\win-unpacked\resources\runtime\python.exe` successfully loaded `fastapi`, `uvicorn`, `sqlalchemy`, `alembic`, and `app.main` -> output `BUNDLED_PYTHON_OK 3.12.16 Red Mercury API`.
- **Bundled Gitleaks Smoke Test:** `dist-electron\win-unpacked\resources\bin\gitleaks.exe version` -> `8.18.2`.
- **Silent NSIS Install (`/S /D=<temp>`):**
  - Exit code: `0`
  - Verified deployed artifacts: `Red Mercury.exe`, `resources/runtime/python.exe`, `resources/bin/gitleaks.exe`, `Uninstall Red Mercury.exe`
  - Verified shortcuts: Start Menu (`Red Mercury.lnk` = `True`) and Desktop (`Red Mercury.lnk` = `True`)
- **Silent Uninstall Cleanup:** Uninstaller removed Start Menu shortcut, Desktop shortcut, and `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\*` entry cleanly while preserving `%APPDATA%\Red Mercury` per policy.

### macOS Clean Uninstall Instructions (Documented for Users)
1. Quit **Red Mercury** (`Cmd+Q`).
2. Drag `/Applications/Red Mercury.app` to the Trash.
3. Optional full data purge: delete `~/Library/Application Support/Red Mercury` and `~/Library/Logs/Red Mercury`.

---

## 7. Automated Test Results (After Final Edits)

| Suite | Command | Result |
|---|---|---|
| Electron Security & Lifecycle | `node --test electron/security.test.cjs` | **15/15 passed** (`633.07ms`) |
| Frontend TypeScript | `npm --prefix frontend run lint` (`tsc --noEmit`) | **0 errors** |
| Frontend Unit & UI Tests | `npm --prefix frontend run test` (`vitest run`) | **7/7 files, 46/46 passed** |
| Backend & Phase 3 Packaging Tests | `python -m pytest tests/test_phase2_desktop_mode.py tests/test_phase3_desktop_packaging.py tests/test_verification_security_hardening.py tests/test_sandbox.py tests/test_health.py -v` | **57 passed, 3 skipped** *(skipped: 3 Linux/Docker-engine integration tests on Windows host without running Docker Linux daemon)* |

---

## 8. Remaining Limitations & Blockers

1. **macOS `.dmg` Execution Pending macOS CI Runner:** Because this environment runs Windows x64, `RedMercury-macOS-x64.dmg` and `RedMercury-macOS-arm64.dmg` have not yet been compiled on Apple hardware. Triggering `.github/workflows/desktop-release.yml` on GitHub-hosted `macos-13` and `macos-14` runners is required to produce and verify the `.dmg` installers.
2. **Code Signing & Notarization Certificates Not Configured:** Unsigned Windows builds will trigger Microsoft Defender SmartScreen prompts on external machines, and unsigned macOS builds will require user Gatekeeper override until Authenticode and Apple Developer ID + notarization secrets are configured.
3. **Semgrep on Windows:** `backend/requirements.txt` pins `semgrep>=1.65.0; sys_platform != "win32"`, so `semgrep` is bundled inside macOS builds and omitted on Windows x64 (which continues to use `gitleaks`, `bandit`, and `pip-audit`).
4. **Git State:** Zero files were staged, committed, or pushed (`git status` remains uncommitted per Phase 3 rules).
