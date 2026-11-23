# Red Mercury Desktop — Windows Installation Guide

**Supported Platforms:** Windows 10 (64-bit `x64`), Windows 11 (64-bit `x64`)  
**Installer Artifact:** `RedMercury-Setup-x64.exe`  

---

## 1. Prerequisites

- **No Python, Node.js, PostgreSQL, or Redis installation required:** Red Mercury bundles its own isolated Python `3.12.16` runtime, `gitleaks` `v8.18.2`, `bandit`, `pip-audit`, and SQLite WAL database engine.
- **Optional — Docker Desktop (WSL2 Backend):** Required only if you plan to run isolated container fix verifications (`VerificationPage`). Static/secret scanning and deterministic offline analysis work without Docker.
  1. Install Docker Desktop for Windows with the **WSL2 Linux engine** enabled.
  2. Start Docker Desktop before triggering containerized verification.
  3. Build the approved worker container once: open **Settings -> Local Docker Verification** inside Red Mercury and click **Build Approved Worker Image**.

---

## 2. Fresh Installation

1. Download `RedMercury-Setup-x64.exe` from the authorized Xerova Digital Solutions release channel and verify its published SHA-256 checksum:
   ```powershell
   Get-FileHash .\RedMercury-Setup-x64.exe -Algorithm SHA256
   ```
2. Double-click `RedMercury-Setup-x64.exe`.
   - *Unsigned Preview Notice:* Prior to Authenticode certificate signing, Windows Defender SmartScreen may display *"Windows protected your PC"*. Verify the exact SHA-256 hash before clicking **More info -> Run anyway**.
3. Choose the installation directory (defaults to per-user `%LOCALAPPDATA%\Programs\Red Mercury` without requiring Administrator elevation).
4. Keep **Create Desktop Shortcut** and **Create Start Menu Shortcut** checked, then click **Install**.

### Silent / Enterprise CLI Installation
```powershell
Start-Process -FilePath ".\RedMercury-Setup-x64.exe" -ArgumentList "/S", "/D=C:\Path\To\RedMercury" -Wait
```

---

## 3. Data Storage Locations

- **Application Binaries:** `%LOCALAPPDATA%\Programs\Red Mercury` (or custom `/D=` folder)
- **Database, Backups, Config & Encrypted Keys:** `%APPDATA%\red-mercury\`
  - `data\redmercury.db` — Local SQLite WAL database
  - `data\backups\` — Integrity-checked `.rmbkp` archives
  - `config\app-config.json` & `config\preferences.json` — Preferences and initialization settings
  - `secrets\desktop-keys.enc` — Installation keys encrypted using your Windows user DPAPI session
  - `logs\electron.log` — Scrubbed application diagnostics log

---

## 4. Upgrading

1. Close **Red Mercury** cleanly from the application window (or system task).
2. Run the newer `RedMercury-Setup-x64.exe` installer over the existing directory.
   - The NSIS installer stops lingering `Red Mercury.exe` processes (`customInit`), updates application binaries, and **preserves** `%APPDATA%\red-mercury` data and encrypted keys automatically.
   - Database schema migrations (Alembic) run automatically on next launch.

---

## 5. Uninstallation

1. Open **Windows Settings -> Apps -> Installed apps -> Red Mercury -> Uninstall**, or run `"<InstallDir>\Uninstall Red Mercury.exe"`.
2. Application binaries, Start Menu shortcut, Desktop shortcut, and Uninstall registry entries are removed.
3. User scan data and backups in `%APPDATA%\red-mercury` are intentionally preserved across uninstalls. To purge all local data completely, delete `%APPDATA%\red-mercury` manually after uninstalling.
