# Red Mercury Desktop — macOS Installation Guide

**Supported Architectures:**
- Apple Silicon (`arm64` / M-series): `RedMercury-macOS-arm64.dmg`
- Intel (`x64`): `RedMercury-macOS-x64.dmg`

*(Choose the DMG matching **About This Mac -> Chip / Processor**.)*

---

## 1. Prerequisites

- **Zero External Language Runtimes Needed:** Each `.app` bundle includes its architecture-matched standalone Python `3.12.16` runtime, `gitleaks` `v8.18.2`, `bandit`, `pip-audit`, `semgrep`, and embedded SQLite WAL database.
- **Optional — Docker Desktop for macOS:** Needed only for isolated container fix verification. Ensure Docker Desktop is running before executing patch verification runs, then click **Build Approved Worker Image** inside **Settings -> Local Docker Verification**.

---

## 2. Fresh Installation

1. Download the matching `.dmg` artifact (`RedMercury-macOS-arm64.dmg` for Apple Silicon or `RedMercury-macOS-x64.dmg` for Intel) and verify its SHA-256 digest:
   ```bash
   shasum -a 256 RedMercury-macOS-arm64.dmg
   ```
2. Double-click the `.dmg` file to mount the disk image.
3. Drag **Red Mercury.app** onto the **Applications** shortcut inside the DMG window.
4. Eject the mounted DMG volume cleanly.
5. **First Launch:**
   - For notarized releases: open **Red Mercury** normally from `/Applications`.
   - For unsigned internal evaluation builds: Control-click **Red Mercury.app -> Open**, or allow in **System Settings -> Privacy & Security -> Open Anyway** (never disable System Integrity Protection).
   - When prompted by macOS, allow Keychain access so Electron `safeStorage` can store the `"Red Mercury Safe Storage"` master key in your login Keychain.

---

## 3. Data Storage Locations

- **Application Bundle:** `/Applications/Red Mercury.app`
- **Persistent Application Data (`0700` owner-only directories):**
  `~/Library/Application Support/red-mercury/`
  - `data/redmercury.db` (`0600`) — Embedded SQLite WAL database
  - `data/backups/` — SHA-256 verified `.rmbkp` backup archives
  - `config/app-config.json` & `config/preferences.json` (`0600`)
  - `secrets/desktop-keys.enc` (`0600`) — Encrypted with your macOS Keychain master key
  - `logs/electron.log` — Scrubbed runtime logs

---

## 4. Upgrading

1. Quit **Red Mercury** (`Cmd+Q`).
2. Mount the new `.dmg`, drag **Red Mercury.app** to `/Applications`, and click **Replace**.
3. Your SQLite database, workspaces, Keychain keys, and backups remain untouched in `~/Library/Application Support/red-mercury/`. Alembic migrations apply automatically on startup.

---

## 5. Clean Uninstallation

1. Quit **Red Mercury** (`Cmd+Q`).
2. Move `/Applications/Red Mercury.app` to the Trash and empty the Trash.
3. *(Optional full data purge)* Remove local databases, configuration, logs, and Keychain entry:
   ```bash
   rm -rf ~/Library/Application\ Support/red-mercury
   ```
   Optionally open **Keychain Access.app** and delete `"Red Mercury Safe Storage"`.
