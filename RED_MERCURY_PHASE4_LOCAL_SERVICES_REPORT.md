# RED MERCURY — PHASE 4
# LOCAL DATABASE, BACKGROUND SERVICES AND OFFLINE OPERATION REPORT

**Organization:** Xerova Digital Solutions  
**Project:** Red Mercury  
**Target Platforms:** Windows 10/11 (`x64`), macOS Intel (`x64`), macOS Apple Silicon (`arm64`)  

---

## 1. Executive Summary

Phase 4 verified and hardened Red Mercury's local persistence, durable background job queue, startup/crash initialization, deterministic offline boundaries, and online-consistent local backup/recovery workflows so the desktop application runs independently without requiring a hosted backend, external PostgreSQL server, or Redis daemon.

---

## 2. Database Strategy Evaluation & Verification

### 2.1 Evaluated Deployment Options
| Option | Assessment | Decision |
|---|---|---|
| **Bundled PostgreSQL** | Adds ~150–300 MB per platform/arch, Windows service permissions, macOS `SHMMAX` / shared-memory tuning, `initdb` lifecycle, and port management overhead for single-user desktop. | Rejected for embedded desktop default |
| **Managed Local PostgreSQL Service** | Requires separate OS package install (Homebrew / EDB installer) or admin elevation; breaks self-contained desktop installation. | Supported optionally via `DATABASE_URL`; not required |
| **Embedded SQLite (WAL + Foreign Keys)** | Zero-install, single-file storage under OS user-data directory (`%APPDATA%\Red Mercury\data\redmercury.db` on Windows; `~/Library/Application Support/Red Mercury/data/redmercury.db` on macOS). | **Selected & Verified for Desktop** (PostgreSQL retained unchanged for server deployments) |

### 2.2 PostgreSQL Parity & Compatibility Verification
All SQLAlchemy models (`backend/app/models/*.py`) and all 14 Alembic migrations (`0001` through `0014`) were audited and verified on SQLite:
- **Zero PostgreSQL-only column types:** Models use portable `String(64)` UUID primary keys and `Text` JSON serialization rather than `JSONB`, `ARRAY`, `UUID`, or `INET`.
- **SQLite DDL compatibility:** Migrations `0002`, `0003`, `0004`, `0008`, `0009`, `0010`, and `0011` use `op.batch_alter_table(...)` cleanly.
- **Model completeness fix:** Added missing `RefreshTokenSession` export in [`backend/app/models/__init__.py`](backend/app/models/__init__.py) so `Base.metadata` and Alembic inspections always include `refresh_token_sessions`.
- **Transaction & Concurrency Hardening ([`backend/app/db/session.py`](backend/app/db/session.py)):** Enables `PRAGMA journal_mode=WAL`, `PRAGMA synchronous=NORMAL`, `PRAGMA busy_timeout=10000`, `PRAGMA cache_size=-64000`, and `PRAGMA foreign_keys=ON` on every connection.
- **Full Migration Parity Test:** `alembic upgrade head` executed from an empty file-backed SQLite database created all core tables through `0014_add_durable_jobs_and_outbox`.

---

## 3. Redis Evaluation & Durable Background Services Architecture

### 3.1 Essential vs Optional Redis Usage Audit
Source inspection across `backend/app` confirmed Redis is used in only two components:
1. **HTTP Rate Limiting ([`backend/app/core/security.py`](backend/app/core/security.py)):** `DistributedRateLimiter` uses Redis Lua sliding windows only when `REDIS_URL` is configured, falling back automatically to thread-safe in-memory `SlidingWindowRateLimiter` for single-host desktop instances bound strictly to `127.0.0.1`.
2. **Job Queue Dispatch Wake-Up ([`backend/app/core/jobs.py`](backend/app/core/jobs.py)):** Redis (`LPUSH`/`LPOP` on `redmercury:jobs:queue`) is strictly an optional wake-up hint. Authoritative job state, transactional outbox events (`job_outbox_events`), idempotency keys, quota/concurrency locks (`active_job_slots`), heartbeats, lease fencing tokens, exponential backoff retries, and cancellation live durably in SQLite/PostgreSQL.

### 3.2 Preserved Durable Queue Guarantees (Verified Without Redis)
- **Dual-dialect atomic claiming (`claim_durable_job_by_id`, `claim_next_durable_job`):** Uses `FOR UPDATE SKIP LOCKED` on PostgreSQL and atomic conditional `UPDATE` CAS with `lease_token` fencing on SQLite.
- **Lease recovery & reconciliation (`reconcile_jobs_on_startup`, `recover_expired_job_leases`):** Recovers expired worker leases on API or worker startup and transitions overdue jobs cleanly to `retrying` or terminal failure.
- **Bug Fixed During Phase 4 Verification:** [`reconcile_jobs_on_startup`](backend/app/core/jobs.py) previously passed `actor_id="system"` to `record_audit_event()`, which violated the `audit_events.actor_id -> users.id` foreign key under SQLite `PRAGMA foreign_keys=ON` and PostgreSQL FK checks. Changed to `actor_id=None` with `metadata={"actor": "system", ...}`, preserving FK integrity while recording `JOB_RECONCILIATION_COMPLETED` audit events cleanly.

---

## 4. First-Run Initialization & Interrupted Startup Recovery

Implemented [`initialize_local_database()`](backend/app/core/backup.py) (called during FastAPI lifespan in [`backend/app/main.py`](backend/app/main.py)) and Electron storage recovery in [`electron/security.cjs`](electron/security.cjs) & [`electron/main.cjs`](electron/main.cjs):
1. **Stale `.tmp` Cleanup:** Purges leftover `.tmp`, `.tmp.zip`, and `.restore_tmp` staging artifacts across `data/`, `backups/`, `config/`, and `worker_tmp/` left behind by interrupted runs.
2. **Pre-Session Restore Application:** Applies any SHA-256-verified `pending_restore.rmbkp` before SQLAlchemy ORM sessions open, preventing Windows WAL handle conflicts across FastAPI and `worker.py`.
3. **Database Integrity Gate:** Executes `PRAGMA quick_check` on existing SQLite files and fails explicitly rather than silently operating on corrupt files.
4. **Dynamic Alembic Alignment:** Escapes SQLAlchemy URL percent-encoding (`%` -> `%%`) for Python `ConfigParser` (fixing Windows drive-colon `C%3A` and space `%20` path crashes), creates missing tables if first-run, dynamically queries `ScriptDirectory.get_current_head()`, and runs `stamp("head")` or `upgrade("head")`.
5. **Encrypted Key & Config Creation:** Electron creates OS-appropriate directories (`0o700` on macOS), records `initializedAt` / `firstRunCompleted` in `config/app-config.json`, initializes `config/preferences.json`, and encrypts `SECRET_KEY` + `ENCRYPTION_KEY` via Electron `safeStorage` (DPAPI on Windows, Keychain on macOS) into `secrets/desktop-keys.enc`.

---

## 5. Offline Mode & Capability Distinction

Added `/api/v1/system/capabilities` ([`backend/app/api/v1/endpoints/system.py`](backend/app/api/v1/endpoints/system.py)) and frontend UI surfacing in [`SettingsPage.tsx`](frontend/src/pages/SettingsPage.tsx), [`AiSecurityAnalyzerScreen.tsx`](frontend/src/components/analyzer/AiSecurityAnalyzerScreen.tsx), and [`AiSecurityAnalystCard.tsx`](frontend/src/components/findings/AiSecurityAnalystCard.tsx):

| Capability Domain | Offline Behavior | How UI / API Distinguishes It |
|---|---|---|
| **Offline Security Scanning** | **Available locally** (`gitleaks`, `bandit`, `pip-audit` offline DB/bounded check, secret detector, deterministic rule analyzer, ZIP & local folder ingestion) | Marked `AVAILABLE LOCALLY` in Runtime Capabilities |
| **AI Features (Gemini API)** | **Disabled in Offline Mode** (`OFFLINE_MODE=true`); requests fall back explicitly to `redmercury-deterministic-fallback-v1.0` | API returns `available: false`, `status: "disabled_offline"`; Patch Analyzer & Finding Card badge show `Offline Deterministic Engine` (never implying cloud AI ran) |
| **GitHub & Remote Git** | **Blocked clearly when Offline** (`publish` endpoint + desktop HTTPS Git clone return 403 policy error explaining internet requirement) | Marked `REQUIRES INTERNET` in Settings; guides operators to ZIP/local ingestion |
| **Local Docker Verification** | **Fail-closed local daemon probe** (`check_docker_availability`) | Marked `DAEMON READY` or `UNAVAILABLE (FAIL-CLOSED)` with exact probe reason |

---

## 6. Local Backup & Recovery Engine

Implemented [`backend/app/core/backup.py`](backend/app/core/backup.py), `/api/v1/system/backups*` endpoints ([`system.py`](backend/app/api/v1/endpoints/system.py)), and interactive controls in [`SettingsPage.tsx`](frontend/src/pages/SettingsPage.tsx):
- **WAL-Consistent Snapshots:** Uses Python `sqlite3.Connection.backup()` for atomic online backups while API and worker connections remain active.
- **Configuration Included / Secrets Excluded:** Packs `config/app-config.json` and `config/preferences.json` when available via `REDMERCURY_CONFIG_DIR`; explicitly excludes `secrets/desktop-keys.enc`, `.env*`, and raw keys.
- **Integrity Validation (`.rmbkp` Format v1.0):** Computes SHA-256 digests and exact sizes for every payload in `manifest.json`; `verify_backup_archive()` blocks Zip-Slip/symlinks, checks every SHA-256 + byte length, and executes `PRAGMA integrity_check` + table checks on the extracted DB.
- **Safe Multi-Process & Direct Restore:**
  - *Staged Restart Restore (desktop default):* Creates a `pre-restore-safety-*.rmbkp` snapshot, stages `pending_restore.rmbkp` + checksum sidecar, and Electron triggers `window.electronAPI.restartBackend()` so `initialize_local_database()` swaps the DB cleanly before API/worker open WAL handles (preventing Windows `WinError 32` locks).
  - *Direct Restore:* Disposes SQLAlchemy engine pools, removes stale `-wal`/`-shm` sidecars, and restores atomically in single-process contexts.

---

## 7. Platform Compatibility Architecture Summary

| Concern | Windows 10/11 (`x64`) | macOS (`x64` & `arm64`) |
|---|---|---|
| **App Data & DB Root** | `%APPDATA%\Red Mercury\data\redmercury.db` | `~/Library/Application Support/Red Mercury/data/redmercury.db` (`0o700`) |
| **Secret Storage** | Electron `safeStorage` (Windows DPAPI) -> `secrets\desktop-keys.enc` | Electron `safeStorage` (macOS Keychain) -> `secrets/desktop-keys.enc` (`0o600`) |
| **URL Percent Escaping in Alembic** | Escapes `C%3A` and `%20` -> `%%` in `backup.py` & `alembic/env.py` | Escapes `%20` (e.g. `Application%20Support`) -> `%%` |
| **Process / Worker Shutdown** | `taskkill /pid <pid> /T /F` | Detached process-group `SIGTERM` (`kill(-pid, SIGTERM)`) |
| **Docker Desktop Integration** | TCP/Named-pipe CLI + no POSIX ACL required | Owner-only `0o700`/`0o600` + GUI binary fallback paths |

---

## 8. Verification Results (After Final Edits)

- **Electron Security & Desktop Lifecycle (`node --test electron/security.test.cjs`):** **15/15 passed**.
- **Frontend TypeScript (`npm --prefix frontend run lint`):** **0 errors**.
- **Frontend Unit & UI Tests (`npm --prefix frontend run test`):** **7/7 files, 46/46 passed**.
- **Frontend Desktop Production Build (`npm run build:desktop`):** **Succeeded cleanly** (`vite build`).
- **Backend Phase 4 & Cross-Phase Regression (`python -m pytest tests/test_phase4_local_services.py tests/test_phase2_desktop_mode.py tests/test_phase3_desktop_packaging.py tests/test_health.py tests/test_ingestion.py tests/test_github_integration.py tests/test_phase6_durable_job_execution.py -v`):** **56 passed, 3 skipped** *(skipped tests require optional live external Docker engine, `REDIS_URL`, or `TEST_POSTGRES_URL`)*.
- **Git State:** Uncommitted per Phase 4 instructions (zero commits or pushes).
