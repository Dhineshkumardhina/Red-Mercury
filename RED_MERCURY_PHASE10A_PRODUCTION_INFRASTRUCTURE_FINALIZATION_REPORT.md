# RED MERCURY — PHASE 10A
# PRODUCTION INFRASTRUCTURE ARCHITECTURE, HOST SELECTION & DEPLOYMENT READINESS REPORT

**Product:** Red Mercury — Enterprise Application Security & Automated Fix Verification Engine  
**Organization:** Xerova Digital Solutions  
**Repository:** `https://github.com/Dhineshkumardhina/Red-Mercury`  
**Verified Release Candidate Commit:** `c1fa7b12f7119e41cd3e3a7fecd9af6ed85e1b7f` (`main`, GitHub Actions Run `#12` / `45036541551` — all 5 jobs passed, `661/661` backend tests)  
**Audit Date (UTC):** `2026-11-23`  
**Phase Scope:** Read-only inspection and production infrastructure architecture planning (**zero cloud, DNS, database, or Git mutations performed**).

---

## 1. Existing Infrastructure Assessment

### 1.1 Codebase & Container Manifest Baseline (Observed)
- **[docker-compose.prod.yml](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/docker-compose.prod.yml):** Defines a 6-service production topology across 3 bridge networks (`redmercury_internal` `internal: true`, `redmercury_worker_isolated` `internal: true`, `redmercury_public`):
  1. `postgres` (`postgres:16-alpine` pinned SHA-256, `cap_drop: ALL`, `postgres_data` persistent volume, `2.0 CPU / 4096M`)
  2. `redis` (`redis:7-alpine` pinned SHA-256, `cap_drop: ALL`, `read_only: true`, ephemeral `--save "" --appendonly no --maxmemory 128mb`, `0.5 CPU / 256M`)
  3. `api` (`Dockerfile.api`, UID `10001`, `cap_drop: ALL`, `read_only: true`, `/tmp` tmpfs, `workspace_data:/app/data/workspaces`, `JOB_DISPATCH_MODE=queue_only`, `2.0 CPU / 2048M`)
  4. `worker` (`Dockerfile.worker`, UID `10002`, `cap_drop: ALL`, `read_only: true`, `workspace_data:/sandbox/workspaces:ro`, `worker_temp:/sandbox/temp`, `/tmp` tmpfs, `2.0 CPU / 2048M`, `pids: 100`)
  5. `frontend` (`Dockerfile.frontend`, `nginx:1.27-alpine-slim` pinned SHA-256, UID `nginx`, static Vite SPA + security headers)
  6. `nginx` (`nginx:1.27-alpine` pinned SHA-256, [nginx/production.conf](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/nginx/production.conf), TLS 1.2/1.3 edge + HTTP->HTTPS 301 + rate limiting + CSP/HSTS/XFO)
- **Container Runtime Security & Socket Findings (Observed in [sandbox.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/verification/sandbox.py) & [Dockerfile.worker](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/Dockerfile.worker)):**
  - `docker-compose.prod.yml` exposes **zero** Docker sockets (`/var/run/docker.sock`) to `postgres`, `redis`, `api`, `frontend`, `nginx`, or `worker`.
  - `run_isolated_verification_command()` spawns ephemeral sibling containers (`redmercury-sbx-*`) via `docker run --rm --network=none --user=10002:10002 --cpus=1.0 --memory=512m --memory-swap=512m --pids-limit=50 --security-opt=no-new-privileges:true --cap-drop=ALL --read-only --tmpfs=/tmp:rw,noexec,nosuid,size=64m -v <ws>:/workspace:rw redmercury-worker:latest`, explicitly omitting host secrets and Docker sockets (`execute_in_container`).
  - **Architectural Operational Note:** Inside `docker-compose.prod.yml` as written, `worker` itself runs inside a rootless/hardened container **without** the `docker` binary or Docker daemon socket, and `TMPDIR` inside `worker` (`tmpfs: /tmp`) is container-private. Therefore, for `SANDBOX_BACKEND="docker"` (`SANDBOX_FAIL_CLOSED=true` enforced in strict mode) to execute dynamically in production without weakening sandboxes, the worker orchestrator on the Linux host must have scoped Docker CLI/engine access (e.g., dedicated host `systemd` worker service or scoped `docker-socket-proxy` sidecar reachable **only** by the worker on a private socket/network) **and** a host-shared `TMPDIR` bind mount (`/var/lib/redmercury/verify-tmp:/var/lib/redmercury/verify-tmp`) matching host & worker paths so `-v <ws>:/workspace:rw` mounts cleanly into the sibling `redmercury-sbx-*` container.

### 1.2 Existing Cloud Resources & Gap Summary (Observed Read-Only)
- **Railway Project `red-mercury` (`daee8a93-1b1d-4a00-b5f4-96d4d06abaff`, env `production`):**
  - `red-mercury-api` (`520296d0-...`): Online at `https://red-mercury-api-production.up.railway.app`, running stale `2026-11-21` image (`4bb4c538-...`, `/live` & `/ready` `200 OK`, `/api/v1/health/jobs` **`HTTP 404`**), only 8 env var keys configured (`APP_ENV`, `CORS_ORIGINS`, `DATABASE_URL`, `DEBUG`, `DOCS_ENABLED`, `LOG_FORMAT_JSON`, `OFFLINE_MODE`, `SECRET_KEY`).
  - `Postgres` (`85575a05-...`): Online (`postgres-ssl:18`, 1 replica in `iad`, `500 MB` volume, no TCP proxy enabled, no buckets).
  - Missing on Railway: Redis service, `red-mercury-worker` service, Docker daemon capability for `redmercury-worker:latest` fix verification containers, `REDIS_URL`, `RATE_LIMIT_FAIL_OPEN=false`, `GITHUB_WEBHOOK_SECRET`, `GIT_EGRESS_PROXY_URL`, and same-origin frontend integration.
- **Cloudflare Workers URL (`https://red-mercury.dhineshkumardhina18.workers.dev/`):** Serves HTTP `200` SPA bundle. Direct Cloudflare API mutation/inspection via MCP failed (`Forbidden: rejected by transport`).
- **Recommendation on Existing Services (Stage 4):**
  - **Cloudflare:** **RETAIN** as DNS + DDoS/WAF edge proxy (`DNS` `A`/`AAAA` + `Full (Strict)` TLS) pointing custom domain (e.g. `redmercury.xerova.com` or chosen production domain) to the Linux Docker host Nginx ingress.
  - **Docker Linux Host (All-in-One Hardened Compose):** Run **Nginx TLS edge + Frontend SPA + FastAPI API + Redis 7 + Worker/Docker Sandbox + PostgreSQL 16** together on one dedicated Linux host initially. Retaining external Railway Postgres across public TCP proxy adds `10–80ms+` per query and breaks internal-only (`internal: true`) database network isolation; migrating/consolidating Postgres onto the internal bridge network is cleaner, faster, safer, and cheaper.
  - **Railway `red-mercury-api` & `Postgres` / `workers.dev`:** **RETIRE** (only **after** DNS cutover, data migration/verification, and smoke tests succeed on the new production host — do not delete beforehand).

---

## 2. Recommended Production Architecture

```text
Internet Clients (Browser / CLI / GitHub Webhooks)
        |
   DNS / Edge WAF (Cloudflare DNS + TLS Full Strict)
        |
   HTTPS :443 (Port 80 -> 301 HTTPS; /live|/ready health HTTP allowed)
        |
   Nginx Reverse Proxy (nginx/production.conf — Single Origin)
     |                                    |
     |-- / -----------------------------> Frontend SPA (redmercury_frontend :8080)
     |-- /api/ -------------------------> FastAPI API  (redmercury_api :8000, UID 10001, ro rootfs)
                                               |
                    +--------------------------+--------------------------+
                    |                          |                          |
             (redmercury_internal: internal:true — zero internet egress)  |
                    |                          |                          |
             PostgreSQL 16               Redis 7                   Shared Volume:
       (postgres_data SSD vol)     (ephemeral rate-limit/       workspace_data (rw API, ro Worker)
                                      job outbox queue)                   |
                                                                          v
                                                         Worker Orchestrator (UID 10002 / host-scoped)
                                                           - Consumes DurableJobs from Postgres + Redis
                                                           - Spawns sibling Docker sandboxes ONLY:
                                                             `docker run --network=none --cap-drop=ALL
                                                              --read-only --pids-limit=50 --user 10002:10002
                                                              --tmpfs /tmp:rw,noexec,nosuid,size=64m`
                                                           - Zero Docker socket inside API, Nginx, Frontend,
                                                             Postgres, Redis, or any redmercury-sbx-* sandbox!
```

### Design Invariants Preserved
1. **Single Application Origin:** Nginx serves `/` (SPA) and `/api/` (FastAPI) under the exact same HTTPS hostname, guaranteeing `SameSite=Lax` `__Host-` / `HttpOnly` cookies (`access_token`, `refresh_token`) and double-submit `rm_csrf_token` work natively without weakening CORS or `COOKIE_SAMESITE`.
2. **Untrusted Execution Isolation:** API container has **zero** Docker daemon/socket access. Untrusted repository verification tests always run in ephemeral `--network=none --cap-drop=ALL --read-only` UID `10002` Docker containers with purged environment secrets (`get_sanitized_runner_env()`).
3. **Egress & SSRF Defense:** Internal networks isolate Postgres and Redis from public internet. Direct Git URL cloning remains fail-closed unless an approved SSRF-filtering forward proxy container (`GIT_EGRESS_PROXY_URL`, e.g., `smokescreen` on a dedicated egress network) is added; ZIP upload ingestion works standalone without egress.

---

## 3. Minimum Suitable Host Requirements

| Resource | Minimum Viable Spec (MVP / Pilot) | Recommended Growth Spec | Justification from `docker-compose.prod.yml` & CI |
| :--- | :--- | :--- | :--- |
| **vCPU** | **2 vCPU** (shared modern x86_64) | **4 vCPU** (dedicated/shared x86_64) | Runs Nginx + Frontend + API (2 Gunicorn workers) + Postgres + Redis + Worker + 1–2 concurrent `1.0` CPU sandbox containers; x86_64 matches SHA-256-verified `gitleaks_8.18.2_linux_x64`. |
| **RAM** | **4 GB RAM** (+ 2 GB swap optional fallback) | **8 GB RAM** | Postgres (~512 MB baseline) + API (~300–500 MB) + Worker (~250 MB) + Semgrep/Bandit peak (~500–800 MB) + Sandbox container (`512m` limit). 4 GB is minimum floor; **8 GB strongly recommended** for concurrent verification + Semgrep scans without OOM. |
| **SSD Storage** | **40 GB NVMe SSD** | **80 GB NVMe SSD** | OS (~5 GB) + Docker images (`api` + `worker` + `frontend` + `postgres` + `redis` + `nginx` ≈ 4–6 GB) + Postgres WAL/data + workspaces + local encrypted daily backups. |
| **OS & Kernel** | **Ubuntu 24.04 LTS x86_64** | **Ubuntu 24.04 LTS x86_64** | Full cgroups v2, Linux namespaces, AppArmor, overlay2, and native POSIX `system.posix_acl_access` support on ext4/tmpfs for `workspace.py` UID `10002` ACLs. |
| **Docker Runtime** | **Docker Engine 26+ & Compose v2 Plugin** | Same | Supports `--cap-drop=ALL`, `--pids-limit`, `--read-only`, `--tmpfs ...noexec`, and `docker compose` profiles cleanly. |
| **Network & Firewall** | Public IPv4 (plus optional IPv6); UFW / Cloud Firewall allowing **TCP 22 (admin IP allowlist), 80, 443 ONLY** | Same + Cloudflare Origin IP allowlisting on 80/443 | Blocks direct external access to ports `5432`, `6379`, `8000`, `8080`, and any Docker socket/API port. |
| **SSH Hardening** | Key-only auth (`PasswordAuthentication no`, `PermitRootLogin no`), fail2ban, unattended-upgrades | Same + Bastion/Tailscale SSH | Protects host Docker daemon & DB volume. |

---

## 4. Provider Comparison (Docker-Capable Linux VPS)

Current reference net monthly pricing checked for 4 GB (2 vCPU) and 8 GB (4 vCPU) Linux instances:

| Provider | Tier / Model | vCPU / RAM / SSD | Monthly Base Cost | Automated Backups / Snapshots | Regions | Docker & Sandbox Support | Complexity |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Hetzner Cloud** *(Recommended Value / Specs)* | **CX23** / **CX33** (x86_64 Shared NVMe) | **CX23:** 2 vCPU, 4 GB, 40 GB NVMe (`20 TB` traffic)<br>**CX33:** 4 vCPU, 8 GB, 80 GB NVMe (`20 TB` traffic) | **CX23:** `€5.49 / mo` (~`$6.49`)<br>**CX33:** `€8.99 / mo` (~`$10.50–$11.00`) *(incl. IPv4 / minor EU VAT if applicable)* | **20% of base** for 7 daily rotating slots (`+€1.10–€1.80 / mo`), or snapshots `€0.0143/GB/mo` | Germany (`fsn1`, `nbg1`), Finland (`hel1`), US (`ash`, `hil`), Singapore (`sin`) *(note: check US/SG tier availability at checkout)* | **Full Native** Docker Engine + Compose + cgroups v2 + POSIX ACLs | **Low** |
| **DigitalOcean** | **Basic Regular NVMe Droplet** | **4 GB:** 2 vCPU, 4 GB, 80 GB SSD (`4 TB` transfer)<br>**8 GB:** 4 vCPU, 8 GB, 160 GB SSD (`5 TB` transfer) | **4 GB:** `$24.00 / mo`<br>**8 GB:** `$48.00 / mo` | Weekly: `+20%` (`$4.80–$9.60/mo`)<br>Daily: `+30%` (`$7.20–$14.40/mo`) | NYC, SFO, AMS, LON, FRA, SGP, BLR, TOR, SYD | **Full Native** Docker Engine + Compose + cgroups v2 + POSIX ACLs | **Low** |
| **AWS Lightsail** | **Linux Bundle (IPv4)** | **4 GB:** 2 vCPU, 4 GB, 80 GB SSD (`4 TB` transfer)<br>**8 GB:** 2 vCPU, 8 GB, 160 GB SSD (`5 TB` transfer) | **4 GB:** `$24.00 / mo`<br>**8 GB:** `$44.00 / mo` *(IPv6-only `$20`/`$40`)* | Manual / scripted snapshots + AWS S3 off-site DB dumps | All major AWS Regions (incl. `us-east-1`, `eu-central-1`, `ap-south-1`, `ap-southeast-1`) | **Full Native** Docker Engine + Compose + cgroups v2 *(note 8 GB bundle has 2 vCPUs)* | **Low–Medium** |

### Recommended Configuration
- **Primary Recommendation:** **Hetzner Cloud CX33 (4 vCPU / 8 GB RAM / 80 GB NVMe)** with **Automated Daily Backups (+20%)** + Cloudflare DNS/WAF Proxy *(or **DigitalOcean 8 GB / 4 vCPU Droplet** if an India/US region not offered on Hetzner CX33 is required)*.
- **Why 4 vCPU / 8 GB RAM (`CX33`):** Only `~€10.79 / mo` total incl. automated daily backups, gives headroom for Semgrep + Bandits + 2 concurrent Docker verification sandboxes + Postgres 16 without memory pressure, and costs less than a single mid-tier PaaS container without sandbox limits.

---

## 5. Estimated Monthly Operating Cost

| Line Item | Recommended (Hetzner CX33 + Cloudflare) | Alternative (DigitalOcean 8 GB Basic + Daily Backups) |
| :--- | :--- | :--- |
| Compute VM (4 vCPU, 8 GB RAM, 80 GB NVMe, IPv4) | `€8.99 / mo` (`~$10.50–$11.00`) | `$48.00 / mo` |
| VM Automated Daily Backups (7-day VM snapshots) | `~€1.80 / mo` (`+20%`) | `$14.40 / mo` (`+30%`) |
| Off-site Encrypted `pg_dump` Object Storage (<20 GB, e.g. R2/S3/Spaces) | `~$0.30–$1.00 / mo` (Cloudflare R2 free tier 10 GB: `$0`) | `~$0.30–$1.00 / mo` (or `$0` on R2 10 GB free tier) |
| Cloudflare DNS + Universal TLS Edge + Domain (`redmercury.xerova.com` / owned domain) | `$0 / mo` (Cloudflare Free plan DNS/Proxy; domain registrar fee ~$10–$15/yr amortized `~$1/mo`) | `$0 / mo` (Cloudflare Free) |
| Gemini API (optional, only if `OFFLINE_MODE=false`) | `$0` with `OFFLINE_MODE=true` deterministic triage (usage-based if enabled) | `$0` with `OFFLINE_MODE=true` |
| **Estimated Total Monthly Run Rate** | **`~$12–$14 / mo` (`~€11/mo`)** | **`~$63–$65 / mo`** |

---

## 6. Required Production Environment Variables

Verified against [backend/app/core/config.py](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/backend/app/core/config.py), [docker-compose.prod.yml](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/docker-compose.prod.yml), and [.env.production.example](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/.env.production.example) (**inject via restricted host secret file chmod `0600` outside Git or secret manager — never commit values**):

| Variable | Mandatory Production Value / Constraint | Enforced By |
| :--- | :--- | :--- |
| `APP_ENV` | `production` | `config.py` `is_strict_env` |
| `DEBUG` | `false` | `Settings.validate_production_configuration` |
| `DOCS_ENABLED` | `false` | Disables `/docs`, `/redoc` |
| `SECRET_KEY` | Random >=32 chars (`openssl rand -hex 32`), no dev substrings | `Settings.validate_production_configuration` |
| `POSTGRES_DB` / `POSTGRES_USER` / `POSTGRES_PASSWORD` | Strong DB credentials matching `DATABASE_URL` | `docker-compose.prod.yml` |
| `DATABASE_URL` | `postgresql+psycopg://<user>:<pass>@postgres:5432/<db>` (non-SQLite) | `Settings.validate_production_configuration` |
| `REDIS_URL` | `redis://redis:6379/0` | Distributed rate limiter & job outbox queue |
| `RATE_LIMIT_FAIL_OPEN` | `false` | Fail closed if Redis unreachable |
| `CORS_ORIGINS` | Exact production HTTPS origin(s), e.g. `https://<domain>` (no `*`, no `null`) | `Settings.validate_production_configuration` |
| `ALLOWED_HOSTS` | Exact production hostname(s), e.g. `<domain>` (no `*`) | `Settings.validate_production_configuration` |
| `COOKIE_HTTPONLY` / `COOKIE_SAMESITE` | `true` / `lax` (`Secure` forced automatically in strict env) | `config.py` `cookie_secure` |
| `CSRF_PROTECTION_ENABLED` | `true` | `Settings.validate_production_configuration` |
| `AUTH_RATE_LIMITING_ENABLED` | `true` | `Settings.validate_production_configuration` |
| `ALLOW_PRIVATE_NETWORKS` | `false` | SSRF protection |
| `ALLOW_LOCAL_INGESTION_IN_PRODUCTION` | `false` | Blocks local filesystem ingestion |
| `SANDBOX_FAIL_CLOSED` / `SANDBOX_ALLOW_HOST_FALLBACK` | `true` / `false` | Fail-closed sandbox invariant |
| `SANDBOX_BACKEND` / `SANDBOX_CONTAINER_IMAGE` | `docker` / `redmercury-worker:latest` | Sibling verification containers |
| `JOB_DISPATCH_MODE` | `queue_only` | Durable DB + Redis queue worker execution |
| `LOG_FORMAT_JSON` / `LOG_LEVEL` | `true` / `INFO` | Structured redacted JSON logging |
| `GITHUB_WEBHOOK_SECRET` | Strong HMAC secret (`openssl rand -hex 32`) | Webhook verification (fails closed without it) |
| `GIT_EGRESS_PROXY_URL` *(optional — only for public `https://` Git cloning)* | e.g. `http://egress-proxy:3128` (`APPROVED_GIT_EGRESS_PROXY_HOSTS`) | Public Git cloning fails closed until configured |
| `OFFLINE_MODE` / `GEMINI_API_KEY` | `true` (default deterministic offline triage) or `false` + vault API key | AI Security Analyst |

---

## 7. Deployment Sequence (Target Runbook for Phase 10B+ Execution)

1. **Provision & Harden Host (Only After User Authorization):** Create Ubuntu 24.04 x86_64 instance (`CX33` / DO `8GB`); enable automated VM backups; configure key-only SSH, `ufw` (`22` restricted + `80`/`443` public), `unattended-upgrades`, and install official Docker Engine + Compose v2 plugin.
2. **Prepare Persistent Host Directories & Secrets Outside Repo:**
   - `/var/lib/redmercury/workspaces` (API + Worker shared workspace store)
   - `/var/lib/redmercury/verify-tmp` (host-aligned `TMPDIR` for sandbox verification bind mounts)
   - `/etc/redmercury/production.env` (`chmod 0600`, root-owned, never inside repo working tree)
   - `/etc/redmercury/ssl/` (Cloudflare Origin Certificate `fullchain` + private key `0600`, or Let's Encrypt certbot cert matching [nginx/production.conf](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/nginx/production.conf))
3. **Checkout Exact Verified Commit & Build Local Images:** Checkout `c1fa7b12f7119e41cd3e3a7fecd9af6ed85e1b7f`, build `redmercury-worker:latest`, `redmercury-api`, and `redmercury-frontend` via Docker Compose.
4. **Apply Worker Host/Socket Isolation Pattern:** Deploy `postgres`, `redis`, `api`, `frontend`, `nginx` via hardened Compose (`cap_drop: ALL`, `read_only: true`, zero Docker socket), and run the worker with host-aligned `verify-tmp` + scoped container spawning (`docker-socket-proxy` permitting ONLY container create/start/inspect/kill/remove for worker **OR** dedicated host `systemd` worker unit with `TMPDIR=/var/lib/redmercury/verify-tmp`).
5. **Run Database Migrations & Pre-Cutover Smoke Checks:** Verify `postgres` healthy -> run `alembic upgrade head` (`0001 -> 0014`) -> verify `curl -f https://localhost/live`, `/ready`, `/api/v1/health`, and `/api/v1/health/jobs`.
6. **DNS Cutover & Full E2E Smoke Verification:** Point Cloudflare DNS record (`A` record, proxied, TLS `Full (Strict)`) -> verify browser register/login (`HttpOnly` + `rm_csrf_token`), ZIP upload scan, Bandit/Gitleaks scan, live Docker fix verification run (`SANDBOX_BACKEND=docker`), audit events, and verification report export -> then retire old `red-mercury-api` Railway deployment cleanly after verification.

---

## 8. Security Controls Checklist

- **Network Boundary:** `redmercury_internal` and `redmercury_worker_isolated` are `internal: true`; only Nginx binds `:80`/`:443`; PostgreSQL `:5432` and Redis `:6379` never listen on public interfaces.
- **Socket & Sandbox Boundary:** Zero `/var/run/docker.sock` in `api`, `frontend`, `nginx`, `postgres`, `redis`, or inside `redmercury-sbx-*` test containers; untrusted verification code runs strictly with `--network=none --cap-drop=ALL --security-opt=no-new-privileges:true --read-only --tmpfs=/tmp:rw,noexec,nosuid,size=64m --pids-limit=50 --memory=512m --cpus=1.0 --user=10002:10002` and UID-10002 POSIX ACLs (`0o007 == 0`).
- **Session & Edge Controls:** Same-origin Nginx routes prevent cross-site `SameSite=Lax` cookie loss; Nginx strips upstream security headers and enforces strict CSP (`default-src 'none'` on API, no wildcards), HSTS, `X-Frame-Options: DENY`, `nosniff`, and auth/upload rate zones; `DOCS_ENABLED=false`.
- **Container Digest & Binary Pinning:** All Compose base images and Gitleaks (`8.18.2`) are SHA-256 pinned in repo Dockerfiles/Compose.
- **External VAPT Tracking:** Automated CI & container security verification (`661/661`) **does not** substitute for an independent external penetration test. Third-party VAPT remains a mandatory pre-public-launch milestone (or requires explicit pilot risk acceptance).

---

## 9. Backup, Monitoring & Rollback Strategy

- **PostgreSQL Backups:**
  - Automated daily encrypted `pg_dump --format=custom --compress=9` via host cron/systemd timer uploaded to encrypted off-site bucket (e.g. Cloudflare R2 / S3) + provider daily VM snapshots (7-day retention).
  - Pre-migration mandatory snapshot before every schema change + quarterly automated restore verification into disposable Postgres container (`test_phase7_sec9` rehearsal pattern).
- **Redis Persistence Strategy:**
  - Configured as ephemeral rate-limit + outbox notification cache (`--save "" --appendonly no --maxmemory 128mb --maxmemory-policy allkeys-lru`). PostgreSQL `durable_jobs` and `job_outbox_events` tables are authoritative: on Redis restart, `recover_undispatched_outbox_events()` and `recover_expired_job_leases()` cleanly re-enqueue pending work without data loss.
- **TLS Renewal & Container Updates:**
  - **TLS:** If using Cloudflare Origin CA (`15-year` cert behind Cloudflare Proxied `Full Strict`) or Let's Encrypt (`certbot` post-hook `docker compose exec nginx nginx -s reload`), automated renewal avoids outage.
  - **Container Updates:** Rebuild pinned base images on tagged/verified `main` commits, backup DB, apply backward-compatible Alembic migration, roll services gracefully.
- **Monitoring & Alerting:**
  - External uptime monitor polling `GET /ready` & `GET /live` every 60s + structured JSON log shipping + alert checks on `/api/v1/health/jobs` (`expired_leases`, `worker_heartbeat_age`, queued depth) and container `docker ps` healthcheck states.
- **Incident Recovery & Deployment Rollback:**
  1. **App Rollback:** `git checkout <previous_verified_sha> && docker compose -f docker-compose.prod.yml up -d --build api worker frontend` (zero image loss).
  2. **DB Schema Rollback:** Restore pre-deployment `pg_restore` snapshot or execute `alembic downgrade -1` (only for additive/reversible revisions).
  3. **Queue Recovery:** Worker startup automatically runs `reconcile_jobs_on_startup()` and `reconcile_interrupted_jobs()`.

---

## 10. Remaining Launch Blockers

| # | Blocker | Severity | Status |
| :--- | :--- | :--- | :--- |
| 1 | Dedicated Docker-capable Ubuntu host not yet provisioned (`CX33` / DO 8GB) | **P0** | Pending user provider choice & Phase 10B authorization |
| 2 | Production domain DNS + TLS certificate + Cloudflare Origin proxy not yet pointed to target host | **P0** | Pending target IP & DNS confirmation |
| 3 | Scoped worker host/socket-proxy + host-aligned `verify-tmp` deployment override not yet applied on target host | **P0** | Designed in §§1–7; ready to deploy alongside Compose |
| 4 | Production secrets (`SECRET_KEY`, `POSTGRES_PASSWORD`, `GITHUB_WEBHOOK_SECRET`, optional `GEMINI_API_KEY` / `GIT_EGRESS_PROXY_URL`) not yet injected into target host vault | **P0** | Template ready ([.env.production.example](file:///c:/PROJECTS/dhina%20projects/Red%20Mercury/Red%20Mercury/.env.production.example)) |
| 5 | Production DB backup timer + restore test on live production volume not yet executed | **P1** | Pending host provisioning |
| 6 | Independent Third-Party External VAPT against live staging/prod URL | **P1** | **PENDING** (requires external test or formal closed-pilot risk sign-off) |

---

## 11. Exact Next Actions & Gate Conclusion

### Conclusion: **`GO FOR INFRASTRUCTURE PROVISIONING`**
*(Architecture, host specification, cost model, security controls, and deployment sequence are fully qualified to proceed to controlled infrastructure provisioning upon explicit user authorization. **Public production launch remains `NO-GO`** until provisioning, migrations, live E2E smoke tests, backup verification, and VAPT / pilot risk acceptance are completed in subsequent Phase 10 execution steps.)*

### Immediate Decisions Needed from Operator Before Any Provisioning / Deployment
1. Confirm target VPS provider & region (Recommended: **Hetzner CX33 4 vCPU / 8 GB RAM / 80 GB NVMe + Automated Backups** at `~€10.79/mo`, or DigitalOcean/AWS alternative).
2. Confirm exact production domain / hostname (e.g. `redmercury.xerova.com` behind Cloudflare DNS).
3. Explicitly authorize **Phase 10B — Infrastructure Provisioning & Staging/Pre-Cutover Deployment** (plus provide VM SSH/target access or Docker-capable host endpoint when ready).
4. Clarify public Git cloning requirement (`GIT_EGRESS_PROXY_URL` container like `smokescreen` vs ZIP-only ingestion at launch) and AI mode (`OFFLINE_MODE=true` deterministic engine vs live `GEMINI_API_KEY`).
