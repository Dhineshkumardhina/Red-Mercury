# Red Mercury - Security Policy & Threat Model

Red Mercury is an Application Security platform. As an AppSec tool, it adheres strictly to industry best practices and defensive engineering principles.

---

## 1. Secrets Management

- **Zero Hardcoded Secrets**: Secrets must never be committed to Git. `.gitignore` strictly rejects `.env`, `.pem`, `.key`, and `.db` files.
- **Frontend Isolation**: Frontend environment variables must never receive database credentials, private API keys, or server secrets. All external services are proxied through the FastAPI backend.
- **Automated Secret Redaction**: Source-code excerpts submitted for analysis are run through pre-flight regex redaction to strip AWS keys, JWT tokens, and API credentials before inspection.

---

## 2. Invariant Rules for AI Security Triaging

Red Mercury enforces 8 core invariants:

1. **Strict Line & File Grounding**: Model cannot invent hypothetical files. Every reference must correspond to real line numbers.
2. **Evidence vs. Inference Separation**: Observed AST taint traces are clearly distinguished from speculative inferences.
3. **Context Completeness**: Truncated 1-line snippets lacking caller context are classified as *Insufficient Evidence*.
4. **Benign Parameterization**: Properly parameterized SQL bindings are recognized as secure, preventing false positives.
5. **Calibrated Confidence**: Confidence scores are treated as probabilistic metrics, not proof of correctness.
6. **Prompt Injection Defense**: Comments within source code are treated as untrusted text to neutralize jailbreak attempts.
7. **Secret Scrubbing**: Discovered secrets are redacted in output.
8. **Operator Consent**: Analysis requires explicit authorization.

---

## 3. Network Hardening & HTTP Headers

All HTTP responses from the backend include:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `X-Permitted-Cross-Domain-Policies: none`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains` (enforced in production)

---

## 4. Verification Execution Sandbox & Untrusted Code Isolation Model

Red Mercury executes untrusted code submitted in repositories or generated test suites during fix verification. To prevent remote code execution, host system compromise, lateral movement, or host secret exfiltration, execution is strictly governed by the **Verification Sandbox Architecture** (`backend/app/verification/sandbox.py`).

### Isolation Controls & Hardening
1. **Dedicated Unprivileged Container**: Untrusted test suites run within an isolated OCI/Docker container (`redmercury-worker:latest` or custom worker image).
2. **Non-Root Execution**: Container execution runs under an unprivileged user/group (`UID:GID 10002:10002`, `redmercury-sandbox`).
3. **No-New-Privileges & Dropped Capabilities**:
   - Dropped capabilities: `--cap-drop=ALL` (drops `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_SETUID`, etc.).
   - Privilege escalation blocked: `--security-opt=no-new-privileges:true`.
4. **Read-Only Root Filesystem & Scoped tmpfs**:
   - Container root filesystem is mounted strictly read-only (`--read-only`).
   - Temporary file writing is restricted to a dedicated memory-backed tmpfs (`--tmpfs /tmp:rw,noexec,nosuid,size=64m`).
5. **Complete Network Isolation**: Containers run with `--network=none` by default. Outbound network requests, socket connections, exfiltration channels, and SSRF attacks are physically blocked at the kernel network namespace level.
6. **Strict Resource Bounding**:
   - CPU quota: `--cpus=1.0` (configurable via `SANDBOX_CPU_LIMIT`).
   - Memory & swap ceiling: `--memory=512m` and `--memory-swap=512m` (configurable via `SANDBOX_MEMORY_LIMIT`).
   - Process count limit: `--pids-limit=50` (mitigating fork bombs and thread exhaustion).
7. **Restricted Filesystem Mounts & Secret Isolation**:
   - Only the specific disposable temporary workspace directory is mounted (`-v <workspace>:/workspace:rw`).
   - No host root (`/`), user homes, `.env` files, or Docker sockets (`/var/run/docker.sock`) are ever mounted into the container.
   - All host environment variables are passed through `get_sanitized_runner_env()`, purging all credentials (`SECRET_KEY`, `DATABASE_URL`, `GEMINI_API_KEY`, AWS tokens, GitHub secrets).
8. **Process-Tree Termination**:
   - Container timeouts (default 30s) trigger an immediate `docker kill <container_name>` followed by `docker rm -f <container_name>`.
   - On Windows or POSIX hosts, host process groups are terminated recursively (`taskkill /F /T` or `os.killpg`) to eliminate orphan background processes.

### Fail-Closed Invariant
If container runtime isolation is unavailable (e.g. Docker daemon is down or unreachable):
- **Production (`APP_ENV=production`)**: Verification execution **FAILS CLOSED** immediately. Untrusted repository code is strictly rejected and never allowed to execute on the host OS.
- **Development/Test (`APP_ENV=development`)**: Host execution fallback is strictly opt-in (`SANDBOX_ALLOW_HOST_FALLBACK=True`), subject to AST pre-execution safety inspection that blocks prohibited system calls (`os.system`, `subprocess`, `socket`). In production, this fallback is hard-blocked and unconditionally disabled.

### Operational Requirements
- Production workers require access to a functioning Docker daemon or rootless container runtime (`podman` or `docker`).
- Worker containers must have the `redmercury-worker:latest` image pulled or pre-built.
- Host kernel must support Linux namespaces and cgroups (cgroups v1 or v2).

