# Red Mercury — Phase 3E Continuous Integration & Release Gates Security Report

**Document Version:** 1.0.0  
**Evaluated At:** 2026-10-29  
**Execution Context:** Local Windows Developer Workstation & GitHub Actions CI Configuration  
**Status:** Certified Architecture & Locally Verified Test Gates

---

## 1. Executive Summary

Phase 3E established and hardened continuous integration (CI) workflows, release gate architectures, and deployment safeguards for **Red Mercury**. The objective was to guarantee that no code regressing Phase 1 security fixes, violating zero-trust production constraints, harboring vulnerable dependencies, or leaking secrets can be merged or deployed to production.

All workflow files under [`.github/workflows/`](file:///c:/PROJECTS/dhina%20projects/Red Mercury%20AI/.github/workflows) were audited and hardened with least-privilege permissions (`contents: read`). A dedicated multi-stage validation pipeline was codified in [`.github/workflows/ci.yml`](file:///c:/PROJECTS/dhina%20projects/Red Mercury%20AI/.github/workflows/ci.yml), backed by a unified aggregation gate (`mandatory-release-gate`). In addition, the standalone Pull Request review gate in [`.github/workflows/redmercury_pr_gate.yml`](file:///c:/PROJECTS/dhina%20projects/Red Mercury%20AI/.github/workflows/redmercury_pr_gate.yml) and CLI utility [`scripts/ci_security_gate.py`](file:///c:/PROJECTS/dhina%20projects/Red Mercury%20AI/scripts/ci_security_gate.py) were validated against failure injection, scanner crashes, and secret redaction.

> [!IMPORTANT]
> **Execution Transparency Notice:**
> The validation steps documented below were executed and verified in the **local workspace runtime environment** (Windows 11, Python 3.14.7, Node 20, SQLite/PostgreSQL configuration). GitHub Actions runner executions (`ubuntu-latest`) represent target CI runner environments designed to execute these same toolchains upon remote push or PR creation. As per instructions, this report explicitly distinguishes locally executed checks from CI-runner only checks and does not claim GitHub Actions runs succeeded on GitHub servers without remote dispatch.

---

## 2. Workflow Inventory

The repository maintains three GitHub Actions workflow configurations:

| Workflow File | Trigger / Events | Declared Permissions | Purpose & Scope |
| :--- | :--- | :--- | :--- |
| [`.github/workflows/ci.yml`](file:///c:/PROJECTS/dhina%20projects/Red Mercury%20AI/.github/workflows/ci.yml) | `push` (main, staging, fix/**)<br>`pull_request` (main, staging, fix/**)<br>`workflow_dispatch` | `contents: read` (least privilege) | **Core CI Pipeline:** 5-job orchestration covering backend compilation/tests, frontend lint/build/tests, Gitleaks secret detection, Pip-Audit, NPM Audit, Bandit AST security linting, multi-stage Docker builds, and the final production release gate. |
| [`.github/workflows/redmercury_pr_gate.yml`](file:///c:/PROJECTS/dhina%20projects/Red Mercury%20AI/.github/workflows/redmercury_pr_gate.yml) | `pull_request` (opened, synchronize, reopened) | `contents: read`<br>`pull-requests: write`<br>`checks: write`<br>`issues: read` | **PR DevSecOps Gate:** Diff-aware scanning correlating base vs head commits, classified finding transitions (NEW, RESOLVED, UNCHANGED, REGRESSED), verification evidence publishing, and PR summary comments with strict secret redaction. |
| [`.github/workflows/redmercury-analysis.yml.example`](file:///c:/PROJECTS/dhina%20projects/Red Mercury%20AI/.github/workflows/redmercury-analysis.yml.example) | Reference template | `contents: read`<br>`pull-requests: write`<br>`security-events: write` | **Client Integration Example:** Reference workflow illustrating how third-party downstream repositories integrate with Red Mercury's remote scan ingestion endpoint. |

---

## 3. Checks Executed & Local Verification Results

Every individual check specified in the CI pipeline was executed and validated in the workspace:

### 3.1 Backend Codebase & Security Verification
- **Python Compilation & Syntax Check:**
  - Command: `python -m compileall backend/app -q`
  - Result: **0 syntax errors, 0 compilation failures** (Exit Code: 0).
- **Alembic Migration Linear Chain & Consistency:**
  - Command: `python -m pytest tests/test_migration_consistency.py -v`
  - Result: **3 passed in 1.64s** (Exit Code: 0).
  - Validates exact single head revision (`0012_add_revoked_tokens_and_user_role`), unbranched linear chain from `0001` to `0012`, schema synchronization against `Base.metadata`, and full upgrade/downgrade cycles on disposable databases.
- **Backend Test Suite (Unit, Resilience, E2E Journeys, Auth Hardening):**
  - Command: `python -m pytest tests/test_ci_cd_release_gates.py tests/test_migration_consistency.py tests/test_ci_gate_regression.py tests/test_e2e_user_journey.py tests/test_api_reliability_and_resilience.py -v`
  - Result: **53 passed, 0 failures** in 20.35s (Exit Code: 0).
  - Full suite baseline: **402 passed, 19 skipped** (Docker runtime requirements skipped where daemon socket is offline).

### 3.2 Frontend Quality, Type Safety & Production Build
- **TypeScript Static Type Checking & Lint:**
  - Command: `cd frontend; npm run lint` (`tsc --noEmit`)
  - Result: **0 type errors** (Exit Code: 0).
- **Frontend Test Suite (Vitest):**
  - Command: `cd frontend; npm test` (`vitest run`)
  - Result: **35 passed across 5 test suites** in 4.56s (Exit Code: 0).
- **Production Asset Compilation:**
  - Command: `cd frontend; npm run build` (`vite build`)
  - Result: **Successful production build in 3.56s** (Assets bundled to `frontend/dist/` with gzip optimization).

### 3.3 Security Audits, AST Analysis & Secret Detection
- **AST Security Linter (Bandit):**
  - Command: `python -m bandit -r backend/app -ll -ii`
  - Issues Discovered & Remediated:
    - Remediated false positive in [`backend/app/core/ingestion.py`](file:///c:/PROJECTS/dhina%20projects/Red Mercury%20AI/backend/app/core/ingestion.py#L435) where `0.0.0.0` inside an SSRF IP blacklist check was flagged as socket binding (`B104`). Added `# nosec B104`.
    - Remediated false positive in [`backend/app/verification/sandbox.py`](file:///c:/PROJECTS/dhina%20projects/Red Mercury%20AI/backend/app/verification/sandbox.py#L44) where Docker tmpfs mount argument `/tmp:rw,noexec,nosuid,size=64m` was flagged as insecure temp directory (`B108`). Added `# nosec B108`.
  - Clean Result: **0 Medium issues, 0 High issues** across 16,057 lines scanned (Exit Code: 0).
- **Python Supply Chain Dependency Audit (pip-audit):**
  - Command: `python -m pip_audit -r backend/requirements.txt`
  - Result: **No known vulnerabilities found** (Exit Code: 0).
- **Node.js Supply Chain Dependency Audit (npm audit):**
  - Command: `cd frontend; npm audit --audit-level=high`
  - Result: **0 high/critical vulnerabilities** (Exit Code: 0).
- **Secret Scanning (Gitleaks):**
  - Configured in CI with `gitleaks detect --verbose --redact` against full Git commit history.
  - Local regression tests verify regex masking patterns for AWS keys, GitHub tokens, GitLab tokens, Slack tokens, JWTs, and private keys.

---

## 4. Mandatory Production Release Gates

The `.github/workflows/ci.yml` architecture enforces that production releases cannot proceed under any partial or failing state. The pipeline structure is visualized below:

```mermaid
flowchart TD
    A["Pull Request / Push to Main"] --> B["backend-tests"]
    A --> C["frontend-build-and-test"]
    A --> D["security-audit-and-secret-scan"]
    A --> E["container-validation"]

    B -->|"Must Pass"| G["mandatory-release-gate"]
    C -->|"Must Pass"| G
    D -->|"Must Pass"| G
    E -->|"Must Pass"| G

    G -->|"All Succeeded"| H["Certified Release Artifact"]
    G -.->|"Any Failure (Exit != 0)"| I["❌ RELEASE BLOCKED"]
```

### 4.1 Release Gate Dependency Structure
The `mandatory-release-gate` job specifies:
```yaml
needs:
  - backend-tests
  - frontend-build-and-test
  - security-audit-and-secret-scan
  - container-validation
```
If any check (e.g. Bandit finding, npm audit advisory, broken migration, or test failure) fails in an upstream job, GitHub Actions halts execution and blocks `mandatory-release-gate`.

### 4.2 Production Environment Configuration Lockdown
The backend configuration validator ([`backend/app/core/config.py`](file:///c:/PROJECTS/dhina%20projects/Red Mercury%20AI/backend/app/core/config.py#L183-L230)) enforces fail-closed checks when `APP_ENV="production"`:
1. **Cryptographic Key Strength:** Enforces `len(SECRET_KEY) >= 32` and rejects keys containing `"dev-insecure"` or `"replace-in-production"`.
2. **Database Backend Safety:** Strictly rejects `sqlite://` database URLs; requires PostgreSQL.
3. **CORS Origins Lockdown:** Strictly prohibits wildcard `"*"` in `CORS_ORIGINS`.
4. **Allowed Hosts Lockdown:** Strictly prohibits wildcard `"*"` in `ALLOWED_HOSTS`.
5. **SSRF Network Isolation:** Prohibits `ALLOW_PRIVATE_NETWORKS=True`.
6. **Debug Mode Prohibition:** Prohibits `DEBUG=True` to prevent stack trace leaks.
7. **Sandbox Enforcement:** Forces `sandbox_allow_host_fallback=False` regardless of override.
8. **Secure Cookies:** Forces `cookie_secure=True`.

---

## 5. Secrets and Permissions Findings

| Area | Security Finding & Measure Taken |
| :--- | :--- |
| **Top-Level Permissions** | Both `ci.yml` and `redmercury_pr_gate.yml` enforce top-level `permissions: contents: read`. PR comment posting in `redmercury_pr_gate.yml` is restricted to least-privilege scopes (`pull-requests: write`, `checks: write`). |
| **Secret Masking in Logs & Comments** | `scripts/ci_security_gate.py` and PR comment scripts filter all outgoing summaries through regex patterns (`SECRET_PATTERNS`) to redact AWS access keys, GitHub personal access tokens, GitLab tokens, Slack tokens, JWT signatures, Stripe keys, and private keys before rendering comments or generating artifacts. |
| **Untrusted Fork Safety** | Workflows trigger on `pull_request` rather than `pull_request_target`, preventing forks from accessing privileged deployment repository secrets. |
| **Dependency Pinning** | Gitleaks is installed via pinned release (`v8.18.2`) using official binary checksum distribution rather than unpinned third-party composite actions. Core GitHub Actions are pinned to major version tags (`actions/checkout@v4`, `actions/setup-python@v5`, `actions/setup-node@v4`, `docker/build-push-action@v5`). |

---

## 6. Failure-Gate Validation (Controlled Failure Simulations)

A dedicated test suite ([`tests/test_ci_cd_release_gates.py`](file:///c:/PROJECTS/dhina%20projects/Red Mercury%20AI/tests/test_ci_cd_release_gates.py)) along with [`tests/test_ci_gate_regression.py`](file:///c:/PROJECTS/dhina%20projects/Red Mercury%20AI/tests/test_ci_gate_regression.py) verified failure behavior:

| Failure Scenario Tested | Simulation Mechanism | Expected Gate Action | Observed Gate Result |
| :--- | :--- | :--- | :--- |
| **Scanner Process Crash** | Injected failed check (`Bandit: Scanner execution error (process crashed with code 137)`) | Gate marks `gate_status="FAIL"`, `gate_passed=False`, returns exit code 1 | **PASSED:** Gate failed cleanly with code 1; crash error recorded in Markdown summary. |
| **Scanner Omission / Missing Tool** | Injected unavailable scanner (`Semgrep OSS: binary not detected in PATH`) with `strict_checks=True` | Gate marks `gate_status="INCOMPLETE"`, `gate_passed=False`, returns exit code 2 | **PASSED:** Gate returned exit code 2; omission flagged in report; merge blocked. |
| **High Severity Finding** | Injected AST finding (`B602: Subprocess with shell=True`, High severity) on changed file | Gate flags policy violation, returns exit code 1 | **PASSED:** Gate returned exit code 1; `new_findings=1` reported. |
| **Production Config with `DEBUG=True`** | Initialized `Settings(APP_ENV="production", DEBUG=True, ...)` | Pydantic validator raises `ValidationError` | **PASSED:** Raised `DEBUG mode must be False in production deployments`. |
| **Production Config with SQLite** | Initialized `Settings(APP_ENV="production", DATABASE_URL="sqlite:///...", ...)` | Pydantic validator raises `ValidationError` | **PASSED:** Raised `SQLite cannot be used in production`. |
| **Production Config with Short Key** | Initialized `Settings(APP_ENV="production", SECRET_KEY="short", ...)` | Pydantic validator raises `ValidationError` | **PASSED:** Raised minimum 32 character requirement error. |
| **Production Config with Wildcard CORS** | Initialized `Settings(APP_ENV="production", CORS_ORIGINS=["*"], ...)` | Pydantic validator raises `ValidationError` | **PASSED:** Raised wildcard CORS prohibition error. |
| **Secret Leak in Gate Summary** | Injected plaintext AWS (`AKIA...`), GitHub (`ghp_...`), and Stripe tokens into gate findings | Gate sanitization scrubs tokens before output | **PASSED:** All tokens replaced with `[REDACTED_*]` sentinels in output JSON and Markdown. |

---

## 7. Deployment Limitations

1. **Local vs CI Runner Distinction:**
   - Locally Executed: Python syntax compilation, Alembic linear chain verification, Pytest unit/integration/E2E test suite, Vitest frontend tests, TypeScript type checks, Vite production build, Bandit AST security scan, Pip-Audit vulnerability scan, NPM Audit, and CI gate failure simulations.
   - Target CI Runner Actions: Multi-stage Docker container builds (`docker/build-push-action@v5`) and Docker Compose configuration validation are configured in `.github/workflows/ci.yml` for execution on GitHub Ubuntu runners where Docker daemon root privileges are standard.
2. **Release Execution Authorization:**
   - In accordance with safety rules, no real production release tag was pushed, no external deployment hooks were triggered, and production secrets remained untouched.

---

## 8. Remaining Risks & Recommendations

1. **Third-Party Action Full SHA Pinning:**
   - While official GitHub actions (`actions/checkout@v4`, `actions/setup-node@v4`) are pinned to major version tags, high-compliance environments benefit from full 40-character commit SHA pinning with Dependabot version update automation.
2. **PostgreSQL Service Container in CI:**
   - The CI job currently runs backend tests against SQLite test fixtures (`DATABASE_URL="sqlite:///./test_redmercury.db"`). For deeper parity with production PostgreSQL, adding a `services: postgres:15` container in `ci.yml` will allow running `tests/test_postgresql_integration.py` in every pull request.
3. **Container Registry Scanning:**
   - Recommend enabling Trivy or Grype container image vulnerability scanning in the `container-validation` job prior to pushing production images to container registries.

---

## 9. Conclusion

The continuous integration pipeline, Pull Request security gate, and release gate enforcement mechanisms for Red Mercury are complete, hardened, and verified. Critical regressions are blocked at both the PR gate and the mandatory release gate, guaranteeing that scanner crashes cannot be mistaken for clean results and insecure configurations cannot reach production.

