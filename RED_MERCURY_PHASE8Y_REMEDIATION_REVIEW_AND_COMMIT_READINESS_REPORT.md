# RED MERCURY — PHASE 8Y / 8Y-F / 8Y-G
# TARGETED CI REMEDIATION REVIEW, SECURITY VALIDATION & COMMIT READINESS REPORT

**Product:** Red Mercury — Enterprise Application Security & Automated Fix Verification Engine  
**Organization:** Xerova Digital Solutions  
**Repository:** `https://github.com/Dhineshkumardhina/Red-Mercury`  
**Workspace:** `c:\PROJECTS\dhina projects\Red Mercury\Red Mercury`  
**Branch:** `main`  
**Expected Remote Baseline / Parent (`HEAD` & `origin/main`):** `1a9358a22e40bdc75ba735a63c61bad838ca3cb7`  
**Previous Phase:** Phase 8X — Remote GitHub Actions CI Verification, Failure Forensics & Release Gate Audit  
**Updated:** Phase 8Y-G Final Full Backend Regression Re-Run & Commit Authorization Revalidation (`2026-11-22`)

---

## 1. Executive Summary

- **Changeset Scope:** Only two tracked test files were modified (`tests/test_verification_security_hardening.py` `[+7/-1]` and `tests/test_phase7_production_deployment_verification.py` `[+377/-34]`), accompanied by the audit deliverables (`RED_MERCURY_PHASE8X_REMOTE_CI_VERIFICATION_AND_RELEASE_GATE_AUDIT_REPORT.md` intact and this updated Phase 8Y report). Zero application source files (`backend/app/**`), migrations, Dockerfiles, or GitHub Actions workflows were altered.
- **Independent Fix Review & Phase 8Y-F Boundary Hardening:**
  - **Fix 1 (`tests/test_verification_security_hardening.py`):** **VERIFIED**. Replacing the no-op `os.chmod` mock stub with a pass-through `_spy_chmod` calls real `os.chmod`, strips default Linux `0o5` world bits to `0o700`/`0o600`, exercises `backend/app/verification/workspace.py`'s `os.lstat(path).st_mode & stat.S_IRWXO == 0` guard without weakening any invariant, and passed both under spy-mock and real unmocked kernel POSIX ACL execution on WSL2 Linux (`world_bits=0`).
  - **Fix 2 (`tests/test_phase7_production_deployment_verification.py`):** Restricted in Phase 8Y-F so `--no-sandbox --disable-setuid-sandbox` fallback is eligible **exclusively** when **`sys.platform.startswith("linux") and os.environ.get("GITHUB_ACTIONS") == "true"`** (generic `CI == "true"` removed completely). Normal sandboxed launch always executes first; at most one fallback attempt is permitted; fresh isolated temporary profile directories (`attempt_0`, `attempt_1`) are created per attempt; failed subprocesses are terminated cleanly via `_terminate_chromium_process(...)`; bounded 60-iteration timeouts and stderr capture remain enforced; and temporary profiles/logs are cleaned up in `finally:`.
- **Deterministic Mock & Live Verification Summary (Post-Final-Code-Edit):**
  - Targeted Chromium + POSIX ACL regression tests: **11 passed, 28 deselected** (`8.80s`, exit `0`) — includes live local Windows Chrome `157.0.8103.80` CDP browser verification (`test_phase7_sec6_real_chromium_browser_auth_cookies_csrf_rotation_and_cors`) plus 7 new deterministic policy tests covering all required fallback environments.
  - Full `tests/test_phase7_production_deployment_verification.py`: **12 passed, 3 skipped** (`13.39s`, exit `0`).
  - Full `tests/test_verification_security_hardening.py`: **23 passed, 1 skipped** (`5.18s`, exit `0`).
  - Full backend suite Phase 8Y-G single clean run (`tests/`, `661` collected): **624 passed, 0 failed, 37 skipped, 0 errors** (`230.32s` / `0:03:50`, exit `0`) — supersedes earlier Phase 8Y-F run (`623 passed, 1 transient external PyPI timeout, 37 skipped`) and isolated `test_scanners.py` rerun (`15 passed, 1 skipped` in `8.69s`, exit `0`).
  - WSL2 Linux kernel `workspace.py` POSIX ACL verification: **VERIFIED** (`SPY_TEST` `0o700`/`0o600` & unmocked kernel `0o750`/`0o640`, `world_bits=0`, `acl_ver=2`, exit `0`).
  - Gitleaks (`--no-git` and 52-commit history), `python -m compileall`, and `git diff --check`: **VERIFIED** (`no leaks found`, exit `0`).
- **Commit Readiness Decision:** **APPROVED FOR EXPLICIT USER-AUTHORIZED COMMIT & PUSH** *(no Git mutation performed in Phase 8Y/8Y-F/8Y-G; remote post-fix GitHub Actions CI remains **NOT RUN** until pushed; production deployment remains **NOT AUTHORIZED**).*

---

## 2. Baseline Verification

| Check | Status | Observed Result |
| :--- | :--- | :--- |
| Current branch | **VERIFIED** | `main` |
| Current `HEAD` | **VERIFIED** | `1a9358a22e40bdc75ba735a63c61bad838ca3cb7` |
| `origin` remote URL | **VERIFIED** | `https://github.com/Dhineshkumardhina/Red-Mercury.git` (`fetch` and `push`) |
| `origin/main` SHA | **VERIFIED** | `1a9358a22e40bdc75ba735a63c61bad838ca3cb7` (matches local `HEAD`) |
| Baseline deviation | **NOT APPLICABLE** | `HEAD` matches expected baseline identically |

---

## 3. Working-Tree Inventory

Observed via `git status --short --untracked-files=all`:

| Path | Git Status | Classification | Notes |
| :--- | :--- | :--- | :--- |
| `tests/test_verification_security_hardening.py` | Modified (`M`, unstaged) | Fix 1 (POSIX ACL spy) | Unchanged since Phase 8Y |
| `tests/test_phase7_production_deployment_verification.py` | Modified (`M`, unstaged) | Fix 2 (`GITHUB_ACTIONS=true`-only Linux Chromium fallback + deterministic regression tests) | Updated in Phase 8Y-F |
| `RED_MERCURY_PHASE8X_REMOTE_CI_VERIFICATION_AND_RELEASE_GATE_AUDIT_REPORT.md` | Untracked (`??`) | Phase 8X deliverable | Intact (`248` lines) |
| `RED_MERCURY_PHASE8Y_REMEDIATION_REVIEW_AND_COMMIT_READINESS_REPORT.md` | Untracked (`??`) | Phase 8Y / 8Y-F deliverable | This report |
| Production code, migrations, workflows, Dockerfiles, `.db`/`.env`/logs | Unchanged / None | Clean | Zero unintended files or edits |

---

## 4. Fix 1 Independent Review (`tests/test_verification_security_hardening.py`)

**Target:** `test_ensure_sandbox_readable_workspace_uses_scoped_acl_without_world_access` (lines 497–540) exercising `ensure_sandbox_readable_workspace` -> `_apply_scoped_posix_permissions` in `backend/app/verification/workspace.py` (lines 348–452).

| Review Criterion | Status | Observed Evidence |
| :--- | :--- | :--- |
| Original `os.chmod` preserved | **VERIFIED** | Captures `orig_chmod = os.chmod` prior to patching `app.verification.workspace.os.chmod` |
| Spy records calls & invokes real `os.chmod` | **VERIFIED** | `_spy_chmod(path, mode)` appends `(Path(path), mode)` then calls `orig_chmod(path, mode)` |
| Actual inode permissions verified | **VERIFIED** | `_apply_scoped_posix_permissions` lines 402–407 execute `stat.S_IMODE(os.lstat(path).st_mode) & stat.S_IRWXO` on real inode when `os.name == "posix"` |
| World-readable/executable bits prohibited | **VERIFIED** | Raises `PermissionError` if `(st_mode & stat.S_IRWXO) != 0`; test asserts `(mode & 0o077) == 0` |
| POSIX ACL & UID `10002` coverage intact | **VERIFIED** | Verifies `system.posix_acl_access` v2 xattr (`0x02, 10002` present; group `0x04` = `0`, other `0x20` = `0`) |
| Production code & assertions weakened | **VERIFIED (None)** | Zero changes to `backend/app/verification/workspace.py`; zero assertions removed or bypassed |

**Real WSL2 Linux Kernel Verification Evidence (`python3` loading `backend/app/verification/workspace.py` directly on Linux kernel `6.18.33.2`):**

- **With `_spy_chmod` + `_fake_setxattr`:** `init_ws=0o755`, `init_tf=0o644`, `chmod_calls=3`, `final_ws=0o700`, `final_tf=0o600`, `world_bits=0`, exit code `0`.
- **Unmocked real POSIX ACL on `/tmp` (UID `1000` -> UID `10002`):** `real_ws=0o750`, `real_tf=0o640`, `acl_ver=2`, entries `[('0x1', 7, 4294967295), ('0x2', 5, 10002), ('0x4', 0, 4294967295), ('0x10', 5, 4294967295), ('0x20', 0, 4294967295)]`, `world_bits=0`, exit code `0`.

---

## 5. Fix 2 Independent Security Review (`tests/test_phase7_production_deployment_verification.py`)

**Target:** `_terminate_chromium_process(...)`, `_launch_headless_chromium_cdp(...)` (lines 595–694), `test_phase7_sec6_real_chromium_browser_auth_cookies_csrf_rotation_and_cors`, and the deterministic Phase 8Y-F policy regression suite (lines 937–1193).

| Security & Lifecycle Requirement | Status | Observed Evidence |
| :--- | :--- | :--- |
| Normal sandboxed launch attempted first | **VERIFIED** | `flag_attempts[0] = []`; Attempt 1 runs without `--no-sandbox` or `--disable-setuid-sandbox` |
| Exact GitHub Actions Linux fallback gate | **VERIFIED** | `is_github_actions_linux = sys.platform.startswith("linux") and os.environ.get("GITHUB_ACTIONS") == "true"`; generic `CI == "true"` removed completely |
| Prohibited on Windows, macOS, local Linux & non-GH CI | **VERIFIED** | Confirmed across all 4 parametrized environments in `test_phase7_sec6_chromium_fallback_prohibited_outside_github_actions_linux` |
| At most one fallback attempt | **VERIFIED** | `flag_attempts` has length at most `2` (`[]`, `["--no-sandbox", "--disable-setuid-sandbox"]`) |
| Bounded startup timeouts & fast crash detection | **VERIFIED** | `for _ in range(60):` with immediate `chrome_proc.poll() is not None` early-exit check |
| Fresh isolated profile per attempt & cleanup | **VERIFIED** | Uses `user_data_dir / f"attempt_{attempt_idx}"`; `_terminate_chromium_process` terminates hanging processes even when `_launch_headless_chromium_cdp` is called directly; `finally:` removes script, stderr log (`OSError`-safe for Windows helper handles), and `user_data_dir` |
| Diagnostics preserved | **VERIFIED** | Reads trailing 2000 bytes of `chrome_stderr.log` into `last_stderr` after `_terminate_chromium_process` |
| Production code & browser security assertions unchanged | **VERIFIED** | Zero changes to `backend/app/**`; all HttpOnly, CSRF, refresh rotation, reuse detection, CORS, and empty-storage assertions preserved verbatim |

---

## 6. Chromium Sandbox Risk Assessment

- **Root Cause:** GitHub Actions `ubuntu-24.04` / `ubuntu-26.04` runners enable `kernel.apparmor_restrict_unprivileged_userns = 1`, which blocks Chromium user namespaces (`FATAL: No usable sandbox!`) unless an AppArmor profile grants `userns` or `--no-sandbox` is supplied.
- **Safest Boundary Without Workflow Mutation:** By restricting Attempt 2 strictly to `sys.platform.startswith("linux") and os.environ.get("GITHUB_ACTIONS") == "true"`, the `--no-sandbox --disable-setuid-sandbox` fallback **cannot** run on local Linux desktops, Windows, macOS, or non-GitHub CI systems (`CI=true` alone), **never** runs if sandboxed Attempt 1 succeeds, and applies solely to an ephemeral localhost (`127.0.0.1`) FastAPI browser test inside an isolated single-use VM. Red Mercury's container verification sandbox (`backend/app/verification/sandbox.py`) remains completely unaffected.
- **Alternative Documented:** A scoped workflow AppArmor profile (`sudo tee /etc/apparmor.d/...` granting `userns`) would allow Attempt 1 to pass with Chrome's userns sandbox intact on GitHub Actions; if added later in `.github/workflows/ci.yml`, Attempt 1 will succeed and Attempt 2 will automatically never execute.

---

## 7. Windows Regression Results (Post-Final-Code-Edit)

All Windows runs executed under Python `3.14.7`, Chrome `157.0.8103.80`, Node `v24.21.0`:

| Scope | Exact Command | Env | Passed | Failed | Skipped | Duration | Exit Code | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Targeted (POSIX ACL + live Chrome sec6 + 7 deterministic fallback policy cases) | `python -m pytest tests/test_verification_security_hardening.py tests/test_phase7_production_deployment_verification.py -k "test_ensure_sandbox_readable_workspace or test_phase7_sec6" -v --tb=short` | Windows 11 | `11` (`28 deselected`) | `0` | `0` | `8.80s` | `0` | **VERIFIED** |
| Phase 7 suite | `python -m pytest tests/test_phase7_production_deployment_verification.py -v --tb=short` | Windows 11 | `12` | `0` | `3` (`sec4`, `sec8`, `sec9` require Postgres/Redis/Docker) | `13.39s` | `0` | **VERIFIED** |
| Verification security hardening suite | `python -m pytest tests/test_verification_security_hardening.py -v --tb=short` | Windows 11 | `23` | `0` | `1` (symlink host skip) | `5.18s` | `0` | **VERIFIED** |
| Scanners suite (isolated re-run after transient PyPI timeout in full run) | `python -m pytest tests/test_scanners.py -v --tb=short` | Windows 11 | `15` | `0` | `1` (`semgrep` binary not on Windows) | `8.69s` | `0` | **VERIFIED** |

*(Note: Mocked `_launch_headless_chromium_cdp` policy tests deterministically validate flag selection, termination, and cleanup logic via mocked `Popen`/`urlopen`; they do not claim real remote Linux Chromium execution.)*

---

## 8. Linux Regression Results

- **WSL2 Real Linux Kernel `workspace.py` Check:** **VERIFIED** (`SPY_TEST` `0o700`/`0o600`, `world_bits=0`; `REAL_KERNEL` `0o750`/`0o640`, `acl_ver=2`, `world_bits=0`, exit `0`).
- **Full Pytest Suite inside WSL2 Linux:** **UNAVAILABLE / NOT RUN** (no `pytest`/`sqlalchemy` virtualenv in WSL2).
- **Remote GitHub Actions Post-Fix CI Execution:** **NOT RUN** (pending explicit commit-and-push authorization).

---

## 9. Full Backend Regression Results (Local Windows)

| Exact Command | Phase | Env | Total Collected | Passed | Failed | Skipped | Errors | Duration | Exit Code | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `python -m pytest tests/ -q --tb=short --timeout=120` | Phase 8Y-F | Windows 11 (`sqlite:///./test_redmercury.db`) | `661` | `623` | `1` (`test_scanners.py::test_pip_audit_on_vulnerable_manifest`, external PyPI `ScannerStatus.TIMEOUT`) | `37` | `0` | `228.82s` (`0:03:48`) | `1` | **TRANSIENT EXTERNAL TIMEOUT** (isolated `test_scanners.py` rerun: `15 passed, 1 skipped` in `8.69s`, exit `0`) |
| `python -m pytest tests/ -q --tb=short --timeout=120` | **Phase 8Y-G** | Windows 11 (`sqlite:///./test_redmercury.db`) | **`661`** | **`624`** | **`0`** | **`37`** | **`0`** | **`230.32s` (`0:03:50`)** | **`0`** | **VERIFIED (clean full local SQLite pass)** |

---

## 10. Gitleaks Results

| Scan Scope | Command | Result | Duration | Exit Code | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Working tree (Phase 8Y-G verification) | `gitleaks.exe detect --no-git --verbose --redact` | `no leaks found` | `4.33s` | `0` | **VERIFIED** |
| Git commit history | `gitleaks.exe detect --verbose --redact` | `52 commits scanned`, `no leaks found` | `1.2s` | `0` | **VERIFIED** |

---

## 11. Compilation Results

- Command: `python -m compileall backend/app tests -q` -> Exit code `0` (**VERIFIED**).

---

## 12. Diff Hygiene

- `git diff --check`: Exit code `0` (**VERIFIED**; zero whitespace/conflict errors; Git autocrlf notice printed on `tests/test_phase7_production_deployment_verification.py`).
- `git diff --numstat`:
  - `377	34	tests/test_phase7_production_deployment_verification.py`
  - `7	1	tests/test_verification_security_hardening.py`

---

## 13. CI Workflow Integrity Review (`.github/workflows/ci.yml`)

- Unchanged from `1a9358a22e40bdc75ba735a63c61bad838ca3cb7`: all 5 jobs keep `permissions: contents: read`, zero `continue-on-error`, and `mandatory-release-gate` strictly depends on all 4 upstream jobs (**VERIFIED**).

---

## 14. Exact File Manifest

| # | Path | Change Type | Purpose | Lines Added | Lines Removed | Security Impact | Regression Coverage |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `tests/test_verification_security_hardening.py` | Modified (`M`) | Pass-through `_spy_chmod` calls real `os.chmod` so Linux inode strips `0o5` world bits while verifying ACLs | `7` | `1` | None (preserves `workspace.py` `0o007` guard) | `23 passed, 1 skipped`; WSL2 kernel ACL probe |
| 2 | `tests/test_phase7_production_deployment_verification.py` | Modified (`M`) | Adds `_terminate_chromium_process`, `_launch_headless_chromium_cdp` (strict `sys.platform.startswith("linux") and GITHUB_ACTIONS == "true"` Attempt-2 fallback), & 7 fallback policy tests | `377` | `34` | Bounded strictly to GitHub Actions Linux Attempt-2 localhost test fallback; Red Mercury sandbox intact | `12 passed, 3 skipped` (`11/11` targeted incl. live Win Chrome & deterministic fallback matrix) |
| 3 | `RED_MERCURY_PHASE8X_REMOTE_CI_VERIFICATION_AND_RELEASE_GATE_AUDIT_REPORT.md` | Untracked (`??`) | Phase 8X Run `#11` forensic & release gate audit report | `248` | `0` | None (documentation) | Intact; Gitleaks clean |
| 4 | `RED_MERCURY_PHASE8Y_REMEDIATION_REVIEW_AND_COMMIT_READINESS_REPORT.md` | Untracked (`??`) | Phase 8Y / 8Y-F / 8Y-G remediation review & commit readiness report | `202` | `0` | None (documentation) | Final Gitleaks & `git status` verified |

---

## 15. Remaining Risks & Limitations

1. **Remote `ubuntu-26.04` GitHub Actions Verification Pending Push (`NOT RUN`):** Live Linux Chrome execution with the `GITHUB_ACTIONS == "true"` fallback has not yet executed remotely; simulated policy tests do not prove live remote Chrome flags without Run `#12`.
2. **External PyPI Network Sensitivity:** `tests/test_scanners.py::test_pip_audit_on_vulnerable_manifest` queries OSV/PyPI live and experienced one transient timeout during the full local suite run before passing immediately on re-run (`8.69s`).
3. **Node 20 GitHub Actions Deprecation Warning:** Pre-existing and non-blocking in `.github/workflows/ci.yml`.

---

## 16. Commit Readiness Decision

**DECISION: READY FOR EXPLICIT USER-AUTHORIZED COMMIT & PUSH**

- Changeset strictly contains only the 4 manifest files above; zero production source, migration, Dockerfile, or workflow files touched.
- Remote post-fix GitHub Actions CI **remains pending** until authorized push.
- **Production deployment is STRICTLY NOT AUTHORIZED.**

---

## 17. Required User Authorization

- **Expected Parent Commit (`HEAD` / `origin/main`):** `1a9358a22e40bdc75ba735a63c61bad838ca3cb7` on branch `main`
- **Tracked Diff Statistics:** `2 files changed, 384 insertions(+), 35 deletions(-)` (+ 2 untracked audit reports)
- **Proposed Commit Message:**
  ```text
  fix(ci): restrict Linux Chromium fallback to GitHub Actions and fix POSIX ACL test spy
  ```
- **Awaiting explicit user approval** to stage these exact 4 files, commit to `main`, push to `origin`, and monitor remote CI Run #12 (without deploying to production).
