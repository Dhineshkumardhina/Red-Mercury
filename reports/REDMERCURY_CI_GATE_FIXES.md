# Red Mercury — CI Security Gate Workflow & Engine Fixes

## 1. Executive Summary

This document details the audit, remediation, and comprehensive validation of the GitHub Actions security-gate workflow ([`.github/workflows/redmercury_pr_gate.yml`](file:///.github/workflows/redmercury_pr_gate.yml)) and standalone CI gate engine ([`scripts/ci_security_gate.py`](file:///scripts/ci_security_gate.py)) in the Red Mercury codebase.

Prior to these fixes, the security gate suffered from fundamental shell exit-code capture defects, risk of silent passes on execution failures or missing artifacts, absence of scanner failure auditing in live scan paths, and lack of credential masking in pull-request comments and JSON evaluation artifacts.

All failure scenarios have been implemented, tested, and validated with regression tests.

---

## 2. Root Cause Analysis of Prior Defects

### Defect 1: Shell Exit-Code Swallowing via `set -e` Abort
* **Mechanism:** In GitHub Actions on `ubuntu-latest`, steps run in bash with `-e` (errexit) enabled by default (`bash -e {0}`).
* **Failure:** In the original workflow:
  ```bash
  python -m scripts.ci_security_gate ...
  GATE_EXIT_CODE=$?
  echo "GATE_EXIT_CODE=${GATE_EXIT_CODE}" >> $GITHUB_ENV
  ```
  When `ci_security_gate.py` returned non-zero (exit code 1 on policy failure or 2 on incomplete checks), bash immediately terminated at the `python` invocation. Lines capturing `GATE_EXIT_CODE=$?` and appending to `$GITHUB_ENV` never executed.
* **Impact:** Combined with `continue-on-error: true`, the step ended without setting `$GATE_EXIT_CODE`. Later, `[ "${GATE_EXIT_CODE}" -eq 0 ]` evaluated `[ "" -eq 0 ]`, which threw an unhandled bash integer expression error.

### Defect 2: Missing and Malformed Exit-Code Handling
* **Mechanism:** The enforcement step assumed `$GATE_EXIT_CODE` was always a valid numeric string ("0", "1", or "2").
* **Impact:** Any missing, empty, or unexpected exit code (e.g., 137 from out-of-memory, 255 from internal bash faults) caused syntax errors in `test`/`[` rather than a clean, predictable gate block.

### Defect 3: Silent Passing on Missing/Malformed Artifacts
* **Mechanism:** The original enforcement step never validated that `.redmercury_artifacts/ci_gate_result.json` was generated, valid JSON, or structurally consistent with the gate verdict.
* **Impact:** A script crash before writing the JSON artifact could allow an unverified build to proceed without a machine-readable audit trail.

### Defect 4: Missing Scanner Execution Failure Handling
* **Mechanism:** `ci_security_gate.py` checked scanner `--version` availability but did not track runtime scanner execution crashes (e.g. fatal AST syntax errors, timeouts, non-zero scanner error codes) into `failed_checks`.
* **Impact:** A broken or crashing scanner could finish without flagging a policy violation, masking serious code review blindspots.

### Defect 5: Unredacted Secrets in Artifacts and PR Comments
* **Mechanism:** Finding excerpts, rule messages, and fix-verification candidate patch diffs were inserted directly into `summary_markdown` and `ci_gate_result.json` without regex-based token redaction.
* **Impact:** Pull request comments and uploaded artifacts could inadvertently publish leaked credentials (AWS keys, GitHub tokens, Slack webhooks, Stripe keys, database passwords) into PR comments and artifact storage.

---

## 3. Detailed Breakdown of Changes

### A. GitHub Actions Workflow ([`.github/workflows/redmercury_pr_gate.yml`](file:///.github/workflows/redmercury_pr_gate.yml))

1. **Reliable Shell Exit-Code Capture:**
   * Removed misleading `continue-on-error: true`.
   * Wrapped gate execution in `set +e ... GATE_EXIT_CODE=$? ... set -e` to guarantee exit-code capture without premature shell abort.
   * Exported `GATE_EXIT_CODE` to both `$GITHUB_ENV` and `$GITHUB_OUTPUT`.
   * Initialized `GATE_EXIT_CODE=255` prior to execution as a fail-safe sentinel.

2. **Result Artifact Integrity Validation:**
   * Added dedicated step `Validate Result Artifact Integrity` (`if: always()`).
   * Verifies that `.redmercury_artifacts/ci_gate_result.json` exists on disk.
   * Parses JSON and verifies required schema fields: `gate_status`, `exit_code`, `gate_passed`, `metrics`.
   * Exports `ARTIFACT_VALID=true` or `ARTIFACT_VALID=false`.

3. **PR Security Summary Comment Sanitization:**
   * Added client-side regex redaction in `actions/github-script` before calling `createComment` / `updateComment`.
   * Handles missing or malformed JSON artifacts gracefully by displaying a structured alert without crashing the action.

4. **Deterministic DevSecOps Gate Enforcement:**
   * Runs `if: always()` as the final authoritative decision maker.
   * Fails immediately if `GATE_EXIT_CODE` is unset or empty.
   * Fails immediately if `ARTIFACT_VALID != "true"`.
   * Evaluates exit codes using a POSIX-compliant `case` construct:
     * `0`: Verifies clean pass (`exit 0`).
     * `1`: Policy failure or execution error (`exit 1`).
     * `2`: Incomplete checks under strict policy (`exit 2`).
     * `*`: Unexpected / malformed code (`exit 1`).

### B. CI Security Gate Engine ([`scripts/ci_security_gate.py`](file:///scripts/ci_security_gate.py))

1. **Comprehensive Secret Redaction:**
   * Implemented `redact_secrets_in_text()` and `sanitize_dict_secrets()`.
   * Masks AWS Access Keys (`[REDACTED_AWS_KEY]`), GitHub PATs (`[REDACTED_GITHUB_TOKEN]`), GitLab tokens (`[REDACTED_GITLAB_TOKEN]`), Slack tokens (`[REDACTED_SLACK_TOKEN]`), Stripe keys (`[REDACTED_STRIPE_KEY]`), Private Keys (`[REDACTED_PRIVATE_KEY]`), JWT tokens (`[REDACTED_JWT_TOKEN]`), and credential assignments (`[REDACTED_SECRET]`).
   * Automatically sanitizes `result_payload`, `summary_markdown`, `categorized_findings`, `verification_evidence`, and SARIF reports.

2. **Live Scanner Execution and Runtime Failure Capture:**
   * When `head_findings_file` is not provided, runs available scanners (`bandit`, `semgrep`, `pip-audit`) on the workspace with appropriate ignore flags (`tests`, `.venv`, `venv`, `backend/data/workspaces`, `samples`).
   * Captures runtime execution errors, crashes, and non-zero exit codes into `failed_checks_list`.
   * Records missing findings files or malformed JSON files into `failed_checks_list`.

3. **CLI Options for Direct Check Auditing:**
   * Added `--failed-check` and `--scanner-failure` CLI options to record explicit execution failures.
   * Added `failed_checks` and `unavailable_checks` parameters to `run_ci_security_gate()`.

4. **Top-Level Exception Safety in `main()`:**
   * Wrapped `main()` in top-level exception handling.
   * If an unhandled exception occurs, writes a fallback JSON error artifact (`gate_status: "ERROR"`, `gate_passed: False`, `exit_code: 1`) to the requested output path and exits with code 1.

---

## 4. Regression Test Matrix & Validation Results

A dedicated regression test suite was created in [`tests/test_ci_gate_regression.py`](file:///tests/test_ci_gate_regression.py) to validate all required scenarios.

| # | Test Scenario | Test Function | Input Condition | Expected Exit Code | Observed Exit Code | Result |
|---|---------------|---------------|-----------------|:------------------:|:------------------:|:------:|
| 1 | **Clean Repository** | `test_clean_repository_passes_gate_with_exit_code_zero` | Zero findings, all checks clean | 0 (PASS) | 0 | ✅ PASS |
| 1b | **Clean Repository CLI** | `test_clean_repository_cli_execution` | CLI execution with empty head findings | 0 (PASS) | 0 | ✅ PASS |
| 2 | **High-Severity Vulnerability** | `test_high_severity_vulnerability_fails_gate_with_exit_code_one` | New HIGH finding (Bandit B608) | 1 (FAIL) | 1 | ✅ PASS |
| 2b | **Critical Severity on High Gate** | `test_critical_severity_vulnerability_fails_on_high_threshold` | New CRITICAL finding (CWE-78) | 1 (FAIL) | 1 | ✅ PASS |
| 3 | **Missing Security Scanner** | `test_missing_security_scanner_returns_exit_code_two_incomplete` | Scanner not in PATH + `--strict-checks` | 2 (INCOMPLETE) | 2 | ✅ PASS |
| 4 | **Scanner Execution Failure** | `test_scanner_execution_failure_fails_gate_with_exit_code_one` | Runtime crash / MemoryError | 1 (FAIL) | 1 | ✅ PASS |
| 5a | **Missing Head Findings File** | `test_missing_head_findings_file_is_recorded_as_failed_check` | Non-existent findings path | 1 (FAIL) | 1 | ✅ PASS |
| 5b | **Malformed Head Findings JSON** | `test_malformed_head_findings_json_is_recorded_as_failed_check` | Corrupted JSON syntax | 1 (FAIL) | 1 | ✅ PASS |
| 5c | **Artifact Integrity Validator** | `test_artifact_integrity_validator_script` | Missing, truncated, or invalid schema | 1 (ERROR) | 1 | ✅ PASS |
| 6 | **Unexpected / Malformed Exit Codes** | `test_unexpected_exit_codes_rejected_by_enforcement_logic` | Codes: `""`, `"abc"`, `137`, `255`, `-1`, `3` | 1 (ERROR) | 1 | ✅ PASS |
| 7 | **Internal Script Exception** | `test_internal_script_exception_fails_with_exit_code_one` | Unhandled Python RuntimeError | 1 (ERROR) | 1 | ✅ PASS |
| 8 | **Secrets Redaction** | `test_secrets_are_redacted_in_artifacts_and_comments` | Findings with AWS, GitHub, Stripe, Slack keys | 1 (Redacted) | 1 | ✅ PASS |
| 9 | **GNU Bash `set -e` Capture** | `test_shell_exit_code_capture_with_set_minus_e` | Subshell failure under `set -e` | 0 (Captured) | 0 | ✅ PASS |

### Test Suite Execution Output

```
============================= test session starts =============================
platform win32 -- Python 3.14.7, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\PROJECTS\dhina projects\Red Mercury
collected 37 items

tests\test_ci_gate_regression.py .............                           [ 35%]
tests\test_ci_security_gate_cli.py .....                                 [ 48%]
tests\test_ci_cd_integration.py ............                             [ 81%]
tests\test_scanners.py .......                                           [100%]

================== 37 passed, 1 warning in 64.00s (0:01:03) ===================
```

---

## 5. GitHub Actions Workflow Shell Behavior & Branch Protection

### Shell Behavior Analysis
1. **Runner Default Shell:** `ubuntu-latest` executes multiline script steps in `bash -e {0}`.
2. **Safe Code Extraction:** By wrapping the Python CLI invocation in `set +e` and restoring `set -e` immediately after reading `$?`, the shell script captures the gate's exit code without aborting prematurely.
3. **Deterministic Variable Propagation:** The captured exit code is written to both `$GITHUB_ENV` (for subsequent steps) and `$GITHUB_OUTPUT` (for action step output tracing).
4. **POSIX-Compliant Fallback:** The final enforcement step uses string-safe `case "${GATE_EXIT_CODE}" in` to prevent integer expression evaluation errors on unexpected or empty inputs.

### Branch Protection Compatibility
* **Job Identifier:** `security-gate` (named `Red Mercury Security Gate & Fix Verification`).
* **Branch Rulesets:** GitHub branch protection monitors the completion status of the overall job.
* **Blocking Mechanism:** If any policy violation occurs (exit code 1), check is omitted (exit code 2), or an unexpected error occurs (exit code 1), the final step exits non-zero, causing the `security-gate` status check to be marked **FAILED** (Red X), thereby blocking pull request merges.
* **Least-Privilege Token Permissions:** Declared permissions (`contents: read`, `pull-requests: write`, `checks: write`, `issues: read`) comply with the principle of least privilege.

---

## 6. Production Readiness Verdict

> [!NOTE]
> **Production-Ready Status: VALIDATED**
> All 7 required failure scenarios (clean repo, high-severity vulnerability, missing scanner, scanner execution failure, malformed/missing artifact, unexpected exit code, internal script exception) plus credential redaction and shell exit-code capture have been implemented and validated against real test suites.

### Remaining Operational Limitations & Recommendations

1. **Monorepo / Large Codebases:** Live scanning across exceptionally large repositories (>1M lines) may exceed the 15-minute job timeout. For very large codebases, configure `--changed-files` diff-aware scanning to restrict analysis strictly to modified paths.
2. **Scanner Network Access:** `pip-audit` requires network connectivity to PyPI / OSV databases. In strictly air-gapped environments, cache vulnerability databases or provide pre-computed vulnerability findings using `--head-findings`.
3. **Artifact Retention:** Artifact retention is set to 14 days in `.github/workflows/redmercury_pr_gate.yml`. Organizations with compliance audit mandates should adjust retention to 90+ days or export SARIF reports to GitHub Code Scanning via `github/codeql-action/upload-sarif`.
