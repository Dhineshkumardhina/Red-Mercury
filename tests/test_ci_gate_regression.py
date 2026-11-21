"""Comprehensive Regression Test Suite for Red Mercury CI Security Gate.

Tests all required failure and pass scenarios:
1. Clean repository (clean pass, exit code 0).
2. Repository with high-severity vulnerability (fail, exit code 1).
3. Missing security scanner under strict checks (incomplete, exit code 2).
4. Scanner execution failure (fail, exit code 1).
5. Malformed or missing result artifact (validation failure, exit code 1).
6. Unexpected or malformed exit code (enforcement failure, exit code 1).
7. Internal script exception (execution error, exit code 1).
8. Secrets redaction in artifacts and markdown comments (no credential leaks).
9. Shell exit-code capture and branch-protection enforcement in GNU bash.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from unittest.mock import patch
import pytest

from scripts.ci_security_gate import (
    run_ci_security_gate,
    redact_secrets_in_text,
    sanitize_dict_secrets,
)

PYTHON_EXE = sys.executable
GATE_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "ci_security_gate.py"


def _get_bash():
    """Locate GNU bash executable for shell-behavior tests."""
    b = shutil.which("bash")
    if b and "system32" not in b.lower():
        return b
    for candidate in [
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files\Git\usr\bin\bash.exe",
    ]:
        if Path(candidate).exists():
            return candidate
    return None


# ==============================================================================
# SCENARIO 1: CLEAN REPOSITORY PASSES GATE WITH EXIT CODE ZERO
# ==============================================================================

def test_clean_repository_passes_gate_with_exit_code_zero(tmp_path: Path):
    """Verify clean repository with zero findings passes gate with exit code 0."""
    baseline_file = tmp_path / "baseline.json"
    head_file = tmp_path / "head.json"
    out_file = tmp_path / "ci_gate_result.json"

    baseline_file.write_text("[]", encoding="utf-8")
    head_file.write_text("[]", encoding="utf-8")

    exit_code, payload = run_ci_security_gate(
        repo_path=tmp_path,
        head_sha="0123456789abcdef0123456789abcdef01234567",
        base_sha="abcdef0123456789abcdef0123456789abcdef01",
        changed_files=["src/clean_app.py"],
        fail_on_severity="HIGH",
        strict_checks=False,
        baseline_findings_file=baseline_file,
        head_findings_file=head_file,
        output_format="json",
        output_file=out_file,
    )

    assert exit_code == 0
    assert payload["gate_status"] == "PASS"
    assert payload["gate_passed"] is True
    assert payload["exit_code"] == 0
    assert payload["metrics"]["new_findings"] == 0
    assert payload["metrics"]["failed_checks"] == 0
    assert len(payload["failed_checks"]) == 0

    # Verify JSON result artifact was generated and is valid
    assert out_file.exists()
    artifact = json.loads(out_file.read_text(encoding="utf-8"))
    assert artifact["gate_status"] == "PASS"
    assert artifact["exit_code"] == 0
    assert artifact["gate_passed"] is True


def test_clean_repository_cli_execution(tmp_path: Path):
    """Verify clean repository passes via CLI execution."""
    head_file = tmp_path / "head.json"
    head_file.write_text("[]", encoding="utf-8")
    out_file = tmp_path / "out.json"

    proc = subprocess.run(
        [
            PYTHON_EXE,
            str(GATE_SCRIPT),
            "--repo-path",
            str(tmp_path),
            "--head-findings",
            str(head_file),
            "--no-strict-checks",
            "--format",
            "json",
            "--output-file",
            str(out_file),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    assert proc.returncode == 0
    assert out_file.exists()
    res = json.loads(out_file.read_text(encoding="utf-8"))
    assert res["gate_status"] == "PASS"
    assert res["exit_code"] == 0
    assert res["gate_passed"] is True


# ==============================================================================
# SCENARIO 2: REPOSITORY WITH HIGH-SEVERITY VULNERABILITY FAILS WITH CODE 1
# ==============================================================================

def test_high_severity_vulnerability_fails_gate_with_exit_code_one(tmp_path: Path):
    """Verify new high-severity vulnerability triggers gate FAIL (code 1)."""
    head_file = tmp_path / "head.json"
    out_file = tmp_path / "ci_gate_result.json"

    head_file.write_text(
        json.dumps([
            {
                "rule_id": "B608",
                "title": "SQL Injection in dynamic string query",
                "severity": "HIGH",
                "confidence": "HIGH",
                "file_path": "backend/app/routes/billing.py",
                "line_number": 105,
                "scanner_name": "bandit",
            }
        ]),
        encoding="utf-8",
    )

    proc = subprocess.run(
        [
            PYTHON_EXE,
            str(GATE_SCRIPT),
            "--repo-path",
            str(tmp_path),
            "--head-findings",
            str(head_file),
            "--changed-files",
            "backend/app/routes/billing.py",
            "--fail-on",
            "HIGH",
            "--format",
            "json",
            "--output-file",
            str(out_file),
            "--no-strict-checks",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    assert proc.returncode == 1
    assert out_file.exists()
    res = json.loads(out_file.read_text(encoding="utf-8"))
    assert res["gate_status"] == "FAIL"
    assert res["exit_code"] == 1
    assert res["gate_passed"] is False
    assert res["metrics"]["new_findings"] == 1
    assert any("B608" in f for f in res["failed_checks"])


def test_critical_severity_vulnerability_fails_on_high_threshold(tmp_path: Path):
    """Verify CRITICAL severity findings trigger failure when threshold is HIGH."""
    head_file = tmp_path / "head.json"
    head_file.write_text(
        json.dumps([
            {
                "rule_id": "CWE-78",
                "title": "Remote OS Command Injection",
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "file_path": "backend/app/core/executor.py",
                "line_number": 42,
                "scanner_name": "semgrep",
            }
        ]),
        encoding="utf-8",
    )

    exit_code, payload = run_ci_security_gate(
        repo_path=tmp_path,
        head_findings_file=head_file,
        changed_files=["backend/app/core/executor.py"],
        fail_on_severity="HIGH",
        strict_checks=False,
    )

    assert exit_code == 1
    assert payload["gate_status"] == "FAIL"
    assert payload["gate_passed"] is False


# ==============================================================================
# SCENARIO 3: MISSING SECURITY SCANNER (INCOMPLETE / EXIT CODE 2)
# ==============================================================================

def test_missing_security_scanner_returns_exit_code_two_incomplete(tmp_path: Path):
    """Verify missing required scanner under strict policy returns exit code 2."""
    head_file = tmp_path / "head.json"
    head_file.write_text("[]", encoding="utf-8")
    out_file = tmp_path / "ci_gate_result.json"

    # Simulate environment where semgrep is not found in PATH
    with patch("subprocess.run") as mock_subproc:
        mock_subproc.side_effect = FileNotFoundError("Executable 'semgrep' not found in PATH")

        exit_code, payload = run_ci_security_gate(
            repo_path=tmp_path,
            head_findings_file=head_file,
            strict_checks=True,
            output_file=out_file,
        )

        assert exit_code == 2
        assert payload["gate_status"] == "INCOMPLETE"
        assert payload["gate_passed"] is False
        assert len(payload["unavailable_checks"]) > 0
        assert any("not detected" in u or "not found" in u for u in payload["unavailable_checks"])

    assert out_file.exists()
    saved = json.loads(out_file.read_text(encoding="utf-8"))
    assert saved["gate_status"] == "INCOMPLETE"
    assert saved["exit_code"] == 2
    assert saved["gate_passed"] is False


# ==============================================================================
# SCENARIO 4: SCANNER EXECUTION FAILURE (FAIL / EXIT CODE 1)
# ==============================================================================

def test_scanner_execution_failure_fails_gate_with_exit_code_one(tmp_path: Path):
    """Verify scanner execution crash or error causes gate FAIL (code 1) instead of silent pass."""
    out_file = tmp_path / "ci_gate_result.json"

    # Direct function call with failed_checks injected
    exit_code, payload = run_ci_security_gate(
        repo_path=tmp_path,
        strict_checks=False,
        failed_checks=["Bandit: Scanner crashed with unhandled MemoryError on large file"],
        output_file=out_file,
    )

    assert exit_code == 1
    assert payload["gate_status"] == "FAIL"
    assert payload["gate_passed"] is False
    assert any("MemoryError" in fc for fc in payload["failed_checks"])

    # Test via CLI argument --failed-check
    proc = subprocess.run(
        [
            PYTHON_EXE,
            str(GATE_SCRIPT),
            "--repo-path",
            str(tmp_path),
            "--failed-check",
            "Semgrep OSS: Fatal error parsing syntax tree in invalid.py",
            "--no-strict-checks",
            "--format",
            "json",
            "--output-file",
            str(out_file),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    assert proc.returncode == 1
    res = json.loads(out_file.read_text(encoding="utf-8"))
    assert res["gate_status"] == "FAIL"
    assert res["exit_code"] == 1
    assert res["gate_passed"] is False
    assert any("Fatal error" in fc for fc in res["failed_checks"])


# ==============================================================================
# SCENARIO 5: MALFORMED OR MISSING RESULT ARTIFACT
# ==============================================================================

def test_missing_head_findings_file_is_recorded_as_failed_check(tmp_path: Path):
    """Verify referencing a non-existent head findings file is recorded as an execution failure."""
    non_existent = tmp_path / "missing_findings.json"

    exit_code, payload = run_ci_security_gate(
        repo_path=tmp_path,
        head_findings_file=non_existent,
        strict_checks=False,
    )

    # Must FAIL with code 1, not silently pass
    assert exit_code == 1
    assert payload["gate_status"] == "FAIL"
    assert payload["gate_passed"] is False
    assert any("not found" in fc for fc in payload["failed_checks"])


def test_malformed_head_findings_json_is_recorded_as_failed_check(tmp_path: Path):
    """Verify corrupted JSON in findings file causes gate to fail."""
    corrupted_file = tmp_path / "corrupted.json"
    corrupted_file.write_text("{ this is not : valid json }}}", encoding="utf-8")

    exit_code, payload = run_ci_security_gate(
        repo_path=tmp_path,
        head_findings_file=corrupted_file,
        strict_checks=False,
    )

    assert exit_code == 1
    assert payload["gate_status"] == "FAIL"
    assert payload["gate_passed"] is False
    assert any("Failed to parse" in fc for fc in payload["failed_checks"])


def test_artifact_integrity_validator_script(tmp_path: Path):
    """Verify the workflow's artifact validation logic detects missing, malformed, or incomplete artifacts."""
    validator_code = """
import json, sys
result_path = sys.argv[1]
try:
    with open(result_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    required = ['gate_status', 'exit_code', 'gate_passed', 'metrics']
    missing = [k for k in required if k not in data]
    if missing:
        sys.exit(1)
    sys.exit(0)
except Exception:
    sys.exit(1)
"""

    # 1. Valid artifact -> exits 0
    valid_file = tmp_path / "valid.json"
    valid_file.write_text(json.dumps({
        "gate_status": "PASS",
        "exit_code": 0,
        "gate_passed": True,
        "metrics": {"new_findings": 0},
    }), encoding="utf-8")

    p = subprocess.run([PYTHON_EXE, "-c", validator_code, str(valid_file)])
    assert p.returncode == 0

    # 2. Corrupted JSON -> exits 1
    corrupt_file = tmp_path / "corrupt.json"
    corrupt_file.write_text("NOT JSON", encoding="utf-8")
    p = subprocess.run([PYTHON_EXE, "-c", validator_code, str(corrupt_file)])
    assert p.returncode == 1

    # 3. Missing required fields -> exits 1
    incomplete_file = tmp_path / "incomplete.json"
    incomplete_file.write_text(json.dumps({"some_key": "some_value"}), encoding="utf-8")
    p = subprocess.run([PYTHON_EXE, "-c", validator_code, str(incomplete_file)])
    assert p.returncode == 1

    # 4. Non-existent file -> exits 1
    p = subprocess.run([PYTHON_EXE, "-c", validator_code, str(tmp_path / "non_existent.json")])
    assert p.returncode == 1


# ==============================================================================
# SCENARIO 6: UNEXPECTED OR MALFORMED EXIT CODES NEVER PASS
# ==============================================================================

def test_unexpected_exit_codes_rejected_by_enforcement_logic():
    """Verify shell enforcement logic strictly rejects unset, malformed, or unexpected exit codes."""
    bash = _get_bash()
    if not bash:
        pytest.skip("GNU bash not installed in test environment")

    enforce_script = """
    GATE_EXIT_CODE="$1"
    ARTIFACT_VALID="$2"

    if [ -z "${GATE_EXIT_CODE:-}" ]; then
        echo "Missing exit code"
        exit 1
    fi

    if [ "${ARTIFACT_VALID:-}" != "true" ]; then
        echo "Invalid artifact"
        exit 1
    fi

    case "${GATE_EXIT_CODE}" in
        0)
            echo "PASSED"
            exit 0
            ;;
        1)
            echo "FAILED"
            exit 1
            ;;
        2)
            echo "INCOMPLETE"
            exit 2
            ;;
        *)
            echo "UNEXPECTED"
            exit 1
            ;;
    esac
    """

    # Test cases: (GATE_EXIT_CODE, ARTIFACT_VALID, expected_returncode)
    test_cases = [
        ("0", "true", 0),       # Valid clean pass
        ("1", "true", 1),       # Valid policy fail
        ("2", "true", 2),       # Valid incomplete
        ("0", "false", 1),      # Exit 0 but artifact invalid -> MUST FAIL
        ("", "true", 1),        # Missing exit code -> MUST FAIL
        ("abc", "true", 1),     # Malformed string -> MUST FAIL
        ("137", "true", 1),     # OOM SIGKILL exit code -> MUST FAIL
        ("255", "true", 1),     # Unhandled error code -> MUST FAIL
        ("-1", "true", 1),      # Negative code -> MUST FAIL
        ("3", "true", 1),       # Unknown code 3 -> MUST FAIL
    ]

    for code_val, art_val, expected_rc in test_cases:
        proc = subprocess.run(
            [bash, "-c", enforce_script, "_", code_val, art_val],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert proc.returncode == expected_rc, f"Failed for code={code_val}, artifact={art_val}: got {proc.returncode}"


# ==============================================================================
# SCENARIO 7: INTERNAL SCRIPT EXCEPTION FAILS WITH EXIT CODE ONE
# ==============================================================================

def test_internal_script_exception_fails_with_exit_code_one(tmp_path: Path):
    """Verify internal unhandled exception exits code 1 and writes error artifact."""
    out_file = tmp_path / "error_result.json"

    # Pass an invalid repo-path that will cause an internal failure
    # and verify top-level error handler catches it, writes error artifact, and exits 1
    script_test = f"""
import sys
from scripts.ci_security_gate import main
sys.argv = [
    'ci_security_gate.py',
    '--repo-path', r'{str(tmp_path)}',
    '--output-file', r'{str(out_file)}',
    '--fail-on', 'HIGH',
]
# Force an unexpected exception inside run_ci_security_gate
from unittest.mock import patch
with patch('scripts.ci_security_gate.run_ci_security_gate') as mock_gate:
    mock_gate.side_effect = RuntimeError("Catastrophic database or memory corruption simulated")
    main()
"""

    proc = subprocess.run(
        [PYTHON_EXE, "-c", script_test],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    # Must exit with code 1
    assert proc.returncode == 1
    assert "Catastrophic database or memory corruption" in proc.stderr or "Error" in proc.stderr

    # Fallback artifact must have been written
    assert out_file.exists()
    err_artifact = json.loads(out_file.read_text(encoding="utf-8"))
    assert err_artifact["gate_status"] == "ERROR"
    assert err_artifact["exit_code"] == 1
    assert err_artifact["gate_passed"] is False
    assert any("Catastrophic" in fc for fc in err_artifact["failed_checks"])


# ==============================================================================
# SCENARIO 8: SECRETS REDACTION IN ARTIFACTS AND MARKDOWN SUMMARIES
# ==============================================================================

def test_secrets_are_redacted_in_artifacts_and_comments(tmp_path: Path):
    """Verify raw secrets, tokens, and API keys are redacted before writing artifacts or comments."""
    head_file = tmp_path / "head.json"
    verif_file = tmp_path / "verif.json"
    out_file = tmp_path / "ci_gate_result.json"

    raw_aws_key = "AKIAIOSFODNN7EXAMPLE"
    raw_github_pat = "ghp_123456789012345678901234567890123456"
    raw_stripe_key = "sk_" + "live_" + "123456789012345678901234"
    raw_slack_token = "xoxb-" + "1234567890-" + "1234567890123-" + "abcdef1234567890"

    head_file.write_text(json.dumps([
        {
            "rule_id": "SEC-01",
            "title": f"Hardcoded AWS key {raw_aws_key} detected in config.py",
            "message": f"Detected secret token: {raw_github_pat}",
            "severity": "HIGH",
            "confidence": "HIGH",
            "file_path": "config.py",
            "line_number": 12,
            "scanner_name": "secret_detector",
        }
    ]), encoding="utf-8")

    verif_file.write_text(json.dumps([
        {
            "finding_title": f"Fixed Stripe key leak {raw_stripe_key}",
            "file_path": "billing.py",
            "status": "VERIFIED",
            "evidence_items": [
                f"Slack webhook removed: {raw_slack_token}",
                "password = 'super_secret_db_password_123'",
            ],
        }
    ]), encoding="utf-8")

    exit_code, payload = run_ci_security_gate(
        repo_path=tmp_path,
        head_findings_file=head_file,
        verifications_file=verif_file,
        strict_checks=False,
        output_file=out_file,
    )

    # Raw secret tokens must NOT appear anywhere in the result payload JSON
    output_text = out_file.read_text(encoding="utf-8")
    assert raw_aws_key not in output_text
    assert raw_github_pat not in output_text
    assert raw_stripe_key not in output_text
    assert raw_slack_token not in output_text
    assert "super_secret_db_password_123" not in output_text

    # Redaction placeholders must be present
    assert "[REDACTED_AWS_KEY]" in output_text
    assert "[REDACTED_GITHUB_TOKEN]" in output_text
    assert "[REDACTED_STRIPE_KEY]" in output_text
    assert "[REDACTED_SLACK_TOKEN]" in output_text
    assert "[REDACTED_SECRET]" in output_text

    # Markdown summary must also be clean
    summary_md = payload["summary_markdown"]
    assert raw_aws_key not in summary_md
    assert raw_github_pat not in summary_md
    assert raw_stripe_key not in summary_md
    assert raw_slack_token not in summary_md


# ==============================================================================
# SCENARIO 9: SHELL EXIT-CODE CAPTURE UNDER SET -E IN GNU BASH
# ==============================================================================

def test_shell_exit_code_capture_with_set_minus_e():
    """Verify that using set +e reliably captures non-zero exit codes without terminating the shell."""
    bash = _get_bash()
    if not bash:
        pytest.skip("GNU bash not installed in test environment")

    # The workflow step snippet
    workflow_step_snippet = """
    set -e
    mkdir -p tmp_artifacts
    
    GATE_EXIT_CODE=255
    set +e
    # Run a command that exits with code 1
    (exit 1)
    GATE_EXIT_CODE=$?
    set -e
    
    echo "GATE_EXIT_CODE=${GATE_EXIT_CODE}"
    """

    proc = subprocess.run(
        [bash, "-c", workflow_step_snippet],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    assert proc.returncode == 0
    assert "GATE_EXIT_CODE=1" in proc.stdout
