"""Automated CLI tests for Red Mercury CI Security Gate (scripts/ci_security_gate.py)."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import pytest

PYTHON_EXE = sys.executable
GATE_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "ci_security_gate.py"


def test_ci_gate_cli_help():
    """Verify --help succeeds with code 0 and displays documented argument aliases."""
    proc = subprocess.run(
        [PYTHON_EXE, str(GATE_SCRIPT), "--help"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert proc.returncode == 0
    assert "--repo-path" in proc.stdout
    assert "--workspace" in proc.stdout
    assert "--output-file" in proc.stdout
    assert "--output-report" in proc.stdout
    assert "sarif" in proc.stdout


def test_ci_gate_invalid_argument_exits_code_2():
    """Verify unrecognized arguments or invalid fail-on values return exit code 2."""
    proc = subprocess.run(
        [PYTHON_EXE, str(GATE_SCRIPT), "--fail-on", "EXTREME_DANGER"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert proc.returncode == 2
    assert "Invalid severity threshold" in proc.stderr or "error" in proc.stderr


def test_ci_gate_aliases_and_sarif_output():
    """Verify execution with documented aliases (--workspace, --output-report, --fail-on high_or_critical, --format sarif)."""
    with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as tf:
        sarif_path = Path(tf.name)

    try:
        proc = subprocess.run(
            [
                PYTHON_EXE,
                str(GATE_SCRIPT),
                "--workspace",
                ".",
                "--fail-on",
                "high_or_critical",
                "--format",
                "sarif",
                "--output-report",
                str(sarif_path),
                "--no-strict-checks",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert proc.returncode in (0, 1)  # clean pass or policy pass
        assert sarif_path.exists()

        content = json.loads(sarif_path.read_text(encoding="utf-8"))
        assert content.get("version") == "2.1.0"
        assert "$schema" in content
        assert "runs" in content
        driver = content["runs"][0]["tool"]["driver"]
        assert driver["name"] == "Red Mercury"
    finally:
        if sarif_path.exists():
            sarif_path.unlink()


def test_ci_gate_policy_threshold_enforcement_exit_code_1():
    """Verify that findings exceeding fail-on severity trigger gate FAIL (exit code 1)."""
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as head_f:
        json.dump([
            {
                "rule_id": "B608",
                "title": "SQL Injection vulnerability",
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "file_path": "backend/app/auth.py",
                "line_number": 42,
                "scanner_name": "bandit",
            }
        ], head_f)
        head_path = Path(head_f.name)

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as out_f:
        out_path = Path(out_f.name)

    try:
        proc = subprocess.run(
            [
                PYTHON_EXE,
                str(GATE_SCRIPT),
                "--repo-path",
                ".",
                "--head-findings",
                str(head_path),
                "--changed-files",
                "backend/app/auth.py",
                "--fail-on",
                "HIGH",
                "--format",
                "json",
                "--output-file",
                str(out_path),
                "--no-strict-checks",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        # CRITICAL finding on HIGH threshold -> exit code 1
        assert proc.returncode == 1

        result = json.loads(out_path.read_text(encoding="utf-8"))
        assert result["gate_status"] == "FAIL"
        assert result["exit_code"] == 1
        assert result["gate_passed"] is False
        assert result["metrics"]["new_findings"] == 1
        assert len(result["failed_checks"]) >= 1
    finally:
        if head_path.exists():
            head_path.unlink()
        if out_path.exists():
            out_path.unlink()


def test_ci_gate_findings_below_threshold_pass_exit_code_0():
    """Verify that findings below threshold (LOW when fail-on is HIGH) pass with exit code 0."""
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as head_f:
        json.dump([
            {
                "rule_id": "B101",
                "title": "Use of assert detected",
                "severity": "LOW",
                "confidence": "LOW",
                "file_path": "backend/app/debug.py",
                "line_number": 10,
                "scanner_name": "bandit",
            }
        ], head_f)
        head_path = Path(head_f.name)

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as out_f:
        out_path = Path(out_f.name)

    try:
        proc = subprocess.run(
            [
                PYTHON_EXE,
                str(GATE_SCRIPT),
                "--repo-path",
                ".",
                "--head-findings",
                str(head_path),
                "--changed-files",
                "backend/app/debug.py",
                "--fail-on",
                "HIGH",
                "--format",
                "json",
                "--output-file",
                str(out_path),
                "--no-strict-checks",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert proc.returncode == 0

        result = json.loads(out_path.read_text(encoding="utf-8"))
        assert result["gate_status"] == "PASS"
        assert result["exit_code"] == 0
        assert result["gate_passed"] is True
        assert result["metrics"]["new_findings"] == 1
        assert len(result["failed_checks"]) == 0
    finally:
        if head_path.exists():
            head_path.unlink()
        if out_path.exists():
            out_path.unlink()
