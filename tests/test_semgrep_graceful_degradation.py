"""Regression tests verifying graceful degradation when Semgrep is not installed."""
from pathlib import Path
import tempfile
from unittest.mock import patch
import pytest

from app.scanner.semgrep import SemgrepScannerAdapter
from app.scanner.registry import scanner_registry
from app.scanner.base import ScannerStatus


def test_semgrep_degrades_gracefully_when_unavailable():
    """Verify Semgrep adapter returns unavailable and TOOL_NOT_INSTALLED when binary is missing."""
    adapter = SemgrepScannerAdapter()

    # Simulate environment where semgrep is not installed or unavailable
    with patch.object(adapter, "_get_executable_cmd", return_value=None):
        assert adapter.is_available() is False
        assert adapter.get_version() is None

        with tempfile.TemporaryDirectory() as tmp_dir:
            result = adapter.scan(
                target_dir=Path(tmp_dir),
                scan_id="test-scan-semgrep-missing"
            )

            assert result.status == ScannerStatus.TOOL_NOT_INSTALLED
            assert result.findings == []
            assert result.execution_time_seconds == 0.0
            assert "Semgrep CLI is not installed or unavailable" in result.error_message


def test_semgrep_in_scanner_registry_when_unavailable():
    """Verify registry describe_scanners reports Semgrep as unavailable without crashing."""
    adapter = scanner_registry.get("semgrep")
    assert adapter is not None

    with patch.object(adapter, "_get_executable_cmd", return_value=None):
        descriptions = scanner_registry.describe_scanners()
        semgrep_meta = next((s for s in descriptions if s["name"] == "semgrep"), None)

        assert semgrep_meta is not None
        assert semgrep_meta["is_available"] is False
        assert semgrep_meta["version"] is None
        assert semgrep_meta["display_name"] == "Semgrep OSS"


def test_semgrep_exception_during_availability_check():
    """Verify any unexpected error during binary resolution results in unavailable, no crash."""
    adapter = SemgrepScannerAdapter()

    with patch.object(adapter, "_get_executable_cmd", side_effect=OSError("Permission denied")):
        assert adapter.is_available() is False
        assert adapter.get_version() is None

        with tempfile.TemporaryDirectory() as tmp_dir:
            result = adapter.scan(
                target_dir=Path(tmp_dir),
                scan_id="test-scan-semgrep-err"
            )
            assert result.status == ScannerStatus.TOOL_NOT_INSTALLED
