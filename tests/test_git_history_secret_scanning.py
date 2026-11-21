"""Phase 2A Regression Tests: Git History Secret Scanning.

Validates:
1. Harmless repository with no secrets reports clean (NO_FINDINGS).
2. Historical synthetic credential committed in an earlier commit and removed in a later commit is detected when history scanning is enabled.
3. Synthetic credential in current working tree is detected in both working tree and history modes.
4. Repositories with no Git history (.git absent) preserve compatibility and fall back gracefully.
5. Repositories with empty Git history (0 commits) report clear diagnostic status and do not crash.
6. Invalid or incomplete Git repository (.git corrupted/missing HEAD) reports EXECUTION_ERROR and never silently reports clean.
7. Gitleaks scanner adapter properly selects 'git' vs 'dir' subcommands based on options and repository structure.
8. Gitleaks failure (exit code 1 with no findings or missing report) is never masked as a clean result.
9. All synthetic secrets are strictly redacted in findings and evidence references.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
from unittest.mock import MagicMock, patch
import pytest

from app.scanner.base import ScannerStatus
from app.scanner.gitleaks import GitleaksScannerAdapter
from app.scanner.secret_detector import SecretScannerAdapter


SYNTHETIC_AWS_KEY = "AKIA" + "0123456789ABCDEF"
SYNTHETIC_GITHUB_PAT = "ghp_" + "A" * 36


def _init_git_repo(path: Path) -> None:
    """Initialize a safe, isolated disposable git repository."""
    subprocess.run(["git", "init"], cwd=str(path), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "audit@redmercury.internal"], cwd=str(path), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Red Mercury Auditor"], cwd=str(path), check=True, capture_output=True)


@pytest.fixture
def harmless_git_repo():
    """Git repo with harmless commits and zero secrets."""
    temp_dir = tempfile.mkdtemp(prefix="redmercury_git_harmless_")
    repo_path = Path(temp_dir)
    try:
        _init_git_repo(repo_path)
        (repo_path / "main.py").write_text("print('Hello World')\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=str(repo_path), check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Initial harmless commit"], cwd=str(repo_path), check=True, capture_output=True)
        yield repo_path
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def repo_with_removed_historical_secret():
    """Git repo where a synthetic credential was committed in commit 1 and removed in commit 2."""
    temp_dir = tempfile.mkdtemp(prefix="redmercury_git_hist_")
    repo_path = Path(temp_dir)
    try:
        _init_git_repo(repo_path)
        # Commit 1: Add synthetic credential
        secret_file = repo_path / "credentials.py"
        secret_file.write_text(f"# Sensitive config\nAWS_ACCESS_KEY_ID = '{SYNTHETIC_AWS_KEY}'\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=str(repo_path), check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Commit 1 with credential"], cwd=str(repo_path), check=True, capture_output=True)

        # Commit 2: Remove the credential from working tree
        secret_file.write_text("# Cleaned config\nAWS_ACCESS_KEY_ID = os.getenv('AWS_KEY')\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=str(repo_path), check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Commit 2 removed credential"], cwd=str(repo_path), check=True, capture_output=True)

        yield repo_path
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def repo_with_working_tree_secret():
    """Git repo with a synthetic secret in the current active working tree."""
    temp_dir = tempfile.mkdtemp(prefix="redmercury_git_wt_")
    repo_path = Path(temp_dir)
    try:
        _init_git_repo(repo_path)
        (repo_path / "app.py").write_text(f"GITHUB_TOKEN = '{SYNTHETIC_GITHUB_PAT}'\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=str(repo_path), check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Committed active secret"], cwd=str(repo_path), check=True, capture_output=True)
        yield repo_path
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def plain_dir_no_git():
    """Plain folder with no .git directory."""
    temp_dir = tempfile.mkdtemp(prefix="redmercury_plain_no_git_")
    proj_path = Path(temp_dir)
    try:
        (proj_path / "script.py").write_text("def run(): pass\n", encoding="utf-8")
        yield proj_path
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def repo_with_empty_git_history():
    """Git repo with .git directory but zero commits (unborn HEAD)."""
    temp_dir = tempfile.mkdtemp(prefix="redmercury_empty_git_")
    repo_path = Path(temp_dir)
    try:
        _init_git_repo(repo_path)
        # No commits made
        yield repo_path
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def corrupt_incomplete_git_repo():
    """Repository directory containing an invalid/incomplete .git folder (missing HEAD)."""
    temp_dir = tempfile.mkdtemp(prefix="redmercury_corrupt_git_")
    repo_path = Path(temp_dir)
    try:
        fake_git = repo_path / ".git"
        fake_git.mkdir(parents=True, exist_ok=True)
        # Write some junk file but do NOT create HEAD
        (fake_git / "config").write_text("[core]\nrepositoryformatversion = 0\n", encoding="utf-8")
        (repo_path / "file.py").write_text("x = 1\n", encoding="utf-8")
        yield repo_path
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


# -----------------------------------------------------------------------------
# Test Cases
# -----------------------------------------------------------------------------

def test_harmless_repo_has_zero_secrets(harmless_git_repo):
    """Verify that a repository with no secrets reports clean status."""
    adapter = SecretScannerAdapter()
    result = adapter.scan(harmless_git_repo, scan_id="test-harmless", options={"scan_git_history": True})
    assert result.status == ScannerStatus.NO_FINDINGS
    assert len(result.findings) == 0


def test_historical_secret_detected_in_git_history(repo_with_removed_historical_secret):
    """Verify that a credential removed from the working tree is detected in commit history."""
    adapter = SecretScannerAdapter()

    # 1. Without git history scanning: working tree is clean
    wt_result = adapter.scan(repo_with_removed_historical_secret, scan_id="test-wt-only", options={"scan_git_history": False})
    assert wt_result.status == ScannerStatus.NO_FINDINGS
    assert len(wt_result.findings) == 0

    # 2. With git history scanning: historical secret in commit 1 is detected
    hist_result = adapter.scan(repo_with_removed_historical_secret, scan_id="test-hist", options={"scan_git_history": True})
    assert hist_result.status == ScannerStatus.SUCCESS
    assert len(hist_result.findings) >= 1

    aws_finding = next((f for f in hist_result.findings if f.scanner_rule_id == "SEC-AWS-KEY"), None)
    assert aws_finding is not None
    assert aws_finding.file_path == "credentials.py"
    assert aws_finding.metadata.get("historical") is True
    assert "commit" in aws_finding.metadata

    # Strictly verify secret is redacted in finding evidence
    assert SYNTHETIC_AWS_KEY not in aws_finding.evidence_reference
    assert "[REDACTED_AWS_KEY]" in aws_finding.evidence_reference


def test_working_tree_secret_detected(repo_with_working_tree_secret):
    """Verify that secret present in working tree is detected and redacted."""
    adapter = SecretScannerAdapter()
    result = adapter.scan(repo_with_working_tree_secret, scan_id="test-wt-secret", options={"scan_git_history": True})

    assert result.status == ScannerStatus.SUCCESS
    assert len(result.findings) >= 1
    gh_finding = next((f for f in result.findings if f.scanner_rule_id == "SEC-GITHUB-TOKEN"), None)
    assert gh_finding is not None
    assert SYNTHETIC_GITHUB_PAT not in gh_finding.evidence_reference
    assert "[REDACTED" in gh_finding.evidence_reference


def test_non_git_repository_compatibility_preserved(plain_dir_no_git):
    """Verify compatibility with directories that lack a .git folder."""
    # Built-in scanner should not crash and should succeed with working tree scan
    adapter = SecretScannerAdapter()
    result = adapter.scan(plain_dir_no_git, scan_id="test-no-git", options={"scan_git_history": True})
    assert result.status == ScannerStatus.NO_FINDINGS
    assert len(result.findings) == 0


def test_empty_git_history_handled_safely(repo_with_empty_git_history):
    """Verify that a Git repository with zero commits reports clear error or safe status."""
    adapter = SecretScannerAdapter()
    result = adapter.scan(repo_with_empty_git_history, scan_id="test-empty-git", options={"scan_git_history": True})
    # In git, 'git log' on unborn HEAD fails; scanner must catch it and report EXECUTION_ERROR
    assert result.status == ScannerStatus.EXECUTION_ERROR
    assert "git history scanning failed" in result.error_message.lower()


def test_corrupt_incomplete_git_repo_reports_execution_error(corrupt_incomplete_git_repo):
    """Verify that an invalid .git folder (missing HEAD) returns EXECUTION_ERROR and never masks failure."""
    adapter = SecretScannerAdapter()
    result = adapter.scan(corrupt_incomplete_git_repo, scan_id="test-corrupt", options={"scan_git_history": True})
    assert result.status == ScannerStatus.EXECUTION_ERROR
    assert "incomplete" in result.error_message.lower() or "head missing" in result.error_message.lower()


def test_gitleaks_adapter_git_vs_dir_mode_selection(harmless_git_repo, plain_dir_no_git, corrupt_incomplete_git_repo):
    """Verify that GitleaksScannerAdapter chooses git vs dir mode and handles missing HEAD."""
    adapter = GitleaksScannerAdapter()

    # 1. When binary is present or mocked:
    with patch("app.scanner.gitleaks.resolve_tool_binary", return_value="C:/tools/gitleaks.exe"):
        # For plain dir with no .git: should fall back to dir mode
        with patch("subprocess.run") as mock_subproc:
            mock_subproc.return_value = MagicMock(returncode=0, stdout="", stderr="")
            res = adapter.scan(plain_dir_no_git, scan_id="test-gl-dir", options={"scan_git_history": True})
            assert mock_subproc.called
            called_args = mock_subproc.call_args[0][0]
            assert "detect" in called_args
            assert "--no-git" in called_args

        # For valid git repo: should use git mode
        with patch("subprocess.run") as mock_subproc:
            mock_subproc.return_value = MagicMock(returncode=0, stdout="", stderr="")
            res = adapter.scan(harmless_git_repo, scan_id="test-gl-git", options={"scan_git_history": True})
            assert mock_subproc.called
            called_args = mock_subproc.call_args[0][0]
            assert "detect" in called_args
            assert "--no-git" not in called_args

        # For corrupt git repo missing HEAD: should report EXECUTION_ERROR without calling subprocess
        res_corrupt = adapter.scan(corrupt_incomplete_git_repo, scan_id="test-gl-corrupt", options={"scan_git_history": True})
        assert res_corrupt.status == ScannerStatus.EXECUTION_ERROR
        assert ".git/HEAD missing" in res_corrupt.error_message


def test_gitleaks_scanner_failure_cannot_silently_be_reported_clean(harmless_git_repo):
    """Verify that if Gitleaks exits with code 1 but no findings were produced, it reports EXECUTION_ERROR."""
    adapter = GitleaksScannerAdapter()
    with patch("app.scanner.gitleaks.resolve_tool_binary", return_value="C:/tools/gitleaks.exe"):
        with patch("subprocess.run") as mock_subproc:
            # Simulate failure: exit code 1, but no report file created
            mock_subproc.return_value = MagicMock(returncode=1, stdout="", stderr="fatal: error opening repository")
            res = adapter.scan(harmless_git_repo, scan_id="test-gl-fail", options={"scan_git_history": True})

            assert res.status == ScannerStatus.EXECUTION_ERROR
            assert "fatal: error opening repository" in res.error_message
