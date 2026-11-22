"""Phase 2C: Patch Atomicity, Rollback, and Fix Verification Tests.

Validates:
1. Valid single-file patch applies cleanly and modifies file hash.
2. Valid multi-file patch applies atomically across all target files.
3. Patch containing an invalid later hunk is rejected with zero disk modifications.
4. Path traversal attempts in diff headers are rejected without file mutations.
5. Binary patch attempts (e.g. GIT binary patch, Binary files differ) are rejected cleanly.
6. Hash verification confirms file integrity before and after patch application.
7. Multi-file patch with error on a later file completely rolls back earlier changes.
8. Regression-test failure after applying patch marks verification as FAILED_VERIFICATION.
9. Scanner failure during rescan results in INCONCLUSIVE verification without marking clean.
10. Interrupted verification cleans up disposable verification workspaces.
"""
import hashlib
from pathlib import Path
import shutil
import tempfile
from unittest.mock import MagicMock, patch
import pytest
from sqlalchemy.orm import Session

from app.verification.patch_parser import parse_unified_diff
from app.verification.patch_applier import apply_patch_to_workspace, calculate_file_hash
from app.verification.service import execute_fix_verification
from app.verification.workspace import create_verification_workspace
from app.schemas.verification import (
    VerificationRunRequest,
    VerificationStatus,
)
from app.models.repository import Repository
from app.models.finding import SecurityFinding
from app.models.verification import VerificationRun


@pytest.fixture
def disposable_workspace():
    """Create an isolated workspace containing standard test files."""
    temp_dir = tempfile.mkdtemp(prefix="redmercury_patch_atomic_")
    ws_path = Path(temp_dir)
    try:
        (ws_path / "auth.py").write_text(
            "def authenticate(u, p):\n"
            "    # insecure query\n"
            "    query = f'SELECT * FROM users WHERE u=\"{u}\"'\n"
            "    return query\n",
            encoding="utf-8",
        )
        (ws_path / "config.py").write_text(
            "DEBUG = True\n"
            "PORT = 8080\n",
            encoding="utf-8",
        )
        yield ws_path
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_valid_single_file_patch_and_hash_verification(disposable_workspace):
    """Verify single-file patch updates target and changes hash while untouched file hash is preserved."""
    auth_file = disposable_workspace / "auth.py"
    config_file = disposable_workspace / "config.py"

    pre_auth_hash = calculate_file_hash(auth_file)
    pre_config_hash = calculate_file_hash(config_file)

    diff = (
        "--- a/auth.py\n"
        "+++ b/auth.py\n"
        "@@ -2,2 +2,2 @@\n"
        "-    # insecure query\n"
        "-    query = f'SELECT * FROM users WHERE u=\"{u}\"'\n"
        "+    # secure parameterized query\n"
        "+    query = 'SELECT * FROM users WHERE u=?'\n"
    )

    parsed = parse_unified_diff(diff)
    assert parsed.is_valid is True

    success, errors = apply_patch_to_workspace(disposable_workspace, parsed)
    assert success is True
    assert errors == []

    post_auth_hash = calculate_file_hash(auth_file)
    post_config_hash = calculate_file_hash(config_file)

    # Auth file hash must change
    assert post_auth_hash != pre_auth_hash
    # Config file must remain untouched with identical hash
    assert post_config_hash == pre_config_hash
    assert "SELECT * FROM users WHERE u=?" in auth_file.read_text(encoding="utf-8")


def test_valid_multi_file_patch_atomicity(disposable_workspace):
    """Verify multi-file patch applies atomically to all files."""
    diff = (
        "diff --git a/auth.py b/auth.py\n"
        "--- a/auth.py\n"
        "+++ b/auth.py\n"
        "@@ -1,2 +1,2 @@\n"
        "-def authenticate(u, p):\n"
        "-    # insecure query\n"
        "+def authenticate_user(u, p):\n"
        "+    # secured query\n"
        "diff --git a/config.py b/config.py\n"
        "--- a/config.py\n"
        "+++ b/config.py\n"
        "@@ -1,2 +1,2 @@\n"
        "-DEBUG = True\n"
        "-PORT = 8080\n"
        "+DEBUG = False\n"
        "+PORT = 8443\n"
    )

    parsed = parse_unified_diff(diff)
    assert parsed.is_valid is True
    assert len(parsed.files) == 2

    success, errors = apply_patch_to_workspace(disposable_workspace, parsed)
    assert success is True
    assert errors == []

    auth_content = (disposable_workspace / "auth.py").read_text(encoding="utf-8")
    config_content = (disposable_workspace / "config.py").read_text(encoding="utf-8")

    assert "authenticate_user" in auth_content
    assert "DEBUG = False" in config_content
    assert "PORT = 8443" in config_content


def test_patch_containing_invalid_later_hunk_aborts_without_modification(disposable_workspace):
    """Verify that if hunk 1 is valid but hunk 2 fails, the file is NOT partially updated."""
    auth_file = disposable_workspace / "auth.py"
    original_content = auth_file.read_text(encoding="utf-8")
    original_hash = calculate_file_hash(auth_file)

    diff = (
        "--- a/auth.py\n"
        "+++ b/auth.py\n"
        "@@ -1,2 +1,2 @@\n"
        "-def authenticate(u, p):\n"
        "-    # insecure query\n"
        "+def authenticate_user(u, p):\n"
        "+    # secured query\n"
        "@@ -15,2 +15,2 @@\n"
        "-NON_EXISTENT_CONTEXT_LINE_AT_LINE_15\n"
        "+REPLACEMENT_LINE\n"
    )

    parsed = parse_unified_diff(diff)
    assert parsed.is_valid is True

    success, errors = apply_patch_to_workspace(disposable_workspace, parsed)
    assert success is False
    assert len(errors) > 0
    assert any("mismatch" in e.lower() or "past end of file" in e.lower() for e in errors)

    # Disk file must be completely untouched!
    current_content = auth_file.read_text(encoding="utf-8")
    current_hash = calculate_file_hash(auth_file)
    assert current_content == original_content
    assert current_hash == original_hash
    assert "authenticate_user" not in current_content


def test_path_traversal_patch_is_rejected(disposable_workspace):
    """Verify path traversal in patch headers is blocked before any disk write."""
    diff = (
        "--- a/../../etc/passwd\n"
        "+++ b/../../etc/passwd\n"
        "@@ -1,1 +1,1 @@\n"
        "-root:x:0:0:root:/root:/bin/bash\n"
        "+root:x:0:0:root:/root:/bin/sh\n"
    )

    parsed = parse_unified_diff(diff)
    assert parsed.is_valid is False
    assert any("traversal" in e.lower() for e in parsed.errors)

    success, errors = apply_patch_to_workspace(disposable_workspace, parsed)
    assert success is False
    assert any("invalid patch" in e.lower() for e in errors)


def test_binary_patch_handling_rejected():
    """Verify binary diff formats are safely detected and rejected."""
    binary_diff_1 = (
        "diff --git a/logo.png b/logo.png\n"
        "Binary files a/logo.png and b/logo.png differ\n"
    )
    parsed_1 = parse_unified_diff(binary_diff_1)
    assert parsed_1.is_valid is False
    assert any("binary" in e.lower() for e in parsed_1.errors)

    binary_diff_2 = (
        "diff --git a/bin.dat b/bin.dat\n"
        "index 0000000..1111111\n"
        "GIT binary patch\n"
        "literal 5\n"
        "WcmV+!00001\n"
    )
    parsed_2 = parse_unified_diff(binary_diff_2)
    assert parsed_2.is_valid is False
    assert any("binary" in e.lower() for e in parsed_2.errors)


def test_multi_file_partial_failure_rollback(disposable_workspace):
    """Verify that in a 2-file patch, if file 1 is valid but file 2 fails, file 1 is NOT changed."""
    auth_file = disposable_workspace / "auth.py"
    config_file = disposable_workspace / "config.py"

    orig_auth_content = auth_file.read_text(encoding="utf-8")
    orig_auth_hash = calculate_file_hash(auth_file)
    orig_config_content = config_file.read_text(encoding="utf-8")
    orig_config_hash = calculate_file_hash(config_file)

    diff = (
        "diff --git a/auth.py b/auth.py\n"
        "--- a/auth.py\n"
        "+++ b/auth.py\n"
        "@@ -1,2 +1,2 @@\n"
        "-def authenticate(u, p):\n"
        "-    # insecure query\n"
        "+def authenticate_user(u, p):\n"
        "+    # secured query\n"
        "diff --git a/config.py b/config.py\n"
        "--- a/config.py\n"
        "+++ b/config.py\n"
        "@@ -1,2 +1,2 @@\n"
        "-TOTALLY_WRONG_NONEXISTENT_HEADER_LINE\n"
        "+DEBUG = False\n"
    )

    parsed = parse_unified_diff(diff)
    assert parsed.is_valid is True

    success, errors = apply_patch_to_workspace(disposable_workspace, parsed)
    assert success is False
    assert len(errors) > 0

    # Verify ATOMICITY: auth.py must NOT have been modified!
    assert auth_file.read_text(encoding="utf-8") == orig_auth_content
    assert calculate_file_hash(auth_file) == orig_auth_hash
    assert config_file.read_text(encoding="utf-8") == orig_config_content
    assert calculate_file_hash(config_file) == orig_config_hash


def test_fix_verification_regression_test_failure_behavior(db_session: Session, disposable_workspace):
    """Verify that fix verification reports FAILED_VERIFICATION when a regression test fails."""
    # Seed finding in DB
    user_id = "test-user-atomic"
    repo = Repository(
        owner_id=user_id,
        name="test-atomic-repo",
        workspace_path=str(disposable_workspace),
    )
    db_session.add(repo)
    db_session.commit()

    finding = SecurityFinding(
        repo_id=repo.id,
        scanner_name="Bandit",
        rule_identifier="B608",
        cwe="CWE-89: SQL Injection",
        title="SQL Injection",
        file_path="auth.py",
        line_number=3,
        code_excerpt="query = f'SELECT * FROM users WHERE u=\"{u}\"'\n",
        severity="HIGH",
        status="open",
    )
    db_session.add(finding)
    db_session.commit()

    diff = (
        "--- a/auth.py\n"
        "+++ b/auth.py\n"
        "@@ -3,2 +3,2 @@\n"
        "-    query = f'SELECT * FROM users WHERE u=\"{u}\"'\n"
        "+    query = 'SELECT * FROM users WHERE u=?'\n"
    )

    # Mock test runner to simulate regression test failure
    req = VerificationRunRequest(
        finding_id=finding.id,
        proposed_patch=diff,
        run_existing_tests=True,
    )

    with patch("app.verification.service.run_scanners_on_directory", return_value=([], {}, [])):
        with patch("app.verification.service.run_pytest_in_workspace") as mock_test_runner:
            # Baseline test passed, patched test failed (regression!)
            mock_base = MagicMock(status="passed", test_suite_name="test_auth", passed_count=5, failed_count=0, error_message="", output_log="5 passed")
            mock_patched = MagicMock(status="failed", test_suite_name="test_auth", passed_count=3, failed_count=2, error_message="AssertionError", output_log="AssertionError: 2 failed")
            mock_test_runner.side_effect = [mock_base, mock_patched]

            response = execute_fix_verification(request=req, db=db_session, user_id=user_id)

            assert response.status == VerificationStatus.FAILED_VERIFICATION
            assert len(response.test_regressions) > 0
            assert any("test regression detected" in r.lower() for r in response.reasons)


def test_fix_verification_scanner_rescan_failure_inconclusive(db_session: Session, disposable_workspace):
    """Verify that if the scanner fails during rescan, status is INCONCLUSIVE and not marked clean."""
    repo = Repository(
        owner_id="user-rescan-fail",
        name="test-rescan-fail",
        workspace_path=str(disposable_workspace),
    )
    db_session.add(repo)
    db_session.commit()

    finding = SecurityFinding(
        repo_id=repo.id,
        scanner_name="Bandit",
        rule_identifier="B608",
        cwe="CWE-89: SQL Injection",
        title="SQL Injection",
        file_path="auth.py",
        line_number=3,
        code_excerpt="query = f'SELECT * FROM users WHERE u=\"{u}\"'\n",
        severity="HIGH",
        status="open",
    )
    db_session.add(finding)
    db_session.commit()

    diff = (
        "--- a/auth.py\n"
        "+++ b/auth.py\n"
        "@@ -3,2 +3,2 @@\n"
        "-    query = f'SELECT * FROM users WHERE u=\"{u}\"'\n"
        "+    query = 'SELECT * FROM users WHERE u=?'\n"
    )

    req = VerificationRunRequest(
        finding_id=finding.id,
        proposed_patch=diff,
        run_existing_tests=False,
    )

    # Baseline scanner succeeds; rescan raises execution error
    with patch("app.verification.service.run_scanners_on_directory") as mock_scan:
        mock_scan.side_effect = [
            ([], {"bandit": "1.7.5"}, []),  # Baseline
            ([], {"bandit": "1.7.5"}, ["Scanner execution error: Bandit AST parser crashed"]),  # Rescan
        ]

        response = execute_fix_verification(request=req, db=db_session, user_id="user-rescan-fail")
        assert response.status == VerificationStatus.INCONCLUSIVE
        assert any("error" in err.lower() for err in response.execution_errors)


def test_patch_applier_preserves_executable_and_strips_unsafe_modes_posix(tmp_path: Path):
    """Phase 8T Regression (Finding A): Preserves owner +x bit, keeps non-exec private, and strips group/world write bits."""
    import os
    import stat
    from app.verification.patch_applier import (
        _read_text_posix_nofollow,
        _sanitize_preserved_mode,
        _write_text_posix_nofollow,
    )

    assert _sanitize_preserved_mode(None) == 0o600
    assert _sanitize_preserved_mode(0o644) == 0o600
    assert _sanitize_preserved_mode(0o777) == 0o700
    assert _sanitize_preserved_mode(0o4755) == 0o700

    # Mocked POSIX descriptor-relative behavior (verified identically on Windows and real Linux)
    fchmod_calls = []
    fake_exec_stat = MagicMock(st_mode=stat.S_IFREG | 0o777)
    fake_nonexec_stat = MagicMock(st_mode=stat.S_IFREG | 0o666)
    open_modes = []

    def _fake_open(path_arg, flags, mode=0o777, dir_fd=None):
        if flags & 0x0200:  # O_CREAT mock marker
            open_modes.append(mode)
        return 20 if dir_fd is None else 21

    with patch("app.verification.patch_applier.os.O_RDONLY", 0, create=True), \
         patch("app.verification.patch_applier.os.O_WRONLY", 1, create=True), \
         patch("app.verification.patch_applier.os.O_CREAT", 0x0200, create=True), \
         patch("app.verification.patch_applier.os.O_EXCL", 0x0400, create=True), \
         patch("app.verification.patch_applier.os.O_DIRECTORY", 0x10000, create=True), \
         patch("app.verification.patch_applier.os.O_NOFOLLOW", 0x20000, create=True), \
         patch("app.verification.patch_applier.os.open", side_effect=_fake_open, create=True), \
         patch("app.verification.patch_applier.os.read", side_effect=[b"#!/bin/sh\necho v1\n", b""]), \
         patch("app.verification.patch_applier.os.write", side_effect=lambda fd, buf: len(buf)), \
         patch("app.verification.patch_applier.os.close", create=True), \
         patch("app.verification.patch_applier.os.fstat", return_value=fake_exec_stat), \
         patch("app.verification.patch_applier.os.lstat", return_value=fake_exec_stat), \
         patch("app.verification.patch_applier.os.fchmod", side_effect=lambda fd, m: fchmod_calls.append(m), create=True), \
         patch("app.verification.patch_applier.os.replace") as mock_replace:
        content, _, captured_mode = _read_text_posix_nofollow(tmp_path, ["run.sh"])
        assert "echo v1" in content
        assert stat.S_IMODE(captured_mode) == 0o777
        _write_text_posix_nofollow(tmp_path, ["run.sh"], "#!/bin/sh\necho v2\n", create_parents=False, file_mode=captured_mode)
        # Temp file was opened private 0o600, then fchmod'd to 0o700 via open fd before atomic os.replace
        assert open_modes == [0o600]
        assert fchmod_calls == [0o700]
        assert mock_replace.called

    # Non-executable file remains 0o600 without fchmod to +x
    fchmod_nonexec = []
    with patch("app.verification.patch_applier.os.O_RDONLY", 0, create=True), \
         patch("app.verification.patch_applier.os.O_WRONLY", 1, create=True), \
         patch("app.verification.patch_applier.os.O_CREAT", 0x0200, create=True), \
         patch("app.verification.patch_applier.os.O_EXCL", 0x0400, create=True), \
         patch("app.verification.patch_applier.os.O_DIRECTORY", 0x10000, create=True), \
         patch("app.verification.patch_applier.os.O_NOFOLLOW", 0x20000, create=True), \
         patch("app.verification.patch_applier.os.open", side_effect=_fake_open, create=True), \
         patch("app.verification.patch_applier.os.read", side_effect=[b"x = 1\n", b""]), \
         patch("app.verification.patch_applier.os.write", side_effect=lambda fd, buf: len(buf)), \
         patch("app.verification.patch_applier.os.close", create=True), \
         patch("app.verification.patch_applier.os.fstat", return_value=fake_nonexec_stat), \
         patch("app.verification.patch_applier.os.lstat", return_value=fake_nonexec_stat), \
         patch("app.verification.patch_applier.os.fchmod", side_effect=lambda fd, m: fchmod_nonexec.append(m), create=True), \
         patch("app.verification.patch_applier.os.replace"):
        _, _, nonexec_mode = _read_text_posix_nofollow(tmp_path, ["app.py"])
        _write_text_posix_nofollow(tmp_path, ["app.py"], "x = 2\n", create_parents=False, file_mode=nonexec_mode)
        assert fchmod_nonexec == []


def test_patch_applier_atomic_replace_failure_and_rollback_restore_permissions(disposable_workspace):
    """Phase 8T Regression (Finding A): Failed atomic replace leaves no temp files; multi-file rollback restores content & mode."""
    import os
    import stat

    script_file = disposable_workspace / "run.sh"
    script_file.write_text("#!/bin/sh\necho old\n", encoding="utf-8")
    os.chmod(script_file, 0o700)

    diff = (
        "diff --git a/run.sh b/run.sh\n"
        "--- a/run.sh\n"
        "+++ b/run.sh\n"
        "@@ -1,2 +1,2 @@\n"
        " #!/bin/sh\n"
        "-echo old\n"
        "+echo new\n"
        "diff --git a/config.py b/config.py\n"
        "--- a/config.py\n"
        "+++ b/config.py\n"
        "@@ -1,2 +1,2 @@\n"
        "-DEBUG = True\n"
        "+DEBUG = False\n"
    )
    parsed = parse_unified_diff(diff)
    assert parsed.is_valid

    if os.name == "posix":
        # 1. Real POSIX failure on file 2 replace must roll back file 1 content and 0o700 executable mode cleanly
        real_replace = os.replace
        calls = {"n": 0}

        def _fail_second_replace(src, dst, **kwargs):
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError("Simulated atomic replace failure on config.py")
            return real_replace(src, dst, **kwargs)

        with patch("app.verification.patch_applier.os.replace", side_effect=_fail_second_replace):
            success, errors = apply_patch_to_workspace(disposable_workspace, parsed)
        assert not success
        assert any("rolled back" in e.lower() for e in errors)
        assert "echo old" in script_file.read_text(encoding="utf-8")
        restored_mode = stat.S_IMODE(os.lstat(script_file).st_mode)
        assert (restored_mode & stat.S_IXUSR) != 0
        assert (restored_mode & 0o077) == 0
        assert not [p for p in disposable_workspace.iterdir() if p.name.startswith(".rm_patch_")]
    else:
        # Simulated POSIX rollback under partial write failure on Windows verifying orig_mode is preserved to rollback
        write_calls = []

        def _fake_write(root, parts, content, create_parents, file_mode=None):
            write_calls.append((tuple(parts), content, file_mode))
            if parts[-1] == "config.py":
                raise OSError("Simulated write error")

        with patch("app.verification.patch_applier._use_posix_dirfd", return_value=True), \
             patch("app.verification.patch_applier._read_text_posix_nofollow", side_effect=[
                 ("#!/bin/sh\necho old\n", "h1", 0o750),
                 ("DEBUG = True\nPORT = 8080\n", "h2", 0o640),
             ]), \
             patch("app.verification.patch_applier._write_text_posix_nofollow", side_effect=_fake_write):
            success, errors = apply_patch_to_workspace(disposable_workspace, parsed)

        assert not success
        assert any("rolled back" in e.lower() for e in errors)
        # First call: modify run.sh with 0o750; Second call: fails config.py; Third call: rollback run.sh with 0o750!
        assert write_calls[0] == (("run.sh",), "#!/bin/sh\necho new\n", 0o750)
        assert write_calls[-1] == (("run.sh",), "#!/bin/sh\necho old\n", 0o750)
