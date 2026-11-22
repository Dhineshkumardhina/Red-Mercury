"""Adversarial Security Test Suite for Red Mercury Fix Verification Engine.

Tests:
1. Malicious repository tests (conftest.py exploits, raw sockets, eval/exec, dynamic imports).
2. Path traversal, Zip Slip, and symlink-based filesystem escapes.
3. Patch applier symlink overwriting and null-byte injection rejection.
4. Excessive resource consumption, process-count bounds, and strict execution timeouts.
5. Full network isolation (--network=none, PIP_NO_INDEX=1, NO_PROXY=*).
6. Application secret, database password, and API key stripping.
7. Reliable disposable workspace destruction and cleanup on completion/error.
8. Strict fail-closed policy (INCONCLUSIVE status when container isolation is unavailable).
9. Dedicated isolated execution worker job processing.
"""
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from unittest.mock import MagicMock, patch
import zipfile

import pytest
from sqlalchemy.orm import Session

from app.core.config import Settings, settings
from app.core.errors import ValidationError
from app.core.ingestion import validate_and_extract_zip
from app.models.finding import SecurityFinding
from app.models.repository import Repository
from app.models.user import User
from app.models.verification import VerificationEvidence, VerificationRun
from app.scanner.base import get_scanner_env
from app.scanner.worker import process_pending_verifications
from app.schemas.verification import (
    PatchValidationResult,
    VerificationRunRequest,
    VerificationStatus,
)
from app.verification.patch_applier import apply_patch_to_workspace
from app.verification.patch_parser import parse_unified_diff
from app.verification.runner import inspect_test_safety, run_pytest_in_workspace
from app.verification.sandbox import (
    SandboxConfig,
    build_container_run_command,
    execute_in_restricted_subprocess,
    run_isolated_verification_command,
    terminate_process_tree,
)
from app.verification.service import execute_fix_verification
from app.verification.workspace import (
    VerificationWorkspace,
    create_verification_workspace,
    get_sanitized_runner_env,
    safe_copy_source_tree,
)


# ==============================================================================
# 1. MALICIOUS TEST CODE & CONFTEST DEFENSE TESTS
# ==============================================================================

def test_adversarial_conftest_os_system_blocked(tmp_path: Path):
    """Verify that malicious conftest.py with os.system is detected and blocked."""
    conftest = tmp_path / "conftest.py"
    conftest.write_text("import os\nos.system('whoami')", encoding="utf-8")

    violation = inspect_test_safety(workspace_dir=tmp_path)
    assert violation is not None
    assert "conftest.py" in violation
    assert "prohibited call" in violation.lower() or "os.system" in violation


def test_adversarial_socket_exfiltration_blocked(tmp_path: Path):
    """Verify that tests attempting raw socket connections for exfiltration are blocked."""
    test_file = tmp_path / "test_exfil.py"
    test_file.write_text(
        "import socket\ndef test_leak():\n    s = socket.socket()\n    s.connect(('169.254.169.254', 80))\n",
        encoding="utf-8",
    )

    violation = inspect_test_safety(workspace_dir=tmp_path)
    assert violation is not None
    assert "prohibited" in violation.lower()
    assert "socket" in violation.lower()


def test_adversarial_dynamic_eval_exec_blocked(tmp_path: Path):
    """Verify that tests employing eval, exec, or __import__ are rejected."""
    test_file = tmp_path / "test_obfuscated.py"
    test_file.write_text(
        "def test_eval():\n    eval('__import__(\"os\").system(\"id\")')\n",
        encoding="utf-8",
    )

    violation = inspect_test_safety(workspace_dir=tmp_path)
    assert violation is not None
    assert "eval" in violation or "prohibited" in violation.lower()


def test_adversarial_ctypes_import_blocked(tmp_path: Path):
    """Verify that tests attempting to load native libraries via ctypes are rejected."""
    test_file = tmp_path / "test_native.py"
    test_file.write_text(
        "import ctypes\ndef test_raw():\n    ctypes.CDLL(None)\n",
        encoding="utf-8",
    )

    violation = inspect_test_safety(workspace_dir=tmp_path)
    assert violation is not None
    assert "ctypes" in violation.lower()


# ==============================================================================
# 2. PATH TRAVERSAL & SYMLINK ESCAPE DEFENSE TESTS
# ==============================================================================

def test_adversarial_archive_traversal_blocked(tmp_path: Path):
    """Verify that zip archives with directory traversal paths are strictly rejected."""
    zip_file = tmp_path / "malicious.zip"
    dest_dir = tmp_path / "extracted"

    # Create zip with directory traversal entry
    with zipfile.ZipFile(zip_file, "w") as zf:
        zf.writestr("../../etc/passwd", "root:pwned:0:0")

    with pytest.raises(ValidationError) as exc_info:
        validate_and_extract_zip(zip_path=zip_file, dest_dir=dest_dir)

    assert "traversal" in str(exc_info.value).lower()


def test_adversarial_workspace_symlink_escape_skipped(tmp_path: Path):
    """Verify that symlinks pointing outside the repository are skipped and not copied into workspaces."""
    secret_dir = tmp_path / "host_secrets"
    secret_dir.mkdir()
    secret_file = secret_dir / "master_db.key"
    secret_file.write_text("SUPER_SECRET_KEY_NEVER_LEAK", encoding="utf-8")

    repo_dir = tmp_path / "untrusted_repo"
    repo_dir.mkdir()
    normal_file = repo_dir / "app.py"
    normal_file.write_text("print('hello')", encoding="utf-8")

    # Create malicious symlink pointing outside repository to host secret
    symlink_file = repo_dir / "external_secret.key"
    try:
        symlink_file.symlink_to(secret_file)
        workspace = create_verification_workspace(source_dir=repo_dir)
        try:
            copied_secret = workspace.workspace_dir / "external_secret.key"
            assert not copied_secret.exists(), "Symlink pointing outside repository was copied into workspace!"
            assert (workspace.workspace_dir / "app.py").exists()
        finally:
            workspace.cleanup()
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation not supported without administrative privileges in this environment")


def test_adversarial_patch_symlink_overwrite_rejected(tmp_path: Path):
    """Verify that a patch targeting an existing symlink is rejected to prevent writing through symlinks."""
    outside_target = tmp_path / "important_host_config.txt"
    outside_target.write_text("ORIGINAL_HOST_CONFIG", encoding="utf-8")

    workspace_dir = tmp_path / "test_ws"
    workspace_dir.mkdir()
    symlink_target = workspace_dir / "link_config.txt"

    diff = (
        "--- a/link_config.txt\n"
        "+++ b/link_config.txt\n"
        "@@ -1,1 +1,1 @@\n"
        "-ORIGINAL_HOST_CONFIG\n"
        "+PWNED_HOST_CONFIG\n"
    )
    parsed = parse_unified_diff(diff)
    assert parsed.is_valid

    try:
        symlink_target.symlink_to(outside_target)
        success, errors = apply_patch_to_workspace(workspace_root=workspace_dir, patch_result=parsed)
        assert not success
        assert any("symbolic link" in e.lower() for e in errors)
        assert outside_target.read_text(encoding="utf-8") == "ORIGINAL_HOST_CONFIG"
    except (OSError, NotImplementedError):
        # On Windows non-admin, test with mocked is_symlink
        symlink_target.write_text("ORIGINAL_HOST_CONFIG", encoding="utf-8")
        with patch.object(Path, "is_symlink", return_value=True):
            success, errors = apply_patch_to_workspace(workspace_root=workspace_dir, patch_result=parsed)
            assert not success
            assert any("symbolic link" in e.lower() for e in errors)


def test_adversarial_patch_null_byte_rejected(tmp_path: Path):
    """Verify that patch paths containing null bytes are rejected."""
    workspace_dir = tmp_path / "ws_null"
    workspace_dir.mkdir()

    # Create dummy parsed patch with null byte
    diff = "--- a/src/app\x00.py\n+++ b/src/app\x00.py\n@@ -1,1 +1,1 @@\n-a\n+b\n"
    parsed = parse_unified_diff(diff)

    success, errors = apply_patch_to_workspace(workspace_root=workspace_dir, patch_result=parsed)
    assert not success
    assert any("null byte" in e.lower() or "invalid" in e.lower() for e in errors)


def test_adversarial_patch_path_traversal_rejected(tmp_path: Path):
    """Verify that patches attempting directory traversal escape are rejected."""
    workspace_dir = tmp_path / "ws_trav"
    workspace_dir.mkdir()

    diff = (
        "--- a/../../../../etc/passwd\n"
        "+++ b/../../../../etc/passwd\n"
        "@@ -1,1 +1,1 @@\n"
        "-root\n"
        "+pwned\n"
    )
    parsed = parse_unified_diff(diff)
    assert not parsed.is_valid
    assert any("traversal" in e.lower() for e in parsed.errors)


# ==============================================================================
# 3. RESOURCE BOUNDING, TIMEOUTS & PROCESS TERMINATION TESTS
# ==============================================================================

def test_container_command_enforces_strict_resource_limits():
    """Verify that container execution command strictly enforces CPU, RAM, swap, and PID limits."""
    ws = Path("/tmp/mock_ws").resolve()
    cfg = SandboxConfig(
        cpu_limit="1.0",
        memory_limit="512m",
        pids_limit=50,
        read_only_root=True,
        network_mode="none",
    )
    cmd = build_container_run_command(
        workspace_dir=ws,
        container_name="test-res-bound",
        cmd_args=["pytest"],
        config=cfg,
    )

    assert "--cpus=1.0" in cmd
    assert "--memory=512m" in cmd
    assert "--memory-swap=512m" in cmd
    assert "--pids-limit=50" in cmd
    assert "--network=none" in cmd
    assert "--read-only" in cmd
    assert "--security-opt=no-new-privileges:true" in cmd
    assert "--cap-drop=ALL" in cmd


def test_execution_timeout_kills_process_tree(tmp_path: Path):
    """Verify that execution exceeding timeout limits is killed and returns timeout status."""
    # Write a test that loops infinitely or sleeps
    test_file = tmp_path / "test_sleep.py"
    test_file.write_text(
        "import time\ndef test_hang():\n    time.sleep(10)\n",
        encoding="utf-8",
    )

    t0 = time.time()
    code, stdout, stderr, is_timeout, err = execute_in_restricted_subprocess(
        workspace_dir=tmp_path,
        cmd_args=["--", "test_sleep.py"],
        timeout_seconds=2,
    )
    elapsed = time.time() - t0

    assert is_timeout is True
    assert elapsed < 5.0, f"Execution hung beyond timeout window ({elapsed:.2f}s)"
    assert err is not None and "timed out" in err.lower()


# ==============================================================================
# 4. SECRET STRIPPING & ENVIRONMENT ISOLATION TESTS
# ==============================================================================

def test_runner_environment_purges_all_credentials():
    """Verify that database passwords, API keys, and sensitive tokens are completely purged."""
    test_secrets = {
        "DATABASE_URL": "postgresql://admin:super_secret_pw@db:5432/prod",
        "POSTGRES_PASSWORD": "super_secret_pw",
        "SECRET_KEY": "production_secret_key_32chars_long",
        "GEMINI_API_KEY": "AIzaSyFakeGeminiKey123",
        "AWS_SECRET_ACCESS_KEY": "fake_aws_secret",
        "GITHUB_TOKEN": "ghp_fake_github_token_xyz",
        "CUSTOM_APP_TOKEN": "custom_token_val",
        "INTERNAL_AUTH_SECRET": "auth_secret_val",
        "MY_DB_PASS": "mydbpass123",
    }

    with patch.dict(os.environ, test_secrets, clear=False):
        sanitized = get_sanitized_runner_env()

        for secret_key in test_secrets:
            assert secret_key not in sanitized, f"Secret {secret_key} leaked into runner environment!"

        # Offline & isolation flags must be enforced
        assert sanitized.get("PIP_NO_INDEX") == "1"
        assert sanitized.get("NO_PROXY") == "*"
        assert sanitized.get("PYTHONUNBUFFERED") == "1"


def test_scanner_environment_purges_credentials():
    """Verify that scanner subprocesses receive secret-sanitized environments."""
    test_secrets = {
        "DATABASE_URL": "postgresql://admin:super_secret_pw@db:5432/prod",
        "POSTGRES_PASSWORD": "super_secret_pw",
        "SECRET_KEY": "production_secret_key_32chars_long",
        "GEMINI_API_KEY": "AIzaSyFakeGeminiKey123",
    }

    with patch.dict(os.environ, test_secrets, clear=False):
        sc_env = get_scanner_env()
        for k in test_secrets:
            assert k not in sc_env, f"Scanner env leaked {k}!"
        assert "PATH" in sc_env


# ==============================================================================
# 5. RELIABLE WORKSPACE CLEANUP TESTS
# ==============================================================================

def test_workspace_reliable_cleanup_on_completion_and_error(tmp_path: Path):
    """Verify that temporary verification workspace files are destroyed on cleanup."""
    ws = create_verification_workspace(
        synthetic_files={"app/main.py": "print('hello')", "README.md": "# Readme"}
    )
    ws_path = ws.workspace_dir
    assert ws_path.exists()
    assert (ws_path / "app/main.py").exists()

    ws.cleanup()
    assert not ws_path.exists(), "Workspace directory was not removed on cleanup!"


def test_workspace_context_manager_cleanup(tmp_path: Path):
    """Verify that VerificationWorkspace as a context manager reliably cleans up upon exit."""
    recorded_path = None
    with create_verification_workspace(synthetic_files={"temp.py": "x = 1"}) as ws:
        recorded_path = ws.workspace_dir
        assert recorded_path.exists()

    assert not recorded_path.exists(), "Context manager failed to clean up workspace upon exit!"


# ==============================================================================
# 6. FAIL-CLOSED SECURITY POLICY TESTS
# ==============================================================================

def test_fail_closed_returns_inconclusive_when_docker_unavailable(tmp_path: Path):
    """Verify that when container isolation is unavailable in production, execution fails closed."""
    cfg = SandboxConfig(
        fail_closed=True,
        allow_host_fallback=False,  # Enforces production policy
    )

    with patch("app.verification.sandbox.check_docker_availability", return_value=(False, "Docker daemon not running")):
        code, stdout, stderr, is_timeout, error_msg = run_isolated_verification_command(
            workspace_dir=tmp_path,
            cmd_args=["--", "tests/test_dummy.py"],
            config=cfg,
        )

        assert code == -1
        assert is_timeout is False
        assert error_msg is not None
        assert "fail-closed" in error_msg.lower()
        assert "Sandbox isolation unavailable" in error_msg


def test_runner_outcome_records_error_on_fail_closed(tmp_path: Path):
    """Verify that run_pytest_in_workspace converts fail-closed error to status='error'."""
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_sample.py").write_text("def test_ok(): pass", encoding="utf-8")

    cfg = SandboxConfig(fail_closed=True, allow_host_fallback=False)
    with patch("app.verification.sandbox.check_docker_availability", return_value=(False, "Docker daemon probe failed")):
        outcome = run_pytest_in_workspace(
            workspace_dir=tmp_path,
            sandbox_config=cfg,
        )
        assert outcome.status == "error"
        assert "fail-closed" in outcome.error_message.lower()


# ==============================================================================
# 7. DEDICATED WORKER JOB PROCESSING TESTS
# ==============================================================================

def test_worker_processes_pending_verifications_in_sandbox(db_session: Session):
    """Verify that background worker picks up and processes pending verification jobs."""
    user = User(
        id="usr_worker_test",
        email="worker_test@redmercury.io",
        password_hash="hash",
        account_status="active",
    )
    repo = Repository(
        id="repo_worker_test",
        name="worker-repo",
        owner_id=user.id,
        source_type="local",
        is_active=True,
    )
    finding = SecurityFinding(
        id="fnd_worker_test",
        repo_id=repo.id,
        rule_identifier="B608",
        scanner_name="bandit",
        cwe="CWE-89",
        file_path="src/dao.py",
        line_number=10,
        severity="HIGH",
        title="SQL Injection",
        code_excerpt="cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
    )
    db_session.add_all([user, repo, finding])
    db_session.commit()

    patch_diff = (
        "--- a/src/dao.py\n"
        "+++ b/src/dao.py\n"
        "@@ -1,1 +1,1 @@\n"
        "-cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')\n"
        "+cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n"
    )

    run = VerificationRun(
        id="vr_worker_pending_01",
        finding_id=finding.id,
        patch_diff=patch_diff,
        status="NOT_TESTED",
    )
    db_session.add(run)
    db_session.commit()

    # Worker processes pending verifications
    processed = process_pending_verifications(db=db_session, max_batch=5)
    assert processed == 1

    # Verify run status is finalized in DB (not stuck in NOT_TESTED)
    db_session.refresh(run)
    assert run.status in (
        VerificationStatus.VERIFIED_AGAINST_DEFINED_CHECKS,
        VerificationStatus.FAILED_VERIFICATION,
        VerificationStatus.INCONCLUSIVE,
    )
    assert run.completed_at is not None


def test_adversarial_patch_symlink_outside_workspace_rejected_with_symlink_reason(tmp_path: Path):
    """Phase 8P Regression: Direct symlink pointing outside workspace must report symbolic link violation before resolve() escapes."""
    outside_target = tmp_path / "host_secret.txt"
    outside_target.write_text("SECRET_CONTENT", encoding="utf-8")

    workspace_dir = tmp_path / "ws_sym_ext"
    workspace_dir.mkdir()
    symlink_target = workspace_dir / "link_config.txt"
    symlink_target.write_text("SECRET_CONTENT", encoding="utf-8")

    diff = (
        "--- a/link_config.txt\n"
        "+++ b/link_config.txt\n"
        "@@ -1,1 +1,1 @@\n"
        "-SECRET_CONTENT\n"
        "+TAMPERED\n"
    )
    parsed = parse_unified_diff(diff)
    assert parsed.is_valid

    orig_resolve = Path.resolve
    orig_is_symlink = Path.is_symlink

    def _fake_resolve(self: Path, *args, **kwargs) -> Path:
        if self.name == "link_config.txt":
            return outside_target
        return orig_resolve(self, *args, **kwargs)

    def _fake_is_symlink(self: Path) -> bool:
        if self.name == "link_config.txt":
            return True
        return orig_is_symlink(self)

    with patch.object(Path, "resolve", _fake_resolve), patch.object(Path, "is_symlink", _fake_is_symlink):
        success, errors = apply_patch_to_workspace(workspace_root=workspace_dir, patch_result=parsed)
        assert not success
        assert any("symbolic link" in e.lower() for e in errors)


def test_ensure_sandbox_readable_workspace_uses_scoped_acl_without_world_access(tmp_path: Path):
    """Phase 8R Regression: POSIX workspace access uses owner-only chmod + UID-10002 POSIX ACL without world bits."""
    import struct
    from app.verification.workspace import ensure_sandbox_readable_workspace

    ws = tmp_path / "ws_perms"
    (ws / "tests").mkdir(parents=True)
    test_file = ws / "tests" / "test_ok.py"
    test_file.write_text("def test_ok(): assert True\n", encoding="utf-8")

    chmod_calls = []
    xattr_calls = []

    def _fake_setxattr(path, attr, value, follow_symlinks=True):
        assert follow_symlinks is False
        assert attr == "system.posix_acl_access"
        xattr_calls.append((Path(path), value))

    orig_chmod = os.chmod

    def _spy_chmod(path, mode):
        chmod_calls.append((Path(path), mode))
        orig_chmod(path, mode)

    with patch("platform.system", return_value="Linux"), \
         patch("app.verification.workspace.os.getuid", return_value=1001, create=True), \
         patch("app.verification.workspace.os.setxattr", side_effect=_fake_setxattr, create=True), \
         patch("app.verification.workspace.os.chmod", side_effect=_spy_chmod):
        ensure_sandbox_readable_workspace(ws, sandbox_uid=10002)

    assert len(chmod_calls) >= 3
    for _, mode in chmod_calls:
        assert (mode & 0o077) == 0, f"Base mode must not grant group or world permissions: {oct(mode)}"

    assert len(xattr_calls) >= 3
    for _, acl_blob in xattr_calls:
        ver = struct.unpack_from("<I", acl_blob, 0)[0]
        entries = [struct.unpack_from("<HHI", acl_blob, 4 + i * 8) for i in range((len(acl_blob) - 4) // 8)]
        assert ver == 2
        # Verify UID 10002 read/exec ACL present while group and other are 0 (no access)
        entry_map = {(tag, eid): perm for tag, perm, eid in entries}
        assert (0x02, 10002) in entry_map
        assert entry_map[(0x04, 0xFFFFFFFF)] == 0
        assert entry_map[(0x20, 0xFFFFFFFF)] == 0


def test_ensure_sandbox_readable_workspace_owner_uid_match_stays_private(tmp_path: Path):
    """Phase 8R Regression: When host UID matches sandbox UID 10002, private 0o700/0o600 suffices without ACL/world bits."""
    from app.verification.workspace import ensure_sandbox_readable_workspace

    ws = tmp_path / "ws_same_uid"
    ws.mkdir()
    (ws / "app.py").write_text("x = 1\n", encoding="utf-8")

    chmod_calls = []
    with patch("platform.system", return_value="Linux"), \
         patch("app.verification.workspace.os.getuid", return_value=10002, create=True), \
         patch("app.verification.workspace.os.setxattr", side_effect=AssertionError("ACL not needed"), create=True), \
         patch("app.verification.workspace.os.chmod", side_effect=lambda p, m: chmod_calls.append((Path(p), m))):
        ensure_sandbox_readable_workspace(ws, sandbox_uid=10002)

    assert len(chmod_calls) == 2
    assert all((mode & 0o077) == 0 for _, mode in chmod_calls)


def test_ensure_sandbox_readable_workspace_fails_closed_when_acl_unavailable(tmp_path: Path):
    """Phase 8R Regression: Failed POSIX ACL setup must fail closed with PermissionError and never chmod world-readable."""
    import errno
    from app.verification.workspace import ensure_sandbox_readable_workspace

    ws = tmp_path / "ws_acl_fail"
    ws.mkdir()
    (ws / "app.py").write_text("x = 1\n", encoding="utf-8")

    chmod_calls = []

    def _raise_enotsup(*args, **kwargs):
        raise OSError(errno.ENOTSUP, "Operation not supported")

    with patch("platform.system", return_value="Linux"), \
         patch("app.verification.workspace.os.getuid", return_value=1001, create=True), \
         patch("app.verification.workspace.os.setxattr", side_effect=_raise_enotsup, create=True), \
         patch("app.verification.workspace.os.chmod", side_effect=lambda p, m: chmod_calls.append((Path(p), m))):
        with pytest.raises(PermissionError, match="Refusing insecure world-readable fallback"):
            ensure_sandbox_readable_workspace(ws, sandbox_uid=10002)

    # Only owner-only base mode (0o700) was set before ACL attempt; never 0o755/0o644/0o777.
    for _, mode in chmod_calls:
        assert (mode & 0o077) == 0


def test_temp_root_boundary_rejects_temp_root_and_outside_paths(tmp_path: Path):
    """Phase 8R Regression: Shared temporary root and outside paths are never passed to recursive permission modification."""
    from app.verification.workspace import ensure_sandbox_readable_workspace, validate_strict_temp_workspace

    temp_root = Path(tempfile.gettempdir()).resolve()

    # 1. Temp root itself must be rejected
    with patch("app.verification.workspace.os.chmod") as mock_chmod:
        with pytest.raises(PermissionError, match="strict temporary-root descendant"):
            validate_strict_temp_workspace(temp_root)
        with pytest.raises(PermissionError, match="strict temporary-root descendant"):
            ensure_sandbox_readable_workspace(temp_root, sandbox_uid=10002)
        mock_chmod.assert_not_called()

    # 2. Path outside temp root must be rejected
    outside_dir = temp_root.parent
    with pytest.raises(PermissionError, match="strict temporary-root descendant"):
        validate_strict_temp_workspace(outside_dir)

    # 3. Non-existent path must be rejected
    missing_dir = tmp_path / "does_not_exist_ws"
    with pytest.raises(FileNotFoundError):
        validate_strict_temp_workspace(missing_dir)

    # 4. Symlink workspace root must be rejected even if targeting a valid temp subdir
    real_sub = tmp_path / "real_ws"
    real_sub.mkdir()
    link_ws = tmp_path / "sym_ws"
    try:
        link_ws.symlink_to(real_sub, target_is_directory=True)
        with pytest.raises(PermissionError, match="symbolic link"):
            validate_strict_temp_workspace(link_ws)
    except (OSError, NotImplementedError):
        with patch.object(Path, "is_symlink", side_effect=lambda self=None: True):
            with pytest.raises(PermissionError, match="symbolic link"):
                validate_strict_temp_workspace(real_sub)


def test_patch_applier_posix_nofollow_rejects_phase2_symlink_swap(tmp_path: Path):
    """Phase 8R Regression: POSIX Phase 2 dir_fd write helper aborts if target becomes a symlink before replace."""
    from app.verification.patch_applier import _write_text_posix_nofollow

    target_dir = tmp_path / "pkg"
    target_dir.mkdir()

    fake_stat_sym = MagicMock(st_mode=0o120777)  # stat.S_IFLNK
    with patch("app.verification.patch_applier.os.O_NOFOLLOW", 0x20000, create=True), \
         patch("app.verification.patch_applier.os.O_DIRECTORY", 0x10000, create=True), \
         patch("app.verification.patch_applier.os.open", return_value=10, create=True), \
         patch("app.verification.patch_applier.os.close", create=True), \
         patch("app.verification.patch_applier.os.lstat", return_value=fake_stat_sym):
        with pytest.raises(PermissionError, match="symbolic link"):
            _write_text_posix_nofollow(tmp_path, ["pkg", "app.py"], "new content", create_parents=False)
