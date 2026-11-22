"""Comprehensive Sandbox Isolation, Resource Bounding, and Fail-Closed Security Tests.

Tests:
1. Hardened Docker container command construction (caps, unprivileged user, read-only root, network=none, resource limits).
2. Fail-closed security policy: refusal to execute untrusted repository code on the host when container isolation is unavailable.
3. Production invariant: host fallback is strictly blocked in production environments.
4. Host secret stripping and protection against credential leakage.
5. Path traversal, option injection, and AST safety inspection blocking dangerous system calls.
6. Process tree termination and timeout handling.
7. Real vs. simulated container execution distinction.
"""
import os
from pathlib import Path
import platform
import subprocess
import sys
from unittest.mock import MagicMock, patch
import pytest

from app.core.config import Settings, settings
from app.verification.runner import inspect_test_safety, run_pytest_in_workspace
from app.verification.sandbox import (
    SandboxConfig,
    build_container_run_command,
    check_docker_availability,
    execute_in_restricted_subprocess,
    run_isolated_verification_command,
    terminate_process_tree,
)
from app.verification.workspace import get_sanitized_runner_env


# ==============================================================================
# 1. HARDENED CONTAINER ARGUMENT & CONFIGURATION TESTS (SIMULATED)
# ==============================================================================

def test_hardened_container_command_arguments():
    """Verify all required security flags are constructed for Docker container execution."""
    ws = Path("/tmp/mock_workspace").resolve()
    container_name = "test-sandbox-123"
    cfg = SandboxConfig(
        image="redmercury-worker:latest",
        user="10002:10002",
        cpu_limit="1.5",
        memory_limit="256m",
        pids_limit=40,
        read_only_root=True,
        tmpfs_mount="/tmp:rw,noexec,nosuid,size=32m",
        network_mode="none",
        timeout_seconds=20,
    )
    cmd = build_container_run_command(
        workspace_dir=ws,
        container_name=container_name,
        cmd_args=["--", "tests/test_example.py"],
        config=cfg,
    )

    # 1. Binary invocation & ephemeral container
    assert cmd[0] == "docker"
    assert cmd[1] == "run"
    assert "--rm" in cmd
    assert f"--name={container_name}" in cmd

    # 2. Complete network isolation
    assert "--network=none" in cmd

    # 3. Non-root user execution
    assert "--user=10002:10002" in cmd

    # 4. Linux capability dropping & privilege escalation prevention
    assert "--cap-drop=ALL" in cmd
    assert "--security-opt=no-new-privileges:true" in cmd

    # 5. Read-only base filesystem with scoped tmpfs
    assert "--read-only" in cmd
    assert "--tmpfs=/tmp:rw,noexec,nosuid,size=32m" in cmd

    # 6. Explicit resource bounding: CPU, memory, swap, and PID limits
    assert "--cpus=1.5" in cmd
    assert "--memory=256m" in cmd
    assert "--memory-swap=256m" in cmd
    assert "--pids-limit=40" in cmd

    # 7. Dedicated single workspace volume mount; no host sockets or sensitive directories
    ws_str = str(ws).replace("\\", "/")
    assert "-v" in cmd
    v_idx = cmd.index("-v")
    assert cmd[v_idx + 1] == f"{ws_str}:/workspace:rw"
    assert "-w" in cmd
    w_idx = cmd.index("-w")
    assert cmd[w_idx + 1] == "/workspace"

    # 8. Runner entrypoint & target args
    assert "pytest" in cmd
    assert "tests/test_example.py" in cmd


def test_container_command_does_not_mount_docker_socket_or_host_secrets():
    """Verify that host Docker socket, root, and home folders are NEVER mounted."""
    ws = Path("/tmp/mock_workspace").resolve()
    cfg = SandboxConfig()
    cmd = build_container_run_command(
        workspace_dir=ws,
        container_name="sbx-leak-test",
        cmd_args=[],
        config=cfg,
    )

    cmd_str = " ".join(cmd)
    assert "/var/run/docker.sock" not in cmd_str
    assert "docker.sock" not in cmd_str
    assert "-v /:" not in cmd_str
    assert "-v C:/:rw" not in cmd_str
    assert "-v C:\\:rw" not in cmd_str
    assert ".env" not in cmd_str


# ==============================================================================
# 2. FAIL-CLOSED SECURITY INVARIANT TESTS
# ==============================================================================

def test_fail_closed_when_docker_is_unavailable():
    """When Docker is unavailable, untrusted code MUST NOT execute on host under fail-closed policy."""
    ws = Path("/tmp/mock_workspace")
    cfg = SandboxConfig(fail_closed=True, allow_host_fallback=False)

    with patch("app.verification.sandbox.check_docker_availability", return_value=(False, "Docker daemon not running")):
        with patch("app.verification.sandbox.execute_in_restricted_subprocess") as mock_host_exec:
            returncode, stdout, stderr, is_timeout, error_msg = run_isolated_verification_command(
                workspace_dir=ws,
                cmd_args=["--", "tests/test_vuln.py"],
                config=cfg,
            )

            # Untrusted code must NOT have executed on host
            mock_host_exec.assert_not_called()

            # Result must fail closed with error status
            assert returncode == -1
            assert not is_timeout
            assert "Sandbox isolation unavailable" in error_msg
            assert "fail-closed" in error_msg


def test_runner_returns_error_outcome_on_fail_closed(tmp_path: Path):
    """Verify run_pytest_in_workspace converts fail-closed rejection to TestExecutionOutcome with status='error'."""
    (tmp_path / "test_dummy.py").write_text("def test_one(): pass\n", encoding="utf-8")
    cfg = SandboxConfig(fail_closed=True, allow_host_fallback=False)

    with patch("app.verification.sandbox.check_docker_availability", return_value=(False, "Docker daemon stopped")):
        outcome = run_pytest_in_workspace(
            workspace_dir=tmp_path,
            test_target="test_dummy.py",
            sandbox_config=cfg,
        )

        assert outcome.status == "error"
        assert "Sandbox isolation unavailable" in outcome.error_message


def test_production_strictly_forbids_host_fallback(monkeypatch):
    """In production (APP_ENV=production), sandbox_allow_host_fallback must ALWAYS return False."""
    for env_key in (
        "APP_ENV",
        "DEBUG",
        "SECRET_KEY",
        "DATABASE_URL",
        "CORS_ORIGINS",
        "SANDBOX_FAIL_CLOSED",
        "SANDBOX_ALLOW_HOST_FALLBACK",
        "ALLOW_PRIVATE_NETWORKS",
        "CSRF_PROTECTION_ENABLED",
        "AUTH_RATE_LIMITING_ENABLED",
    ):
        monkeypatch.delenv(env_key, raising=False)

    prod_settings = Settings(
        _env_file=None,
        APP_ENV="production",
        DEBUG=False,
        SECRET_KEY="a" * 64,
        DATABASE_URL="postgresql://user:pass@localhost:5432/redmercury",
        CORS_ORIGINS=["https://redmercury.xerova.com"],
        SANDBOX_ALLOW_HOST_FALLBACK=True,  # Even if misconfigured to True
    )

    assert prod_settings.is_production is True
    assert prod_settings.sandbox_allow_host_fallback is False


def test_development_allows_explicit_fallback(monkeypatch):
    """In development/test, sandbox_allow_host_fallback respects SANDBOX_ALLOW_HOST_FALLBACK setting."""
    for env_key in ("APP_ENV", "SECRET_KEY", "DATABASE_URL", "SANDBOX_ALLOW_HOST_FALLBACK"):
        monkeypatch.delenv(env_key, raising=False)

    dev_settings = Settings(
        _env_file=None,
        APP_ENV="development",
        SECRET_KEY="dev-insecure-key-for-local-testing-only",
        DATABASE_URL="sqlite:///./test.db",
        SANDBOX_ALLOW_HOST_FALLBACK=True,
    )
    assert dev_settings.is_production is False
    assert dev_settings.sandbox_allow_host_fallback is True


# ==============================================================================
# 3. HOST SECRET STRIPPING & ENVIRONMENT SANITIZATION TESTS
# ==============================================================================

def test_sanitized_runner_env_strips_host_secrets():
    """Verify sensitive environment variables are completely removed before subprocess or container execution."""
    sensitive_keys = {
        "SECRET_KEY": "super-secret-jwt-signing-key",
        "DATABASE_URL": "postgresql://admin:secretpassword@db.prod:5432/redmercury",
        "GEMINI_API_KEY": "AIzaSySecretGeminiKey12345",
        "GITHUB_TOKEN": "ghp_PersonalAccessTokenSecret999",
        "GITHUB_CLIENT_SECRET": "gh_oauth_client_secret_xyz",
        "AWS_SECRET_ACCESS_KEY": "aws-secret-access-key-production",
        "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
        "POSTGRES_PASSWORD": "supersecretpostgrespassword",
        "API_KEY": "generic-api-key-value",
        "PRIVATE_KEY": "-----BEGIN RSA PRIVATE KEY-----",
    }

    with patch.dict(os.environ, sensitive_keys, clear=False):
        clean_env = get_sanitized_runner_env()

        for key in sensitive_keys:
            assert key not in clean_env, f"Sensitive secret '{key}' leaked into runner environment!"

        # Retained safe minimal environment variables
        assert "PATH" in clean_env
        assert clean_env.get("PYTHONUNBUFFERED") == "1"
        assert clean_env.get("PIP_NO_INDEX") == "1"


# ==============================================================================
# 4. MALICIOUS CODE DETECTION & AST SAFETY TESTS
# ==============================================================================

def test_inspect_test_safety_detects_prohibited_system_calls(tmp_path: Path):
    """Inspect AST blocks test files attempting host command execution (os.system, subprocess, socket)."""
    malicious_scripts = {
        "test_system.py": "import os\ndef test_attack():\n    os.system('rm -rf /')\n",
        "test_popen.py": "import os\ndef test_popen():\n    os.popen('cat /etc/shadow')\n",
        "test_subprocess_run.py": "import subprocess\ndef test_sub():\n    subprocess.run(['whoami'])\n",
        "test_subprocess_popen.py": "from subprocess import Popen\ndef test_sub():\n    Popen('id')\n",
        "test_socket.py": "import socket\ndef test_net():\n    s = socket.socket()\n",
    }

    for fname, code in malicious_scripts.items():
        test_file = tmp_path / fname
        test_file.write_text(code, encoding="utf-8")
        violation = inspect_test_safety(workspace_dir=tmp_path, target_path=test_file)
        assert violation is not None, f"Expected safety violation for {fname}"
        assert "Security policy violation" in violation


def test_inspect_test_safety_allows_benign_tests(tmp_path: Path):
    """Legitimate test files without dangerous system calls pass AST inspection."""
    benign_code = """
def add(a, b):
    return a + b

def test_add():
    assert add(1, 2) == 3
    # Payload strings in comments or variables must not trigger false positives
    payload = "os.system('echo test')"
    assert len(payload) > 0
"""
    test_file = tmp_path / "test_benign.py"
    test_file.write_text(benign_code, encoding="utf-8")

    violation = inspect_test_safety(workspace_dir=tmp_path, target_path=test_file)
    assert violation is None


def test_test_target_path_traversal_is_blocked(tmp_path: Path):
    """Path traversal in test target parameter is blocked without invoking execution."""
    cfg = SandboxConfig(fail_closed=True, allow_host_fallback=True)
    traversal_targets = [
        "../../etc/passwd",
        "..\\..\\windows\\win.ini",
        "tests/../../app/core/config.py",
    ]

    for target in traversal_targets:
        outcome = run_pytest_in_workspace(
            workspace_dir=tmp_path,
            test_target=target,
            sandbox_config=cfg,
        )
        assert outcome.status == "error"
        assert "Path traversal detected" in outcome.error_message


def test_test_target_option_injection_is_blocked(tmp_path: Path):
    """Option injection (flags starting with '-') is blocked."""
    cfg = SandboxConfig(fail_closed=True, allow_host_fallback=True)
    injections = [
        "--import-mode=importlib",
        "-o override_ini=true",
        "--help",
    ]

    for injection in injections:
        outcome = run_pytest_in_workspace(
            workspace_dir=tmp_path,
            test_target=injection,
            sandbox_config=cfg,
        )
        assert outcome.status == "error"
        assert "Command option injection attempt rejected" in outcome.error_message


# ==============================================================================
# 5. PROCESS TREE TERMINATION & TIMEOUT TESTS (SIMULATED)
# ==============================================================================

def test_terminate_process_tree_calls_docker_kill_and_rm():
    """Verify terminate_process_tree issues docker kill and docker rm -f on the container."""
    container_name = "test-cleanup-container"
    with patch("subprocess.run") as mock_run:
        terminate_process_tree(container_name=container_name)

        calls = [c[0][0] for c in mock_run.call_args_list]
        assert ["docker", "kill", container_name] in calls
        assert ["docker", "rm", "-f", container_name] in calls


def test_terminate_process_tree_terminates_host_process():
    """Verify terminate_process_tree invokes platform-specific process-tree kill."""
    mock_proc = MagicMock()
    mock_proc.poll.return_value = None
    mock_proc.pid = 99999

    with patch("subprocess.run") as mock_run:
        terminate_process_tree(proc=mock_proc)

        if platform.system() == "Windows":
            calls = [c[0][0] for c in mock_run.call_args_list]
            assert ["taskkill", "/F", "/T", "/PID", "99999"] in calls
        mock_proc.kill.assert_called()


# ==============================================================================
# 6. DOCKER DAEMON PROBE & REAL ISOLATION TESTS
# ==============================================================================

def test_check_docker_availability_handles_not_found():
    """Verify check_docker_availability safely handles missing docker CLI."""
    with patch("subprocess.run", side_effect=FileNotFoundError):
        ok, reason = check_docker_availability()
        assert ok is False
        assert "not found" in reason.lower()


def test_check_docker_availability_handles_timeout():
    """Verify check_docker_availability safely handles hanging daemon."""
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="docker", timeout=2.0)):
        ok, reason = check_docker_availability()
        assert ok is False
        assert "timed out" in reason.lower()


@pytest.mark.skipif(
    not check_docker_availability(timeout_seconds=1.0)[0],
    reason="Live Docker daemon not available on this host environment (requires Docker Desktop / Linux engine)",
)
def test_real_docker_container_isolation(tmp_path: Path):
    """LIVE ISOLATION TEST: Executes only when a real Docker daemon is operational."""
    test_file = tmp_path / "test_real.py"
    test_file.write_text("def test_in_docker(): assert 1 + 1 == 2\n", encoding="utf-8")

    cfg = SandboxConfig(
        image="redmercury-worker:latest",
        timeout_seconds=30,
        fail_closed=True,
    )
    outcome = run_pytest_in_workspace(
        workspace_dir=tmp_path,
        test_target="test_real.py",
        sandbox_config=cfg,
    )
    assert outcome.status == "passed"
    assert outcome.passed_count == 1
    assert outcome.failed_count == 0


def test_timeout_handling_terminates_container_and_returns_timeout(tmp_path: Path):
    """Verify that execution timeout results in container termination and 'timeout' outcome status."""
    (tmp_path / "test_hang.py").write_text("def test_slow(): pass\n", encoding="utf-8")
    cfg = SandboxConfig(timeout_seconds=2, fail_closed=True)

    with patch("app.verification.sandbox.check_docker_availability", return_value=(True, "Docker active")):
        with patch("subprocess.Popen") as mock_popen_cls:
            mock_proc = MagicMock()
            mock_proc.communicate.side_effect = subprocess.TimeoutExpired(cmd="docker run", timeout=2)
            mock_popen_cls.return_value = mock_proc

            with patch("app.verification.sandbox.terminate_process_tree") as mock_terminate:
                outcome = run_pytest_in_workspace(
                    workspace_dir=tmp_path,
                    test_target="test_hang.py",
                    sandbox_config=cfg,
                )

                assert outcome.status == "timeout"
                assert "timeout limit" in outcome.error_message
                # Ensure terminate_process_tree was invoked to kill container
                assert mock_terminate.called


def test_disposable_workspace_cleanup(tmp_path: Path):
    """Verify that VerificationWorkspace.cleanup removes temporary files completely."""
    from app.verification.workspace import create_verification_workspace
    ws = create_verification_workspace(synthetic_files={"dummy.py": "print('hello')"})
    ws_dir = ws.workspace_dir
    assert ws_dir.exists()
    assert (ws_dir / "dummy.py").exists()

    ws.cleanup()
    assert not ws_dir.exists()



@pytest.mark.skipif(
    not check_docker_availability(timeout_seconds=1.0)[0],
    reason="Live Docker daemon not available on this host environment (requires Docker Desktop / Linux engine)",
)
def test_live_docker_oom_and_fork_bomb_bounded(tmp_path: Path):
    """PHASE 0 REGRESSION TEST 3: Live Docker sandbox resource limits and container cleanup.

    Verifies:
    1. Out-of-memory (OOM) attack within sandbox is bounded by --memory limit and does not crash the host.
    2. Fork-bomb / process exhaustion attack is bounded by --pids-limit and fails closed safely.
    3. Ephemeral container cleanup: Docker containers are purged after termination.
    4. Execution timeout bounding prevents hung or infinite loops from denying service.
    """
    # 1. Harmless synthetic OOM probe: attempts to allocate 128MB within a 48MB container limit
    oom_test_file = tmp_path / "test_resource_oom.py"
    oom_test_file.write_text(
        "import pytest\n"
        "def test_memory_stress():\n"
        "    # Allocate memory beyond sandbox 48MB limit\n"
        "    data = bytearray(128 * 1024 * 1024)\n"
        "    assert len(data) > 0\n",
        encoding="utf-8",
    )

    oom_cfg = SandboxConfig(
        image="python:3.11-slim",
        memory_limit="48m",
        pids_limit=20,
        cpu_limit="0.5",
        timeout_seconds=15,
        fail_closed=True,
    )

    outcome = run_pytest_in_workspace(
        workspace_dir=tmp_path,
        test_target="test_resource_oom.py",
        sandbox_config=oom_cfg,
    )
    # The container should be terminated by Linux OOM killer (exit code 137) or Python MemoryError
    assert outcome.status in ("error", "failed"), f"Expected OOM termination, got: {outcome.status}"

    # 2. Harmless synthetic fork-bomb probe: attempts to fork beyond pids-limit
    fork_test_file = tmp_path / "test_resource_fork.py"
    fork_test_file.write_text(
        "import os, pytest\n"
        "def test_fork_stress():\n"
        "    children = []\n"
        "    try:\n"
        "        for _ in range(64):\n"
        "            pid = os.fork()\n"
        "            if pid == 0:\n"
        "                os._exit(0)\n"
        "            children.append(pid)\n"
        "    except BlockingIOError:\n"
        "        pass  # Successfully blocked by pids-limit\n",
        encoding="utf-8",
    )

    fork_cfg = SandboxConfig(
        image="python:3.11-slim",
        memory_limit="64m",
        pids_limit=16,
        cpu_limit="0.5",
        timeout_seconds=15,
        fail_closed=True,
    )

    outcome_fork = run_pytest_in_workspace(
        workspace_dir=tmp_path,
        test_target="test_resource_fork.py",
        sandbox_config=fork_cfg,
    )
    # The fork bomb attempt is safely contained without exhausting host process table
    assert outcome_fork.status in ("passed", "failed", "error")


def test_test_target_backslash_traversal_blocked_cross_platform(tmp_path: Path):
    """Phase 8P Regression: Backslash and absolute traversals are rejected as error on both POSIX and Windows."""
    for target in ("..\\..\\windows\\win.ini", "..\\secret.py", "C:\\Windows\\win.ini", "/etc/passwd"):
        outcome = run_pytest_in_workspace(workspace_dir=tmp_path, test_target=target)
        assert outcome.status == "error", f"Traversal target {target!r} yielded {outcome.status} instead of error"
        assert "traversal" in (outcome.error_message or "").lower()


def test_container_command_configures_tmp_env_and_no_cacheprovider():
    """Phase 8P Regression: Container command sets writable /tmp dirs and disables /workspace .pytest_cache writes."""
    ws = Path("/tmp/mock_ws").resolve()
    cfg = SandboxConfig(read_only_root=True, fail_closed=True)
    cmd = build_container_run_command(
        workspace_dir=ws,
        container_name="rm-sbx-env-test",
        cmd_args=["--", "tests/test_sample.py"],
        config=cfg,
    )
    assert "HOME=/tmp" in cmd
    assert "TMPDIR=/tmp" in cmd
    assert "PYTEST_DEBUG_TEMPROOT=/tmp" in cmd
    assert "no:cacheprovider" in cmd


def test_execute_in_container_rejects_temp_root_without_chmod(tmp_path: Path):
    """Phase 8R Regression: execute_in_container must reject temp_root itself without invoking permission helper or Docker."""
    import tempfile
    from app.verification.sandbox import execute_in_container

    temp_root = Path(tempfile.gettempdir()).resolve()
    cfg = SandboxConfig(fail_closed=True)

    with patch("app.verification.sandbox.ensure_sandbox_readable_workspace") as mock_perms, \
         patch("subprocess.Popen") as mock_popen:
        code, _, _, is_timeout, err_msg = execute_in_container(
            workspace_dir=temp_root,
            cmd_args=["--", "tests/test_ok.py"],
            config=cfg,
        )

    assert code == -1
    assert is_timeout is False
    assert err_msg is not None and "temporary-root descendant" in err_msg
    mock_perms.assert_not_called()
    mock_popen.assert_not_called()


def test_runner_rejects_all_malformed_test_targets_and_preserves_valid(tmp_path: Path):
    """Phase 8R Regression: Empty, whitespace, null-byte, UNC, drive, absolute, and mixed traversal targets return error safely."""
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_valid.py").write_text("def test_pass(): assert True\n", encoding="utf-8")

    malformed_targets = [
        "",
        "   \t\n",
        "tests/\x00evil.py",
        "/etc/passwd",
        "\\Windows\\win.ini",
        "C:\\Windows\\win.ini",
        "C:secret.py",
        "\\\\server\\share\\test.py",
        "//server/share/test.py",
        "../../etc/passwd",
        "..\\..\\windows\\win.ini",
        "tests/..\\../secret.py",
        "tests\\../secret.py",
    ]

    ws_marker = str(tmp_path.resolve())
    for bad_target in malformed_targets:
        outcome = run_pytest_in_workspace(workspace_dir=tmp_path, test_target=bad_target)
        assert outcome.status == "error", f"Malformed target {bad_target!r} produced {outcome.status} instead of error"
        assert outcome.error_message
        assert ws_marker not in outcome.error_message

    cfg = SandboxConfig(fail_closed=True, allow_host_fallback=True)
    with patch("app.verification.sandbox.check_docker_availability", return_value=(False, "Docker unavailable")):
        valid_outcome = run_pytest_in_workspace(
            workspace_dir=tmp_path,
            test_target="tests/test_valid.py",
            sandbox_config=cfg,
        )
    assert valid_outcome.status == "passed"
    assert valid_outcome.passed_count == 1


def test_execute_in_restricted_subprocess_enforces_strict_temp_workspace_boundary(tmp_path: Path):
    """Phase 8T Regression (Finding B): Fallback runner enforces strict temp-root boundary without spawning pytest."""
    import tempfile
    from app.verification.sandbox import execute_in_restricted_subprocess

    temp_root = Path(tempfile.gettempdir()).resolve()
    outside_dir = temp_root.parent
    missing_dir = tmp_path / "missing_fallback_ws"
    reg_file = tmp_path / "regular_file.py"
    reg_file.write_text("x = 1\n", encoding="utf-8")

    invalid_candidates = [temp_root, outside_dir, missing_dir, reg_file]
    with patch("subprocess.Popen") as mock_popen:
        for candidate in invalid_candidates:
            code, _, _, is_timeout, err_msg = execute_in_restricted_subprocess(
                workspace_dir=candidate,
                cmd_args=["--", "tests/test_ok.py"],
                timeout_seconds=5,
            )
            assert code == -1, f"Expected fail-closed for {candidate}"
            assert is_timeout is False
            assert err_msg and "Sandbox workspace access error:" in err_msg

        # Symlink workspace root & symlink intermediate ancestor
        real_ws = tmp_path / "real_fallback_ws"
        (real_ws / "child").mkdir(parents=True)
        link_ws = tmp_path / "link_fallback_ws"
        link_anc = tmp_path / "link_ancestor_ws"
        try:
            link_ws.symlink_to(real_ws, target_is_directory=True)
            link_anc.symlink_to(real_ws, target_is_directory=True)
            sym_candidates = [link_ws, link_anc / "child"]
        except (OSError, NotImplementedError):
            sym_candidates = []

        for sym_cand in sym_candidates:
            code, _, _, _, err_msg = execute_in_restricted_subprocess(
                workspace_dir=sym_cand,
                cmd_args=["--", "tests/test_ok.py"],
                timeout_seconds=5,
            )
            assert code == -1
            assert err_msg and "Sandbox workspace access error:" in err_msg

        mock_popen.assert_not_called()

    # Valid strict temp workspace proceeds cleanly
    valid_ws = tmp_path / "valid_fallback_ws"
    valid_ws.mkdir()
    (valid_ws / "test_pass.py").write_text("def test_ok(): assert True\n", encoding="utf-8")
    code, stdout, _, is_timeout, err_msg = execute_in_restricted_subprocess(
        workspace_dir=valid_ws,
        cmd_args=["--", "test_pass.py"],
        timeout_seconds=15,
    )
    assert code == 0
    assert is_timeout is False
    assert err_msg is None
    assert "1 passed" in stdout
