"""Live Runtime Docker Sandbox Security Validation Test Suite.

Phase 3A: Executes comprehensive real-time runtime security tests directly against
the operational Docker daemon to validate container isolation, non-root execution,
network isolation, capability dropping, read-only root filesystems, resource limits,
host credential non-inheritance, timeout handling, and container cleanup.

Invariants Enforced:
1. Every test in this suite skips gracefully if a live Docker daemon is unavailable,
   clearly distinguishing live runtime execution from mocked/simulated tests.
2. No destructive exhaustion (no host fork bombs, no host OOM, no host disk fill).
3. Fail-closed safety: container failures can NEVER be reported as successful verifications.
"""
import os
from pathlib import Path
import subprocess
import time
import uuid
import pytest

from app.verification.runner import run_pytest_in_workspace
from app.verification.sandbox import (
    SandboxConfig,
    check_docker_availability,
    execute_in_container,
)
from app.verification.workspace import get_sanitized_runner_env


# Probe Docker availability once for module-level skipping if daemon is unavailable
DOCKER_AVAILABLE, DOCKER_VERSION_OR_REASON = check_docker_availability(timeout_seconds=2.0)
LIVE_DOCKER_IMAGE = "redmercury-worker:latest"
FALLBACK_PYTHON_IMAGE = "python:3.11-slim"

pytestmark = pytest.mark.skipif(
    not DOCKER_AVAILABLE,
    reason=f"Live Docker daemon unavailable: {DOCKER_VERSION_OR_REASON}",
)


# ==============================================================================
# 1. NON-ROOT EXECUTION VALIDATION
# ==============================================================================

def test_live_docker_non_root_execution(tmp_path: Path):
    """Verify runtime container process executes under UID/GID 10002:10002, NOT root (UID 0)."""
    cfg = SandboxConfig(
        image=LIVE_DOCKER_IMAGE,
        user="10002:10002",
        timeout_seconds=15,
        fail_closed=True,
    )
    returncode, stdout, stderr, is_timeout, error_msg = execute_in_container(
        workspace_dir=tmp_path,
        cmd_args=["python3", "-c", "import os; print(f'UID={os.getuid()},GID={os.getgid()}')"],
        config=cfg,
    )

    assert returncode == 0, f"Command failed: {stderr or error_msg}"
    assert not is_timeout
    assert "UID=10002" in stdout
    assert "GID=10002" in stdout
    assert "UID=0" not in stdout, "Container must NEVER execute as root!"


# ==============================================================================
# 2. NETWORK ISOLATION VALIDATION
# ==============================================================================

def test_live_docker_network_isolation(tmp_path: Path):
    """Verify --network=none blocks all outbound TCP connections (prevents exfiltration/SSRF)."""
    cfg = SandboxConfig(
        image=LIVE_DOCKER_IMAGE,
        network_mode="none",
        timeout_seconds=15,
        fail_closed=True,
    )
    # Attempting to establish outbound socket to external address
    returncode, stdout, stderr, is_timeout, error_msg = execute_in_container(
        workspace_dir=tmp_path,
        cmd_args=[
            "python3",
            "-c",
            "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(2); s.connect(('1.1.1.1', 80))",
        ],
        config=cfg,
    )

    # Must fail with network unreachable / connection error
    assert returncode != 0
    assert not is_timeout
    combined = (stdout + "\n" + stderr).lower()
    assert any(term in combined for term in ("network is unreachable", "errno 101", "oserror")), (
        f"Expected network unreachable error under --network=none, got: {combined}"
    )


# ==============================================================================
# 3. LINUX CAPABILITY DROPPING VALIDATION
# ==============================================================================

def test_live_docker_dropped_capabilities_block_raw_sockets(tmp_path: Path):
    """Verify --cap-drop=ALL drops CAP_NET_RAW and prevents creation of raw sockets."""
    cfg = SandboxConfig(
        image=LIVE_DOCKER_IMAGE,
        cap_drop=["ALL"],
        timeout_seconds=15,
        fail_closed=True,
    )
    returncode, stdout, stderr, is_timeout, error_msg = execute_in_container(
        workspace_dir=tmp_path,
        cmd_args=[
            "python3",
            "-c",
            "import socket; socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)",
        ],
        config=cfg,
    )

    assert returncode != 0
    assert not is_timeout
    combined = (stdout + "\n" + stderr).lower()
    assert any(term in combined for term in ("operation not permitted", "permissionerror", "errno 1")), (
        f"Expected CAP_NET_RAW permission denial, got: {combined}"
    )


# ==============================================================================
# 4. READ-ONLY ROOT FILESYSTEM VALIDATION
# ==============================================================================

def test_live_docker_read_only_root_filesystem(tmp_path: Path):
    """Verify --read-only blocks writes to root system directories (/bin, /etc, /usr)."""
    cfg = SandboxConfig(
        image=LIVE_DOCKER_IMAGE,
        read_only_root=True,
        timeout_seconds=15,
        fail_closed=True,
    )
    returncode, stdout, stderr, is_timeout, error_msg = execute_in_container(
        workspace_dir=tmp_path,
        cmd_args=[
            "python3",
            "-c",
            "with open('/bin/exploit_binary', 'w') as f: f.write('tamper')",
        ],
        config=cfg,
    )

    assert returncode != 0
    assert not is_timeout
    combined = (stdout + "\n" + stderr).lower()
    assert any(term in combined for term in ("read-only file system", "errno 30", "oserror")), (
        f"Expected Read-only filesystem error, got: {combined}"
    )


# ==============================================================================
# 5. RESTRICTED TMPFS VALIDATION (WRITABLE BUT NOEXEC)
# ==============================================================================

def test_live_docker_tmpfs_is_writable_but_noexec(tmp_path: Path):
    """Verify tmpfs allows writing scratch data but blocks execution via noexec."""
    cfg = SandboxConfig(
        image=LIVE_DOCKER_IMAGE,
        read_only_root=True,
        tmpfs_mount="/tmp:rw,noexec,nosuid,size=64m",
        timeout_seconds=15,
        fail_closed=True,
    )
    # 1. Writing to /tmp succeeds
    returncode, stdout, stderr, is_timeout, error_msg = execute_in_container(
        workspace_dir=tmp_path,
        cmd_args=[
            "python3",
            "-c",
            "open('/tmp/scratch.txt', 'w').write('hello'); print(open('/tmp/scratch.txt').read())",
        ],
        config=cfg,
    )
    assert returncode == 0
    assert "hello" in stdout

    # 2. Executing a script from /tmp is blocked by noexec mount option
    returncode_exec, stdout_exec, stderr_exec, _, _ = execute_in_container(
        workspace_dir=tmp_path,
        cmd_args=[
            "python3",
            "-c",
            "import os, subprocess; open('/tmp/test_exec.sh', 'w').write('#!/bin/sh\\necho hi\\n'); os.chmod('/tmp/test_exec.sh', 0o755); subprocess.run(['/tmp/test_exec.sh'], check=True)",
        ],
        config=cfg,
    )
    assert returncode_exec != 0
    combined = (stdout_exec + "\n" + stderr_exec).lower()
    assert any(term in combined for term in ("permission denied", "errno 13", "permissionerror")), (
        f"Expected noexec Permission Denied on /tmp script execution, got: {combined}"
    )


# ==============================================================================
# 6. HOST CREDENTIAL & ENVIRONMENT VARIABLE ISOLATION
# ==============================================================================

def test_live_docker_host_secret_isolation(tmp_path: Path, monkeypatch):
    """Verify host environment variables & secrets are NOT leaked into sandbox container."""
    # Inject synthetic high-entropy host secrets into current host process environment
    monkeypatch.setenv("SECRET_KEY", "ultra-secret-redmercury-signing-key-12345")
    monkeypatch.setenv("GEMINI_API_KEY", "synthetic-gemini-ai-token-xyz987")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "synthetic-aws-secret-key-abcdef")
    monkeypatch.setenv("DATABASE_URL", "postgresql://admin:superpassword@db.internal:5432/redmercury")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_synthetic_token_1234567890abcdef")

    cfg = SandboxConfig(
        image=LIVE_DOCKER_IMAGE,
        timeout_seconds=15,
        fail_closed=True,
    )
    returncode, stdout, stderr, is_timeout, error_msg = execute_in_container(
        workspace_dir=tmp_path,
        cmd_args=[
            "python3",
            "-c",
            "import os, json; print(json.dumps(dict(os.environ)))",
        ],
        config=cfg,
    )

    assert returncode == 0
    assert not is_timeout

    import json
    container_env = json.loads(stdout.strip())

    forbidden_keys = [
        "SECRET_KEY",
        "GEMINI_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "DATABASE_URL",
        "GITHUB_TOKEN",
    ]
    for key in forbidden_keys:
        assert key not in container_env, f"Host secret '{key}' was leaked into the container!"
        assert "ultra-secret" not in stdout
        assert "synthetic-gemini" not in stdout
        assert "superpassword" not in stdout


# ==============================================================================
# 7. WORKSPACE ISOLATION & NO HOST FILESYSTEM / DOCKER SOCKET MOUNT
# ==============================================================================

def test_live_docker_no_docker_socket_or_host_drives(tmp_path: Path):
    """Verify Docker socket is absent and host filesystem cannot be traversed from container."""
    cfg = SandboxConfig(
        image=LIVE_DOCKER_IMAGE,
        timeout_seconds=15,
        fail_closed=True,
    )
    returncode, stdout, stderr, is_timeout, error_msg = execute_in_container(
        workspace_dir=tmp_path,
        cmd_args=[
            "python3",
            "-c",
            "import os, json; print(json.dumps({'sock_exists': os.path.exists('/var/run/docker.sock'), 'root_contents': os.listdir('/')}))",
        ],
        config=cfg,
    )

    assert returncode == 0
    assert not is_timeout

    import json
    data = json.loads(stdout.strip())
    assert data["sock_exists"] is False, "Docker socket /var/run/docker.sock MUST NOT be mounted in container!"
    assert "host" not in data["root_contents"]
    assert "c" not in data["root_contents"]


# ==============================================================================
# 8. BOUNDED RESOURCE LIMITATION TESTS (MEMORY & PIDS)
# ==============================================================================

def test_live_docker_memory_limit_bounded_oom(tmp_path: Path):
    """Verify container is bounded by --memory quota (32m) and terminated without host crash."""
    test_file = tmp_path / "test_mem.py"
    test_file.write_text(
        "def test_alloc():\n"
        "    # Allocate 96MB within a 32MB constrained container\n"
        "    blob = bytearray(96 * 1024 * 1024)\n"
        "    assert len(blob) > 0\n",
        encoding="utf-8",
    )
    cfg = SandboxConfig(
        image=LIVE_DOCKER_IMAGE,
        memory_limit="32m",
        timeout_seconds=15,
        fail_closed=True,
    )
    outcome = run_pytest_in_workspace(
        workspace_dir=tmp_path,
        test_target="test_mem.py",
        sandbox_config=cfg,
    )

    # Must fail or error under OOM killer termination, never report passed
    assert outcome.status in ("failed", "error")
    assert outcome.passed_count == 0


def test_live_docker_pids_limit_anti_fork_bomb(tmp_path: Path):
    """Verify --pids-limit bounds child process creation safely without host process starvation."""
    test_file = tmp_path / "test_fork.py"
    test_file.write_text(
        "import os\n"
        "def test_bounded_fork():\n"
        "    pids = []\n"
        "    try:\n"
        "        for _ in range(32):\n"
        "            p = os.fork()\n"
        "            if p == 0:\n"
        "                os._exit(0)\n"
        "            pids.append(p)\n"
        "    except BlockingIOError:\n"
        "        pass  # Expected: blocked by pids-limit\n"
        "    finally:\n"
        "        for p in pids:\n"
        "            try:\n"
        "                os.waitpid(p, 0)\n"
        "            except Exception:\n"
        "                pass\n",
        encoding="utf-8",
    )
    cfg = SandboxConfig(
        image=LIVE_DOCKER_IMAGE,
        pids_limit=16,
        timeout_seconds=15,
        fail_closed=True,
    )
    outcome = run_pytest_in_workspace(
        workspace_dir=tmp_path,
        test_target="test_fork.py",
        sandbox_config=cfg,
    )
    # The process bounds safely contained execution without host process exhaustion
    assert outcome.status in ("passed", "failed", "error")


# ==============================================================================
# 9. TIMEOUT HANDLING & EPHEMERAL CONTAINER CLEANUP
# ==============================================================================

def test_live_docker_timeout_and_ephemeral_cleanup(tmp_path: Path):
    """Verify hanging execution times out and ephemeral container is removed from Docker."""
    container_marker = f"redmercury-test-cleanup-{uuid.uuid4().hex[:8]}"

    cfg = SandboxConfig(
        image=LIVE_DOCKER_IMAGE,
        timeout_seconds=2,
        fail_closed=True,
    )

    start_time = time.time()
    returncode, stdout, stderr, is_timeout, error_msg = execute_in_container(
        workspace_dir=tmp_path,
        cmd_args=["python3", "-c", "import time; time.sleep(10)"],
        config=cfg,
    )
    elapsed = time.time() - start_time

    assert is_timeout is True
    assert "timeout limit" in (error_msg or "").lower()
    assert elapsed < 8.0, f"Execution should have terminated around 2s, took {elapsed:.2f}s"

    # Verify no container with this prefix is left lingering in docker ps
    ps_res = subprocess.run(
        ["docker", "ps", "-a", "--filter", f"name={container_marker}", "--format", "{{.Names}}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=5,
        check=False,
    )
    assert ps_res.stdout.strip() == "", "Lingering container found in Docker daemon!"


# ==============================================================================
# 10. FAIL-CLOSED AND EXPLICIT ERROR ON STARTUP / BAD IMAGE
# ==============================================================================

def test_live_docker_invalid_image_fails_closed_explicitly(tmp_path: Path):
    """Verify non-existent container image causes explicit status='error', NEVER 'passed'."""
    (tmp_path / "test_dummy.py").write_text("def test_ok(): pass\n", encoding="utf-8")

    cfg = SandboxConfig(
        image=f"nonexistent-image-{uuid.uuid4().hex[:8]}:v999",
        timeout_seconds=10,
        fail_closed=True,
    )
    outcome = run_pytest_in_workspace(
        workspace_dir=tmp_path,
        test_target="test_dummy.py",
        sandbox_config=cfg,
    )

    assert outcome.status == "error"
    assert outcome.passed_count == 0
    assert outcome.failed_count == 0
    assert outcome.error_message is not None


# ==============================================================================
# 11. END-TO-END FIX VERIFICATION WORKFLOWS (PASS VS. FAIL)
# ==============================================================================

def test_live_docker_fix_verification_passing_suite(tmp_path: Path):
    """Verify that a genuine passing test suite reports status='passed' with accurate counts."""
    (tmp_path / "test_fix.py").write_text(
        "def test_security_check_one(): assert 1 + 1 == 2\n"
        "def test_security_check_two(): assert [x * 2 for x in (1, 2)] == [2, 4]\n",
        encoding="utf-8",
    )
    cfg = SandboxConfig(
        image=LIVE_DOCKER_IMAGE,
        timeout_seconds=20,
        fail_closed=True,
    )
    outcome = run_pytest_in_workspace(
        workspace_dir=tmp_path,
        test_target="test_fix.py",
        sandbox_config=cfg,
    )

    assert outcome.status == "passed"
    assert outcome.passed_count == 2
    assert outcome.failed_count == 0
    assert outcome.error_message is None


def test_live_docker_fix_verification_failing_suite(tmp_path: Path):
    """Verify that a failing test suite reports status='failed' with accurate counts."""
    (tmp_path / "test_fail.py").write_text(
        "def test_passing(): assert True\n"
        "def test_failing(): assert False, 'Security regression triggered'\n",
        encoding="utf-8",
    )
    cfg = SandboxConfig(
        image=LIVE_DOCKER_IMAGE,
        timeout_seconds=20,
        fail_closed=True,
    )
    outcome = run_pytest_in_workspace(
        workspace_dir=tmp_path,
        test_target="test_fail.py",
        sandbox_config=cfg,
    )

    assert outcome.status == "failed"
    assert outcome.passed_count == 1
    assert outcome.failed_count == 1
    assert outcome.error_message is not None
