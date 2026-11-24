"""Phase 5 Tests: Cross-Platform Secure Docker Verification (Windows WSL2 & macOS Intel/ARM64)."""
import json
from pathlib import Path
import subprocess
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from app.core.config import settings
from app.verification import runner, sandbox

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_detect_docker_installation_supports_windows_appdata_and_macos_paths():
    """Docker CLI resolution must detect per-user Windows AppData and macOS GUI paths."""
    mock_appdata = r"C:\Users\testuser\AppData\Local"
    appdata_docker = rf"{mock_appdata}\Programs\DockerDesktop\resources\bin\docker.exe"
    with (
        patch.dict(sandbox.os.environ, {"LOCALAPPDATA": mock_appdata}),
        patch.object(sandbox.shutil, "which", return_value=None),
        patch.object(sandbox.platform, "system", return_value="Windows"),
        patch.object(sandbox.os.path, "isfile", side_effect=lambda p: p == appdata_docker),
    ):
        assert sandbox.resolve_docker_binary() == appdata_docker

    mac_app_docker = "/Applications/Docker.app/Contents/Resources/bin/docker"
    with (
        patch.object(sandbox.shutil, "which", return_value=None),
        patch.object(sandbox.platform, "system", return_value="Darwin"),
        patch.object(sandbox.os.path, "isfile", side_effect=lambda p: p == mac_app_docker),
    ):
        assert sandbox.resolve_docker_binary() == mac_app_docker


def test_detect_docker_daemon_and_architecture_windows_wsl2_and_macos():
    """Daemon & arch probes must classify Windows WSL2, macOS Intel/ARM64, and reject Windows-container OSType."""
    def _mock_info(out: str):
        m = MagicMock()
        m.returncode = 0
        m.stdout = out
        m.stderr = ""
        return m

    with (
        patch.object(sandbox.platform, "system", return_value="Windows"),
        patch.object(sandbox.platform, "machine", return_value="AMD64"),
        patch("subprocess.run", return_value=_mock_info("27.4.0|linux|x86_64|Docker Desktop (WSL2)|overlay2")),
    ):
        daemon = sandbox.detect_docker_daemon()
        arch = sandbox.detect_supported_architecture(daemon["architecture"])
        assert daemon["available"] is True
        assert daemon["backend"] == "wsl2"
        assert daemon["architecture"] == "amd64"
        assert arch["supported"] is True

    with (
        patch.object(sandbox.platform, "system", return_value="Darwin"),
        patch.object(sandbox.platform, "machine", return_value="arm64"),
        patch("subprocess.run", return_value=_mock_info("27.4.0|linux|aarch64|Docker Desktop|overlayfs")),
    ):
        daemon = sandbox.detect_docker_daemon()
        arch = sandbox.detect_supported_architecture(daemon["architecture"])
        assert daemon["available"] is True
        assert daemon["backend"] == "docker_desktop_mac"
        assert daemon["architecture"] == "arm64"
        assert arch["supported"] is True

    with (
        patch.object(sandbox.platform, "system", return_value="Windows"),
        patch("subprocess.run", return_value=_mock_info("27.4.0|windows|x86_64|Windows|windowsfilter")),
    ):
        daemon = sandbox.detect_docker_daemon()
        assert daemon["available"] is False
        assert "linux containers" in daemon["message"].lower()


def test_validate_worker_image_digest_and_user_enforcement(tmp_path):
    """Worker image inspection must enforce non-root user, Linux OS, and pinned SHA-256 digest match."""
    img_payload = {
        "Id": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "RepoDigests": [],
        "Architecture": "arm64",
        "Os": "linux",
        "Config": {"User": "10002:10002"},
    }
    ok_res = MagicMock(returncode=0, stdout=json.dumps(img_payload), stderr="")

    with patch("subprocess.run", return_value=ok_res):
        valid = sandbox.inspect_worker_image(
            "redmercury-worker:latest",
            expected_digest="sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        assert valid["available"] is True
        assert valid["digest_verified"] is True
        assert valid["architecture"] == "arm64"

        tampered = sandbox.inspect_worker_image(
            "redmercury-worker:latest",
            expected_digest="sha256:2222222222222222222222222222222222222222222222222222222222222222",
        )
        assert tampered["available"] is False
        assert tampered["digest_verified"] is False
        assert "mismatch" in tampered["message"].lower()

    root_payload = {**img_payload, "Config": {"User": "0:0"}}
    with patch("subprocess.run", return_value=MagicMock(returncode=0, stdout=json.dumps(root_payload), stderr="")):
        rejected = sandbox.inspect_worker_image("redmercury-worker:latest")
        assert rejected["available"] is False
        assert "non-root" in rejected["message"].lower()


def test_verify_sandbox_configuration_rejects_weakened_invariants():
    """Every mandatory Phase 5 invariant must be verified and enforced fail-closed."""
    default_ok, violations = sandbox.verify_sandbox_configuration(sandbox.SandboxConfig())
    assert default_ok is True
    assert violations == []

    weak_configs = [
        sandbox.SandboxConfig(network_mode="bridge"),
        sandbox.SandboxConfig(cap_drop=[]),
        sandbox.SandboxConfig(read_only_root=False),
        sandbox.SandboxConfig(pids_limit=100),
        sandbox.SandboxConfig(memory_limit="1024m"),
        sandbox.SandboxConfig(cpu_limit="2.0"),
        sandbox.SandboxConfig(user="0:0"),
        sandbox.SandboxConfig(no_new_privileges=False),
    ]
    for cfg in weak_configs:
        ok, v = sandbox.verify_sandbox_configuration(cfg)
        assert ok is False
        assert len(v) >= 1
        code, _out, _err, _to, msg = sandbox.execute_in_container(Path("/tmp"), [], cfg)
        assert code == -1
        assert "security invariants" in (msg or "").lower()


def test_volume_mount_normalization_and_unc_rejection(tmp_path):
    """Cross-platform volume mount formatting must normalize paths and reject Windows UNC network shares."""
    mounted = sandbox.format_docker_volume_mount_path(tmp_path)
    assert "\\" not in mounted

    try:
        sandbox.format_docker_volume_mount_path(Path(r"\\attacker-smb\share\repo"))
        raised = False
    except ValueError:
        raised = True
    assert raised is True


def test_dockerfile_worker_supports_multi_arch_amd64_and_arm64():
    """Approved Dockerfile.worker must verify pinned Gitleaks SHA-256 digests for both amd64 and arm64."""
    df_text = (REPO_ROOT / "Dockerfile.worker").read_text(encoding="utf-8")
    assert "ARG TARGETARCH" in df_text
    assert "6298c9235dfc9278c14b28afd9b7fa4e6f4a289cb1974bd27949fc1e9122bdee" in df_text
    assert "4df25683f95b9e1dbb8cc71dac74d10067b8aba221e7f991e01cafa05bcbd030" in df_text
    assert "USER redmercury-sandbox:redmercury-sandbox" in df_text


def test_unavailable_docker_never_passes_verification_and_scans_remain_usable(
    client_a: TestClient,
    tmp_path,
    monkeypatch,
):
    """When Docker is unavailable, verification never passes and scoped sandbox status API reports unavailable honestly."""
    monkeypatch.setattr(settings, "APP_ENV", "desktop")
    monkeypatch.setattr(settings, "SANDBOX_FAIL_CLOSED", True)
    monkeypatch.setattr(settings, "SANDBOX_ALLOW_HOST_FALLBACK", False)
    with (
        patch.object(sandbox, "check_docker_availability", return_value=(False, "Docker daemon not running")),
        patch("subprocess.run", side_effect=FileNotFoundError("docker missing")),
    ):
        outcome = runner.run_pytest_in_workspace(workspace_dir=tmp_path, timeout_seconds=10)
        # No unit tests -> skipped, OR with unit test -> error; never 'passed'
        assert outcome.status != "passed"

        # With an actual test file, fail-closed must return explicit error (never passed)
        (tmp_path / "tests").mkdir(exist_ok=True)
        (tmp_path / "tests" / "test_sample.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")
        fail_outcome = runner.run_pytest_in_workspace(workspace_dir=tmp_path, timeout_seconds=10)
        assert fail_outcome.status == "error"
        assert "fail-closed" in (fail_outcome.error_message or "").lower()

        res = client_a.get("/api/v1/system/sandbox/status")
        assert res.status_code == 200
        body = res.json()
        assert body["ready"] is False
        assert body["fail_closed"] is True
        assert "--network=none" in body["sandbox_config"]["enforced_invariants"]
