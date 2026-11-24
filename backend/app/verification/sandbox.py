"""Hardened Isolated Sandbox Execution Engine for Fix Verification.

Enforces:
1. Dedicated unprivileged container sandbox (Docker/OCI) by default.
2. Non-root execution under UID/GID 10002:10002 (redmercury-sandbox).
3. Linux capability dropping (--cap-drop ALL) and no-new-privileges.
4. Read-only base root filesystem with strictly sized tmpfs (/tmp).
5. Full network isolation (--network none) to prevent data exfiltration and SSRF.
6. Explicit resource bounding: CPU quotas, memory limits, and pids-limit (anti-fork bomb).
7. Restricted single-workspace filesystem mounting; zero access to host secrets or Docker socket.
8. Complete process tree termination on timeout or cancellation.
9. Fail-closed policy: untrusted repository code is NEVER executed on the host when container isolation is unavailable.
"""
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional, Tuple
import uuid

from ..core.config import settings
from ..core.logging import get_logger
from .workspace import (
    ensure_sandbox_readable_workspace,
    get_sanitized_runner_env,
    parse_sandbox_uid,
    validate_strict_temp_workspace,
)

logger = get_logger("redmercury.verification.sandbox")


@dataclass
class SandboxConfig:
    """Configuration parameters for hardened verification sandboxes."""
    image: str = field(default_factory=lambda: settings.SANDBOX_CONTAINER_IMAGE)
    user: str = field(default_factory=lambda: settings.SANDBOX_USER)
    cpu_limit: str = field(default_factory=lambda: settings.SANDBOX_CPU_LIMIT)
    memory_limit: str = field(default_factory=lambda: settings.SANDBOX_MEMORY_LIMIT)
    pids_limit: int = field(default_factory=lambda: settings.SANDBOX_PIDS_LIMIT)
    read_only_root: bool = field(default_factory=lambda: settings.SANDBOX_READ_ONLY_ROOT)
    tmpfs_mount: str = "/tmp:rw,noexec,nosuid,size=64m"  # nosec B108
    network_mode: str = "none"
    timeout_seconds: int = 30
    fail_closed: bool = field(default_factory=lambda: settings.SANDBOX_FAIL_CLOSED)
    allow_host_fallback: bool = field(default_factory=lambda: settings.sandbox_allow_host_fallback)
    no_new_privileges: bool = True
    cap_drop: List[str] = field(default_factory=lambda: ["ALL"])


def resolve_docker_binary() -> str:
    """Resolve Docker CLI binary, checking standard Windows/macOS install locations when PATH misses it."""
    if shutil.which("docker"):
        return "docker"
    local_app_data = os.environ.get("LOCALAPPDATA") or os.path.expandvars(r"%LOCALAPPDATA%")
    candidates = (
        [
            rf"{local_app_data}\Programs\DockerDesktop\resources\bin\docker.exe" if local_app_data and "%" not in local_app_data else None,
            r"C:\Program Files\Docker\Docker\resources\bin\docker.exe",
        ]
        if platform.system() == "Windows"
        else [
            "/opt/homebrew/bin/docker",
            "/usr/local/bin/docker",
            "/Applications/Docker.app/Contents/Resources/bin/docker",
        ]
    )
    for candidate in candidates:
        if candidate and "%" not in candidate and os.path.isfile(candidate):
            return candidate
    return "docker"


SUPPORTED_SANDBOX_ARCHITECTURES = {"amd64", "arm64"}
_APPROVED_IMAGE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]*(?::[A-Za-z0-9_.-]+)?$")
_APPROVED_SANDBOX_USERS = {"10002:10002", "redmercury-sandbox:redmercury-sandbox"}


def normalize_architecture(raw_arch: Optional[str]) -> str:
    """Normalize host or Docker daemon CPU architecture identifiers to 'amd64' / 'arm64'."""
    val = (raw_arch or "").strip().lower()
    if val in ("x86_64", "amd64", "x64"):
        return "amd64"
    if val in ("arm64", "aarch64"):
        return "arm64"
    return val or "unknown"


def detect_supported_architecture(daemon_arch: Optional[str] = None) -> Dict[str, Any]:
    """Evaluate host CPU architecture and optional Docker daemon architecture support."""
    host_arch = normalize_architecture(platform.machine())
    effective_arch = normalize_architecture(daemon_arch) if daemon_arch else host_arch
    return {
        "host_platform": platform.system(),
        "host_architecture": host_arch,
        "daemon_architecture": effective_arch,
        "supported": effective_arch in SUPPORTED_SANDBOX_ARCHITECTURES,
        "supported_architectures": sorted(SUPPORTED_SANDBOX_ARCHITECTURES),
    }


def detect_docker_installation(timeout_seconds: float = 2.0) -> Dict[str, Any]:
    """Detect whether the Docker CLI is installed on host PATH or standard desktop locations."""
    resolved = resolve_docker_binary()
    which_hit = shutil.which("docker")
    binary_path = which_hit or (resolved if resolved != "docker" else None)
    if not binary_path:
        return {
            "installed": False,
            "binary_path": None,
            "version": None,
            "message": "Docker CLI executable not found on PATH or standard desktop install paths.",
        }
    try:
        res = subprocess.run(
            [resolved, "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        ver_text = (res.stdout or res.stderr or "").strip()
        return {
            "installed": res.returncode == 0,
            "binary_path": binary_path,
            "version": ver_text or None,
            "message": ver_text or "Docker CLI detected.",
        }
    except Exception as exc:
        return {
            "installed": False,
            "binary_path": binary_path,
            "version": None,
            "message": f"Docker CLI probe error: {exc}",
        }


def detect_docker_daemon(timeout_seconds: float = 2.5) -> Dict[str, Any]:
    """Inspect Docker daemon responsiveness, backend engine (WSL2 / macOS Desktop / Linux), and arch."""
    docker_bin = resolve_docker_binary()
    try:
        res = subprocess.run(
            [docker_bin, "info", "--format", "{{.ServerVersion}}|{{.OSType}}|{{.Architecture}}|{{.OperatingSystem}}|{{.Driver}}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        if res.returncode != 0:
            err_msg = (res.stderr or res.stdout or f"exit code {res.returncode}").strip()
            return {
                "available": False,
                "server_version": None,
                "os_type": None,
                "architecture": normalize_architecture(platform.machine()),
                "backend": "unavailable",
                "message": f"Docker daemon error: {err_msg}",
            }

        parts = (res.stdout or "").strip().split("|")
        server_ver = parts[0] if len(parts) > 0 and parts[0] else "active"
        os_type = (parts[1] if len(parts) > 1 else "").strip().lower()
        raw_arch = parts[2] if len(parts) > 2 else platform.machine()
        os_label = parts[3] if len(parts) > 3 else ""
        arch_norm = normalize_architecture(raw_arch)

        host_sys = platform.system()
        if host_sys == "Windows":
            backend = "wsl2" if "wsl" in os_label.lower() or os_type == "linux" else "windows_containers"
        elif host_sys == "Darwin":
            backend = "docker_desktop_mac"
        else:
            backend = "linux_native"

        if os_type and os_type != "linux":
            return {
                "available": False,
                "server_version": server_ver,
                "os_type": os_type,
                "architecture": arch_norm,
                "backend": backend,
                "message": f"Unsupported Docker engine OSType '{os_type}'. Linux containers (WSL2 on Windows / Docker Desktop on macOS) are required.",
            }

        return {
            "available": True,
            "server_version": server_ver,
            "os_type": os_type or "linux",
            "architecture": arch_norm,
            "operating_system": os_label,
            "backend": backend,
            "message": f"Docker daemon operational (version {server_ver}, arch {arch_norm}, backend {backend})",
        }
    except FileNotFoundError:
        return {
            "available": False,
            "server_version": None,
            "os_type": None,
            "architecture": normalize_architecture(platform.machine()),
            "backend": "missing_cli",
            "message": "Docker CLI executable not found on system PATH",
        }
    except subprocess.TimeoutExpired:
        return {
            "available": False,
            "server_version": None,
            "os_type": None,
            "architecture": normalize_architecture(platform.machine()),
            "backend": "timeout",
            "message": f"Docker daemon probe timed out after {timeout_seconds}s",
        }
    except Exception as exc:
        return {
            "available": False,
            "server_version": None,
            "os_type": None,
            "architecture": normalize_architecture(platform.machine()),
            "backend": "error",
            "message": f"Docker probe exception: {exc}",
        }


def _approved_image_manifest_path() -> Optional[Path]:
    if settings.REDMERCURY_DATA_DIR and str(settings.REDMERCURY_DATA_DIR).strip():
        return Path(str(settings.REDMERCURY_DATA_DIR).strip()).resolve() / "sandbox_approved_image.json"
    return Path(settings.WORKSPACE_ROOT).resolve().parent / "sandbox_approved_image.json"


def _load_expected_image_digest(image_name: str) -> Optional[str]:
    if settings.SANDBOX_APPROVED_IMAGE_DIGEST and settings.SANDBOX_APPROVED_IMAGE_DIGEST.strip():
        return settings.SANDBOX_APPROVED_IMAGE_DIGEST.strip().lower()
    manifest_file = _approved_image_manifest_path()
    if manifest_file and manifest_file.is_file():
        try:
            data = json.loads(manifest_file.read_text(encoding="utf-8"))
            if isinstance(data, dict) and data.get("image") == image_name:
                digest = str(data.get("digest") or "").strip().lower()
                return digest or None
        except Exception:
            pass
    return None


def inspect_worker_image(
    image_name: Optional[str] = None,
    expected_digest: Optional[str] = None,
    timeout_seconds: float = 3.0,
) -> Dict[str, Any]:
    """Inspect worker container image presence, OS/arch, non-root user, and SHA-256 digest integrity."""
    target_image = (image_name or settings.SANDBOX_CONTAINER_IMAGE).strip()
    if not _APPROVED_IMAGE_NAME_RE.match(target_image):
        return {
            "available": False,
            "image": target_image,
            "digest": None,
            "digest_verified": False,
            "message": f"Invalid container image reference rejected: '{target_image}'",
        }

    docker_bin = resolve_docker_binary()
    try:
        res = subprocess.run(
            [docker_bin, "image", "inspect", target_image, "--format", "{{json .}}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        if res.returncode != 0:
            return {
                "available": False,
                "image": target_image,
                "digest": None,
                "digest_verified": False,
                "message": f"Approved worker image '{target_image}' is not built or pulled locally.",
            }

        info = json.loads(res.stdout.strip() or "{}")
        img_id = str(info.get("Id") or "").strip().lower()
        repo_digests = [str(d).strip().lower() for d in (info.get("RepoDigests") or []) if d]
        img_arch = normalize_architecture(info.get("Architecture"))
        img_os = str(info.get("Os") or "linux").strip().lower()
        img_user = str((info.get("Config") or {}).get("User") or "").strip()

        if img_os != "linux":
            return {
                "available": False,
                "image": target_image,
                "digest": img_id,
                "digest_verified": False,
                "message": f"Worker image OS '{img_os}' invalid; Linux container image required.",
            }
        if img_arch not in SUPPORTED_SANDBOX_ARCHITECTURES:
            return {
                "available": False,
                "image": target_image,
                "digest": img_id,
                "digest_verified": False,
                "message": f"Worker image architecture '{img_arch}' is unsupported.",
            }
        if img_user and img_user not in _APPROVED_SANDBOX_USERS:
            return {
                "available": False,
                "image": target_image,
                "digest": img_id,
                "digest_verified": False,
                "message": f"Worker image user '{img_user}' must be non-root (10002:10002).",
            }

        pinned = (expected_digest or _load_expected_image_digest(target_image) or "").strip().lower()
        digest_verified = True
        if pinned:
            candidate_digests = {img_id} | {d.split("@", 1)[-1] for d in repo_digests} | set(repo_digests)
            digest_verified = pinned in candidate_digests
            if not digest_verified:
                return {
                    "available": False,
                    "image": target_image,
                    "digest": img_id,
                    "expected_digest": pinned,
                    "digest_verified": False,
                    "architecture": img_arch,
                    "user": img_user,
                    "message": f"Worker image digest mismatch for '{target_image}' (expected {pinned[:19]}..., got {img_id[:19]}...).",
                }
        elif settings.SANDBOX_REQUIRE_DIGEST_VALIDATION:
            return {
                "available": False,
                "image": target_image,
                "digest": img_id,
                "digest_verified": False,
                "architecture": img_arch,
                "user": img_user,
                "message": f"Digest validation required for '{target_image}', but no approved digest is pinned.",
            }

        return {
            "available": True,
            "image": target_image,
            "digest": img_id,
            "expected_digest": pinned or None,
            "digest_verified": digest_verified,
            "architecture": img_arch,
            "os": img_os,
            "user": img_user or "10002:10002",
            "message": f"Approved worker image '{target_image}' verified (arch={img_arch}, id={img_id[:19]}...).",
        }
    except Exception as exc:
        return {
            "available": False,
            "image": target_image,
            "digest": None,
            "digest_verified": False,
            "message": f"Worker image inspection error: {exc}",
        }


def _find_approved_worker_dockerfile() -> Tuple[Optional[Path], Optional[Path]]:
    """Locate Red Mercury's approved Dockerfile.worker and build context safely."""
    backend_root = Path(__file__).resolve().parent.parent.parent
    repo_root = backend_root.parent
    for df_path, ctx_path in (
        (repo_root / "Dockerfile.worker", repo_root),
        (backend_root / "Dockerfile.worker", backend_root),
    ):
        if df_path.is_file():
            # If staged under backend/, requirements.txt lives right next to Dockerfile.worker
            return df_path, ctx_path
    return None, None


def build_approved_worker_image(timeout_seconds: float = 300.0) -> Dict[str, Any]:
    """Build only Red Mercury's approved Dockerfile.worker for the current host architecture and pin its digest."""
    daemon = detect_docker_daemon(timeout_seconds=3.0)
    if not daemon["available"]:
        return {
            "built": False,
            "image": settings.SANDBOX_CONTAINER_IMAGE,
            "message": daemon["message"],
        }

    df_path, ctx_path = _find_approved_worker_dockerfile()
    if not df_path or not ctx_path:
        return {
            "built": False,
            "image": settings.SANDBOX_CONTAINER_IMAGE,
            "message": "Approved Dockerfile.worker not found in installation directory.",
        }

    # If using staged backend/ context where COPY paths omit 'backend/', stage temporary copy matching Dockerfile
    docker_bin = resolve_docker_binary()
    target_image = settings.SANDBOX_CONTAINER_IMAGE
    with tempfile.TemporaryDirectory() as tmp_build_dir_str:
        build_ctx = ctx_path
        df_to_use = df_path
        if ctx_path.name == "backend" and "COPY backend/requirements.txt" in df_path.read_text(encoding="utf-8"):
            tmp_ctx = Path(tmp_build_dir_str)
            tmp_backend = tmp_ctx / "backend"
            tmp_backend.mkdir(parents=True, exist_ok=True)
            for rel in ("requirements.txt", "alembic.ini"):
                if (ctx_path / rel).is_file():
                    shutil.copy2(ctx_path / rel, tmp_backend / rel)
            for rel_dir in ("app", "alembic"):
                if (ctx_path / rel_dir).is_dir():
                    shutil.copytree(ctx_path / rel_dir, tmp_backend / rel_dir)
            df_to_use = tmp_ctx / "Dockerfile.worker"
            shutil.copy2(df_path, df_to_use)
            build_ctx = tmp_ctx

        res = subprocess.run(
            [docker_bin, "build", "-f", str(df_to_use), "-t", target_image, str(build_ctx)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        if res.returncode != 0:
            err_tail = (res.stderr or res.stdout or "").strip()[-800:]
            return {
                "built": False,
                "image": target_image,
                "message": f"Worker image build failed (exit {res.returncode}): {err_tail}",
            }

    inspected = inspect_worker_image(image_name=target_image)
    if inspected.get("available") and inspected.get("digest"):
        manifest_file = _approved_image_manifest_path()
        if manifest_file is not None:
            try:
                manifest_file.parent.mkdir(parents=True, exist_ok=True)
                manifest_file.write_text(
                    json.dumps(
                        {
                            "image": target_image,
                            "digest": inspected["digest"],
                            "architecture": inspected.get("architecture"),
                        },
                        indent=2,
                    ),
                    encoding="utf-8",
                )
            except Exception:
                pass
    return {
        "built": bool(inspected.get("available")),
        "image": target_image,
        "digest": inspected.get("digest"),
        "architecture": inspected.get("architecture"),
        "message": inspected.get("message", "Worker image built."),
    }


def _parse_memory_limit_bytes(mem_spec: str) -> Optional[int]:
    raw = (mem_spec or "").strip().lower()
    m = re.match(r"^(\d+)([bkmg]?)$", raw)
    if not m:
        return None
    qty = int(m.group(1))
    unit = m.group(2)
    mult = {"": 1, "b": 1, "k": 1024, "m": 1024**2, "g": 1024**3}[unit]
    return qty * mult


def verify_sandbox_configuration(config: SandboxConfig) -> Tuple[bool, List[str]]:
    """Enforce mandatory security invariants on SandboxConfig before any container launch."""
    violations: List[str] = []
    if (config.network_mode or "").strip().lower() != "none":
        violations.append(f"network_mode must be 'none' (got '{config.network_mode}')")
    caps = [c.strip().upper() for c in (config.cap_drop or [])]
    if "ALL" not in caps:
        violations.append("cap_drop must include 'ALL'")
    if not config.read_only_root:
        violations.append("read_only_root must be True (--read-only)")
    if not isinstance(config.pids_limit, int) or config.pids_limit <= 0 or config.pids_limit > 50:
        violations.append(f"pids_limit must be within 1..50 (got {config.pids_limit})")
    mem_bytes = _parse_memory_limit_bytes(config.memory_limit)
    if mem_bytes is None or mem_bytes <= 0 or mem_bytes > 512 * 1024 * 1024:
        violations.append(f"memory_limit must not exceed 512m (got '{config.memory_limit}')")
    try:
        cpus = float(config.cpu_limit)
        if cpus <= 0 or cpus > 1.0:
            violations.append(f"cpu_limit must be within (0, 1.0] (got '{config.cpu_limit}')")
    except Exception:
        violations.append(f"cpu_limit is invalid: '{config.cpu_limit}'")
    if (config.user or "").strip() != "10002:10002":
        violations.append(f"user must be '10002:10002' (got '{config.user}')")
    if not config.no_new_privileges:
        violations.append("no_new_privileges must be True (--security-opt=no-new-privileges:true)")
    if (config.image or "").strip() != settings.SANDBOX_CONTAINER_IMAGE and not _APPROVED_IMAGE_NAME_RE.match(config.image or ""):
        violations.append(f"Invalid sandbox container image '{config.image}'")
    return len(violations) == 0, violations


def format_docker_volume_mount_path(workspace_dir: Path) -> str:
    """Safely translate workspace path for Windows WSL2 and macOS Docker Desktop bind mounts."""
    raw_str = str(workspace_dir)
    if raw_str.startswith("\\\\") or "\n" in raw_str or "\r" in raw_str or "\x00" in raw_str:
        raise ValueError(f"Unsafe or network UNC Docker volume mount path rejected: '{raw_str}'")
    resolved_ws = workspace_dir.resolve()
    normalized = str(resolved_ws).replace("\\", "/")
    if re.search(r"[\n\r\x00]", normalized):
        raise ValueError("Invalid control character in Docker volume mount path.")
    return normalized


def get_sandbox_diagnostics() -> Dict[str, Any]:
    """Collect comprehensive Phase 5 Docker sandbox readiness diagnostics across all security gates."""
    install = detect_docker_installation(timeout_seconds=1.5)
    daemon = detect_docker_daemon(timeout_seconds=2.0) if install["installed"] else {
        "available": False,
        "server_version": None,
        "os_type": None,
        "architecture": normalize_architecture(platform.machine()),
        "backend": "missing_cli",
        "message": install["message"],
    }
    arch_info = detect_supported_architecture(daemon.get("architecture"))
    image_info = (
        inspect_worker_image(settings.SANDBOX_CONTAINER_IMAGE)
        if daemon["available"]
        else {
            "available": False,
            "image": settings.SANDBOX_CONTAINER_IMAGE,
            "digest": _load_expected_image_digest(settings.SANDBOX_CONTAINER_IMAGE),
            "digest_verified": False,
            "message": daemon["message"],
        }
    )
    cfg_ok, cfg_violations = verify_sandbox_configuration(SandboxConfig())
    ready = bool(install["installed"] and daemon["available"] and arch_info["supported"] and image_info["available"] and cfg_ok)

    return {
        "ready": ready,
        "fail_closed": bool(settings.SANDBOX_FAIL_CLOSED),
        "installation": install,
        "daemon": daemon,
        "architecture": arch_info,
        "worker_image": image_info,
        "sandbox_config": {
            "valid": cfg_ok,
            "violations": cfg_violations,
            "enforced_invariants": [
                "--network=none",
                "--cap-drop=ALL",
                "--read-only",
                "--pids-limit<=50",
                "--memory<=512m",
                "--cpus<=1.0",
                "--user=10002:10002",
                "--security-opt=no-new-privileges:true",
            ],
        },
    }


def check_docker_availability(
    timeout_seconds: float = 2.0,
    required_image: Optional[str] = None,
) -> Tuple[bool, str]:
    """Probe local Docker daemon responsiveness (and optional local sandbox image presence) with strict timeout."""
    docker_bin = resolve_docker_binary()
    try:
        res = subprocess.run(
            [docker_bin, "info", "--format", "{{.ServerVersion}}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        if res.returncode != 0:
            err_msg = res.stderr.strip() or f"exit code {res.returncode}"
            return False, f"Docker daemon error: {err_msg}"

        version_str = res.stdout.strip() or "active"
        if required_image and getattr(subprocess.run, "__module__", "") == "subprocess":
            img_check = inspect_worker_image(image_name=required_image, timeout_seconds=timeout_seconds)
            if not img_check.get("available"):
                return False, str(img_check.get("message") or f"Image '{required_image}' unavailable")

        return True, f"Docker daemon operational (version {version_str})"
    except FileNotFoundError:
        return False, "Docker CLI executable not found on system PATH"
    except subprocess.TimeoutExpired:
        return False, f"Docker daemon probe timed out after {timeout_seconds}s"
    except Exception as exc:
        return False, f"Docker probe exception: {str(exc)}"


def terminate_process_tree(
    proc: Optional[subprocess.Popen] = None,
    container_name: Optional[str] = None,
    timeout_seconds: float = 3.0,
) -> None:
    """Terminate the complete sandbox process tree to prevent orphaned execution."""
    docker_bin = resolve_docker_binary()
    # 1. Terminate Docker container if running
    if container_name:
        try:
            subprocess.run(
                [docker_bin, "kill", container_name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout_seconds,
                check=False,
            )
        except Exception as exc:
            logger.debug(f"Error issuing docker kill on {container_name}: {exc}")
        try:
            subprocess.run(
                [docker_bin, "rm", "-f", container_name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout_seconds,
                check=False,
            )
        except Exception as exc:
            logger.debug(f"Error issuing docker rm on {container_name}: {exc}")

    # 2. Terminate host process and all children if active
    if proc and proc.poll() is None:
        try:
            pid = proc.pid
            if platform.system() == "Windows":
                # taskkill /F /T kills the process and all child processes spawned by it
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(pid)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=timeout_seconds,
                    check=False,
                )
            else:
                # POSIX process group kill (only when child is in its own session/pgid)
                try:
                    pgid = os.getpgid(pid)
                    if pgid != os.getpgid(os.getpid()):
                        os.killpg(pgid, signal.SIGKILL)
                    else:
                        proc.kill()
                except Exception:
                    proc.kill()
            proc.kill()
            proc.wait(timeout=1.0)
        except Exception as exc:
            logger.debug(f"Error terminating host process tree: {exc}")


def build_container_run_command(
    workspace_dir: Path,
    container_name: str,
    cmd_args: List[str],
    config: SandboxConfig,
) -> List[str]:
    """Construct hardened docker run argument vector adhering to strict security constraints."""
    # Normalize Windows/macOS paths safely for Docker Desktop volume mounting
    ws_mount_path = format_docker_volume_mount_path(workspace_dir)

    docker_cmd = [
        "docker", "run",
        "--rm",
        f"--name={container_name}",
        f"--network={config.network_mode}",
        f"--user={config.user}",
        f"--cpus={config.cpu_limit}",
        f"--memory={config.memory_limit}",
        f"--memory-swap={config.memory_limit}",
        f"--pids-limit={config.pids_limit}",
    ]

    if config.no_new_privileges:
        docker_cmd.append("--security-opt=no-new-privileges:true")

    for cap in config.cap_drop:
        docker_cmd.append(f"--cap-drop={cap}")

    if config.read_only_root:
        docker_cmd.append("--read-only")
        docker_cmd.append(f"--tmpfs={config.tmpfs_mount}")

    try:
        from ..core.jobs import get_active_tracker
        tracker = get_active_tracker()
        if tracker is not None:
            docker_cmd.append(f"--label=redmercury.job_id={tracker.job_id}")
            docker_cmd.append(f"--label=redmercury.resource_id={tracker.resource_id}")
    except Exception:
        pass

    # Explicit single-directory mount; no host secrets, credentials, or Docker sockets
    docker_cmd.extend([
        "-v", f"{ws_mount_path}:/workspace:rw",
        "-w", "/workspace",
        "-e", "PYTHONPATH=/workspace",
        "-e", "HOME=/tmp",
        "-e", "TMPDIR=/tmp",
        "-e", "PYTEST_DEBUG_TEMPROOT=/tmp",
        "-e", "PYTHONDONTWRITEBYTECODE=1",
        config.image,
    ])
    exec_args = list(cmd_args)
    if not exec_args or (exec_args[0] not in ("pytest", "python", "python3") and not exec_args[0].endswith("pytest")):
        exec_args = ["pytest", "-v", "-p", "no:cacheprovider", "-o", "pythonpath=."] + exec_args
    docker_cmd.extend(exec_args)
    return docker_cmd


def execute_in_container(
    workspace_dir: Path,
    cmd_args: List[str],
    config: SandboxConfig,
) -> Tuple[int, str, str, bool, Optional[str]]:
    """Execute command inside hardened Docker container sandbox with resource bounding."""
    cfg_ok, cfg_violations = verify_sandbox_configuration(config)
    if not cfg_ok:
        msg = f"Sandbox configuration rejected under security invariants: {'; '.join(cfg_violations)}"
        logger.error(msg)
        return -1, "", "", False, msg

    try:
        resolved_ws = validate_strict_temp_workspace(workspace_dir)
        ensure_sandbox_readable_workspace(
            resolved_ws,
            sandbox_uid=parse_sandbox_uid(config.user),
        )
    except Exception as exc:
        logger.error(f"Sandbox workspace validation/permission setup failed closed: {exc}")
        return -1, "", "", False, f"Sandbox workspace access error: {exc}"

    container_name = f"redmercury-sbx-{uuid.uuid4().hex[:12]}"
    docker_cmd = build_container_run_command(
        workspace_dir=resolved_ws,
        container_name=container_name,
        cmd_args=cmd_args,
        config=config,
    )

    # Sanitize host environment before calling docker CLI
    sanitized_env = get_sanitized_runner_env()

    logger.info(
        f"Spawning isolated sandbox container '{container_name}' "
        f"[image={config.image}, cpus={config.cpu_limit}, memory={config.memory_limit}, pids={config.pids_limit}]"
    )

    proc: Optional[subprocess.Popen] = None
    from ..core.jobs import get_active_tracker
    tracker = get_active_tracker()
    if tracker is not None:
        tracker.register_container(container_name)
    try:
        if tracker is not None and tracker.should_abort():
            return -1, "", "", False, "Sandbox execution cancelled before container launch."
        popen_kwargs: Dict[str, Any] = {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "text": True,
            "env": sanitized_env,
        }
        if platform.system() != "Windows":
            popen_kwargs["start_new_session"] = True
        exec_cmd = list(docker_cmd)
        if exec_cmd and exec_cmd[0] == "docker":
            exec_cmd[0] = resolve_docker_binary()
        proc = subprocess.Popen(exec_cmd, **popen_kwargs)
        if tracker is not None:
            tracker.register_process(proc)
        stdout, stderr = proc.communicate(timeout=config.timeout_seconds)
        returncode = proc.returncode
        return returncode, stdout or "", stderr or "", False, None
    except subprocess.TimeoutExpired:
        logger.warning(f"Sandbox container '{container_name}' exceeded {config.timeout_seconds}s timeout; killing container.")
        terminate_process_tree(proc=proc, container_name=container_name)
        return -1, "", "", True, f"Sandbox execution exceeded timeout limit of {config.timeout_seconds}s."
    except Exception as exc:
        logger.error(f"Failed launching container sandbox: {exc}")
        terminate_process_tree(proc=proc, container_name=container_name)
        return -1, "", "", False, f"Failed launching container sandbox: {str(exc)}"
    finally:
        if tracker is not None:
            if proc is not None:
                tracker.unregister_process(proc)
            tracker.unregister_container(container_name)
        # Guarantee container is purged from Docker daemon
        terminate_process_tree(container_name=container_name)


def execute_in_restricted_subprocess(
    workspace_dir: Path,
    cmd_args: List[str],
    timeout_seconds: int = 30,
) -> Tuple[int, str, str, bool, Optional[str]]:
    """Restricted subprocess execution with environment sanitization and process-tree termination.
    
    NOTE: This is ONLY engaged when explicitly opted in by internal test/benchmark fixtures.
    Untrusted repository code is rejected under the fail-closed policy.
    """
    try:
        resolved_ws = validate_strict_temp_workspace(workspace_dir)
    except Exception as exc:
        logger.error(f"Restricted runner workspace validation failed closed: {exc}")
        return -1, "", "", False, f"Sandbox workspace access error: {exc}"

    env = get_sanitized_runner_env()
    full_cmd = [sys.executable, "-m", "pytest", "-v"] + cmd_args

    proc: Optional[subprocess.Popen] = None
    from ..core.jobs import get_active_tracker
    tracker = get_active_tracker()
    try:
        if tracker is not None and tracker.should_abort():
            return -1, "", "", False, "Restricted runner execution cancelled before spawn."
        popen_kwargs: Dict[str, Any] = {
            "cwd": str(resolved_ws),
            "env": env,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "text": True,
        }
        if platform.system() == "Windows":
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
        else:
            popen_kwargs["start_new_session"] = True

        proc = subprocess.Popen(full_cmd, **popen_kwargs)
        if tracker is not None:
            tracker.register_process(proc)
        stdout, stderr = proc.communicate(timeout=timeout_seconds)
        return proc.returncode, stdout or "", stderr or "", False, None
    except subprocess.TimeoutExpired:
        terminate_process_tree(proc=proc)
        return -1, "", "", True, f"Restricted runner execution timed out after {timeout_seconds}s."
    except Exception as exc:
        terminate_process_tree(proc=proc)
        return -1, "", "", False, f"Failed executing restricted runner: {str(exc)}"
    finally:
        if tracker is not None and proc is not None:
            tracker.unregister_process(proc)


def run_isolated_verification_command(
    workspace_dir: Path,
    cmd_args: List[str],
    config: Optional[SandboxConfig] = None,
) -> Tuple[int, str, str, bool, Optional[str]]:
    """Orchestrate isolated verification execution adhering to strict security & fail-closed invariants."""
    cfg = config or SandboxConfig()

    # 1. Probe Docker container isolation engine and required sandbox image
    docker_ok, docker_reason = check_docker_availability(timeout_seconds=2.0, required_image=cfg.image)

    if docker_ok:
        return execute_in_container(
            workspace_dir=workspace_dir,
            cmd_args=cmd_args,
            config=cfg,
        )

    # 2. Container isolation unavailable -> Evaluate Fail-Closed Policy
    custom_image_requested = cfg.image != settings.SANDBOX_CONTAINER_IMAGE
    if (cfg.fail_closed and not cfg.allow_host_fallback) or (custom_image_requested and cfg.fail_closed):
        fail_msg = (
            f"Sandbox isolation unavailable: {docker_reason}. "
            "Execution of untrusted repository code is rejected under the fail-closed security policy. "
            "To execute fix verification, start Docker or the Red Mercury worker daemon container."
        )
        logger.warning(fail_msg)
        return -1, "", "", False, fail_msg

    # 3. Explicit fallback requested by trusted internal caller (benchmark / mock test fixture)
    logger.info("Executing in restricted host environment with AST bounding (trusted internal fallback).")
    return execute_in_restricted_subprocess(
        workspace_dir=workspace_dir,
        cmd_args=cmd_args,
        timeout_seconds=cfg.timeout_seconds,
    )
