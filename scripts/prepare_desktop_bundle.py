"""Prepare architecture-specific relocatable desktop runtime, scanner binaries, and clean backend staging.

Usage:
    python scripts/prepare_desktop_bundle.py --target win32-x64
    python scripts/prepare_desktop_bundle.py --target darwin-x64
    python scripts/prepare_desktop_bundle.py --target darwin-arm64
"""
import argparse
import hashlib
import io
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import urllib.request
import zipfile

REPO_ROOT = Path(__file__).resolve().parent.parent
STAGING_BASE = REPO_ROOT / "build" / "staging"
CACHE_DIR = REPO_ROOT / "build" / "cache"

PYTHON_STANDALONE_RELEASE = "20261110"
PYTHON_STANDALONE_ASSETS = {
    "win32-x64": {
        "url": f"https://github.com/astral-sh/python-build-standalone/releases/download/{PYTHON_STANDALONE_RELEASE}/cpython-3.12.16%2B{PYTHON_STANDALONE_RELEASE}-x86_64-pc-windows-msvc-install_only_stripped.tar.gz",
        "sha256": "355ee61b8207b91574491b1c6dc9b0ebb4408fc56bfafe498f3ef439314b52dc",
        "python_rel": "python.exe",
    },
    "darwin-x64": {
        "url": f"https://github.com/astral-sh/python-build-standalone/releases/download/{PYTHON_STANDALONE_RELEASE}/cpython-3.12.16%2B{PYTHON_STANDALONE_RELEASE}-x86_64-apple-darwin-install_only_stripped.tar.gz",
        "sha256": "b78a4c479f1964ec484880bee567568266f68da102269fb93a05fe8716b45f91",
        "python_rel": "bin/python3",
    },
    "darwin-arm64": {
        "url": f"https://github.com/astral-sh/python-build-standalone/releases/download/{PYTHON_STANDALONE_RELEASE}/cpython-3.12.16%2B{PYTHON_STANDALONE_RELEASE}-aarch64-apple-darwin-install_only_stripped.tar.gz",
        "sha256": "2f11b8aa3726bdbd87dd9eb76568412faddf4f47e26913fa45d6a2e424972acd",
        "python_rel": "bin/python3",
    },
}

GITLEAKS_VERSION = "8.18.2"
GITLEAKS_ASSETS = {
    "win32-x64": {
        "url": f"https://github.com/gitleaks/gitleaks/releases/download/v{GITLEAKS_VERSION}/gitleaks_{GITLEAKS_VERSION}_windows_x64.zip",
        "sha256": "aa19543417c668b15e89b3357413099d81a75029a8ebbaec5034b7c8cc33c7e5",
        "archive_type": "zip",
        "binary_name": "gitleaks.exe",
    },
    "darwin-x64": {
        "url": f"https://github.com/gitleaks/gitleaks/releases/download/v{GITLEAKS_VERSION}/gitleaks_{GITLEAKS_VERSION}_darwin_x64.tar.gz",
        "sha256": "b2dc4f853128062856273d422e2f29791a036641c1655feb83192078970fbfc0",
        "archive_type": "tar.gz",
        "binary_name": "gitleaks",
    },
    "darwin-arm64": {
        "url": f"https://github.com/gitleaks/gitleaks/releases/download/v{GITLEAKS_VERSION}/gitleaks_{GITLEAKS_VERSION}_darwin_arm64.tar.gz",
        "sha256": "7be53fa77d7ec10cb8a7085d6ebcf375d55dd4c71f2cf6e7e6bf11554847a095",
        "archive_type": "tar.gz",
        "binary_name": "gitleaks",
    },
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest().lower()


def download_verified(url: str, expected_sha256: str, dest_file: Path) -> Path:
    dest_file.parent.mkdir(parents=True, exist_ok=True)
    if dest_file.exists():
        if sha256_file(dest_file) == expected_sha256.lower():
            print(f"[bundle] Using SHA-256 verified cached artifact: {dest_file.name}")
            return dest_file
        dest_file.unlink()

    print(f"[bundle] Downloading {url}...")
    req = urllib.request.Request(url, headers={"User-Agent": "RedMercury-Packager/1.0"})
    with urllib.request.urlopen(req, timeout=120) as resp, open(dest_file, "wb") as out:
        shutil.copyfileobj(resp, out)

    actual = sha256_file(dest_file)
    if actual != expected_sha256.lower():
        dest_file.unlink(missing_ok=True)
        raise RuntimeError(f"SHA-256 mismatch for {dest_file.name}: expected {expected_sha256}, got {actual}")
    print(f"[bundle] Verified SHA-256 for {dest_file.name}: {actual}")
    return dest_file


def _safe_extract_tar(archive_path: Path, dest_dir: Path) -> None:
    resolved_dest = dest_dir.resolve()
    with tarfile.open(archive_path, "r:gz") as tf:
        for member in tf.getmembers():
            target = (resolved_dest / member.name).resolve()
            if target != resolved_dest and not target.is_relative_to(resolved_dest):
                raise RuntimeError(f"Blocked tar path traversal: {member.name}")
        tf.extractall(resolved_dest)


def prepare_python_runtime(target: str, runtime_dir: Path) -> None:
    spec = PYTHON_STANDALONE_ASSETS[target]
    archive_name = f"python-{target}-{PYTHON_STANDALONE_RELEASE}.tar.gz"
    archive_path = download_verified(spec["url"], spec["sha256"], CACHE_DIR / archive_name)

    if runtime_dir.exists():
        shutil.rmtree(runtime_dir)
    extract_tmp = runtime_dir.parent / f"_py_extract_{target}"
    if extract_tmp.exists():
        shutil.rmtree(extract_tmp)
    extract_tmp.mkdir(parents=True, exist_ok=True)

    _safe_extract_tar(archive_path, extract_tmp)
    inner_python = extract_tmp / "python"
    if not inner_python.exists():
        raise RuntimeError(f"Unexpected python-build-standalone layout in {archive_path}")
    shutil.move(str(inner_python), str(runtime_dir))
    shutil.rmtree(extract_tmp, ignore_errors=True)

    python_bin = runtime_dir / spec["python_rel"]
    if not python_bin.exists():
        raise RuntimeError(f"Bundled Python executable missing at {python_bin}")

    req_file = REPO_ROOT / "backend" / "requirements.txt"
    print(f"[bundle] Installing production Python requirements into {runtime_dir}...")
    subprocess.run(
        [str(python_bin), "-m", "pip", "install", "--no-cache-dir", "--upgrade", "pip"],
        check=True,
    )
    subprocess.run(
        [str(python_bin), "-m", "pip", "install", "--no-cache-dir", "-r", str(req_file)],
        check=True,
    )

    # Remove bytecode caches and pip cache artifacts to keep bundle lean and reproducible
    for cache_dir in list(runtime_dir.rglob("__pycache__")):
        shutil.rmtree(cache_dir, ignore_errors=True)
    for pyc in list(runtime_dir.rglob("*.pyc")):
        pyc.unlink(missing_ok=True)

    # Verify zero dev/test packages entered the production runtime
    pip_freeze = subprocess.run(
        [str(python_bin), "-m", "pip", "list", "--format=freeze"],
        stdout=subprocess.PIPE,
        text=True,
        check=True,
    ).stdout.lower()
    for forbidden_pkg in ("pytest==", "locust==", "pytest-asyncio=="):
        if forbidden_pkg in pip_freeze:
            raise RuntimeError(f"Forbidden development dependency found in runtime: {forbidden_pkg}")
    print(f"[bundle] Verified production Python runtime ready at {runtime_dir}")


def prepare_gitleaks_binary(target: str, bin_dir: Path) -> None:
    spec = GITLEAKS_ASSETS[target]
    bin_dir.mkdir(parents=True, exist_ok=True)
    out_bin = bin_dir / spec["binary_name"]
    if out_bin.exists():
        out_bin.unlink()

    ext = "zip" if spec["archive_type"] == "zip" else "tar.gz"
    archive_path = download_verified(
        spec["url"],
        spec["sha256"],
        CACHE_DIR / f"gitleaks-{GITLEAKS_VERSION}-{target}.{ext}",
    )

    if spec["archive_type"] == "zip":
        with zipfile.ZipFile(archive_path, "r") as zf:
            for member in zf.namelist():
                if Path(member).name == spec["binary_name"]:
                    with zf.open(member) as src, open(out_bin, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    break
    else:
        with tarfile.open(archive_path, "r:gz") as tf:
            for member in tf.getmembers():
                if Path(member.name).name == spec["binary_name"]:
                    src = tf.extractfile(member)
                    if src is None:
                        continue
                    with src, open(out_bin, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    break

    if not out_bin.exists():
        raise RuntimeError(f"Failed to extract {spec['binary_name']} from {archive_path}")
    if os.name != "nt":
        os.chmod(out_bin, 0o755)
    print(f"[bundle] Verified {spec['binary_name']} placed at {out_bin}")


def prepare_clean_backend(backend_dest: Path) -> None:
    src_backend = REPO_ROOT / "backend"
    if backend_dest.exists():
        shutil.rmtree(backend_dest)

    ignore = shutil.ignore_patterns(
        "__pycache__",
        "*.pyc",
        "*.pyo",
        ".pytest_cache",
        "data",
        "*.db",
        "*.db-*",
        "*.sqlite*",
        ".env",
        ".env.*",
        "requirements-dev.txt",
        "pyproject.toml",
        "tests",
    )
    shutil.copytree(src_backend, backend_dest, ignore=ignore)

    # Include approved Dockerfile.worker so desktop builds can provision redmercury-worker locally
    dockerfile_worker = REPO_ROOT / "Dockerfile.worker"
    if dockerfile_worker.is_file():
        shutil.copy2(dockerfile_worker, backend_dest / "Dockerfile.worker")

    # Hard security assertion: verify zero .env or .db files leaked into backend staging
    for leaked in list(backend_dest.rglob(".env*")) + list(backend_dest.rglob("*.db*")):
        if leaked.is_file():
            raise RuntimeError(f"Forbidden sensitive/dev file in staged backend: {leaked}")
    print(f"[bundle] Clean backend staged at {backend_dest}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Prepare Red Mercury desktop bundle staging directory")
    parser.add_argument(
        "--target",
        choices=["win32-x64", "darwin-x64", "darwin-arm64"],
        required=True,
        help="Target OS and CPU architecture",
    )
    parser.add_argument(
        "--skip-runtime",
        action="store_true",
        help="Skip downloading/installing Python runtime (reuse existing staged runtime)",
    )
    args = parser.parse_args()

    # Keep active staging cleanly populated at build/staging/active for electron-builder extraResources
    target_dir = STAGING_BASE / args.target
    active_dir = STAGING_BASE / "active"
    target_dir.mkdir(parents=True, exist_ok=True)

    runtime_dir = target_dir / "runtime"
    bin_dir = target_dir / "bin"
    backend_dir = target_dir / "backend"

    if not args.skip_runtime:
        prepare_python_runtime(args.target, runtime_dir)
    prepare_gitleaks_binary(args.target, bin_dir)
    prepare_clean_backend(backend_dir)

    if active_dir.exists():
        shutil.rmtree(active_dir)
    shutil.copytree(target_dir, active_dir)
    print(f"[bundle] Active staging synchronized at {active_dir} for target {args.target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
