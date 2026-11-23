"""Phase 3 Desktop Packaging, Cross-Platform Binary Resolution, and Bundle Hygiene Tests."""
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import shutil
import stat
import sys
from unittest.mock import patch

import pytest

from app.scanner.base import get_scanner_search_paths
from app.verification import sandbox, workspace

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_prepare_bundle_module():
    script_path = REPO_ROOT / "scripts" / "prepare_desktop_bundle.py"
    spec = importlib.util.spec_from_file_location("prepare_desktop_bundle", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_scanner_search_paths_includes_redmercury_bin_dir_and_executable_dir(tmp_path, monkeypatch):
    """Bundled desktop binary dir and interpreter directory must appear in scanner PATH lookup."""
    custom_bin = tmp_path / "bundled_bin"
    custom_bin.mkdir()
    monkeypatch.setenv("REDMERCURY_BIN_DIR", str(custom_bin))

    paths = get_scanner_search_paths()

    assert paths[0] == str(custom_bin)
    assert os.path.dirname(sys.executable) in paths


def test_darwin_workspace_permissions_enforces_owner_only_without_acl(tmp_path):
    """macOS workspace setup must apply strict owner-only bits, skip symlinks, and avoid Linux ACL calls."""
    ws_dir = tmp_path / "verify_ws"
    ws_dir.mkdir()
    sub_dir = ws_dir / "pkg"
    sub_dir.mkdir()
    script_file = sub_dir / "run_check.py"
    script_file.write_text("print('ok')\n", encoding="utf-8")

    chmod_calls = []

    def fake_chmod(target, mode):
        chmod_calls.append((Path(target), mode))

    with (
        patch.object(workspace, "validate_strict_temp_workspace", return_value=ws_dir.resolve()),
        patch.object(workspace.platform, "system", return_value="Darwin"),
        patch.object(workspace.os, "chmod", side_effect=fake_chmod),
    ):
        workspace.ensure_sandbox_readable_workspace(ws_dir, sandbox_uid=10002)

    assert len(chmod_calls) >= 3
    for _, mode in chmod_calls:
        assert (mode & (stat.S_IRWXG | stat.S_IRWXO)) == 0
        assert (mode & stat.S_IRUSR) != 0


def test_resolve_docker_binary_checks_macos_gui_fallbacks():
    """Docker resolution must check macOS GUI locations when PATH omits Docker."""
    expected_mac_docker = "/opt/homebrew/bin/docker"
    with (
        patch.object(sandbox.shutil, "which", return_value=None),
        patch.object(sandbox.platform, "system", return_value="Darwin"),
        patch.object(sandbox.os.path, "isfile", side_effect=lambda p: p == expected_mac_docker),
    ):
        assert sandbox.resolve_docker_binary() == expected_mac_docker

    with patch.object(sandbox.shutil, "which", return_value="/usr/bin/docker"):
        assert sandbox.resolve_docker_binary() == "docker"


def test_prepare_desktop_bundle_excludes_secrets_and_dev_files(tmp_path, monkeypatch):
    """Backend staging must strip .env files, sqlite DBs, tests, caches, and dev metadata."""
    mod = _load_prepare_bundle_module()
    monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)

    src_backend = tmp_path / "backend"
    (src_backend / "app" / "__pycache__").mkdir(parents=True)
    (src_backend / "tests").mkdir(parents=True)
    (src_backend / "data").mkdir(parents=True)
    (src_backend / "app" / "main.py").write_text("app = object()\n", encoding="utf-8")
    (src_backend / "app" / "__pycache__" / "main.cpython-312.pyc").write_bytes(b"pyc")
    (src_backend / "tests" / "test_secret.py").write_text("assert True\n", encoding="utf-8")
    (src_backend / ".env").write_text("SECRET_KEY=dev-secret\n", encoding="utf-8")
    (src_backend / ".env.production").write_text("SECRET_KEY=prod-secret\n", encoding="utf-8")
    (src_backend / "redmercury_desktop.db").write_bytes(b"sqlite")
    (src_backend / "requirements-dev.txt").write_text("pytest\n", encoding="utf-8")
    (src_backend / "data" / "stale.json").write_text("{}", encoding="utf-8")

    dest_backend = tmp_path / "staged_backend"
    mod.prepare_clean_backend(dest_backend)

    assert (dest_backend / "app" / "main.py").exists()
    assert not (dest_backend / ".env").exists()
    assert not (dest_backend / ".env.production").exists()
    assert not (dest_backend / "redmercury_desktop.db").exists()
    assert not (dest_backend / "requirements-dev.txt").exists()
    assert not (dest_backend / "tests").exists()
    assert not (dest_backend / "data").exists()
    assert not (dest_backend / "app" / "__pycache__").exists()


def test_package_json_and_build_resources_integrity():
    """Verify Electron Builder config, macOS entitlements, NSIS script, and notarization hook exist and match Phase 3 targets."""
    pkg = json.loads((REPO_ROOT / "package.json").read_text(encoding="utf-8"))
    build_cfg = pkg["build"]

    assert build_cfg["appId"] == "com.xerova.redmercury"
    assert build_cfg["afterSign"] == "build/notarize.cjs"
    assert build_cfg["nsis"]["artifactName"] == "RedMercury-Setup-${arch}.${ext}"
    assert build_cfg["nsis"]["deleteAppDataOnUninstall"] is False
    assert build_cfg["nsis"]["createDesktopShortcut"] is True
    assert build_cfg["nsis"]["createStartMenuShortcut"] is True

    mac_cfg = build_cfg["mac"]
    assert mac_cfg["artifactName"] == "RedMercury-macOS-${arch}.${ext}"
    assert mac_cfg["hardenedRuntime"] is True
    assert mac_cfg["entitlements"] == "build/entitlements.mac.plist"
    dmg_target = next(t for t in mac_cfg["target"] if t["target"] == "dmg")
    assert set(dmg_target["arch"]) == {"x64", "arm64"}

    extra_targets = {item["to"]: item["from"] for item in build_cfg["extraResources"]}
    assert extra_targets["backend"] == "build/staging/active/backend"
    assert extra_targets["runtime"] == "build/staging/active/runtime"
    assert extra_targets["bin"] == "build/staging/active/bin"

    entitlements = plistlib.loads((REPO_ROOT / "build" / "entitlements.mac.plist").read_bytes())
    assert entitlements["com.apple.security.cs.allow-jit"] is True
    assert entitlements["com.apple.security.network.client"] is True
    assert entitlements["com.apple.security.network.server"] is True

    assert (REPO_ROOT / "build" / "installer.nsh").is_file()
    assert (REPO_ROOT / "build" / "notarize.cjs").is_file()
