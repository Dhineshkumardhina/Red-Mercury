"""Phase 2 Security Regression Test Suite: Repository Ingestion, ZIP Extraction, SSRF & Workspace Cleanup.

Covers:
- SEC-05: Bounded chunked ZIP extraction, path normalization, traversal/absolute/Windows/symlink/duplicate/
          nested-archive/malformed-ZIP rejection, and partial extraction cleanup.
- SEC-06: Git SSRF defense across IPv4/IPv6/IPv4-mapped/CGNAT/metadata/internal hostnames, protocol restrictions,
          DNS rebinding, removal of invalid -c http.resolve, sanitized Git env, optional egress proxy,
          timeout tree-kill & cleanup, post-clone quotas, and worker internal network isolation.
- SEC-15: Workspace deletion & stale cleanup confinement, symlink rejection, prefix-collision immunity,
          cross-tenant deletion prevention, active-workspace protection, and idempotent cleanup.
"""
import io
import os
from pathlib import Path
import socket
import stat
import struct
import subprocess
import time
import uuid
import zipfile
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.errors import SecurityPolicyViolationError, ValidationError
from app.core.ingestion import (
    _build_sanitized_git_env,
    clone_git_repository,
    get_repository_workspace,
    is_ip_blocked,
    validate_and_extract_zip,
    validate_git_url,
)
from app.core.workspace_cleanup import (
    clean_stale_workspaces,
    safe_delete_workspace_dir,
    validate_workspace_deletion_path,
)
from app.models.repository import Repository
from app.models.scan import Scan


def _write_zip(path: Path, entries: list) -> Path:
    """Create a ZIP file from a list of (filename_or_ZipInfo, content_bytes_or_str)."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for entry, content in entries:
            zf.writestr(entry, content)
    return path


# ==============================================================================
# TASK 1 — SEC-05: Secure Bounded ZIP Extraction
# ==============================================================================


def test_sec05_valid_zip_extraction_returns_actual_bytes(tmp_path: Path):
    """Valid ZIP extracts cleanly and reports actual bytes written."""
    zpath = _write_zip(
        tmp_path / "valid.zip",
        [
            ("src/app.py", "print('ok')\n"),
            ("README.md", "# Title\n"),
        ],
    )
    dest = tmp_path / "out"
    count, total_bytes, langs = validate_and_extract_zip(zpath, dest)
    assert count == 2
    assert total_bytes == len("print('ok')\n") + len("# Title\n")
    assert "Python" in langs
    assert (dest / "src" / "app.py").read_text(encoding="utf-8") == "print('ok')\n"


@pytest.mark.parametrize(
    "bad_name",
    [
        "../escape.py",
        "a/../../escape.py",
        "/etc/passwd",
        "\\Windows\\System32\\cmd.exe",
        "..\\..\\windows_escape.py",
        "C:\\Users\\victim\\evil.py",
        "C:evil.py",
        "normal.txt:ads_stream",
        "sub/CON.py",
        "trailing_dot.py.",
    ],
)
def test_sec05_zip_rejects_traversal_absolute_windows_and_unsafe_paths(tmp_path: Path, bad_name: str):
    """ZIP extraction must reject ../, absolute, Windows drive/backslash/ADS, and reserved paths."""
    zpath = _write_zip(tmp_path / "bad.zip", [(bad_name, "evil")])
    dest = tmp_path / "out"
    with pytest.raises(ValidationError):
        validate_and_extract_zip(zpath, dest)
    assert not dest.exists()


def test_sec05_zip_rejects_null_byte_filename_in_archive_header(tmp_path: Path, monkeypatch):
    """ZIP entry whose raw header contains a null byte must be rejected and cleaned up."""
    zpath = _write_zip(tmp_path / "nullbyte.zip", [("safe.py", "x = 1")])
    orig_infolist = zipfile.ZipFile.infolist

    def inject_null_byte(self):
        infos = orig_infolist(self)
        infos[0].filename = "evil\x00.py"
        return infos

    monkeypatch.setattr(zipfile.ZipFile, "infolist", inject_null_byte)
    dest = tmp_path / "out_null"
    with pytest.raises(ValidationError, match="null byte"):
        validate_and_extract_zip(zpath, dest)
    assert not dest.exists()


def test_sec05_zip_rejects_symlink_and_special_node_entries(tmp_path: Path):
    """ZIP entries marked as POSIX symlinks or special device/FIFO nodes must be rejected."""
    # 1. Symlink entry
    sym_info = zipfile.ZipInfo("link_to_etc")
    sym_info.create_system = 3  # Unix
    sym_info.external_attr = (stat.S_IFLNK | 0o777) << 16
    zpath_sym = _write_zip(tmp_path / "sym.zip", [(sym_info, "/etc/passwd")])
    dest_sym = tmp_path / "out_sym"
    with pytest.raises(SecurityPolicyViolationError, match="symbolic link"):
        validate_and_extract_zip(zpath_sym, dest_sym)
    assert not dest_sym.exists()

    # 2. FIFO special node entry
    fifo_info = zipfile.ZipInfo("evil_fifo")
    fifo_info.create_system = 3
    fifo_info.external_attr = (stat.S_IFIFO | 0o600) << 16
    zpath_fifo = _write_zip(tmp_path / "fifo.zip", [(fifo_info, b"")])
    dest_fifo = tmp_path / "out_fifo"
    with pytest.raises(SecurityPolicyViolationError, match="special filesystem node"):
        validate_and_extract_zip(zpath_fifo, dest_fifo)
    assert not dest_fifo.exists()


def test_sec05_zip_rejects_excessive_entry_counts(tmp_path: Path, monkeypatch):
    """ZIP extraction must enforce MAX_FILE_COUNT and clean up."""
    monkeypatch.setattr(settings, "MAX_FILE_COUNT", 3)
    entries = [(f"file_{i}.py", f"x = {i}\n") for i in range(5)]
    zpath = _write_zip(tmp_path / "many.zip", entries)
    dest = tmp_path / "out_many"
    with pytest.raises(ValidationError, match="maximum allowed limit"):
        validate_and_extract_zip(zpath, dest)
    assert not dest.exists()


def test_sec05_zip_rejects_oversized_individual_file_including_forged_header(tmp_path: Path, monkeypatch):
    """Oversized individual files must be rejected based on actual bytes written, even if ZIP header lies."""
    monkeypatch.setattr(settings, "MAX_SINGLE_FILE_BYTES", 512)
    monkeypatch.setattr(settings, "MAX_EXTRACTED_SIZE_BYTES", 1024 * 1024)
    monkeypatch.setattr(settings, "MAX_COMPRESSION_RATIO", 1000.0)

    # 1. Honest header > limit
    zpath = _write_zip(tmp_path / "big.zip", [("big.py", "X" * 1024)])
    dest = tmp_path / "out_big"
    with pytest.raises(ValidationError, match="single-file"):
        validate_and_extract_zip(zpath, dest)
    assert not dest.exists()

    # 2. Forged header claiming file_size=10 while actual decompressed stream yields 1024 bytes
    zpath_small_hdr = _write_zip(tmp_path / "forged_single.zip", [("big.py", "0123456789")])
    monkeypatch.setattr(zipfile.ZipFile, "open", lambda self, member, mode="r": io.BytesIO(b"X" * 1024))

    dest_forged = tmp_path / "out_forged"
    with pytest.raises(ValidationError, match="single-file"):
        validate_and_extract_zip(zpath_small_hdr, dest_forged)
    assert not dest_forged.exists()


def test_sec05_zip_rejects_excessive_cumulative_extracted_size_with_cleanup(tmp_path: Path, monkeypatch):
    """Cumulative actual bytes written exceeding MAX_EXTRACTED_SIZE_BYTES must fail and clean up partial files."""
    monkeypatch.setattr(settings, "MAX_SINGLE_FILE_BYTES", 4096)
    monkeypatch.setattr(settings, "MAX_EXTRACTED_SIZE_BYTES", 2500)
    monkeypatch.setattr(settings, "MAX_COMPRESSION_RATIO", 1000.0)

    # Small headers (10 bytes each) so header pre-check passes, while actual stream yields 1500 bytes per file
    zpath = _write_zip(
        tmp_path / "cumul.zip",
        [
            ("part1.py", "0123456789"),
            ("part2.py", "0123456789"),
        ],
    )
    monkeypatch.setattr(zipfile.ZipFile, "open", lambda self, member, mode="r": io.BytesIO(b"A" * 1500))

    dest = tmp_path / "out_cumul"
    with pytest.raises(ValidationError, match="quota"):
        validate_and_extract_zip(zpath, dest)
    # Partial file part1.py MUST be cleaned up
    assert not dest.exists()


def test_sec05_zip_rejects_malformed_and_corrupted_archives(tmp_path: Path):
    """Malformed/truncated ZIP archives must raise ValidationError (422) and leave no partial directory."""
    # Valid PK magic header followed by garbage bytes
    corrupt = tmp_path / "corrupt.zip"
    corrupt.write_bytes(b"PK\x03\x04" + b"\xff" * 64)
    dest = tmp_path / "out_corrupt"
    with pytest.raises(ValidationError):
        validate_and_extract_zip(corrupt, dest)
    assert not dest.exists()


def test_sec05_zip_rejects_duplicate_filenames(tmp_path: Path):
    """Duplicate normalized filenames (including case variants) must be rejected and cleaned up."""
    zpath = tmp_path / "dup.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("src/app.py", "safe = True\n")
        zf.writestr("src/APP.py", "evil = True\n")
    dest = tmp_path / "out_dup"
    with pytest.raises(ValidationError, match="duplicate"):
        validate_and_extract_zip(zpath, dest)
    assert not dest.exists()


def test_sec05_zip_enforces_nested_archive_limit(tmp_path: Path, monkeypatch):
    """Excessive nested archive entries must be rejected cleanly."""
    monkeypatch.setattr(settings, "MAX_NESTED_ARCHIVES", 2)
    zpath = _write_zip(
        tmp_path / "nested.zip",
        [
            ("a.zip", b"PK\x05\x06" + b"\x00" * 18),
            ("b.tar", b"tar-bytes"),
            ("c.gz", b"gz-bytes"),
        ],
    )
    dest = tmp_path / "out_nested"
    with pytest.raises(ValidationError, match="nested archive"):
        validate_and_extract_zip(zpath, dest)
    assert not dest.exists()


# ==============================================================================
# TASK 2 — SEC-06: SSRF & Git Ingestion Hardening
# ==============================================================================


@pytest.mark.parametrize(
    "blocked_ip",
    [
        "127.0.0.1",
        "127.255.255.254",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.10",
        "100.64.0.1",
        "169.254.169.254",
        "169.254.170.2",
        "0.0.0.0",
        "::1",
        "fc00::1",
        "fd12:3456::1",
        "fe80::1",
        "fd00:ec2::254",
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
        "::ffff:10.0.0.5",
        "::ffff:100.64.0.2",
    ],
)
def test_sec06_is_ip_blocked_covers_all_prohibited_ranges(blocked_ip: str):
    """is_ip_blocked must block loopback, RFC1918, CGNAT, link-local, metadata, IPv6 ULA, and IPv4-mapped IPv6."""
    assert is_ip_blocked(blocked_ip) is True


def test_sec06_is_ip_blocked_allows_public_ips():
    """Public routable IPv4 and IPv6 addresses must be permitted."""
    assert is_ip_blocked("93.184.216.34") is False
    assert is_ip_blocked("140.82.121.4") is False
    assert is_ip_blocked("2606:2800:220:1:248:1893:25c8:1946") is False


@pytest.mark.parametrize(
    "bad_url",
    [
        "file:///etc/passwd",
        "ssh://git@github.com/org/repo.git",
        "git://github.com/org/repo.git",
        "ftp://example.com/repo.git",
        "http://github.com/org/repo.git",
        "ext::sh -c touch /tmp/pwned",
        "/etc/passwd",
        "C:\\Users\\admin\\repo",
        "./relative/repo",
        "https://localhost/repo.git",
        "https://sub.localhost/repo.git",
        "https://metadata.google.internal/computeMetadata/v1/",
        "https://service.internal/repo.git",
        "https://printer.local/repo.git",
        "https://postgres/repo.git",
        "https://[::1]/repo.git",
        "https://[::ffff:169.254.169.254]/repo.git",
        "https://100.64.0.1/repo.git",
    ],
)
def test_sec06_validate_git_url_rejects_prohibited_protocols_paths_and_hosts(bad_url: str):
    """validate_git_url must reject non-HTTPS protocols, local paths, remote-helper syntax, and internal hosts."""
    with pytest.raises((SecurityPolicyViolationError, ValidationError)):
        validate_git_url(bad_url, allow_private=False)


def test_sec06_create_repository_endpoint_validates_git_url(client_a: TestClient):
    """POST /api/v1/repositories must validate optional git_url against SSRF."""
    res = client_a.post(
        "/api/v1/repositories",
        json={
            "name": f"ssrf-create-{uuid.uuid4().hex[:6]}",
            "source_type": "public_git",
            "git_url": "https://169.254.169.254/latest/meta-data/",
        },
    )
    assert res.status_code == 403


def test_sec06_clone_removes_invalid_http_resolve_and_uses_valid_hardened_flags(
    tmp_path: Path, monkeypatch
):
    """clone_git_repository must NOT pass invalid -c http.resolve and must pass valid security flags & sanitized env."""
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda host, port, *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))],
    )
    monkeypatch.setattr(settings, "GIT_EGRESS_PROXY_URL", "http://egress-proxy.corp:3128")
    monkeypatch.setenv("GIT_SSH_COMMAND", "evil_ssh")
    monkeypatch.setenv("HTTP_PROXY", "http://attacker:8080")

    captured = {}

    def fake_run_git(cmd, cwd, env, timeout):
        captured["cmd"] = list(cmd)
        captured["cwd"] = cwd
        captured["env"] = dict(env)
        captured["timeout"] = timeout
        # Simulate cloned file
        dest = Path(cmd[-1])
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "main.py").write_text("print('clean')\n", encoding="utf-8")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr("app.core.ingestion._run_git_command", fake_run_git)

    dest_dir = tmp_path / "repo_clone"
    count, size, langs, branch = clone_git_repository(
        git_url="https://example.com/org/repo.git",
        dest_dir=dest_dir,
        branch="main",
        timeout=30,
    )
    assert count == 1
    assert size > 0
    assert "Python" in langs
    assert branch == "main"

    cmd = captured["cmd"]
    # Invalid http.resolve MUST be absent
    assert not any("http.resolve" in arg for arg in cmd)
    assert not any(".resolve=" in arg for arg in cmd)
    # Valid security flags MUST be present
    assert "protocol.file.allow=never" in cmd
    assert "protocol.allow=never" in cmd
    assert "protocol.https.allow=always" in cmd
    assert "http.followRedirects=false" in cmd
    assert "core.symlinks=false" in cmd
    assert "submodule.recurse=false" in cmd
    assert "--no-recurse-submodules" in cmd
    assert "http.proxy=http://egress-proxy.corp:3128" in cmd

    # Sanitized env MUST strip dangerous overrides and lock GIT_ALLOW_PROTOCOL
    env = captured["env"]
    assert env["GIT_ALLOW_PROTOCOL"] == "https"
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert "GIT_SSH_COMMAND" not in env
    assert "HTTP_PROXY" not in env


def test_sec06_clone_timeout_cleans_up_temp_directory(tmp_path: Path, monkeypatch):
    """Git clone timeout must raise ValidationError and delete partial clone directory."""
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda host, port, *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))],
    )

    def fake_timeout(cmd, cwd, env, timeout):
        dest = Path(cmd[-1])
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "partial.py").write_text("partial", encoding="utf-8")
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=timeout)

    monkeypatch.setattr("app.core.ingestion._run_git_command", fake_timeout)

    dest_dir = tmp_path / "timeout_clone"
    with pytest.raises(ValidationError, match="timed out"):
        clone_git_repository("https://example.com/org/slow.git", dest_dir, timeout=2)
    assert not dest_dir.exists()


def test_sec06_worker_compose_network_is_internal_isolated():
    """docker-compose.prod.yml must isolate worker onto an internal: true network."""
    compose_path = Path(__file__).resolve().parent.parent / "docker-compose.prod.yml"
    text = compose_path.read_text(encoding="utf-8")
    assert "redmercury_worker_isolated:" in text
    assert "internal: true" in text
    worker_block = text[text.index("  worker:"):text.index("  frontend:")]
    assert "redmercury_worker_isolated" in worker_block
    assert "redmercury_internal" not in worker_block


# ==============================================================================
# TASK 3 — SEC-15: Workspace Cleanup & Deletion Safety
# ==============================================================================


def test_sec15_validate_workspace_deletion_rejects_traversal_outside_root_and_prefix_collision(
    tmp_path: Path, monkeypatch
):
    """Workspace deletion validation must reject traversal, outside paths, root itself, and alice/alice2 prefix collision."""
    monkeypatch.setattr(settings, "WORKSPACE_ROOT", str(tmp_path))

    # 1. Traversal '..'
    with pytest.raises(SecurityPolicyViolationError):
        validate_workspace_deletion_path(str(tmp_path / "alice" / ".." / "bob" / "repo1"), owner_id="alice")

    # 2. Outside workspace root
    outside = tmp_path.parent / "outside_dir"
    with pytest.raises(SecurityPolicyViolationError):
        validate_workspace_deletion_path(str(outside), owner_id="alice")

    # 3. Workspace root itself
    with pytest.raises(SecurityPolicyViolationError):
        validate_workspace_deletion_path(str(tmp_path), owner_id="alice")

    # 4. Tenant root itself
    with pytest.raises(SecurityPolicyViolationError):
        validate_workspace_deletion_path(str(tmp_path / "alice"), owner_id="alice")

    # 5. Prefix collision: alice attempting to delete alice2's repo
    alice2_repo = get_repository_workspace("alice2", "repo1")
    with pytest.raises(SecurityPolicyViolationError):
        validate_workspace_deletion_path(str(alice2_repo), owner_id="alice")


def test_sec15_validate_workspace_deletion_rejects_symlink_before_resolve(tmp_path: Path, monkeypatch):
    """Symlink workspace paths must be rejected BEFORE resolve()."""
    monkeypatch.setattr(settings, "WORKSPACE_ROOT", str(tmp_path))
    ws = get_repository_workspace("alice", "repo_sym")
    ws.mkdir(parents=True, exist_ok=True)

    orig_is_symlink = Path.is_symlink

    def fake_is_symlink(self: Path) -> bool:
        if self == ws:
            return True
        return orig_is_symlink(self)

    monkeypatch.setattr(Path, "is_symlink", fake_is_symlink)

    with pytest.raises(SecurityPolicyViolationError, match="symbolic link"):
        validate_workspace_deletion_path(str(ws), owner_id="alice")


def test_sec15_cross_tenant_and_tampered_workspace_deletion_blocked(
    client_a: TestClient,
    client_b: TestClient,
    db_session: Session,
    tmp_path: Path,
    monkeypatch,
):
    """Cross-tenant deletion returns 403; tampered out-of-bounds workspace_path refuses deletion and preserves target."""
    monkeypatch.setattr(settings, "WORKSPACE_ROOT", str(tmp_path / "ws_root"))

    # Create repo owned by Alice
    res = client_a.post(
        "/api/v1/repositories",
        json={"name": f"owned-repo-{uuid.uuid4().hex[:6]}", "source_type": "zip_upload"},
    )
    assert res.status_code == 201
    repo_id = res.json()["id"]
    owner_id = res.json()["owner_id"]

    ws_dir = get_repository_workspace(owner_id, repo_id)
    ws_dir.mkdir(parents=True, exist_ok=True)
    (ws_dir / "code.py").write_text("x = 1\n", encoding="utf-8")

    repo = db_session.query(Repository).filter(Repository.id == repo_id).first()
    repo.workspace_path = str(ws_dir)
    db_session.commit()

    # Bob attempts to delete Alice's repo -> 403 and workspace untouched
    bob_del = client_b.delete(f"/api/v1/repositories/{repo_id}")
    assert bob_del.status_code == 403
    assert ws_dir.exists()

    # Simulate tampered out-of-bounds workspace_path pointing to victim directory outside WORKSPACE_ROOT
    victim_dir = tmp_path / "victim_host_data"
    victim_dir.mkdir()
    (victim_dir / "important.txt").write_text("DO_NOT_DELETE", encoding="utf-8")
    repo.workspace_path = str(victim_dir)
    db_session.commit()

    tampered_del = client_a.delete(f"/api/v1/repositories/{repo_id}")
    assert tampered_del.status_code == 403
    assert (victim_dir / "important.txt").exists()


def test_sec15_active_scan_blocks_workspace_deletion(
    client_a: TestClient, db_session: Session, tmp_path: Path, monkeypatch
):
    """Deleting a repository with an active (running) scan must be rejected and preserve its workspace."""
    monkeypatch.setattr(settings, "WORKSPACE_ROOT", str(tmp_path / "ws_active"))

    res = client_a.post(
        "/api/v1/repositories",
        json={"name": f"active-scan-repo-{uuid.uuid4().hex[:6]}", "source_type": "zip_upload"},
    )
    assert res.status_code == 201
    repo_id = res.json()["id"]
    owner_id = res.json()["owner_id"]

    ws_dir = get_repository_workspace(owner_id, repo_id)
    ws_dir.mkdir(parents=True, exist_ok=True)
    (ws_dir / "app.py").write_text("print('active')\n", encoding="utf-8")

    repo = db_session.query(Repository).filter(Repository.id == repo_id).first()
    repo.workspace_path = str(ws_dir)
    active_scan = Scan(repository_id=repo_id, status="running")
    db_session.add(active_scan)
    db_session.commit()

    del_res = client_a.delete(f"/api/v1/repositories/{repo_id}")
    assert del_res.status_code == 422
    assert "active" in del_res.json()["error"]["message"].lower()
    assert ws_dir.exists()


def test_sec15_clean_stale_workspaces_protects_active_and_purges_orphaned_only(
    db_session: Session, create_test_user, tmp_path: Path, monkeypatch
):
    """clean_stale_workspaces must preserve active repo workspaces and only remove orphaned stale repo folders."""
    ws_root = tmp_path / "workspaces"
    monkeypatch.setattr(settings, "WORKSPACE_ROOT", str(ws_root))

    user = create_test_user(email=f"cleanup_{uuid.uuid4().hex[:6]}@xerova.com", role="analyst")
    active_repo = Repository(
        owner_id=user.id,
        name=f"live-repo-{uuid.uuid4().hex[:6]}",
        source_type="zip_upload",
        is_active=True,
    )
    db_session.add(active_repo)
    db_session.commit()

    active_ws = get_repository_workspace(user.id, active_repo.id)
    active_ws.mkdir(parents=True, exist_ok=True)
    (active_ws / "live.py").write_text("live = True\n", encoding="utf-8")
    active_repo.workspace_path = str(active_ws)
    db_session.commit()

    # Orphaned stale repo folder under same tenant
    orphan_ws = get_repository_workspace(user.id, "orphan-repo-999")
    orphan_ws.mkdir(parents=True, exist_ok=True)
    (orphan_ws / "old.py").write_text("old = True\n", encoding="utf-8")

    # Backdate both folders by 48 hours
    old_ts = time.time() - (48 * 3600)
    os.utime(active_ws.parent, (old_ts, old_ts))
    os.utime(orphan_ws.parent, (old_ts, old_ts))

    summary = clean_stale_workspaces(db=db_session, max_age_hours=24)

    # Active repo workspace MUST remain intact; orphaned repo folder MUST be purged
    assert (active_ws / "live.py").exists()
    assert not orphan_ws.parent.exists()
    assert summary["removed_directories"] >= 1
    assert summary["reclaimed_bytes"] >= len("old = True\n")

    # Idempotent safe deletion on already-missing path
    deleted, reclaimed = safe_delete_workspace_dir(str(orphan_ws), owner_id=user.id)
    assert deleted is False
    assert reclaimed == 0
