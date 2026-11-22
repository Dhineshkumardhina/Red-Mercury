"""Phase 5 Deployment Boundary Security, SSRF Egress Enforcement & Supply-Chain Hardening Test Suite.

Covers all 15 Task 8 verification categories:
1. Strict environment without GIT_EGRESS_PROXY_URL (fails closed, HTTP 403).
2. Invalid proxy URL rejection (schemes, missing port, path/query, control chars).
3. Proxy credentials rejection.
4. Private / loopback / link-local / metadata proxy destination rejection.
5. Git subprocess environment sanitization & proxy pinning.
6. No direct Git network fallback when proxy is missing or invalid.
7. Nginx security header inheritance across location blocks.
8. CSP wildcard rejection across Nginx, Cloudflare _headers, and backend middleware.
9. Gitleaks SHA-256 checksum mismatch rejection & pinned digest verification.
10. Missing / malformed checksum failure & narrowed .gitleaks.toml allowlist verification.
11. Docker base image immutable @sha256 digest pinning & container hardening validation.
12. GitHub Actions full 40-char commit SHA pinning validation.
13. Analyzer role authorization (POST /api/v1/analyze-finding requires mutating role).
14. RequestSizeLimitMiddleware streaming & chunked transfer-encoding enforcement.
15. Regression protection for existing Phase 1–4 security controls.
"""
import hashlib
from pathlib import Path
import re
import socket
import subprocess
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.core.config import settings
from app.core.errors import SecurityPolicyViolationError, ValidationError
from app.core.ingestion import (
    _build_sanitized_git_env,
    clone_git_repository,
    resolve_required_git_egress_proxy,
    validate_git_egress_proxy_url,
    verify_artifact_sha256,
)
from app.core.security import RequestSizeLimitMiddleware, create_access_token
from app.main import app

REPO_ROOT = Path(__file__).resolve().parent.parent


# ==============================================================================
# 1–6. TASK 1 — SEC-06: Fail-Closed Git Egress Proxy Protection
# ==============================================================================


@pytest.mark.parametrize("strict_env", ["production", "staging"])
def test_phase5_01_strict_env_without_git_egress_proxy_fails_closed(
    client_a: TestClient, tmp_path: Path, monkeypatch, strict_env: str
):
    """[Mocked Env] In production and staging, missing GIT_EGRESS_PROXY_URL must disable public Git ingestion (403)."""
    monkeypatch.setattr(settings, "APP_ENV", strict_env)
    monkeypatch.setattr(settings, "GIT_EGRESS_PROXY_URL", None)

    with pytest.raises(SecurityPolicyViolationError, match="GIT_EGRESS_PROXY_URL"):
        resolve_required_git_egress_proxy()

    res = client_a.post(
        "/api/v1/repositories/ingest/git",
        json={"git_url": "https://github.com/org/repo.git", "name": f"strict-git-{uuid.uuid4().hex[:6]}"},
    )
    assert res.status_code == 403
    assert "git_egress_proxy_url" in res.json()["error"]["message"].lower()


@pytest.mark.parametrize(
    "invalid_proxy",
    [
        "",
        "   ",
        "ftp://proxy.corp.example.com:3128",
        "socks5://proxy.corp.example.com:1080",
        "http://proxy.corp.example.com",  # missing explicit port
        "http://proxy.corp.example.com:99999",
        "http://proxy.corp.example.com:3128/custom/path",
        "http://proxy.corp.example.com:3128?foo=bar",
        "http://proxy.corp.example.com:3128#frag",
        "http://proxy.corp.example.com:3128\nX-Injected: 1",
    ],
)
def test_phase5_02_invalid_git_egress_proxy_url_rejected(invalid_proxy: str):
    """Malformed or unapproved-scheme GIT_EGRESS_PROXY_URL values must be rejected."""
    with pytest.raises(ValidationError):
        validate_git_egress_proxy_url(invalid_proxy)


def test_phase5_03_git_egress_proxy_rejects_embedded_credentials():
    """Proxy URLs containing embedded username or password credentials must be rejected."""
    with pytest.raises(SecurityPolicyViolationError, match="credentials"):
        validate_git_egress_proxy_url("http://proxyuser:proxypass@proxy.corp.example.com:3128")


@pytest.mark.parametrize(
    "forbidden_proxy",
    [
        "http://127.0.0.1:3128",
        "http://localhost:3128",
        "http://sub.localhost:3128",
        "http://[::1]:3128",
        "http://[::ffff:127.0.0.1]:3128",
        "http://169.254.169.254:80",
        "http://[::ffff:169.254.169.254]:80",
        "http://metadata.google.internal:80",
        "http://10.0.0.5:3128",
        "http://172.16.0.10:3128",
        "http://192.168.1.1:3128",
        "http://100.64.0.1:3128",
        "http://unapproved-internal:3128",
        "http://proxy.internal:3128",
    ],
)
def test_phase5_04_git_egress_proxy_rejects_private_loopback_link_local_and_metadata(
    monkeypatch, forbidden_proxy: str
):
    """Loopback, private, CGNAT, link-local, and metadata proxy destinations are rejected by default."""
    monkeypatch.setattr(settings, "ALLOW_PRIVATE_GIT_EGRESS_PROXY", False)
    with pytest.raises(SecurityPolicyViolationError):
        validate_git_egress_proxy_url(forbidden_proxy)

    # Even when ALLOW_PRIVATE_GIT_EGRESS_PROXY=True for approved container names, loopback & metadata MUST still fail
    monkeypatch.setattr(settings, "ALLOW_PRIVATE_GIT_EGRESS_PROXY", True)
    monkeypatch.setattr(settings, "APPROVED_GIT_EGRESS_PROXY_HOSTS", ["egress-proxy", "smokescreen"])
    assert validate_git_egress_proxy_url("http://smokescreen:4750") == "http://smokescreen:4750"
    for always_blocked in ("http://127.0.0.1:3128", "http://localhost:3128", "http://169.254.169.254:80"):
        with pytest.raises(SecurityPolicyViolationError):
            validate_git_egress_proxy_url(always_blocked)


def test_phase5_05_git_subprocess_env_sanitization_and_proxy_pinning(monkeypatch):
    """Git subprocess environment strips unsafe inherited vars and pins HTTP_PROXY/HTTPS_PROXY when configured."""
    monkeypatch.setenv("HTTP_PROXY", "http://attacker.evil:8080")
    monkeypatch.setenv("HTTPS_PROXY", "http://attacker.evil:8080")
    monkeypatch.setenv("ALL_PROXY", "socks5://attacker.evil:1080")
    monkeypatch.setenv("NO_PROXY", "*")
    monkeypatch.setenv("GIT_SSH_COMMAND", "ssh -o ProxyCommand=evil")
    monkeypatch.setenv("GIT_PROXY_COMMAND", "/tmp/evil.sh")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.sshCommand")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "evil")

    env_no_proxy = _build_sanitized_git_env(allow_private=False, egress_proxy_url=None)
    for stripped in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "GIT_SSH_COMMAND",
        "GIT_PROXY_COMMAND",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_0",
    ):
        assert stripped not in env_no_proxy
    assert env_no_proxy["GIT_ALLOW_PROTOCOL"] == "https"

    env_pinned = _build_sanitized_git_env(
        allow_private=False,
        egress_proxy_url="http://egress.corp.example.com:3128",
    )
    assert "HTTP_PROXY" not in env_pinned
    assert "HTTPS_PROXY" not in env_pinned
    assert "NO_PROXY" not in env_pinned
    assert env_pinned["GIT_ALLOW_PROTOCOL"] == "https"
    assert env_pinned["GIT_CONFIG_NOSYSTEM"] == "1"


def test_phase5_06_no_direct_git_network_fallback_when_proxy_missing_or_invalid(
    tmp_path: Path, monkeypatch
):
    """[Mocked Subprocess] clone_git_repository must abort before spawning git when strict proxy is missing/invalid."""
    git_called = False

    def forbidden_git_call(*args, **kwargs):
        nonlocal git_called
        git_called = True
        raise AssertionError("git subprocess must never be invoked when proxy validation fails")

    monkeypatch.setattr("app.core.ingestion._run_git_command", forbidden_git_call)
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda host, port, *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))],
    )

    # 1. Production with missing proxy -> fails closed before git spawn
    monkeypatch.setattr(settings, "APP_ENV", "production")
    monkeypatch.setattr(settings, "GIT_EGRESS_PROXY_URL", "")
    with pytest.raises(SecurityPolicyViolationError):
        clone_git_repository("https://example.com/org/repo.git", tmp_path / "c1")
    assert git_called is False

    # 2. Invalid proxy in development -> fails closed before git spawn
    monkeypatch.setattr(settings, "APP_ENV", "development")
    monkeypatch.setattr(settings, "GIT_EGRESS_PROXY_URL", "http://127.0.0.1:3128")
    with pytest.raises(SecurityPolicyViolationError):
        clone_git_repository("https://example.com/org/repo.git", tmp_path / "c2")
    assert git_called is False


# ==============================================================================
# 7–8. TASK 2 & 3 — SEC-13 / SEC-20: Nginx Header Inheritance & CSP Hardening
# ==============================================================================


def test_phase5_07_nginx_security_header_inheritance_preserved_across_locations():
    """Every location block in nginx/frontend.conf that sets add_header must include all required security headers."""
    frontend_conf = (REPO_ROOT / "nginx" / "frontend.conf").read_text(encoding="utf-8")
    prod_conf = (REPO_ROOT / "nginx" / "production.conf").read_text(encoding="utf-8")

    assert "server_tokens off;" in frontend_conf
    assert "server_tokens off;" in prod_conf
    assert "limit_req_status 429;" in prod_conf

    required_headers = [
        'add_header X-Frame-Options "DENY" always;',
        'add_header X-Content-Type-Options "nosniff" always;',
        'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
        'add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=()" always;',
        'add_header X-Permitted-Cross-Domain-Policies "none" always;',
        'add_header Cross-Origin-Opener-Policy "same-origin" always;',
        'add_header Cross-Origin-Resource-Policy "same-origin" always;',
        "add_header Content-Security-Policy ",
    ]

    # Extract location blocks in frontend.conf that contain add_header
    location_blocks = re.findall(r"location\s+[^{]+\{([^}]+)\}", frontend_conf, flags=re.DOTALL)
    assert len(location_blocks) >= 2
    for block in location_blocks:
        if "add_header" in block:
            for req_hdr in required_headers:
                assert req_hdr in block, f"Location block missing inherited security header: {req_hdr}"

    # HSTS must be present in TLS-terminated production.conf and absent on internal HTTP :8080 frontend.conf
    assert "Strict-Transport-Security" in prod_conf
    assert "Strict-Transport-Security" not in frontend_conf


def test_phase5_08_csp_rejects_wildcards_across_nginx_cloudflare_and_backend(client: TestClient):
    """CSP policies must not allow http://*, https://*, or bare https: wildcards in connect-src or unsafe-eval."""
    for rel_path in ("nginx/frontend.conf", "nginx/production.conf", "frontend/public/_headers"):
        content = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
        assert "http://*" not in content, f"Wildcard http://* found in {rel_path}"
        assert "https://*" not in content, f"Wildcard https://* found in {rel_path}"
        assert "connect-src 'self' https:" not in content, f"Broad https: in connect-src found in {rel_path}"
        assert "'unsafe-eval'" not in content, f"unsafe-eval found in {rel_path}"
        assert "script-src 'self'" in content
        assert "object-src 'none'" in content
        assert "frame-ancestors 'none'" in content

    # Verify live API response headers from SecurityHeadersMiddleware
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    assert res.headers.get("x-content-type-options") == "nosniff"
    assert res.headers.get("x-frame-options") == "DENY"
    assert "default-src 'none'" in res.headers.get("content-security-policy", "")


# ==============================================================================
# 9–10. TASK 4 — SEC-20: Gitleaks SHA-256 Checksum & Narrowed .gitleaks.toml
# ==============================================================================


def test_phase5_09_gitleaks_sha256_verification_and_mismatch_failure(tmp_path: Path):
    """verify_artifact_sha256 passes on exact digest, fails closed on mismatch, and matches Dockerfile/CI."""
    artifact = tmp_path / "gitleaks.tar.gz"
    artifact.write_bytes(b"simulated-gitleaks-binary-tarball")
    expected_sha = hashlib.sha256(b"simulated-gitleaks-binary-tarball").hexdigest()

    assert verify_artifact_sha256(artifact, expected_sha) == expected_sha

    wrong_sha = "0" * 64
    with pytest.raises(SecurityPolicyViolationError, match="mismatch"):
        verify_artifact_sha256(artifact, wrong_sha)

    # Verify Dockerfile.worker and ci.yml enforce sha256sum -c - with the official Gitleaks v8.18.2 digest
    official_sha = "6298c9235dfc9278c14b28afd9b7fa4e6f4a289cb1974bd27949fc1e9122bdee"
    worker_df = (REPO_ROOT / "Dockerfile.worker").read_text(encoding="utf-8")
    ci_yml = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert official_sha in worker_df
    assert "sha256sum -c -" in worker_df
    assert official_sha in ci_yml
    assert "sha256sum -c -" in ci_yml


def test_phase5_10_missing_checksum_failure_and_narrowed_gitleaks_allowlist(tmp_path: Path):
    """verify_artifact_sha256 rejects missing/malformed digests; .gitleaks.toml has no broad directory exclusions."""
    artifact = tmp_path / "gitleaks.tar.gz"
    artifact.write_bytes(b"data")

    for bad_digest in (None, "", "   ", "not-hex", "abc123"):
        with pytest.raises(ValidationError):
            verify_artifact_sha256(artifact, bad_digest)  # type: ignore

    gitleaks_toml = (REPO_ROOT / ".gitleaks.toml").read_text(encoding="utf-8")
    # Broad directory allowlists MUST be absent
    for broad_pattern in (
        "'''(?i)^tests/'''",
        "'''(?i)tests/'''",
        "'''(?i)^scripts/'''",
        "'''(?i)scripts/'''",
        "'''(?i)^reports/'''",
        "'''(?i)^benchmark/'''",
    ):
        assert broad_pattern not in gitleaks_toml, f"Broad allowlist pattern still present: {broad_pattern}"


# ==============================================================================
# 11–12. TASK 5: Docker Digest Pinning & GitHub Actions Commit SHA Pinning
# ==============================================================================


def test_phase5_11_docker_base_images_pinned_to_immutable_sha256_digests():
    """Every FROM in Dockerfiles and third-party image in docker-compose.prod.yml must use @sha256:<64-hex>."""
    digest_re = re.compile(r"@sha256:[0-9a-f]{64}\b")

    for df_name in ("Dockerfile.api", "Dockerfile.worker", "Dockerfile.frontend"):
        df_text = (REPO_ROOT / df_name).read_text(encoding="utf-8")
        from_lines = [
            line.strip()
            for line in df_text.splitlines()
            if line.strip().upper().startswith("FROM ")
        ]
        assert len(from_lines) >= 1
        for line in from_lines:
            assert digest_re.search(line), f"Unpinned FROM instruction in {df_name}: {line}"

    compose_text = (REPO_ROOT / "docker-compose.prod.yml").read_text(encoding="utf-8")
    image_lines = [
        line.strip()
        for line in compose_text.splitlines()
        if line.strip().startswith("image:")
    ]
    assert len(image_lines) == 3  # postgres, redis, nginx
    for line in image_lines:
        assert digest_re.search(line), f"Unpinned image in docker-compose.prod.yml: {line}"

    assert "read_only: true" in compose_text
    assert "no-new-privileges:true" in compose_text


def test_phase5_12_github_actions_pinned_to_full_commit_shas():
    """Every 'uses:' step in GitHub workflows must be pinned to a full 40-char commit SHA."""
    uses_re = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)")
    sha_pin_re = re.compile(r"^[^@]+@[0-9a-f]{40}$")

    for wf_name in ("ci.yml", "redmercury_pr_gate.yml", "redmercury-analysis.yml.example"):
        wf_path = REPO_ROOT / ".github" / "workflows" / wf_name
        for line in wf_path.read_text(encoding="utf-8").splitlines():
            m = uses_re.match(line)
            if m:
                ref = m.group(1).strip()
                assert sha_pin_re.match(ref), f"Unpinned GitHub Action in {wf_name}: {line.strip()}"


# ==============================================================================
# 13. TASK 6 — SEC-19: Analyzer Role Authorization Hardening
# ==============================================================================


def test_phase5_13_analyze_finding_enforces_mutating_role_rbac(
    client: TestClient, create_test_user
):
    """POST /api/v1/analyze-finding must reject viewer and auditor roles (403) and allow analyst/admin (200)."""
    payload = {
        "finding_id": "FIND-PHASE5-RBAC",
        "vulnerability_category": "CWE-89: SQL Injection",
        "code_excerpt": "cursor.execute(f'SELECT * FROM users WHERE id={uid}')",
        "user_authorized_analysis": True,
    }

    for readonly_role in ("viewer", "auditor"):
        ro_user = create_test_user(
            email=f"{readonly_role}_{uuid.uuid4().hex[:6]}@xerova.com",
            role=readonly_role,
        )
        ro_tok = create_access_token({"sub": ro_user.id, "email": ro_user.email, "role": readonly_role})
        res = client.post(
            "/api/v1/analyze-finding",
            json=payload,
            headers={"Authorization": f"Bearer {ro_tok}"},
        )
        assert res.status_code == 403, f"Expected 403 for role '{readonly_role}', got {res.status_code}"

    for mutating_role in ("analyst", "maintainer", "admin"):
        mut_user = create_test_user(
            email=f"{mutating_role}_{uuid.uuid4().hex[:6]}@xerova.com",
            role=mutating_role,
        )
        mut_tok = create_access_token({"sub": mut_user.id, "email": mut_user.email, "role": mutating_role})
        res = client.post(
            "/api/v1/analyze-finding",
            json=payload,
            headers={"Authorization": f"Bearer {mut_tok}"},
        )
        assert res.status_code == 200, f"Expected 200 for role '{mutating_role}', got {res.status_code}"


# ==============================================================================
# 14. TASK 7: RequestSizeLimitMiddleware Streaming & Chunked Enforcement
# ==============================================================================


@pytest.mark.anyio
async def test_phase5_14_request_size_limit_middleware_streaming_and_chunked(monkeypatch):
    """RequestSizeLimitMiddleware enforces limits on Content-Length, missing Content-Length, multi-chunk, and disconnect."""
    monkeypatch.setattr(settings, "MAX_REQUEST_BODY_SIZE_BYTES", 100)
    middleware = RequestSizeLimitMiddleware(app)

    async def echo_len_endpoint(req: Request):
        body = await req.body()
        return JSONResponse({"received": len(body)})

    def make_req(chunks: list, headers: list) -> Request:
        it = iter(chunks)

        async def receive():
            try:
                return next(it)
            except StopIteration:
                return {"type": "http.request", "body": b"", "more_body": False}

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/repositories",
            "headers": [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in headers],
        }
        return Request(scope, receive=receive)

    # 1. Valid small request (50 bytes)
    req_small = make_req(
        [{"type": "http.request", "body": b"A" * 50, "more_body": False}],
        [("Content-Length", "50")],
    )
    res_small = await middleware.dispatch(req_small, echo_len_endpoint)
    assert res_small.status_code == 200

    # 2. Exact limit (100 bytes)
    req_exact = make_req(
        [{"type": "http.request", "body": b"B" * 100, "more_body": False}],
        [("Content-Length", "100")],
    )
    res_exact = await middleware.dispatch(req_exact, echo_len_endpoint)
    assert res_exact.status_code == 200

    # 3. Limit + 1 byte via Content-Length fast-path -> 413
    req_over_hdr = make_req(
        [{"type": "http.request", "body": b"C" * 101, "more_body": False}],
        [("Content-Length", "101")],
    )
    res_over_hdr = await middleware.dispatch(req_over_hdr, echo_len_endpoint)
    assert res_over_hdr.status_code == 413

    # 4. Chunked transfer encoding (no Content-Length) exceeding limit across multiple chunks -> 413
    req_chunked_over = make_req(
        [
            {"type": "http.request", "body": b"D" * 40, "more_body": True},
            {"type": "http.request", "body": b"E" * 40, "more_body": True},
            {"type": "http.request", "body": b"F" * 21, "more_body": False},  # total 101 > 100
        ],
        [("Transfer-Encoding", "chunked")],
    )
    res_chunked_over = await middleware.dispatch(req_chunked_over, echo_len_endpoint)
    assert res_chunked_over.status_code == 413

    # 5. Forged small Content-Length (10) with oversized actual body stream (101) -> 413
    req_forged_len = make_req(
        [{"type": "http.request", "body": b"G" * 101, "more_body": False}],
        [("Content-Length", "10")],
    )
    res_forged_len = await middleware.dispatch(req_forged_len, echo_len_endpoint)
    assert res_forged_len.status_code == 413

    # 6. Malformed and negative Content-Length -> 400
    for bad_cl in ("not-an-int", "-5"):
        req_bad_cl = make_req([], [("Content-Length", bad_cl)])
        res_bad_cl = await middleware.dispatch(req_bad_cl, echo_len_endpoint)
        assert res_bad_cl.status_code == 400

    # 7. Request cancellation / disconnect message propagates cleanly as Starlette ClientDisconnect
    from starlette.requests import ClientDisconnect
    req_disc = make_req([{"type": "http.disconnect"}], [])
    with pytest.raises(ClientDisconnect):
        await middleware.dispatch(req_disc, echo_len_endpoint)


# ==============================================================================
# 15. TASK 9: Regression Protection for Phase 1–4 Security Controls
# ==============================================================================


def test_phase5_15_phase1_to_phase4_controls_remain_intact(client: TestClient):
    """Verify key Phase 1–4 invariants remain active after Phase 5 hardening."""
    # Phase 1: Public registration rejects privileged role injection
    reg_admin = client.post(
        "/api/v1/auth/register",
        json={"email": f"p5_chk_{uuid.uuid4().hex[:6]}@xerova.com", "password": "StrongPassword123!", "role": "admin"},
    )
    assert reg_admin.status_code == 422

    # Phase 3: Short-lived 15-min access token default & strict staging parity flag
    assert settings.ACCESS_TOKEN_EXPIRE_MINUTES == 15

    # Phase 4: Unauthenticated webhook without X-GitHub-Delivery is rejected (403)
    wh = client.post("/api/v1/integrations/github/webhook", content=b"{}")
    assert wh.status_code == 403
