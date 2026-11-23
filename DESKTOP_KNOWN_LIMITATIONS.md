# Red Mercury Desktop — Known Limitations

**Version:** `1.0.0` Desktop  
**Updated:** 2026-11-23  

---

## 1. Platform & Release Status Limitations

1. **macOS Installers Not Yet Executed on Apple Hardware:**
   - `RedMercury-macOS-x64.dmg` and `RedMercury-macOS-arm64.dmg` build pipelines and packaging configuration are complete, **but live DMG builds, Keychain prompts, and Docker Desktop execution have NOT yet been run on physical Intel or Apple Silicon macOS hardware or CI runners.**
2. **Windows 10 `x64` Not Tested on Live OS Hardware:**
   - Windows installer validation ran on **Windows 11 `x64` (`10.0.26300`)**. Behavior on Windows 10 `x64` is inferred from compatible Electron `45.0.0` / Python `3.12` targets but not executed on a Windows 10 host.
3. **Unsigned Distribution Artifacts (`NotSigned`):**
   - Local Windows installers are `NotSigned` (Authenticode `WIN_CSC_LINK` not supplied), triggering Windows Defender SmartScreen warnings.
   - macOS bundles lack Developer ID signing & Apple notarization (`MAC_CSC_LINK` / `APPLE_*` secrets not configured), triggering Gatekeeper prompts until signed in CI.

## 2. Offline & AI Capability Limitations

4. **External Cloud AI Unavailable in Offline Mode:**
   - Desktop installs default to `OFFLINE_MODE=true`. Requests to the Security Analyzer use Red Mercury's local deterministic rule engine (`redmercury-deterministic-fallback-v1.0`) unless online mode and a valid `GEMINI_API_KEY` are explicitly configured.
5. **GitHub Integrations Disabled in Offline Mode:**
   - Remote HTTPS repository cloning, GitHub PR comment publishing, and webhook synchronization require internet connectivity and are blocked in desktop Offline Mode. Local folder ingestion and ZIP archive uploads remain fully functional offline.

## 3. Docker Verification & Scanner Limitations

6. **Docker Desktop Required for Container Fix Verification:**
   - Isolated patch verification requires Docker Desktop running with **Linux containers** (WSL2 backend on Windows; Docker Desktop VM on macOS).
   - If Docker Desktop is absent or stopped (including Windows-container mode `OSType=windows`), fix verification strictly **fails closed** and reports `INCONCLUSIVE` rather than bypassing isolation.
   - Live Linux container execution was skipped on the Windows test workstation because Docker Desktop's WSL2 daemon was stopped during testing.
7. **Semgrep Unavailable on Windows Builds:**
   - Upstream `semgrep` does not support native Windows (`sys_platform != "win32"` in `backend/requirements.txt`). Windows desktop scans use `gitleaks`, `bandit`, `pip-audit`, and Red Mercury's secret detector; `semgrep` is bundled on macOS builds and inside the Linux Docker verification worker image.
8. **Auto-Updater Inactive Until Signed:**
   - Automatic background updates are intentionally inactive (`electron-updater` not enabled) and gated behind `verifyUpdateManifestSignature()` requiring signed builds and Ed25519 manifest signatures.
9. **Local Desktop Auth Multi-User Caveat:**
   - While database models enforce tenant isolation (`owner_id`), a single Windows DPAPI / macOS Keychain profile shares the local `userData` directory (`%APPDATA%\red-mercury` or `~/Library/Application Support/red-mercury`). Each OS login account receives its own isolated desktop data & key storage.
10. **Independent Security Assessment Pending:**
    - Automated security tests and internal engineering audits do not replace an independent third-party VAPT prior to commercial GA release.
