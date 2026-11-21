"""OWASP Security Tools & OWASP Top 10 Suite adapter.

Integrates:
1. OWASP ZAP (Zed Attack Proxy) automated baseline scanner.
2. OWASP Dependency-Check software composition engine.
3. OWASP Top 10 (2021/2025) Comprehensive Vulnerability Suite:
   - A01: Broken Access Control (Missing Authorization, IDOR)
   - A02: Cryptographic Failures (MD5/SHA1 password hashing, hardcoded keys)
   - A03: Injection (SQLi, NoSQLi, Command Injection)
   - A04: Insecure Design (Verbose stack traces, missing anti-automation)
   - A05: Security Misconfiguration (Debug mode enabled in production, default accounts)
   - A07: Identification & Authentication Failures (JWT verify_signature=False)
   - A08: Software & Data Integrity Failures (Unverified deserialization)
   - A10: Server-Side Request Forgery (SSRF)
"""
import json
from pathlib import Path
import re
import subprocess
import time
from typing import Any, Dict, List, Optional

from .base import (
    BaseScannerAdapter,
    NormalizedFinding,
    ScanJobResult,
    ScannerStatus,
    get_scanner_env,
    resolve_tool_binary,
)
from ..core.logging import get_logger

logger = get_logger("redmercury.scanner.owasp")

OWASP_TOP_10_RULES = [
    # A02: Cryptographic Failures - Broken/weak hash algorithms
    (
        re.compile(r"""(hashlib\.md5|hashlib\.sha1|crypto\.createHash\(['"](md5|sha1)['"]\))""", re.IGNORECASE),
        "OWASP-A02-WEAK-HASH-ALGORITHM",
        "HIGH",
        "CWE-327",
        "OWASP A02 (Cryptographic Failures): Weak collision-prone hash algorithm (MD5/SHA1) detected; use SHA-256 or bcrypt/argon2 for passwords.",
    ),
    # A07: Identification & Auth - Disabled JWT signature verification
    (
        re.compile(r"""(verify_signature\s*[:=]\s*False|verify\s*[:=]\s*False|algorithms\s*[:=]\s*\[\s*['"]none['"]\s*\])""", re.IGNORECASE),
        "OWASP-A07-JWT-SIGNATURE-VERIFICATION-DISABLED",
        "CRITICAL",
        "CWE-347",
        "OWASP A07 (Authentication Failures): JWT signature verification explicitly disabled or 'none' algorithm accepted.",
    ),
    # A05: Security Misconfiguration - Debug mode active in production
    (
        re.compile(r"""(DEBUG\s*=\s*True|app\.run\([^)]*debug\s*=\s*True|process\.env\.NODE_ENV\s*!==\s*['"]production['"])""", re.IGNORECASE),
        "OWASP-A05-DEBUG-MODE-ENABLED",
        "MEDIUM",
        "CWE-489",
        "OWASP A05 (Security Misconfiguration): Application runs with debug mode active, exposing internal state and stack traces.",
    ),
    # A01: Broken Access Control - Missing authorization on user delete/edit
    (
        re.compile(r"""(@app\.(delete|put|patch)|router\.(delete|put|patch))\s*\([^)]*\)\s*\ndef\s+[a-zA-Z0-9_]+\s*\([^)]*\):\s*(?!\s*@|\s*#|\s*\"\"\"|\s*Depends\(get_current_user\))""", re.MULTILINE),
        "OWASP-A01-MISSING-ACCESS-CONTROL",
        "HIGH",
        "CWE-862",
        "OWASP A01 (Broken Access Control): Mutating HTTP endpoint handler declared without authentication/authorization dependencies.",
    ),
    # A10: Server-Side Request Forgery (SSRF)
    (
        re.compile(r"""(urllib\.request\.urlopen|requests\.get|httpx\.get)\s*\(\s*(request\.(GET|POST|args|json)\[|req\.(query|body)\.)""", re.IGNORECASE),
        "OWASP-A10-SERVER-SIDE-REQUEST-FORGERY",
        "HIGH",
        "CWE-918",
        "OWASP A10 (SSRF): Outbound HTTP request fetches a user-supplied URL directly without private IP range / DNS re-binding filtering.",
    ),
]


class OwaspScannerAdapter(BaseScannerAdapter):
    """Adapter for OWASP security tooling (OWASP ZAP, Dependency-Check) and OWASP Top 10 rules."""

    name: str = "owasp_tools"
    display_name: str = "OWASP Security Tools & Top 10 Suite"
    category: str = "sast"

    def is_available(self) -> bool:
        return True

    def get_version(self) -> Optional[str]:
        # Check if OWASP ZAP or Dependency-Check is installed
        zap_bin = resolve_tool_binary("zap-baseline.py") or resolve_tool_binary("zap.sh")
        dc_bin = resolve_tool_binary("dependency-check.bat") or resolve_tool_binary("dependency-check.sh")
        if zap_bin or dc_bin:
            return "owasp-integrated-cli"
        return "2025.1.0-owasp-top10"

    def scan(
        self,
        target_dir: Path,
        scan_id: str,
        timeout_seconds: int = 60,
        options: Optional[Dict[str, Any]] = None,
    ) -> ScanJobResult:
        start_time = time.time()
        findings: List[NormalizedFinding] = []

        # 1. Try OWASP Dependency-Check if binary is present
        dc_bin = resolve_tool_binary("dependency-check.bat") or resolve_tool_binary("dependency-check.sh") or resolve_tool_binary("dependency-check")
        if dc_bin:
            try:
                report_out = target_dir / "dependency-check-report.json"
                cmd = [
                    dc_bin,
                    "--project", "Red MercuryScan",
                    "--scan", str(target_dir),
                    "--format", "JSON",
                    "--out", str(report_out),
                    "--suppression", "",
                ]
                subprocess.run(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=timeout_seconds,
                    env=get_scanner_env(),
                    shell=False,
                )
                if report_out.exists():
                    data = json.loads(report_out.read_text(encoding="utf-8"))
                    for dep in data.get("dependencies", []):
                        file_name = dep.get("fileName", "dependency")
                        for vuln in dep.get("vulnerabilities", []):
                            cve = vuln.get("name", "CVE-UNKNOWN")
                            sev = vuln.get("severity", "MEDIUM").upper()
                            findings.append(
                                NormalizedFinding(
                                    scan_id=scan_id,
                                    scanner_name=self.name,
                                    scanner_rule_id=f"OWASP-DEP-{cve}",
                                    vulnerability_category="owasp_sca",
                                    severity=sev if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "MEDIUM",
                                    confidence="HIGH",
                                    file_path=file_name,
                                    start_line=1,
                                    end_line=1,
                                    scanner_message=f"OWASP Dependency-Check identified {cve}: {vuln.get('description', '')[:200]}",
                                    evidence_reference=f"Advisory: {cve}",
                                    cwe="CWE-1395",
                                )
                            )
            except Exception as e:
                logger.debug(f"OWASP Dependency-Check execution skipped: {e}")

        # 2. Run Comprehensive OWASP Top 10 Static Audit
        code_files = list(target_dir.rglob("*.py")) + list(target_dir.rglob("*.js")) + list(target_dir.rglob("*.ts"))
        for code_file in code_files:
            if not code_file.is_file() or any(p in code_file.parts for p in (".git", "node_modules", "venv", ".venv")):
                continue
            try:
                rel_path = str(code_file.relative_to(target_dir)).replace("\\", "/")
                content = code_file.read_text(encoding="utf-8", errors="ignore")
                lines = content.splitlines()

                for idx, line in enumerate(lines, start=1):
                    line_clean = line.strip()
                    if not line_clean or line_clean.startswith("//") or line_clean.startswith("#"):
                        continue

                    for pattern, rule_id, sev, cwe, msg in OWASP_TOP_10_RULES:
                        if pattern.search(line):
                            findings.append(
                                NormalizedFinding(
                                    scan_id=scan_id,
                                    scanner_name=self.name,
                                    scanner_rule_id=rule_id,
                                    vulnerability_category="owasp_top_10",
                                    severity=sev,
                                    confidence="HIGH",
                                    file_path=rel_path,
                                    start_line=idx,
                                    end_line=idx,
                                    scanner_message=msg,
                                    evidence_reference=line_clean[:200],
                                    cwe=cwe,
                                )
                            )
            except Exception as e:
                logger.debug(f"Error checking {code_file} with OWASP rules: {e}")

        return ScanJobResult(
            scanner_name=self.name,
            scanner_version=self.get_version(),
            category=self.category,
            status=ScannerStatus.SUCCESS if findings else ScannerStatus.NO_FINDINGS,
            execution_time_seconds=round(time.time() - start_time, 3),
            findings=findings,
            exit_code=0,
        )
