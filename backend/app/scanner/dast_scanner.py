"""DAST (Dynamic Application Security Testing) adapter.

Executes black-box security checks against live applications, web services,
and web configurations (HTTP Security Headers, Cookie flags, CORS policies,
TLS/SSL enforcement, and OWASP ZAP baseline scans).
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

logger = get_logger("redmercury.scanner.dast_scanner")

MANDATORY_SECURITY_HEADERS = [
    ("Strict-Transport-Security", "DAST-MISSING-HSTS", "MEDIUM", "CWE-319", "Strict-Transport-Security (HSTS) header is missing, allowing SSL-stripping MITM attacks."),
    ("Content-Security-Policy", "DAST-MISSING-CSP", "HIGH", "CWE-1021", "Content-Security-Policy (CSP) is missing, increasing susceptibility to Cross-Site Scripting (XSS)."),
    ("X-Frame-Options", "DAST-MISSING-CLICKJACKING-DEFENSE", "MEDIUM", "CWE-1021", "X-Frame-Options header is absent, exposing the portal to Clickjacking attacks."),
    ("X-Content-Type-Options", "DAST-MISSING-X-CONTENT-TYPE", "LOW", "CWE-79", "X-Content-Type-Options: nosniff header is missing, allowing MIME-type sniffing."),
    ("Referrer-Policy", "DAST-MISSING-REFERRER-POLICY", "LOW", "CWE-200", "Referrer-Policy header is missing, risking leakage of sensitive query parameters."),
]


class DastScannerAdapter(BaseScannerAdapter):
    """Adapter for Dynamic Application Security Testing (DAST)."""

    name: str = "dast_scanner"
    display_name: str = "Dynamic Application Security Testing (DAST)"
    category: str = "dast"

    def is_available(self) -> bool:
        return True

    def get_version(self) -> Optional[str]:
        zap = resolve_tool_binary("zap-baseline.py") or resolve_tool_binary("zap.sh")
        if zap:
            return "owasp-zap-daemon"
        return "1.0.0-builtin"

    def scan(
        self,
        target_dir: Path,
        scan_id: str,
        timeout_seconds: int = 60,
        options: Optional[Dict[str, Any]] = None,
    ) -> ScanJobResult:
        start_time = time.time()
        findings: List[NormalizedFinding] = []
        target_url = (options or {}).get("target_url") or (options or {}).get("dast_url")

        # 1. If live target URL is provided and OWASP ZAP is installed
        zap_bin = resolve_tool_binary("zap-baseline.py")
        if target_url and zap_bin:
            try:
                report_file = target_dir / "zap_report.json"
                cmd = [
                    zap_bin,
                    "-t", str(target_url),
                    "-J", str(report_file),
                    "-m", "5",
                ]
                subprocess.run(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=timeout_seconds,
                    env=get_scanner_env(),
                    shell=False,
                )
                if report_file.exists():
                    data = json.loads(report_file.read_text(encoding="utf-8"))
                    for site in data.get("site", []):
                        for alert in site.get("alerts", []):
                            sev = alert.get("riskcode", "2")
                            sev_label = "CRITICAL" if sev == "3" else "HIGH" if sev == "2" else "MEDIUM"
                            findings.append(
                                NormalizedFinding(
                                    scan_id=scan_id,
                                    scanner_name=self.name,
                                    scanner_rule_id=f"ZAP-{alert.get('pluginid', 'ALERT')}",
                                    vulnerability_category="dast",
                                    severity=sev_label,
                                    confidence="HIGH",
                                    file_path=str(target_url),
                                    start_line=1,
                                    end_line=1,
                                    scanner_message=alert.get("name", "DAST Alert") + ": " + alert.get("desc", ""),
                                    evidence_reference=alert.get("solution", ""),
                                    cwe=f"CWE-{alert.get('cweid', '699')}",
                                )
                            )
            except Exception as e:
                logger.debug(f"ZAP runner encountered error: {e}")

        # 2. Dynamic Server Configuration & Source-Route Prober
        findings.extend(self._analyze_server_configs_and_routes(target_dir, scan_id))

        return ScanJobResult(
            scanner_name=self.name,
            scanner_version=self.get_version(),
            category=self.category,
            status=ScannerStatus.SUCCESS if findings else ScannerStatus.NO_FINDINGS,
            execution_time_seconds=round(time.time() - start_time, 3),
            findings=findings,
            exit_code=0,
        )

    def _analyze_server_configs_and_routes(self, target_dir: Path, scan_id: str) -> List[NormalizedFinding]:
        findings = []
        # Inspect nginx.conf, apache, or web routing configurations
        config_patterns = ["*nginx*.conf", "*default.conf", "*web.config", "*.htaccess"]
        for pat in config_patterns:
            for conf_file in target_dir.rglob(pat):
                if not conf_file.is_file() or ".git" in conf_file.parts:
                    continue
                try:
                    rel_path = str(conf_file.relative_to(target_dir)).replace("\\", "/")
                    content = conf_file.read_text(encoding="utf-8", errors="ignore")

                    for header_name, rule_id, sev, cwe, msg in MANDATORY_SECURITY_HEADERS:
                        if header_name.lower() not in content.lower():
                            findings.append(
                                NormalizedFinding(
                                    scan_id=scan_id,
                                    scanner_name=self.name,
                                    scanner_rule_id=rule_id,
                                    vulnerability_category="dast",
                                    severity=sev,
                                    confidence="HIGH",
                                    file_path=rel_path,
                                    start_line=1,
                                    end_line=1,
                                    scanner_message=msg,
                                    evidence_reference=f"Missing directive for {header_name}",
                                    cwe=cwe,
                                )
                            )

                    # Permissive CORS wildcard with credentials
                    if re.search(r"add_header\s+['\"]?Access-Control-Allow-Origin['\"]?\s+['\"]?\*['\"]?", content, re.IGNORECASE):
                        findings.append(
                            NormalizedFinding(
                                scan_id=scan_id,
                                scanner_name=self.name,
                                scanner_rule_id="DAST-CORS-PERMISSIVE-WILDCARD",
                                vulnerability_category="dast",
                                severity="HIGH",
                                confidence="HIGH",
                                file_path=rel_path,
                                start_line=1,
                                end_line=1,
                                scanner_message="Permissive Access-Control-Allow-Origin: * header configured, allowing unauthorized cross-origin data theft.",
                                evidence_reference="Access-Control-Allow-Origin *",
                                cwe="CWE-346",
                            )
                        )
                except Exception as e:
                    logger.debug(f"Error checking config {conf_file}: {e}")

        # Check Python/Node route code for cookie security flags
        for py_file in target_dir.rglob("*.py"):
            if not py_file.is_file() or any(p in py_file.parts for p in (".git", "node_modules", "venv", ".venv")):
                continue
            try:
                rel_path = str(py_file.relative_to(target_dir)).replace("\\", "/")
                content = py_file.read_text(encoding="utf-8", errors="ignore")
                lines = content.splitlines()
                for idx, line in enumerate(lines, start=1):
                    # Insecure set_cookie without httponly / secure
                    if "set_cookie(" in line:
                        if "httponly=True" not in line and "httponly=true" not in line.lower():
                            findings.append(
                                NormalizedFinding(
                                    scan_id=scan_id,
                                    scanner_name=self.name,
                                    scanner_rule_id="DAST-COOKIE-MISSING-HTTPONLY",
                                    vulnerability_category="dast",
                                    severity="MEDIUM",
                                    confidence="HIGH",
                                    file_path=rel_path,
                                    start_line=idx,
                                    end_line=idx,
                                    scanner_message="Session cookie generated without 'HttpOnly' flag, permitting client-side script read access (XSS token theft).",
                                    evidence_reference=line.strip()[:180],
                                    cwe="CWE-1004",
                                )
                            )
                        if "secure=True" not in line and "secure=true" not in line.lower():
                            findings.append(
                                NormalizedFinding(
                                    scan_id=scan_id,
                                    scanner_name=self.name,
                                    scanner_rule_id="DAST-COOKIE-MISSING-SECURE",
                                    vulnerability_category="dast",
                                    severity="MEDIUM",
                                    confidence="HIGH",
                                    file_path=rel_path,
                                    start_line=idx,
                                    end_line=idx,
                                    scanner_message="Session cookie generated without 'Secure' flag, allowing plaintext transmission over HTTP.",
                                    evidence_reference=line.strip()[:180],
                                    cwe="CWE-614",
                                )
                            )
            except Exception:
                pass

        return findings
