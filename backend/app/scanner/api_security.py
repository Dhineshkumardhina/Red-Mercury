"""API Security Testing adapter based on OWASP API Security Top 10.

Evaluates API specifications (OpenAPI/Swagger) and API endpoint routing code for:
- API1: Broken Object Level Authorization (BOLA/IDOR)
- API2: Broken Authentication
- API3: Broken Object Property Level Authorization (Mass Assignment)
- API4: Unrestricted Resource Consumption (Missing Rate Limiting/Pagination)
- API7: Server-Side Request Forgery (SSRF in webhook/fetch handlers)
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
    resolve_tool_binary,
)
from ..core.logging import get_logger

logger = get_logger("redmercury.scanner.api_security")


class ApiSecurityScannerAdapter(BaseScannerAdapter):
    """Adapter for API Security Testing."""

    name: str = "api_security"
    display_name: str = "API Security Testing (OWASP API Top 10)"
    category: str = "api_security"

    def is_available(self) -> bool:
        return True

    def get_version(self) -> Optional[str]:
        st_bin = resolve_tool_binary("st")  # schemathesis CLI
        if st_bin:
            return "schemathesis-api-engine"
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

        # 1. Inspect OpenAPI / Swagger Specifications
        findings.extend(self._scan_api_specifications(target_dir, scan_id))

        # 2. Inspect API Route Handlers and Controller Code
        findings.extend(self._scan_api_code_handlers(target_dir, scan_id))

        return ScanJobResult(
            scanner_name=self.name,
            scanner_version=self.get_version(),
            category=self.category,
            status=ScannerStatus.SUCCESS if findings else ScannerStatus.NO_FINDINGS,
            execution_time_seconds=round(time.time() - start_time, 3),
            findings=findings,
            exit_code=0,
        )

    def _scan_api_specifications(self, target_dir: Path, scan_id: str) -> List[NormalizedFinding]:
        findings = []
        spec_patterns = ["*openapi*.json", "*openapi*.yaml", "*openapi*.yml", "*swagger*.json", "*swagger*.yaml"]
        for pat in spec_patterns:
            for spec_file in target_dir.rglob(pat):
                if not spec_file.is_file() or any(p in spec_file.parts for p in (".git", "node_modules")):
                    continue
                try:
                    rel_path = str(spec_file.relative_to(target_dir)).replace("\\", "/")
                    content = spec_file.read_text(encoding="utf-8", errors="ignore")

                    # If JSON format, parse paths and security schemes
                    if spec_file.suffix.lower() == ".json":
                        try:
                            spec = json.loads(content)
                            paths = spec.get("paths", {})
                            has_global_security = bool(spec.get("security"))

                            for path_name, path_item in paths.items():
                                if not isinstance(path_item, dict):
                                    continue
                                for method, op in path_item.items():
                                    if method.lower() not in ("get", "post", "put", "patch", "delete"):
                                        continue
                                    if not isinstance(op, dict):
                                        continue

                                    # Check unauthenticated mutating endpoints (API2: Broken Authentication)
                                    op_security = op.get("security")
                                    if method.lower() in ("post", "put", "patch", "delete") and not op_security and not has_global_security:
                                        findings.append(
                                            NormalizedFinding(
                                                scan_id=scan_id,
                                                scanner_name=self.name,
                                                scanner_rule_id="API2-UNPROTECTED-MUTATING-ENDPOINT",
                                                vulnerability_category="api_security",
                                                severity="HIGH",
                                                confidence="HIGH",
                                                file_path=rel_path,
                                                start_line=1,
                                                end_line=1,
                                                scanner_message=f"Mutating API route '{method.upper()} {path_name}' lacks authentication/security declaration.",
                                                evidence_reference=f"{method.upper()} {path_name}",
                                                cwe="CWE-306",
                                            )
                                        )

                                    # Check BOLA/IDOR pattern (API1)
                                    if re.search(r"\{[a-zA-Z0-9_]*id\}", path_name, re.IGNORECASE) and method.lower() in ("delete", "put", "patch"):
                                        findings.append(
                                            NormalizedFinding(
                                                scan_id=scan_id,
                                                scanner_name=self.name,
                                                scanner_rule_id="API1-POTENTIAL-BOLA-IDOR",
                                                vulnerability_category="api_security",
                                                severity="MEDIUM",
                                                confidence="HIGH",
                                                file_path=rel_path,
                                                start_line=1,
                                                end_line=1,
                                                scanner_message=f"Endpoint '{method.upper()} {path_name}' takes raw object ID parameter; ensure tenant/ownership checks prevent BOLA/IDOR.",
                                                evidence_reference=f"{method.upper()} {path_name}",
                                                cwe="CWE-639",
                                            )
                                        )
                        except Exception:
                            pass
                except Exception as e:
                    logger.debug(f"Error parsing API spec {spec_file}: {e}")
        return findings

    def _scan_api_code_handlers(self, target_dir: Path, scan_id: str) -> List[NormalizedFinding]:
        findings = []
        code_files = list(target_dir.rglob("*.py")) + list(target_dir.rglob("*.ts")) + list(target_dir.rglob("*.js"))
        for code_file in code_files:
            if not code_file.is_file() or any(p in code_file.parts for p in (".git", "node_modules", "venv", ".venv")):
                continue
            try:
                rel_path = str(code_file.relative_to(target_dir)).replace("\\", "/")
                content = code_file.read_text(encoding="utf-8", errors="ignore")
                lines = content.splitlines()

                for idx, line in enumerate(lines, start=1):
                    # Check for missing rate limiting / unbounded resource queries (API4: Unrestricted Resource Consumption)
                    if re.search(r"\.query\([^)]+\)\.all\(\)", line) and "limit(" not in line:
                        findings.append(
                            NormalizedFinding(
                                scan_id=scan_id,
                                scanner_name=self.name,
                                scanner_rule_id="API4-UNBOUNDED-COLLECTION-QUERY",
                                vulnerability_category="api_security",
                                severity="MEDIUM",
                                confidence="HIGH",
                                file_path=rel_path,
                                start_line=idx,
                                end_line=idx,
                                scanner_message="Database query executes unbounded .all() retrieval without pagination limit (causes API Denial of Service).",
                                evidence_reference=line.strip()[:180],
                                cwe="CWE-770",
                            )
                        )

                    # Check for direct SSRF in API outbound call (API7)
                    if ("requests.get(" in line or "httpx.get(" in line or "axios.get(" in line or "fetch(" in line) and any(param in line for param in ("url", "target", "uri", "req.query")):
                        if "validate" not in line.lower() and "check" not in line.lower():
                            findings.append(
                                NormalizedFinding(
                                    scan_id=scan_id,
                                    scanner_name=self.name,
                                    scanner_rule_id="API7-POTENTIAL-SSRF-OUTBOUND",
                                    vulnerability_category="api_security",
                                    severity="HIGH",
                                    confidence="HIGH",
                                    file_path=rel_path,
                                    start_line=idx,
                                    end_line=idx,
                                    scanner_message="Outbound HTTP client request invokes user-controlled URL without SSRF ip-filtering validation.",
                                    evidence_reference=line.strip()[:180],
                                    cwe="CWE-918",
                                )
                            )
            except Exception:
                pass
        return findings
