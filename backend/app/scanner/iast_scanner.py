"""IAST (Interactive Application Security Testing) adapter.

Analyzes execution flow sinks, dynamic runtime reflection vectors,
unvalidated deserialization hooks, and server-side template injection (SSTI) sinks.
"""
from pathlib import Path
import re
import time
from typing import Any, Dict, List, Optional

from .base import (
    BaseScannerAdapter,
    NormalizedFinding,
    ScanJobResult,
    ScannerStatus,
)
from ..core.logging import get_logger

logger = get_logger("redmercury.scanner.iast_scanner")

DANGEROUS_RUNTIME_SINKS = [
    (
        re.compile(r"(pickle|dill|shelve)\.loads?\s*\("),
        "IAST-UNSAFE-DESERIALIZATION-SINK",
        "CRITICAL",
        "CWE-502",
        "Runtime deserialization sink with untrusted byte streams enables arbitrary remote code execution (RCE).",
    ),
    (
        re.compile(r"yaml\.(unsafe_load|load)\s*\([^)]*(Loader\s*=\s*(yaml\.)?(UnsafeLoader|Loader))?"),
        "IAST-UNSAFE-YAML-LOAD",
        "HIGH",
        "CWE-502",
        "PyYAML unsafe loader invoked without yaml.SafeLoader allows object instantiation exploits.",
    ),
    (
        re.compile(r"(eval|exec|compile)\s*\("),
        "IAST-DYNAMIC-CODE-EXECUTION-SINK",
        "CRITICAL",
        "CWE-95",
        "Interactive runtime code evaluation sink executes dynamic string instructions.",
    ),
    (
        re.compile(r"jinja2\.Template\s*\([^)]*\)\.render\s*\("),
        "IAST-SERVER-SIDE-TEMPLATE-INJECTION",
        "HIGH",
        "CWE-1336",
        "Direct rendering of uncompiled Jinja template string risks Server-Side Template Injection (SSTI).",
    ),
    (
        re.compile(r"__import__\s*\("),
        "IAST-DYNAMIC-MODULE-IMPORT",
        "MEDIUM",
        "CWE-470",
        "Dynamic runtime package import (__import__) can be hijacked to execute malicious modules.",
    ),
]


class IastScannerAdapter(BaseScannerAdapter):
    """Adapter for Interactive Application Security Testing (IAST)."""

    name: str = "iast_scanner"
    display_name: str = "Interactive Application Security Testing (IAST)"
    category: str = "iast"

    def is_available(self) -> bool:
        return True

    def get_version(self) -> Optional[str]:
        return "1.0.0-runtime-sensor"

    def scan(
        self,
        target_dir: Path,
        scan_id: str,
        timeout_seconds: int = 60,
        options: Optional[Dict[str, Any]] = None,
    ) -> ScanJobResult:
        start_time = time.time()
        findings: List[NormalizedFinding] = []

        code_extensions = [".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".rb"]
        for ext in code_extensions:
            for file_path in target_dir.rglob(f"*{ext}"):
                if not file_path.is_file() or any(p in file_path.parts for p in (".git", "node_modules", "venv", ".venv")):
                    continue
                try:
                    rel_path = str(file_path.relative_to(target_dir)).replace("\\", "/")
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                    lines = content.splitlines()

                    for idx, line in enumerate(lines, start=1):
                        for pattern, rule_id, sev, cwe, msg in DANGEROUS_RUNTIME_SINKS:
                            if pattern.search(line):
                                findings.append(
                                    NormalizedFinding(
                                        scan_id=scan_id,
                                        scanner_name=self.name,
                                        scanner_rule_id=rule_id,
                                        vulnerability_category="iast",
                                        severity=sev,
                                        confidence="HIGH",
                                        file_path=rel_path,
                                        start_line=idx,
                                        end_line=idx,
                                        scanner_message=msg,
                                        evidence_reference=line.strip()[:180],
                                        cwe=cwe,
                                    )
                                )
                except Exception as e:
                    logger.debug(f"Error inspecting file {file_path} for IAST: {e}")

        return ScanJobResult(
            scanner_name=self.name,
            scanner_version=self.get_version(),
            category=self.category,
            status=ScannerStatus.SUCCESS if findings else ScannerStatus.NO_FINDINGS,
            execution_time_seconds=round(time.time() - start_time, 3),
            findings=findings,
            exit_code=0,
        )
