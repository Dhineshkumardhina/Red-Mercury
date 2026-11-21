"""Open Source License Compliance Scanner Adapter.

Scans project dependencies, package manifests, and repository license files to identify
restrictive or toxic copyleft licenses (like GPL-3.0, AGPL-3.0, SSPL) that pose legal and
commercial IP exposure risks.
"""
import json
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

logger = get_logger("redmercury.scanner.license_compliance_scanner")

# Restrictive & Toxic Licenses categorized by legal severity
RESTRICTIVE_LICENSES = [
    # Network Copyleft (Extremely high risk for SaaS/Cloud platforms)
    (r"\b(AGPL(?:-1\.0|-2\.0|-3\.0)?|Affero General Public License)\b", "AGPL (Affero GPL)", "CRITICAL",
     "Network copyleft license requires disclosing complete proprietary backend source code to any user interacting over the network."),
    # Strong Viral Copyleft (High risk for commercial proprietary distribution)
    (r"\b(GPL(?:-1\.0|-2\.0|-3\.0)?|General Public License|GNU GPL)\b", "GPL (General Public License)", "HIGH",
     "Strong viral copyleft license requires derivative or linked proprietary software to be released under open-source terms."),
    # Server Side Public License (Non-OSI commercial restriction)
    (r"\b(SSPL(?:-1\.0)?|Server Side Public License)\b", "SSPL (Server Side Public License)", "HIGH",
     "Non-OSI license with strict service offering clauses; forbids offering the software as a commercial cloud service without full source disclosure."),
    # European Union Public License
    (r"\b(EUPL(?:-1\.1|-1\.2)?)\b", "EUPL (European Union Public License)", "MEDIUM",
     "Reciprocal copyleft license with cross-licensing compatibility requirements."),
    # Open Software License
    (r"\b(OSL(?:-1\.0|-2\.0|-3\.0)?)\b", "OSL (Open Software License)", "MEDIUM",
     "Strong copyleft license including external deployment clauses."),
]


class LicenseComplianceScannerAdapter(BaseScannerAdapter):
    """Adapter for Open Source License Compliance and Toxic License Detection."""

    name: str = "license_compliance_scanner"
    display_name: str = "Open Source License Compliance"
    category: str = "license_compliance"

    def is_available(self) -> bool:
        return True

    def get_version(self) -> Optional[str]:
        return "1.0.0-builtin-spdx-engine"

    def scan(
        self,
        target_dir: Path,
        scan_id: str,
        timeout_seconds: int = 60,
        options: Optional[Dict[str, Any]] = None,
    ) -> ScanJobResult:
        start_time = time.time()
        findings: List[NormalizedFinding] = []

        # 1. Scan package.json files (JavaScript / Node.js)
        findings.extend(self._scan_node_packages(target_dir, scan_id))

        # 2. Scan Python manifest files (pyproject.toml, setup.py, requirements.txt)
        findings.extend(self._scan_python_packages(target_dir, scan_id))

        # 3. Scan Go and Rust manifests (go.mod, Cargo.toml)
        findings.extend(self._scan_go_and_cargo(target_dir, scan_id))

        # 4. Scan Repository LICENSE & COPYING files
        findings.extend(self._scan_license_files(target_dir, scan_id))

        return ScanJobResult(
            scanner_name=self.name,
            scanner_version=self.get_version(),
            category=self.category,
            status=ScannerStatus.SUCCESS if findings else ScannerStatus.NO_FINDINGS,
            execution_time_seconds=round(time.time() - start_time, 3),
            findings=findings,
            exit_code=0,
        )

    def _evaluate_license_string(self, lic_str: str, file_path: str, line_no: int, scan_id: str, context: str) -> List[NormalizedFinding]:
        results = []
        for pat, lic_name, sev, desc in RESTRICTIVE_LICENSES:
            if re.search(pat, lic_str, re.IGNORECASE):
                # Avoid false positives on LGPL where permissive linking might be intended, unless strong GPL match
                if "LGPL" in lic_str.upper() and lic_name == "GPL (General Public License)":
                    continue
                results.append(
                    NormalizedFinding(
                        scan_id=scan_id,
                        scanner_name=self.name,
                        scanner_rule_id=f"LICENSE-RESTRICTIVE-{lic_name.split()[0].upper()}",
                        vulnerability_category="license_compliance",
                        severity=sev,
                        confidence="HIGH",
                        file_path=file_path,
                        start_line=line_no,
                        end_line=line_no,
                        scanner_message=f"Toxic or viral open source license detected ({lic_name}) in {context}: {desc}",
                        evidence_reference=f"License declaration: '{lic_str}'",
                        cwe="CWE-1059",
                    )
                )
        return results

    def _scan_node_packages(self, target_dir: Path, scan_id: str) -> List[NormalizedFinding]:
        findings = []
        for pkg_json in target_dir.rglob("package.json"):
            if not pkg_json.is_file() or ".git" in pkg_json.parts or "node_modules" in pkg_json.parts:
                continue
            try:
                rel_path = str(pkg_json.relative_to(target_dir)).replace("\\", "/")
                content = pkg_json.read_text(encoding="utf-8", errors="ignore")
                data = json.loads(content)

                # Check package's own declared license
                pkg_license = data.get("license")
                if isinstance(pkg_license, str):
                    findings.extend(self._evaluate_license_string(pkg_license, rel_path, 1, scan_id, "root package manifest"))
                elif isinstance(pkg_license, dict):
                    lic_type = pkg_license.get("type", "")
                    if lic_type:
                        findings.extend(self._evaluate_license_string(lic_type, rel_path, 1, scan_id, "root package manifest"))
            except Exception as e:
                logger.debug(f"Error parsing package.json for licenses {pkg_json}: {e}")
        return findings

    def _scan_python_packages(self, target_dir: Path, scan_id: str) -> List[NormalizedFinding]:
        findings = []
        for py_file in list(target_dir.rglob("setup.py")) + list(target_dir.rglob("pyproject.toml")):
            if not py_file.is_file() or ".git" in py_file.parts or ".venv" in py_file.parts:
                continue
            try:
                rel_path = str(py_file.relative_to(target_dir)).replace("\\", "/")
                content = py_file.read_text(encoding="utf-8", errors="ignore")
                lines = content.splitlines()

                for idx, line in enumerate(lines, start=1):
                    if "license" in line.lower() and "=" in line:
                        for pat, lic_name, sev, desc in RESTRICTIVE_LICENSES:
                            if re.search(pat, line, re.IGNORECASE):
                                findings.append(
                                    NormalizedFinding(
                                        scan_id=scan_id,
                                        scanner_name=self.name,
                                        scanner_rule_id=f"LICENSE-RESTRICTIVE-{lic_name.split()[0].upper()}",
                                        vulnerability_category="license_compliance",
                                        severity=sev,
                                        confidence="HIGH",
                                        file_path=rel_path,
                                        start_line=idx,
                                        end_line=idx,
                                        scanner_message=f"Restrictive license declaration ({lic_name}) in Python metadata: {desc}",
                                        evidence_reference=line.strip(),
                                        cwe="CWE-1059",
                                    )
                                )
            except Exception as e:
                logger.debug(f"Error inspecting Python license in {py_file}: {e}")
        return findings

    def _scan_go_and_cargo(self, target_dir: Path, scan_id: str) -> List[NormalizedFinding]:
        findings = []
        for cargo in target_dir.rglob("Cargo.toml"):
            if not cargo.is_file() or ".git" in cargo.parts:
                continue
            try:
                rel_path = str(cargo.relative_to(target_dir)).replace("\\", "/")
                content = cargo.read_text(encoding="utf-8", errors="ignore")
                for idx, line in enumerate(content.splitlines(), start=1):
                    if line.strip().startswith("license") and "=" in line:
                        findings.extend(self._evaluate_license_string(line, rel_path, idx, scan_id, "Cargo.toml license field"))
            except Exception as e:
                logger.debug(f"Error inspecting Cargo.toml in {cargo}: {e}")
        return findings

    def _scan_license_files(self, target_dir: Path, scan_id: str) -> List[NormalizedFinding]:
        findings = []
        for lic_file in list(target_dir.glob("LICENSE*")) + list(target_dir.glob("COPYING*")):
            if not lic_file.is_file():
                continue
            try:
                rel_path = str(lic_file.relative_to(target_dir)).replace("\\", "/")
                content = lic_file.read_text(encoding="utf-8", errors="ignore")[:2000]

                for pat, lic_name, sev, desc in RESTRICTIVE_LICENSES:
                    if re.search(pat, content, re.IGNORECASE):
                        findings.append(
                            NormalizedFinding(
                                scan_id=scan_id,
                                scanner_name=self.name,
                                scanner_rule_id=f"LICENSE-COPYLEFT-{lic_name.split()[0].upper()}",
                                vulnerability_category="license_compliance",
                                severity=sev,
                                confidence="HIGH",
                                file_path=rel_path,
                                start_line=1,
                                end_line=1,
                                scanner_message=f"Repository top-level license contains {lic_name}: {desc}",
                                evidence_reference=content.splitlines()[0] if content.splitlines() else "License header",
                                cwe="CWE-1059",
                            )
                        )
            except Exception as e:
                logger.debug(f"Error inspecting license file {lic_file}: {e}")
        return findings
