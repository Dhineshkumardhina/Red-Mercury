"""Vulnerability & IaC Misconfiguration scanner adapter.

Inspects Infrastructure as Code (IaC) files: Dockerfiles, Docker Compose,
Kubernetes manifests, and Terraform files for structural security flaws and CVEs.
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

logger = get_logger("redmercury.scanner.vuln_scanner")


class VulnScannerAdapter(BaseScannerAdapter):
    """Adapter for Vulnerability & Infrastructure-as-Code (IaC) Scanning."""

    name: str = "vuln_scanner"
    display_name: str = "Vulnerability & IaC Scanner"
    category: str = "vulnerability_scanning"

    def is_available(self) -> bool:
        return True

    def get_version(self) -> Optional[str]:
        bin_path = resolve_tool_binary("trivy")
        if bin_path:
            return "trivy-iac-engine"
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

        # 1. Try Trivy config scanner if available
        bin_path = resolve_tool_binary("trivy")
        if bin_path:
            try:
                cmd = [
                    bin_path,
                    "config",
                    "--format", "json",
                    "--exit-code", "0",
                    "--quiet",
                    str(target_dir),
                ]
                res = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=timeout_seconds,
                    env=get_scanner_env(),
                    shell=False,
                )
                if res.stdout:
                    data = json.loads(res.stdout)
                    for item in data.get("Results", []):
                        target_file = item.get("Target", "infra-config")
                        for misconf in item.get("Misconfigurations", []):
                            rule_id = misconf.get("ID", "IAC-MISCONF")
                            sev = misconf.get("Severity", "MEDIUM").upper()
                            msg = misconf.get("Title", "") + ": " + misconf.get("Description", "")
                            cause = misconf.get("CauseMetadata", {})
                            start_l = cause.get("StartLine", 1)
                            end_l = cause.get("EndLine", 1)

                            findings.append(
                                NormalizedFinding(
                                    scan_id=scan_id,
                                    scanner_name=self.name,
                                    scanner_rule_id=rule_id,
                                    vulnerability_category="vulnerability_scanning",
                                    severity=sev if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "MEDIUM",
                                    confidence="HIGH",
                                    file_path=target_file,
                                    start_line=start_l,
                                    end_line=end_l,
                                    scanner_message=msg[:300],
                                    evidence_reference=misconf.get("Resolution", None),
                                    cwe="CWE-250",
                                )
                            )
            except Exception as e:
                logger.debug(f"Trivy config scanner failed, using builtin IaC analyzer: {e}")

        # 2. Builtin IaC AST & Pattern Analysis
        findings.extend(self._scan_dockerfiles(target_dir, scan_id))
        findings.extend(self._scan_kubernetes_and_compose(target_dir, scan_id))

        return ScanJobResult(
            scanner_name=self.name,
            scanner_version=self.get_version(),
            category=self.category,
            status=ScannerStatus.SUCCESS if findings else ScannerStatus.NO_FINDINGS,
            execution_time_seconds=round(time.time() - start_time, 3),
            findings=findings,
            exit_code=0,
        )

    def _scan_dockerfiles(self, target_dir: Path, scan_id: str) -> List[NormalizedFinding]:
        findings = []
        for df in target_dir.rglob("*Dockerfile*"):
            if not df.is_file() or ".git" in df.parts:
                continue
            try:
                rel_path = str(df.relative_to(target_dir)).replace("\\", "/")
                lines = df.read_text(encoding="utf-8", errors="ignore").splitlines()
                has_user = False
                has_latest_tag = False

                for idx, line in enumerate(lines, start=1):
                    line_clean = line.strip()
                    # Check base image tag
                    if line_clean.upper().startswith("FROM "):
                        image = line_clean.split()[1] if len(line_clean.split()) > 1 else ""
                        if ":" not in image or image.endswith(":latest"):
                            has_latest_tag = True
                            findings.append(
                                NormalizedFinding(
                                    scan_id=scan_id,
                                    scanner_name=self.name,
                                    scanner_rule_id="IAC-DOCKER-UNPINNED-BASE-IMAGE",
                                    vulnerability_category="vulnerability_scanning",
                                    severity="MEDIUM",
                                    confidence="HIGH",
                                    file_path=rel_path,
                                    start_line=idx,
                                    end_line=idx,
                                    scanner_message=f"Base image '{image}' lacks deterministic sha256 or version pin; risks unverified upstream supply chain drift.",
                                    evidence_reference=line_clean,
                                    cwe="CWE-1395",
                                )
                            )

                    # Check non-root user declaration
                    if line_clean.upper().startswith("USER "):
                        user_name = line_clean.split()[1] if len(line_clean.split()) > 1 else ""
                        if user_name not in ("root", "0"):
                            has_user = True

                    # Check sensitive host mount or dangerous permissions
                    if "chmod 777" in line_clean:
                        findings.append(
                            NormalizedFinding(
                                scan_id=scan_id,
                                scanner_name=self.name,
                                scanner_rule_id="IAC-DOCKER-PERMISSIVE-CHMOD",
                                vulnerability_category="vulnerability_scanning",
                                severity="HIGH",
                                confidence="HIGH",
                                file_path=rel_path,
                                start_line=idx,
                                end_line=idx,
                                scanner_message="World-writable directory permissions (chmod 777) detected in container build step.",
                                evidence_reference=line_clean,
                                cwe="CWE-732",
                            )
                        )

                if not has_user and len(lines) > 0:
                    findings.append(
                        NormalizedFinding(
                            scan_id=scan_id,
                            scanner_name=self.name,
                            scanner_rule_id="IAC-DOCKER-ROOT-CONTAINER-EXECUTION",
                            vulnerability_category="vulnerability_scanning",
                            severity="HIGH",
                            confidence="HIGH",
                            file_path=rel_path,
                            start_line=1,
                            end_line=1,
                            scanner_message="Container runs by default as superuser (root). Missing non-root 'USER' specification.",
                            evidence_reference="Default execution user is root",
                            cwe="CWE-250",
                        )
                    )
            except Exception as e:
                logger.debug(f"Error parsing Dockerfile {df}: {e}")
        return findings

    def _scan_kubernetes_and_compose(self, target_dir: Path, scan_id: str) -> List[NormalizedFinding]:
        findings = []
        patterns = ["*compose*.yml", "*compose*.yaml", "*deployment*.yml", "*deployment*.yaml", "*k8s*.yaml"]
        for pat in patterns:
            for file_path in target_dir.rglob(pat):
                if not file_path.is_file() or any(p in file_path.parts for p in (".git", "node_modules")):
                    continue
                try:
                    rel_path = str(file_path.relative_to(target_dir)).replace("\\", "/")
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                    lines = content.splitlines()

                    for idx, line in enumerate(lines, start=1):
                        # Privileged container
                        if re.search(r"privileged\s*:\s*true", line, re.IGNORECASE):
                            findings.append(
                                NormalizedFinding(
                                    scan_id=scan_id,
                                    scanner_name=self.name,
                                    scanner_rule_id="IAC-PRIVILEGED-CONTAINER",
                                    vulnerability_category="vulnerability_scanning",
                                    severity="CRITICAL",
                                    confidence="HIGH",
                                    file_path=rel_path,
                                    start_line=idx,
                                    end_line=idx,
                                    scanner_message="Container configured with 'privileged: true', disabling kernel namespace isolation.",
                                    evidence_reference=line.strip(),
                                    cwe="CWE-250",
                                )
                            )

                        # Docker socket mounting
                        if "/var/run/docker.sock" in line:
                            findings.append(
                                NormalizedFinding(
                                    scan_id=scan_id,
                                    scanner_name=self.name,
                                    scanner_rule_id="IAC-DOCKER-SOCKET-MOUNT",
                                    vulnerability_category="vulnerability_scanning",
                                    severity="CRITICAL",
                                    confidence="HIGH",
                                    file_path=rel_path,
                                    start_line=idx,
                                    end_line=idx,
                                    scanner_message="Exposing the Docker daemon socket '/var/run/docker.sock' allows full host takeover.",
                                    evidence_reference=line.strip(),
                                    cwe="CWE-250",
                                )
                            )
                except Exception as e:
                    logger.debug(f"Error parsing manifest {file_path}: {e}")
        return findings
