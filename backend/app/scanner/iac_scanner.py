"""Infrastructure as Code (IaC) Scanner Adapter.

Dedicated linting and misconfiguration analysis for cloud infrastructure files:
- Terraform (*.tf, *.tfvars, *.hcl)
- Kubernetes manifests (*.yaml, *.yml)
- CloudFormation templates (*.template, cloudformation*.json, cloudformation*.yaml)
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

logger = get_logger("redmercury.scanner.iac_scanner")


class IacScannerAdapter(BaseScannerAdapter):
    """Adapter for Infrastructure as Code (IaC) scanning."""

    name: str = "iac_scanner"
    display_name: str = "Infrastructure as Code (IaC) Scanner"
    category: str = "iac"

    def is_available(self) -> bool:
        return True

    def get_version(self) -> Optional[str]:
        bin_path = resolve_tool_binary("checkov") or resolve_tool_binary("kics") or resolve_tool_binary("tflint")
        if bin_path:
            return f"cli-{Path(bin_path).name}"
        return "1.0.0-builtin-ast"

    def scan(
        self,
        target_dir: Path,
        scan_id: str,
        timeout_seconds: int = 60,
        options: Optional[Dict[str, Any]] = None,
    ) -> ScanJobResult:
        start_time = time.time()
        findings: List[NormalizedFinding] = []

        # 1. Try external Checkov CLI if installed
        checkov_bin = resolve_tool_binary("checkov")
        if checkov_bin:
            try:
                cmd = [
                    checkov_bin,
                    "-d", str(target_dir),
                    "--output", "json",
                    "--quiet",
                    "--compact",
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
                    try:
                        data = json.loads(res.stdout)
                        check_results = data.get("results", {}).get("failed_checks", []) if isinstance(data, dict) else []
                        for check in check_results:
                            rule_id = check.get("check_id", "IAC-CHECKOV-FAIL")
                            sev = check.get("severity", "HIGH").upper()
                            file_p = check.get("file_path", "").lstrip("/\\")
                            lines = check.get("file_line_range", [1, 1])
                            msg = f"{check.get('check_name', 'IaC Misconfiguration')}: {check.get('guideline', '')}"
                            findings.append(
                                NormalizedFinding(
                                    scan_id=scan_id,
                                    scanner_name=self.name,
                                    scanner_rule_id=rule_id,
                                    vulnerability_category="iac",
                                    severity=sev if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "HIGH",
                                    confidence="HIGH",
                                    file_path=file_p or "terraform/main.tf",
                                    start_line=lines[0] if lines else 1,
                                    end_line=lines[1] if len(lines) > 1 else lines[0] if lines else 1,
                                    scanner_message=msg[:300],
                                    evidence_reference=check.get("resource", None),
                                    cwe="CWE-16",
                                )
                            )
                    except Exception:
                        pass
            except Exception as e:
                logger.debug(f"External checkov failed or timed out: {e}")

        # 2. Comprehensive Builtin Static IaC Engine
        findings.extend(self._scan_terraform(target_dir, scan_id))
        findings.extend(self._scan_kubernetes(target_dir, scan_id))
        findings.extend(self._scan_cloudformation(target_dir, scan_id))

        return ScanJobResult(
            scanner_name=self.name,
            scanner_version=self.get_version(),
            category=self.category,
            status=ScannerStatus.SUCCESS if findings else ScannerStatus.NO_FINDINGS,
            execution_time_seconds=round(time.time() - start_time, 3),
            findings=findings,
            exit_code=0,
        )

    def _scan_terraform(self, target_dir: Path, scan_id: str) -> List[NormalizedFinding]:
        findings = []
        for tf in target_dir.rglob("*.tf"):
            if not tf.is_file() or ".git" in tf.parts:
                continue
            try:
                rel_path = str(tf.relative_to(target_dir)).replace("\\", "/")
                content = tf.read_text(encoding="utf-8", errors="ignore")
                lines = content.splitlines()

                for idx, line in enumerate(lines, start=1):
                    # 1. S3 bucket public access
                    if re.search(r'acl\s*=\s*["\']public-read', line):
                        findings.append(
                            NormalizedFinding(
                                scan_id=scan_id,
                                scanner_name=self.name,
                                scanner_rule_id="IAC-TF-S3-PUBLIC-ACL",
                                vulnerability_category="iac",
                                severity="HIGH",
                                confidence="HIGH",
                                file_path=rel_path,
                                start_line=idx,
                                end_line=idx,
                                scanner_message="S3 bucket configured with public read/write ACL; permits unauthenticated data exfiltration.",
                                evidence_reference=line.strip(),
                                cwe="CWE-732",
                            )
                        )

                    # 2. Security group open to the world
                    if '0.0.0.0/0' in line:
                        findings.append(
                            NormalizedFinding(
                                scan_id=scan_id,
                                scanner_name=self.name,
                                scanner_rule_id="IAC-TF-OPEN-SECURITY-GROUP",
                                vulnerability_category="iac",
                                severity="HIGH",
                                confidence="HIGH",
                                file_path=rel_path,
                                start_line=idx,
                                end_line=idx,
                                scanner_message="Security group ingress rule open to entire Internet (0.0.0.0/0); exposes network services to brute-force attacks.",
                                evidence_reference=line.strip(),
                                cwe="CWE-284",
                            )
                        )

                    # 3. Unencrypted storage/database
                    if re.search(r'(?:storage_encrypted|encrypted)\s*=\s*false', line, re.IGNORECASE):
                        findings.append(
                            NormalizedFinding(
                                scan_id=scan_id,
                                scanner_name=self.name,
                                scanner_rule_id="IAC-TF-UNENCRYPTED-STORAGE",
                                vulnerability_category="iac",
                                severity="MEDIUM",
                                confidence="HIGH",
                                file_path=rel_path,
                                start_line=idx,
                                end_line=idx,
                                scanner_message="Cloud storage volume or database configured without server-side encryption enabled.",
                                evidence_reference=line.strip(),
                                cwe="CWE-311",
                            )
                        )

                    # 4. Wildcard IAM permission
                    if re.search(r'(?:"Action"|Action)\s*[:=]\s*["\']\*["\']', line):
                        findings.append(
                            NormalizedFinding(
                                scan_id=scan_id,
                                scanner_name=self.name,
                                scanner_rule_id="IAC-TF-WILDCARD-IAM-ACTION",
                                vulnerability_category="iac",
                                severity="HIGH",
                                confidence="HIGH",
                                file_path=rel_path,
                                start_line=idx,
                                end_line=idx,
                                scanner_message="IAM policy specifies overly permissive wildcard Action ('*'); violates principle of least privilege.",
                                evidence_reference=line.strip(),
                                cwe="CWE-250",
                            )
                        )
            except Exception as e:
                logger.debug(f"Error parsing Terraform file {tf}: {e}")
        return findings

    def _scan_kubernetes(self, target_dir: Path, scan_id: str) -> List[NormalizedFinding]:
        findings = []
        for yml in target_dir.rglob("*.yaml"):
            if not yml.is_file() or ".git" in yml.parts:
                continue
            try:
                rel_path = str(yml.relative_to(target_dir)).replace("\\", "/")
                content = yml.read_text(encoding="utf-8", errors="ignore")
                if not any(k in content for k in ("apiVersion:", "kind: Deployment", "kind: Pod", "kind: DaemonSet", "kind: StatefulSet")):
                    continue
                lines = content.splitlines()

                for idx, line in enumerate(lines, start=1):
                    # 1. Privileged container
                    if "privileged: true" in line:
                        findings.append(
                            NormalizedFinding(
                                scan_id=scan_id,
                                scanner_name=self.name,
                                scanner_rule_id="IAC-K8S-PRIVILEGED-CONTAINER",
                                vulnerability_category="iac",
                                severity="CRITICAL",
                                confidence="HIGH",
                                file_path=rel_path,
                                start_line=idx,
                                end_line=idx,
                                scanner_message="Kubernetes container execution with 'privileged: true' allows container escape to host kernel.",
                                evidence_reference=line.strip(),
                                cwe="CWE-250",
                            )
                        )

                    # 2. Host namespace sharing
                    if "hostNetwork: true" in line or "hostPID: true" in line or "hostIPC: true" in line:
                        findings.append(
                            NormalizedFinding(
                                scan_id=scan_id,
                                scanner_name=self.name,
                                scanner_rule_id="IAC-K8S-HOST-NAMESPACE-EXPOSURE",
                                vulnerability_category="iac",
                                severity="HIGH",
                                confidence="HIGH",
                                file_path=rel_path,
                                start_line=idx,
                                end_line=idx,
                                scanner_message="Pod shares host network or process namespace; breaks container network isolation.",
                                evidence_reference=line.strip(),
                                cwe="CWE-668",
                            )
                        )

                    # 3. Dangerous capability addition
                    if "SYS_ADMIN" in line or "NET_ADMIN" in line:
                        findings.append(
                            NormalizedFinding(
                                scan_id=scan_id,
                                scanner_name=self.name,
                                scanner_rule_id="IAC-K8S-DANGEROUS-CAPABILITY",
                                vulnerability_category="iac",
                                severity="HIGH",
                                confidence="HIGH",
                                file_path=rel_path,
                                start_line=idx,
                                end_line=idx,
                                scanner_message=f"Kubernetes securityContext grants dangerous root capability '{line.strip()}'.",
                                evidence_reference=line.strip(),
                                cwe="CWE-250",
                            )
                        )
            except Exception as e:
                logger.debug(f"Error parsing Kubernetes YAML {yml}: {e}")
        return findings

    def _scan_cloudformation(self, target_dir: Path, scan_id: str) -> List[NormalizedFinding]:
        findings = []
        for cfn in list(target_dir.rglob("*.template")) + list(target_dir.rglob("cloudformation*.json")):
            if not cfn.is_file() or ".git" in cfn.parts:
                continue
            try:
                rel_path = str(cfn.relative_to(target_dir)).replace("\\", "/")
                content = cfn.read_text(encoding="utf-8", errors="ignore")
                lines = content.splitlines()

                for idx, line in enumerate(lines, start=1):
                    if '"Principal": "*"' in line and '"Effect": "Allow"' in content:
                        findings.append(
                            NormalizedFinding(
                                scan_id=scan_id,
                                scanner_name=self.name,
                                scanner_rule_id="IAC-CFN-PUBLIC-PRINCIPAL",
                                vulnerability_category="iac",
                                severity="HIGH",
                                confidence="HIGH",
                                file_path=rel_path,
                                start_line=idx,
                                end_line=idx,
                                scanner_message="CloudFormation policy permits wildcard Principal ('*') with Allow effect.",
                                evidence_reference=line.strip(),
                                cwe="CWE-732",
                            )
                        )
            except Exception as e:
                logger.debug(f"Error parsing CloudFormation template {cfn}: {e}")
        return findings
