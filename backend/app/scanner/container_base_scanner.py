"""Container Base Image Scanner Adapter.

Deep OS-level inspection of Dockerfile base layers, checking OS package managers
(apt, apk, rpm), base distro lifecycle/EOL status, compiler leakages, and unpinned tags.
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
    resolve_tool_binary,
)
from ..core.logging import get_logger

logger = get_logger("redmercury.scanner.container_base_scanner")

# Outdated / End-of-Life base distributions with known unpatched kernel/libc CVEs
EOL_BASE_PATTERNS = [
    (r"alpine:(?:2\.|3\.[0-9]\b|3\.1[0-4]\b)", "Alpine Linux version is End-of-Life (EOL) and contains unpatched OS packages."),
    (r"ubuntu:(?:12\.|14\.|16\.|18\.04)", "Ubuntu LTS distribution version is End-of-Life (EOL) or past standard security support."),
    (r"debian:(?:wheezy|jessie|stretch|buster)", "Debian release is End-of-Life (EOL) with deprecated glibc and security updates."),
    (r"python:(?:2\.|3\.[0-7]\b)", "Python base image version is End-of-Life (EOL) and no longer receives upstream security patches."),
    (r"node:(?:8|10|12|14|16)\b", "Node.js runtime base image is End-of-Life (EOL) with vulnerable V8 engine and OpenSSL dependencies."),
    (r"centos:(?:6|7|8)\b", "CentOS distribution release is End-of-Life (EOL) and upstream package repositories are dead."),
]


class ContainerBaseScannerAdapter(BaseScannerAdapter):
    """Adapter for Container Base Image & OS-level Package Scanning."""

    name: str = "container_base_scanner"
    display_name: str = "Container Base Image Scanner"
    category: str = "container_security"

    def is_available(self) -> bool:
        return True

    def get_version(self) -> Optional[str]:
        bin_path = resolve_tool_binary("trivy") or resolve_tool_binary("dockle")
        if bin_path:
            return f"cli-{Path(bin_path).name}"
        return "1.0.0-builtin-os-analyzer"

    def scan(
        self,
        target_dir: Path,
        scan_id: str,
        timeout_seconds: int = 60,
        options: Optional[Dict[str, Any]] = None,
    ) -> ScanJobResult:
        start_time = time.time()
        findings: List[NormalizedFinding] = []

        for df in target_dir.rglob("*Dockerfile*"):
            if not df.is_file() or ".git" in df.parts:
                continue
            try:
                rel_path = str(df.relative_to(target_dir)).replace("\\", "/")
                lines = df.read_text(encoding="utf-8", errors="ignore").splitlines()
                has_user = False

                for idx, line in enumerate(lines, start=1):
                    clean = line.strip()

                    # 1. Inspect Base Image Declaration (FROM)
                    if clean.upper().startswith("FROM "):
                        parts = clean.split()
                        image = parts[1] if len(parts) > 1 else ""

                        # Check unpinned tag or :latest
                        if ":" not in image or image.endswith(":latest"):
                            findings.append(
                                NormalizedFinding(
                                    scan_id=scan_id,
                                    scanner_name=self.name,
                                    scanner_rule_id="CONTAINER-BASE-UNPINNED-TAG",
                                    vulnerability_category="container_security",
                                    severity="MEDIUM",
                                    confidence="HIGH",
                                    file_path=rel_path,
                                    start_line=idx,
                                    end_line=idx,
                                    scanner_message=f"Base image '{image}' lacks a deterministic digest (sha256) or explicit version tag; vulnerable to upstream mutable tag poison.",
                                    evidence_reference=clean,
                                    cwe="CWE-1395",
                                )
                            )

                        # Check End-of-Life (EOL) base distribution
                        for pat, desc in EOL_BASE_PATTERNS:
                            if re.search(pat, image, re.IGNORECASE):
                                findings.append(
                                    NormalizedFinding(
                                        scan_id=scan_id,
                                        scanner_name=self.name,
                                        scanner_rule_id="CONTAINER-BASE-EOL-IMAGE",
                                        vulnerability_category="container_security",
                                        severity="HIGH",
                                        confidence="HIGH",
                                        file_path=rel_path,
                                        start_line=idx,
                                        end_line=idx,
                                        scanner_message=f"Base OS image '{image}' is deprecated: {desc}",
                                        evidence_reference=clean,
                                        cwe="CWE-1104",
                                    )
                                )

                    # 2. Inspect OS Package Manager Commands (apt, apk, yum)
                    if clean.upper().startswith("RUN "):
                        # Pipe to shell execution
                        if re.search(r"(curl|wget)[^|;&]+\|\s*(sh|bash)", clean, re.IGNORECASE):
                            findings.append(
                                NormalizedFinding(
                                    scan_id=scan_id,
                                    scanner_name=self.name,
                                    scanner_rule_id="CONTAINER-OS-PIPE-TO-SHELL",
                                    vulnerability_category="container_security",
                                    severity="HIGH",
                                    confidence="HIGH",
                                    file_path=rel_path,
                                    start_line=idx,
                                    end_line=idx,
                                    scanner_message="Unverified web download piped directly into shell (curl | bash); risks arbitrary code execution during build.",
                                    evidence_reference=clean,
                                    cwe="CWE-494",
                                )
                            )

                        # apt-get without cache cleanup
                        if "apt-get install" in clean and not ("rm -rf /var/lib/apt/lists/*" in clean or "clean" in clean):
                            findings.append(
                                NormalizedFinding(
                                    scan_id=scan_id,
                                    scanner_name=self.name,
                                    scanner_rule_id="CONTAINER-OS-APT-CACHE-RETAINED",
                                    vulnerability_category="container_security",
                                    severity="LOW",
                                    confidence="HIGH",
                                    file_path=rel_path,
                                    start_line=idx,
                                    end_line=idx,
                                    scanner_message="apt-get installs packages without clearing '/var/lib/apt/lists/*'; leaves stale package cache in base container layers.",
                                    evidence_reference=clean,
                                    cwe="CWE-1188",
                                )
                            )

                        # apk add without --no-cache
                        if "apk add" in clean and "--no-cache" not in clean:
                            findings.append(
                                NormalizedFinding(
                                    scan_id=scan_id,
                                    scanner_name=self.name,
                                    scanner_rule_id="CONTAINER-OS-APK-NO-CACHE-MISSING",
                                    vulnerability_category="container_security",
                                    severity="LOW",
                                    confidence="HIGH",
                                    file_path=rel_path,
                                    start_line=idx,
                                    end_line=idx,
                                    scanner_message="Alpine apk package installation missing '--no-cache'; retains package index metadata in container image.",
                                    evidence_reference=clean,
                                    cwe="CWE-1188",
                                )
                            )

                        # Build tools and compilers leaked into production image
                        if re.search(r"\b(build-essential|gcc|g\+\+|gdb|make)\b", clean) and "builder" not in rel_path.lower():
                            findings.append(
                                NormalizedFinding(
                                    scan_id=scan_id,
                                    scanner_name=self.name,
                                    scanner_rule_id="CONTAINER-OS-COMPILER-LEAK",
                                    vulnerability_category="container_security",
                                    severity="MEDIUM",
                                    confidence="HIGH",
                                    file_path=rel_path,
                                    start_line=idx,
                                    end_line=idx,
                                    scanner_message="C/C++ compiler or build tools (gcc/make) installed in container layer; increases attacker post-exploitation utility.",
                                    evidence_reference=clean,
                                    cwe="CWE-1188",
                                )
                            )

                    # 3. Check for non-root USER directive
                    if clean.upper().startswith("USER "):
                        user = clean.split()[1] if len(clean.split()) > 1 else ""
                        if user not in ("root", "0"):
                            has_user = True

                if not has_user and len(lines) > 0:
                    findings.append(
                        NormalizedFinding(
                            scan_id=scan_id,
                            scanner_name=self.name,
                            scanner_rule_id="CONTAINER-BASE-MISSING-NONROOT-USER",
                            vulnerability_category="container_security",
                            severity="HIGH",
                            confidence="HIGH",
                            file_path=rel_path,
                            start_line=1,
                            end_line=1,
                            scanner_message="Container base layer executes as superuser (root). No non-root USER instruction configured.",
                            evidence_reference="Default execution user is root",
                            cwe="CWE-250",
                        )
                    )
            except Exception as e:
                logger.debug(f"Error inspecting container base image {df}: {e}")

        return ScanJobResult(
            scanner_name=self.name,
            scanner_version=self.get_version(),
            category=self.category,
            status=ScannerStatus.SUCCESS if findings else ScannerStatus.NO_FINDINGS,
            execution_time_seconds=round(time.time() - start_time, 3),
            findings=findings,
            exit_code=0,
        )
