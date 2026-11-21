"""Malicious Package & Supply Chain Defense Scanner Adapter.

Implements pre-installation and static dependency verification (Socket.dev / Phylum patterns):
1. Typosquatting detection against high-profile open source packages.
2. Dangerous lifecycle scripts (preinstall, postinstall, install) in package manifests.
3. Obfuscated payloads (base64 execution, eval/exec in install scripts).
4. Outbound network exfiltration sinks in package setup code (env credential theft, webhook leaks).
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

logger = get_logger("redmercury.scanner.supply_chain_scanner")

# Popular target packages paired with common typosquatting signatures
POPULAR_PACKAGES = [
    # Python
    ("requests", ["reqeusts", "requeests", "request-py", "python-requests-lib"]),
    ("urllib3", ["urllib4", "urllib5", "url-lib3", "urllib-3"]),
    ("colorama", ["collorama", "color-ama", "colorama-py"]),
    ("pydantic", ["py-dantic", "pydantics", "pydantic-core-rs"]),
    ("cryptography", ["cryptograpy", "python-cryptography-lib", "cryptograph"]),
    ("boto3", ["boto4", "boto-3", "boto3-sdk"]),
    # JavaScript / npm
    ("lodash", ["lodaash", "lodash-es-fake", "lodas", "lowdash"]),
    ("cross-env", ["cross-env.js", "crossenv", "cross_env"]),
    ("chalk", ["chalk-js", "chalks", "chalk-color"]),
    ("axios", ["axois", "axios-js", "axioos"]),
    ("express", ["expres", "express-js", "expresss"]),
    ("react", ["react-js", "reacts", "react-dom-mock"]),
    ("electron", ["electorn", "electron-js"]),
]

# Obfuscated or dangerous execution signatures in lifecycle scripts
SUSPICIOUS_LIFECYCLE_PATTERNS = [
    (r"\b(Buffer\.from\([^)]*base64[^)]*\)|atob\(|eval\(|Function\()", "Obfuscated dynamic code execution (eval/base64 buffer decode) in package install lifecycle hook."),
    (r"(curl|wget)[^;\n|]+(\||;|\&\&)\s*(sh|bash|powershell|cmd)", "Automated binary or script download and pipe to shell execution in lifecycle script."),
    (r"(powershell|cmd\.exe)[^;\n]+(Invoke-WebRequest|iwr|downloadstring)", "PowerShell remote payload download instruction in package install script."),
    (r"(discord\.com/api/webhooks|api\.telegram\.org/bot|pastebin\.com/raw)", "Hardcoded external webhook / exfiltration endpoint detected in package install hooks."),
]


class SupplyChainScannerAdapter(BaseScannerAdapter):
    """Adapter for Malicious Package & Supply Chain Defense."""

    name: str = "supply_chain_scanner"
    display_name: str = "Malicious Package & Supply Chain Defense"
    category: str = "supply_chain_defense"

    def is_available(self) -> bool:
        return True

    def get_version(self) -> Optional[str]:
        return "1.0.0-builtin-supply-chain"

    def scan(
        self,
        target_dir: Path,
        scan_id: str,
        timeout_seconds: int = 60,
        options: Optional[Dict[str, Any]] = None,
    ) -> ScanJobResult:
        start_time = time.time()
        findings: List[NormalizedFinding] = []

        # 1. Typosquatting checks across dependency manifests
        findings.extend(self._scan_typosquatting(target_dir, scan_id))

        # 2. Dangerous install lifecycle scripts in package.json
        findings.extend(self._scan_package_lifecycle_scripts(target_dir, scan_id))

        # 3. Environment theft and telemetry exfiltration in setup scripts
        findings.extend(self._scan_setup_scripts(target_dir, scan_id))

        return ScanJobResult(
            scanner_name=self.name,
            scanner_version=self.get_version(),
            category=self.category,
            status=ScannerStatus.SUCCESS if findings else ScannerStatus.NO_FINDINGS,
            execution_time_seconds=round(time.time() - start_time, 3),
            findings=findings,
            exit_code=0,
        )

    def _scan_typosquatting(self, target_dir: Path, scan_id: str) -> List[NormalizedFinding]:
        findings = []

        # Check package.json dependencies
        for pkg_json in target_dir.rglob("package.json"):
            if not pkg_json.is_file() or ".git" in pkg_json.parts or "node_modules" in pkg_json.parts:
                continue
            try:
                rel_path = str(pkg_json.relative_to(target_dir)).replace("\\", "/")
                data = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
                deps = {}
                deps.update(data.get("dependencies", {}))
                deps.update(data.get("devDependencies", {}))

                for dep_name in deps.keys():
                    dep_clean = dep_name.strip().lower()
                    for legit, typos in POPULAR_PACKAGES:
                        if dep_clean in typos and dep_clean != legit:
                            findings.append(
                                NormalizedFinding(
                                    scan_id=scan_id,
                                    scanner_name=self.name,
                                    scanner_rule_id="SUPPLY-CHAIN-TYPOSQUAT-DEPENDENCY",
                                    vulnerability_category="supply_chain_defense",
                                    severity="CRITICAL",
                                    confidence="HIGH",
                                    file_path=rel_path,
                                    start_line=1,
                                    end_line=1,
                                    scanner_message=f"Suspicious dependency '{dep_name}' appears to be a typosquatted variant of popular package '{legit}'. Known supply chain attack vector.",
                                    evidence_reference=f"package.json dependency entry: '{dep_name}'",
                                    cwe="CWE-1395",
                                )
                            )
            except Exception as e:
                logger.debug(f"Error checking typosquatting in {pkg_json}: {e}")

        # Check requirements.txt dependencies
        for req_txt in target_dir.rglob("*requirements*.txt"):
            if not req_txt.is_file() or ".git" in req_txt.parts:
                continue
            try:
                rel_path = str(req_txt.relative_to(target_dir)).replace("\\", "/")
                lines = req_txt.read_text(encoding="utf-8", errors="ignore").splitlines()

                for idx, line in enumerate(lines, start=1):
                    clean_line = line.split("==")[0].split(">=")[0].split("<=")[0].split("~=")[0].strip().lower()
                    if not clean_line or clean_line.startswith("#"):
                        continue
                    for legit, typos in POPULAR_PACKAGES:
                        if clean_line in typos and clean_line != legit:
                            findings.append(
                                NormalizedFinding(
                                    scan_id=scan_id,
                                    scanner_name=self.name,
                                    scanner_rule_id="SUPPLY-CHAIN-TYPOSQUAT-DEPENDENCY",
                                    vulnerability_category="supply_chain_defense",
                                    severity="CRITICAL",
                                    confidence="HIGH",
                                    file_path=rel_path,
                                    start_line=idx,
                                    end_line=idx,
                                    scanner_message=f"Suspicious dependency '{clean_line}' appears to be a typosquatted variant of popular Python package '{legit}'.",
                                    evidence_reference=line.strip(),
                                    cwe="CWE-1395",
                                )
                            )
            except Exception as e:
                logger.debug(f"Error checking typosquatting in {req_txt}: {e}")

        return findings

    def _scan_package_lifecycle_scripts(self, target_dir: Path, scan_id: str) -> List[NormalizedFinding]:
        findings = []
        for pkg_json in target_dir.rglob("package.json"):
            if not pkg_json.is_file() or ".git" in pkg_json.parts or "node_modules" in pkg_json.parts:
                continue
            try:
                rel_path = str(pkg_json.relative_to(target_dir)).replace("\\", "/")
                data = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
                scripts = data.get("scripts", {})

                # Suspicious lifecycle script hooks
                dangerous_hooks = ["preinstall", "install", "postinstall", "preuninstall", "postuninstall"]
                for hook in dangerous_hooks:
                    hook_cmd = scripts.get(hook)
                    if isinstance(hook_cmd, str) and hook_cmd.strip():
                        # Check for suspicious command patterns
                        for pat, desc in SUSPICIOUS_LIFECYCLE_PATTERNS:
                            if re.search(pat, hook_cmd, re.IGNORECASE):
                                findings.append(
                                    NormalizedFinding(
                                        scan_id=scan_id,
                                        scanner_name=self.name,
                                        scanner_rule_id=f"SUPPLY-CHAIN-MALICIOUS-{hook.upper()}-HOOK",
                                        vulnerability_category="supply_chain_defense",
                                        severity="CRITICAL",
                                        confidence="HIGH",
                                        file_path=rel_path,
                                        start_line=1,
                                        end_line=1,
                                        scanner_message=f"Dangerous '{hook}' lifecycle script detected: {desc}",
                                        evidence_reference=f'"{hook}": "{hook_cmd}"',
                                        cwe="CWE-94",
                                    )
                                )
            except Exception as e:
                logger.debug(f"Error inspecting package.json lifecycle scripts in {pkg_json}: {e}")
        return findings

    def _scan_setup_scripts(self, target_dir: Path, scan_id: str) -> List[NormalizedFinding]:
        findings = []
        for script_file in list(target_dir.rglob("setup.py")) + list(target_dir.rglob("install.js")):
            if not script_file.is_file() or ".git" in script_file.parts or ".venv" in script_file.parts:
                continue
            try:
                rel_path = str(script_file.relative_to(target_dir)).replace("\\", "/")
                content = script_file.read_text(encoding="utf-8", errors="ignore")
                lines = content.splitlines()

                has_env_access = "process.env" in content or "os.environ" in content
                has_network_req = any(k in content for k in ("requests.post", "urllib.request", "http.request", "fetch(", "curl", "discord.com", "pastebin"))

                if has_env_access and has_network_req:
                    for idx, line in enumerate(lines, start=1):
                        if any(k in line for k in ("requests.post", "urllib.request", "fetch(", "webhook", "environ", "process.env")):
                            findings.append(
                                NormalizedFinding(
                                    scan_id=scan_id,
                                    scanner_name=self.name,
                                    scanner_rule_id="SUPPLY-CHAIN-CREDENTIAL-EXFILTRATION-SINK",
                                    vulnerability_category="supply_chain_defense",
                                    severity="CRITICAL",
                                    confidence="HIGH",
                                    file_path=rel_path,
                                    start_line=idx,
                                    end_line=idx,
                                    scanner_message="Package installation script accesses environment variables and issues outbound network requests (potential credential theft / exfiltration).",
                                    evidence_reference=line.strip(),
                                    cwe="CWE-200",
                                )
                            )
                            break
            except Exception as e:
                logger.debug(f"Error inspecting setup script {script_file}: {e}")
        return findings
