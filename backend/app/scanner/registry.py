"""Scanner registry managing adapters and tool availability."""
from typing import Any, Dict, List, Optional
from .base import BaseScannerAdapter
from .bandit import BanditScannerAdapter
from .pip_audit import PipAuditScannerAdapter
from .semgrep import SemgrepScannerAdapter
from .gitleaks import GitleaksScannerAdapter
from .secret_detector import SecretScannerAdapter
from .trivy_sca import TrivyScaScannerAdapter
from .vuln_scanner import VulnScannerAdapter
from .dast_scanner import DastScannerAdapter
from .api_security import ApiSecurityScannerAdapter
from .iast_scanner import IastScannerAdapter
from .pentest_scanner import PentestScannerAdapter
from .injection_scanner import InjectionScannerAdapter
from .owasp_scanner import OwaspScannerAdapter
from .iac_scanner import IacScannerAdapter
from .container_base_scanner import ContainerBaseScannerAdapter
from .license_compliance_scanner import LicenseComplianceScannerAdapter
from .supply_chain_scanner import SupplyChainScannerAdapter


class ScannerRegistry:
    """Central registry for discovering, configuring, and invoking security scanners."""

    def __init__(self):
        self._adapters: Dict[str, BaseScannerAdapter] = {}
        # 1. SAST (Static Application Security Testing)
        self.register(SemgrepScannerAdapter())
        self.register(BanditScannerAdapter())
        self.register(InjectionScannerAdapter())
        self.register(OwaspScannerAdapter())
        # 2. SCA (Software Composition Analysis)
        self.register(TrivyScaScannerAdapter())
        self.register(PipAuditScannerAdapter())
        # 3. Secret Scanning
        self.register(GitleaksScannerAdapter())
        self.register(SecretScannerAdapter())
        # 4. Vulnerability Scanning
        self.register(VulnScannerAdapter())
        # 5. DAST (Dynamic Application Security Testing)
        self.register(DastScannerAdapter())
        # 6. API Security Testing (OWASP API Top 10)
        self.register(ApiSecurityScannerAdapter())
        # 7. IAST (Interactive Application Security Testing)
        self.register(IastScannerAdapter())
        # 8. Penetration Testing (Automated Recon & Exploitation Checks)
        self.register(PentestScannerAdapter())
        # 9. Ingestion & Static Analysis Extras
        self.register(IacScannerAdapter())
        self.register(ContainerBaseScannerAdapter())
        self.register(LicenseComplianceScannerAdapter())
        self.register(SupplyChainScannerAdapter())

    def register(self, adapter: BaseScannerAdapter) -> None:
        """Register a scanner adapter."""
        self._adapters[adapter.name] = adapter

    def get(self, name: str) -> Optional[BaseScannerAdapter]:
        """Retrieve adapter by short identifier."""
        return self._adapters.get(name)

    def list_all(self) -> List[BaseScannerAdapter]:
        """List all registered adapters."""
        return list(self._adapters.values())

    def get_available(self) -> List[BaseScannerAdapter]:
        """List adapters currently available on the host/worker environment."""
        available = []
        for adapter in self._adapters.values():
            try:
                if adapter.is_available():
                    available.append(adapter)
            except Exception:
                pass
        return available

    def describe_scanners(self) -> List[Dict[str, Any]]:
        """Return metadata summary for all registered scanners."""
        info = []
        for adapter in self._adapters.values():
            try:
                available = adapter.is_available()
            except Exception:
                available = False
            try:
                version = adapter.get_version() if available else None
            except Exception:
                version = None
            info.append({
                "name": adapter.name,
                "display_name": adapter.display_name,
                "category": adapter.category,
                "is_available": available,
                "version": version,
            })
        return info


scanner_registry = ScannerRegistry()
