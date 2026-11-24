import React, { useState, useMemo } from 'react';
import {
  CheckCircle2,
  Search,
  Sparkles,
  Key,
  ShieldCheck,
  Box,
  AlertCircle,
} from 'lucide-react';
import { ScannerToolInfo } from '../../services/api';

export interface TestSelectorProps {
  tools: ScannerToolInfo[];
  selectedTools: string[];
  onChange: (selected: string[]) => void;
  isLoading?: boolean;
  compact?: boolean;
}

export const SCANNER_METADATA: Record<
  string,
  { summary: string; detail: string; categoryLabel: string; badgeCls: string }
> = {
  bandit: {
    summary: 'Python AST Code Analysis',
    detail: 'Inspects code syntax trees for SQL injection, dangerous functions, weak ciphers, and debug flags.',
    categoryLabel: 'SAST',
    badgeCls: 'bg-purple-100 text-purple-700 border-purple-200',
  },
  injection_scanner: {
    summary: 'SQL & Command Injection Scanner',
    detail: 'Deep AST query interpolation analysis to flag raw f-string SQL queries and unsafe command execution.',
    categoryLabel: 'SAST',
    badgeCls: 'bg-purple-100 text-purple-700 border-purple-200',
  },
  owasp_tools: {
    summary: 'OWASP Top 10 Suite',
    detail: 'Validates against OWASP A01-A10 web application standards, broken access controls, and deserialization.',
    categoryLabel: 'SAST',
    badgeCls: 'bg-purple-100 text-purple-700 border-purple-200',
  },
  semgrep: {
    summary: 'Semgrep Multi-Language SAST',
    detail: 'Polyglot static analysis rules for code vulnerabilities, insecure library calls, and logic flaws.',
    categoryLabel: 'SAST',
    badgeCls: 'bg-purple-100 text-purple-700 border-purple-200',
  },
  gitleaks: {
    summary: 'Gitleaks Secret Scanner',
    detail: 'Standalone entropy and regex scanner for API keys, bearer tokens, SSH keys, and cloud credentials.',
    categoryLabel: 'Secrets',
    badgeCls: 'bg-rose-100 text-rose-700 border-rose-200',
  },
  secret_detector: {
    summary: 'Red Mercury Secret Engine',
    detail: 'Automated secret detection with evidence scrubbing, token redaction, and pattern verification.',
    categoryLabel: 'Secrets',
    badgeCls: 'bg-rose-100 text-rose-700 border-rose-200',
  },
  pip_audit: {
    summary: 'pip-audit Dependency SCA',
    detail: 'Scans requirements.txt and Python packages against the PyPA/OSV advisory vulnerability database.',
    categoryLabel: 'SCA',
    badgeCls: 'bg-emerald-100 text-emerald-700 border-emerald-200',
  },
  trivy_sca: {
    summary: 'Trivy Dependency Scanner',
    detail: 'Audits package manifests, lockfiles, and project dependencies for CVEs and outdated libraries.',
    categoryLabel: 'SCA',
    badgeCls: 'bg-emerald-100 text-emerald-700 border-emerald-200',
  },
  iac_scanner: {
    summary: 'Infrastructure as Code (IaC) Scanner',
    detail: 'Detects security misconfigurations and privilege escalations in Dockerfile, K8s, and Terraform.',
    categoryLabel: 'IaC & Container',
    badgeCls: 'bg-amber-100 text-amber-800 border-amber-200',
  },
  container_base_scanner: {
    summary: 'Container Base Image Scanner',
    detail: 'Analyzes Docker base images for root user risks, end-of-life operating systems, and stale packages.',
    categoryLabel: 'IaC & Container',
    badgeCls: 'bg-amber-100 text-amber-800 border-amber-200',
  },
  license_compliance_scanner: {
    summary: 'Open Source License Compliance',
    detail: 'Identifies copyleft licenses (GPL/AGPL) and flags intellectual property and distribution conflicts.',
    categoryLabel: 'Compliance',
    badgeCls: 'bg-indigo-100 text-indigo-700 border-indigo-200',
  },
  supply_chain_scanner: {
    summary: 'Supply Chain Defense Engine',
    detail: 'Detects typosquatting risks, suspicious install hooks, and unauthorized dependency modifications.',
    categoryLabel: 'Supply Chain',
    badgeCls: 'bg-rose-100 text-rose-800 border-rose-200',
  },
  api_security: {
    summary: 'OWASP API Security Top 10',
    detail: 'Audits REST/GraphQL routes for broken object-level auth, mass assignment, and endpoint security.',
    categoryLabel: 'API Security',
    badgeCls: 'bg-teal-100 text-teal-700 border-teal-200',
  },
  dast_scanner: {
    summary: 'Dynamic Application Security (DAST)',
    detail: 'Probes exposed web routes, endpoints, and security response headers for active weaknesses.',
    categoryLabel: 'DAST',
    badgeCls: 'bg-blue-100 text-blue-700 border-blue-200',
  },
  iast_scanner: {
    summary: 'Interactive Application Security (IAST)',
    detail: 'Monitors runtime execution sensor hooks and tainted data flows across application sinks.',
    categoryLabel: 'IAST',
    badgeCls: 'bg-cyan-100 text-cyan-700 border-cyan-200',
  },
  pentest_scanner: {
    summary: 'Automated Penetration Testing',
    detail: 'Executes automated reconnaissance, open port risk checks, and external attack surface checks.',
    categoryLabel: 'PenTest',
    badgeCls: 'bg-orange-100 text-orange-700 border-orange-200',
  },
  vuln_scanner: {
    summary: 'Vulnerability & Config Scanner',
    detail: 'Cross-checks configuration files and system manifests against global vulnerability datasets.',
    categoryLabel: 'Vuln Config',
    badgeCls: 'bg-slate-100 text-slate-700 border-slate-200',
  },
};

const CATEGORIES = [
  { id: 'all', label: 'All Tests' },
  { id: 'sast', label: 'SAST (Code)' },
  { id: 'secret', label: 'Secrets' },
  { id: 'sca', label: 'Dependencies (SCA)' },
  { id: 'iac', label: 'IaC & Container' },
  { id: 'compliance', label: 'Compliance & Supply Chain' },
  { id: 'api_dynamic', label: 'API & Dynamic' },
];

export const DEFAULT_FALLBACK_TOOLS: ScannerToolInfo[] = [
  { name: 'semgrep', display_name: 'Semgrep OSS', category: 'sast', is_available: false, version: undefined },
  { name: 'bandit', display_name: 'Bandit Python SAST', category: 'sast', is_available: true, version: 'python.exe' },
  { name: 'injection_scanner', display_name: 'SQL & NoSQL Injection Scanner', category: 'sast', is_available: true, version: '1.0.0-injection-ast' },
  { name: 'owasp_tools', display_name: 'OWASP Security Tools & Top 10 Suite', category: 'sast', is_available: true, version: '2025.1.0-owasp-top10' },
  { name: 'trivy_sca', display_name: 'Trivy Dependency Scanner (SCA)', category: 'sca', is_available: true, version: '1.0.0-builtin' },
  { name: 'pip_audit', display_name: 'pip-audit Dependency SCA', category: 'sca', is_available: true, version: 'pip-audit 2.10.1' },
  { name: 'gitleaks', display_name: 'Gitleaks Secret Scanner', category: 'secret', is_available: true, version: '8.18.2' },
  { name: 'secret_detector', display_name: 'Red Mercury Secret Engine', category: 'secret', is_available: true, version: 'Red Mercury Secret Engine v1.0.0' },
  { name: 'vuln_scanner', display_name: 'Vulnerability & IaC Scanner', category: 'vulnerability_scanning', is_available: true, version: '1.0.0-builtin' },
  { name: 'dast_scanner', display_name: 'Dynamic Application Security Testing (DAST)', category: 'dast', is_available: true, version: '1.0.0-builtin' },
  { name: 'api_security', display_name: 'API Security Testing (OWASP API Top 10)', category: 'api_security', is_available: true, version: '1.0.0-builtin' },
  { name: 'iast_scanner', display_name: 'Interactive Application Security Testing (IAST)', category: 'iast', is_available: true, version: '1.0.0-runtime-sensor' },
  { name: 'pentest_scanner', display_name: 'Automated Penetration Testing (Recon)', category: 'penetration_testing', is_available: true, version: '1.0.0-builtin' },
  { name: 'iac_scanner', display_name: 'Infrastructure as Code (IaC) Scanner', category: 'iac', is_available: true, version: '1.0.0-builtin-ast' },
  { name: 'container_base_scanner', display_name: 'Container Base Image Scanner', category: 'container_security', is_available: true, version: '1.0.0-builtin-os-analyzer' },
  { name: 'license_compliance_scanner', display_name: 'Open Source License Compliance', category: 'license_compliance', is_available: true, version: '1.0.0-builtin-spdx-engine' },
  { name: 'supply_chain_scanner', display_name: 'Malicious Package & Supply Chain Defense', category: 'supply_chain_defense', is_available: true, version: '1.0.0-builtin-supply-chain' },
];

export const TestSelector: React.FC<TestSelectorProps> = ({
  tools,
  selectedTools,
  onChange,
  isLoading = false,
  compact = false,
}) => {
  const effectiveTools = useMemo(() => {
    return tools && tools.length > 0 ? tools : DEFAULT_FALLBACK_TOOLS;
  }, [tools]);

  const [searchQuery, setSearchQuery] = useState('');
  const [activeCategory, setActiveCategory] = useState('all');

  const availableTools = useMemo(() => effectiveTools.filter(t => t.is_available), [effectiveTools]);
  const availableToolNames = useMemo(() => availableTools.map(t => t.name), [availableTools]);

  // Presets
  const applyPreset = (preset: 'recommended' | 'secrets' | 'full' | 'dependencies' | 'none') => {
    if (preset === 'none') {
      onChange([]);
      return;
    }
    if (preset === 'full') {
      onChange(availableToolNames);
      return;
    }
    if (preset === 'secrets') {
      const secrets = ['gitleaks', 'secret_detector'].filter(name => availableToolNames.includes(name));
      onChange(secrets);
      return;
    }
    if (preset === 'dependencies') {
      const deps = ['pip_audit', 'trivy_sca', 'supply_chain_scanner', 'license_compliance_scanner'].filter(name =>
        availableToolNames.includes(name)
      );
      onChange(deps);
      return;
    }
    if (preset === 'recommended') {
      const core = ['bandit', 'injection_scanner', 'owasp_tools', 'gitleaks', 'secret_detector', 'pip_audit', 'trivy_sca'].filter(
        name => availableToolNames.includes(name)
      );
      onChange(core);
      return;
    }
  };

  const toggleTool = (name: string) => {
    if (selectedTools.includes(name)) {
      onChange(selectedTools.filter(t => t !== name));
    } else {
      onChange([...selectedTools, name]);
    }
  };

  // Filter tools
  const filteredTools = useMemo(() => {
    return tools.filter(tool => {
      // Category filter
      if (activeCategory === 'sast') {
        if (!['sast'].includes(tool.category.toLowerCase())) return false;
      } else if (activeCategory === 'secret') {
        if (!['secret'].includes(tool.category.toLowerCase())) return false;
      } else if (activeCategory === 'sca') {
        if (!['sca'].includes(tool.category.toLowerCase())) return false;
      } else if (activeCategory === 'iac') {
        if (!['iac', 'container_security', 'vulnerability_scanning'].includes(tool.category.toLowerCase())) return false;
      } else if (activeCategory === 'compliance') {
        if (!['license_compliance', 'supply_chain_defense'].includes(tool.category.toLowerCase())) return false;
      } else if (activeCategory === 'api_dynamic') {
        if (!['dast', 'api_security', 'iast', 'penetration_testing'].includes(tool.category.toLowerCase())) return false;
      }

      // Search filter
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const meta = SCANNER_METADATA[tool.name];
        const matchName = tool.name.toLowerCase().includes(q) || tool.display_name.toLowerCase().includes(q);
        const matchCategory = tool.category.toLowerCase().includes(q);
        const matchMeta = meta && (meta.summary.toLowerCase().includes(q) || meta.detail.toLowerCase().includes(q));
        if (!matchName && !matchCategory && !matchMeta) return false;
      }

      return true;
    });
  }, [effectiveTools, activeCategory, searchQuery]);

  if (isLoading && (!tools || tools.length === 0)) {
    return (
      <div className="p-6 text-center text-xs text-slate-500 bg-slate-50 rounded-lg border border-slate-200 animate-pulse">
        Discovering available security engines and test suites...
      </div>
    );
  }

  return (
    <div className="space-y-3 font-sans">
      {/* Quick Presets Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 pb-1 border-b border-slate-100">
        <div className="flex flex-wrap items-center gap-1.5 text-xs">
          <span className="font-semibold text-slate-600 mr-1 text-[11px] uppercase tracking-wider">
            Test Presets:
          </span>
          <button
            type="button"
            onClick={() => applyPreset('recommended')}
            className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-blue-50 hover:bg-blue-100 text-blue-700 font-medium text-xs border border-blue-200 transition-colors cursor-pointer"
            title="Core SAST + Secret Scanner + Dependency Vulnerability Checks"
          >
            <Sparkles className="w-3 h-3 text-blue-600" />
            <span>Recommended</span>
          </button>
          <button
            type="button"
            onClick={() => applyPreset('secrets')}
            className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-rose-50 hover:bg-rose-100 text-rose-700 font-medium text-xs border border-rose-200 transition-colors cursor-pointer"
            title="Scan for exposed API keys, passwords, and tokens"
          >
            <Key className="w-3 h-3 text-rose-600" />
            <span>Secrets Only</span>
          </button>
          <button
            type="button"
            onClick={() => applyPreset('dependencies')}
            className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-emerald-50 hover:bg-emerald-100 text-emerald-700 font-medium text-xs border border-emerald-200 transition-colors cursor-pointer"
            title="SCA Vulnerabilities & Supply Chain checks"
          >
            <Box className="w-3 h-3 text-emerald-600" />
            <span>Dependencies</span>
          </button>
          <button
            type="button"
            onClick={() => applyPreset('full')}
            className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-purple-50 hover:bg-purple-100 text-purple-700 font-medium text-xs border border-purple-200 transition-colors cursor-pointer"
            title="Execute all available security testing layers"
          >
            <ShieldCheck className="w-3 h-3 text-purple-600" />
            <span>Full 7-Layer Audit</span>
          </button>
        </div>

        <div className="flex items-center gap-2 text-xs">
          <button
            type="button"
            onClick={() => onChange(availableToolNames)}
            className="text-slate-500 hover:text-slate-800 text-[11px] underline cursor-pointer"
          >
            Select All
          </button>
          <span className="text-slate-300">|</span>
          <button
            type="button"
            onClick={() => onChange([])}
            className="text-slate-500 hover:text-rose-600 text-[11px] underline cursor-pointer"
          >
            Clear All
          </button>
        </div>
      </div>

      {/* Category Tabs & Search */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div className="flex items-center gap-1 overflow-x-auto pb-1 text-xs">
          {CATEGORIES.map(cat => (
            <button
              key={cat.id}
              type="button"
              onClick={() => setActiveCategory(cat.id)}
              className={`px-2.5 py-1 rounded-md text-[11px] font-medium whitespace-nowrap transition-colors cursor-pointer ${
                activeCategory === cat.id
                  ? 'bg-slate-900 text-white shadow-2xs'
                  : 'bg-slate-100 hover:bg-slate-200 text-slate-600'
              }`}
            >
              {cat.label}
            </button>
          ))}
        </div>

        {/* Search */}
        <div className="relative min-w-[160px] sm:w-48">
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            placeholder="Search test..."
            className="w-full pl-8 pr-2.5 py-1 text-xs bg-slate-50 border border-slate-200 rounded-md focus:bg-white focus:outline-hidden focus:border-slate-400"
          />
        </div>
      </div>

      {/* Tools Grid */}
      <div className={`grid grid-cols-1 ${compact ? 'gap-1.5' : 'gap-2'} max-h-64 overflow-y-auto pr-1`}>
        {filteredTools.length === 0 ? (
          <div className="p-4 text-center text-xs text-slate-400 bg-slate-50 rounded-lg border border-slate-100">
            No tests match the current filter.
          </div>
        ) : (
          filteredTools.map(tool => {
            const isSelected = selectedTools.includes(tool.name);
            const meta = SCANNER_METADATA[tool.name] || {
              summary: tool.display_name,
              detail: `Security engine for ${tool.category}`,
              categoryLabel: tool.category.toUpperCase(),
              badgeCls: 'bg-slate-100 text-slate-700 border-slate-200',
            };

            return (
              <div
                key={tool.name}
                onClick={() => tool.is_available && toggleTool(tool.name)}
                className={`p-2.5 rounded-lg border text-left transition-all ${
                  !tool.is_available
                    ? 'bg-slate-50 border-slate-200 opacity-60 cursor-not-allowed'
                    : isSelected
                    ? 'bg-blue-50/60 border-blue-400 cursor-pointer shadow-2xs'
                    : 'bg-white border-slate-200 hover:border-slate-300 hover:bg-slate-50/50 cursor-pointer'
                }`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-start gap-2.5 flex-1 min-w-0">
                    <input
                      type="checkbox"
                      checked={isSelected}
                      disabled={!tool.is_available}
                      onChange={() => {}}
                      className="mt-0.5 h-4 w-4 text-blue-600 rounded border-slate-300 focus:ring-blue-500 cursor-pointer"
                    />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <span className="font-semibold text-xs text-slate-900 truncate">
                          {tool.display_name}
                        </span>
                        <span
                          className={`text-[10px] font-bold px-1.5 py-0.2 rounded border ${meta.badgeCls}`}
                        >
                          {meta.categoryLabel}
                        </span>
                        {tool.version && (
                          <span className="text-[10px] text-slate-400 font-mono">
                            v{tool.version.split(' ')[0]}
                          </span>
                        )}
                      </div>
                      <p className="text-[11px] text-slate-500 leading-snug mt-0.5 line-clamp-2">
                        {meta.detail}
                      </p>
                    </div>
                  </div>

                  <div className="shrink-0 pt-0.5">
                    {tool.is_available ? (
                      <span className="inline-flex items-center gap-1 text-[11px] font-medium text-emerald-600 bg-emerald-50 px-2 py-0.5 rounded-full border border-emerald-200">
                        <CheckCircle2 className="w-3 h-3" />
                        Ready
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-[10px] font-medium text-slate-400 bg-slate-100 px-2 py-0.5 rounded-full">
                        Not Installed
                      </span>
                    )}
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Summary Footer */}
      <div className="flex items-center justify-between text-xs pt-1 border-t border-slate-100">
        <div className="flex items-center gap-2">
          <span className="font-semibold text-slate-700">
            Selected Tests:
          </span>
          <span
            className={`font-bold px-2 py-0.5 rounded-full text-xs ${
              selectedTools.length > 0
                ? 'bg-blue-100 text-blue-700 border border-blue-200'
                : 'bg-rose-100 text-rose-700 border border-rose-200'
            }`}
          >
            {selectedTools.length} of {availableTools.length} available
          </span>
        </div>

        {selectedTools.length === 0 && (
          <div className="text-rose-600 text-[11px] flex items-center gap-1">
            <AlertCircle className="w-3.5 h-3.5" />
            <span>Select at least 1 test to proceed</span>
          </div>
        )}
      </div>
    </div>
  );
};

