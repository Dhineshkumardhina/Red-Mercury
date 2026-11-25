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
    summary: 'Code Security & Syntax Analysis',
    detail: 'Checks Python code syntax for insecure functions, weak cryptography, and debug flags.',
    categoryLabel: 'Code',
    badgeCls: 'bg-slate-100 text-slate-700 border-slate-200',
  },
  injection_scanner: {
    summary: 'SQL & Injection Defense',
    detail: 'Prevents raw string interpolation in queries and flags unsafe command execution.',
    categoryLabel: 'Injection',
    badgeCls: 'bg-slate-100 text-slate-700 border-slate-200',
  },
  owasp_tools: {
    summary: 'OWASP Top 10 Standards',
    detail: 'Checks for broken access controls, insecure design, and common web security flaws.',
    categoryLabel: 'Security',
    badgeCls: 'bg-slate-100 text-slate-700 border-slate-200',
  },
  semgrep: {
    summary: 'Multi-Language Code Check',
    detail: 'Polyglot static analysis rules for code vulnerabilities and unsafe library usage.',
    categoryLabel: 'Code',
    badgeCls: 'bg-slate-100 text-slate-700 border-slate-200',
  },
  gitleaks: {
    summary: 'API Key & Token Scanner',
    detail: 'Detects accidentally committed API keys, bearer tokens, and cloud credentials.',
    categoryLabel: 'Secrets',
    badgeCls: 'bg-slate-100 text-slate-700 border-slate-200',
  },
  secret_detector: {
    summary: 'Passwords & Credentials Scanner',
    detail: 'Finds hardcoded passwords, private tokens, and confidential keys in source files.',
    categoryLabel: 'Secrets',
    badgeCls: 'bg-slate-100 text-slate-700 border-slate-200',
  },
  pip_audit: {
    summary: 'Python Dependencies (pip)',
    detail: 'Checks installed Python libraries and requirements.txt against known vulnerability databases.',
    categoryLabel: 'Packages',
    badgeCls: 'bg-slate-100 text-slate-700 border-slate-200',
  },
  trivy_sca: {
    summary: 'Package & Library Audit',
    detail: 'Scans package manifests and lockfiles for known security vulnerabilities.',
    categoryLabel: 'Packages',
    badgeCls: 'bg-slate-100 text-slate-700 border-slate-200',
  },
  iac_scanner: {
    summary: 'Configuration & Docker Check',
    detail: 'Detects security misconfigurations in Dockerfile, Kubernetes, and config files.',
    categoryLabel: 'Config',
    badgeCls: 'bg-slate-100 text-slate-700 border-slate-200',
  },
  container_base_scanner: {
    summary: 'Container Image Check',
    detail: 'Checks base container images for root privileges and outdated software packages.',
    categoryLabel: 'Config',
    badgeCls: 'bg-slate-100 text-slate-700 border-slate-200',
  },
  license_compliance_scanner: {
    summary: 'License Compliance',
    detail: 'Verifies third-party package licenses for intellectual property compatibility.',
    categoryLabel: 'License',
    badgeCls: 'bg-slate-100 text-slate-700 border-slate-200',
  },
  supply_chain_scanner: {
    summary: 'Supply Chain Defense',
    detail: 'Detects suspicious package install scripts and unauthorized modifications.',
    categoryLabel: 'Packages',
    badgeCls: 'bg-slate-100 text-slate-700 border-slate-200',
  },
  api_security: {
    summary: 'API Route Security',
    detail: 'Checks REST and GraphQL endpoints for authorization flaws and parameter exposure.',
    categoryLabel: 'API',
    badgeCls: 'bg-slate-100 text-slate-700 border-slate-200',
  },
  dast_scanner: {
    summary: 'Dynamic Security Check',
    detail: 'Probes exposed web routes and security headers for configuration weaknesses.',
    categoryLabel: 'Web',
    badgeCls: 'bg-slate-100 text-slate-700 border-slate-200',
  },
  iast_scanner: {
    summary: 'Interactive Runtime Check',
    detail: 'Monitors runtime execution paths and tainted data flows across application sinks.',
    categoryLabel: 'Runtime',
    badgeCls: 'bg-slate-100 text-slate-700 border-slate-200',
  },
  pentest_scanner: {
    summary: 'Attack Surface Inspection',
    detail: 'Checks open ports, exposed services, and external entry points for security risks.',
    categoryLabel: 'Network',
    badgeCls: 'bg-slate-100 text-slate-700 border-slate-200',
  },
  vuln_scanner: {
    summary: 'General Vulnerability Check',
    detail: 'Cross-checks configuration files and system manifests against vulnerability datasets.',
    categoryLabel: 'General',
    badgeCls: 'bg-slate-100 text-slate-700 border-slate-200',
  },
};

const CATEGORIES = [
  { id: 'all', label: 'All Checks' },
  { id: 'sast', label: 'Code' },
  { id: 'secret', label: 'Secrets' },
  { id: 'sca', label: 'Packages' },
  { id: 'iac', label: 'Config' },
];

export const DEFAULT_FALLBACK_TOOLS: ScannerToolInfo[] = [
  { name: 'semgrep', display_name: 'Semgrep Multi-Language SAST', category: 'sast', is_available: false, version: undefined },
  { name: 'bandit', display_name: 'Bandit Python Code Check', category: 'sast', is_available: true, version: undefined },
  { name: 'injection_scanner', display_name: 'SQL & Injection Scanner', category: 'sast', is_available: true, version: undefined },
  { name: 'owasp_tools', display_name: 'OWASP Security Suite', category: 'sast', is_available: true, version: undefined },
  { name: 'trivy_sca', display_name: 'Trivy Package Scanner', category: 'sca', is_available: true, version: undefined },
  { name: 'pip_audit', display_name: 'pip-audit Dependencies', category: 'sca', is_available: true, version: undefined },
  { name: 'gitleaks', display_name: 'Gitleaks API Key Finder', category: 'secret', is_available: true, version: undefined },
  { name: 'secret_detector', display_name: 'Password & Secret Detector', category: 'secret', is_available: true, version: undefined },
  { name: 'vuln_scanner', display_name: 'Vulnerability & Config Check', category: 'vulnerability_scanning', is_available: true, version: undefined },
  { name: 'dast_scanner', display_name: 'Dynamic Web Route Check', category: 'dast', is_available: true, version: undefined },
  { name: 'api_security', display_name: 'API Security Testing', category: 'api_security', is_available: true, version: undefined },
  { name: 'iast_scanner', display_name: 'Interactive Runtime Check', category: 'iast', is_available: true, version: undefined },
  { name: 'pentest_scanner', display_name: 'Attack Surface Inspection', category: 'penetration_testing', is_available: true, version: undefined },
  { name: 'iac_scanner', display_name: 'Config & Docker Check', category: 'iac', is_available: true, version: undefined },
  { name: 'container_base_scanner', display_name: 'Container Image Check', category: 'container_security', is_available: true, version: undefined },
  { name: 'license_compliance_scanner', display_name: 'License Compliance', category: 'license_compliance', is_available: true, version: undefined },
  { name: 'supply_chain_scanner', display_name: 'Supply Chain Defense', category: 'supply_chain_defense', is_available: true, version: undefined },
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

  // Presets - Clean neutral buttons, no rainbow colors
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
    return effectiveTools.filter(tool => {
      // Category filter
      if (activeCategory === 'sast') {
        if (!['sast'].includes(tool.category.toLowerCase())) return false;
      } else if (activeCategory === 'secret') {
        if (!['secret'].includes(tool.category.toLowerCase())) return false;
      } else if (activeCategory === 'sca') {
        if (!['sca'].includes(tool.category.toLowerCase())) return false;
      } else if (activeCategory === 'iac') {
        if (!['iac', 'container_security', 'vulnerability_scanning'].includes(tool.category.toLowerCase())) return false;
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
      <div className="p-4 text-center text-xs text-slate-500 bg-slate-50 rounded-lg border border-slate-200 animate-pulse">
        Checking available security tools...
      </div>
    );
  }

  return (
    <div className="space-y-3 font-sans">
      {/* Presets Bar - Clean Monochromatic */}
      <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-slate-100">
        <div className="flex flex-wrap items-center gap-1.5 text-xs">
          <button
            type="button"
            onClick={() => applyPreset('recommended')}
            className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md bg-slate-900 text-white font-medium text-xs hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <Sparkles className="w-3 h-3" />
            <span>Recommended</span>
          </button>
          <button
            type="button"
            onClick={() => applyPreset('secrets')}
            className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md bg-white hover:bg-slate-50 text-slate-700 font-medium text-xs border border-slate-200 transition-colors cursor-pointer"
          >
            <Key className="w-3 h-3 text-slate-500" />
            <span>Secrets Only</span>
          </button>
          <button
            type="button"
            onClick={() => applyPreset('dependencies')}
            className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md bg-white hover:bg-slate-50 text-slate-700 font-medium text-xs border border-slate-200 transition-colors cursor-pointer"
          >
            <Box className="w-3 h-3 text-slate-500" />
            <span>Packages</span>
          </button>
          <button
            type="button"
            onClick={() => applyPreset('full')}
            className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md bg-white hover:bg-slate-50 text-slate-700 font-medium text-xs border border-slate-200 transition-colors cursor-pointer"
          >
            <ShieldCheck className="w-3 h-3 text-slate-500" />
            <span>All Checks</span>
          </button>
        </div>

        <div className="flex items-center gap-2 text-xs">
          <button
            type="button"
            onClick={() => onChange(availableToolNames)}
            className="text-slate-500 hover:text-slate-800 text-[11px] font-medium cursor-pointer"
          >
            Select All
          </button>
          <span className="text-slate-300">•</span>
          <button
            type="button"
            onClick={() => onChange([])}
            className="text-slate-500 hover:text-slate-800 text-[11px] font-medium cursor-pointer"
          >
            Clear
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
        <div className="relative min-w-[160px] sm:w-44">
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            placeholder="Search test..."
            className="w-full pl-8 pr-2.5 py-1 text-xs bg-slate-50 border border-slate-200 rounded-md focus:bg-white focus:outline-hidden focus:border-slate-400 text-slate-800"
          />
        </div>
      </div>

      {/* Tools Grid - Clean Monochromatic */}
      <div className={`grid grid-cols-1 ${compact ? 'gap-1.5' : 'gap-2'} max-h-56 overflow-y-auto pr-1`}>
        {filteredTools.length === 0 ? (
          <div className="p-4 text-center text-xs text-slate-400 bg-slate-50 rounded-lg border border-slate-100">
            No checks match the current filter.
          </div>
        ) : (
          filteredTools.map(tool => {
            const isSelected = selectedTools.includes(tool.name);
            const meta = SCANNER_METADATA[tool.name] || {
              summary: tool.display_name,
              detail: `Security engine for ${tool.category}`,
              categoryLabel: 'Check',
              badgeCls: 'bg-slate-100 text-slate-700 border-slate-200',
            };

            return (
              <div
                key={tool.name}
                onClick={() => tool.is_available && toggleTool(tool.name)}
                className={`p-2.5 rounded-lg border text-left transition-all ${
                  !tool.is_available
                    ? 'bg-slate-50 border-slate-200 opacity-50 cursor-not-allowed'
                    : isSelected
                    ? 'bg-slate-50/80 border-slate-900 cursor-pointer shadow-2xs'
                    : 'bg-white border-slate-200 hover:border-slate-300 hover:bg-slate-50/40 cursor-pointer'
                }`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-start gap-2.5 flex-1 min-w-0">
                    <input
                      type="checkbox"
                      checked={isSelected}
                      disabled={!tool.is_available}
                      onChange={() => {}}
                      className="mt-0.5 h-4 w-4 rounded border-slate-300 accent-slate-900 cursor-pointer"
                    />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <span className="font-semibold text-xs text-slate-900 truncate">
                          {tool.display_name}
                        </span>
                        <span className="text-[10px] font-medium px-1.5 py-0.2 rounded bg-slate-100 text-slate-600 border border-slate-200">
                          {meta.categoryLabel}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-500 leading-snug mt-0.5 line-clamp-2">
                        {meta.detail}
                      </p>
                    </div>
                  </div>

                  <div className="shrink-0 pt-0.5">
                    {tool.is_available ? (
                      <span className="inline-flex items-center gap-1 text-[11px] font-medium text-slate-600 bg-slate-100 px-2 py-0.5 rounded-md border border-slate-200">
                        <CheckCircle2 className="w-3 h-3 text-slate-700" />
                        Ready
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-[10px] font-medium text-slate-400 bg-slate-100 px-2 py-0.5 rounded-md">
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
          <span className="text-slate-500 text-xs">
            Selected:
          </span>
          <span className="font-semibold px-2 py-0.5 rounded-md text-xs bg-slate-100 text-slate-800 border border-slate-200">
            {selectedTools.length} of {availableTools.length} available
          </span>
        </div>

        {selectedTools.length === 0 && (
          <div className="text-slate-600 text-[11px] flex items-center gap-1">
            <AlertCircle className="w-3.5 h-3.5" />
            <span>Select at least 1 check</span>
          </div>
        )}
      </div>
    </div>
  );
};
