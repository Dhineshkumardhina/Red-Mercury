import React, { useState, useMemo } from 'react';
import { SecurityEvidenceRecord } from '../../services/api';
import { EmptyState } from '../common';

interface EvidenceCenterScreenProps {
  evidenceList: SecurityEvidenceRecord[];
  onOpenExportModal: () => void;
  onInspectEvidence: (evidence: SecurityEvidenceRecord) => void;
  onExportReport: (type: 'findings' | 'verification', format: 'markdown' | 'json') => void;
  isExporting: boolean;
}

export const EvidenceCenterScreen: React.FC<EvidenceCenterScreenProps> = ({
  evidenceList,
  onOpenExportModal,
  onInspectEvidence,
  onExportReport,
  isExporting,
}) => {
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Stats calculation
  const stats = useMemo(() => {
    const total = evidenceList.length;
    const scanner = evidenceList.filter(e => e.provenance === 'scanner_observed' || e.evidence_category === 'scanner_output').length;
    const sandbox = evidenceList.filter(e => e.provenance === 'sandbox_observed' || e.evidence_category === 'test_result').length;
    const patches = evidenceList.filter(e => e.evidence_category === 'patch_diff').length;
    return { total, scanner, sandbox, patches };
  }, [evidenceList]);

  // Filtered evidence items
  const filteredEvidence = useMemo(() => {
    return evidenceList.filter(e => {
      // Category filter
      if (selectedCategory !== 'all' && e.evidence_category !== selectedCategory) {
        return false;
      }

      // Search query filter
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesId = e.id?.toLowerCase().includes(q);
        const matchesTitle = e.title?.toLowerCase().includes(q);
        const matchesTool = e.tool_name?.toLowerCase().includes(q);
        const matchesHash = e.content_hash?.toLowerCase().includes(q);
        const matchesProvenance = e.provenance?.toLowerCase().includes(q);

        if (!matchesId && !matchesTitle && !matchesTool && !matchesHash && !matchesProvenance) {
          return false;
        }
      }

      return true;
    });
  }, [evidenceList, selectedCategory, searchQuery]);

  const getProvenanceBadge = (provenance: string) => {
    switch (provenance) {
      case 'scanner_observed':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-blue-50 text-blue-700 border border-blue-200 text-xs font-semibold">
            <span className="material-symbols-outlined text-xs text-blue-600">biotech</span>
            Scanner Observed
          </span>
        );
      case 'sandbox_observed':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200 text-xs font-semibold">
            <span className="material-symbols-outlined text-xs text-emerald-600">shield</span>
            Sandbox Observed
          </span>
        );
      case 'ai_generated_commentary':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-slate-100 text-slate-700 border border-slate-200 text-xs font-medium">
            <span className="material-symbols-outlined text-xs text-slate-500">auto_awesome</span>
            AI Commentary
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-slate-100 text-slate-700 border border-slate-200 text-xs font-medium">
            <span className="material-symbols-outlined text-xs text-slate-500">fact_check</span>
            {provenance ? provenance.replace('_', ' ') : 'Evidence Artifact'}
          </span>
        );
    }
  };

  return (
    <div className="flex flex-col w-full pb-16 font-sans">
      {/* Header */}
      <div className="px-4 lg:px-8 py-5 bg-white border-b border-slate-200">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2.5">
              <h1 className="text-xl font-bold text-slate-900 tracking-tight">
                Evidence Center
              </h1>
              <span className="px-2 py-0.5 rounded-full bg-slate-100 text-slate-700 text-xs font-semibold border border-slate-200">
                {stats.total} Artifacts
              </span>
            </div>
            <p className="text-xs text-slate-500 mt-1">
              Tamper-evident logs of scanner outputs, compiler AST proofs, and ephemeral verification runs.
            </p>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <button
              type="button"
              onClick={() => onExportReport('findings', 'markdown')}
              disabled={isExporting || evidenceList.length === 0}
              title={evidenceList.length === 0 ? 'No findings available to export yet.' : 'Export findings as Markdown'}
              className="px-3 py-1.5 bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 rounded-lg text-xs font-medium shadow-2xs transition-colors flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
            >
              <span className="material-symbols-outlined text-sm">description</span>
              <span>Export (MD)</span>
            </button>

            <button
              type="button"
              onClick={() => onExportReport('findings', 'json')}
              disabled={isExporting || evidenceList.length === 0}
              title={evidenceList.length === 0 ? 'No findings available to export yet.' : 'Export findings as JSON'}
              className="px-3 py-1.5 bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 rounded-lg text-xs font-medium shadow-2xs transition-colors flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
            >
              <span className="material-symbols-outlined text-sm">data_object</span>
              <span>Export (JSON)</span>
            </button>

            <button
              type="button"
              onClick={onOpenExportModal}
              className="px-3.5 py-1.5 bg-slate-900 hover:bg-slate-800 text-white rounded-lg text-xs font-semibold shadow-2xs transition-colors flex items-center gap-1.5 cursor-pointer"
            >
              <span className="material-symbols-outlined text-sm">file_download</span>
              <span>Auditor Bundle (SARIF)</span>
            </button>
          </div>
        </div>

        {/* Interactive KPI Summary Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-5">
          {/* Card: Total Artifacts */}
          <button
            type="button"
            onClick={() => setSelectedCategory('all')}
            className={`p-3 rounded-xl border text-left transition-all cursor-pointer ${
              selectedCategory === 'all'
                ? 'bg-slate-50 border-slate-400 shadow-2xs ring-1 ring-slate-400'
                : 'bg-white border-slate-200 hover:border-slate-300'
            }`}
          >
            <div className="flex items-center justify-between text-xs text-slate-500 mb-1 font-medium">
              <span>All Artifacts</span>
              <span className="material-symbols-outlined text-base text-slate-400">inventory_2</span>
            </div>
            <div className="text-xl font-bold text-slate-900">{stats.total}</div>
            <div className="text-[11px] text-slate-400 mt-0.5">Tamper-evident records</div>
          </button>

          {/* Card: Scanner Evidence */}
          <button
            type="button"
            onClick={() => setSelectedCategory('scanner_output')}
            className={`p-3 rounded-xl border text-left transition-all cursor-pointer ${
              selectedCategory === 'scanner_output'
                ? 'bg-blue-50/60 border-blue-400 shadow-2xs ring-1 ring-blue-400'
                : 'bg-white border-slate-200 hover:border-blue-200'
            }`}
          >
            <div className="flex items-center justify-between text-xs text-blue-600 mb-1 font-medium">
              <span>Scanner Evidence</span>
              <span className="material-symbols-outlined text-base text-blue-500">biotech</span>
            </div>
            <div className="text-xl font-bold text-blue-600">{stats.scanner}</div>
            <div className="text-[11px] text-slate-400 mt-0.5">Static analysis outputs</div>
          </button>

          {/* Card: Sandbox Proofs */}
          <button
            type="button"
            onClick={() => setSelectedCategory('test_result')}
            className={`p-3 rounded-xl border text-left transition-all cursor-pointer ${
              selectedCategory === 'test_result'
                ? 'bg-emerald-50/60 border-emerald-400 shadow-2xs ring-1 ring-emerald-400'
                : 'bg-white border-slate-200 hover:border-emerald-200'
            }`}
          >
            <div className="flex items-center justify-between text-xs text-emerald-700 mb-1 font-medium">
              <span>Sandbox Proofs</span>
              <span className="material-symbols-outlined text-base text-emerald-600">shield</span>
            </div>
            <div className="text-xl font-bold text-emerald-700">{stats.sandbox}</div>
            <div className="text-[11px] text-slate-400 mt-0.5">Verification test logs</div>
          </button>

          {/* Card: Patch Diffs */}
          <button
            type="button"
            onClick={() => setSelectedCategory('patch_diff')}
            className={`p-3 rounded-xl border text-left transition-all cursor-pointer ${
              selectedCategory === 'patch_diff'
                ? 'bg-purple-50/60 border-purple-400 shadow-2xs ring-1 ring-purple-400'
                : 'bg-white border-slate-200 hover:border-purple-200'
            }`}
          >
            <div className="flex items-center justify-between text-xs text-purple-700 mb-1 font-medium">
              <span>Patch Diffs</span>
              <span className="material-symbols-outlined text-base text-purple-600">difference</span>
            </div>
            <div className="text-xl font-bold text-purple-700">{stats.patches}</div>
            <div className="text-[11px] text-slate-400 mt-0.5">Candidate remediation diffs</div>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="px-4 lg:px-8 py-3.5 bg-slate-50 border-b border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        {/* Category Filter Segment */}
        <div className="inline-flex p-0.5 rounded-lg bg-slate-200/70 border border-slate-200 self-start">
          <button
            type="button"
            onClick={() => setSelectedCategory('all')}
            className={`px-3 py-1 rounded-md text-xs font-medium transition-colors cursor-pointer ${
              selectedCategory === 'all'
                ? 'bg-white text-slate-900 shadow-2xs font-semibold'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            All ({stats.total})
          </button>
          <button
            type="button"
            onClick={() => setSelectedCategory('scanner_output')}
            className={`px-3 py-1 rounded-md text-xs font-medium transition-colors cursor-pointer flex items-center gap-1.5 ${
              selectedCategory === 'scanner_output'
                ? 'bg-white text-slate-900 shadow-2xs font-semibold'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <span>Scanners ({stats.scanner})</span>
          </button>
          <button
            type="button"
            onClick={() => setSelectedCategory('test_result')}
            className={`px-3 py-1 rounded-md text-xs font-medium transition-colors cursor-pointer flex items-center gap-1.5 ${
              selectedCategory === 'test_result'
                ? 'bg-white text-slate-900 shadow-2xs font-semibold'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <span>Tests ({stats.sandbox})</span>
          </button>
          <button
            type="button"
            onClick={() => setSelectedCategory('patch_diff')}
            className={`px-3 py-1 rounded-md text-xs font-medium transition-colors cursor-pointer flex items-center gap-1.5 ${
              selectedCategory === 'patch_diff'
                ? 'bg-white text-slate-900 shadow-2xs font-semibold'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <span>Diffs ({stats.patches})</span>
          </button>
        </div>

        {/* Search Input & Reset */}
        <div className="flex items-center gap-2">
          <div className="relative min-w-[220px]">
            <span className="material-symbols-outlined text-slate-400 text-sm absolute left-2.5 top-1/2 -translate-y-1/2">
              search
            </span>
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search ID, title, tool, hash..."
              className="w-full pl-8 pr-7 py-1.5 bg-white border border-slate-200 rounded-lg text-xs text-slate-800 placeholder:text-slate-400 focus:outline-hidden focus:border-slate-400 shadow-2xs"
            />
            {searchQuery && (
              <button
                type="button"
                onClick={() => setSearchQuery('')}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 cursor-pointer"
              >
                <span className="material-symbols-outlined text-xs">close</span>
              </button>
            )}
          </div>

          {(selectedCategory !== 'all' || searchQuery.trim()) && (
            <button
              type="button"
              onClick={() => {
                setSelectedCategory('all');
                setSearchQuery('');
              }}
              className="px-2.5 py-1.5 text-xs text-slate-600 hover:text-slate-900 border border-slate-200 rounded-lg bg-white hover:bg-slate-50 transition-colors cursor-pointer shadow-2xs"
            >
              Reset
            </button>
          )}
        </div>
      </div>

      {/* Main Content Area */}
      <div className="px-4 lg:px-8 py-5">
        {/* Results Banner */}
        <div className="flex items-center justify-between text-xs text-slate-500 mb-3">
          <span>
            Showing <strong className="text-slate-800">{filteredEvidence.length}</strong> of{' '}
            <strong className="text-slate-800">{stats.total}</strong> evidence artifacts
          </span>
          <span className="text-slate-400 hidden sm:inline">
            SHA-256 verifiable • Secrets redacted
          </span>
        </div>

        {/* Empty State */}
        {filteredEvidence.length === 0 ? (
          <EmptyState
            icon="fact_check"
            title={stats.total === 0 ? 'No evidence artifacts recorded yet' : 'No evidence matches your filters'}
            description={
              stats.total === 0
                ? 'Evidence records are generated automatically whenever security scans and fix verifications are executed.'
                : 'Try clearing your search query or switching categories to find other records.'
            }
            actionLabel={stats.total === 0 ? undefined : 'Reset Filters'}
            onAction={
              stats.total === 0
                ? undefined
                : () => {
                    setSelectedCategory('all');
                    setSearchQuery('');
                  }
            }
          />
        ) : (
          /* Evidence Records Table */
          <div className="bg-white border border-slate-200 rounded-xl shadow-2xs overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-slate-50 border-b border-slate-200 text-slate-600 font-semibold">
                    <th className="py-3 px-4">Artifact ID &amp; Title</th>
                    <th className="py-3 px-4">Provenance</th>
                    <th className="py-3 px-4">Tool &amp; Version</th>
                    <th className="py-3 px-4">Content Hash (SHA-256)</th>
                    <th className="py-3 px-4">Recorded</th>
                    <th className="py-3 px-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {filteredEvidence.map(ev => (
                    <tr
                      key={ev.id}
                      onClick={() => onInspectEvidence(ev)}
                      className="hover:bg-slate-50/80 transition-colors cursor-pointer group"
                    >
                      {/* ID and Title */}
                      <td className="py-3.5 px-4 font-mono">
                        <div className="font-semibold text-slate-900 group-hover:text-blue-600 transition-colors">
                          {ev.id}
                        </div>
                        <div className="text-slate-600 text-xs font-sans truncate max-w-xs mt-0.5">
                          {ev.title}
                        </div>
                      </td>

                      {/* Provenance */}
                      <td className="py-3.5 px-4">
                        {getProvenanceBadge(ev.provenance)}
                      </td>

                      {/* Tool & Version */}
                      <td className="py-3.5 px-4 font-mono text-xs">
                        <span className="font-semibold text-slate-800">{ev.tool_name}</span>
                        {ev.tool_version && (
                          <span className="text-slate-500 block text-[11px] font-sans">
                            {ev.tool_version}
                          </span>
                        )}
                      </td>

                      {/* Hash */}
                      <td className="py-3.5 px-4 font-mono text-[11px] text-slate-600">
                        <span title={ev.content_hash} className="bg-slate-100 px-1.5 py-0.5 rounded border border-slate-200">
                          {ev.content_hash?.slice(0, 16)}...
                        </span>
                      </td>

                      {/* Recorded At */}
                      <td className="py-3.5 px-4 text-slate-500 text-[11px]">
                        {new Date(ev.recorded_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </td>

                      {/* Action */}
                      <td className="py-3.5 px-4 text-right" onClick={e => e.stopPropagation()}>
                        <button
                          type="button"
                          onClick={() => onInspectEvidence(ev)}
                          className="px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-800 font-semibold text-xs transition-colors border border-slate-200 cursor-pointer"
                        >
                          Inspect Payload
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
