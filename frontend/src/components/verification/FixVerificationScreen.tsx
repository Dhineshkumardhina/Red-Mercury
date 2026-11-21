import React, { useState, useMemo } from 'react';
import { VerificationItem } from '../../types';
import { ApiVerificationRun, VerificationStatus } from '../../services/api';
import { EmptyState } from '../common';

interface FixVerificationScreenProps {
  items?: VerificationItem[];
  liveRuns?: ApiVerificationRun[];
  onOpenDiffModal: (item: VerificationItem) => void;
  onOpenCrashModal: (item: VerificationItem) => void;
  onOpenEvidenceModal?: (run: ApiVerificationRun) => void;
  onOpenNewRunModal?: () => void;
  onApproveAndMerge?: (id: string, prNumber?: number) => void;
  mergedPrs?: Set<number>;
}

export const FixVerificationScreen: React.FC<FixVerificationScreenProps> = ({
  liveRuns = [],
  onOpenDiffModal,
  onOpenEvidenceModal,
  onOpenNewRunModal,
}) => {
  const [activeFilter, setActiveFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Statistics calculation for verification runs
  const safeRuns = useMemo(() => (Array.isArray(liveRuns) ? liveRuns : []), [liveRuns]);
  const stats = useMemo(() => {
    const total = safeRuns.length;
    const verified = safeRuns.filter(r => r.status === 'VERIFIED_AGAINST_DEFINED_CHECKS').length;
    const failed = safeRuns.filter(r => r.status === 'FAILED_VERIFICATION').length;
    const inconclusive = safeRuns.filter(r => r.status === 'INCONCLUSIVE').length;
    return { total, verified, failed, inconclusive };
  }, [safeRuns]);

  // Filtered runs based on search and status
  const filteredRuns = useMemo(() => {
    return safeRuns.filter(run => {
      // Status filter
      if (activeFilter !== 'all' && run.status !== activeFilter) {
        return false;
      }

      // Search query
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesId = run.id?.toLowerCase().includes(q);
        const matchesFinding = run.finding_id?.toLowerCase().includes(q);
        const matchesScanner = Object.keys(run.scanner_metadata || {}).some(k => k.toLowerCase().includes(q));
        const matchesReason = run.reasons?.some(r => r.toLowerCase().includes(q));
        const matchesTest = run.test_summary?.toLowerCase().includes(q);

        if (!matchesId && !matchesFinding && !matchesScanner && !matchesReason && !matchesTest) {
          return false;
        }
      }

      return true;
    });
  }, [safeRuns, activeFilter, searchQuery]);

  const renderStatusBadge = (status: VerificationStatus | string) => {
    switch (status) {
      case 'VERIFIED_AGAINST_DEFINED_CHECKS':
      case 'verified':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200 text-xs font-semibold">
            <span className="material-symbols-outlined text-xs text-emerald-600">verified</span>
            Verified Safe
          </span>
        );
      case 'FAILED_VERIFICATION':
      case 'failed':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-rose-50 text-rose-700 border border-rose-200 text-xs font-semibold">
            <span className="material-symbols-outlined text-xs text-rose-600">cancel</span>
            Failed Checks
          </span>
        );
      case 'INCONCLUSIVE':
      case 'inconclusive':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-amber-50 text-amber-700 border border-amber-200 text-xs font-semibold">
            <span className="material-symbols-outlined text-xs text-amber-600">help_outline</span>
            Inconclusive
          </span>
        );
      case 'RUNNING':
      case 'running':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-blue-50 text-blue-700 border border-blue-200 text-xs font-semibold">
            <span className="w-1.5 h-1.5 rounded-full bg-blue-600 animate-pulse" />
            Running
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-slate-100 text-slate-700 border border-slate-200 text-xs font-medium">
            <span className="material-symbols-outlined text-xs text-slate-500">hourglass_empty</span>
            Pending
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
                Fix Verification
              </h1>
              <span className="px-2 py-0.5 rounded-full bg-slate-100 text-slate-700 text-xs font-semibold border border-slate-200">
                {stats.total} Runs
              </span>
            </div>
            <p className="text-xs text-slate-500 mt-1">
              Automated testing and scanner gate verification to ensure candidate patches safely eliminate vulnerabilities.
            </p>
          </div>

          <div className="flex items-center gap-2.5">
            {onOpenNewRunModal && (
              <button
                type="button"
                onClick={onOpenNewRunModal}
                className="px-3.5 py-1.5 bg-slate-900 hover:bg-slate-800 text-white rounded-lg text-xs font-semibold shadow-2xs transition-colors flex items-center gap-1.5 cursor-pointer"
              >
                <span className="material-symbols-outlined text-sm">play_arrow</span>
                <span>Run Fix Verification</span>
              </button>
            )}
          </div>
        </div>

        {/* Interactive KPI Summary Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-5">
          {/* Total Runs */}
          <button
            type="button"
            onClick={() => setActiveFilter('all')}
            className={`p-3 rounded-xl border text-left transition-all cursor-pointer ${
              activeFilter === 'all'
                ? 'bg-slate-50 border-slate-400 shadow-2xs ring-1 ring-slate-400'
                : 'bg-white border-slate-200 hover:border-slate-300'
            }`}
          >
            <div className="flex items-center justify-between text-xs text-slate-500 mb-1 font-medium">
              <span>Total Runs</span>
              <span className="material-symbols-outlined text-base text-slate-400">fact_check</span>
            </div>
            <div className="text-xl font-bold text-slate-900">{stats.total}</div>
            <div className="text-[11px] text-slate-400 mt-0.5">Isolated test runs</div>
          </button>

          {/* Verified Safe */}
          <button
            type="button"
            onClick={() => setActiveFilter('VERIFIED_AGAINST_DEFINED_CHECKS')}
            className={`p-3 rounded-xl border text-left transition-all cursor-pointer ${
              activeFilter === 'VERIFIED_AGAINST_DEFINED_CHECKS'
                ? 'bg-emerald-50/60 border-emerald-400 shadow-2xs ring-1 ring-emerald-400'
                : 'bg-white border-slate-200 hover:border-emerald-200'
            }`}
          >
            <div className="flex items-center justify-between text-xs text-emerald-700 mb-1 font-medium">
              <span>Verified Safe</span>
              <span className="material-symbols-outlined text-base text-emerald-600">verified</span>
            </div>
            <div className="text-xl font-bold text-emerald-700">{stats.verified}</div>
            <div className="text-[11px] text-slate-400 mt-0.5">Passed scanner &amp; tests</div>
          </button>

          {/* Failed Verification */}
          <button
            type="button"
            onClick={() => setActiveFilter('FAILED_VERIFICATION')}
            className={`p-3 rounded-xl border text-left transition-all cursor-pointer ${
              activeFilter === 'FAILED_VERIFICATION'
                ? 'bg-rose-50/60 border-rose-400 shadow-2xs ring-1 ring-rose-400'
                : 'bg-white border-slate-200 hover:border-rose-200'
            }`}
          >
            <div className="flex items-center justify-between text-xs text-rose-700 mb-1 font-medium">
              <span>Failed Checks</span>
              <span className="material-symbols-outlined text-base text-rose-600">cancel</span>
            </div>
            <div className="text-xl font-bold text-rose-700">{stats.failed}</div>
            <div className="text-[11px] text-slate-400 mt-0.5">Vulnerability persisted</div>
          </button>

          {/* Inconclusive */}
          <button
            type="button"
            onClick={() => setActiveFilter('INCONCLUSIVE')}
            className={`p-3 rounded-xl border text-left transition-all cursor-pointer ${
              activeFilter === 'INCONCLUSIVE'
                ? 'bg-amber-50/60 border-amber-400 shadow-2xs ring-1 ring-amber-400'
                : 'bg-white border-slate-200 hover:border-amber-200'
            }`}
          >
            <div className="flex items-center justify-between text-xs text-amber-700 mb-1 font-medium">
              <span>Inconclusive</span>
              <span className="material-symbols-outlined text-base text-amber-600">help_outline</span>
            </div>
            <div className="text-xl font-bold text-amber-700">{stats.inconclusive}</div>
            <div className="text-[11px] text-slate-400 mt-0.5">Timeout or path issues</div>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="px-4 lg:px-8 py-3.5 bg-slate-50 border-b border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        {/* Status Filter Segment */}
        <div className="inline-flex p-0.5 rounded-lg bg-slate-200/70 border border-slate-200 self-start">
          <button
            type="button"
            onClick={() => setActiveFilter('all')}
            className={`px-3 py-1 rounded-md text-xs font-medium transition-colors cursor-pointer ${
              activeFilter === 'all'
                ? 'bg-white text-slate-900 shadow-2xs font-semibold'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            All ({stats.total})
          </button>
          <button
            type="button"
            onClick={() => setActiveFilter('VERIFIED_AGAINST_DEFINED_CHECKS')}
            className={`px-3 py-1 rounded-md text-xs font-medium transition-colors cursor-pointer flex items-center gap-1.5 ${
              activeFilter === 'VERIFIED_AGAINST_DEFINED_CHECKS'
                ? 'bg-white text-slate-900 shadow-2xs font-semibold'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
            <span>Verified ({stats.verified})</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveFilter('FAILED_VERIFICATION')}
            className={`px-3 py-1 rounded-md text-xs font-medium transition-colors cursor-pointer flex items-center gap-1.5 ${
              activeFilter === 'FAILED_VERIFICATION'
                ? 'bg-white text-slate-900 shadow-2xs font-semibold'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <span className="w-1.5 h-1.5 rounded-full bg-rose-500"></span>
            <span>Failed ({stats.failed})</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveFilter('INCONCLUSIVE')}
            className={`px-3 py-1 rounded-md text-xs font-medium transition-colors cursor-pointer flex items-center gap-1.5 ${
              activeFilter === 'INCONCLUSIVE'
                ? 'bg-white text-slate-900 shadow-2xs font-semibold'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <span className="w-1.5 h-1.5 rounded-full bg-amber-500"></span>
            <span>Inconclusive ({stats.inconclusive})</span>
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
              placeholder="Search run, finding, scanner..."
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

          {(activeFilter !== 'all' || searchQuery.trim()) && (
            <button
              type="button"
              onClick={() => {
                setActiveFilter('all');
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
            Showing <strong className="text-slate-800">{filteredRuns.length}</strong> of{' '}
            <strong className="text-slate-800">{stats.total}</strong> verification runs
          </span>
          <span className="text-slate-400 hidden sm:inline">
            Ephemeral workspaces with isolated environments
          </span>
        </div>

        {/* Empty State */}
        {filteredRuns.length === 0 ? (
          <EmptyState
            icon="verified_user"
            title={stats.total === 0 ? 'No verification runs recorded yet' : 'No verification runs match your filters'}
            description={
              stats.total === 0
                ? 'Select a security finding and trigger a verification run to validate candidate patches against defined scanner gates and automated tests.'
                : 'Try adjusting your search query or status filter to see other verification runs.'
            }
            actionLabel={stats.total === 0 ? 'Trigger Fix Verification' : 'Reset Filters'}
            onAction={
              stats.total === 0
                ? onOpenNewRunModal
                : () => {
                    setActiveFilter('all');
                    setSearchQuery('');
                  }
            }
          />
        ) : (
          /* Verification Runs Table */
          <div className="bg-white border border-slate-200 rounded-xl shadow-2xs overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-slate-50 border-b border-slate-200 text-slate-600 font-semibold">
                    <th className="py-3 px-4">Run &amp; Finding</th>
                    <th className="py-3 px-4">Scanner &amp; Tests</th>
                    <th className="py-3 px-4">Verification Status</th>
                    <th className="py-3 px-4">Source Hashes</th>
                    <th className="py-3 px-4">Result Summary</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {filteredRuns.map(run => (
                    <tr
                      key={run.id}
                      onClick={() => onOpenEvidenceModal && onOpenEvidenceModal(run)}
                      className="hover:bg-slate-50/80 transition-colors cursor-pointer group"
                    >
                      {/* Run ID & Finding */}
                      <td className="py-3.5 px-4 font-mono">
                        <div className="font-semibold text-slate-900 group-hover:text-blue-600 transition-colors">
                          {run.id}
                        </div>
                        <div className="text-blue-600 font-medium text-[11px] mt-0.5">
                          {run.finding_id || 'General Patch'}
                        </div>
                      </td>

                      {/* Scanner & Tests */}
                      <td className="py-3.5 px-4">
                        <div className="font-semibold text-slate-800">
                          {Object.keys(run.scanner_metadata || {}).join(', ') || 'Semgrep OSS'}
                        </div>
                        <div className="text-slate-500 text-[11px] font-mono mt-0.5">
                          {run.tests_executed?.length || 0} tests ({run.test_summary || 'pytest'})
                        </div>
                      </td>

                      {/* Status */}
                      <td className="py-3.5 px-4">
                        {renderStatusBadge(run.status)}
                      </td>

                      {/* Hashes */}
                      <td className="py-3.5 px-4 font-mono text-[11px]">
                        <div className="text-slate-700" title={run.baseline_hash}>
                          Base: {run.baseline_hash?.slice(0, 8) || '4b91f092'}...
                        </div>
                        <div className="text-slate-500 mt-0.5" title={run.patched_hash}>
                          Patch: {run.patched_hash?.slice(0, 8) || '7c82a194'}...
                        </div>
                      </td>

                      {/* Result Rationale */}
                      <td className="py-3.5 px-4 max-w-xs">
                        <p className="text-slate-600 truncate" title={run.reasons?.[0] || 'Verification completed against defined scanner rules.'}>
                          {run.reasons?.[0] || 'Verification completed against defined scanner rules.'}
                        </p>
                      </td>

                      {/* Actions */}
                      <td className="py-3.5 px-4 text-right font-mono" onClick={e => e.stopPropagation()}>
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            type="button"
                            onClick={() => onOpenEvidenceModal && onOpenEvidenceModal(run)}
                            className="px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-semibold text-xs shadow-2xs transition-colors cursor-pointer"
                          >
                            Inspect Evidence
                          </button>
                          {run.patch_diff && (
                            <button
                              type="button"
                              onClick={() => {
                                const legacyItem: VerificationItem = {
                                  id: run.id,
                                  repo: run.finding_id ? `Finding ${run.finding_id}` : 'Patch',
                                  branch: 'main',
                                  gitHash: run.baseline_hash?.slice(0, 7) || 'HEAD',
                                  engine: Object.keys(run.scanner_metadata || {})[0] || 'Verification Runner',
                                  target: run.finding_id,
                                  prNumber: undefined,
                                  findingsCount: {},
                                  status: run.status === 'VERIFIED_AGAINST_DEFINED_CHECKS' ? 'verified' : 'failed',
                                  message: run.reasons?.[0] || '',
                                  executionTime: run.test_summary || 'Completed',
                                  timestamp: run.completed_at ? new Date(run.completed_at).toLocaleTimeString() : 'Recently',
                                  diff: {
                                    filePath: 'candidate.patch',
                                    ruleId: run.classified_findings?.[0]?.rule_id || 'Verification Patch',
                                    oldCode: run.patch_diff ? [{ line: 1, text: run.patch_diff }] : [],
                                    newCode: [],
                                  },
                                };
                                onOpenDiffModal(legacyItem);
                              }}
                              className="px-2.5 py-1 rounded-lg bg-white hover:bg-slate-50 text-slate-700 text-xs font-medium border border-slate-200 transition-colors cursor-pointer"
                            >
                              Diff
                            </button>
                          )}
                        </div>
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
