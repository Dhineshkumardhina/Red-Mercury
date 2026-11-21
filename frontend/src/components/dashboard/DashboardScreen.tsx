import React, { useState, useMemo } from 'react';
import { Play, Download } from 'lucide-react';
import { VerificationItem } from '../../types';
import { ApiRepository, ApiFinding } from '../../services/api';
import { PrioritizedRemediationQueueCard } from './PrioritizedRemediationQueueCard';

interface DashboardScreenProps {
  verificationItems: VerificationItem[];
  liveRepos?: ApiRepository[];
  liveFindings?: ApiFinding[];
  isLoadingLive?: boolean;
  onOpenDiffModal: (item: VerificationItem) => void;
  onOpenCrashModal: (item: VerificationItem) => void;
  onOpenScanModal: (target?: string) => void;
  onOpenExportModal: () => void;
  onNavigateToQueue: () => void;
  onNavigateToFindings: (filter?: string) => void;
  onNavigateToRepositories: () => void;
  onApproveAndMerge?: (id: string, prNumber?: number) => void;
  mergedPrs?: Set<number>;
  onShowToast?: (message: string) => void;
}

export const DashboardScreen: React.FC<DashboardScreenProps> = ({
  verificationItems,
  liveRepos = [],
  liveFindings = [],
  onOpenDiffModal,
  onOpenCrashModal,
  onOpenScanModal,
  onOpenExportModal,
  onNavigateToQueue,
  onNavigateToFindings,
  onNavigateToRepositories,
}) => {
  const [selectedRepoFilter, setSelectedRepoFilter] = useState<string>('all');

  const activeRepo = useMemo(() => {
    if (selectedRepoFilter === 'all') return null;
    return liveRepos.find(r => r.name === selectedRepoFilter) || null;
  }, [liveRepos, selectedRepoFilter]);

  const findingsStats = useMemo(() => {
    const list = activeRepo
      ? liveFindings.filter(f => f.repo_id === activeRepo.id)
      : liveFindings;

    if (list.length > 0) {
      return {
        total: list.length,
        critical: list.filter(f => f.severity === 'CRITICAL').length,
        high: list.filter(f => f.severity === 'HIGH').length,
        medium: list.filter(f => f.severity === 'MEDIUM').length,
        low: list.filter(f => f.severity === 'LOW').length,
      };
    }

    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;
    const items = activeRepo
      ? verificationItems.filter(i => i.repo.toLowerCase().includes(activeRepo.name.toLowerCase()))
      : verificationItems;

    items.forEach(item => {
      critical += item.findingsCount.critical || 0;
      high += item.findingsCount.high || 0;
      medium += item.findingsCount.med || 0;
      low += item.findingsCount.low || 0;
    });
    return { total: critical + high + medium + low, critical, high, medium, low };
  }, [liveFindings, verificationItems, activeRepo]);

  const verificationStats = useMemo(() => {
    const items = activeRepo
      ? verificationItems.filter(i => i.repo.toLowerCase().includes(activeRepo.name.toLowerCase()))
      : verificationItems;
    const verified = items.filter(i => i.status === 'verified').length;
    const failed = items.filter(i => i.status === 'failed').length;
    const inconclusive = items.filter(i => i.status === 'inconclusive').length;
    const total = verified + failed + inconclusive;
    const passRate = total > 0 ? Math.round((verified / total) * 100) : null;
    return { verified, failed, inconclusive, total, passRate };
  }, [verificationItems, activeRepo]);

  const filteredGates = useMemo(() => {
    if (selectedRepoFilter === 'all') return verificationItems;
    const target = selectedRepoFilter.toLowerCase();
    return verificationItems.filter(item => item.repo.toLowerCase().includes(target));
  }, [verificationItems, selectedRepoFilter]);

  const cweBreakdown = useMemo(() => {
    const list = activeRepo
      ? liveFindings.filter(f => f.repo_id === activeRepo.id)
      : liveFindings;
    if (list.length === 0) return [];

    const counts: Record<string, number> = {};
    list.forEach(f => {
      const key = f.cwe || 'Uncategorized';
      counts[key] = (counts[key] || 0) + 1;
    });

    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([cwe, count]) => ({ cwe, count }));
  }, [liveFindings, activeRepo]);

  return (
    <div className="flex flex-col w-full pb-12 font-sans">
      <div className="px-4 lg:px-8 py-4 bg-white border-b border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <h1 className="text-lg font-semibold text-slate-900 tracking-tight">
          Security Overview
        </h1>

        <div className="flex items-center gap-2 flex-wrap">
          {liveRepos.length > 0 && (
            <select
              aria-label="Filter by repository"
              value={selectedRepoFilter}
              onChange={e => setSelectedRepoFilter(e.target.value)}
              className="px-2.5 py-1.5 bg-white rounded-md border border-slate-200 text-slate-700 text-xs font-medium focus:outline-hidden focus:border-slate-400 cursor-pointer"
            >
              <option value="all">All Repositories ({liveRepos.length})</option>
              {liveRepos.map(r => (
                <option key={r.id} value={r.name}>
                  {r.name}
                </option>
              ))}
            </select>
          )}

          <button
            type="button"
            onClick={onOpenExportModal}
            className="px-3 py-1.5 rounded-md bg-white hover:bg-slate-50 text-slate-700 font-medium text-xs border border-slate-200 transition-colors cursor-pointer flex items-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5 text-slate-500" />
            <span>Export</span>
          </button>

          <button
            type="button"
            onClick={() => onOpenScanModal(selectedRepoFilter !== 'all' ? selectedRepoFilter : undefined)}
            className="px-3 py-1.5 rounded-md bg-slate-900 hover:bg-slate-800 text-white font-medium text-xs transition-colors cursor-pointer flex items-center gap-1.5"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>Run Scan</span>
          </button>
        </div>
      </div>

      <div className="px-4 lg:px-8 py-6 space-y-6">
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <button
            type="button"
            onClick={() => onNavigateToFindings('severity=CRITICAL')}
            className="bg-white rounded-lg p-4 border border-slate-200 hover:border-slate-300 transition-colors text-left cursor-pointer"
          >
            <div className="text-xs font-medium text-slate-500">Critical</div>
            <div className={`text-2xl font-semibold mt-1 tabular-nums ${findingsStats.critical > 0 ? 'text-rose-600' : 'text-slate-900'}`}>
              {findingsStats.critical}
            </div>
            <div className="text-xs text-slate-400 mt-1">
              {findingsStats.total} total findings
            </div>
          </button>

          <button
            type="button"
            onClick={() => onNavigateToFindings('severity=HIGH')}
            className="bg-white rounded-lg p-4 border border-slate-200 hover:border-slate-300 transition-colors text-left cursor-pointer"
          >
            <div className="text-xs font-medium text-slate-500">High</div>
            <div className={`text-2xl font-semibold mt-1 tabular-nums ${findingsStats.high > 0 ? 'text-amber-600' : 'text-slate-900'}`}>
              {findingsStats.high}
            </div>
            <div className="text-xs text-slate-400 mt-1">
              {findingsStats.medium} medium, {findingsStats.low} low
            </div>
          </button>

          <button
            type="button"
            onClick={onNavigateToQueue}
            className="bg-white rounded-lg p-4 border border-slate-200 hover:border-slate-300 transition-colors text-left cursor-pointer"
          >
            <div className="text-xs font-medium text-slate-500">Verification</div>
            <div className="text-2xl font-semibold text-slate-900 mt-1 tabular-nums">
              {verificationStats.passRate !== null ? `${verificationStats.passRate}%` : '—'}
            </div>
            <div className="text-xs text-slate-400 mt-1">
              {verificationStats.verified} of {verificationStats.total} passed
            </div>
          </button>

          <button
            type="button"
            onClick={onNavigateToRepositories}
            className="bg-white rounded-lg p-4 border border-slate-200 hover:border-slate-300 transition-colors text-left cursor-pointer"
          >
            <div className="text-xs font-medium text-slate-500">Repositories</div>
            <div className="text-2xl font-semibold text-slate-900 mt-1 tabular-nums">
              {liveRepos.length}
            </div>
            <div className="text-xs text-slate-400 mt-1">Monitored</div>
          </button>
        </div>

        <PrioritizedRemediationQueueCard
          onOpenDiffModal={onOpenDiffModal}
          onNavigateToFinding={() => onNavigateToFindings()}
          repoFilter={selectedRepoFilter !== 'all' ? selectedRepoFilter : undefined}
        />

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          <div className="lg:col-span-7 bg-white rounded-lg border border-slate-200 overflow-hidden">
            <div className="px-4 py-3 border-b border-slate-200 flex items-center justify-between">
              <h2 className="text-sm font-semibold text-slate-900">Recent Verification Runs</h2>
              <button
                type="button"
                onClick={onNavigateToQueue}
                className="text-xs text-slate-600 hover:text-slate-900 font-medium cursor-pointer"
              >
                View all
              </button>
            </div>

            {filteredGates.length === 0 ? (
              <div className="py-8 px-4 text-center text-xs text-slate-500">
                No verification runs yet.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="bg-slate-50 text-slate-500 border-b border-slate-200">
                      <th className="py-2 px-4 font-medium">Target</th>
                      <th className="py-2 px-4 font-medium">Check</th>
                      <th className="py-2 px-4 font-medium">Status</th>
                      <th className="py-2 px-4 font-medium text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {filteredGates.slice(0, 5).map(item => (
                      <tr key={item.id} className="hover:bg-slate-50/70">
                        <td className="py-2.5 px-4">
                          <div className="font-medium text-slate-900">{item.repo}</div>
                          <div className="text-[11px] font-mono text-slate-400">
                            {item.branch}{item.gitHash ? ` · ${item.gitHash}` : ''}
                          </div>
                        </td>
                        <td className="py-2.5 px-4">
                          <div className="text-slate-700">{item.engine}</div>
                          <div className="text-[11px] text-slate-400 truncate max-w-xs">{item.message}</div>
                        </td>
                        <td className="py-2.5 px-4">
                          {item.status === 'verified' && (
                            <span className="text-xs font-medium text-emerald-700">Verified</span>
                          )}
                          {item.status === 'failed' && (
                            <span className="text-xs font-medium text-rose-700">Failed</span>
                          )}
                          {item.status === 'inconclusive' && (
                            <span className="text-xs font-medium text-amber-700">Pending</span>
                          )}
                        </td>
                        <td className="py-2.5 px-4 text-right">
                          {item.status === 'verified' ? (
                            <button
                              type="button"
                              onClick={() => onOpenDiffModal(item)}
                              className="px-2 py-1 rounded bg-white hover:bg-slate-50 text-slate-700 text-xs font-medium border border-slate-200 cursor-pointer"
                            >
                              Diff
                            </button>
                          ) : (
                            <button
                              type="button"
                              onClick={() => onOpenCrashModal(item)}
                              className="px-2 py-1 rounded bg-white hover:bg-slate-50 text-slate-700 text-xs font-medium border border-slate-200 cursor-pointer"
                            >
                              Logs
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="lg:col-span-5 bg-white rounded-lg border border-slate-200 overflow-hidden">
            <div className="px-4 py-3 border-b border-slate-200 flex items-center justify-between">
              <h2 className="text-sm font-semibold text-slate-900">Top Categories</h2>
              <button
                type="button"
                onClick={() => onNavigateToFindings()}
                className="text-xs text-slate-600 hover:text-slate-900 font-medium cursor-pointer"
              >
                All findings
              </button>
            </div>

            {cweBreakdown.length > 0 ? (
              <div className="divide-y divide-slate-100">
                {cweBreakdown.map(item => (
                  <button
                    key={item.cwe}
                    type="button"
                    onClick={() => onNavigateToFindings(item.cwe)}
                    className="w-full px-4 py-2.5 hover:bg-slate-50 transition-colors flex items-center justify-between text-left cursor-pointer"
                  >
                    <span className="text-xs text-slate-700 truncate pr-3">{item.cwe}</span>
                    <span className="text-xs font-medium text-slate-500 tabular-nums shrink-0">
                      {item.count}
                    </span>
                  </button>
                ))}
              </div>
            ) : (
              <div className="py-8 px-4 text-center text-xs text-slate-500">
                No findings recorded.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
