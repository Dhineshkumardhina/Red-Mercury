import React, { useState, useMemo } from 'react';
import {
  Play,
  Download,
  ChevronRight,
  CheckCircle2,
  AlertTriangle,
  Search,
} from 'lucide-react';
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
  const [tableSearch, setTableSearch] = useState('');

  // Selected repository object (if a specific repo is filtered)
  const activeRepo = useMemo(() => {
    if (selectedRepoFilter === 'all') return null;
    return liveRepos.find(r => r.name === selectedRepoFilter) || null;
  }, [liveRepos, selectedRepoFilter]);

  // 1. Findings Stats (scoped to selected repo filter if active)
  const findingsStats = useMemo(() => {
    let list = liveFindings;
    if (activeRepo) {
      list = list.filter(f => f.repo_id === activeRepo.id);
    }
    if (list.length > 0) {
      const critical = list.filter(f => f.severity === 'CRITICAL').length;
      const high = list.filter(f => f.severity === 'HIGH').length;
      const medium = list.filter(f => f.severity === 'MEDIUM').length;
      const low = list.filter(f => f.severity === 'LOW').length;
      return { total: list.length, critical, high, medium, low };
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

  // 2. Verification Stats
  const verificationStats = useMemo(() => {
    const items = activeRepo
      ? verificationItems.filter(i => i.repo.toLowerCase().includes(activeRepo.name.toLowerCase()))
      : verificationItems;
    const verified = items.filter(i => i.status === 'verified').length;
    const failed = items.filter(i => i.status === 'failed').length;
    const inconclusive = items.filter(i => i.status === 'inconclusive').length;
    const total = verified + failed + inconclusive;
    const passRate = total > 0 ? Math.round((verified / total) * 100) : 100;
    return { verified, failed, inconclusive, total, passRate };
  }, [verificationItems, activeRepo]);

  // 3. Filtered Verification Items (Recent Gates)
  const filteredGates = useMemo(() => {
    return verificationItems.filter(item => {
      if (selectedRepoFilter !== 'all' && !item.repo.toLowerCase().includes(selectedRepoFilter.toLowerCase())) {
        return false;
      }
      if (!tableSearch) return true;
      const q = tableSearch.toLowerCase();
      return (
        item.repo.toLowerCase().includes(q) ||
        (item.prNumber && item.prNumber.toString().includes(q)) ||
        (item.gitHash && item.gitHash.toLowerCase().includes(q)) ||
        item.engine.toLowerCase().includes(q) ||
        item.message.toLowerCase().includes(q)
      );
    });
  }, [verificationItems, selectedRepoFilter, tableSearch]);

  // 4. Vulnerability Vectors (CWE Breakdown)
  const cweBreakdown = useMemo(() => {
    let list = liveFindings;
    if (activeRepo) {
      list = list.filter(f => f.repo_id === activeRepo.id);
    }
    if (list.length === 0) return [];
    const counts: Record<string, { count: number; name: string; severity: string }> = {};
    list.forEach(f => {
      const cweKey = f.cwe || 'General Security Finding';
      if (!counts[cweKey]) {
        counts[cweKey] = {
          count: 0,
          name: f.title || cweKey,
          severity: f.severity || 'MEDIUM',
        };
      }
      counts[cweKey].count += 1;
    });
    const total = list.length || 1;
    return Object.entries(counts).map(([cwe, info]) => ({
      cwe,
      name: info.name,
      count: info.count,
      percentage: Math.round((info.count / total) * 100),
      severity: info.severity,
      color:
        info.severity === 'CRITICAL'
          ? 'bg-rose-500'
          : info.severity === 'HIGH'
          ? 'bg-amber-500'
          : 'bg-blue-500',
    }));
  }, [liveFindings, activeRepo]);

  // Severity percentages for visual distribution bar
  const severityDistribution = useMemo(() => {
    const total = findingsStats.total || 1;
    return {
      criticalPct: Math.round((findingsStats.critical / total) * 100),
      highPct: Math.round((findingsStats.high / total) * 100),
      mediumPct: Math.round((findingsStats.medium / total) * 100),
      lowPct: Math.round((findingsStats.low / total) * 100),
    };
  }, [findingsStats]);

  const hasUrgentIssues = findingsStats.critical > 0 || findingsStats.high > 0;

  return (
    <div className="flex flex-col w-full pb-16 font-sans">
      {/* Top Header Action Ribbon */}
      <div className="px-4 lg:px-8 py-4 bg-white border-b border-slate-200 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-lg font-bold text-slate-900 tracking-tight font-sans">
              Security Overview
            </h1>
            {hasUrgentIssues ? (
              <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-50 text-rose-700 border border-rose-200">
                <span className="w-1.5 h-1.5 rounded-full bg-rose-600"></span>
                {findingsStats.critical} {findingsStats.critical === 1 ? 'Critical Issue' : 'Critical Issues'}
              </span>
            ) : (
              <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-600"></span>
                All Checks Passing
              </span>
            )}
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Workspace security posture, vulnerability findings, and branch protection.
          </p>
        </div>

        <div className="flex items-center gap-2.5 flex-wrap">
          {liveRepos.length > 0 && (
            <select
              value={selectedRepoFilter}
              onChange={e => setSelectedRepoFilter(e.target.value)}
              className="px-2.5 py-1.5 bg-slate-50 rounded-lg border border-slate-200 text-slate-800 text-xs font-medium focus:outline-hidden focus:border-slate-400 cursor-pointer"
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
            className="px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 text-slate-700 font-semibold text-xs border border-slate-200 shadow-2xs transition-colors cursor-pointer flex items-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5 text-slate-500" />
            <span>Export</span>
          </button>

          <button
            type="button"
            onClick={() => onOpenScanModal(selectedRepoFilter !== 'all' ? selectedRepoFilter : undefined)}
            className="px-3.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-semibold text-xs shadow-xs transition-colors cursor-pointer flex items-center gap-1.5"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>Run Scan</span>
          </button>
        </div>
      </div>

      {/* Main Body */}
      <div className="px-4 lg:px-8 py-5 space-y-5">
        {/* 4 Precision Metric Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
          {/* Card 1: Critical Risks */}
          <div
            onClick={() => onNavigateToFindings('severity=CRITICAL')}
            className="bg-white rounded-xl p-4 border border-slate-200 hover:border-rose-300 transition-all cursor-pointer group shadow-2xs flex flex-col justify-between"
          >
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider font-sans">
                Critical Findings
              </span>
              <span className="w-2 h-2 rounded-full bg-rose-500"></span>
            </div>
            <div className="my-2.5 flex items-baseline gap-2">
              <span className="text-2xl font-bold text-slate-900 tracking-tight font-sans">
                {findingsStats.critical}
              </span>
              <span className="text-xs text-rose-600 font-medium">Requires immediate patch</span>
            </div>
            <div className="text-[11px] text-slate-400 pt-2 border-t border-slate-100 flex items-center justify-between">
              <span>View critical findings</span>
              <ChevronRight className="w-3.5 h-3.5 text-slate-300 group-hover:text-slate-600 transition-colors" />
            </div>
          </div>

          {/* Card 2: High Risks */}
          <div
            onClick={() => onNavigateToFindings('severity=HIGH')}
            className="bg-white rounded-xl p-4 border border-slate-200 hover:border-amber-300 transition-all cursor-pointer group shadow-2xs flex flex-col justify-between"
          >
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider font-sans">
                High Severity
              </span>
              <span className="w-2 h-2 rounded-full bg-amber-500"></span>
            </div>
            <div className="my-2.5 flex items-baseline gap-2">
              <span className="text-2xl font-bold text-slate-900 tracking-tight font-sans">
                {findingsStats.high}
              </span>
              <span className="text-xs text-amber-700 font-medium">Elevated risk vulnerabilities</span>
            </div>
            <div className="text-[11px] text-slate-400 pt-2 border-t border-slate-100 flex items-center justify-between">
              <span>{findingsStats.medium} med • {findingsStats.low} low findings</span>
              <ChevronRight className="w-3.5 h-3.5 text-slate-300 group-hover:text-slate-600 transition-colors" />
            </div>
          </div>

          {/* Card 3: Gate Pass Rate */}
          <div
            onClick={() => onNavigateToQueue()}
            className="bg-white rounded-xl p-4 border border-slate-200 hover:border-emerald-300 transition-all cursor-pointer group shadow-2xs flex flex-col justify-between"
          >
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider font-sans">
                Verification Pass Rate
              </span>
              <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
            </div>
            <div className="my-2.5 flex items-baseline gap-2">
              <span className="text-2xl font-bold text-slate-900 tracking-tight font-sans">
                {verificationStats.total === 0 ? '100%' : `${verificationStats.passRate}%`}
              </span>
              <span className="text-xs text-emerald-700 font-medium">Patches passing all checks</span>
            </div>
            <div className="text-[11px] text-slate-400 pt-2 border-t border-slate-100 flex items-center justify-between">
              <span>{verificationStats.verified} verified of {verificationStats.total || 0} runs</span>
              <ChevronRight className="w-3.5 h-3.5 text-slate-300 group-hover:text-slate-600 transition-colors" />
            </div>
          </div>

          {/* Card 4: Monitored Repos */}
          <div
            onClick={() => onNavigateToRepositories()}
            className="bg-white rounded-xl p-4 border border-slate-200 hover:border-slate-300 transition-all cursor-pointer group shadow-2xs flex flex-col justify-between"
          >
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider font-sans">
                Monitored Repositories
              </span>
              <span className="w-2 h-2 rounded-full bg-slate-400"></span>
            </div>
            <div className="my-2.5 flex items-baseline gap-2">
              <span className="text-2xl font-bold text-slate-900 tracking-tight font-sans">
                {liveRepos.length}
              </span>
              <span className="text-xs text-slate-600 font-medium">Connected repositories</span>
            </div>
            <div className="text-[11px] text-slate-400 pt-2 border-t border-slate-100 flex items-center justify-between">
              <span>Automated branch protection active</span>
              <ChevronRight className="w-3.5 h-3.5 text-slate-300 group-hover:text-slate-600 transition-colors" />
            </div>
          </div>
        </div>

        {/* Section 1: Remediation Queue */}
        <div>
          <PrioritizedRemediationQueueCard
            onOpenDiffModal={onOpenDiffModal}
            onNavigateToFinding={() => onNavigateToFindings()}
            repoFilter={selectedRepoFilter !== 'all' ? selectedRepoFilter : undefined}
          />
        </div>

        {/* Section 2: Split Grid (Recent Pull Request Gates & Vulnerability Breakdown) */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
          {/* Left: Pull Request Gates (7 cols) */}
          <div className="lg:col-span-7 bg-white rounded-xl border border-slate-200 shadow-2xs overflow-hidden flex flex-col">
            <div className="px-4 py-3 border-b border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
              <div>
                <h2 className="text-sm font-bold text-slate-900 tracking-tight">
                  Branch &amp; Pull Request Gates
                </h2>
                <p className="text-xs text-slate-500">
                  Automated verification runs evaluated against test suites and security policies.
                </p>
              </div>

              {filteredGates.length > 0 && (
                <div className="relative">
                  <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
                  <input
                    type="text"
                    value={tableSearch}
                    onChange={e => setTableSearch(e.target.value)}
                    placeholder="Filter gates..."
                    className="pl-7 pr-2.5 py-1 text-xs bg-slate-50 border border-slate-200 rounded-md text-slate-800 focus:outline-hidden focus:border-slate-400 w-40 font-sans"
                  />
                </div>
              )}
            </div>

            {filteredGates.length === 0 ? (
              <div className="py-10 px-4 text-center flex flex-col items-center justify-center space-y-1 text-xs">
                <CheckCircle2 className="w-8 h-8 text-emerald-500 mb-1" />
                <span className="font-semibold text-slate-800">No Pending Verification Runs</span>
                <p className="text-slate-400 max-w-sm">
                  All pull requests have been verified, or no new patches are currently awaiting verification.
                </p>
              </div>
            ) : (
              <div className="overflow-x-auto w-full">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="bg-slate-50/80 text-slate-500 text-[11px] font-semibold uppercase tracking-wider border-b border-slate-200">
                      <th className="py-2.5 px-4 font-semibold">Repository &amp; Ref</th>
                      <th className="py-2.5 px-4 font-semibold">Scanner / Check</th>
                      <th className="py-2.5 px-4 font-semibold">Status</th>
                      <th className="py-2.5 px-4 font-semibold text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {filteredGates.slice(0, 5).map(item => (
                      <tr key={item.id} className="hover:bg-slate-50/70 transition-colors">
                        <td className="py-2.5 px-4">
                          <div className="font-semibold text-slate-900">{item.repo}</div>
                          <div className="text-[11px] font-mono text-slate-400 mt-0.5">
                            {item.branch} {item.gitHash && `• #${item.gitHash}`}
                          </div>
                        </td>

                        <td className="py-2.5 px-4">
                          <div className="text-slate-800 font-medium">{item.engine}</div>
                          <div className="text-[11px] text-slate-400 truncate max-w-xs">{item.message}</div>
                        </td>

                        <td className="py-2.5 px-4">
                          {item.status === 'verified' && (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-50 text-emerald-800 border border-emerald-200">
                              <span className="w-1.5 h-1.5 rounded-full bg-emerald-600"></span>
                              Verified
                            </span>
                          )}
                          {item.status === 'failed' && (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold bg-rose-50 text-rose-800 border border-rose-200">
                              <span className="w-1.5 h-1.5 rounded-full bg-rose-600"></span>
                              Blocked
                            </span>
                          )}
                          {item.status === 'inconclusive' && (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold bg-amber-50 text-amber-800 border border-amber-200">
                              <span className="w-1.5 h-1.5 rounded-full bg-amber-600"></span>
                              In Progress
                            </span>
                          )}
                        </td>

                        <td className="py-2.5 px-4 text-right">
                          <div className="flex items-center justify-end gap-1.5">
                            {item.status === 'verified' && (
                              <button
                                type="button"
                                onClick={() => onOpenDiffModal(item)}
                                className="px-2 py-1 rounded bg-emerald-50 hover:bg-emerald-100 text-emerald-800 text-xs font-semibold transition-colors border border-emerald-200 cursor-pointer"
                              >
                                View Diff
                              </button>
                            )}
                            {(item.status === 'failed' || item.status === 'inconclusive') && (
                              <button
                                type="button"
                                onClick={() => onOpenCrashModal(item)}
                                className="px-2 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold transition-colors border border-slate-200 cursor-pointer"
                              >
                                View Logs
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Right: Vulnerability Vectors (5 cols) */}
          <div className="lg:col-span-5 bg-white rounded-xl p-4 border border-slate-200 shadow-2xs space-y-3.5">
            <div className="flex items-center justify-between pb-2 border-b border-slate-100">
              <div>
                <h2 className="text-sm font-bold text-slate-900 tracking-tight">
                  Vulnerability Categories
                </h2>
                <p className="text-xs text-slate-500">Distribution across monitored repositories by CWE</p>
              </div>

              <button
                type="button"
                onClick={() => onNavigateToFindings()}
                className="text-xs text-blue-600 hover:text-blue-700 hover:underline font-semibold cursor-pointer flex items-center gap-0.5"
              >
                <span>View All</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* Severity Distribution Bar */}
            {findingsStats.total > 0 && (
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-xs text-slate-500 font-sans">
                  <span className="font-semibold text-slate-700">Severity Breakdown</span>
                  <span className="text-[11px] text-slate-500">{findingsStats.total} total</span>
                </div>
                <div className="h-1.5 w-full bg-slate-100 rounded-full overflow-hidden flex">
                  {severityDistribution.criticalPct > 0 && (
                    <div
                      style={{ width: `${severityDistribution.criticalPct}%` }}
                      className="bg-rose-500 h-full"
                      title={`Critical: ${findingsStats.critical}`}
                    />
                  )}
                  {severityDistribution.highPct > 0 && (
                    <div
                      style={{ width: `${severityDistribution.highPct}%` }}
                      className="bg-amber-500 h-full"
                      title={`High: ${findingsStats.high}`}
                    />
                  )}
                  {severityDistribution.mediumPct > 0 && (
                    <div
                      style={{ width: `${severityDistribution.mediumPct}%` }}
                      className="bg-blue-500 h-full"
                      title={`Medium: ${findingsStats.medium}`}
                    />
                  )}
                  {severityDistribution.lowPct > 0 && (
                    <div
                      style={{ width: `${severityDistribution.lowPct}%` }}
                      className="bg-slate-400 h-full"
                      title={`Low: ${findingsStats.low}`}
                    />
                  )}
                </div>
                <div className="flex items-center gap-3 text-[11px] text-slate-500 pt-0.5">
                  <span className="flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-rose-500"></span>
                    Critical ({findingsStats.critical})
                  </span>
                  <span className="flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-amber-500"></span>
                    High ({findingsStats.high})
                  </span>
                  <span className="flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-blue-500"></span>
                    Med ({findingsStats.medium})
                  </span>
                </div>
              </div>
            )}

            {/* CWE Categories List with Clean Progress Bars */}
            {cweBreakdown.length > 0 ? (
              <div className="space-y-1.5 pt-1 text-xs">
                {cweBreakdown.map(item => (
                  <button
                    key={item.cwe}
                    type="button"
                    onClick={() => onNavigateToFindings(item.cwe)}
                    className="w-full p-2 rounded-lg bg-slate-50 hover:bg-slate-100/80 border border-slate-200 transition-colors flex flex-col gap-1 text-left cursor-pointer group"
                  >
                    <div className="flex items-center justify-between w-full">
                      <span className="font-semibold text-slate-800 group-hover:text-blue-600 transition-colors truncate text-xs">
                        {item.cwe}
                      </span>
                      <span className="px-1.5 py-0.2 rounded bg-white border border-slate-200 font-bold text-slate-700 text-[10px] shrink-0 ml-2">
                        {item.count}
                      </span>
                    </div>
                    <div className="w-full bg-slate-200/80 rounded-full h-1 overflow-hidden">
                      <div
                        className={`h-full rounded-full ${item.color}`}
                        style={{ width: `${item.percentage}%` }}
                      />
                    </div>
                  </button>
                ))}
              </div>
            ) : (
              <div className="py-8 px-4 text-center rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-500">
                <CheckCircle2 className="w-8 h-8 text-emerald-500 mx-auto mb-1.5" />
                No vulnerabilities detected across monitored repositories.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
