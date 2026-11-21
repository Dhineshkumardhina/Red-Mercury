import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  CheckCircle2,
  Clock,
  AlertTriangle,
  Activity,
  Search,
  ArrowRight,
  GitCompare,
  RotateCw,
} from 'lucide-react';
import { api, RemediationQueueItem } from '../../services/api';
import { VerificationItem } from '../../types';

interface PrioritizedRemediationQueueCardProps {
  onOpenDiffModal?: (item: VerificationItem) => void;
  onNavigateToFinding?: (findingId: string) => void;
  repoFilter?: string;
}

export const PrioritizedRemediationQueueCard: React.FC<PrioritizedRemediationQueueCardProps> = ({
  onOpenDiffModal,
  onNavigateToFinding,
  repoFilter,
}) => {
  const navigate = useNavigate();
  const [allItems, setAllItems] = useState<RemediationQueueItem[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedPriority, setSelectedPriority] = useState<string>('all');
  const [isLoading, setIsLoading] = useState(true);

  const fetchQueue = () => {
    setIsLoading(true);
    api.getRemediationQueue()
      .then(items => {
        setAllItems(Array.isArray(items) ? items : []);
      })
      .catch(() => {
        setAllItems([]);
      })
      .finally(() => setIsLoading(false));
  };

  useEffect(() => {
    fetchQueue();
  }, []);

  // Filter items by repository if repoFilter is active
  const repoScopedItems = useMemo(() => {
    if (!repoFilter || repoFilter === 'all') return allItems;
    return allItems.filter(item =>
      item.repo_name?.toLowerCase().includes(repoFilter.toLowerCase())
    );
  }, [allItems, repoFilter]);

  const priorityCounts = useMemo(() => {
    return {
      all: repoScopedItems.length,
      critical: repoScopedItems.filter(i => i.contextual_priority?.toLowerCase() === 'critical').length,
      high: repoScopedItems.filter(i => i.contextual_priority?.toLowerCase() === 'high').length,
      medium: repoScopedItems.filter(i => i.contextual_priority?.toLowerCase() === 'medium').length,
      low: repoScopedItems.filter(i => i.contextual_priority?.toLowerCase() === 'low').length,
    };
  }, [repoScopedItems]);

  const filteredItems = useMemo(() => {
    return repoScopedItems.filter(item => {
      if (selectedPriority !== 'all' && item.contextual_priority?.toLowerCase() !== selectedPriority.toLowerCase()) {
        return false;
      }
      if (!searchQuery.trim()) return true;
      const q = searchQuery.toLowerCase();
      return (
        item.title?.toLowerCase().includes(q) ||
        item.repo_name?.toLowerCase().includes(q) ||
        item.file_path?.toLowerCase().includes(q) ||
        item.suggested_action?.toLowerCase().includes(q)
      );
    });
  }, [repoScopedItems, selectedPriority, searchQuery]);

  const handleRowClick = (findingId: string) => {
    if (onNavigateToFinding) {
      onNavigateToFinding(findingId);
    } else {
      navigate(`/findings/${findingId}`);
    }
  };

  const getPriorityBadge = (priority: string) => {
    const p = priority?.toUpperCase();
    switch (p) {
      case 'CRITICAL':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-bold bg-rose-50 text-rose-700 border border-rose-200">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-600"></span>
            CRITICAL
          </span>
        );
      case 'HIGH':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-bold bg-amber-50 text-amber-800 border border-amber-200">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-500"></span>
            HIGH
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-semibold bg-blue-50 text-blue-700 border border-blue-200">
            <span className="w-1.5 h-1.5 rounded-full bg-blue-500"></span>
            MEDIUM
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-medium bg-slate-100 text-slate-700 border border-slate-200">
            <span className="w-1.5 h-1.5 rounded-full bg-slate-400"></span>
            {p || 'LOW'}
          </span>
        );
    }
  };

  const getReadinessBadge = (status: string) => {
    switch (status) {
      case 'VERIFIED_FIX_READY':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-50 text-emerald-800 border border-emerald-200">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
            Patch Verified
          </span>
        );
      case 'PATCH_PENDING_REVIEW':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-medium bg-sky-50 text-sky-800 border border-sky-200">
            <Clock className="w-3.5 h-3.5 text-sky-600" />
            Pending Review
          </span>
        );
      case 'PATCH_FAILED_TESTS':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-semibold bg-rose-50 text-rose-800 border border-rose-200">
            <AlertTriangle className="w-3.5 h-3.5 text-rose-600" />
            Verification Failed
          </span>
        );
      case 'ANALYSIS_AVAILABLE':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-medium bg-slate-100 text-slate-700 border border-slate-200">
            <Activity className="w-3.5 h-3.5 text-slate-500" />
            Analysis Available
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-medium bg-slate-50 text-slate-600 border border-slate-200">
            <Search className="w-3.5 h-3.5 text-slate-400" />
            Triage Required
          </span>
        );
    }
  };

  return (
    <div className="rounded-xl bg-white border border-slate-200 shadow-2xs overflow-hidden">
      {/* Header with Title and Search */}
      <div className="px-4 py-3 bg-white border-b border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <h2 className="text-sm font-bold text-slate-900 tracking-tight font-sans">
            Remediation Queue
          </h2>
          <span className="px-2 py-0.5 rounded-full bg-slate-100 text-slate-600 text-[11px] font-medium border border-slate-200 font-sans">
            {repoScopedItems.length} open
          </span>
        </div>

        {/* Search & Actions */}
        <div className="flex items-center gap-2.5 flex-wrap">
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Filter queue..."
              className="pl-7 pr-2.5 py-1 text-xs bg-slate-50 hover:bg-slate-100/70 focus:bg-white border border-slate-200 focus:border-slate-400 rounded-md text-slate-800 placeholder-slate-400 w-44 sm:w-52 transition-colors focus:outline-hidden font-sans"
            />
          </div>

          <button
            type="button"
            onClick={() => navigate('/findings')}
            className="text-xs text-blue-600 hover:text-blue-700 hover:underline font-semibold flex items-center gap-0.5 cursor-pointer font-sans"
          >
            <span>All Findings</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Priority Filter Bar */}
      <div className="px-4 py-2 bg-slate-50/70 border-b border-slate-200 flex items-center gap-1.5 overflow-x-auto">
        <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mr-1 font-sans">
          Severity:
        </span>
        {(
          [
            { key: 'all', label: 'All', count: priorityCounts.all },
            { key: 'critical', label: 'Critical', count: priorityCounts.critical },
            { key: 'high', label: 'High', count: priorityCounts.high },
            { key: 'medium', label: 'Medium', count: priorityCounts.medium },
            { key: 'low', label: 'Low', count: priorityCounts.low },
          ] as const
        ).map(p => (
          <button
            key={p.key}
            type="button"
            onClick={() => setSelectedPriority(p.key)}
            className={`px-2.5 py-0.5 text-xs rounded-md font-medium transition-colors border flex items-center gap-1 cursor-pointer font-sans ${
              selectedPriority === p.key
                ? 'bg-slate-900 text-white border-slate-900 shadow-2xs font-semibold'
                : 'bg-white text-slate-600 hover:text-slate-900 border-slate-200 hover:bg-slate-100'
            }`}
          >
            <span>{p.label}</span>
            <span
              className={`text-[10px] px-1.5 py-0.2 rounded-full font-sans font-medium ${
                selectedPriority === p.key
                  ? 'bg-slate-700 text-slate-100'
                  : 'bg-slate-100 text-slate-500'
              }`}
            >
              {p.count}
            </span>
          </button>
        ))}
      </div>

      {/* Queue Items Table */}
      <div className="overflow-x-auto w-full">
        <table className="w-full text-left border-collapse text-xs font-sans">
          <thead>
            <tr className="bg-slate-50/80 border-b border-slate-200 text-[11px] font-semibold uppercase text-slate-500 tracking-wider font-sans">
              <th className="py-2.5 px-4 font-semibold w-28">Severity</th>
              <th className="py-2.5 px-4 font-semibold">Vulnerability &amp; Location</th>
              <th className="py-2.5 px-4 font-semibold w-40">Status</th>
              <th className="py-2.5 px-4 font-semibold w-32 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {isLoading ? (
              <tr>
                <td colSpan={4} className="py-8 text-center text-slate-400">
                  <div className="flex items-center justify-center gap-2 text-xs">
                    <RotateCw className="w-4 h-4 animate-spin text-slate-400" />
                    <span>Loading findings...</span>
                  </div>
                </td>
              </tr>
            ) : filteredItems.length === 0 ? (
              <tr>
                <td colSpan={4} className="py-8 text-center text-slate-500">
                  <div className="flex flex-col items-center justify-center space-y-1 text-xs">
                    <span className="font-semibold text-slate-700">No findings match filter</span>
                    <p className="text-slate-400">
                      {searchQuery
                        ? `No items found matching "${searchQuery}".`
                        : `No open findings match the selected filter.`}
                    </p>
                  </div>
                </td>
              </tr>
            ) : (
              filteredItems.map(item => (
                <tr
                  key={item.finding_id}
                  onClick={() => handleRowClick(item.finding_id)}
                  className="hover:bg-slate-50/70 transition-colors cursor-pointer group"
                >
                  {/* Severity */}
                  <td className="py-2.5 px-4 align-middle shrink-0">
                    {getPriorityBadge(item.contextual_priority)}
                  </td>

                  {/* Vulnerability Title & Location */}
                  <td className="py-2.5 px-4 align-middle">
                    <div className="min-w-0">
                      <div className="font-semibold text-slate-900 group-hover:text-blue-600 transition-colors text-xs truncate max-w-xl">
                        {item.title}
                      </div>

                      {/* Precise inline metadata */}
                      <div className="flex items-center gap-1.5 text-[11px] text-slate-500 mt-0.5 truncate max-w-xl">
                        <span className="font-medium text-slate-700">{item.repo_name}</span>
                        <span>•</span>
                        <span className="font-sans text-slate-600">{item.file_path}:{item.line_number}</span>
                        {item.suggested_action && (
                          <>
                            <span>•</span>
                            <span className="text-slate-400 truncate">{item.suggested_action}</span>
                          </>
                        )}
                      </div>
                    </div>
                  </td>

                  {/* Fix Readiness */}
                  <td className="py-2.5 px-4 align-middle">
                    {getReadinessBadge(item.remediation_status)}
                  </td>

                  {/* Action */}
                  <td className="py-2.5 px-4 align-middle text-right" onClick={e => e.stopPropagation()}>
                    <div className="flex items-center justify-end gap-1.5">
                      {item.linkage?.patch_proposal_id && onOpenDiffModal ? (
                        <button
                          type="button"
                          onClick={() => {
                            if (onOpenDiffModal) {
                              onOpenDiffModal({
                                id: item.finding_id,
                                repo: item.repo_name,
                                branch: 'main',
                                gitHash: 'HEAD',
                                engine: item.scanner_name,
                                target: item.file_path,
                                findingsCount: { critical: 1 },
                                status: 'verified',
                                message: item.title,
                                prNumber: 418,
                                executionTime: '1.2s',
                                timestamp: 'Just now',
                              });
                            }
                          }}
                          className="px-2.5 py-1 bg-emerald-600 hover:bg-emerald-700 text-white rounded text-xs font-semibold shadow-2xs transition-colors flex items-center gap-1.5 cursor-pointer"
                        >
                          <GitCompare className="w-3.5 h-3.5" />
                          <span>Review Patch</span>
                        </button>
                      ) : (
                        <button
                          type="button"
                          onClick={() => handleRowClick(item.finding_id)}
                          className="px-2.5 py-1 bg-white hover:bg-slate-100 border border-slate-200 text-slate-700 rounded text-xs font-medium transition-colors flex items-center gap-1 shadow-2xs cursor-pointer"
                        >
                          <span>View Finding</span>
                          <ArrowRight className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
