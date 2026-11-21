import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, RemediationQueueItem } from '../../services/api';
import { VerificationItem } from '../../types';

interface PrioritizedRemediationQueueCardProps {
  onOpenDiffModal?: (item: VerificationItem) => void;
  onNavigateToFinding?: (findingId: string) => void;
  repoFilter?: string;
}

const PRIORITY_STYLES: Record<string, string> = {
  CRITICAL: 'text-rose-700 bg-rose-50 border-rose-200',
  HIGH: 'text-amber-700 bg-amber-50 border-amber-200',
  MEDIUM: 'text-blue-700 bg-blue-50 border-blue-200',
  LOW: 'text-slate-600 bg-slate-50 border-slate-200',
};

const STATUS_LABELS: Record<string, string> = {
  VERIFIED_FIX_READY: 'Patch verified',
  PATCH_PENDING_REVIEW: 'Pending review',
  PATCH_FAILED_TESTS: 'Tests failed',
  ANALYSIS_AVAILABLE: 'Analyzed',
};

export const PrioritizedRemediationQueueCard: React.FC<PrioritizedRemediationQueueCardProps> = ({
  onOpenDiffModal,
  onNavigateToFinding,
  repoFilter,
}) => {
  const navigate = useNavigate();
  const [allItems, setAllItems] = useState<RemediationQueueItem[]>([]);
  const [selectedPriority, setSelectedPriority] = useState<string>('all');
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    let active = true;
    setIsLoading(true);
    api.getRemediationQueue()
      .then(items => {
        if (active) setAllItems(Array.isArray(items) ? items : []);
      })
      .catch(() => {
        if (active) setAllItems([]);
      })
      .finally(() => {
        if (active) setIsLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  const repoScopedItems = useMemo(() => {
    if (!repoFilter || repoFilter === 'all') return allItems;
    const target = repoFilter.toLowerCase();
    return allItems.filter(item => item.repo_name?.toLowerCase().includes(target));
  }, [allItems, repoFilter]);

  const filteredItems = useMemo(() => {
    if (selectedPriority === 'all') return repoScopedItems;
    return repoScopedItems.filter(
      item => item.contextual_priority?.toLowerCase() === selectedPriority
    );
  }, [repoScopedItems, selectedPriority]);

  const handleRowClick = (findingId: string) => {
    if (onNavigateToFinding) {
      onNavigateToFinding(findingId);
    } else {
      navigate(`/findings/${findingId}`);
    }
  };

  return (
    <div className="rounded-lg bg-white border border-slate-200 overflow-hidden">
      <div className="px-4 py-3 border-b border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div className="flex items-center gap-3">
          <h2 className="text-sm font-semibold text-slate-900">Remediation Queue</h2>
          <div className="flex items-center gap-1">
            {(['all', 'critical', 'high', 'medium', 'low'] as const).map(level => (
              <button
                key={level}
                type="button"
                onClick={() => setSelectedPriority(level)}
                className={`px-2 py-0.5 text-xs rounded capitalize cursor-pointer transition-colors ${
                  selectedPriority === level
                    ? 'bg-slate-900 text-white font-medium'
                    : 'text-slate-600 hover:bg-slate-100'
                }`}
              >
                {level}
              </button>
            ))}
          </div>
        </div>

        <button
          type="button"
          onClick={() => navigate('/findings')}
          className="text-xs text-slate-600 hover:text-slate-900 font-medium cursor-pointer self-start sm:self-auto"
        >
          All findings
        </button>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse text-xs">
          <thead>
            <tr className="bg-slate-50 border-b border-slate-200 text-slate-500">
              <th className="py-2 px-4 font-medium w-24">Severity</th>
              <th className="py-2 px-4 font-medium">Finding</th>
              <th className="py-2 px-4 font-medium w-36">Status</th>
              <th className="py-2 px-4 font-medium w-28 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {isLoading ? (
              <tr>
                <td colSpan={4} className="py-6 text-center text-slate-400">
                  Loading...
                </td>
              </tr>
            ) : filteredItems.length === 0 ? (
              <tr>
                <td colSpan={4} className="py-6 text-center text-slate-500">
                  No open items in queue.
                </td>
              </tr>
            ) : (
              filteredItems.map(item => {
                const priority = (item.contextual_priority || 'LOW').toUpperCase();
                return (
                  <tr
                    key={item.finding_id}
                    onClick={() => handleRowClick(item.finding_id)}
                    className="hover:bg-slate-50/70 cursor-pointer"
                  >
                    <td className="py-2.5 px-4">
                      <span
                        className={`inline-block px-1.5 py-0.5 rounded text-[11px] font-medium border ${
                          PRIORITY_STYLES[priority] || PRIORITY_STYLES.LOW
                        }`}
                      >
                        {priority}
                      </span>
                    </td>
                    <td className="py-2.5 px-4">
                      <div className="font-medium text-slate-900 truncate max-w-xl">
                        {item.title}
                      </div>
                      <div className="text-[11px] text-slate-500 mt-0.5 truncate max-w-xl">
                        {item.repo_name} · {item.file_path}:{item.line_number}
                      </div>
                    </td>
                    <td className="py-2.5 px-4 text-slate-600">
                      {STATUS_LABELS[item.remediation_status] || 'Needs triage'}
                    </td>
                    <td className="py-2.5 px-4 text-right" onClick={e => e.stopPropagation()}>
                      {item.linkage?.patch_proposal_id && onOpenDiffModal ? (
                        <button
                          type="button"
                          onClick={() =>
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
                              executionTime: '1.2s',
                              timestamp: 'Just now',
                            })
                          }
                          className="px-2.5 py-1 bg-slate-900 hover:bg-slate-800 text-white rounded text-xs font-medium cursor-pointer"
                        >
                          Review
                        </button>
                      ) : (
                        <button
                          type="button"
                          onClick={() => handleRowClick(item.finding_id)}
                          className="px-2.5 py-1 bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 rounded text-xs font-medium cursor-pointer"
                        >
                          Open
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
