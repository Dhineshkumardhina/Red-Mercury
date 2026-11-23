import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { FixVerificationScreen } from '../components/verification/FixVerificationScreen';
import { VerificationEvidenceModal } from '../components/verification/VerificationEvidenceModal';
import { NewVerificationModal } from '../components/verification/NewVerificationModal';
import { DiffModal } from '../components/modals/DiffModal';
import { CrashInspectorModal } from '../components/modals/CrashInspectorModal';
import { VerificationItem } from '../types';
import { api, ApiVerificationRun } from '../services/api';

export const VerificationPage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const initialFindingIdParam = searchParams.get('finding_id') || undefined;

  const [items, setItems] = useState<VerificationItem[]>([]);
  const [liveRuns, setLiveRuns] = useState<ApiVerificationRun[]>([]);
  const [mergedPrs, setMergedPrs] = useState<Set<number>>(new Set());

  // Modals
  const [activeDiffItem, setActiveDiffItem] = useState<VerificationItem | null>(null);
  const [activeCrashItem, setActiveCrashItem] = useState<VerificationItem | null>(null);
  const [activeEvidenceRun, setActiveEvidenceRun] = useState<ApiVerificationRun | null>(null);
  const [isNewRunOpen, setIsNewRunOpen] = useState(Boolean(initialFindingIdParam));
  const [targetFindingId] = useState<string | undefined>(initialFindingIdParam);

  const [isMerging, setIsMerging] = useState(false);
  const [isRerunningSandbox, setIsRerunningSandbox] = useState(false);
  const [toastMessage, setToastMessage] = useState<{ text: string; type: 'success' | 'warning' | 'error' } | null>(null);

  const showToast = (text: string, type: 'success' | 'warning' | 'error' = 'success') => {
    setToastMessage({ text, type });
    setTimeout(() => setToastMessage(null), 4000);
  };

  useEffect(() => {
    api.getVerificationRuns()
      .then(runs => {
        setLiveRuns(Array.isArray(runs) ? runs : []);
      })
      .catch(() => {
        setLiveRuns([]);
      });
  }, []);

  const handleApproveAndMerge = async (id: string, prNumber?: number) => {
    if (isMerging) return;
    setIsMerging(true);
    try {
      const response = await api.approveAndMergeVerification(id);
      setMergedPrs(prev => new Set(prev).add(prNumber || 0));
      setItems(prev =>
        prev.map(item => item.id === id ? { ...item, status: 'verified', message: response.message || `PR #${prNumber} approved & merged.` } : item)
      );
      showToast(`✓ ${response.message || `Pull Request #${prNumber} approved and merged.`}`, 'success');
      if (activeDiffItem) setActiveDiffItem(null);
    } catch (err: any) {
      // Honest state: Red Mercury does not fabricate successful merges
      const errMsg = err?.message || 'Automated direct merge unavailable. Maintainers must merge directly on GitHub.';
      showToast(`⚠️ Direct Merge Unavailable: ${errMsg}`, 'warning');
    } finally {
      setIsMerging(false);
    }
  };

  const handleRerunTest = async (id: string) => {
    if (isRerunningSandbox) return;
    setIsRerunningSandbox(true);
    try {
      const run = await api.rerunVerification(id);
      const isVerified = run.status === 'VERIFIED_AGAINST_DEFINED_CHECKS';
      const newStatus = isVerified ? 'verified' : (run.status === 'FAILED_VERIFICATION' ? 'failed' : 'inconclusive');
      const updatedTimestamp = new Date(run.completed_at || run.started_at).toLocaleTimeString();
      const reasonMsg = run.reasons?.[0] || `Verification completed with status: ${run.status}`;

      // Update live runs list with fresh execution data from backend
      setLiveRuns(prev => {
        const idx = prev.findIndex(r => r.id === run.id);
        if (idx >= 0) {
          const updated = [...prev];
          updated[idx] = run;
          return updated;
        }
        return [run, ...prev];
      });

      // Update legacy items list
      setItems(prev =>
        prev.map(item =>
          item.id === id
            ? {
                ...item,
                status: newStatus,
                message: reasonMsg,
                timestamp: updatedTimestamp,
                executionTime: run.test_summary || '1.2s',
                unitTestsPassRate: run.test_summary || (isVerified ? 'All Tests Passed' : 'Test Regressions Detected'),
              }
            : item
        )
      );

      // Update activeCrashItem if currently open
      if (activeCrashItem && activeCrashItem.id === id) {
        setActiveCrashItem({
          ...activeCrashItem,
          status: newStatus,
          message: reasonMsg,
          crashReason: run.reasons?.join('; ') || 'Execution completed in sandbox.',
          timestamp: updatedTimestamp,
          executionTime: run.test_summary || '1.2s',
          unitTestsPassRate: run.test_summary || (isVerified ? 'Pass' : 'Fail'),
          crashLogs: [
            `[backend-sandbox] Rerun initiated at ${run.started_at}`,
            `[backend-sandbox] Baseline SHA: ${run.baseline_hash?.slice(0, 10)}... | Patched SHA: ${run.patched_hash?.slice(0, 10)}...`,
            `[backend-sandbox] Tests executed: ${run.tests_executed?.join(', ') || 'pytest'}`,
            `[backend-sandbox] Status: ${run.status}`,
            ...(run.execution_errors?.length ? run.execution_errors.map(e => `[ERROR] ${e}`) : []),
            `[backend-sandbox] Completed at ${run.completed_at || run.started_at}`,
          ],
        });
      }

      showToast(`✓ Sandbox rerun finished: ${run.status} (${run.test_summary || 'evaluated'})`, 'success');
    } catch (err: any) {
      showToast(`❌ Sandbox rerun failed: ${err.message}`, 'error');
    } finally {
      setIsRerunningSandbox(false);
    }
  };

  const handleNewRunCreated = (newRun: ApiVerificationRun) => {
    setLiveRuns(prev => [newRun, ...prev]);
    showToast(`✓ Fix Verification run ${newRun.id} completed with status: ${newRun.status}`, 'success');
    setActiveEvidenceRun(newRun);
  };

  return (
    <>
      {toastMessage && (
        <div className={`fixed bottom-5 right-5 z-50 px-4 py-3 rounded-lg shadow-lg font-sans font-medium text-xs flex items-center gap-2 animate-in fade-in slide-in-from-bottom-2 duration-200 ${
          toastMessage.type === 'error'
            ? 'bg-rose-950 border border-rose-700 text-rose-200'
            : toastMessage.type === 'warning'
            ? 'bg-amber-950 border border-amber-700 text-amber-200'
            : 'bg-slate-900 border border-slate-700 text-white'
        }`}>
          <span className={`w-2 h-2 rounded-full shrink-0 ${
            toastMessage.type === 'error'
              ? 'bg-rose-400'
              : toastMessage.type === 'warning'
              ? 'bg-amber-400'
              : 'bg-emerald-400'
          }`} />
          <span>{toastMessage.text}</span>
        </div>
      )}

      <FixVerificationScreen
        items={items}
        liveRuns={liveRuns}
        onOpenDiffModal={item => setActiveDiffItem(item)}
        onOpenCrashModal={item => setActiveCrashItem(item)}
        onOpenEvidenceModal={run => setActiveEvidenceRun(run)}
        onOpenNewRunModal={() => setIsNewRunOpen(true)}
        onApproveAndMerge={handleApproveAndMerge}
        mergedPrs={mergedPrs}
      />

      {/* Fix Verification Evidence Inspector Modal */}
      <VerificationEvidenceModal
        run={activeEvidenceRun}
        onClose={() => setActiveEvidenceRun(null)}
      />

      {/* New Fix Verification Trigger Modal */}
      <NewVerificationModal
        isOpen={isNewRunOpen}
        onClose={() => setIsNewRunOpen(false)}
        onSuccess={handleNewRunCreated}
        initialFindingId={targetFindingId}
      />

      {/* Legacy Diff Modal */}
      <DiffModal
        item={activeDiffItem}
        onClose={() => setActiveDiffItem(null)}
        onApproveAndMerge={handleApproveAndMerge}
        isMerged={activeDiffItem?.prNumber ? mergedPrs.has(activeDiffItem.prNumber) : false}
        isMerging={isMerging}
      />

      {/* Legacy Crash Modal */}
      <CrashInspectorModal
        item={activeCrashItem}
        onClose={() => setActiveCrashItem(null)}
        onRerun={handleRerunTest}
        isRerunning={isRerunningSandbox}
      />
    </>
  );
};
