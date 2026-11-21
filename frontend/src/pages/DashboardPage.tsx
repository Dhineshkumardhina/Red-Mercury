import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { DashboardScreen } from '../components/dashboard/DashboardScreen';
import { DiffModal } from '../components/modals/DiffModal';
import { CrashInspectorModal } from '../components/modals/CrashInspectorModal';
import { ScanModal } from '../components/modals/ScanModal';
import { ExportModal } from '../components/modals/ExportModal';
import { VerificationItem, VerificationStatus } from '../types';
import { api, ApiRepository, ApiFinding } from '../services/api';

export const DashboardPage: React.FC = () => {
  const navigate = useNavigate();

  const [verificationItems, setVerificationItems] = useState<VerificationItem[]>([]);
  const [mergedPrs, setMergedPrs] = useState<Set<number>>(new Set());
  const [isMerging, setIsMerging] = useState(false);
  const [toastMessage, setToastMessage] = useState<{ text: string; type: 'success' | 'warning' | 'error' } | null>(null);

  // Live backend data
  const [liveRepos, setLiveRepos] = useState<ApiRepository[]>([]);
  const [liveFindings, setLiveFindings] = useState<ApiFinding[]>([]);
  const [isLoadingLive, setIsLoadingLive] = useState(true);

  // Modals
  const [activeDiffItem, setActiveDiffItem] = useState<VerificationItem | null>(null);
  const [activeCrashItem, setActiveCrashItem] = useState<VerificationItem | null>(null);
  const [isScanModalOpen, setIsScanModalOpen] = useState(false);
  const [isExportModalOpen, setIsExportModalOpen] = useState(false);
  const [scanTargetName, setScanTargetName] = useState('All Monitored Repositories');
  const [selectedScanRepoId, setSelectedScanRepoId] = useState<string>('');
  const [isRerunningSandbox, setIsRerunningSandbox] = useState(false);

  const refreshLiveDashboard = () => {
    setIsLoadingLive(true);
    Promise.all([
      api.getRepositories().catch(() => [] as ApiRepository[]),
      api.getFindings().catch(() => [] as ApiFinding[]),
      api.getVerificationRuns().catch(() => [] as any[]),
    ])
      .then(([repos, findings, runs]) => {
        setLiveRepos(repos || []);
        setLiveFindings(findings || []);
        if (Array.isArray(runs) && runs.length > 0) {
          const mappedItems: VerificationItem[] = runs.map(r => ({
            id: r.id,
            repo: r.finding_id ? `Finding ${r.finding_id}` : 'Patch',
            branch: 'main',
            gitHash: r.baseline_hash?.slice(0, 7) || 'HEAD',
            engine: Object.keys(r.scanner_metadata || {})[0] || 'Verification Runner',
            target: r.finding_id || 'Verification Check',
            findingsCount: {},
            status: (r.status === 'VERIFIED_AGAINST_DEFINED_CHECKS' ? 'verified' : r.status === 'FAILED_VERIFICATION' ? 'failed' : 'inconclusive') as VerificationStatus,
            message: r.reasons?.[0] || 'Verification completed.',
            executionTime: r.test_summary || '1.2s',
            timestamp: r.completed_at ? new Date(r.completed_at).toLocaleTimeString() : 'Recently',
            prNumber: undefined,
            diff: r.patch_diff ? {
              filePath: 'patch.diff',
              ruleId: 'verification.patch',
              oldCode: [{ line: 1, text: r.patch_diff }],
              newCode: [],
            } : undefined,
          }));
          setVerificationItems(mappedItems);
        } else {
          setVerificationItems([]);
        }
      })
      .finally(() => setIsLoadingLive(false));
  };

  useEffect(() => {
    refreshLiveDashboard();
  }, []);

  const showToast = (text: string, type: 'success' | 'warning' | 'error' = 'success') => {
    setToastMessage({ text, type });
    setTimeout(() => setToastMessage(null), 4000);
  };

  const handleApproveAndMerge = async (id: string, prNumber?: number) => {
    if (isMerging) return;
    setIsMerging(true);
    try {
      const response = await api.approveAndMergeVerification(id);
      setMergedPrs(prev => new Set(prev).add(prNumber || 0));
      setVerificationItems(prev =>
        prev.map(item =>
          item.id === id
            ? {
                ...item,
                status: 'verified',
                message: response.message || `PR #${prNumber} approved & successfully merged into default branch.`,
              }
            : item
        )
      );
      showToast(response.message || `Pull Request #${prNumber} approved and merged.`, 'success');
      if (activeDiffItem) setActiveDiffItem(null);
    } catch (err: any) {
      const errMsg = err?.message || 'Automated merge unavailable. Merge directly on GitHub.';
      showToast(errMsg, 'warning');
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

      setVerificationItems(prev =>
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

      showToast(`Sandbox rerun finished: ${run.status}`, 'success');
    } catch (err: any) {
      showToast(`Sandbox rerun failed: ${err.message}`, 'error');
    } finally {
      setIsRerunningSandbox(false);
    }
  };

  return (
    <>
      {toastMessage && (
        <div
          className={`fixed bottom-5 right-5 z-50 px-3.5 py-2.5 rounded-md shadow-md text-xs font-medium border ${
            toastMessage.type === 'error'
              ? 'bg-rose-950 border-rose-800 text-rose-100'
              : toastMessage.type === 'warning'
              ? 'bg-amber-950 border-amber-800 text-amber-100'
              : 'bg-slate-900 border-slate-700 text-white'
          }`}
        >
          {toastMessage.text}
        </div>
      )}

      <DashboardScreen
        verificationItems={verificationItems}
        liveRepos={liveRepos}
        liveFindings={liveFindings}
        isLoadingLive={isLoadingLive}
        onOpenDiffModal={item => setActiveDiffItem(item)}
        onOpenCrashModal={item => setActiveCrashItem(item)}
        onOpenScanModal={(target) => {
          const matchedRepo = liveRepos.find(r => r.name === target);
          setScanTargetName(target || 'All Monitored Repositories');
          setSelectedScanRepoId(matchedRepo?.id || '');
          setIsScanModalOpen(true);
        }}
        onOpenExportModal={() => setIsExportModalOpen(true)}
        onNavigateToQueue={() => navigate('/verification')}
        onNavigateToFindings={filter => {
          if (filter?.startsWith('severity=')) {
            navigate(`/findings?${filter}`);
          } else if (filter) {
            navigate(`/findings?cwe=${encodeURIComponent(filter)}`);
          } else {
            navigate('/findings');
          }
        }}
        onNavigateToRepositories={() => navigate('/repositories')}
        onApproveAndMerge={handleApproveAndMerge}
        mergedPrs={mergedPrs}
        onShowToast={msg => showToast(msg, 'success')}
      />

      {/* Modals */}
      <DiffModal
        item={activeDiffItem}
        onClose={() => setActiveDiffItem(null)}
        onApproveAndMerge={handleApproveAndMerge}
        isMerged={activeDiffItem?.prNumber ? mergedPrs.has(activeDiffItem.prNumber) : false}
        isMerging={isMerging}
      />

      <CrashInspectorModal
        item={activeCrashItem}
        onClose={() => setActiveCrashItem(null)}
        onRerun={handleRerunTest}
        isRerunning={isRerunningSandbox}
      />

      <ScanModal
        isOpen={isScanModalOpen}
        onClose={() => setIsScanModalOpen(false)}
        onScanComplete={() => {
          showToast('✓ Security scan completed. Repository metrics updated.');
          refreshLiveDashboard();
          setIsScanModalOpen(false);
        }}
        targetRepoName={scanTargetName}
        targetRepoId={selectedScanRepoId}
      />

      <ExportModal
        isOpen={isExportModalOpen}
        onClose={() => setIsExportModalOpen(false)}
        findings={liveFindings}
        repositories={liveRepos}
      />
    </>
  );
};
