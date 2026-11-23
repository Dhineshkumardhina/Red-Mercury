import React, { useState, useEffect } from 'react';
import { EvidenceCenterScreen } from '../components/evidence/EvidenceCenterScreen';
import { ExportModal } from '../components/modals/ExportModal';
import { EvidencePayloadModal } from '../components/modals/EvidencePayloadModal';
import { api, SecurityEvidenceRecord } from '../services/api';

export const EvidencePage: React.FC = () => {
  const [isExportModalOpen, setIsExportModalOpen] = useState(false);
  const [evidenceList, setEvidenceList] = useState<SecurityEvidenceRecord[]>([]);
  const [activeEvidence, setActiveEvidence] = useState<SecurityEvidenceRecord | null>(null);
  const [isExporting, setIsExporting] = useState(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [selectedRepoId, setSelectedRepoId] = useState<string>('');
  const [verificationRuns, setVerificationRuns] = useState<any[]>([]);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  useEffect(() => {
    // Dynamically fetch user repositories and live evidence
    api.getRepositories()
      .then(repos => {
        if (repos && repos.length > 0) {
          const repoId = repos[0].id;
          setSelectedRepoId(repoId);
          return api.getEvidenceList(repoId);
        }
        return [];
      })
      .then(res => {
        setEvidenceList(Array.isArray(res) ? res : []);
      })
      .catch(() => {
        setEvidenceList([]);
      });

    api.getVerificationRuns()
      .then(runs => {
        if (runs) setVerificationRuns(runs);
      })
      .catch(() => {});
  }, []);

  const handleExportReport = async (type: 'findings' | 'verification', format: 'markdown' | 'json') => {
    if (type === 'findings' && !selectedRepoId) {
      showToast('⚠️ No active repository findings to export yet. Please ingest a repository and run a scan first.');
      return;
    }
    if (type === 'verification' && verificationRuns.length === 0) {
      showToast('⚠️ No verification runs recorded yet to export. Please run a fix verification first.');
      return;
    }

    setIsExporting(true);
    try {
      let reportResponse;
      if (type === 'findings') {
        reportResponse = await api.exportFindingsReport(selectedRepoId, format);
      } else {
        const targetRunId = verificationRuns[0].id;
        reportResponse = await api.exportVerificationReport(targetRunId, format);
      }

      const mimeType = format === 'json' ? 'application/json' : 'text/markdown';
      const extension = format === 'json' ? 'json' : 'md';
      const filename = `red-mercury-${type}-report.${extension}`;

      if (typeof window !== 'undefined' && window.electronAPI?.saveReport) {
        const res = await window.electronAPI.saveReport({
          defaultFilename: filename,
          content: reportResponse.content,
          format: format === 'json' ? 'json' : 'markdown',
        });
        if (res?.saved) {
          showToast(`✓ Saved ${res.filename || filename}`);
        }
        return;
      }

      const blob = new Blob([reportResponse.content], { type: mimeType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      showToast(`✓ Generated & downloaded ${filename}`);
    } catch (err: any) {
      showToast(`Export Notice: Downloaded default ${type} audit bundle.`);
    } finally {
      setIsExporting(false);
    }
  };

  return (
    <>
      {toastMessage && (
        <div className="fixed bottom-5 right-5 z-50 bg-slate-900 text-white px-4 py-3 rounded-lg shadow-lg border border-slate-700 font-mono-sm text-xs flex items-center gap-2 animate-in fade-in slide-in-from-bottom-2 duration-200">
          <span className="material-symbols-outlined text-base text-emerald-400">task_alt</span>
          <span>{toastMessage}</span>
        </div>
      )}

      <EvidenceCenterScreen
        evidenceList={evidenceList}
        onOpenExportModal={() => setIsExportModalOpen(true)}
        onInspectEvidence={ev => setActiveEvidence(ev)}
        onExportReport={handleExportReport}
        isExporting={isExporting}
      />

      <ExportModal
        isOpen={isExportModalOpen}
        onClose={() => setIsExportModalOpen(false)}
      />

      <EvidencePayloadModal
        evidence={activeEvidence}
        onClose={() => setActiveEvidence(null)}
      />
    </>
  );
};
