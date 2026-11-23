import React, { useState, useEffect } from 'react';
import { ArrowDownCircle, RefreshCw, X, Download, ShieldCheck } from 'lucide-react';
import type { UpdateStatus, UpdateProgress } from '../../types/electron';

export const UpdateNotification: React.FC = () => {
  const [updateStatus, setUpdateStatus] = useState<UpdateStatus | null>(null);
  const [progress, setProgress] = useState<UpdateProgress | null>(null);
  const [isDismissed, setIsDismissed] = useState(false);
  const [isActionLoading, setIsActionLoading] = useState(false);

  useEffect(() => {
    if (typeof window === 'undefined' || !window.electronAPI?.getUpdateStatus) {
      return;
    }

    let mounted = true;
    window.electronAPI.getUpdateStatus()
      .then((status) => {
        if (mounted && status) setUpdateStatus(status);
      })
      .catch(() => {});

    const unsubStatus = window.electronAPI.onUpdateStatus?.((status) => {
      if (mounted) {
        setUpdateStatus(status);
        if (status.state === 'available' || status.state === 'ready-to-install') {
          setIsDismissed(false);
        }
      }
    });

    const unsubProgress = window.electronAPI.onUpdateProgress?.((p) => {
      if (mounted) setProgress(p);
    });

    return () => {
      mounted = false;
      if (unsubStatus) unsubStatus();
      if (unsubProgress) unsubProgress();
    };
  }, []);

  if (!updateStatus || isDismissed) {
    return null;
  }

  // Only display global banner when there's an action or active process
  const activeStates = ['available', 'downloading', 'verifying', 'ready-to-install', 'installing'];
  if (!activeStates.includes(updateStatus.state)) {
    return null;
  }

  const handleDownload = async () => {
    if (!window.electronAPI?.downloadUpdate || isActionLoading) return;
    setIsActionLoading(true);
    try {
      await window.electronAPI.downloadUpdate();
    } catch {} finally {
      setIsActionLoading(false);
    }
  };

  const handleCancelDownload = async () => {
    if (!window.electronAPI?.cancelUpdateDownload) return;
    try {
      await window.electronAPI.cancelUpdateDownload();
    } catch {}
  };

  const handleInstall = async () => {
    if (!window.electronAPI?.installUpdate || isActionLoading) return;
    setIsActionLoading(true);
    try {
      await window.electronAPI.installUpdate();
    } catch {} finally {
      setIsActionLoading(false);
    }
  };

  const formatBytes = (bytes: number) => {
    if (!bytes || bytes === 0) return '0 B';
    const mb = bytes / (1024 * 1024);
    return `${mb.toFixed(1)} MB`;
  };

  return (
    <div className="fixed bottom-5 right-5 z-50 max-w-md w-full bg-slate-900 text-slate-100 rounded-xl shadow-2xl border border-slate-700/80 p-4 transition-all animate-in fade-in slide-in-from-bottom-4">
      {/* Header */}
      <div className="flex items-start justify-between gap-3 mb-2">
        <div className="flex items-center gap-2">
          {updateStatus.state === 'ready-to-install' ? (
            <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0" />
          ) : (
            <ArrowDownCircle className="w-5 h-5 text-sky-400 shrink-0" />
          )}
          <span className="text-xs font-bold tracking-wider uppercase text-sky-400">
            {updateStatus.state === 'ready-to-install' ? 'Update Ready to Install' : 'Red Mercury — Update Available'}
          </span>
        </div>
        <button
          type="button"
          onClick={() => setIsDismissed(true)}
          className="text-slate-400 hover:text-slate-200 transition-colors"
          title="Remind Me Later"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Body for Update Available */}
      {updateStatus.state === 'available' && updateStatus.availableUpdate && (
        <div>
          <div className="text-xs text-slate-300 space-y-0.5 mb-2.5">
            <div>
              Installed version: <span className="font-mono text-slate-400">v{updateStatus.currentVersion}</span>
            </div>
            <div>
              Available version:{' '}
              <span className="font-mono font-semibold text-emerald-400">
                v{updateStatus.availableUpdate.version}
              </span>
            </div>
          </div>

          {updateStatus.availableUpdate.releaseNotes && (
            <div className="mb-3 p-2 bg-slate-800/80 rounded border border-slate-700/60 text-[11px] text-slate-300 max-h-24 overflow-y-auto whitespace-pre-line">
              <span className="font-semibold text-slate-200 block mb-1">What's New:</span>
              {updateStatus.availableUpdate.releaseNotes}
            </div>
          )}

          <div className="flex items-center justify-end gap-2 pt-1 border-t border-slate-800">
            <button
              type="button"
              onClick={() => setIsDismissed(true)}
              className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200 rounded font-medium transition-colors"
            >
              Remind Me Later
            </button>
            <button
              type="button"
              onClick={handleDownload}
              disabled={isActionLoading}
              className="px-3 py-1.5 text-xs font-semibold text-white bg-sky-600 hover:bg-sky-500 rounded transition-colors flex items-center gap-1.5 shadow-sm disabled:opacity-50"
            >
              <Download className="w-3.5 h-3.5" />
              {isActionLoading ? 'Starting...' : 'Download Update'}
            </button>
          </div>
        </div>
      )}

      {/* Body for Downloading */}
      {updateStatus.state === 'downloading' && (
        <div>
          <div className="flex items-center justify-between text-xs text-slate-300 mb-1.5">
            <span>Downloading update payload...</span>
            <span className="font-mono font-semibold text-sky-400">{progress?.percent || 0}%</span>
          </div>

          <div className="w-full bg-slate-800 rounded-full h-2 mb-2 overflow-hidden border border-slate-700">
            <div
              className="bg-sky-500 h-2 rounded-full transition-all duration-300"
              style={{ width: `${progress?.percent || 0}%` }}
            />
          </div>

          <div className="flex items-center justify-between text-[11px] text-slate-400 mb-2">
            <span>
              {formatBytes(progress?.transferredBytes || 0)}
              {progress?.totalBytes ? ` / ${formatBytes(progress.totalBytes)}` : ''}
            </span>
            <button
              type="button"
              onClick={handleCancelDownload}
              className="text-rose-400 hover:text-rose-300 underline font-medium"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Body for Verifying */}
      {updateStatus.state === 'verifying' && (
        <div className="flex items-center gap-2.5 py-2 text-xs text-slate-300">
          <RefreshCw className="w-4 h-4 text-sky-400 animate-spin shrink-0" />
          <span>Verifying Ed25519 signature & SHA-512 cryptographic digest...</span>
        </div>
      )}

      {/* Body for Ready to Install */}
      {updateStatus.state === 'ready-to-install' && (
        <div>
          <p className="text-xs text-slate-300 mb-3">
            Update downloaded and cryptographically verified. Click below to restart into the updated application.
            Existing application databases and configuration will be preserved.
          </p>

          <div className="flex items-center justify-end gap-2 pt-1 border-t border-slate-800">
            <button
              type="button"
              onClick={() => setIsDismissed(true)}
              className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200 rounded font-medium transition-colors"
            >
              Later
            </button>
            <button
              type="button"
              onClick={handleInstall}
              disabled={isActionLoading}
              className="px-3 py-1.5 text-xs font-semibold text-white bg-emerald-600 hover:bg-emerald-500 rounded transition-colors flex items-center gap-1.5 shadow-sm disabled:opacity-50"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              {isActionLoading ? 'Preparing...' : 'Restart and Install'}
            </button>
          </div>
        </div>
      )}

      {/* Body for Installing */}
      {updateStatus.state === 'installing' && (
        <div className="flex items-center gap-2.5 py-2 text-xs text-slate-300">
          <RefreshCw className="w-4 h-4 text-emerald-400 animate-spin shrink-0" />
          <span>Launching installer and closing Red Mercury...</span>
        </div>
      )}
    </div>
  );
};
