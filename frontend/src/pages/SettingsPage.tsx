import React, { useState, useEffect, useRef } from 'react';
import { useAuth } from '../context/AuthContext';
import {
  api,
  BackendHealth,
  LocalBackupEntry,
  SandboxDiagnostics,
  SystemCapabilities,
} from '../services/api';
import type { BackendSupervisorStatus, UpdateStatus } from '../types/electron';

const PREFS_STORAGE_KEY = 'redmercury_ui_preferences';

export const SettingsPage: React.FC = () => {
  const { user } = useAuth();

  // Policy toggles
  const [zeroSecrets, setZeroSecrets] = useState(true);
  const [autoMergeSafe, setAutoMergeSafe] = useState(true);
  const [strictAstTaint, setStrictAstTaint] = useState(true);
  const [sandboxTimeout, setSandboxTimeout] = useState('120');
  const [notifyOnCritical, setNotifyOnCritical] = useState(true);

  // Backend Health, Capabilities, Backup & Desktop Supervisor Telemetry
  const [healthData, setHealthData] = useState<BackendHealth | null>(null);
  const [capabilitiesData, setCapabilitiesData] = useState<SystemCapabilities | null>(null);
  const [sandboxDiag, setSandboxDiag] = useState<SandboxDiagnostics | null>(null);
  const [isBuildingWorkerImage, setIsBuildingWorkerImage] = useState(false);
  const [sandboxNotice, setSandboxNotice] = useState<string | null>(null);
  const [backups, setBackups] = useState<LocalBackupEntry[]>([]);
  const [backupsSupported, setBackupsSupported] = useState(true);
  const [isBackupBusy, setIsBackupBusy] = useState(false);
  const [backupNotice, setBackupNotice] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);
  const restoreFileInputRef = useRef<HTMLInputElement | null>(null);
  const [desktopStatus, setDesktopStatus] = useState<BackendSupervisorStatus | null>(null);
  const [updateStatus, setUpdateStatus] = useState<UpdateStatus | null>(null);
  const [isCheckingUpdates, setIsCheckingUpdates] = useState(false);
  const [updateActionMsg, setUpdateActionMsg] = useState<string | null>(null);
  const [isRestartingEngine, setIsRestartingEngine] = useState(false);
  const [savedToast, setSavedToast] = useState(false);

  const refreshBackupsList = async () => {
    try {
      const res = await api.getBackups();
      setBackupsSupported(Boolean(res?.supported));
      setBackups(Array.isArray(res?.backups) ? res.backups : []);
    } catch {
      // Ignore if unauthenticated or endpoint unavailable
    }
  };

  useEffect(() => {
    let isMounted = true;
    api.getHealth()
      .then(res => {
        if (isMounted) setHealthData(res);
      })
      .catch(() => {});

    api.getSystemCapabilities()
      .then(caps => {
        if (isMounted && caps) setCapabilitiesData(caps);
      })
      .catch(() => {});

    api.getSandboxStatus()
      .then(diag => {
        if (isMounted && diag) setSandboxDiag(diag);
      })
      .catch(() => {});

    refreshBackupsList();

    if (typeof window !== 'undefined' && window.electronAPI?.getPreferences) {
      window.electronAPI.getPreferences()
        .then(prefs => {
          if (!isMounted || !prefs) return;
          setStrictAstTaint(prefs.strictAstTaint);
          setZeroSecrets(prefs.zeroSecrets);
          setAutoMergeSafe(prefs.autoMergeSafe);
          setNotifyOnCritical(prefs.notifyOnCritical);
          setSandboxTimeout(String(prefs.sandboxTimeout));
        })
        .catch(() => {});
    } else if (typeof window !== 'undefined') {
      try {
        const raw = window.localStorage.getItem(PREFS_STORAGE_KEY);
        if (raw) {
          const parsed = JSON.parse(raw);
          if (typeof parsed.strictAstTaint === 'boolean') setStrictAstTaint(parsed.strictAstTaint);
          if (typeof parsed.zeroSecrets === 'boolean') setZeroSecrets(parsed.zeroSecrets);
          if (typeof parsed.autoMergeSafe === 'boolean') setAutoMergeSafe(parsed.autoMergeSafe);
          if (typeof parsed.notifyOnCritical === 'boolean') setNotifyOnCritical(parsed.notifyOnCritical);
          if (parsed.sandboxTimeout !== undefined) setSandboxTimeout(String(parsed.sandboxTimeout));
        }
      } catch {}
    }

    let unsubscribe: (() => void) | undefined;
    if (typeof window !== 'undefined' && window.electronAPI?.getBackendStatus) {
      window.electronAPI.getBackendStatus().then(st => {
        if (isMounted && st) setDesktopStatus(st);
      }).catch(() => {});
      if (window.electronAPI.onBackendStatus) {
        unsubscribe = window.electronAPI.onBackendStatus((st) => {
          if (isMounted) setDesktopStatus(st);
        });
      }
    }

    let unsubUpdate: (() => void) | undefined;
    if (typeof window !== 'undefined' && window.electronAPI?.getUpdateStatus) {
      window.electronAPI.getUpdateStatus().then(st => {
        if (isMounted && st) setUpdateStatus(st);
      }).catch(() => {});
      if (window.electronAPI.onUpdateStatus) {
        unsubUpdate = window.electronAPI.onUpdateStatus((st) => {
          if (isMounted) setUpdateStatus(st);
        });
      }
    }

    return () => {
      isMounted = false;
      if (unsubscribe) unsubscribe();
      if (unsubUpdate) unsubUpdate();
    };
  }, []);

  const handleCheckForUpdates = async () => {
    if (!window.electronAPI?.checkForUpdates || isCheckingUpdates) return;
    setIsCheckingUpdates(true);
    setUpdateActionMsg(null);
    try {
      const res = await window.electronAPI.checkForUpdates();
      setUpdateStatus(res);
      if (res.state === 'not-available') {
        setUpdateActionMsg('Application is up to date.');
      }
    } catch (err: any) {
      setUpdateActionMsg(`Update check failed: ${err.message}`);
    } finally {
      setIsCheckingUpdates(false);
    }
  };

  const handleDownloadUpdate = async () => {
    if (!window.electronAPI?.downloadUpdate) return;
    try {
      await window.electronAPI.downloadUpdate();
    } catch (err: any) {
      setUpdateActionMsg(`Download failed: ${err.message}`);
    }
  };

  const handleInstallUpdate = async () => {
    if (!window.electronAPI?.installUpdate) return;
    try {
      await window.electronAPI.installUpdate();
    } catch (err: any) {
      setUpdateActionMsg(`Install failed: ${err.message}`);
    }
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    const timeoutNum = Math.min(600, Math.max(10, Number.parseInt(sandboxTimeout, 10) || 120));
    const prefsPayload = {
      strictAstTaint,
      zeroSecrets,
      autoMergeSafe,
      notifyOnCritical,
      sandboxTimeout: timeoutNum,
    };

    if (typeof window !== 'undefined' && window.electronAPI?.savePreferences) {
      try {
        const saved = await window.electronAPI.savePreferences(prefsPayload);
        setSandboxTimeout(String(saved.sandboxTimeout));
      } catch {}
    } else if (typeof window !== 'undefined') {
      try {
        window.localStorage.setItem(PREFS_STORAGE_KEY, JSON.stringify(prefsPayload));
      } catch {}
    }

    setSavedToast(true);
    setTimeout(() => setSavedToast(false), 3000);
  };

  const handleRestartEngine = async () => {
    if (!window.electronAPI?.restartBackend || isRestartingEngine) return;
    setIsRestartingEngine(true);
    try {
      const st = await window.electronAPI.restartBackend();
      setDesktopStatus(st);
      const h = await api.getHealth().catch(() => null);
      if (h) setHealthData(h);
      const caps = await api.getSystemCapabilities().catch(() => null);
      if (caps) setCapabilitiesData(caps);
    } finally {
      setIsRestartingEngine(false);
    }
  };

  const handleBuildWorkerImage = async () => {
    if (isBuildingWorkerImage) return;
    setIsBuildingWorkerImage(true);
    setSandboxNotice(null);
    try {
      const res = await api.buildApprovedWorkerImage();
      setSandboxNotice(res.message);
      const diag = await api.getSandboxStatus().catch(() => null);
      if (diag) setSandboxDiag(diag);
    } catch (err: any) {
      setSandboxNotice(err?.message || 'Worker image build failed.');
    } finally {
      setIsBuildingWorkerImage(false);
    }
  };

  const handleCreateBackup = async () => {
    if (isBackupBusy) return;
    setIsBackupBusy(true);
    setBackupNotice(null);
    try {
      const created = await api.createBackup();
      setBackupNotice({
        kind: 'ok',
        text: `Created verified backup ${created.filename} (SHA-256: ${created.sha256.slice(0, 12)}...).`,
      });
      await refreshBackupsList();
    } catch (err: any) {
      setBackupNotice({ kind: 'err', text: err?.message || 'Backup creation failed.' });
    } finally {
      setIsBackupBusy(false);
    }
  };

  const handleVerifyBackup = async (filename: string) => {
    if (isBackupBusy) return;
    setIsBackupBusy(true);
    setBackupNotice(null);
    try {
      const res = await api.verifyBackup(filename);
      setBackupNotice({
        kind: 'ok',
        text: `${res.filename} verified cleanly (DB integrity: ${res.db_integrity}, SHA-256: ${res.sha256.slice(0, 12)}...).`,
      });
    } catch (err: any) {
      setBackupNotice({ kind: 'err', text: err?.message || `Verification failed for ${filename}.` });
    } finally {
      setIsBackupBusy(false);
    }
  };

  const handleRestoreBackup = async (filename: string) => {
    if (isBackupBusy) return;
    setIsBackupBusy(true);
    setBackupNotice(null);
    try {
      const res = await api.restoreBackup(filename, true);
      if (res.requires_restart && window.electronAPI?.restartBackend) {
        const st = await window.electronAPI.restartBackend();
        setDesktopStatus(st);
        setBackupNotice({
          kind: 'ok',
          text: `Restored from ${res.archive_filename} and restarted local security engine. Pre-restore snapshot: ${res.pre_restore_backup || 'none'}.`,
        });
      } else {
        setBackupNotice({
          kind: 'ok',
          text: `Restore staged from ${res.archive_filename}. Restart backend service to apply cleanly.`,
        });
      }
      await refreshBackupsList();
    } catch (err: any) {
      setBackupNotice({ kind: 'err', text: err?.message || `Restore failed for ${filename}.` });
    } finally {
      setIsBackupBusy(false);
    }
  };

  const handleUploadRestore = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file || isBackupBusy) return;
    setIsBackupBusy(true);
    setBackupNotice(null);
    try {
      const res = await api.restoreUploadedBackup(file, true);
      if (res.requires_restart && window.electronAPI?.restartBackend) {
        const st = await window.electronAPI.restartBackend();
        setDesktopStatus(st);
        setBackupNotice({
          kind: 'ok',
          text: `Verified and restored ${file.name}; local engine restarted cleanly.`,
        });
      } else {
        setBackupNotice({
          kind: 'ok',
          text: `Verified and staged ${file.name}. Restart backend to apply cleanly.`,
        });
      }
      await refreshBackupsList();
    } catch (err: any) {
      setBackupNotice({ kind: 'err', text: err?.message || 'Uploaded archive failed verification or restore.' });
    } finally {
      setIsBackupBusy(false);
    }
  };

  return (
    <div className="flex flex-col w-full pb-20 font-sans">
      {/* Page Header */}
      <div className="px-4 lg:px-8 py-5 bg-white border-b border-slate-200">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2.5">
              <h1 className="text-xl font-bold text-slate-900 tracking-tight">
                Settings &amp; Governance
              </h1>
              <span className="px-2 py-0.5 rounded-full bg-slate-100 text-slate-700 text-xs font-semibold border border-slate-200">
                Workspace Preferences
              </span>
            </div>
            <p className="text-xs text-slate-500 mt-1">
              Configure automated security gates, test runner parameters, and system telemetry.
            </p>
          </div>

          <button
            type="button"
            onClick={handleSave}
            className="px-4 py-2 bg-slate-900 hover:bg-slate-800 text-white rounded-lg text-xs font-semibold shadow-2xs transition-colors flex items-center gap-1.5 cursor-pointer self-start sm:self-auto"
          >
            <span className="material-symbols-outlined text-sm">save</span>
            <span>Save Settings</span>
          </button>
        </div>
      </div>

      <div className="px-4 lg:px-8 py-6 max-w-4xl space-y-6">
        {/* Saved Success Alert */}
        {savedToast && (
          <div className="p-3.5 rounded-xl bg-emerald-50 text-emerald-800 border border-emerald-200 text-xs flex items-center gap-2 shadow-2xs animate-in fade-in">
            <span className="material-symbols-outlined text-base text-emerald-600">check_circle</span>
            <span className="font-medium">Settings and governance policies saved successfully.</span>
          </div>
        )}

        {/* 1. System & Backend Telemetry Card */}
        <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-2xs space-y-4">
          <div className="flex items-center justify-between border-b border-slate-100 pb-3">
            <div>
              <h2 className="text-sm font-bold text-slate-900">System &amp; Backend Telemetry</h2>
              <p className="text-xs text-slate-500 mt-0.5">Real-time status of backend microservices and databases</p>
            </div>
            <span className="px-2 py-0.5 text-[11px] font-mono rounded bg-slate-100 text-slate-600 border border-slate-200">
              /api/v1/health
            </span>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
              <span className="text-[10px] text-slate-400 uppercase font-semibold block mb-1">Service Status</span>
              <span className="font-bold text-emerald-600 flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                {healthData?.status ? healthData.status.toUpperCase() : 'CONNECTED'}
              </span>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
              <span className="text-[10px] text-slate-400 uppercase font-semibold block mb-1">Engine Version</span>
              <span className="font-bold text-slate-800">{healthData?.version || 'v1.4.0'}</span>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
              <span className="text-[10px] text-slate-400 uppercase font-semibold block mb-1">Database Dialect</span>
              <span className="font-bold text-slate-800 uppercase">{healthData?.database?.dialect || 'SQLITE'}</span>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
              <span className="text-[10px] text-slate-400 uppercase font-semibold block mb-1">Environment</span>
              <span className="font-bold text-slate-800 uppercase">{healthData?.environment || 'DESKTOP'}</span>
            </div>
          </div>

          {desktopStatus && (
            <div className="pt-2 border-t border-slate-100 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
              <div className="text-slate-600">
                <span className="font-semibold text-slate-800">Local Desktop Engine:</span>{' '}
                <span className="font-mono">{desktopStatus.state.toUpperCase()}</span>
                {desktopStatus.port ? ` (127.0.0.1:${desktopStatus.port})` : ''}
                {desktopStatus.lastError ? ` — ${desktopStatus.lastError}` : ''}
              </div>
              {window.electronAPI?.restartBackend && (
                <button
                  type="button"
                  onClick={handleRestartEngine}
                  disabled={isRestartingEngine}
                  className="px-3 py-1.5 rounded-md border border-slate-200 bg-white hover:bg-slate-50 text-slate-800 font-medium text-xs cursor-pointer disabled:opacity-50"
                >
                  {isRestartingEngine ? 'Restarting Engine...' : 'Restart Local Engine'}
                </button>
              )}
            </div>
          )}
        </div>

        {/* 1A. About Red Mercury — Version & Updates */}
        <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-2xs space-y-4">
          <div className="flex items-center justify-between border-b border-slate-100 pb-3">
            <div>
              <h2 className="text-sm font-bold text-slate-900">About Red Mercury — Version &amp; Updates</h2>
              <p className="text-xs text-slate-500 mt-0.5">Desktop application update channel, authenticity verification, and lifecycle</p>
            </div>
            <span className="px-2.5 py-0.5 text-[11px] font-semibold rounded-full bg-sky-50 text-sky-700 border border-sky-200">
              Ed25519 Verified
            </span>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
              <span className="text-[10px] text-slate-400 uppercase font-semibold block mb-1">Installed Version</span>
              <span className="font-bold text-slate-800">v{updateStatus?.currentVersion || '1.0.0'}</span>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
              <span className="text-[10px] text-slate-400 uppercase font-semibold block mb-1">Release Channel</span>
              <span className="font-bold text-slate-800">Stable (Official)</span>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
              <span className="text-[10px] text-slate-400 uppercase font-semibold block mb-1">Last Update Check</span>
              <span className="font-semibold text-slate-700">
                {updateStatus?.lastCheckedAt ? new Date(updateStatus.lastCheckedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'On Startup'}
              </span>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
              <span className="text-[10px] text-slate-400 uppercase font-semibold block mb-1">Update Status</span>
              <span className="font-bold flex items-center gap-1.5">
                {updateStatus?.state === 'available' ? (
                  <span className="text-amber-600">v{updateStatus.availableUpdate?.version} Available</span>
                ) : updateStatus?.state === 'downloading' ? (
                  <span className="text-sky-600">Downloading ({updateStatus.downloadProgress?.percent || 0}%)</span>
                ) : updateStatus?.state === 'verifying' ? (
                  <span className="text-sky-600">Verifying...</span>
                ) : updateStatus?.state === 'ready-to-install' ? (
                  <span className="text-emerald-600">Ready to Install</span>
                ) : updateStatus?.state === 'error' ? (
                  <span className="text-rose-600 truncate" title={updateStatus.lastError || ''}>Update Error</span>
                ) : (
                  <span className="text-emerald-600">Up to Date</span>
                )}
              </span>
            </div>
          </div>

          {updateActionMsg && (
            <p className="text-xs text-slate-600 italic bg-slate-50 p-2 rounded border border-slate-200">
              {updateActionMsg}
            </p>
          )}

          <div className="pt-2 border-t border-slate-100 flex flex-wrap items-center justify-between gap-3 text-xs">
            <span className="text-slate-500 text-[11px]">
              Updates are cryptographically signed with Ed25519 and verified against publisher identity.
            </span>
            <div className="flex items-center gap-2">
              {updateStatus?.state === 'available' && (
                <button
                  type="button"
                  onClick={handleDownloadUpdate}
                  className="px-3 py-1.5 rounded-md bg-sky-600 hover:bg-sky-500 text-white font-medium text-xs shadow-xs"
                >
                  Download Update
                </button>
              )}
              {updateStatus?.state === 'ready-to-install' && (
                <button
                  type="button"
                  onClick={handleInstallUpdate}
                  className="px-3 py-1.5 rounded-md bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs shadow-xs"
                >
                  Restart &amp; Install
                </button>
              )}
              <button
                type="button"
                onClick={handleCheckForUpdates}
                disabled={isCheckingUpdates || updateStatus?.state === 'downloading'}
                className="px-3 py-1.5 rounded-md border border-slate-200 bg-white hover:bg-slate-50 text-slate-800 font-medium text-xs cursor-pointer disabled:opacity-50"
              >
                {isCheckingUpdates ? 'Checking for Updates...' : 'Check for Updates'}
              </button>
            </div>
          </div>
        </div>

        {/* 1B. Runtime Capabilities & Offline Mode Boundaries */}
        <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-2xs space-y-4">
          <div className="flex items-center justify-between border-b border-slate-100 pb-3">
            <div>
              <h2 className="text-sm font-bold text-slate-900">Runtime Capabilities &amp; Offline Boundaries</h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Clear separation between offline local analysis, external APIs, GitHub, and Docker sandboxing
              </p>
            </div>
            <span
              className={`px-2.5 py-0.5 rounded-full text-[11px] font-semibold border ${
                (capabilitiesData?.offline_mode ?? healthData?.offline_mode ?? true)
                  ? 'bg-amber-50 text-amber-800 border-amber-200'
                  : 'bg-blue-50 text-blue-700 border-blue-200'
              }`}
            >
              {(capabilitiesData?.offline_mode ?? healthData?.offline_mode ?? true)
                ? 'Offline-First Mode'
                : 'Connected Mode'}
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
            <div className="p-3.5 rounded-lg border border-emerald-200 bg-emerald-50/40 space-y-1">
              <div className="flex items-center justify-between">
                <span className="font-bold text-slate-900">Offline Security Scanning</span>
                <span className="px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800 text-[10px] font-semibold">
                  AVAILABLE LOCALLY
                </span>
              </div>
              <p className="text-[11px] text-slate-600">
                {capabilitiesData?.capabilities.offline_scanning.message ||
                  'Static, secret, and deterministic rule analysis operate locally without internet access.'}
              </p>
            </div>

            <div
              className={`p-3.5 rounded-lg border space-y-1 ${
                capabilitiesData?.capabilities.external_ai.available
                  ? 'border-blue-200 bg-blue-50/40'
                  : 'border-slate-200 bg-slate-50'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="font-bold text-slate-900">External AI (Gemini API)</span>
                <span
                  className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${
                    capabilitiesData?.capabilities.external_ai.available
                      ? 'bg-blue-100 text-blue-800'
                      : 'bg-amber-100 text-amber-800'
                  }`}
                >
                  {capabilitiesData?.capabilities.external_ai.available
                    ? 'CONNECTED'
                    : capabilitiesData?.capabilities.external_ai.status === 'missing_api_key'
                    ? 'KEY NOT SET (LOCAL FALLBACK)'
                    : 'DISABLED OFFLINE (LOCAL FALLBACK)'}
                </span>
              </div>
              <p className="text-[11px] text-slate-600">
                {capabilitiesData?.capabilities.external_ai.message ||
                  'External AI requires internet access and a configured GEMINI_API_KEY. Deterministic local rule analysis handles requests offline.'}
              </p>
            </div>

            <div
              className={`p-3.5 rounded-lg border space-y-1 ${
                capabilitiesData?.capabilities.github_integrations.available
                  ? 'border-blue-200 bg-blue-50/40'
                  : 'border-slate-200 bg-slate-50'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="font-bold text-slate-900">GitHub &amp; Remote Git</span>
                <span
                  className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${
                    capabilitiesData?.capabilities.github_integrations.available
                      ? 'bg-blue-100 text-blue-800'
                      : 'bg-slate-200 text-slate-700'
                  }`}
                >
                  {capabilitiesData?.capabilities.github_integrations.available ? 'ONLINE ENABLED' : 'REQUIRES INTERNET'}
                </span>
              </div>
              <p className="text-[11px] text-slate-600">
                {capabilitiesData?.capabilities.github_integrations.message ||
                  'PR syncing and remote HTTPS cloning require internet access; local folders and ZIP uploads work offline.'}
              </p>
            </div>

            <div
              className={`p-3.5 rounded-lg border space-y-2 ${
                (sandboxDiag?.ready ?? capabilitiesData?.capabilities.docker_verification.available)
                  ? 'border-emerald-200 bg-emerald-50/40'
                  : 'border-slate-200 bg-slate-50'
              }`}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="font-bold text-slate-900">Local Docker Verification</span>
                <span
                  className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${
                    (sandboxDiag?.ready ?? capabilitiesData?.capabilities.docker_verification.available)
                      ? 'bg-emerald-100 text-emerald-800'
                      : 'bg-rose-100 text-rose-800'
                  }`}
                >
                  {sandboxDiag?.ready
                    ? 'SANDBOX READY'
                    : sandboxDiag?.daemon.available
                    ? 'IMAGE MISSING / UNVERIFIED'
                    : 'UNAVAILABLE (FAIL-CLOSED)'}
                </span>
              </div>
              <p className="text-[11px] text-slate-600">
                {sandboxDiag?.worker_image?.message ||
                  sandboxDiag?.daemon?.message ||
                  capabilitiesData?.capabilities.docker_verification.message ||
                  'Isolated container verification runs locally via Docker Desktop and fails closed if unavailable.'}
              </p>
              {sandboxDiag && (
                <div className="text-[10px] font-mono text-slate-500 space-y-0.5">
                  <div>
                    Backend: {sandboxDiag.daemon.backend} • Arch: {sandboxDiag.architecture.daemon_architecture} (
                    {sandboxDiag.architecture.supported ? 'supported' : 'unsupported'})
                  </div>
                  <div>
                    Image: {sandboxDiag.worker_image.image} • Digest Verified:{' '}
                    {sandboxDiag.worker_image.digest_verified ? 'YES' : 'NO'}
                  </div>
                </div>
              )}
              {sandboxDiag?.daemon.available && !sandboxDiag?.worker_image.available && (
                <button
                  type="button"
                  disabled={isBuildingWorkerImage}
                  onClick={handleBuildWorkerImage}
                  className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 text-white text-[11px] font-semibold cursor-pointer disabled:opacity-50"
                >
                  {isBuildingWorkerImage ? 'Building Worker Image...' : 'Build Approved Worker Image'}
                </button>
              )}
              {sandboxNotice && <div className="text-[11px] text-slate-700 font-medium">{sandboxNotice}</div>}
            </div>
          </div>
        </div>

        {/* 1C. Local Database & Configuration Backup / Recovery */}
        <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-2xs space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 pb-3">
            <div>
              <h2 className="text-sm font-bold text-slate-900">Local Backup &amp; Recovery</h2>
              <p className="text-xs text-slate-500 mt-0.5">
                WAL-consistent SQLite snapshots &amp; non-secret configuration archives verified with SHA-256 checksums
              </p>
            </div>
            <div className="flex items-center gap-2">
              <input
                ref={restoreFileInputRef}
                type="file"
                accept=".rmbkp"
                onChange={handleUploadRestore}
                className="hidden"
              />
              <button
                type="button"
                disabled={!backupsSupported || isBackupBusy}
                onClick={() => restoreFileInputRef.current?.click()}
                className="px-3 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 text-xs font-semibold cursor-pointer disabled:opacity-50"
              >
                Import &amp; Restore .rmbkp
              </button>
              <button
                type="button"
                disabled={!backupsSupported || isBackupBusy}
                onClick={handleCreateBackup}
                className="px-3.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold cursor-pointer disabled:opacity-50"
              >
                {isBackupBusy ? 'Working...' : 'Create Backup'}
              </button>
            </div>
          </div>

          {backupNotice && (
            <div
              className={`p-3 rounded-lg border text-xs ${
                backupNotice.kind === 'ok'
                  ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
                  : 'bg-rose-50 border-rose-200 text-rose-800'
              }`}
            >
              {backupNotice.text}
            </div>
          )}

          {backups.length === 0 ? (
            <p className="text-xs text-slate-500 py-2">
              No local backups created yet. Click <strong>Create Backup</strong> to snapshot your SQLite database and preferences.
            </p>
          ) : (
            <div className="divide-y divide-slate-100 border border-slate-200 rounded-lg overflow-hidden">
              {backups.map((b) => (
                <div
                  key={b.filename}
                  className="px-3.5 py-2.5 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs bg-slate-50/40"
                >
                  <div>
                    <div className="font-mono font-semibold text-slate-900">{b.filename}</div>
                    <div className="text-[11px] text-slate-500">
                      {Math.max(1, Math.round(b.size_bytes / 1024))} KB • Revision {b.alembic_revision || 'unknown'} •{' '}
                      {b.includes_config ? 'DB + Config' : 'DB only'}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      disabled={isBackupBusy}
                      onClick={() => handleVerifyBackup(b.filename)}
                      className="px-2.5 py-1 rounded border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium cursor-pointer"
                    >
                      Verify
                    </button>
                    <a
                      href={api.getBackupDownloadUrl(b.filename)}
                      download={b.filename}
                      className="px-2.5 py-1 rounded border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium"
                    >
                      Download
                    </a>
                    <button
                      type="button"
                      disabled={isBackupBusy}
                      onClick={() => handleRestoreBackup(b.filename)}
                      className="px-2.5 py-1 rounded border border-amber-300 bg-amber-50 hover:bg-amber-100 text-amber-900 font-semibold cursor-pointer"
                    >
                      Restore
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* 2. Active Operator Profile */}
        <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-2xs space-y-4">
          <div className="border-b border-slate-100 pb-3">
            <h2 className="text-sm font-bold text-slate-900">Security Operator Profile</h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Active authenticated session profile and access privileges.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
            <div>
              <span className="text-[10px] text-slate-400 uppercase font-semibold block mb-1">Full Name</span>
              <span className="font-semibold text-slate-900 text-sm">{user?.fullName || 'Authenticated User'}</span>
            </div>

            <div>
              <span className="text-[10px] text-slate-400 uppercase font-semibold block mb-1">Corporate Email</span>
              <span className="font-mono text-slate-700">{user?.email || 'Not signed in'}</span>
            </div>

            <div>
              <span className="text-[10px] text-slate-400 uppercase font-semibold block mb-1">Role &amp; Permissions</span>
              <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-blue-50 text-blue-700 font-semibold border border-blue-200 text-xs">
                <span className="material-symbols-outlined text-xs">verified_user</span>
                {user?.role || 'analyst'}
              </span>
            </div>
          </div>
        </div>

        {/* 3. Safety Gates & Verification Policy */}
        <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-2xs space-y-4">
          <div className="border-b border-slate-100 pb-3">
            <h2 className="text-sm font-bold text-slate-900">Automated Fix Verification Safety Gates</h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Rules and policies enforced before candidate patches are eligible for automated approval.
            </p>
          </div>

          <div className="space-y-3">
            {/* Strict AST Taint */}
            <label className="flex items-center justify-between p-3.5 rounded-xl border border-slate-200 bg-slate-50/50 hover:bg-slate-50 cursor-pointer transition-colors">
              <div className="pr-4">
                <span className="font-semibold text-xs text-slate-900 block">
                  Strict AST Taint Verification
                </span>
                <span className="text-[11px] text-slate-500">
                  Reject candidate fixes unless static dataflow and taint vectors completely clear without sanitization bypasses.
                </span>
              </div>
              <input
                type="checkbox"
                checked={strictAstTaint}
                onChange={e => setStrictAstTaint(e.target.checked)}
                className="w-4 h-4 text-blue-600 rounded border-slate-300 focus:ring-slate-900 cursor-pointer"
              />
            </label>

            {/* Zero Secrets */}
            <label className="flex items-center justify-between p-3.5 rounded-xl border border-slate-200 bg-slate-50/50 hover:bg-slate-50 cursor-pointer transition-colors">
              <div className="pr-4">
                <span className="font-semibold text-xs text-slate-900 block">
                  Zero Hardcoded Secrets Policy
                </span>
                <span className="text-[11px] text-slate-500">
                  Immediate PR blocker preventing credentials, private keys, high-entropy tokens, or passwords from entering repository code.
                </span>
              </div>
              <input
                type="checkbox"
                checked={zeroSecrets}
                onChange={e => setZeroSecrets(e.target.checked)}
                className="w-4 h-4 text-blue-600 rounded border-slate-300 focus:ring-slate-900 cursor-pointer"
              />
            </label>

            {/* Auto-Merge Safe */}
            <label className="flex items-center justify-between p-3.5 rounded-xl border border-slate-200 bg-slate-50/50 hover:bg-slate-50 cursor-pointer transition-colors">
              <div className="pr-4">
                <span className="font-semibold text-xs text-slate-900 block">
                  Auto-Merge Verified Fixes
                </span>
                <span className="text-[11px] text-slate-500">
                  Automatically approve and merge pull requests when 100% of unit tests and regression scanner checks pass.
                </span>
              </div>
              <input
                type="checkbox"
                checked={autoMergeSafe}
                onChange={e => setAutoMergeSafe(e.target.checked)}
                className="w-4 h-4 text-blue-600 rounded border-slate-300 focus:ring-slate-900 cursor-pointer"
              />
            </label>

            {/* Notify on Critical */}
            <label className="flex items-center justify-between p-3.5 rounded-xl border border-slate-200 bg-slate-50/50 hover:bg-slate-50 cursor-pointer transition-colors">
              <div className="pr-4">
                <span className="font-semibold text-xs text-slate-900 block">
                  Instant Alerts for Critical Findings
                </span>
                <span className="text-[11px] text-slate-500">
                  Send high-priority alerts to SecOps team when CVSS &gt;= 9.0 vulnerabilities or leaked secrets are detected.
                </span>
              </div>
              <input
                type="checkbox"
                checked={notifyOnCritical}
                onChange={e => setNotifyOnCritical(e.target.checked)}
                className="w-4 h-4 text-blue-600 rounded border-slate-300 focus:ring-slate-900 cursor-pointer"
              />
            </label>
          </div>

          {/* Sandbox Timeout */}
          <div className="pt-2">
            <label className="block text-xs font-semibold text-slate-700 mb-1">
              Sandbox Runner Execution Timeout (Seconds)
            </label>
            <input
              type="number"
              value={sandboxTimeout}
              onChange={e => setSandboxTimeout(e.target.value)}
              className="w-36 px-3 py-1.5 bg-white border border-slate-200 rounded-lg text-xs font-mono text-slate-900 focus:border-slate-400 focus:outline-hidden shadow-2xs"
            />
            <p className="text-[11px] text-slate-400 mt-1">
              Maximum execution duration before ephemeral test container is safely halted.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
