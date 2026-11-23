export interface BackendSupervisorStatus {
  state: 'stopped' | 'starting' | 'running' | 'restarting' | 'error';
  healthy: boolean;
  port: number | null;
  host?: string;
  backendUrl: string | null;
  restartCount?: number;
  lastError?: string | null;
}

export interface DesktopUserPreferences {
  strictAstTaint: boolean;
  zeroSecrets: boolean;
  autoMergeSafe: boolean;
  notifyOnCritical: boolean;
  sandboxTimeout: number;
}

export interface UpdateStatus {
  state:
    | 'idle'
    | 'checking'
    | 'available'
    | 'not-available'
    | 'downloading'
    | 'verifying'
    | 'ready-to-install'
    | 'installing'
    | 'error';
  currentVersion: string;
  platform: string;
  arch?: string;
  lastCheckedAt?: string | null;
  availableUpdate?: {
    version: string;
    releaseDate?: string;
    releaseNotes?: string;
    publisher?: string;
  } | null;
  downloadProgress?: {
    percent: number;
    transferredBytes: number;
    totalBytes: number;
  } | null;
  lastError?: string | null;
  isReadyToInstall: boolean;
}

export interface UpdateProgress {
  percent: number;
  transferredBytes: number;
  totalBytes: number;
}

export interface ElectronAPI {
  isElectron: boolean;
  selectDirectory: () => Promise<string | null>;
  saveReport?: (payload: {
    defaultFilename: string;
    content: string;
    format: 'sarif' | 'json' | 'markdown' | 'md' | 'txt';
  }) => Promise<{ saved: boolean; canceled?: boolean; filename?: string }>;
  getAppInfo: () => Promise<{
    version: string;
    platform: string;
    arch?: string;
    isPackaged: boolean;
    backendUrl: string;
    sameOriginApi?: boolean;
    uiPort?: number;
    backendState?: string;
  }>;
  checkBackend: () => Promise<boolean>;
  getBackendStatus?: () => Promise<BackendSupervisorStatus>;
  restartBackend?: () => Promise<BackendSupervisorStatus>;
  onBackendStatus?: (callback: (status: BackendSupervisorStatus) => void) => () => void;
  getPreferences?: () => Promise<DesktopUserPreferences>;
  savePreferences?: (prefs: DesktopUserPreferences) => Promise<DesktopUserPreferences>;
  openExternal: (url: string) => Promise<boolean>;
  checkForUpdates?: (feedUrl?: string) => Promise<UpdateStatus>;
  getUpdateStatus?: () => Promise<UpdateStatus>;
  downloadUpdate?: () => Promise<UpdateStatus>;
  cancelUpdateDownload?: () => Promise<boolean>;
  installUpdate?: () => Promise<{ success: boolean; platform: string; installerPath?: string }>;
  onUpdateStatus?: (callback: (status: UpdateStatus) => void) => () => void;
  onUpdateProgress?: (callback: (progress: UpdateProgress) => void) => () => void;
}

declare global {
  interface Window {
    electronAPI?: ElectronAPI;
  }
}
