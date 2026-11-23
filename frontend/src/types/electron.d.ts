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
}

declare global {
  interface Window {
    electronAPI?: ElectronAPI;
  }
}
