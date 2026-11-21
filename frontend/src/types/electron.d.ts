export interface ElectronAPI {
  isElectron: boolean;
  selectDirectory: () => Promise<string | null>;
  getAppInfo: () => Promise<{
    version: string;
    platform: string;
    isPackaged: boolean;
    backendUrl: string;
    uiPort?: number;
  }>;
  checkBackend: () => Promise<boolean>;
  openExternal: (url: string) => Promise<boolean>;
}

declare global {
  interface Window {
    electronAPI?: ElectronAPI;
  }
}
