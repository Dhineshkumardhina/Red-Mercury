const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  isElectron: true,
  selectDirectory: () => ipcRenderer.invoke('dialog:openDirectory'),
  saveReport: (payload) => ipcRenderer.invoke('dialog:saveReport', payload),
  getAppInfo: () => ipcRenderer.invoke('app:getInfo'),
  checkBackend: () => ipcRenderer.invoke('app:checkBackend'),
  getBackendStatus: () => ipcRenderer.invoke('app:getBackendStatus'),
  restartBackend: () => ipcRenderer.invoke('app:restartBackend'),
  onBackendStatus: (callback) => {
    if (typeof callback !== 'function') {
      return () => {};
    }
    const listener = (_event, status) => callback(status);
    ipcRenderer.on('backend:status', listener);
    return () => {
      ipcRenderer.removeListener('backend:status', listener);
    };
  },
  getPreferences: () => ipcRenderer.invoke('preferences:get'),
  savePreferences: (prefs) => ipcRenderer.invoke('preferences:set', prefs),
  openExternal: (url) => ipcRenderer.invoke('shell:openExternal', url),
});
