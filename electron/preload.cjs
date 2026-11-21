const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  isElectron: true,
  selectDirectory: () => ipcRenderer.invoke('dialog:openDirectory'),
  getAppInfo: () => ipcRenderer.invoke('app:getInfo'),
  checkBackend: () => ipcRenderer.invoke('app:checkBackend'),
  openExternal: (url) => ipcRenderer.invoke('shell:openExternal', url),
});
