const { app, BrowserWindow, Menu, ipcMain, dialog, shell, safeStorage, session } = require('electron');
const path = require('path');
const http = require('http');
const fs = require('fs');
const {
  ALLOWED_IPC_INVOKE_CHANNELS,
  DEFAULT_USER_PREFERENCES,
  assertAllowedIpcChannel,
  isTrustedLocalHostHeader,
  parseBackendPort,
  resolveStaticAssetPath,
  isSafeExternalUrl,
  isTrustedOriginUrl,
  validateSaveReportPayload,
  sanitizeUserPreferences,
  resolveDesktopStoragePaths,
  loadOrCreateEncryptedDesktopKeys,
  scrubLogText,
  BackendSupervisor,
} = require('./security.cjs');

let mainWindow = null;
let splashWindow = null;
let uiServer = null;
let uiServerPort = null;
let storagePaths = null;
let backendSupervisor = null;
let updateManager = null;

const isDev = process.env.NODE_ENV === 'development';
const BACKEND_HOST = '127.0.0.1';
const PREFERRED_BACKEND_PORT = process.env.PORT ? parseBackendPort(process.env.PORT, 8001) : 8001;
const approvedLocalDirectories = new Set();

function appendDesktopLog(level, message) {
  const line = `[${new Date().toISOString()}] [${String(level).toUpperCase()}] ${scrubLogText(message)}`;
  if (level === 'error') {
    console.error(line);
  } else if (level === 'warn') {
    console.warn(line);
  } else {
    console.log(line);
  }

  if (storagePaths && storagePaths.electronLogFile) {
    try {
      fs.appendFileSync(storagePaths.electronLogFile, line + '\n', 'utf8');
    } catch {}
  }
}

function getTrustedAppOrigins() {
  const origins = [];
  if (uiServerPort) {
    origins.push(`http://127.0.0.1:${uiServerPort}`);
  }
  if (isDev && process.env.VITE_DEV_SERVER_URL) {
    origins.push(process.env.VITE_DEV_SERVER_URL);
  }
  return origins;
}

function assertTrustedIpcSender(event) {
  const senderUrl = event?.senderFrame?.url || '';
  if (!isTrustedOriginUrl(senderUrl, getTrustedAppOrigins())) {
    throw new Error('Unauthorized IPC sender origin');
  }
}

function registerSecureIpcHandler(channel, handler) {
  assertAllowedIpcChannel(channel);
  ipcMain.handle(channel, async (event, ...args) => {
    assertTrustedIpcSender(event);
    return await handler(event, ...args);
  });
}

function broadcastBackendStatus(status) {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  try {
    const currentUrl = mainWindow.webContents.getURL();
    if (isTrustedOriginUrl(currentUrl, getTrustedAppOrigins())) {
      mainWindow.webContents.send('backend:status', status);
    }
  } catch {}
}

function broadcastUpdateStatus(status) {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  try {
    const currentUrl = mainWindow.webContents.getURL();
    if (isTrustedOriginUrl(currentUrl, getTrustedAppOrigins())) {
      mainWindow.webContents.send('updater:status', status);
    }
  } catch {}
}

function broadcastUpdateProgress(progress) {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  try {
    const currentUrl = mainWindow.webContents.getURL();
    if (isTrustedOriginUrl(currentUrl, getTrustedAppOrigins())) {
      mainWindow.webContents.send('updater:progress', progress);
    }
  } catch {}
}

function readJsonFileSafe(filePath, fallback) {
  try {
    if (fs.existsSync(filePath)) {
      return JSON.parse(fs.readFileSync(filePath, 'utf8'));
    }
  } catch {}
  return fallback;
}

function writeJsonFileSafe(filePath, data) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const tmpPath = `${filePath}.tmp`;
  fs.writeFileSync(tmpPath, JSON.stringify(data, null, 2), process.platform === 'win32' ? 'utf8' : { encoding: 'utf8', mode: 0o600 });
  fs.renameSync(tmpPath, filePath);
}

// Ensure single instance lock
const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
  });
}

function configureApplicationMenu() {
  if (process.platform === 'darwin') {
    const template = [
      {
        label: app.name,
        submenu: [
          { role: 'about' },
          { type: 'separator' },
          { role: 'services' },
          { type: 'separator' },
          { role: 'hide' },
          { role: 'hideOthers' },
          { role: 'unhide' },
          { type: 'separator' },
          { role: 'quit' },
        ],
      },
      {
        label: 'Edit',
        submenu: [
          { role: 'undo' },
          { role: 'redo' },
          { type: 'separator' },
          { role: 'cut' },
          { role: 'copy' },
          { role: 'paste' },
          { role: 'selectAll' },
        ],
      },
      {
        label: 'Window',
        submenu: [
          { role: 'minimize' },
          { role: 'zoom' },
          { role: 'close' },
        ],
      },
    ];
    Menu.setApplicationMenu(Menu.buildFromTemplate(template));
  } else {
    Menu.setApplicationMenu(null);
  }
}

/**
 * Creates the splash screen while backend & frontend initialize
 */
function createSplashScreen() {
  splashWindow = new BrowserWindow({
    width: 520,
    height: 380,
    frame: false,
    transparent: true,
    alwaysOnTop: true,
    center: true,
    resizable: false,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      webSecurity: true,
    },
  });

  splashWindow.webContents.on('will-navigate', (event) => {
    event.preventDefault();
  });
  splashWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));

  const splashHtml = `
  <!DOCTYPE html>
  <html>
  <head>
    <meta charset="UTF-8">
    <style>
      * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
      body {
        background: #090d16;
        color: #f8fafc;
        height: 100vh;
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
        border-radius: 16px;
        border: 1px solid #1e293b;
        box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.8);
        padding: 32px;
        user-select: none;
        -webkit-app-region: drag;
      }
      .logo {
        width: 72px;
        height: 72px;
        background: linear-gradient(135deg, #0284c7 0%, #4f46e5 100%);
        border-radius: 18px;
        display: flex;
        align-items: center;
        justify-content: center;
        box-shadow: 0 10px 25px rgba(2, 132, 199, 0.4);
        margin-bottom: 20px;
      }
      .shield-icon { width: 42px; height: 42px; fill: white; }
      h1 {
        font-size: 24px;
        font-weight: 700;
        letter-spacing: -0.5px;
        margin-bottom: 6px;
        background: linear-gradient(to right, #38bdf8, #818cf8);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
      }
      p.subtitle { font-size: 13px; color: #94a3b8; margin-bottom: 28px; text-align: center; }
      .status-box {
        display: flex;
        align-items: center;
        gap: 12px;
        background: #0f172a;
        padding: 10px 20px;
        border-radius: 10px;
        border: 1px solid #334155;
      }
      .spinner {
        width: 16px;
        height: 16px;
        border: 2px solid #38bdf8;
        border-top-color: transparent;
        border-radius: 50%;
        animation: spin 0.8s linear infinite;
      }
      @keyframes spin { to { transform: rotate(360deg); } }
      .status-text { font-size: 13px; color: #cbd5e1; }
      .version-tag { position: absolute; bottom: 12px; font-size: 11px; color: #64748b; }
    </style>
  </head>
  <body>
    <div class="logo">
      <svg class="shield-icon" viewBox="0 0 24 24">
        <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 2.18l7 3.12v4.7c0 4.54-3.08 8.8-7 9.92-3.92-1.12-7-5.38-7-9.92V6.3l7-3.12zm-1 5v6h2v-6h-2zm0 8v2h2v-2h-2z"/>
      </svg>
    </div>
    <h1>Red Mercury</h1>
    <p class="subtitle">Enterprise Application Security & Automated Fix Verification</p>
    <div class="status-box">
      <div class="spinner"></div>
      <div class="status-text" id="status">Initializing Security Engine...</div>
    </div>
    <div class="version-tag">Version 1.0.0 Desktop • Xerova Digital Solutions</div>
  </body>
  </html>
  `;

  splashWindow.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(splashHtml)}`);
}

/**
 * Resolve root directory for packaged vs unpacked development execution.
 */
function getAppRootDir() {
  if (!app.isPackaged) {
    return path.resolve(__dirname, '..');
  }
  const asarUnpacked = path.join(process.resourcesPath, 'app.asar.unpacked');
  if (fs.existsSync(path.join(asarUnpacked, 'backend'))) {
    return asarUnpacked;
  }
  const unpackedDir = path.join(process.resourcesPath, 'app');
  if (fs.existsSync(path.join(unpackedDir, 'backend'))) {
    return unpackedDir;
  }
  return process.resourcesPath;
}

/**
 * Initialize secure OS-appropriate storage, encrypted keys, and backend supervisor.
 */
function initializeDesktopServices() {
  storagePaths = resolveDesktopStoragePaths(app.getPath('userData'));

  const existingAppConfig = readJsonFileSafe(storagePaths.appConfigFile, null);
  const nowIso = new Date().toISOString();
  const appConfig = {
    version: app.getVersion(),
    offlineMode: true,
    preferredPort: PREFERRED_BACKEND_PORT,
    ...(existingAppConfig && typeof existingAppConfig === 'object' ? existingAppConfig : {}),
    initializedAt: existingAppConfig?.initializedAt || nowIso,
    firstRunCompleted: true,
    updatedAt: nowIso,
  };
  writeJsonFileSafe(storagePaths.appConfigFile, appConfig);

  if (!fs.existsSync(storagePaths.preferencesFile)) {
    writeJsonFileSafe(storagePaths.preferencesFile, DEFAULT_USER_PREFERENCES);
  }

  const keys = loadOrCreateEncryptedDesktopKeys({
    secretsFile: storagePaths.secretsFile,
    safeStorage,
    fsMod: fs,
    platform: process.platform,
  });

  const rootDir = getAppRootDir();
  const backendDir = path.join(rootDir, 'backend');

  backendSupervisor = new BackendSupervisor({
    rootDir,
    backendDir,
    preferredPort: Number.isInteger(appConfig.preferredPort) ? appConfig.preferredPort : PREFERRED_BACKEND_PORT,
    logFn: appendDesktopLog,
    envOverrides: {
      APP_ENV: isDev ? 'development' : 'desktop',
      DEBUG: 'false',
      OFFLINE_MODE: appConfig.offlineMode === false ? 'false' : 'true',
      SECRET_KEY: keys.secretKey,
      ENCRYPTION_KEY: keys.encryptionKey,
      REDMERCURY_DATA_DIR: storagePaths.dataDir,
      REDMERCURY_CONFIG_DIR: storagePaths.configDir,
      REDMERCURY_LOG_DIR: storagePaths.logsDir,
      WORKSPACE_ROOT: storagePaths.workspacesDir,
      WORKER_TEMP_DIR: storagePaths.workerTempDir,
      TMPDIR: storagePaths.verifyTempDir,
      TEMP: storagePaths.verifyTempDir,
      TMP: storagePaths.verifyTempDir,
      REDMERCURY_BIN_DIR: path.join(rootDir, 'bin'),
      JOB_DISPATCH_MODE: 'queue_only',
    },
  });

  backendSupervisor.on('status', (status) => {
    broadcastBackendStatus(status);
  });

  const { UpdateManager } = require('./updater.cjs');
  updateManager = new UpdateManager({
    currentVersion: app.getVersion(),
    storagePaths,
    isAppSigned: app.isPackaged || process.env.REDMERCURY_FORCE_APP_SIGNED === 'true',
    logFn: appendDesktopLog,
    onBeforeInstall: async () => {
      terminateAllManagedServices();
    },
    appQuitFn: () => {
      app.quit();
    },
  });

  updateManager.on('status', (status) => {
    broadcastUpdateStatus(status);
  });

  updateManager.on('progress', (progress) => {
    broadcastUpdateProgress(progress);
  });
}

/**
 * Starts internal lightweight web server for UI & same-origin /api reverse proxy.
 */
function startStaticUiServer(distPath) {
  return new Promise((resolve) => {
    const mimeTypes = {
      '.html': 'text/html; charset=UTF-8',
      '.js': 'text/javascript; charset=UTF-8',
      '.css': 'text/css; charset=UTF-8',
      '.json': 'application/json',
      '.png': 'image/png',
      '.jpg': 'image/jpeg',
      '.svg': 'image/svg+xml',
      '.ico': 'image/x-icon',
      '.woff': 'font/woff',
      '.woff2': 'font/woff2',
    };

    const server = http.createServer((req, res) => {
      const boundAddr = server.address();
      const listenPort = boundAddr && typeof boundAddr === 'object' ? boundAddr.port : null;
      if (listenPort && !isTrustedLocalHostHeader(req.headers.host, listenPort)) {
        res.writeHead(403, { 'Content-Type': 'text/plain; charset=UTF-8' });
        res.end('Untrusted Host header rejected');
        return;
      }

      // Reverse-proxy /api directly to the supervised localhost FastAPI backend
      if (req.url && req.url.startsWith('/api/')) {
        const targetPort = backendSupervisor && backendSupervisor.port ? backendSupervisor.port : null;
        if (!targetPort) {
          res.writeHead(503, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              error: {
                code: 'BACKEND_STARTING',
                message: 'Red Mercury local security engine is starting or unavailable.',
              },
            })
          );
          return;
        }

        const proxyReq = http.request(
          {
            hostname: BACKEND_HOST,
            port: targetPort,
            path: req.url,
            method: req.method,
            headers: {
              ...req.headers,
              host: `${BACKEND_HOST}:${targetPort}`,
            },
          },
          (proxyRes) => {
            res.writeHead(proxyRes.statusCode || 502, proxyRes.headers);
            proxyRes.pipe(res, { end: true });
          }
        );

        proxyReq.on('error', (err) => {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              error: {
                code: 'BACKEND_UNAVAILABLE',
                message: `Local backend service unavailable: ${scrubLogText(err.message)}`,
              },
            })
          );
        });

        req.pipe(proxyReq, { end: true });
        return;
      }

      // Serve static assets with strict path containment & SPA fallback
      const resolved = resolveStaticAssetPath(distPath, req.url || '/');
      if (!resolved.ok) {
        res.writeHead(resolved.status, {
          'Content-Type': 'text/plain; charset=UTF-8',
          'X-Content-Type-Options': 'nosniff',
        });
        res.end(resolved.error);
        return;
      }

      const filePath = resolved.filePath;
      const ext = path.extname(filePath).toLowerCase();
      const contentType = mimeTypes[ext] || 'application/octet-stream';

      fs.readFile(filePath, (err, content) => {
        if (err) {
          res.writeHead(500, { 'Content-Type': 'text/plain; charset=UTF-8', 'X-Content-Type-Options': 'nosniff' });
          res.end('Error loading application assets');
        } else {
          res.writeHead(200, {
            'Content-Type': contentType,
            'Cache-Control': 'no-cache',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'Referrer-Policy': 'no-referrer',
            'Content-Security-Policy':
              "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';",
          });
          res.end(content);
        }
      });
    });

    server.listen(0, BACKEND_HOST, () => {
      const port = server.address().port;
      appendDesktopLog('info', `[Electron] Internal UI server listening on http://${BACKEND_HOST}:${port}`);
      resolve({ server, port });
    });
  });
}

/**
 * Creates the primary application window
 */
async function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 920,
    minWidth: 1100,
    minHeight: 720,
    show: false,
    backgroundColor: '#090d16',
    title: 'Red Mercury - Enterprise Security & Automated Fix Engine',
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      webSecurity: true,
      spellcheck: false,
      navigateOnDragDrop: false,
    },
  });

  if (process.platform !== 'darwin') {
    mainWindow.removeMenu();
  }

  if (isDev && process.env.VITE_DEV_SERVER_URL) {
    appendDesktopLog('info', `[Electron] Loading Vite dev server at ${process.env.VITE_DEV_SERVER_URL}`);
    await mainWindow.loadURL(process.env.VITE_DEV_SERVER_URL);
  } else {
    if (!uiServer) {
      const candidates = [
        path.resolve(__dirname, '..', 'frontend', 'dist'),
        path.join(getAppRootDir(), 'frontend', 'dist'),
      ];
      const distPath = candidates.find((p) => fs.existsSync(p)) || candidates[0];
      if (!fs.existsSync(distPath)) {
        appendDesktopLog('error', `[Electron] Frontend dist path does not exist at ${distPath}`);
      }
      const { server, port } = await startStaticUiServer(distPath);
      uiServer = server;
      uiServerPort = port;
    }
    await mainWindow.loadURL(`http://${BACKEND_HOST}:${uiServerPort}`);
  }

  mainWindow.once('ready-to-show', () => {
    if (splashWindow && !splashWindow.isDestroyed()) {
      splashWindow.close();
      splashWindow = null;
    }
    mainWindow.show();
    mainWindow.focus();
    if (backendSupervisor) {
      broadcastBackendStatus(backendSupervisor.getStatus());
    }
  });

  // Restrict in-window navigation strictly to trusted local application origins
  mainWindow.webContents.on('will-navigate', (event, navigationUrl) => {
    if (!isTrustedOriginUrl(navigationUrl, getTrustedAppOrigins())) {
      appendDesktopLog('warn', `[Electron] Blocked unauthorized navigation to: ${navigationUrl}`);
      event.preventDefault();
    }
  });

  // Intercept external links and open safely in external system browser
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (isSafeExternalUrl(url)) {
      shell.openExternal(url);
    }
    return { action: 'deny' };
  });

  // Security Hardening: block arbitrary <webview> attachments
  mainWindow.webContents.on('will-attach-webview', (event) => {
    appendDesktopLog('warn', '[Electron] Blocked unauthorized <webview> attachment');
    event.preventDefault();
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

function terminateAllManagedServices() {
  if (updateManager) {
    updateManager.stopPeriodicChecks();
  }
  if (backendSupervisor) {
    appendDesktopLog('info', '[Electron] Stopping managed backend and worker processes...');
    backendSupervisor.stop();
  }
  if (uiServer) {
    try {
      uiServer.close();
    } catch {}
    uiServer = null;
    uiServerPort = null;
  }
}

// Strict allowlisted IPC Handlers (all validate trusted sender origin + inputs)
registerSecureIpcHandler('dialog:openDirectory', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openDirectory'],
    title: 'Select Repository or Project Directory for Security Scan',
  });
  if (result.canceled || result.filePaths.length === 0) {
    return null;
  }
  const selectedPath = result.filePaths[0];
  approvedLocalDirectories.add(path.resolve(selectedPath));
  return selectedPath;
});

registerSecureIpcHandler('dialog:saveReport', async (_event, payload) => {
  const safePayload = validateSaveReportPayload(payload);
  const ext = safePayload.format === 'markdown' ? 'md' : safePayload.format;
  const result = await dialog.showSaveDialog(mainWindow, {
    title: 'Export Security Report',
    defaultPath: safePayload.defaultFilename,
    filters: [{ name: `${ext.toUpperCase()} Report`, extensions: [ext] }],
  });
  if (result.canceled || !result.filePath) {
    return { saved: false, canceled: true };
  }
  fs.writeFileSync(result.filePath, safePayload.content, 'utf8');
  return { saved: true, canceled: false, filename: path.basename(result.filePath) };
});

registerSecureIpcHandler('app:getInfo', () => {
  const status = backendSupervisor ? backendSupervisor.getStatus() : null;
  return {
    version: app.getVersion(),
    platform: process.platform,
    arch: process.arch,
    isPackaged: app.isPackaged,
    backendUrl: status && status.backendUrl ? status.backendUrl : `http://${BACKEND_HOST}:${PREFERRED_BACKEND_PORT}`,
    sameOriginApi: !isDev,
    uiPort: uiServerPort,
    backendState: status ? status.state : 'stopped',
  };
});

registerSecureIpcHandler('app:checkBackend', async () => {
  if (!backendSupervisor) return false;
  return await backendSupervisor.pollHealth();
});

registerSecureIpcHandler('app:getBackendStatus', () => {
  if (!backendSupervisor) {
    return { state: 'stopped', healthy: false, port: null, lastError: 'Supervisor not initialized' };
  }
  return backendSupervisor.getStatus();
});

registerSecureIpcHandler('app:restartBackend', async () => {
  if (!backendSupervisor) {
    throw new Error('Backend supervisor not initialized');
  }
  try {
    await backendSupervisor.restart();
    return backendSupervisor.getStatus();
  } catch (err) {
    return backendSupervisor.getStatus();
  }
});

registerSecureIpcHandler('preferences:get', () => {
  if (!storagePaths) return DEFAULT_USER_PREFERENCES;
  const saved = readJsonFileSafe(storagePaths.preferencesFile, DEFAULT_USER_PREFERENCES);
  return sanitizeUserPreferences(saved);
});

registerSecureIpcHandler('preferences:set', (_event, rawPrefs) => {
  const cleanPrefs = sanitizeUserPreferences(rawPrefs);
  if (storagePaths) {
    writeJsonFileSafe(storagePaths.preferencesFile, cleanPrefs);
  }
  return cleanPrefs;
});

registerSecureIpcHandler('shell:openExternal', async (_event, url) => {
  if (isSafeExternalUrl(url)) {
    await shell.openExternal(url.trim());
    return true;
  }
  return false;
});

registerSecureIpcHandler('updater:check', async (_event, feedUrl) => {
  if (!updateManager) throw new Error('Update manager not initialized');
  const safeFeedUrl = typeof feedUrl === 'string' && feedUrl.trim() ? feedUrl.trim() : undefined;
  return await updateManager.checkForUpdates(safeFeedUrl);
});

registerSecureIpcHandler('updater:getStatus', () => {
  if (!updateManager) return { state: 'idle', currentVersion: app.getVersion() };
  return updateManager.getStatus();
});

registerSecureIpcHandler('updater:download', async () => {
  if (!updateManager) throw new Error('Update manager not initialized');
  return await updateManager.downloadUpdate();
});

registerSecureIpcHandler('updater:cancelDownload', () => {
  if (!updateManager) return false;
  return updateManager.cancelDownload();
});

registerSecureIpcHandler('updater:install', async () => {
  if (!updateManager) throw new Error('Update manager not initialized');
  return await updateManager.installUpdate();
});

// Sanity assertion: every allowlisted invoke channel was registered
for (const ch of ALLOWED_IPC_INVOKE_CHANNELS) {
  assertAllowedIpcChannel(ch);
}

// App lifecycle
app.whenReady().then(async () => {
  // Global session security hardening: deny arbitrary web permissions
  if (session && session.defaultSession) {
    session.defaultSession.setPermissionRequestHandler((webContents, permission, callback) => {
      callback(false);
    });
    session.defaultSession.setPermissionCheckHandler(() => {
      return false;
    });
  }

  configureApplicationMenu();
  initializeDesktopServices();
  createSplashScreen();

  try {
    await backendSupervisor.start();
  } catch (err) {
    appendDesktopLog('error', `[Electron] Initial backend startup failed: ${err.message}`);
    // Do not crash silently: show main window with backend error banner OR prompt user if severe
    dialog.showMessageBox({
      type: 'warning',
      title: 'Red Mercury Engine Startup Warning',
      message: 'Local Security Engine could not start cleanly.',
      detail: `${err.message}\n\nYou can retry starting the engine from inside the application.`,
      buttons: ['Continue to Console'],
    }).catch(() => {});
  }

  await createMainWindow();

  // Non-blocking auto-check for updates after startup
  setTimeout(() => {
    if (updateManager) {
      updateManager.checkForUpdates().catch(() => {});
      updateManager.startPeriodicChecks();
    }
  }, 5000);

  app.on('activate', async () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      if (backendSupervisor && backendSupervisor.state === 'stopped') {
        try {
          await backendSupervisor.start();
        } catch {}
      }
      await createMainWindow();
    }
  });
});

app.on('before-quit', () => {
  terminateAllManagedServices();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    terminateAllManagedServices();
    app.quit();
  }
});
