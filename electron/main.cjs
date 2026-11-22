const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const {
  parseBackendPort,
  buildBackendArgs,
  detectPythonExecutable,
  resolveStaticAssetPath,
  isSafeExternalUrl,
  isTrustedOriginUrl,
  terminateBackendProcess,
} = require('./security.cjs');

let mainWindow = null;
let splashWindow = null;
let backendProcess = null;
let uiServer = null;
let uiServerPort = null;

const BACKEND_PORT = parseBackendPort(process.env.PORT, 8001);
const BACKEND_HOST = '127.0.0.1';
const HEALTH_URL = `http://${BACKEND_HOST}:${BACKEND_PORT}/api/v1/health`;
const isDev = process.env.NODE_ENV === 'development';

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
      .shield-icon {
        width: 42px;
        height: 42px;
        fill: white;
      }
      h1 {
        font-size: 24px;
        font-weight: 700;
        letter-spacing: -0.5px;
        margin-bottom: 6px;
        background: linear-gradient(to right, #38bdf8, #818cf8);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
      }
      p.subtitle {
        font-size: 13px;
        color: #94a3b8;
        margin-bottom: 28px;
        text-align: center;
      }
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
      .status-text {
        font-size: 13px;
        color: #cbd5e1;
      }
      .version-tag {
        position: absolute;
        bottom: 12px;
        font-size: 11px;
        color: #64748b;
      }
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
 * Checks if FastAPI backend is healthy
 */
function checkBackendHealth() {
  return new Promise((resolve) => {
    const req = http.get(HEALTH_URL, { timeout: 1500 }, (res) => {
      if (res.statusCode === 200) {
        resolve(true);
      } else {
        resolve(false);
      }
    });
    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
  });
}

/**
 * Spawns the Python backend if not already running
 */
async function startBackend() {
  const isHealthy = await checkBackendHealth();
  if (isHealthy) {
    console.log('[Electron] Backend is already running and healthy.');
    return;
  }

  console.log('[Electron] Starting local Python FastAPI backend...');

  const rootDir = app.isPackaged
    ? path.join(process.resourcesPath, 'app')
    : path.resolve(__dirname, '..');

  const backendDir = path.join(rootDir, 'backend');

  // Detect Python environment (Windows & POSIX virtualenv or system python)
  const pythonCmd = detectPythonExecutable(rootDir, process.platform);
  const args = buildBackendArgs(backendDir, BACKEND_HOST, BACKEND_PORT);

  try {
    backendProcess = spawn(pythonCmd, args, {
      cwd: rootDir,
      env: {
        ...process.env,
        PYTHONUNBUFFERED: '1',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
      shell: false,
    });

    backendProcess.stdout.on('data', (data) => {
      console.log(`[FastAPI] ${data.toString().trim()}`);
    });

    backendProcess.stderr.on('data', (data) => {
      console.warn(`[FastAPI Err] ${data.toString().trim()}`);
    });

    backendProcess.on('exit', (code, signal) => {
      console.log(`[FastAPI] Process exited with code ${code} and signal ${signal}`);
      backendProcess = null;
    });
  } catch (err) {
    console.error('[Electron] Failed to spawn python backend process:', err);
  }
}

/**
 * Polls backend until it is up and running
 */
async function waitForBackend(maxRetries = 35, interval = 600) {
  for (let i = 0; i < maxRetries; i++) {
    const ready = await checkBackendHealth();
    if (ready) return true;
    await new Promise((r) => setTimeout(r, interval));
  }
  return false;
}

/**
 * Starts internal lightweight web server for UI & reverse proxy
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
      // Reverse-proxy /api directly to FastAPI backend
      if (req.url && req.url.startsWith('/api/')) {
        const proxyReq = http.request(
          {
            hostname: BACKEND_HOST,
            port: BACKEND_PORT,
            path: req.url,
            method: req.method,
            headers: {
              ...req.headers,
              host: `${BACKEND_HOST}:${BACKEND_PORT}`,
            },
          },
          (proxyRes) => {
            res.writeHead(proxyRes.statusCode, proxyRes.headers);
            proxyRes.pipe(res, { end: true });
          }
        );

        proxyReq.on('error', (err) => {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: { message: 'Backend service unavailable: ' + err.message } }));
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
              `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' http://${BACKEND_HOST}:${BACKEND_PORT}; object-src 'none'; base-uri 'self'; frame-ancestors 'none';`,
          });
          res.end(content);
        }
      });
    });

    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      console.log(`[Electron] Internal UI server listening on http://127.0.0.1:${port}`);
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
    },
  });

  mainWindow.removeMenu();

  if (isDev && process.env.VITE_DEV_SERVER_URL) {
    console.log(`[Electron] Loading Vite dev server at ${process.env.VITE_DEV_SERVER_URL}`);
    await mainWindow.loadURL(process.env.VITE_DEV_SERVER_URL);
  } else {
    const rootDir = app.isPackaged
      ? path.join(process.resourcesPath, 'app')
      : path.resolve(__dirname, '..');
    const distPath = path.join(rootDir, 'frontend', 'dist');

    if (!fs.existsSync(distPath)) {
      console.error(`[Electron] Frontend dist path does not exist at ${distPath}`);
    }

    const { server, port } = await startStaticUiServer(distPath);
    uiServer = server;
    uiServerPort = port;
    await mainWindow.loadURL(`http://127.0.0.1:${port}`);
  }

  mainWindow.once('ready-to-show', () => {
    if (splashWindow && !splashWindow.isDestroyed()) {
      splashWindow.close();
      splashWindow = null;
    }
    mainWindow.show();
    mainWindow.focus();
  });

  // Restrict in-window navigation strictly to trusted local application origins
  mainWindow.webContents.on('will-navigate', (event, navigationUrl) => {
    if (!isTrustedOriginUrl(navigationUrl, getTrustedAppOrigins())) {
      console.warn(`[Electron] Blocked unauthorized navigation to: ${navigationUrl}`);
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

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

/**
 * Gracefully and synchronously kill child backend process tree on Windows/Unix
 */
function terminateBackend() {
  if (backendProcess && backendProcess.pid) {
    console.log(`[Electron] Terminating backend process PID ${backendProcess.pid}...`);
    terminateBackendProcess(backendProcess, { platform: process.platform });
    backendProcess = null;
  }
  if (uiServer) {
    try {
      uiServer.close();
    } catch {}
    uiServer = null;
  }
}

// IPC Handlers (all validate trusted sender origin)
ipcMain.handle('dialog:openDirectory', async (event) => {
  assertTrustedIpcSender(event);
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openDirectory'],
    title: 'Select Repository or Project Directory for Security Scan',
  });
  if (result.canceled || result.filePaths.length === 0) {
    return null;
  }
  return result.filePaths[0];
});

ipcMain.handle('app:getInfo', (event) => {
  assertTrustedIpcSender(event);
  return {
    version: app.getVersion(),
    platform: process.platform,
    isPackaged: app.isPackaged,
    backendUrl: `http://${BACKEND_HOST}:${BACKEND_PORT}`,
    uiPort: uiServerPort,
  };
});

ipcMain.handle('app:checkBackend', async (event) => {
  assertTrustedIpcSender(event);
  return await checkBackendHealth();
});

ipcMain.handle('shell:openExternal', async (event, url) => {
  assertTrustedIpcSender(event);
  if (isSafeExternalUrl(url)) {
    await shell.openExternal(url.trim());
    return true;
  }
  return false;
});

// App lifecycle
app.whenReady().then(async () => {
  createSplashScreen();
  await startBackend();
  const backendReady = await waitForBackend();
  if (!backendReady) {
    console.warn('[Electron] Backend health check timed out. Proceeding to load UI...');
  }
  await createMainWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createMainWindow();
    }
  });
});

app.on('before-quit', () => {
  terminateBackend();
});

app.on('window-all-closed', () => {
  terminateBackend();
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
