/**
 * Electron security, storage, and backend supervision utilities for Red Mercury Desktop.
 *
 * Isolates path containment, URI decoding, origin validation, external URL
 * verification, IPC allowlisting, encrypted key storage, and backend process
 * supervision so they can be verified directly by automated regression tests.
 */
const path = require('path');
const fs = require('fs');
const net = require('net');
const http = require('http');
const crypto = require('crypto');
const { EventEmitter } = require('events');
const { execFileSync } = require('child_process');

const ALLOWED_IPC_INVOKE_CHANNELS = Object.freeze([
  'dialog:openDirectory',
  'dialog:saveReport',
  'app:getInfo',
  'app:checkBackend',
  'app:getBackendStatus',
  'app:restartBackend',
  'preferences:get',
  'preferences:set',
  'shell:openExternal',
  'updater:check',
  'updater:getStatus',
  'updater:download',
  'updater:cancelDownload',
  'updater:install',
]);

const ALLOWED_IPC_EVENT_CHANNELS = Object.freeze([
  'backend:status',
  'updater:status',
  'updater:progress',
]);

const ALLOWED_IPC_CHANNEL_SET = new Set([
  ...ALLOWED_IPC_INVOKE_CHANNELS,
  ...ALLOWED_IPC_EVENT_CHANNELS,
]);

const DEFAULT_USER_PREFERENCES = Object.freeze({
  strictAstTaint: true,
  zeroSecrets: true,
  autoMergeSafe: true,
  notifyOnCritical: true,
  sandboxTimeout: 120,
});

const DEFAULT_UPDATE_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAzQDiqMSWzNSIcGoXCFfqxhnlGKVYSz8nVdEQijWqDP8=
-----END PUBLIC KEY-----`;

const ALLOWED_REPORT_FORMATS = new Set(['sarif', 'json', 'markdown', 'md', 'txt']);
const MAX_REPORT_CONTENT_BYTES = 25 * 1024 * 1024;

function assertAllowedIpcChannel(channel) {
  if (typeof channel !== 'string' || !ALLOWED_IPC_CHANNEL_SET.has(channel)) {
    throw new Error(`Disallowed IPC channel: '${String(channel)}'`);
  }
  return channel;
}

function isLocalhostBindHost(host) {
  return host === '127.0.0.1' || host === 'localhost';
}

function isTrustedLocalHostHeader(hostHeader, expectedPort) {
  if (typeof hostHeader !== 'string' || !hostHeader.trim()) {
    return false;
  }
  const clean = hostHeader.trim().toLowerCase();
  return clean === `127.0.0.1:${expectedPort}` || clean === `localhost:${expectedPort}`;
}

function isValidUpdateFeedUrl(rawUrl) {
  if (typeof rawUrl !== 'string' || !rawUrl.trim()) {
    return false;
  }
  try {
    const parsed = new URL(rawUrl.trim());
    if (parsed.protocol !== 'https:') {
      return false;
    }
    const host = (parsed.hostname || '').toLowerCase();
    if (!host || host === 'localhost' || host === '127.0.0.1' || host === '::1') {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

function compareSemverStrings(a, b) {
  const parse = (v) =>
    String(v || '0.0.0')
      .replace(/^v/i, '')
      .split('-')[0]
      .split('.')
      .slice(0, 3)
      .map((n) => Number.parseInt(n, 10) || 0);
  const pa = parse(a);
  const pb = parse(b);
  for (let i = 0; i < 3; i++) {
    if (pa[i] !== pb[i]) return pa[i] > pb[i] ? 1 : -1;
  }
  return 0;
}

/**
 * Fail-closed verification gate for any future auto-update payload & detached signature.
 * Refuses insecure transports, unsigned builds, version downgrades, SHA-512 mismatches,
 * and invalid cryptographic signatures.
 */
function verifyUpdateManifestSignature(options = {}) {
  const {
    manifest,
    artifactBuffer,
    publicKeyPem,
    currentVersion,
    expectedPublisher = 'Xerova Digital Solutions',
    isAppSigned = false,
  } = options;

  if (!isAppSigned) {
    return { valid: false, reason: 'Automatic updates are disabled on unsigned builds.' };
  }
  if (!manifest || typeof manifest !== 'object') {
    return { valid: false, reason: 'Missing update manifest object.' };
  }
  if (!isValidUpdateFeedUrl(manifest.url)) {
    return { valid: false, reason: 'Update URL must use HTTPS and a non-local public host.' };
  }
  if (manifest.publisher !== expectedPublisher) {
    return { valid: false, reason: 'Untrusted update publisher identity.' };
  }
  if (!manifest.version || compareSemverStrings(manifest.version, currentVersion) <= 0) {
    return { valid: false, reason: 'Update version must be strictly newer than current version (downgrade blocked).' };
  }
  if (!Buffer.isBuffer(artifactBuffer) || artifactBuffer.length === 0) {
    return { valid: false, reason: 'Update artifact payload is empty or invalid.' };
  }
  const actualSha512 = crypto.createHash('sha512').update(artifactBuffer).digest('base64');
  if (actualSha512 !== manifest.sha512) {
    return { valid: false, reason: 'Update artifact SHA-512 digest mismatch.' };
  }
  if (!publicKeyPem || typeof manifest.signature !== 'string' || !manifest.signature.trim()) {
    return { valid: false, reason: 'Missing cryptographic signature or verification key.' };
  }

  const canonicalPayload = Buffer.from(
    `${manifest.version}|${manifest.url}|${manifest.sha512}|${manifest.publisher}`,
    'utf8'
  );
  let sigOk = false;
  try {
    sigOk = crypto.verify(
      null,
      canonicalPayload,
      publicKeyPem,
      Buffer.from(manifest.signature, 'base64')
    );
  } catch {
    sigOk = false;
  }
  if (!sigOk) {
    return { valid: false, reason: 'Cryptographic update signature verification failed.' };
  }
  return { valid: true, sha512: actualSha512, version: manifest.version };
}

/**
 * Scrub sensitive credentials, tokens, and connection strings from log lines or UI errors.
 */
function scrubLogText(rawText) {
  if (rawText === undefined || rawText === null) {
    return '';
  }
  let text = String(rawText);
  text = text.replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, '[REDACTED_PRIVATE_KEY]');
  text = text.replace(/\b(AKIA[0-9A-Z]{16})\b/g, '[REDACTED_AWS_KEY]');
  text = text.replace(/\beyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*\b/g, '[REDACTED_JWT]');
  text = text.replace(/(Bearer\s+)[A-Za-z0-9\-_.]+/gi, '$1[REDACTED_TOKEN]');
  text = text.replace(/(SECRET_KEY|ENCRYPTION_KEY|GEMINI_API_KEY|REDMERCURY_IPC_TOKEN|PASSWORD|TOKEN)\s*[:=]\s*[^\s,;]+/gi, '$1=[REDACTED]');
  text = text.replace(/(postgres(?:ql)?|redis):\/\/([^:]+):([^@]+)@/gi, '$1://$2:[REDACTED]@');
  return text;
}

/**
 * Parse and strictly validate backend port (1..65535).
 */
function parseBackendPort(rawPort, fallback = 8001) {
  if (rawPort === undefined || rawPort === null || String(rawPort).trim() === '') {
    return fallback;
  }
  const str = String(rawPort).trim();
  if (!/^\d+$/.test(str)) {
    throw new Error(`Invalid BACKEND_PORT: '${str}'`);
  }
  const num = Number.parseInt(str, 10);
  if (!Number.isInteger(num) || num < 1 || num > 65535) {
    throw new Error(`Out-of-range BACKEND_PORT: ${num}`);
  }
  return num;
}

/**
 * Probe and allocate a free localhost TCP port (never binds to 0.0.0.0).
 * If preferredPort is busy (EADDRINUSE/EACCES), transparently allocates an ephemeral port.
 */
function findAvailableLocalPort(preferredPort = null, host = '127.0.0.1') {
  if (!isLocalhostBindHost(host)) {
    return Promise.reject(new Error(`Untrusted bind host: '${host}'`));
  }

  const tryBind = (targetPort) =>
    new Promise((resolve, reject) => {
      const srv = net.createServer();
      srv.unref();
      srv.once('error', (err) => reject(err));
      srv.listen(targetPort, host, () => {
        const addr = srv.address();
        const allocated = addr && typeof addr === 'object' ? addr.port : targetPort;
        srv.close(() => resolve(allocated));
      });
    });

  if (preferredPort !== null && preferredPort !== undefined) {
    const validPreferred = parseBackendPort(preferredPort);
    return tryBind(validPreferred)
      .then((port) => ({ port, conflicted: false }))
      .catch(async (err) => {
        if (err && (err.code === 'EADDRINUSE' || err.code === 'EACCES')) {
          const fallbackPort = await tryBind(0);
          return { port: fallbackPort, conflicted: true };
        }
        throw err;
      });
  }

  return tryBind(0).then((port) => ({ port, conflicted: false }));
}

/**
 * Construct validated uvicorn launch arguments (never passed through a shell).
 */
function buildBackendArgs(backendDir, host, port) {
  if (typeof backendDir !== 'string' || !backendDir.trim() || backendDir.includes('\0')) {
    throw new Error('Invalid backend directory path');
  }
  if (!isLocalhostBindHost(host)) {
    throw new Error(`Untrusted backend host: '${host}'`);
  }
  const validPort = parseBackendPort(port);
  return [
    '-m',
    'uvicorn',
    'app.main:app',
    '--app-dir',
    path.resolve(backendDir),
    '--host',
    host,
    '--port',
    String(validPort),
  ];
}

/**
 * Construct validated durable worker launch arguments (never passed through a shell).
 */
function buildWorkerArgs(intervalSeconds = 1.0, concurrency = 2) {
  const interval = Number(intervalSeconds);
  const conc = Number(concurrency);
  const safeInterval = Number.isFinite(interval) && interval >= 0.25 && interval <= 30 ? interval : 1.0;
  const safeConc = Number.isInteger(conc) && conc >= 1 && conc <= 8 ? conc : 2;
  return [
    '-m',
    'app.scanner.worker',
    '--interval',
    String(safeInterval),
    '--concurrency',
    String(safeConc),
  ];
}

/**
 * Detect local Python executable across bundled runtime, virtualenvs, or system Python.
 */
function detectPythonExecutable(rootDir, platform = process.platform, arch = process.arch) {
  const candidates =
    platform === 'win32'
      ? [
          path.join(rootDir, 'runtime', `win32-${arch}`, 'python.exe'),
          path.join(rootDir, 'runtime', 'python.exe'),
          path.join(rootDir, '.venv', 'Scripts', 'python.exe'),
          path.join(rootDir, 'venv', 'Scripts', 'python.exe'),
        ]
      : [
          path.join(rootDir, 'runtime', `${platform}-${arch}`, 'bin', 'python3'),
          path.join(rootDir, 'runtime', `${platform}-${arch}`, 'bin', 'python'),
          path.join(rootDir, 'runtime', 'bin', 'python3'),
          path.join(rootDir, '.venv', 'bin', 'python'),
          path.join(rootDir, 'venv', 'bin', 'python'),
        ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  return platform === 'win32' ? 'python' : 'python3';
}

/**
 * Safely resolve an HTTP request URL against a static UI dist directory.
 */
function resolveStaticAssetPath(distPath, rawUrl) {
  if (typeof rawUrl !== 'string' || !rawUrl.startsWith('/')) {
    return { ok: false, status: 400, error: 'Malformed request URL' };
  }

  const rawPath = rawUrl.split('?')[0].split('#')[0];

  let decodedPath;
  try {
    decodedPath = decodeURIComponent(rawPath);
  } catch {
    return { ok: false, status: 400, error: 'Malformed URI encoding' };
  }

  if (
    decodedPath.includes('\0') ||
    decodedPath.includes('\\') ||
    /(?:^|\/)\.\.(?:\/|$)/.test(decodedPath)
  ) {
    return { ok: false, status: 403, error: 'Path traversal forbidden' };
  }

  if (/%2e%2e|%2f|%5c/i.test(decodedPath)) {
    return { ok: false, status: 403, error: 'Encoded path traversal forbidden' };
  }

  const resolvedDist = path.resolve(distPath);
  const relativePath = decodedPath === '/' ? 'index.html' : decodedPath.replace(/^\/+/, '');
  const resolvedCandidate = path.resolve(resolvedDist, relativePath);

  if (
    resolvedCandidate !== resolvedDist &&
    !resolvedCandidate.startsWith(resolvedDist + path.sep)
  ) {
    return { ok: false, status: 403, error: 'Access outside UI root forbidden' };
  }

  if (fs.existsSync(resolvedCandidate)) {
    let stat;
    try {
      stat = fs.lstatSync(resolvedCandidate);
    } catch {
      return { ok: false, status: 403, error: 'Unable to inspect asset' };
    }

    if (stat.isSymbolicLink()) {
      try {
        const realDist = fs.realpathSync(resolvedDist);
        const realTarget = fs.realpathSync(resolvedCandidate);
        if (realTarget !== realDist && !realTarget.startsWith(realDist + path.sep)) {
          return { ok: false, status: 403, error: 'Symbolic link escape forbidden' };
        }
      } catch {
        return { ok: false, status: 403, error: 'Invalid symbolic link' };
      }
    }

    if (!stat.isDirectory()) {
      return { ok: true, filePath: resolvedCandidate };
    }
  }

  const indexPath = path.resolve(resolvedDist, 'index.html');
  if (!indexPath.startsWith(resolvedDist + path.sep)) {
    return { ok: false, status: 403, error: 'Invalid index fallback' };
  }
  return { ok: true, filePath: indexPath };
}

/**
 * Validate URLs passed to shell.openExternal or window.open.
 */
function isSafeExternalUrl(rawUrl) {
  if (typeof rawUrl !== 'string' || !rawUrl.trim()) {
    return false;
  }
  try {
    const parsed = new URL(rawUrl.trim());
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      return false;
    }
    if (!parsed.hostname) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * Validate that a frame/navigation URL belongs to an explicitly trusted application origin.
 */
function isTrustedOriginUrl(candidateUrl, trustedOrigins) {
  if (typeof candidateUrl !== 'string' || !candidateUrl.trim()) {
    return false;
  }
  if (!Array.isArray(trustedOrigins) || trustedOrigins.length === 0) {
    return false;
  }
  try {
    const parsed = new URL(candidateUrl);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return false;
    }
    const normalizedTrusted = new Set(
      trustedOrigins
        .map((origin) => {
          try {
            return new URL(origin).origin;
          } catch {
            return null;
          }
        })
        .filter(Boolean)
    );
    return normalizedTrusted.has(parsed.origin);
  } catch {
    return false;
  }
}

/**
 * Validate and sanitize report save payloads received over IPC.
 */
function validateSaveReportPayload(payload) {
  if (!payload || typeof payload !== 'object') {
    throw new Error('Invalid report payload');
  }
  const format = String(payload.format || 'json').trim().toLowerCase();
  if (!ALLOWED_REPORT_FORMATS.has(format)) {
    throw new Error(`Unsupported report format: '${format}'`);
  }
  if (typeof payload.content !== 'string') {
    throw new Error('Report content must be a string');
  }
  if (Buffer.byteLength(payload.content, 'utf8') > MAX_REPORT_CONTENT_BYTES) {
    throw new Error('Report content exceeds maximum allowed export size (25 MB)');
  }

  const rawName = String(payload.defaultFilename || `red-mercury-report.${format}`).trim();
  const baseName = path.basename(rawName).replace(/[^a-zA-Z0-9._-]/g, '_');
  const safeName = baseName && !baseName.startsWith('.') ? baseName : `red-mercury-report.${format}`;

  return {
    format,
    content: payload.content,
    defaultFilename: safeName,
  };
}

/**
 * Strictly validate and normalize persisted user preferences (never accepts secrets).
 */
function sanitizeUserPreferences(raw) {
  const input = raw && typeof raw === 'object' ? raw : {};
  const rawTimeout = Number.parseInt(String(input.sandboxTimeout ?? DEFAULT_USER_PREFERENCES.sandboxTimeout), 10);
  const clampedTimeout = Number.isFinite(rawTimeout) ? Math.min(600, Math.max(10, rawTimeout)) : DEFAULT_USER_PREFERENCES.sandboxTimeout;

  return {
    strictAstTaint:
      typeof input.strictAstTaint === 'boolean' ? input.strictAstTaint : DEFAULT_USER_PREFERENCES.strictAstTaint,
    zeroSecrets:
      typeof input.zeroSecrets === 'boolean' ? input.zeroSecrets : DEFAULT_USER_PREFERENCES.zeroSecrets,
    autoMergeSafe:
      typeof input.autoMergeSafe === 'boolean' ? input.autoMergeSafe : DEFAULT_USER_PREFERENCES.autoMergeSafe,
    notifyOnCritical:
      typeof input.notifyOnCritical === 'boolean' ? input.notifyOnCritical : DEFAULT_USER_PREFERENCES.notifyOnCritical,
    sandboxTimeout: clampedTimeout,
  };
}

/**
 * Create and secure OS-appropriate application storage directories under userData.
 */
function resolveDesktopStoragePaths(userDataDir, options = {}) {
  if (typeof userDataDir !== 'string' || !userDataDir.trim()) {
    throw new Error('Invalid userData directory');
  }
  const fsMod = options.fsMod || fs;
  const platform = options.platform || process.platform;
  const root = path.resolve(userDataDir);

  const dirs = {
    root,
    dataDir: path.join(root, 'data'),
    backupsDir: path.join(root, 'data', 'backups'),
    workspacesDir: path.join(root, 'data', 'workspaces'),
    verifyTempDir: path.join(root, 'data', 'verify_tmp'),
    workerTempDir: path.join(root, 'data', 'worker_tmp'),
    configDir: path.join(root, 'config'),
    logsDir: path.join(root, 'logs'),
    secretsDir: path.join(root, 'secrets'),
  };

  for (const dirPath of Object.values(dirs)) {
    fsMod.mkdirSync(dirPath, { recursive: true });
    if (platform !== 'win32') {
      try {
        fsMod.chmodSync(dirPath, 0o700);
      } catch {}
    }
  }

  for (const dirToSweep of [dirs.configDir, dirs.dataDir, dirs.backupsDir]) {
    try {
      const entries = fsMod.readdirSync(dirToSweep);
      for (const name of entries) {
        if (name.endsWith('.tmp') || name.endsWith('.tmp.zip')) {
          try {
            fsMod.unlinkSync(path.join(dirToSweep, name));
          } catch {}
        }
      }
    } catch {}
  }

  return {
    ...dirs,
    dbFile: path.join(dirs.dataDir, 'redmercury.db'),
    appConfigFile: path.join(dirs.configDir, 'app-config.json'),
    preferencesFile: path.join(dirs.configDir, 'preferences.json'),
    secretsFile: path.join(dirs.secretsDir, 'desktop-keys.enc'),
    electronLogFile: path.join(dirs.logsDir, 'electron.log'),
  };
}

/**
 * Load or generate installation-scoped cryptographic keys using OS-backed safeStorage.
 * Secrets are never persisted in plaintext on disk.
 */
function loadOrCreateEncryptedDesktopKeys(options = {}) {
  const {
    secretsFile,
    safeStorage,
    fsMod = fs,
    platform = process.platform,
  } = options;

  const generateKeys = () => ({
    secretKey: crypto.randomBytes(32).toString('hex'),
    encryptionKey: crypto.randomBytes(32).toString('base64url'),
  });

  const canEncrypt = Boolean(
    safeStorage &&
      typeof safeStorage.isEncryptionAvailable === 'function' &&
      safeStorage.isEncryptionAvailable() &&
      typeof safeStorage.encryptString === 'function' &&
      typeof safeStorage.decryptString === 'function'
  );

  if (!canEncrypt || !secretsFile) {
    return {
      ...generateKeys(),
      persistedEncrypted: false,
    };
  }

  try {
    if (fsMod.existsSync(secretsFile)) {
      const cipherBuf = fsMod.readFileSync(secretsFile);
      const plaintext = safeStorage.decryptString(cipherBuf);
      const parsed = JSON.parse(plaintext);
      if (
        parsed &&
        typeof parsed.secretKey === 'string' &&
        parsed.secretKey.length >= 32 &&
        typeof parsed.encryptionKey === 'string' &&
        parsed.encryptionKey.length >= 16
      ) {
        return {
          secretKey: parsed.secretKey,
          encryptionKey: parsed.encryptionKey,
          persistedEncrypted: true,
        };
      }
    }
  } catch {
    // Fall through to regenerate encrypted keys if file was corrupted or unreadable
  }

  const keys = generateKeys();
  const serialized = JSON.stringify(keys);
  const encrypted = safeStorage.encryptString(serialized);
  fsMod.mkdirSync(path.dirname(secretsFile), { recursive: true });
  fsMod.writeFileSync(secretsFile, encrypted, platform === 'win32' ? undefined : { mode: 0o600 });
  if (platform !== 'win32') {
    try {
      fsMod.chmodSync(secretsFile, 0o600);
    } catch {}
  }

  return {
    ...keys,
    persistedEncrypted: true,
  };
}

/**
 * Probe local FastAPI /api/v1/health endpoint on 127.0.0.1 and optionally verify IPC ownership header.
 */
function checkLocalBackendHealth(port, options = {}) {
  const host = options.host || '127.0.0.1';
  const ipcToken = options.ipcToken || null;
  const timeoutMs = options.timeoutMs || 1500;

  if (!isLocalhostBindHost(host)) {
    return Promise.resolve({ healthy: false, ipcVerified: false, statusCode: 0 });
  }

  return new Promise((resolve) => {
    const headers = {};
    if (ipcToken) {
      headers['X-RedMercury-IPC-Token'] = ipcToken;
    }
    const req = http.get(
      {
        hostname: host,
        port,
        path: '/api/v1/health',
        timeout: timeoutMs,
        headers,
      },
      (res) => {
        res.resume();
        const verifiedHeader = String(res.headers['x-redmercury-ipc-verified'] || '').toLowerCase() === 'true';
        resolve({
          healthy: res.statusCode === 200,
          ipcVerified: ipcToken ? verifiedHeader : true,
          statusCode: res.statusCode || 0,
        });
      }
    );
    req.on('error', () => resolve({ healthy: false, ipcVerified: false, statusCode: 0 }));
    req.on('timeout', () => {
      req.destroy();
      resolve({ healthy: false, ipcVerified: false, statusCode: 0 });
    });
  });
}

/**
 * Synchronously terminate a spawned backend or worker process tree on Windows/POSIX.
 */
function terminateBackendProcess(proc, options = {}) {
  const platform = options.platform || process.platform;
  const execFileSyncFn = options.execFileSyncFn || execFileSync;
  const processKillFn = options.processKillFn || process.kill.bind(process);

  if (!proc || !proc.pid) {
    return { terminated: false, method: 'none' };
  }

  const pid = Number(proc.pid);
  if (!Number.isInteger(pid) || pid <= 0) {
    return { terminated: false, method: 'invalid_pid' };
  }

  if (platform === 'win32') {
    try {
      execFileSyncFn('taskkill', ['/pid', String(pid), '/T', '/F'], {
        stdio: 'ignore',
        timeout: 5000,
        windowsHide: true,
      });
      return { terminated: true, method: 'taskkill' };
    } catch {
      try {
        proc.kill('SIGKILL');
        return { terminated: true, method: 'kill_fallback' };
      } catch {
        return { terminated: false, method: 'failed' };
      }
    }
  }

  // On POSIX, attempt process-group signal first (when spawned with detached: true)
  try {
    processKillFn(-pid, 'SIGTERM');
    return { terminated: true, method: 'sigterm_group' };
  } catch {
    try {
      proc.kill('SIGTERM');
      return { terminated: true, method: 'sigterm' };
    } catch {
      return { terminated: false, method: 'failed' };
    }
  }
}

/**
 * Supervises the local FastAPI API and background worker processes with port-conflict
 * resolution, readiness polling, health monitoring, bounded crash recovery, and clean shutdown.
 */
class BackendSupervisor extends EventEmitter {
  constructor(options = {}) {
    super();
    this.rootDir = options.rootDir || path.resolve(__dirname, '..');
    this.backendDir = options.backendDir || path.join(this.rootDir, 'backend');
    this.platform = options.platform || process.platform;
    this.arch = options.arch || process.arch;
    this.host = '127.0.0.1';
    this.preferredPort = options.preferredPort ?? null;
    this.ipcToken = options.ipcToken || crypto.randomBytes(32).toString('hex');
    this.envOverrides = options.envOverrides || {};
    this.maxRestarts = options.maxRestarts ?? 3;
    this.restartWindowMs = options.restartWindowMs ?? 60000;
    this.healthIntervalMs = options.healthIntervalMs ?? 10000;
    this.startupMaxRetries = options.startupMaxRetries ?? 40;
    this.startupRetryIntervalMs = options.startupRetryIntervalMs ?? 500;
    this.logFn = options.logFn || (() => {});

    // Dependency injection hooks for unit testing
    this.spawnFn = options.spawnFn || require('child_process').spawn;
    this.detectPythonFn = options.detectPythonFn || detectPythonExecutable;
    this.allocatePortFn = options.allocatePortFn || findAvailableLocalPort;
    this.checkHealthFn = options.checkHealthFn || checkLocalBackendHealth;
    this.terminateFn = options.terminateFn || terminateBackendProcess;

    this.apiProcess = null;
    this.workerProcess = null;
    this.port = null;
    this.state = 'stopped';
    this.healthy = false;
    this.lastError = null;
    this.stopping = false;
    this.restartTimestamps = [];
    this.healthTimer = null;
    this.recoveryPromise = null;
    this.startPromise = null;
    this.recentStderr = [];
  }

  getStatus() {
    return {
      state: this.state,
      healthy: this.healthy,
      port: this.port,
      host: this.host,
      backendUrl: this.port ? `http://${this.host}:${this.port}` : null,
      restartCount: this.restartTimestamps.length,
      lastError: this.lastError,
      apiPid: this.apiProcess ? this.apiProcess.pid : null,
      workerPid: this.workerProcess ? this.workerProcess.pid : null,
    };
  }

  _setStatus(state, healthy, lastError = null) {
    this.state = state;
    this.healthy = Boolean(healthy);
    this.lastError = lastError ? scrubLogText(lastError) : null;
    this.emit('status', this.getStatus());
  }

  async start() {
    if (this.startPromise) {
      return this.startPromise;
    }
    this.startPromise = this._startInternal().finally(() => {
      this.startPromise = null;
    });
    return this.startPromise;
  }

  async _startInternal() {
    this.stopping = false;
    this.recentStderr = [];
    this._setStatus('starting', false, null);

    const { port, conflicted } = await this.allocatePortFn(this.preferredPort, this.host);
    this.port = port;
    if (conflicted) {
      this.logFn('warn', `[Supervisor] Preferred port ${this.preferredPort} busy; allocated free localhost port ${port}`);
    }

    const pythonCmd = this.detectPythonFn(this.rootDir, this.platform, this.arch);
    const apiArgs = buildBackendArgs(this.backendDir, this.host, this.port);
    const workerArgs = buildWorkerArgs(1.0, 2);

    const childEnv = {
      ...process.env,
      ...this.envOverrides,
      HOST: this.host,
      PORT: String(this.port),
      PYTHONPATH: this.backendDir,
      PYTHONUNBUFFERED: '1',
      REDMERCURY_IPC_TOKEN: this.ipcToken,
    };

    const spawnOpts = {
      cwd: this.backendDir,
      env: childEnv,
      stdio: ['ignore', 'pipe', 'pipe'],
      shell: false,
      windowsHide: true,
      detached: this.platform !== 'win32',
    };

    let earlyExitMessage = null;
    let apiProc;
    try {
      apiProc = this.spawnFn(pythonCmd, apiArgs, spawnOpts);
    } catch (err) {
      const msg = `Failed to launch Python backend (${pythonCmd}): ${scrubLogText(err.message)}`;
      this._setStatus('error', false, msg);
      throw new Error(msg);
    }

    this.apiProcess = apiProc;
    if (apiProc.stdout && typeof apiProc.stdout.on === 'function') {
      apiProc.stdout.on('data', (chunk) => {
        this.logFn('info', `[FastAPI] ${scrubLogText(chunk.toString().trim())}`);
      });
    }
    if (apiProc.stderr && typeof apiProc.stderr.on === 'function') {
      apiProc.stderr.on('data', (chunk) => {
        const line = scrubLogText(chunk.toString().trim());
        if (line) {
          this.recentStderr.push(line);
          if (this.recentStderr.length > 20) this.recentStderr.shift();
          this.logFn('warn', `[FastAPI Err] ${line}`);
        }
      });
    }
    apiProc.on('error', (err) => {
      earlyExitMessage = `Backend spawn error: ${scrubLogText(err.message)}`;
    });
    apiProc.on('exit', (code, signal) => {
      const exitDetail = `Backend exited unexpectedly (code=${code}, signal=${signal})`;
      if (this.apiProcess === apiProc) {
        this.apiProcess = null;
      }
      if (!this.stopping) {
        earlyExitMessage = `${exitDetail}${this.recentStderr.length ? `: ${this.recentStderr[this.recentStderr.length - 1]}` : ''}`;
        if (this.state === 'running') {
          this.logFn('error', `[Supervisor] ${earlyExitMessage}`);
          this._handleUnexpectedCrash(earlyExitMessage);
        }
      }
    });

    // Wait for FastAPI readiness and verify IPC instance ownership
    let ready = false;
    for (let i = 0; i < this.startupMaxRetries; i++) {
      if (this.stopping) {
        return false;
      }
      if (earlyExitMessage || !this.apiProcess) {
        break;
      }
      const probe = await this.checkHealthFn(this.port, {
        host: this.host,
        ipcToken: this.ipcToken,
      });
      if (probe && probe.healthy && probe.ipcVerified) {
        ready = true;
        break;
      }
      await new Promise((r) => setTimeout(r, this.startupRetryIntervalMs));
    }

    if (!ready) {
      const reason =
        earlyExitMessage ||
        (this.recentStderr.length ? this.recentStderr[this.recentStderr.length - 1] : null) ||
        `Backend failed to respond on ${this.host}:${this.port} within startup timeout.`;
      this._terminateChildren();
      this._setStatus('error', false, reason);
      throw new Error(reason);
    }

    // Start managed durable background worker alongside FastAPI
    this._startWorker(pythonCmd, workerArgs, spawnOpts);

    this._setStatus('running', true, null);
    this._startHealthMonitor();
    return true;
  }

  _startWorker(pythonCmd, workerArgs, spawnOpts) {
    try {
      const wProc = this.spawnFn(pythonCmd, workerArgs, spawnOpts);
      this.workerProcess = wProc;
      if (wProc.stdout && typeof wProc.stdout.on === 'function') {
        wProc.stdout.on('data', (chunk) => {
          this.logFn('info', `[Worker] ${scrubLogText(chunk.toString().trim())}`);
        });
      }
      if (wProc.stderr && typeof wProc.stderr.on === 'function') {
        wProc.stderr.on('data', (chunk) => {
          this.logFn('warn', `[Worker Err] ${scrubLogText(chunk.toString().trim())}`);
        });
      }
      wProc.on('exit', (code, signal) => {
        if (this.workerProcess === wProc) {
          this.workerProcess = null;
        }
        if (!this.stopping) {
          this.logFn('warn', `[Supervisor] Background worker exited (code=${code}, signal=${signal})`);
        }
      });
    } catch (err) {
      this.logFn('warn', `[Supervisor] Unable to start worker process: ${scrubLogText(err.message)}`);
    }
  }

  _startHealthMonitor() {
    this._stopHealthMonitor();
    if (this.healthIntervalMs <= 0) return;
    this.healthTimer = setInterval(() => {
      this.pollHealth().catch(() => {});
    }, this.healthIntervalMs);
    if (typeof this.healthTimer.unref === 'function') {
      this.healthTimer.unref();
    }
  }

  _stopHealthMonitor() {
    if (this.healthTimer) {
      clearInterval(this.healthTimer);
      this.healthTimer = null;
    }
  }

  async pollHealth() {
    if (this.stopping || this.state === 'starting' || this.state === 'restarting') {
      return this.healthy;
    }
    if (!this.port || !this.apiProcess) {
      if (!this.stopping && this.state === 'running') {
        await this._handleUnexpectedCrash('Backend process is not running');
      }
      return false;
    }

    const probe = await this.checkHealthFn(this.port, {
      host: this.host,
      ipcToken: this.ipcToken,
    });
    const ok = Boolean(probe && probe.healthy && probe.ipcVerified);
    if (!ok && !this.stopping && this.state === 'running') {
      await this._handleUnexpectedCrash('Backend health check failed');
    }
    return ok;
  }

  async _handleUnexpectedCrash(reason) {
    if (this.stopping || this.recoveryPromise) {
      return this.recoveryPromise;
    }

    const now = Date.now();
    this.restartTimestamps = this.restartTimestamps.filter((ts) => now - ts < this.restartWindowMs);

    if (this.restartTimestamps.length >= this.maxRestarts) {
      this._terminateChildren();
      this._setStatus(
        'error',
        false,
        `Security engine stopped after ${this.maxRestarts} restart attempts: ${reason}`
      );
      return false;
    }

    this.restartTimestamps.push(now);
    const attempt = this.restartTimestamps.length;
    this._setStatus('restarting', false, `Recovering security engine (attempt ${attempt}/${this.maxRestarts})...`);
    this._terminateChildren();

    this.recoveryPromise = (async () => {
      try {
        await new Promise((r) => setTimeout(r, Math.min(2000, 250 * attempt)));
        if (this.stopping) return false;
        await this.start();
        return true;
      } catch (err) {
        this._setStatus('error', false, err.message);
        return false;
      } finally {
        this.recoveryPromise = null;
      }
    })();

    return this.recoveryPromise;
  }

  async restart() {
    this.restartTimestamps = [];
    this.stop();
    return this.start();
  }

  _terminateChildren() {
    if (this.workerProcess && this.workerProcess.pid) {
      this.terminateFn(this.workerProcess, { platform: this.platform });
      this.workerProcess = null;
    }
    if (this.apiProcess && this.apiProcess.pid) {
      this.terminateFn(this.apiProcess, { platform: this.platform });
      this.apiProcess = null;
    }
  }

  stop() {
    this.stopping = true;
    this._stopHealthMonitor();
    this._terminateChildren();
    this._setStatus('stopped', false, null);
  }
}

module.exports = {
  ALLOWED_IPC_INVOKE_CHANNELS,
  ALLOWED_IPC_EVENT_CHANNELS,
  DEFAULT_USER_PREFERENCES,
  assertAllowedIpcChannel,
  isLocalhostBindHost,
  isTrustedLocalHostHeader,
  isValidUpdateFeedUrl,
  compareSemverStrings,
  verifyUpdateManifestSignature,
  DEFAULT_UPDATE_PUBLIC_KEY_PEM,
  scrubLogText,
  parseBackendPort,
  findAvailableLocalPort,
  buildBackendArgs,
  buildWorkerArgs,
  detectPythonExecutable,
  resolveStaticAssetPath,
  isSafeExternalUrl,
  isTrustedOriginUrl,
  validateSaveReportPayload,
  sanitizeUserPreferences,
  resolveDesktopStoragePaths,
  loadOrCreateEncryptedDesktopKeys,
  checkLocalBackendHealth,
  terminateBackendProcess,
  BackendSupervisor,
};
