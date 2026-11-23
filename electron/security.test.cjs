/**
 * Electron Security & Desktop Integration Test Suite (SEC-04, SEC-10, Phase 2)
 * Run via: node --test electron/security.test.cjs
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');

const {
  ALLOWED_IPC_INVOKE_CHANNELS,
  ALLOWED_IPC_EVENT_CHANNELS,
  assertAllowedIpcChannel,
  isLocalhostBindHost,
  isTrustedLocalHostHeader,
  isValidUpdateFeedUrl,
  verifyUpdateManifestSignature,
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
  terminateBackendProcess,
  BackendSupervisor,
} = require('./security.cjs');

function createMockChildProcess(pid = 12345) {
  const proc = new EventEmitter();
  proc.pid = pid;
  proc.stdout = new EventEmitter();
  proc.stderr = new EventEmitter();
  proc.killed = false;
  proc.kill = (sig) => {
    proc.killed = true;
    proc.lastSignal = sig;
  };
  return proc;
}

test('SEC-04: resolves legitimate UI assets and SPA routes inside distPath', () => {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rm-electron-sec-'));
  const distPath = path.join(tmpRoot, 'dist');
  fs.mkdirSync(path.join(distPath, 'assets'), { recursive: true });
  fs.writeFileSync(path.join(distPath, 'index.html'), '<html>ok</html>');
  fs.writeFileSync(path.join(distPath, 'assets', 'app.js'), 'console.log(1);');

  try {
    const rootRes = resolveStaticAssetPath(distPath, '/');
    assert.equal(rootRes.ok, true);
    assert.equal(rootRes.filePath, path.join(distPath, 'index.html'));

    const assetRes = resolveStaticAssetPath(distPath, '/assets/app.js?v=123');
    assert.equal(assetRes.ok, true);
    assert.equal(assetRes.filePath, path.join(distPath, 'assets', 'app.js'));

    const spaRes = resolveStaticAssetPath(distPath, '/findings/123');
    assert.equal(spaRes.ok, true);
    assert.equal(spaRes.filePath, path.join(distPath, 'index.html'));
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
});

test('SEC-04: blocks direct directory traversal attempts with 403', () => {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rm-electron-trav-'));
  const distPath = path.join(tmpRoot, 'dist');
  fs.mkdirSync(distPath, { recursive: true });
  fs.writeFileSync(path.join(distPath, 'index.html'), '<html>ok</html>');
  fs.writeFileSync(path.join(tmpRoot, 'secret.txt'), 'TOP_SECRET');

  try {
    for (const payload of [
      '/../secret.txt',
      '/../../../../Windows/win.ini',
      '/assets/../../secret.txt',
      '/..\\secret.txt',
      '/index.html\0.png',
    ]) {
      const res = resolveStaticAssetPath(distPath, payload);
      assert.equal(res.ok, false, `Expected traversal payload to fail: ${payload}`);
      assert.equal(res.status, 403);
    }
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
});

test('SEC-04: blocks percent-encoded and double-encoded path traversal with 403', () => {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rm-electron-enc-'));
  const distPath = path.join(tmpRoot, 'dist');
  fs.mkdirSync(distPath, { recursive: true });
  fs.writeFileSync(path.join(distPath, 'index.html'), '<html>ok</html>');

  try {
    for (const payload of [
      '/%2e%2e/secret.txt',
      '/%2e%2e%2f%2e%2e%2fetc%2fpasswd',
      '/%252e%252e/secret.txt',
      '/%2e%2e%5csecret.txt',
    ]) {
      const res = resolveStaticAssetPath(distPath, payload);
      assert.equal(res.ok, false, `Expected encoded traversal payload to fail: ${payload}`);
      assert.equal(res.status, 403);
    }
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
});

test('SEC-04: handles malformed percent encoding safely with 400 (no crash)', () => {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rm-electron-uri-'));
  const distPath = path.join(tmpRoot, 'dist');
  fs.mkdirSync(distPath, { recursive: true });

  try {
    for (const payload of ['/%E0%A4%A', '/%ZZ', '/%']) {
      const res = resolveStaticAssetPath(distPath, payload);
      assert.equal(res.ok, false);
      assert.equal(res.status, 400);
    }
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
});

test('SEC-10: restricts navigation and IPC sender origins to trusted app origins', () => {
  const trusted = ['http://127.0.0.1:54321'];

  assert.equal(isTrustedOriginUrl('http://127.0.0.1:54321/', trusted), true);
  assert.equal(isTrustedOriginUrl('http://127.0.0.1:54321/dashboard', trusted), true);

  for (const untrusted of [
    'https://evil.example.com',
    'http://127.0.0.1:9999/dashboard',
    'file:///C:/Windows/win.ini',
    'javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    '',
    null,
  ]) {
    assert.equal(isTrustedOriginUrl(untrusted, trusted), false, `Expected untrusted origin to fail: ${untrusted}`);
  }
});

test('SEC-10: validates external URLs passed to shell.openExternal', () => {
  assert.equal(isSafeExternalUrl('https://github.com/Dhineshkumardhina/Red-Mercury'), true);
  assert.equal(isSafeExternalUrl('http://127.0.0.1:8001/docs'), true);

  for (const unsafe of [
    'javascript:alert(1)',
    'file:///etc/passwd',
    'file:///C:/Windows/System32/calc.exe',
    'data:text/html,<h1>hi</h1>',
    'vbscript:msgbox(1)',
    'ftp://example.com/file',
    '',
    null,
    12345,
    {},
  ]) {
    assert.equal(isSafeExternalUrl(unsafe), false, `Expected unsafe URL to be rejected: ${String(unsafe)}`);
  }
});

test('SEC-10: validates backend port, worker args, and localhost-only binding', () => {
  assert.equal(parseBackendPort(undefined, 8001), 8001);
  assert.equal(parseBackendPort('8001'), 8001);
  assert.throws(() => parseBackendPort('8001 & calc.exe'));
  assert.throws(() => parseBackendPort('0'));
  assert.throws(() => parseBackendPort('70000'));

  assert.equal(isLocalhostBindHost('127.0.0.1'), true);
  assert.equal(isLocalhostBindHost('localhost'), true);
  assert.equal(isLocalhostBindHost('0.0.0.0'), false);
  assert.equal(isLocalhostBindHost('::'), false);

  const args = buildBackendArgs('/tmp/backend', '127.0.0.1', 8001);
  assert.deepEqual(args.slice(0, 4), ['-m', 'uvicorn', 'app.main:app', '--app-dir']);
  assert.equal(args[6], '127.0.0.1');
  assert.equal(args[8], '8001');

  const workerArgs = buildWorkerArgs(1.5, 2);
  assert.deepEqual(workerArgs, ['-m', 'app.scanner.worker', '--interval', '1.5', '--concurrency', '2']);

  assert.throws(() => buildBackendArgs('/tmp/backend', '0.0.0.0', 8001));
  assert.throws(() => buildBackendArgs('/tmp/bad\0dir', '127.0.0.1', 8001));
});

test('SEC-10: supports Windows and POSIX virtualenv & bundled runtime detection', () => {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rm-electron-py-'));
  const posixBin = path.join(tmpRoot, '.venv', 'bin');
  fs.mkdirSync(posixBin, { recursive: true });
  const posixPython = path.join(posixBin, 'python');
  fs.writeFileSync(posixPython, '');

  const bundledWin = path.join(tmpRoot, 'runtime', 'win32-x64');
  fs.mkdirSync(bundledWin, { recursive: true });
  const bundledWinExe = path.join(bundledWin, 'python.exe');
  fs.writeFileSync(bundledWinExe, '');

  try {
    assert.equal(detectPythonExecutable(tmpRoot, 'linux', 'x64'), posixPython);
    assert.equal(detectPythonExecutable(tmpRoot, 'win32', 'x64'), bundledWinExe);
    assert.equal(detectPythonExecutable(tmpRoot, 'win32', 'arm64'), 'python');
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
});

test('SEC-10: terminates backend subprocess synchronously on Windows and process-group on POSIX', () => {
  const calls = [];
  const fakeExecFileSync = (cmd, args, opts) => {
    calls.push({ cmd, args, opts });
  };
  const fakeProcWin = { pid: 4321, kill: () => {} };
  const winResult = terminateBackendProcess(fakeProcWin, {
    platform: 'win32',
    execFileSyncFn: fakeExecFileSync,
  });
  assert.equal(winResult.terminated, true);
  assert.equal(winResult.method, 'taskkill');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].cmd, 'taskkill');
  assert.deepEqual(calls[0].args, ['/pid', '4321', '/T', '/F']);
  assert.equal(calls[0].opts.windowsHide, true);

  const posixKills = [];
  const fakeProcPosix = { pid: 9876, kill: () => {} };
  const posixResult = terminateBackendProcess(fakeProcPosix, {
    platform: 'darwin',
    processKillFn: (pid, sig) => posixKills.push({ pid, sig }),
  });
  assert.equal(posixResult.terminated, true);
  assert.equal(posixResult.method, 'sigterm_group');
  assert.deepEqual(posixKills, [{ pid: -9876, sig: 'SIGTERM' }]);
});

test('Phase 2: port conflict handling falls back to free localhost port and blocks 0.0.0.0', async () => {
  await assert.rejects(() => findAvailableLocalPort(8001, '0.0.0.0'), /Untrusted bind host/);

  const blocker = net.createServer();
  await new Promise((resolve) => blocker.listen(0, '127.0.0.1', resolve));
  const occupiedPort = blocker.address().port;

  try {
    const res = await findAvailableLocalPort(occupiedPort, '127.0.0.1');
    assert.equal(res.conflicted, true);
    assert.notEqual(res.port, occupiedPort);
    assert.ok(res.port > 0 && res.port <= 65535);
  } finally {
    await new Promise((resolve) => blocker.close(resolve));
  }
});

test('Phase 2: IPC allowlist, report validation, and preference sanitization enforce strict schemas', () => {
  for (const ch of ALLOWED_IPC_INVOKE_CHANNELS) {
    assert.equal(assertAllowedIpcChannel(ch), ch);
  }
  for (const ev of ALLOWED_IPC_EVENT_CHANNELS) {
    assert.equal(assertAllowedIpcChannel(ev), ev);
  }
  assert.throws(() => assertAllowedIpcChannel('shell:exec'));
  assert.throws(() => assertAllowedIpcChannel('fs:readFile'));
  assert.throws(() => assertAllowedIpcChannel('docker:run'));

  const validReport = validateSaveReportPayload({
    defaultFilename: '../../etc/passwd.sarif',
    content: '{"version":"2.1.0"}',
    format: 'sarif',
  });
  assert.equal(validReport.defaultFilename, 'passwd.sarif');
  assert.throws(() => validateSaveReportPayload({ format: 'exe', content: 'mz' }));

  const cleanPrefs = sanitizeUserPreferences({
    strictAstTaint: false,
    sandboxTimeout: 99999,
    secretKey: 'should-be-stripped',
    arbitraryShell: 'rm -rf /',
  });
  assert.deepEqual(cleanPrefs, {
    strictAstTaint: false,
    zeroSecrets: true,
    autoMergeSafe: true,
    notifyOnCritical: true,
    sandboxTimeout: 600,
  });
  assert.equal('secretKey' in cleanPrefs, false);
});

test('Phase 2: renderer isolation & IPC allowlisting in main.cjs and preload.cjs', () => {
  const mainSource = fs.readFileSync(path.join(__dirname, 'main.cjs'), 'utf-8');
  const preloadSource = fs.readFileSync(path.join(__dirname, 'preload.cjs'), 'utf-8');

  assert.match(mainSource, /sandbox:\s*true/);
  assert.doesNotMatch(mainSource, /sandbox:\s*false/);
  assert.match(mainSource, /contextIsolation:\s*true/);
  assert.match(mainSource, /nodeIntegration:\s*false/);
  assert.match(mainSource, /webSecurity:\s*true/);
  assert.match(mainSource, /on\('will-navigate'/);
  assert.match(mainSource, /assertTrustedIpcSender/);
  assert.match(mainSource, /registerSecureIpcHandler/);
  assert.match(mainSource, /process\.platform !== 'darwin'/);

  // Preload must never expose raw ipcRenderer, node builtins, or arbitrary invoke
  assert.match(preloadSource, /contextBridge\.exposeInMainWorld/);
  assert.doesNotMatch(preloadSource, /require\(['"](fs|child_process|path|os|http)['"]\)/);
  assert.doesNotMatch(preloadSource, /ipcRenderer\.invoke\([^'"]/);
});

test('Phase 2: desktop application storage encrypts keys via safeStorage without plaintext secrets', () => {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rm-electron-store-'));
  try {
    const paths = resolveDesktopStoragePaths(tmpRoot);
    assert.ok(fs.existsSync(paths.dataDir));
    assert.ok(fs.existsSync(paths.configDir));
    assert.ok(fs.existsSync(paths.logsDir));
    assert.ok(fs.existsSync(paths.secretsDir));

    const fakeSafeStorage = {
      isEncryptionAvailable: () => true,
      encryptString: (plain) => Buffer.from(`ENC::${Buffer.from(plain, 'utf8').toString('base64')}`, 'utf8'),
      decryptString: (buf) => {
        const str = buf.toString('utf8');
        assert.ok(str.startsWith('ENC::'));
        return Buffer.from(str.slice(5), 'base64').toString('utf8');
      },
    };

    const created = loadOrCreateEncryptedDesktopKeys({
      secretsFile: paths.secretsFile,
      safeStorage: fakeSafeStorage,
    });
    assert.equal(created.persistedEncrypted, true);
    assert.ok(created.secretKey.length >= 64);

    const rawOnDisk = fs.readFileSync(paths.secretsFile, 'utf8');
    assert.equal(rawOnDisk.includes(created.secretKey), false);
    assert.equal(rawOnDisk.includes(created.encryptionKey), false);

    const reloaded = loadOrCreateEncryptedDesktopKeys({
      secretsFile: paths.secretsFile,
      safeStorage: fakeSafeStorage,
    });
    assert.equal(reloaded.secretKey, created.secretKey);
    assert.equal(reloaded.encryptionKey, created.encryptionKey);

    const scrubbed = scrubLogText(`SECRET_KEY=${created.secretKey} Bearer eyJabc.def.ghi`);
    assert.equal(scrubbed.includes(created.secretKey), false);
    assert.ok(scrubbed.includes('[REDACTED]'));
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
});

test('Phase 2: BackendSupervisor manages startup, worker spawn, localhost binding, and clean shutdown', async () => {
  const spawned = [];
  const terminated = [];

  const supervisor = new BackendSupervisor({
    rootDir: '/tmp/rm-app',
    backendDir: '/tmp/rm-app/backend',
    platform: 'win32',
    preferredPort: 8001,
    startupRetryIntervalMs: 5,
    healthIntervalMs: 0,
    detectPythonFn: () => '/tmp/rm-app/runtime/python.exe',
    allocatePortFn: async () => ({ port: 18432, conflicted: true }),
    spawnFn: (cmd, args, opts) => {
      const proc = createMockChildProcess(1000 + spawned.length);
      spawned.push({ cmd, args, opts, proc });
      return proc;
    },
    checkHealthFn: async (port, { host, ipcToken }) => {
      assert.equal(host, '127.0.0.1');
      assert.equal(port, 18432);
      assert.ok(ipcToken);
      return { healthy: true, ipcVerified: true, statusCode: 200 };
    },
    terminateFn: (proc) => {
      terminated.push(proc.pid);
      return { terminated: true, method: 'taskkill' };
    },
  });

  const started = await supervisor.start();
  assert.equal(started, true);
  assert.equal(supervisor.getStatus().state, 'running');
  assert.equal(supervisor.getStatus().port, 18432);
  assert.equal(spawned.length, 2); // API + Worker
  assert.equal(spawned[0].opts.shell, false);
  assert.equal(spawned[0].opts.windowsHide, true);
  assert.equal(spawned[0].opts.cwd, '/tmp/rm-app/backend');
  assert.equal(spawned[0].opts.env.PYTHONPATH, '/tmp/rm-app/backend');
  assert.ok(spawned[0].args.includes('127.0.0.1'));
  assert.ok(spawned[1].args.includes('app.scanner.worker'));

  supervisor.stop();
  assert.equal(supervisor.getStatus().state, 'stopped');
  assert.deepEqual(terminated, [1001, 1000]); // Worker then API terminated
});

test('Phase 2: BackendSupervisor detects startup failures and performs bounded crash recovery', async () => {
  let spawnCounter = 0;
  let apiHealthy = false;
  const statuses = [];

  const supervisor = new BackendSupervisor({
    rootDir: '/tmp/rm-app',
    backendDir: '/tmp/rm-app/backend',
    platform: 'darwin',
    startupMaxRetries: 4,
    startupRetryIntervalMs: 5,
    healthIntervalMs: 0,
    maxRestarts: 1,
    detectPythonFn: () => '/tmp/rm-app/runtime/bin/python3',
    allocatePortFn: async () => ({ port: 19001, conflicted: false }),
    spawnFn: () => {
      spawnCounter += 1;
      const proc = createMockChildProcess(2000 + spawnCounter);
      // First API spawn exits immediately with startup error
      if (spawnCounter === 1) {
        setTimeout(() => {
          proc.stderr.emit('data', Buffer.from('ValueError: invalid SECRET_KEY'));
          proc.emit('exit', 1, null);
        }, 5);
      }
      return proc;
    },
    checkHealthFn: async () => ({ healthy: apiHealthy, ipcVerified: apiHealthy, statusCode: apiHealthy ? 200 : 0 }),
    terminateFn: () => ({ terminated: true, method: 'sigterm_group' }),
  });

  supervisor.on('status', (s) => statuses.push(s.state));

  // 1. Startup failure surfaces meaningful error
  await assert.rejects(() => supervisor.start(), /ValueError: invalid SECRET_KEY/);
  assert.equal(supervisor.getStatus().state, 'error');

  // 2. Subsequent healthy start succeeds, then unexpected exit triggers crash recovery
  apiHealthy = true;
  await supervisor.start();
  assert.equal(supervisor.getStatus().state, 'running');
  const firstApiProc = supervisor.apiProcess;
  firstApiProc.emit('exit', 137, 'SIGKILL');

  // Wait for bounded recovery to complete
  await new Promise((r) => setTimeout(r, 350));
  assert.equal(supervisor.getStatus().state, 'running');
  assert.equal(supervisor.getStatus().restartCount, 1);

  // 3. Exceeding maxRestarts transitions supervisor cleanly to 'error'
  supervisor.apiProcess.emit('exit', 137, 'SIGKILL');
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(supervisor.getStatus().state, 'error');
  assert.match(supervisor.getStatus().lastError, /stopped after 1 restart attempts/);
  assert.ok(statuses.includes('restarting'));

  supervisor.stop();
});

test('Phase 6: rejects untrusted Host headers, invalid/oversized IPC payloads, and prototype pollution', () => {
  assert.equal(isTrustedLocalHostHeader('127.0.0.1:54321', 54321), true);
  assert.equal(isTrustedLocalHostHeader('localhost:54321', 54321), true);
  assert.equal(isTrustedLocalHostHeader('evil.example.com:54321', 54321), false);
  assert.equal(isTrustedLocalHostHeader('127.0.0.1:9999', 54321), false);
  assert.equal(isTrustedLocalHostHeader('', 54321), false);

  assert.throws(() => validateSaveReportPayload(null));
  assert.throws(() => validateSaveReportPayload({ format: 'ps1', content: 'calc.exe' }));
  assert.throws(() => validateSaveReportPayload({ format: 'json', content: 12345 }));
  assert.throws(() =>
    validateSaveReportPayload({
      format: 'json',
      content: 'A'.repeat(26 * 1024 * 1024),
    })
  );

  const sanitized = sanitizeUserPreferences({
    sandboxTimeout: 'invalid',
    __proto__: { polluted: true },
    token: 'ghp_secret',
  });
  assert.equal(sanitized.sandboxTimeout, 120);
  assert.equal(Object.prototype.hasOwnProperty.call(sanitized, 'token'), false);
  assert.equal({}.polluted, undefined);
});

test('Phase 6: verifies cryptographic Ed25519 update signature, SHA-512, HTTPS feed, and blocks downgrades/unsigned apps', () => {
  const crypto = require('crypto');
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const artifact = Buffer.from('RedMercury-1.2.0-signed-payload', 'utf8');
  const sha512 = crypto.createHash('sha512').update(artifact).digest('base64');
  const manifest = {
    version: '1.2.0',
    url: 'https://releases.xerova.com/redmercury/RedMercury-Setup-x64.exe',
    sha512,
    publisher: 'Xerova Digital Solutions',
  };
  const canonical = Buffer.from(
    `${manifest.version}|${manifest.url}|${manifest.sha512}|${manifest.publisher}`,
    'utf8'
  );
  manifest.signature = crypto.sign(null, canonical, privateKey).toString('base64');

  // Valid signed manifest on signed app
  const validRes = verifyUpdateManifestSignature({
    manifest,
    artifactBuffer: artifact,
    publicKeyPem: publicKey,
    currentVersion: '1.0.0',
    isAppSigned: true,
  });
  assert.equal(validRes.valid, true);

  // Reject unsigned builds cleanly
  const unsignedRes = verifyUpdateManifestSignature({
    manifest,
    artifactBuffer: artifact,
    publicKeyPem: publicKey,
    currentVersion: '1.0.0',
    isAppSigned: false,
  });
  assert.equal(unsignedRes.valid, false);
  assert.match(unsignedRes.reason, /unsigned/i);

  // Reject HTTP or loopback feed URLs
  assert.equal(isValidUpdateFeedUrl('http://releases.xerova.com/update.exe'), false);
  assert.equal(isValidUpdateFeedUrl('https://127.0.0.1/update.exe'), false);

  // Reject SHA-512 tamper
  const tamperedRes = verifyUpdateManifestSignature({
    manifest,
    artifactBuffer: Buffer.from('trojanized-payload', 'utf8'),
    publicKeyPem: publicKey,
    currentVersion: '1.0.0',
    isAppSigned: true,
  });
  assert.equal(tamperedRes.valid, false);
  assert.match(tamperedRes.reason, /SHA-512/i);

  // Reject version downgrade
  const downgradeRes = verifyUpdateManifestSignature({
    manifest,
    artifactBuffer: artifact,
    publicKeyPem: publicKey,
    currentVersion: '1.2.0',
    isAppSigned: true,
  });
  assert.equal(downgradeRes.valid, false);
  assert.match(downgradeRes.reason, /downgrade/i);

  // Reject invalid cryptographic signature
  const badSigRes = verifyUpdateManifestSignature({
    manifest: { ...manifest, signature: Buffer.from('forged-sig').toString('base64') },
    artifactBuffer: artifact,
    publicKeyPem: publicKey,
    currentVersion: '1.0.0',
    isAppSigned: true,
  });
  assert.equal(badSigRes.valid, false);
  assert.match(badSigRes.reason, /signature/i);
});
