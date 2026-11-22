/**
 * Electron Security Regression Test Suite (SEC-04 & SEC-10)
 * Run via: node --test electron/security.test.cjs
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  parseBackendPort,
  buildBackendArgs,
  detectPythonExecutable,
  resolveStaticAssetPath,
  isSafeExternalUrl,
  isTrustedOriginUrl,
  terminateBackendProcess,
} = require('./security.cjs');

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

test('SEC-10: validates backend port and launch arguments against injection', () => {
  assert.equal(parseBackendPort(undefined, 8001), 8001);
  assert.equal(parseBackendPort('8001'), 8001);
  assert.throws(() => parseBackendPort('8001 & calc.exe'));
  assert.throws(() => parseBackendPort('0'));
  assert.throws(() => parseBackendPort('70000'));

  const args = buildBackendArgs('/tmp/backend', '127.0.0.1', 8001);
  assert.deepEqual(args.slice(0, 4), ['-m', 'uvicorn', 'app.main:app', '--app-dir']);
  assert.equal(args[6], '127.0.0.1');
  assert.equal(args[8], '8001');

  assert.throws(() => buildBackendArgs('/tmp/backend', '0.0.0.0', 8001));
  assert.throws(() => buildBackendArgs('/tmp/bad\0dir', '127.0.0.1', 8001));
});

test('SEC-10: supports Windows and POSIX virtualenv detection', () => {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rm-electron-py-'));
  const posixBin = path.join(tmpRoot, '.venv', 'bin');
  fs.mkdirSync(posixBin, { recursive: true });
  const posixPython = path.join(posixBin, 'python');
  fs.writeFileSync(posixPython, '');

  try {
    assert.equal(detectPythonExecutable(tmpRoot, 'linux'), posixPython);
    assert.equal(detectPythonExecutable(tmpRoot, 'win32'), 'python');
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
});

test('SEC-10: terminates backend subprocess synchronously on Windows and SIGTERM on POSIX', () => {
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

  let posixSignal = null;
  const fakeProcPosix = {
    pid: 9876,
    kill: (sig) => {
      posixSignal = sig;
    },
  };
  const posixResult = terminateBackendProcess(fakeProcPosix, { platform: 'linux' });
  assert.equal(posixResult.terminated, true);
  assert.equal(posixResult.method, 'sigterm');
  assert.equal(posixSignal, 'SIGTERM');
});

test('SEC-10: electron/main.cjs enables sandbox, contextIsolation, shell:false, and will-navigate guard', () => {
  const mainSource = fs.readFileSync(path.join(__dirname, 'main.cjs'), 'utf-8');
  assert.match(mainSource, /sandbox:\s*true/);
  assert.doesNotMatch(mainSource, /sandbox:\s*false/);
  assert.match(mainSource, /contextIsolation:\s*true/);
  assert.match(mainSource, /nodeIntegration:\s*false/);
  assert.match(mainSource, /shell:\s*false/);
  assert.doesNotMatch(mainSource, /shell:\s*process\.platform/);
  assert.match(mainSource, /on\('will-navigate'/);
  assert.match(mainSource, /assertTrustedIpcSender/);
});
