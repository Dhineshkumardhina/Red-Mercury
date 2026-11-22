/**
 * Electron security utilities for Red Mercury Desktop.
 *
 * Isolates path containment, URI decoding, origin validation, external URL
 * verification, and backend process argument/termination logic so they can be
 * verified directly by automated security regression tests.
 */
const path = require('path');
const fs = require('fs');
const { execFileSync } = require('child_process');

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
 * Construct validated uvicorn launch arguments (never passed through a shell).
 */
function buildBackendArgs(backendDir, host, port) {
  if (typeof backendDir !== 'string' || !backendDir.trim() || backendDir.includes('\0')) {
    throw new Error('Invalid backend directory path');
  }
  if (host !== '127.0.0.1' && host !== 'localhost') {
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
 * Detect local Python executable across Windows and POSIX virtualenvs.
 */
function detectPythonExecutable(rootDir, platform = process.platform) {
  const candidates =
    platform === 'win32'
      ? [
          path.join(rootDir, '.venv', 'Scripts', 'python.exe'),
          path.join(rootDir, 'venv', 'Scripts', 'python.exe'),
        ]
      : [
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
 *
 * Returns:
 * - { ok: true, filePath: string } for an in-bounds file (or SPA index.html fallback)
 * - { ok: false, status: 400 | 403, error: string } for malformed encoding or traversal
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

  // Reject null bytes, backslashes, or traversal segments (including double-encoded attempts)
  if (
    decodedPath.includes('\0') ||
    decodedPath.includes('\\') ||
    /(?:^|\/)\.\.(?:\/|$)/.test(decodedPath)
  ) {
    return { ok: false, status: 403, error: 'Path traversal forbidden' };
  }

  // Also reject percent-encoded traversal indicators that survived single decode
  if (/%2e%2e|%2f|%5c/i.test(decodedPath)) {
    return { ok: false, status: 403, error: 'Encoded path traversal forbidden' };
  }

  const resolvedDist = path.resolve(distPath);
  const relativePath = decodedPath === '/' ? 'index.html' : decodedPath.replace(/^\/+/, '');
  const resolvedCandidate = path.resolve(resolvedDist, relativePath);

  // Strict containment check with path separator boundary (prevents prefix collisions)
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

  // SPA fallback to index.html ONLY after traversal & encoding validation passed
  const indexPath = path.resolve(resolvedDist, 'index.html');
  if (!indexPath.startsWith(resolvedDist + path.sep)) {
    return { ok: false, status: 403, error: 'Invalid index fallback' };
  }
  return { ok: true, filePath: indexPath };
}

/**
 * Validate URLs passed to shell.openExternal or window.open.
 * Permits only well-formed http/https URLs with a non-empty hostname.
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
 * Synchronously terminate a spawned backend process tree so no orphan Uvicorn remains on exit.
 */
function terminateBackendProcess(proc, options = {}) {
  const platform = options.platform || process.platform;
  const execFileSyncFn = options.execFileSyncFn || execFileSync;

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

  try {
    proc.kill('SIGTERM');
    return { terminated: true, method: 'sigterm' };
  } catch {
    return { terminated: false, method: 'failed' };
  }
}

module.exports = {
  parseBackendPort,
  buildBackendArgs,
  detectPythonExecutable,
  resolveStaticAssetPath,
  isSafeExternalUrl,
  isTrustedOriginUrl,
  terminateBackendProcess,
};
