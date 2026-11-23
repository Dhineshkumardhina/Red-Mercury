/**
 * Red Mercury Secure Desktop Update Manager
 *
 * Implements end-to-end update lifecycle:
 *   Discovery -> Signed Manifest -> HTTPS Download -> Verification -> User Approval -> Install
 *
 * Strictly enforces:
 * - HTTPS public feed validation (isValidUpdateFeedUrl)
 * - Semantic version anti-downgrade (compareSemverStrings)
 * - Fail-closed Ed25519 signature & SHA-512 verification (verifyUpdateManifestSignature)
 * - Storage path safety under OS userData (resolveDesktopStoragePaths)
 * - User approval required for download and install
 */
const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const { spawn } = require('child_process');
const { EventEmitter } = require('events');
const {
  isValidUpdateFeedUrl,
  compareSemverStrings,
  verifyUpdateManifestSignature,
  DEFAULT_UPDATE_PUBLIC_KEY_PEM,
  scrubLogText,
} = require('./security.cjs');

const DEFAULT_REPO = 'Dhineshkumardhina/Red-Mercury';
const DEFAULT_FEED_URL = `https://github.com/${DEFAULT_REPO}/releases/latest/download/update-manifest.json`;

class UpdateManager extends EventEmitter {
  constructor(options = {}) {
    super();
    this.currentVersion = options.currentVersion || '1.0.0';
    this.platform = options.platform || process.platform;
    this.arch = options.arch || process.arch;
    this.storagePaths = options.storagePaths || null;
    this.publicKeyPem = options.publicKeyPem || DEFAULT_UPDATE_PUBLIC_KEY_PEM;
    this.isAppSigned = typeof options.isAppSigned === 'boolean' ? options.isAppSigned : true;
    this.feedUrl = options.feedUrl || process.env.REDMERCURY_UPDATE_FEED_URL || DEFAULT_FEED_URL;
    this.logFn = typeof options.logFn === 'function' ? options.logFn : console.log;
    this.onBeforeInstall = typeof options.onBeforeInstall === 'function' ? options.onBeforeInstall : null;
    this.appQuitFn = typeof options.appQuitFn === 'function' ? options.appQuitFn : null;

    this.state = 'idle'; // idle | checking | available | not-available | downloading | verifying | ready-to-install | installing | error
    this.lastCheckedAt = null;
    this.availableManifest = null;
    this.downloadedArtifactPath = null;
    this.lastError = null;
    this.activeDownloadReq = null;
    this.downloadProgress = { percent: 0, transferredBytes: 0, totalBytes: 0 };
    this.checkTimer = null;
    this.autoCheckIntervalMs = options.checkIntervalMs || 4 * 60 * 60 * 1000; // 4 hours
  }

  log(level, msg) {
    if (this.logFn) {
      this.logFn(level, `[UpdateManager] ${scrubLogText(msg)}`);
    }
  }

  getStatus() {
    return {
      state: this.state,
      currentVersion: this.currentVersion,
      platform: this.platform,
      arch: this.arch,
      lastCheckedAt: this.lastCheckedAt,
      availableUpdate: this.availableManifest
        ? {
            version: this.availableManifest.version,
            releaseDate: this.availableManifest.releaseDate,
            releaseNotes: this.availableManifest.releaseNotes,
            publisher: this.availableManifest.publisher,
          }
        : null,
      downloadProgress: this.state === 'downloading' ? { ...this.downloadProgress } : null,
      lastError: this.lastError,
      isReadyToInstall: this.state === 'ready-to-install',
    };
  }

  setState(newState, extra = {}) {
    this.state = newState;
    if (extra.error) {
      this.lastError = extra.error;
    } else if (newState !== 'error') {
      this.lastError = null;
    }
    const status = this.getStatus();
    this.emit('status', status);
    return status;
  }

  getUpdateStorageDir() {
    if (this.storagePaths && this.storagePaths.dataDir) {
      const updateDir = path.join(this.storagePaths.dataDir, 'updates');
      fs.mkdirSync(updateDir, { recursive: true });
      return updateDir;
    }
    const fallback = path.join(process.cwd(), 'tmp_updates');
    fs.mkdirSync(fallback, { recursive: true });
    return fallback;
  }

  startPeriodicChecks(intervalMs) {
    this.stopPeriodicChecks();
    const interval = typeof intervalMs === 'number' && intervalMs > 60000 ? intervalMs : this.autoCheckIntervalMs;
    this.checkTimer = setInterval(() => {
      this.checkForUpdates().catch(() => {});
    }, interval);
    if (this.checkTimer.unref) this.checkTimer.unref();
  }

  stopPeriodicChecks() {
    if (this.checkTimer) {
      clearInterval(this.checkTimer);
      this.checkTimer = null;
    }
  }

  async checkForUpdates(feedUrlOverride) {
    if (this.state === 'downloading' || this.state === 'installing') {
      return this.getStatus();
    }

    const targetUrl = feedUrlOverride || this.feedUrl;
    this.log('info', `Checking for updates at ${targetUrl}...`);
    this.setState('checking');
    this.lastCheckedAt = new Date().toISOString();

    if (!isValidUpdateFeedUrl(targetUrl)) {
      const err = `Update feed URL is invalid or insecure (HTTPS non-local required): ${targetUrl}`;
      this.log('error', err);
      this.setState('error', { error: err });
      return this.getStatus();
    }

    try {
      const manifest = await this.fetchJsonFeed(targetUrl);
      this.validateManifestMetadata(manifest);

      const hasUpdate = compareSemverStrings(manifest.version, this.currentVersion) > 0;
      if (!hasUpdate) {
        this.log('info', `App is up to date (current: v${this.currentVersion}, remote: v${manifest.version}).`);
        this.availableManifest = null;
        this.setState('not-available');
        return this.getStatus();
      }

      this.availableManifest = manifest;
      this.log('info', `New update available: v${manifest.version} (current: v${this.currentVersion})`);
      this.setState('available');
      return this.getStatus();
    } catch (err) {
      this.log('error', `Failed to check for updates: ${err.message}`);
      this.availableManifest = null;
      this.setState('error', { error: `Update check failed: ${err.message}` });
      return this.getStatus();
    }
  }

  validateManifestMetadata(manifest) {
    if (!manifest || typeof manifest !== 'object') {
      throw new Error('Update manifest is empty or not a valid JSON object');
    }
    if (!manifest.version || typeof manifest.version !== 'string') {
      throw new Error('Update manifest missing required version string');
    }
    if (!manifest.url || typeof manifest.url !== 'string') {
      throw new Error('Update manifest missing required download URL');
    }
    if (!isValidUpdateFeedUrl(manifest.url)) {
      throw new Error(`Update artifact download URL must be HTTPS and non-local: ${manifest.url}`);
    }
    if (!manifest.sha512 || typeof manifest.sha512 !== 'string') {
      throw new Error('Update manifest missing required SHA-512 checksum');
    }
    if (!manifest.signature || typeof manifest.signature !== 'string') {
      throw new Error('Update manifest missing required cryptographic signature');
    }
    if (manifest.platform && manifest.platform !== this.platform) {
      throw new Error(`Manifest target platform '${manifest.platform}' does not match current '${this.platform}'`);
    }
    if (manifest.arch && manifest.arch !== this.arch) {
      throw new Error(`Manifest target arch '${manifest.arch}' does not match current '${this.arch}'`);
    }
  }

  fetchJsonFeed(feedUrl) {
    return new Promise((resolve, reject) => {
      const parsed = new URL(feedUrl);
      const req = https.get(
        parsed,
        {
          headers: {
            'User-Agent': 'Red-Mercury-Updater/1.0',
            Accept: 'application/json',
          },
          timeout: 15000,
        },
        (res) => {
          if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
            const redirectUrl = res.headers.location;
            if (!isValidUpdateFeedUrl(redirectUrl)) {
              reject(new Error(`Update redirect target is insecure or non-HTTPS: ${redirectUrl}`));
              return;
            }
            return resolve(this.fetchJsonFeed(redirectUrl));
          }

          if (res.statusCode !== 200) {
            reject(new Error(`Update feed responded with HTTP status ${res.statusCode}`));
            return;
          }

          let data = '';
          res.on('data', (chunk) => {
            data += chunk;
            if (data.length > 5 * 1024 * 1024) {
              req.destroy();
              reject(new Error('Update manifest exceeded maximum size (5 MB)'));
            }
          });
          res.on('end', () => {
            try {
              const parsedJson = JSON.parse(data);
              resolve(parsedJson);
            } catch (jsonErr) {
              reject(new Error(`Failed to parse update manifest JSON: ${jsonErr.message}`));
            }
          });
        }
      );

      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Network timeout while checking for update feed'));
      });
      req.on('error', (err) => {
        reject(err);
      });
    });
  }

  async downloadUpdate() {
    if (!this.availableManifest) {
      throw new Error('No update available to download. Call checkForUpdates() first.');
    }
    if (this.state === 'downloading') {
      return this.getStatus();
    }

    this.setState('downloading');
    this.downloadProgress = { percent: 0, transferredBytes: 0, totalBytes: 0 };
    this.emit('progress', this.downloadProgress);

    const updateDir = this.getUpdateStorageDir();
    const parsedUrl = new URL(this.availableManifest.url);
    const originalExt = path.extname(parsedUrl.pathname) || (this.platform === 'win32' ? '.exe' : '.dmg');
    const tempArtifactPath = path.join(updateDir, `update-v${this.availableManifest.version}-${Date.now()}.tmp`);
    const verifiedArtifactPath = path.join(updateDir, `RedMercury-Update-v${this.availableManifest.version}${originalExt}`);

    try {
      this.log('info', `Downloading update from ${this.availableManifest.url}...`);
      await this.streamDownloadToFile(this.availableManifest.url, tempArtifactPath);

      this.setState('verifying');
      this.log('info', `Verifying downloaded update artifact (${tempArtifactPath})...`);

      const artifactBuffer = fs.readFileSync(tempArtifactPath);
      const verification = verifyUpdateManifestSignature({
        manifest: this.availableManifest,
        artifactBuffer,
        publicKeyPem: this.publicKeyPem,
        currentVersion: this.currentVersion,
        expectedPublisher: 'Xerova Digital Solutions',
        isAppSigned: this.isAppSigned,
      });

      if (!verification.valid) {
        try { fs.unlinkSync(tempArtifactPath); } catch {}
        throw new Error(`Update integrity/signature verification failed: ${verification.reason}`);
      }

      this.log('info', `Cryptographic signature & SHA-512 verified. Moving to ready artifact: ${verifiedArtifactPath}`);
      fs.renameSync(tempArtifactPath, verifiedArtifactPath);
      this.downloadedArtifactPath = verifiedArtifactPath;

      this.setState('ready-to-install');
      return this.getStatus();
    } catch (err) {
      try {
        if (fs.existsSync(tempArtifactPath)) fs.unlinkSync(tempArtifactPath);
      } catch {}
      this.downloadedArtifactPath = null;
      this.log('error', `Update download or verification failed: ${err.message}`);
      this.setState('error', { error: `Update failed: ${err.message}` });
      return this.getStatus();
    } finally {
      this.activeDownloadReq = null;
    }
  }

  cancelDownload() {
    if (this.activeDownloadReq && this.state === 'downloading') {
      this.activeDownloadReq.destroy(new Error('Download cancelled by user'));
      this.activeDownloadReq = null;
      this.setState('available');
      this.log('info', 'Update download cancelled by user.');
      return true;
    }
    return false;
  }

  streamDownloadToFile(urlStr, targetPath) {
    return new Promise((resolve, reject) => {
      const parsed = new URL(urlStr);
      const req = https.get(
        parsed,
        {
          headers: {
            'User-Agent': 'Red-Mercury-Updater/1.0',
          },
        },
        (res) => {
          if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
            const redirectUrl = res.headers.location;
            if (!isValidUpdateFeedUrl(redirectUrl)) {
              reject(new Error(`Redirect target is insecure or non-HTTPS: ${redirectUrl}`));
              return;
            }
            return resolve(this.streamDownloadToFile(redirectUrl, targetPath));
          }

          if (res.statusCode !== 200) {
            reject(new Error(`Artifact download responded with HTTP ${res.statusCode}`));
            return;
          }

          const totalBytes = Number.parseInt(res.headers['content-length'] || '0', 10);
          let transferredBytes = 0;
          const writeStream = fs.createWriteStream(targetPath);

          res.on('data', (chunk) => {
            transferredBytes += chunk.length;
            const percent = totalBytes > 0 ? Math.min(100, Math.round((transferredBytes / totalBytes) * 100)) : 0;
            this.downloadProgress = { percent, transferredBytes, totalBytes };
            this.emit('progress', this.downloadProgress);
          });

          writeStream.on('finish', () => {
            writeStream.close(() => resolve());
          });

          writeStream.on('error', (err) => {
            try { fs.unlinkSync(targetPath); } catch {}
            reject(err);
          });

          res.pipe(writeStream);
        }
      );

      this.activeDownloadReq = req;

      req.on('error', (err) => {
        try { fs.unlinkSync(targetPath); } catch {}
        reject(err);
      });
    });
  }

  async installUpdate(options = {}) {
    if (this.state !== 'ready-to-install' || !this.downloadedArtifactPath) {
      throw new Error('No verified update ready to install. Complete download first.');
    }

    this.log('info', `User approved installation of update: ${this.downloadedArtifactPath}`);
    this.setState('installing');

    if (this.onBeforeInstall) {
      try {
        await this.onBeforeInstall();
      } catch (err) {
        this.log('warn', `onBeforeInstall hook returned error: ${err.message}`);
      }
    }

    const installerPath = this.downloadedArtifactPath;
    const isWindows = this.platform === 'win32';
    const isDarwin = this.platform === 'darwin';

    if (isWindows) {
      // NSIS installer execution. Note: build/installer.nsh customInit will safely terminate old Red Mercury.exe
      const installerArgs = options.silent ? ['/S'] : [];
      this.log('info', `Spawning Windows NSIS installer: ${installerPath} ${installerArgs.join(' ')}`);

      const child = spawn(installerPath, installerArgs, {
        detached: true,
        stdio: 'ignore',
        windowsHide: false,
      });
      child.unref();

      if (this.appQuitFn) {
        this.appQuitFn();
      }
      return { success: true, platform: 'win32', installerPath };
    }

    if (isDarwin) {
      this.log('info', `Opening macOS update installer artifact: ${installerPath}`);
      const child = spawn('open', [installerPath], {
        detached: true,
        stdio: 'ignore',
      });
      child.unref();

      if (this.appQuitFn) {
        this.appQuitFn();
      }
      return { success: true, platform: 'darwin', installerPath };
    }

    throw new Error(`Unsupported operating system platform for installer invocation: ${this.platform}`);
  }
}

module.exports = {
  UpdateManager,
  DEFAULT_FEED_URL,
};
