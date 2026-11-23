/**
 * Red Mercury Desktop Update Manifest Generator
 *
 * Generates an Ed25519-signed update manifest for a built installer artifact.
 * The signature covers the canonical payload:
 *   `${version}|${url}|${sha512}|${publisher}`
 *
 * Private signing key is loaded strictly from environment variable
 * REDMERCURY_UPDATE_SIGNING_KEY or an explicitly provided key file.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function parseArgs() {
  const args = process.argv.slice(2);
  const options = {
    version: '',
    url: '',
    artifactPath: '',
    outputPath: '',
    platform: process.platform === 'win32' ? 'win32' : 'darwin',
    arch: process.arch,
    publisher: 'Xerova Digital Solutions',
    keyFile: '',
    releaseNotes: '',
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--version' && args[i + 1]) options.version = args[++i];
    else if (arg === '--url' && args[i + 1]) options.url = args[++i];
    else if (arg === '--artifact' && args[i + 1]) options.artifactPath = args[++i];
    else if (arg === '--output' && args[i + 1]) options.outputPath = args[++i];
    else if (arg === '--platform' && args[i + 1]) options.platform = args[++i];
    else if (arg === '--arch' && args[i + 1]) options.arch = args[++i];
    else if (arg === '--publisher' && args[i + 1]) options.publisher = args[++i];
    else if (arg === '--key-file' && args[i + 1]) options.keyFile = args[++i];
    else if (arg === '--release-notes' && args[i + 1]) options.releaseNotes = args[++i];
  }

  return options;
}

function resolveSigningPrivateKey(keyFile) {
  if (process.env.REDMERCURY_UPDATE_SIGNING_KEY) {
    return process.env.REDMERCURY_UPDATE_SIGNING_KEY.trim();
  }
  if (keyFile && fs.existsSync(keyFile)) {
    return fs.readFileSync(keyFile, 'utf8').trim();
  }
  throw new Error('Signing private key not found. Set REDMERCURY_UPDATE_SIGNING_KEY or specify --key-file.');
}

function generateManifest(options) {
  if (!options.artifactPath || !fs.existsSync(options.artifactPath)) {
    throw new Error(`Artifact file not found at: ${options.artifactPath}`);
  }
  if (!options.version) {
    throw new Error('Version is required (e.g. --version 1.1.0)');
  }
  if (!options.url) {
    throw new Error('Update download URL is required (e.g. --url https://github.com/...)');
  }

  const artifactBuffer = fs.readFileSync(options.artifactPath);
  const sha512 = crypto.createHash('sha512').update(artifactBuffer).digest('base64');
  const privateKeyPem = resolveSigningPrivateKey(options.keyFile);

  const canonicalPayload = Buffer.from(
    `${options.version}|${options.url}|${sha512}|${options.publisher}`,
    'utf8'
  );

  const signature = crypto.sign(null, canonicalPayload, privateKeyPem).toString('base64');

  const manifest = {
    version: options.version,
    url: options.url,
    sha512,
    publisher: options.publisher,
    platform: options.platform,
    arch: options.arch,
    releaseDate: new Date().toISOString(),
    releaseNotes: options.releaseNotes || `Red Mercury Desktop v${options.version} release.`,
    signature,
  };

  const jsonStr = JSON.stringify(manifest, null, 2);

  if (options.outputPath) {
    fs.mkdirSync(path.dirname(path.resolve(options.outputPath)), { recursive: true });
    fs.writeFileSync(options.outputPath, jsonStr, 'utf8');
    console.log(`[manifest] Signed update manifest written to ${options.outputPath}`);
  }

  return manifest;
}

if (require.main === module) {
  try {
    const opts = parseArgs();
    const manifest = generateManifest(opts);
    if (!opts.outputPath) {
      console.log(JSON.stringify(manifest, null, 2));
    }
  } catch (err) {
    console.error(`[manifest error] ${err.message}`);
    process.exit(1);
  }
}

module.exports = {
  generateManifest,
};
