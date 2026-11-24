/**
 * Electron Builder afterSign hook for macOS notarization.
 *
 * Runs notarization only when Apple Developer credentials are explicitly provided
 * via environment variables; otherwise skips cleanly so unsigned/ad-hoc CI builds
 * are clearly reported without failing or misreporting signing status.
 */
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

exports.default = async function afterSign(context) {
  if (context.electronPlatformName !== 'darwin') {
    return;
  }

  const appName = context.packager.appInfo.productFilename;
  const appPath = path.join(context.appOutDir, `${appName}.app`);

  const hasAppleIdAuth = Boolean(
    process.env.APPLE_ID &&
      process.env.APPLE_APP_SPECIFIC_PASSWORD &&
      process.env.APPLE_TEAM_ID
  );
  const hasApiKeyAuth = Boolean(
    process.env.APPLE_API_KEY &&
      process.env.APPLE_API_KEY_ID &&
      process.env.APPLE_API_ISSUER
  );

  if (!hasAppleIdAuth && !hasApiKeyAuth) {
    console.log(
      `[notarize] Skipping macOS notarization for ${appPath}: Apple Developer credentials not configured (unsigned build).`
    );
    return;
  }

  if (!fs.existsSync(appPath)) {
    throw new Error(`[notarize] Expected app bundle missing at ${appPath}`);
  }

  const zipPath = path.join(context.appOutDir, `${appName}-notarize.zip`);
  try {
    console.log(`[notarize] Archiving ${appPath} for Apple notarytool submission...`);
    execFileSync('ditto', ['-c', '-k', '--keepParent', appPath, zipPath], { stdio: 'inherit' });

    const notaryArgs = ['notarytool', 'submit', zipPath, '--wait'];
    if (hasApiKeyAuth) {
      notaryArgs.push(
        '--key', process.env.APPLE_API_KEY,
        '--key-id', process.env.APPLE_API_KEY_ID,
        '--issuer', process.env.APPLE_API_ISSUER
      );
    } else {
      notaryArgs.push(
        '--apple-id', process.env.APPLE_ID,
        '--password', process.env.APPLE_APP_SPECIFIC_PASSWORD,
        '--team-id', process.env.APPLE_TEAM_ID
      );
    }

    execFileSync('xcrun', notaryArgs, { stdio: 'inherit' });
    execFileSync('xcrun', ['stapler', 'staple', appPath], { stdio: 'inherit' });
    console.log(`[notarize] Successfully notarized and stapled ${appPath}`);
  } finally {
    if (fs.existsSync(zipPath)) {
      fs.rmSync(zipPath, { force: true });
    }
  }
};
