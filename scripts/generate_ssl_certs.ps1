# ==============================================================================
# Red Mercury - Generate SSL/TLS Certificates (Windows PowerShell)
# ==============================================================================
$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$sslDir = Join-Path $repoRoot "ssl"

if (-not (Test-Path $sslDir)) {
    New-Item -ItemType Directory -Path $sslDir -Force | Out-Null
}

$pyScript = Join-Path $scriptDir "generate_ssl_certs.py"
python $pyScript --output-dir $sslDir
