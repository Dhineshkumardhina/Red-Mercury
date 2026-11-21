# Red Mercury Desktop Software Launcher
# Xerova Digital Solutions

$Host.UI.RawUI.WindowTitle = "Red Mercury Desktop Engine"

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "      Red Mercury - Desktop Software Launcher" -ForegroundColor White
Write-Host "           Xerova Digital Solutions" -ForegroundColor Gray
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ProjectRoot

# Check prerequisites
Write-Host "[1/3] Checking environment..." -ForegroundColor Yellow
$py = Get-Command python -ErrorAction SilentlyContinue
$node = Get-Command node -ErrorAction SilentlyContinue

if (-not $py) {
    Write-Host "[ERROR] Python 3.11+ is not found in PATH." -ForegroundColor Red
    pause
    exit 1
}

if (-not $node) {
    Write-Host "[ERROR] Node.js is not found in PATH." -ForegroundColor Red
    pause
    exit 1
}

# Verify frontend build exists
Write-Host "[2/3] Checking UI bundle..." -ForegroundColor Yellow
if (-not (Test-Path "$ProjectRoot\frontend\dist\index.html")) {
    Write-Host "Building UI production bundle for desktop..." -ForegroundColor Cyan
    npm run build
}

# Launch desktop app
Write-Host "[3/3] Launching Red Mercury Desktop Software..." -ForegroundColor Green
npm run desktop
