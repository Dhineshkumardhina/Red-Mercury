# Setup Script for Red Mercury (Windows PowerShell)
# Xerova Digital Solutions
param (
    [switch]$Force = $false
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Red Mercury - Local Environment Bootstrap" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
if (-not $ScriptDir) { $ScriptDir = $PSScriptRoot }
$WorkspaceRoot = Split-Path -Parent $ScriptDir
Set-Location "$WorkspaceRoot"

# 1. Prepare .env file if missing
if (-not (Test-Path ".env")) {
    Write-Host "[1/4] Creating .env from .env.example..." -ForegroundColor Yellow
    Copy-Item .env.example .env
} else {
    Write-Host "[1/4] Existing .env detected." -ForegroundColor Green
}

# 2. Install backend dependencies (with fast check)
$pyCheck = python -c "import fastapi, uvicorn, sqlalchemy, pydantic, bandit, pip_audit" 2>$null
if ($LASTEXITCODE -eq 0 -and -not $Force) {
    Write-Host "[2/4] Python dependencies already satisfied. (Use -Force to reinstall)" -ForegroundColor Green
} else {
    Write-Host "[2/4] Installing backend dependencies (using cached binary wheels)..." -ForegroundColor Yellow
    python -m pip install --prefer-binary --disable-pip-version-check -r backend/requirements.txt
}

# 3. Run database migrations
Write-Host "[3/4] Running Alembic database migrations..." -ForegroundColor Yellow
$env:PYTHONPATH = "backend"
python -m alembic -c backend/alembic.ini upgrade head

# 4. Install frontend and desktop npm dependencies (with fast check)
Write-Host "[4/4] Verifying desktop and frontend npm packages..." -ForegroundColor Yellow
if (-not (Test-Path "node_modules") -or $Force) {
    Write-Host "      Installing root desktop dependencies..." -ForegroundColor DarkGray
    npm.cmd install --prefer-offline
} else {
    Write-Host "      Root desktop dependencies already installed." -ForegroundColor Green
}

if (-not (Test-Path "frontend/node_modules") -or $Force) {
    Write-Host "      Installing frontend dependencies..." -ForegroundColor DarkGray
    npm.cmd --prefix frontend install --prefer-offline
} else {
    Write-Host "      Frontend dependencies already installed." -ForegroundColor Green
}

Write-Host "==========================================================" -ForegroundColor Green
Write-Host " Setup complete! You can now start the services:" -ForegroundColor Green
Write-Host " Backend:  .\scripts\run_backend.ps1" -ForegroundColor Cyan
Write-Host " Frontend: .\scripts\run_frontend.ps1" -ForegroundColor Cyan
Write-Host " Tests:    .\scripts\run_tests.ps1" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Green
