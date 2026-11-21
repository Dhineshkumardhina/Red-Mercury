# ==============================================================================
# Red Mercury - Start All Services (PowerShell Launcher)
# Starts both FastAPI Backend (port 8001) and React Frontend (port 3000)
# ==============================================================================

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  🛡️  Launching Red Mercury Complete Application Stack     " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
if (-not $ScriptDir) { $ScriptDir = $PSScriptRoot }
$WorkspaceRoot = Split-Path -Parent $ScriptDir
Set-Location "$WorkspaceRoot"

$BackendScript = "$WorkspaceRoot\scripts\run_backend.ps1"
$FrontendScript = "$WorkspaceRoot\scripts\run_frontend.ps1"

# 1. Start FastAPI Backend in a separate PowerShell window
Write-Host "[1/2] Starting Backend API Server (http://127.0.0.1:8001)..." -ForegroundColor Yellow
Start-Process powershell -WorkingDirectory "$WorkspaceRoot" -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-File", "`"$BackendScript`""

# 2. Start Vite Frontend in a separate PowerShell window
Write-Host "[2/2] Starting Frontend UI (http://localhost:3000)..." -ForegroundColor Yellow
Start-Process powershell -WorkingDirectory "$WorkspaceRoot" -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-File", "`"$FrontendScript`""

Write-Host ""
Write-Host "Waiting for services to initialize..." -ForegroundColor DarkGray
Start-Sleep -Seconds 3

# Verify if ports are active
$backendPort = Get-NetTCPConnection -LocalPort 8001 -ErrorAction SilentlyContinue
$frontendPort = Get-NetTCPConnection -LocalPort 3000 -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "  Application Launch Status:                              " -ForegroundColor Green
if ($backendPort) {
    Write-Host "  - Backend API:       http://127.0.0.1:8001  [ONLINE]" -ForegroundColor Green
    Write-Host "  - Swagger API Docs:  http://127.0.0.1:8001/docs" -ForegroundColor White
    Write-Host "  - Health Check:      http://127.0.0.1:8001/api/v1/health" -ForegroundColor White
} else {
    Write-Host "  - Backend API:       http://127.0.0.1:8001  [STARTING / CHECK CONSOLE]" -ForegroundColor Yellow
    Write-Host "  - Swagger API Docs:  http://127.0.0.1:8001/docs" -ForegroundColor White
    Write-Host "  - Health Check:      http://127.0.0.1:8001/api/v1/health" -ForegroundColor White
}

if ($frontendPort) {
    Write-Host "  - Frontend UI:       http://localhost:3000  [ONLINE]" -ForegroundColor Green
} else {
    Write-Host "  - Frontend UI:       http://localhost:3000  [STARTING / CHECK CONSOLE]" -ForegroundColor Yellow
}
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "  Tip: Both servers are running in separate console windows." -ForegroundColor Gray
Write-Host "       Keep those windows open to keep the servers active." -ForegroundColor Gray
Write-Host "==========================================================" -ForegroundColor Green
