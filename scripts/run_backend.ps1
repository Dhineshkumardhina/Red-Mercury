# Launch Red Mercury Backend Server (FastAPI + Uvicorn)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
if (-not $ScriptDir) { $ScriptDir = $PSScriptRoot }
$WorkspaceRoot = Split-Path -Parent $ScriptDir
Set-Location "$WorkspaceRoot"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Starting Red Mercury FastAPI Backend on http://127.0.0.1:8001" -ForegroundColor Cyan
Write-Host " Interactive API Docs: http://127.0.0.1:8001/docs" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan

$env:PYTHONPATH = "$WorkspaceRoot\backend"
python -m uvicorn app.main:app --app-dir backend --reload-dir backend/app --host 127.0.0.1 --port 8001 --reload
if ($LASTEXITCODE -ne 0) {
    Write-Host "`n[ERROR] Backend server stopped with exit code: $LASTEXITCODE" -ForegroundColor Red
    Read-Host "Press Enter to exit..."
}
