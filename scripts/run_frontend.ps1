# Launch Red Mercury Frontend Dev Server (Vite + React)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
if (-not $ScriptDir) { $ScriptDir = $PSScriptRoot }
$WorkspaceRoot = Split-Path -Parent $ScriptDir
Set-Location "$WorkspaceRoot\frontend"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Starting Red Mercury Frontend on http://localhost:3000" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

npm run dev
if ($LASTEXITCODE -ne 0) {
    Write-Host "`n[ERROR] Frontend server stopped with exit code: $LASTEXITCODE" -ForegroundColor Red
    Read-Host "Press Enter to exit..."
}
