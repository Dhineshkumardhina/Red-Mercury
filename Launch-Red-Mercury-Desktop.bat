@echo off
title Red Mercury - Enterprise Desktop App
echo ========================================================
echo       Red Mercury - Desktop Software Launcher
echo            Xerova Digital Solutions
echo ========================================================
echo.
echo [1/2] Verifying Python and Node.js environment...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python 3.11+ is not found in PATH. Please install Python.
    pause
    exit /b 1
)

node -v >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Node.js is not found in PATH. Please install Node.js.
    pause
    exit /b 1
)

echo [2/2] Launching Red Mercury Native Desktop App...
npm run desktop

if %errorlevel% neq 0 (
    echo.
    echo [INFO] Building frontend distribution...
    npm run build
    npm run desktop
)
