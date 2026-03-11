@echo off
:: level-debug.cmd — Launcher with auto-elevation for level-debug.ps1

:: Resolve full paths NOW before elevation loses them
set "SCRIPT_DIR=%~dp0"
set "PS_SCRIPT=%~dp0level-debug.ps1"

:: Check for admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Script location: %PS_SCRIPT%
    echo Requesting administrator privileges...
    :: Write a temp launcher that has the absolute path baked in
    echo @echo off > "%TEMP%\level-debug-elevated.cmd"
    echo cd /d "%SCRIPT_DIR%" >> "%TEMP%\level-debug-elevated.cmd"
    echo powershell -ExecutionPolicy Bypass -NoProfile -NoExit -File "%PS_SCRIPT%" >> "%TEMP%\level-debug-elevated.cmd"
    powershell -Command "Start-Process cmd.exe -ArgumentList '/k \"%TEMP%\level-debug-elevated.cmd\"' -Verb RunAs"
    exit /b
)

:: We're already admin — run directly
cd /d "%SCRIPT_DIR%"
echo Running Level agent diagnostics as Administrator...
echo.
powershell -ExecutionPolicy Bypass -NoProfile -NoExit -File "%PS_SCRIPT%"
