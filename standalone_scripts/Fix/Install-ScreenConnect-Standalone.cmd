@echo off
:: Install-ScreenConnect-Standalone.cmd - Launcher with auto-elevation

set "SCRIPT_DIR=%~dp0"
set "PS_SCRIPT=%~dp0Install-ScreenConnect-Standalone.ps1"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    echo @echo off > "%TEMP%\sc-install-elevated.cmd"
    echo cd /d "%SCRIPT_DIR%" >> "%TEMP%\sc-install-elevated.cmd"
    echo powershell -ExecutionPolicy Bypass -NoProfile -NoExit -File "%PS_SCRIPT%" >> "%TEMP%\sc-install-elevated.cmd"
    powershell -Command "Start-Process cmd.exe -ArgumentList '/k \"%TEMP%\sc-install-elevated.cmd\"' -Verb RunAs"
    exit /b
)

cd /d "%SCRIPT_DIR%"
echo Installing ScreenConnect...
echo.
powershell -ExecutionPolicy Bypass -NoProfile -NoExit -File "%PS_SCRIPT%"
