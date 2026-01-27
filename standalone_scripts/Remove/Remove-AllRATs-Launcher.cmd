@echo off
setlocal EnableDelayedExpansion

:: ============================================================================
:: Remove All RATs - Launcher Script
:: ============================================================================
:: This launcher runs the RAT removal in two phases:
::   1. WhatIf scan - shows what would be removed (no changes made)
::   2. Full removal - only runs if user confirms
::
:: Logs are saved to the same directory as this script.
:: ============================================================================

title Remove All RATs - Standalone Tool

:: Get the directory where this script is located
set "SCRIPT_DIR=%~dp0"
set "PS_SCRIPT=%SCRIPT_DIR%Remove-AllRATs-Standalone.ps1"

:: Generate timestamp for log files
for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /value') do set "DT=%%I"
set "TIMESTAMP=%DT:~0,4%-%DT:~4,2%-%DT:~6,2%_%DT:~8,2%%DT:~10,2%%DT:~12,2%"
set "LOG_DIR=%SCRIPT_DIR%Logs"
set "SCAN_LOG=%LOG_DIR%\RAT-Scan-%TIMESTAMP%.log"
set "REMOVAL_LOG=%LOG_DIR%\RAT-Removal-%TIMESTAMP%.log"

:: Create logs directory if it doesn't exist
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

:: Check if PowerShell script exists
if not exist "%PS_SCRIPT%" (
    echo.
    echo  ERROR: Cannot find Remove-AllRATs-Standalone.ps1
    echo  Expected location: %PS_SCRIPT%
    echo.
    pause
    exit /b 1
)

:: Check for admin privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo  ============================================================
    echo   ADMINISTRATOR PRIVILEGES REQUIRED
    echo  ============================================================
    echo.
    echo   This tool must be run as Administrator.
    echo.
    echo   Please right-click this file and select:
    echo   "Run as administrator"
    echo.
    pause
    exit /b 1
)

cls
echo.
echo  ================================================================================
echo                        REMOVE ALL RATs - STANDALONE TOOL
echo  ================================================================================
echo.
echo   This tool will scan for and remove unauthorized remote access tools.
echo.
echo   PHASE 1: Scan (WhatIf mode - no changes will be made)
echo            Shows what RATs are installed and what would be removed.
echo.
echo   PHASE 2: Removal (only if you confirm)
echo            Actually removes the detected RATs.
echo.
echo   Log files will be saved to: %LOG_DIR%
echo.
echo  ================================================================================
echo.
pause

:: ============================================================================
:: PHASE 1: WhatIf Scan
:: ============================================================================
cls
echo.
echo  ================================================================================
echo                           PHASE 1: SCANNING (WhatIf Mode)
echo  ================================================================================
echo.
echo   Scanning for remote access tools...
echo   NO CHANGES will be made during this phase.
echo.
echo   Log: %SCAN_LOG%
echo.
echo  --------------------------------------------------------------------------------
echo.

:: Run PowerShell script in WhatIf mode
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%PS_SCRIPT%" -WhatIf -LogPath "%SCAN_LOG%"
set "SCAN_EXIT=%errorlevel%"

echo.
echo  --------------------------------------------------------------------------------
echo.

if %SCAN_EXIT% equ 0 (
    echo   SCAN COMPLETE: No unauthorized RATs detected.
    echo.
    echo   Your system appears clean!
    echo.
    echo   Log saved to: %SCAN_LOG%
    echo.
    pause
    exit /b 0
)

:: RATs were detected
echo   SCAN COMPLETE: Unauthorized RATs were detected!
echo.
echo   Review the output above to see what was found.
echo   Full details are in: %SCAN_LOG%
echo.
echo  ================================================================================
echo.

:: ============================================================================
:: Ask user to proceed with removal
:: ============================================================================
:ASK_REMOVAL
echo.
set /p "CONFIRM=  Do you want to proceed with FULL REMOVAL? [Y/N]: "

if /i "%CONFIRM%"=="Y" goto :DO_REMOVAL
if /i "%CONFIRM%"=="YES" goto :DO_REMOVAL
if /i "%CONFIRM%"=="N" goto :SKIP_REMOVAL
if /i "%CONFIRM%"=="NO" goto :SKIP_REMOVAL

echo   Invalid input. Please enter Y or N.
goto :ASK_REMOVAL

:SKIP_REMOVAL
echo.
echo   Removal skipped by user.
echo   Scan log saved to: %SCAN_LOG%
echo.
pause
exit /b 0

:: ============================================================================
:: PHASE 2: Full Removal
:: ============================================================================
:DO_REMOVAL
cls
echo.
echo  ================================================================================
echo                          PHASE 2: REMOVING RATs
echo  ================================================================================
echo.
echo   WARNING: This will permanently remove detected RATs from this system!
echo.
echo   Log: %REMOVAL_LOG%
echo.
echo  --------------------------------------------------------------------------------
echo.

:: Run PowerShell script with Force flag for removal
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%PS_SCRIPT%" -Force -LogPath "%REMOVAL_LOG%"
set "REMOVAL_EXIT=%errorlevel%"

echo.
echo  --------------------------------------------------------------------------------
echo.

if %REMOVAL_EXIT% equ 0 (
    echo   REMOVAL COMPLETE: All detected RATs have been removed successfully!
) else (
    echo   REMOVAL COMPLETE: Some items may require manual removal or a reboot.
)

echo.
echo   Logs saved to:
echo     Scan:    %SCAN_LOG%
echo     Removal: %REMOVAL_LOG%
echo.
echo  ================================================================================
echo.
pause
exit /b %REMOVAL_EXIT%
