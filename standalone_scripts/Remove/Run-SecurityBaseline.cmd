@echo off
setlocal

:: ============================================================================
:: Security Baseline Checker - Launcher Script
:: ============================================================================
:: Runs the comprehensive 36-section Windows security audit.
:: Report is saved to the same directory as this script.
:: ============================================================================

title Security Baseline Checker

:: Get the directory where this script is located (remove trailing backslash)
set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"
set "PS_SCRIPT=%SCRIPT_DIR%\Check-SecurityBaseline.ps1"

:: Check if PowerShell script exists
if not exist "%PS_SCRIPT%" (
    echo.
    echo  ERROR: Cannot find Check-SecurityBaseline.ps1
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
echo                      SECURITY BASELINE CHECKER
echo  ================================================================================
echo.
echo   This tool performs a comprehensive 36-section Windows security audit.
echo.
echo   Checks include:
echo     - Windows Defender, Firewall, UAC
echo     - Keylogger indicators, persistence mechanisms
echo     - Browser extensions, scheduled tasks
echo     - Network indicators, ransomware signs
echo     - And much more...
echo.
echo   A temporary Defender exclusion will be added to prevent false positives.
echo   It will be automatically removed when the scan completes.
echo.
echo   Report will be saved to: %SCRIPT_DIR%
echo.
echo  ================================================================================
echo.
pause

:: Add temporary Defender exclusion
echo.
echo  Adding temporary Defender exclusion...
powershell -NoProfile -Command "Add-MpPreference -ExclusionPath '%SCRIPT_DIR%'" 2>nul
if %errorlevel% neq 0 (
    echo  [!] Could not add exclusion - script may be blocked by Defender.
    echo      Add manually: Windows Security ^> Exclusions ^> Add folder
    echo.
    pause
)

echo.
echo  ================================================================================
echo   RUNNING SECURITY BASELINE CHECK
echo  ================================================================================
echo.

:: Run the PowerShell script
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%PS_SCRIPT%" -OutputPath "%SCRIPT_DIR%"
set "SCAN_EXIT=%errorlevel%"

echo.
echo  ================================================================================
echo   CLEANUP
echo  ================================================================================
echo.
echo  Removing Defender exclusion...
powershell -NoProfile -Command "Remove-MpPreference -ExclusionPath '%SCRIPT_DIR%'" 2>nul

echo.
echo  ================================================================================
echo   SCAN COMPLETE
echo  ================================================================================
echo.
echo   Report saved to: %SCRIPT_DIR%
echo   Look for: SecurityBaseline-*.txt
echo.
pause
exit /b %SCAN_EXIT%
