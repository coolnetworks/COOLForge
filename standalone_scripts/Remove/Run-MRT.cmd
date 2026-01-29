@echo off
setlocal EnableDelayedExpansion

:: ============================================================================
:: Microsoft Malicious Software Removal Tool - Launcher
:: ============================================================================
:: Runs MRT.exe with logging to the Logs folder.
:: Beeps when complete to alert the technician.
:: ============================================================================

title Microsoft Malicious Software Removal Tool

:: Get the directory where this script is located
set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"
set "MRT_EXE=%SCRIPT_DIR%\MRT.exe"
set "LOG_DIR=%SCRIPT_DIR%\Logs"

:: Generate timestamp for log file
for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /value') do set "DT=%%I"
set "TIMESTAMP=%DT:~0,4%-%DT:~4,2%-%DT:~6,2%_%DT:~8,2%%DT:~10,2%%DT:~12,2%"
set "MRT_LOG=%LOG_DIR%\MRT-%TIMESTAMP%.log"

:: Create logs directory if it doesn't exist
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

:: Check if MRT.exe exists
if not exist "%MRT_EXE%" (
    echo.
    echo  ERROR: Cannot find MRT.exe
    echo  Expected location: %MRT_EXE%
    echo.
    echo  Run Copy-ToUSB.cmd or Copy-SecurityToolkit-ToUSB.cmd first
    echo  to download MRT.exe from Microsoft.
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
echo       MICROSOFT MALICIOUS SOFTWARE REMOVAL TOOL (MRT)
echo  ================================================================================
echo.
echo   This tool scans for and removes known malware from Windows systems.
echo.
echo   Scan modes:
echo     [1] Quick Scan  - System folders only (fastest)
echo     [2] Full Scan   - All drives (thorough, may take 30+ minutes)
echo     [3] Full Scan + Auto-Clean - Remove threats automatically
echo.
echo   Log will be saved to: %LOG_DIR%
echo.
echo  ================================================================================
echo.

set "CHOICE="
set /p "CHOICE=  Select scan mode [1/2/3] or Q to quit: "

if /i "%CHOICE%"=="Q" (
    echo  Cancelled.
    exit /b 0
)
if "%CHOICE%"=="1" (
    set "MRT_MODE=/Q"
    set "MODE_DESC=Quick Scan"
)
if "%CHOICE%"=="2" (
    set "MRT_MODE=/Q /F"
    set "MODE_DESC=Full Scan"
)
if "%CHOICE%"=="3" (
    set "MRT_MODE=/Q /F:Y"
    set "MODE_DESC=Full Scan + Auto-Clean"
)

if not defined MRT_MODE (
    echo  Invalid choice.
    pause
    exit /b 1
)

echo.
echo  ================================================================================
echo   STARTING %MODE_DESC%
echo  ================================================================================
echo.
echo   Started: %DATE% %TIME%
echo   Mode: %MODE_DESC%
echo   This may take a while. An audible beep will sound when complete.
echo.

:: Write log header
(
    echo ================================================================================
    echo Microsoft Malicious Software Removal Tool Log
    echo ================================================================================
    echo Started:    %DATE% %TIME%
    echo Computer:   %COMPUTERNAME%
    echo User:       %USERNAME%
    echo Mode:       %MODE_DESC%
    echo MRT Path:   %MRT_EXE%
    echo ================================================================================
    echo.
) > "%MRT_LOG%"

:: Run MRT and capture output
echo   Running MRT.exe %MRT_MODE% ...
echo.

:: MRT writes its own log to %WINDIR%\Debug\mrt.log - we'll copy it after
"%MRT_EXE%" %MRT_MODE%
set "MRT_EXIT=%errorlevel%"

:: Copy MRT's native log if it exists
if exist "%WINDIR%\Debug\mrt.log" (
    echo. >> "%MRT_LOG%"
    echo === MRT Native Log === >> "%MRT_LOG%"
    type "%WINDIR%\Debug\mrt.log" >> "%MRT_LOG%"
)

:: Write completion info
(
    echo.
    echo ================================================================================
    echo Completed: %DATE% %TIME%
    echo Exit Code: %MRT_EXIT%
    echo ================================================================================
) >> "%MRT_LOG%"

echo.
echo  ================================================================================
echo   SCAN COMPLETE
echo  ================================================================================
echo.
echo   Exit code: %MRT_EXIT%
echo   Log saved: %MRT_LOG%
echo.

if %MRT_EXIT%==0 (
    echo   Result: No malware detected
    echo.
) else (
    echo   Result: Malware was detected - check log for details
    echo.
)

:: AUDIBLE BEEPS - 3 beeps to alert technician
echo   *** BEEPING TO ALERT TECHNICIAN ***
for /L %%i in (1,1,3) do (
    powershell -Command "[console]::beep(1000,300)"
    timeout /t 1 /nobreak >nul
)

echo.
pause
exit /b %MRT_EXIT%
