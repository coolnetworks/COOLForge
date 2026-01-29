@echo off
setlocal EnableDelayedExpansion

:: ============================================================================
:: Run All Offline Scanners
:: ============================================================================
:: Runs all offline AV scanners sequentially with logging.
:: Beeps when complete to alert technician.
::
:: Scanners: MRT, KVRT, TDSSKiller, AdwCleaner, Stinger
:: ============================================================================

title Offline Security Scanner Suite

:: Get the directory where this script is located
set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"
set "LOG_DIR=%SCRIPT_DIR%\Logs"

:: Generate timestamp for log files
for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /value') do set "DT=%%I"
set "TIMESTAMP=%DT:~0,4%-%DT:~4,2%-%DT:~6,2%_%DT:~8,2%%DT:~10,2%%DT:~12,2%"
set "MASTER_LOG=%LOG_DIR%\AllScanners-%TIMESTAMP%.log"

:: Create logs directory if it doesn't exist
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

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
echo       OFFLINE SECURITY SCANNER SUITE
echo  ================================================================================
echo.
echo   This will run the following scanners in sequence:
echo.
echo     1. Microsoft MRT         - Malicious Software Removal Tool
echo     2. Kaspersky KVRT        - Full antivirus scan
echo     3. Kaspersky TDSSKiller  - Rootkit/bootkit scanner
echo     4. Malwarebytes AdwCleaner - Adware/PUP cleaner
echo     5. McAfee Stinger        - Targeted malware removal
echo.
echo   All logs will be saved to: %LOG_DIR%
echo   An audible alert will sound when all scans complete.
echo.
echo  ================================================================================
echo.

:: Check which scanners are available
set "SCANNERS_FOUND=0"
if exist "%SCRIPT_DIR%\MRT.exe" set /a SCANNERS_FOUND+=1
if exist "%SCRIPT_DIR%\KVRT.exe" set /a SCANNERS_FOUND+=1
if exist "%SCRIPT_DIR%\TDSSKiller.exe" set /a SCANNERS_FOUND+=1
if exist "%SCRIPT_DIR%\AdwCleaner.exe" set /a SCANNERS_FOUND+=1
if exist "%SCRIPT_DIR%\Stinger.exe" set /a SCANNERS_FOUND+=1

if %SCANNERS_FOUND%==0 (
    echo  ERROR: No scanners found in toolkit folder.
    echo  Run update-usb-scanners.sh to download scanners.
    echo.
    pause
    exit /b 1
)

echo   Found %SCANNERS_FOUND% scanner(s) available.
echo.

set "CHOICE="
set /p "CHOICE=  Start scanning? [Y/N]: "
if /i not "%CHOICE%"=="Y" (
    echo  Cancelled.
    exit /b 0
)

:: Initialize master log
(
    echo ================================================================================
    echo OFFLINE SECURITY SCANNER SUITE - MASTER LOG
    echo ================================================================================
    echo Started:    %DATE% %TIME%
    echo Computer:   %COMPUTERNAME%
    echo User:       %USERNAME%
    echo ================================================================================
    echo.
) > "%MASTER_LOG%"

set "SCAN_COUNT=0"
set "SCAN_PASS=0"
set "SCAN_FAIL=0"
set "START_TIME=%TIME%"

:: ============================================================================
:: SCANNER 1: Microsoft MRT
:: ============================================================================
if exist "%SCRIPT_DIR%\MRT.exe" (
    echo.
    echo  ================================================================================
    echo   [1/5] MICROSOFT MALICIOUS SOFTWARE REMOVAL TOOL
    echo  ================================================================================
    echo.
    echo   Running full scan... this may take a while.
    echo.

    set /a SCAN_COUNT+=1
    set "MRT_LOG=%LOG_DIR%\MRT-%TIMESTAMP%.log"

    echo [%DATE% %TIME%] Starting MRT scan... >> "%MASTER_LOG%"

    "%SCRIPT_DIR%\MRT.exe" /Q /F
    set "MRT_EXIT=!errorlevel!"

    :: Copy MRT native log if it exists
    if exist "%WINDIR%\Debug\mrt.log" (
        copy /Y "%WINDIR%\Debug\mrt.log" "!MRT_LOG!" >nul 2>&1
    )

    if !MRT_EXIT!==0 (
        echo   [PASS] MRT: No malware detected
        echo [%DATE% %TIME%] MRT: PASS - No malware detected >> "%MASTER_LOG%"
        set /a SCAN_PASS+=1
    ) else (
        echo   [ALERT] MRT: Threats detected or cleaned - check log
        echo [%DATE% %TIME%] MRT: ALERT - Exit code !MRT_EXIT! >> "%MASTER_LOG%"
        set /a SCAN_FAIL+=1
    )
) else (
    echo   [SKIP] MRT.exe not found
    echo [%DATE% %TIME%] MRT: SKIPPED - not found >> "%MASTER_LOG%"
)

:: ============================================================================
:: SCANNER 2: Kaspersky KVRT
:: ============================================================================
if exist "%SCRIPT_DIR%\KVRT.exe" (
    echo.
    echo  ================================================================================
    echo   [2/5] KASPERSKY VIRUS REMOVAL TOOL
    echo  ================================================================================
    echo.
    echo   Running scan... this may take 15-30 minutes.
    echo.

    set /a SCAN_COUNT+=1
    set "KVRT_LOG=%LOG_DIR%\KVRT-%TIMESTAMP%"

    echo [%DATE% %TIME%] Starting KVRT scan... >> "%MASTER_LOG%"

    :: KVRT options: -d report_dir -silent -adinsilent -processlevel 2 (disinfect)
    "%SCRIPT_DIR%\KVRT.exe" -d "!KVRT_LOG!" -silent -accepteula -processlevel 2
    set "KVRT_EXIT=!errorlevel!"

    if !KVRT_EXIT!==0 (
        echo   [PASS] KVRT: Scan completed successfully
        echo [%DATE% %TIME%] KVRT: PASS - Exit code 0 >> "%MASTER_LOG%"
        set /a SCAN_PASS+=1
    ) else (
        echo   [ALERT] KVRT: Threats found or errors - check log folder
        echo [%DATE% %TIME%] KVRT: ALERT - Exit code !KVRT_EXIT! >> "%MASTER_LOG%"
        set /a SCAN_FAIL+=1
    )
) else (
    echo   [SKIP] KVRT.exe not found
    echo [%DATE% %TIME%] KVRT: SKIPPED - not found >> "%MASTER_LOG%"
)

:: ============================================================================
:: SCANNER 3: Kaspersky TDSSKiller
:: ============================================================================
if exist "%SCRIPT_DIR%\TDSSKiller.exe" (
    echo.
    echo  ================================================================================
    echo   [3/5] KASPERSKY TDSSKILLER (Rootkit Scanner)
    echo  ================================================================================
    echo.
    echo   Scanning for rootkits and bootkits...
    echo.

    set /a SCAN_COUNT+=1
    set "TDSS_LOG=%LOG_DIR%\TDSSKiller-%TIMESTAMP%.log"

    echo [%DATE% %TIME%] Starting TDSSKiller scan... >> "%MASTER_LOG%"

    :: TDSSKiller options: -l logfile -silent -qall -dcexact
    "%SCRIPT_DIR%\TDSSKiller.exe" -l "!TDSS_LOG!" -silent -accepteula -qall -dcexact
    set "TDSS_EXIT=!errorlevel!"

    if !TDSS_EXIT!==0 (
        echo   [PASS] TDSSKiller: No rootkits detected
        echo [%DATE% %TIME%] TDSSKiller: PASS - No rootkits >> "%MASTER_LOG%"
        set /a SCAN_PASS+=1
    ) else (
        echo   [ALERT] TDSSKiller: Threats found - check log
        echo [%DATE% %TIME%] TDSSKiller: ALERT - Exit code !TDSS_EXIT! >> "%MASTER_LOG%"
        set /a SCAN_FAIL+=1
    )
) else (
    echo   [SKIP] TDSSKiller.exe not found
    echo [%DATE% %TIME%] TDSSKiller: SKIPPED - not found >> "%MASTER_LOG%"
)

:: ============================================================================
:: SCANNER 4: AdwCleaner
:: ============================================================================
if exist "%SCRIPT_DIR%\AdwCleaner.exe" (
    echo.
    echo  ================================================================================
    echo   [4/5] MALWAREBYTES ADWCLEANER
    echo  ================================================================================
    echo.
    echo   Scanning for adware and PUPs...
    echo.

    set /a SCAN_COUNT+=1
    set "ADW_LOG=%LOG_DIR%\AdwCleaner-%TIMESTAMP%"

    echo [%DATE% %TIME%] Starting AdwCleaner scan... >> "%MASTER_LOG%"

    :: AdwCleaner options: /eula /scan /clean /noreboot /path
    :: Using /scan first, then /clean with /noreboot to prevent auto-reboot
    "%SCRIPT_DIR%\AdwCleaner.exe" /eula /clean /noreboot /preinstalled /path "!ADW_LOG!"
    set "ADW_EXIT=!errorlevel!"

    if !ADW_EXIT!==0 (
        echo   [PASS] AdwCleaner: Scan completed
        echo [%DATE% %TIME%] AdwCleaner: PASS - Completed >> "%MASTER_LOG%"
        set /a SCAN_PASS+=1
    ) else if !ADW_EXIT!==4 (
        echo   [INFO] AdwCleaner: Reboot required for full cleanup
        echo [%DATE% %TIME%] AdwCleaner: INFO - Reboot required >> "%MASTER_LOG%"
        set /a SCAN_PASS+=1
    ) else (
        echo   [ALERT] AdwCleaner: Issues found - check log
        echo [%DATE% %TIME%] AdwCleaner: ALERT - Exit code !ADW_EXIT! >> "%MASTER_LOG%"
        set /a SCAN_FAIL+=1
    )
) else (
    echo   [SKIP] AdwCleaner.exe not found
    echo [%DATE% %TIME%] AdwCleaner: SKIPPED - not found >> "%MASTER_LOG%"
)

:: ============================================================================
:: SCANNER 5: McAfee Stinger
:: ============================================================================
if exist "%SCRIPT_DIR%\Stinger.exe" (
    echo.
    echo  ================================================================================
    echo   [5/5] MCAFEE STINGER
    echo  ================================================================================
    echo.
    echo   Scanning for targeted malware...
    echo.

    set /a SCAN_COUNT+=1
    set "STINGER_LOG=%LOG_DIR%\Stinger-%TIMESTAMP%.html"

    echo [%DATE% %TIME%] Starting Stinger scan... >> "%MASTER_LOG%"

    :: Stinger options: --silent --reportpath --delete --program
    "%SCRIPT_DIR%\Stinger.exe" --silent --reportpath="%LOG_DIR%" --delete --go
    set "STINGER_EXIT=!errorlevel!"

    :: Rename the default report
    if exist "%LOG_DIR%\Stinger*.html" (
        for %%f in ("%LOG_DIR%\Stinger*.html") do (
            if not "%%f"=="!STINGER_LOG!" move /Y "%%f" "!STINGER_LOG!" >nul 2>&1
        )
    )

    if !STINGER_EXIT!==0 (
        echo   [PASS] Stinger: Scan completed
        echo [%DATE% %TIME%] Stinger: PASS - Completed >> "%MASTER_LOG%"
        set /a SCAN_PASS+=1
    ) else (
        echo   [ALERT] Stinger: Threats found - check log
        echo [%DATE% %TIME%] Stinger: ALERT - Exit code !STINGER_EXIT! >> "%MASTER_LOG%"
        set /a SCAN_FAIL+=1
    )
) else (
    echo   [SKIP] Stinger.exe not found
    echo [%DATE% %TIME%] Stinger: SKIPPED - not found >> "%MASTER_LOG%"
)

:: ============================================================================
:: SUMMARY
:: ============================================================================

echo.
echo  ================================================================================
echo   ALL SCANS COMPLETE
echo  ================================================================================
echo.
echo   Started:  %START_TIME%
echo   Finished: %TIME%
echo.
echo   Scanners run: %SCAN_COUNT%
echo   Clean:        %SCAN_PASS%
echo   Alerts:       %SCAN_FAIL%
echo.
echo   Logs saved to: %LOG_DIR%
echo   Master log:    %MASTER_LOG%
echo.

:: Write summary to master log
(
    echo.
    echo ================================================================================
    echo SUMMARY
    echo ================================================================================
    echo Finished:     %DATE% %TIME%
    echo Scanners run: %SCAN_COUNT%
    echo Clean:        %SCAN_PASS%
    echo Alerts:       %SCAN_FAIL%
    echo ================================================================================
) >> "%MASTER_LOG%"

if %SCAN_FAIL% GTR 0 (
    echo  *** ALERTS DETECTED - Review logs for details ***
    echo.
)

:: ============================================================================
:: AUDIBLE ALERT - 5 beeps for all scanners complete
:: ============================================================================

echo  *** BEEPING TO ALERT TECHNICIAN ***
for /L %%i in (1,1,5) do (
    powershell -Command "[console]::beep(1200,200)"
    timeout /t 1 /nobreak >nul
)

echo.
pause
exit /b %SCAN_FAIL%
