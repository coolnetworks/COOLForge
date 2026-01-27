@echo off
setlocal EnableDelayedExpansion

:: ============================================================================
:: Copy Security Toolkit to USB Drive
:: ============================================================================
:: This script:
::   1. Asks for the target USB drive letter
::   2. Creates a Security-Toolkit folder structure
::   3. Downloads all security scanning tools
::   4. Copies RAT removal scripts
::   5. Creates orchestrator and README
:: ============================================================================

title Copy Security Toolkit to USB

:: Get the directory where this script is located
set "SCRIPT_DIR=%~dp0"

cls
echo.
echo  ================================================================================
echo              COPY SECURITY TOOLKIT TO USB DRIVE
echo  ================================================================================
echo.
echo   This will create a comprehensive security toolkit on a USB drive:
echo.
echo   DETECTION TOOLS:
echo     - Autoruns (Sysinternals)     Enumerate all auto-start locations
echo     - PersistenceSniper           PowerShell persistence detector
echo     - Trawler                     IR-focused persistence scanner
echo     - LOKI                        IOC and YARA scanner
echo.
echo   REMEDIATION TOOLS:
echo     - Microsoft MRT               Malicious Software Removal Tool
echo     - RAT Removal Toolkit         Remove unauthorized remote access tools
echo.
echo   All tools are configured to run OFFLINE after initial download.
echo.
echo  ================================================================================
echo.

:: Check for required files
echo  Checking source files...
echo.

set "MISSING_FILES=0"

if exist "%SCRIPT_DIR%Remove-AllRATs-Standalone.ps1" (
    echo   [OK] Remove-AllRATs-Standalone.ps1
) else (
    echo   [MISSING] Remove-AllRATs-Standalone.ps1
    set "MISSING_FILES=1"
)

if exist "%SCRIPT_DIR%Remove-AllRATs-Launcher.cmd" (
    echo   [OK] Remove-AllRATs-Launcher.cmd
) else (
    echo   [MISSING] Remove-AllRATs-Launcher.cmd
    set "MISSING_FILES=1"
)

echo.

if "%MISSING_FILES%"=="1" (
    echo  ERROR: Required files are missing!
    echo  Please run this script from the correct directory.
    echo.
    pause
    exit /b 1
)

:: Show available drives
echo  ================================================================================
echo   AVAILABLE DRIVES
echo  ================================================================================
echo.
echo   The following removable drives were detected:
echo.

:: Use PowerShell to list removable drives
powershell -NoProfile -Command "Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DriveType -eq 2 } | ForEach-Object { Write-Host ('   ' + $_.DeviceID + '  ' + $(if($_.VolumeName){'['+$_.VolumeName+']'}else{'[No Label]'}).PadRight(20) + [math]::Round($_.Size/1GB,1).ToString().PadLeft(6) + ' GB total, ' + [math]::Round($_.FreeSpace/1GB,1).ToString().PadLeft(6) + ' GB free') }"

echo.
echo   (If no drives shown above, insert a USB drive and restart this script)
echo.
echo   NOTE: Approximately 200MB of free space required for all tools.
echo.
echo  --------------------------------------------------------------------------------
echo.

:: Ask for drive letter
:ASK_DRIVE
set /p "DRIVE_LETTER=  Enter USB drive letter (e.g., E): "

:: Clean up input - remove colon and spaces, convert to uppercase
set "DRIVE_LETTER=%DRIVE_LETTER: =%"
set "DRIVE_LETTER=%DRIVE_LETTER::=%"

:: Validate input
if "%DRIVE_LETTER%"=="" (
    echo   Please enter a drive letter.
    goto :ASK_DRIVE
)

:: Check if it's a single letter
set "DRIVE_CHECK=%DRIVE_LETTER:~1%"
if not "%DRIVE_CHECK%"=="" (
    echo   Please enter a single letter (e.g., E).
    goto :ASK_DRIVE
)

:: Set target paths
set "TARGET_DRIVE=%DRIVE_LETTER%:"
set "TOOLKIT_ROOT=%TARGET_DRIVE%\Security-Toolkit"
set "RAT_FOLDER=%TOOLKIT_ROOT%\RAT-Removal"
set "AUTORUNS_FOLDER=%TOOLKIT_ROOT%\Autoruns"
set "PERSISTENCE_FOLDER=%TOOLKIT_ROOT%\PersistenceSniper"
set "TRAWLER_FOLDER=%TOOLKIT_ROOT%\Trawler"
set "LOKI_FOLDER=%TOOLKIT_ROOT%\Loki"
set "REPORTS_FOLDER=%TOOLKIT_ROOT%\Reports"

:: Check if drive exists
if not exist "%TARGET_DRIVE%\" (
    echo.
    echo   ERROR: Drive %TARGET_DRIVE% does not exist or is not accessible.
    echo.
    goto :ASK_DRIVE
)

echo.
echo   Target folder: %TOOLKIT_ROOT%
echo.

:: Confirm
set /p "CONFIRM=  Proceed with download and copy? [Y/N]: "
if /i not "%CONFIRM%"=="Y" (
    echo.
    echo   Cancelled.
    echo.
    pause
    exit /b 0
)

echo.
echo  ================================================================================
echo   CREATING FOLDER STRUCTURE
echo  ================================================================================
echo.

:: Create all folders
for %%F in ("%TOOLKIT_ROOT%" "%RAT_FOLDER%" "%RAT_FOLDER%\Logs" "%AUTORUNS_FOLDER%" "%PERSISTENCE_FOLDER%" "%TRAWLER_FOLDER%" "%LOKI_FOLDER%" "%REPORTS_FOLDER%") do (
    if not exist "%%~F" (
        mkdir "%%~F"
        echo   Created: %%~F
    )
)

echo.
echo  ================================================================================
echo   DOWNLOADING TOOLS
echo  ================================================================================
echo.

:: ============================================================================
:: 1. AUTORUNS (Sysinternals)
:: ============================================================================
echo   [1/5] Downloading Autoruns (Sysinternals)...

set "AUTORUNS_URL=https://download.sysinternals.com/files/Autoruns.zip"
set "AUTORUNS_ZIP=%TOOLKIT_ROOT%\autoruns_temp.zip"

powershell -NoProfile -Command "try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri '%AUTORUNS_URL%' -OutFile '%AUTORUNS_ZIP%' -UseBasicParsing; Expand-Archive -Path '%AUTORUNS_ZIP%' -DestinationPath '%AUTORUNS_FOLDER%' -Force; Remove-Item '%AUTORUNS_ZIP%' -Force; Write-Host '         [OK] Autoruns downloaded and extracted' -ForegroundColor Green } catch { Write-Host '         [FAIL] Autoruns download failed:' $_.Exception.Message -ForegroundColor Red }"

:: ============================================================================
:: 2. PERSISTENCESNIPER (PowerShell Gallery)
:: ============================================================================
echo.
echo   [2/5] Downloading PersistenceSniper...

:: Download directly from GitHub releases
set "PS_SNIPER_URL=https://github.com/last-byte/PersistenceSniper/releases/latest/download/PersistenceSniper.zip"
set "PS_SNIPER_ZIP=%TOOLKIT_ROOT%\persistencesniper_temp.zip"

powershell -NoProfile -Command "try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri '%PS_SNIPER_URL%' -OutFile '%PS_SNIPER_ZIP%' -UseBasicParsing; Expand-Archive -Path '%PS_SNIPER_ZIP%' -DestinationPath '%PERSISTENCE_FOLDER%' -Force; Remove-Item '%PS_SNIPER_ZIP%' -Force; Write-Host '         [OK] PersistenceSniper downloaded' -ForegroundColor Green } catch { Write-Host '         [FAIL] PersistenceSniper download failed:' $_.Exception.Message -ForegroundColor Red; Write-Host '         Trying alternative method...' -ForegroundColor Yellow }"

:: If ZIP download failed, try direct file download
if not exist "%PERSISTENCE_FOLDER%\PersistenceSniper.psm1" (
    if not exist "%PERSISTENCE_FOLDER%\PersistenceSniper\PersistenceSniper.psm1" (
        powershell -NoProfile -Command "try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/last-byte/PersistenceSniper/main/PersistenceSniper/PersistenceSniper.psd1' -OutFile '%PERSISTENCE_FOLDER%\PersistenceSniper.psd1' -UseBasicParsing; Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/last-byte/PersistenceSniper/main/PersistenceSniper/PersistenceSniper.psm1' -OutFile '%PERSISTENCE_FOLDER%\PersistenceSniper.psm1' -UseBasicParsing; Write-Host '         [OK] PersistenceSniper downloaded (direct)' -ForegroundColor Green } catch { Write-Host '         [FAIL] PersistenceSniper download failed' -ForegroundColor Red }"
    )
)

:: ============================================================================
:: 3. TRAWLER
:: ============================================================================
echo.
echo   [3/5] Downloading Trawler...

set "TRAWLER_URL=https://raw.githubusercontent.com/joeavanzato/Trawler/main/trawler.ps1"

powershell -NoProfile -Command "try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri '%TRAWLER_URL%' -OutFile '%TRAWLER_FOLDER%\trawler.ps1' -UseBasicParsing; Write-Host '         [OK] Trawler downloaded' -ForegroundColor Green } catch { Write-Host '         [FAIL] Trawler download failed:' $_.Exception.Message -ForegroundColor Red }"

:: ============================================================================
:: 4. LOKI
:: ============================================================================
echo.
echo   [4/5] Downloading LOKI IOC Scanner...
echo         (This may take a minute - includes signature database)

set "LOKI_URL=https://github.com/Neo23x0/Loki/releases/download/v0.51.0/loki_0.51.0.zip"
set "LOKI_ZIP=%TOOLKIT_ROOT%\loki_temp.zip"

powershell -NoProfile -Command "try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri '%LOKI_URL%' -OutFile '%LOKI_ZIP%' -UseBasicParsing -TimeoutSec 120; Expand-Archive -Path '%LOKI_ZIP%' -DestinationPath '%LOKI_FOLDER%' -Force; Remove-Item '%LOKI_ZIP%' -Force; Write-Host '         [OK] LOKI downloaded and extracted' -ForegroundColor Green } catch { Write-Host '         [FAIL] LOKI download failed:' $_.Exception.Message -ForegroundColor Red }"

:: Download/update LOKI signatures
echo         Updating LOKI signatures...
if exist "%LOKI_FOLDER%\loki\loki-upgrader.exe" (
    pushd "%LOKI_FOLDER%\loki"
    loki-upgrader.exe --nolog 2>nul
    popd
    echo         [OK] LOKI signatures updated
) else if exist "%LOKI_FOLDER%\loki-upgrader.exe" (
    pushd "%LOKI_FOLDER%"
    loki-upgrader.exe --nolog 2>nul
    popd
    echo         [OK] LOKI signatures updated
) else (
    echo         [--] Signature update skipped (upgrader not found)
)

:: ============================================================================
:: 5. MICROSOFT MRT
:: ============================================================================
echo.
echo   [5/5] Downloading Microsoft Malicious Software Removal Tool...

:: Detect system architecture
if "%PROCESSOR_ARCHITECTURE%"=="AMD64" (
    set "MRT_URL=https://go.microsoft.com/fwlink/?LinkId=212732"
    set "MRT_ARCH=64-bit"
) else (
    set "MRT_URL=https://go.microsoft.com/fwlink/?LinkId=212733"
    set "MRT_ARCH=32-bit"
)

set "MRT_FILE=%TOOLKIT_ROOT%\MRT.exe"

powershell -NoProfile -Command "try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri '%MRT_URL%' -OutFile '%MRT_FILE%' -UseBasicParsing; Write-Host '         [OK] MRT downloaded (%MRT_ARCH%)' -ForegroundColor Green } catch { Write-Host '         [FAIL] MRT download failed:' $_.Exception.Message -ForegroundColor Red }"

echo.
echo  ================================================================================
echo   COPYING RAT REMOVAL SCRIPTS
echo  ================================================================================
echo.

:: Copy RAT removal scripts
copy /Y "%SCRIPT_DIR%Remove-AllRATs-Standalone.ps1" "%RAT_FOLDER%\" >nul && echo   [OK] Remove-AllRATs-Standalone.ps1
copy /Y "%SCRIPT_DIR%Remove-AllRATs-Launcher.cmd" "%RAT_FOLDER%\" >nul && echo   [OK] Remove-AllRATs-Launcher.cmd

if exist "%SCRIPT_DIR%Remove-AnyDesk-Standalone.ps1" (
    copy /Y "%SCRIPT_DIR%Remove-AnyDesk-Standalone.ps1" "%RAT_FOLDER%\" >nul && echo   [OK] Remove-AnyDesk-Standalone.ps1
)

if exist "%SCRIPT_DIR%Remove-NonMspScreenConnect-Standalone.ps1" (
    copy /Y "%SCRIPT_DIR%Remove-NonMspScreenConnect-Standalone.ps1" "%RAT_FOLDER%\" >nul && echo   [OK] Remove-NonMspScreenConnect-Standalone.ps1
)

echo.
echo  ================================================================================
echo   CREATING ORCHESTRATOR SCRIPT
echo  ================================================================================
echo.

:: Create the main orchestrator script
(
echo @echo off
echo setlocal EnableDelayedExpansion
echo.
echo :: ============================================================================
echo :: Security Toolkit - Main Orchestrator
echo :: ============================================================================
echo :: Run Order ^(Detection before Remediation^):
echo ::   1. Autoruns      - Fast snapshot of all auto-start locations
echo ::   2. PersistenceSniper - Comprehensive persistence detection
echo ::   3. Trawler       - IR-focused persistence scanner with allow lists
echo ::   4. LOKI          - Deep IOC/YARA scan of files and memory
echo ::   5. MRT           - Microsoft malware scan ^(optional^)
echo ::   6. RAT Removal   - Remove unauthorized remote access ^(if needed^)
echo :: ============================================================================
echo.
echo title Security Toolkit - Comprehensive Scan
echo.
echo :: Get script directory
echo set "TOOLKIT_DIR=%%~dp0"
echo set "REPORTS_DIR=%%TOOLKIT_DIR%%Reports"
echo.
echo :: Generate timestamp
echo for /f "tokens=2 delims==" %%%%I in ^('wmic os get localdatetime /value'^) do set "DT=%%%%I"
echo set "TIMESTAMP=%%DT:~0,4%%-%%DT:~4,2%%-%%DT:~6,2%%_%%DT:~8,2%%%%DT:~10,2%%%%DT:~12,2%%"
echo set "SCAN_PREFIX=%%REPORTS_DIR%%\Scan-%%TIMESTAMP%%"
echo.
echo :: Create reports directory
echo if not exist "%%REPORTS_DIR%%" mkdir "%%REPORTS_DIR%%"
echo.
echo :: Check for admin
echo net session ^>nul 2^>^&1
echo if %%errorlevel%% neq 0 ^(
echo     echo.
echo     echo  ============================================================
echo     echo   ADMINISTRATOR PRIVILEGES REQUIRED
echo     echo  ============================================================
echo     echo.
echo     echo   Right-click this file and select "Run as administrator"
echo     echo.
echo     pause
echo     exit /b 1
echo ^)
echo.
echo cls
echo echo.
echo echo  ================================================================================
echo echo                    SECURITY TOOLKIT - COMPREHENSIVE SCAN
echo echo  ================================================================================
echo echo.
echo echo   This toolkit will run multiple security scans in optimal order:
echo echo.
echo echo   PHASE 1 - DETECTION ^(No changes made^)
echo echo     Step 1: Autoruns          - Enumerate all auto-start locations
echo echo     Step 2: PersistenceSniper - Detect persistence mechanisms
echo echo     Step 3: Trawler           - IR-focused persistence scan
echo echo     Step 4: LOKI              - IOC and YARA signature scan
echo echo.
echo echo   PHASE 2 - REMEDIATION ^(Optional, requires confirmation^)
echo echo     Step 5: Microsoft MRT     - Malware removal ^(optional^)
echo echo     Step 6: RAT Removal       - Remove unauthorized remote access
echo echo.
echo echo   All reports will be saved to: %%REPORTS_DIR%%
echo echo.
echo echo  ================================================================================
echo echo.
echo pause
echo.
echo :: ============================================================================
echo :: PHASE 1: DETECTION
echo :: ============================================================================
echo.
echo :: ----------------------------------------------------------------------------
echo :: STEP 1: AUTORUNS
echo :: ----------------------------------------------------------------------------
echo cls
echo echo.
echo echo  ================================================================================
echo echo   STEP 1/6: AUTORUNS - Enumerating Auto-Start Locations
echo echo  ================================================================================
echo echo.
echo echo   This creates a baseline of all programs that start automatically.
echo echo   Output: %%SCAN_PREFIX%%-Autoruns.csv
echo echo.
echo echo  --------------------------------------------------------------------------------
echo echo.
echo.
echo set "AUTORUNS_EXE=%%TOOLKIT_DIR%%Autoruns\autorunsc.exe"
echo if exist "%%AUTORUNS_EXE%%" ^(
echo     "%%AUTORUNS_EXE%%" -a * -c -h -nobanner ^> "%%SCAN_PREFIX%%-Autoruns.csv"
echo     echo   [OK] Autoruns scan complete
echo     echo   Results: %%SCAN_PREFIX%%-Autoruns.csv
echo ^) else ^(
echo     echo   [SKIP] Autoruns not found
echo ^)
echo.
echo echo.
echo pause
echo.
echo :: ----------------------------------------------------------------------------
echo :: STEP 2: PERSISTENCESNIPER
echo :: ----------------------------------------------------------------------------
echo cls
echo echo.
echo echo  ================================================================================
echo echo   STEP 2/6: PERSISTENCESNIPER - Comprehensive Persistence Detection
echo echo  ================================================================================
echo echo.
echo echo   Scanning for known persistence techniques...
echo echo   Output: %%SCAN_PREFIX%%-PersistenceSniper.csv
echo echo.
echo echo  --------------------------------------------------------------------------------
echo echo.
echo.
echo set "PS_MODULE=%%TOOLKIT_DIR%%PersistenceSniper\PersistenceSniper.psm1"
echo if not exist "%%PS_MODULE%%" set "PS_MODULE=%%TOOLKIT_DIR%%PersistenceSniper\PersistenceSniper\PersistenceSniper.psm1"
echo.
echo if exist "%%PS_MODULE%%" ^(
echo     powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Import-Module '%%PS_MODULE%%' -Force; Find-AllPersistence -IncludeHighFalsePositivesChecks | Export-Csv -Path '%%SCAN_PREFIX%%-PersistenceSniper.csv' -NoTypeInformation; Write-Host ''; Write-Host '   [OK] PersistenceSniper scan complete' -ForegroundColor Green"
echo     echo   Results: %%SCAN_PREFIX%%-PersistenceSniper.csv
echo ^) else ^(
echo     echo   [SKIP] PersistenceSniper not found
echo ^)
echo.
echo echo.
echo pause
echo.
echo :: ----------------------------------------------------------------------------
echo :: STEP 3: TRAWLER
echo :: ----------------------------------------------------------------------------
echo cls
echo echo.
echo echo  ================================================================================
echo echo   STEP 3/6: TRAWLER - IR-Focused Persistence Scanner
echo echo  ================================================================================
echo echo.
echo echo   Scanning with built-in allow lists to reduce false positives...
echo echo   Output: %%SCAN_PREFIX%%-Trawler.csv
echo echo.
echo echo  --------------------------------------------------------------------------------
echo echo.
echo.
echo set "TRAWLER_PS=%%TOOLKIT_DIR%%Trawler\trawler.ps1"
echo if exist "%%TRAWLER_PS%%" ^(
echo     powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%%TRAWLER_PS%%" -outpath "%%SCAN_PREFIX%%-Trawler.csv"
echo     echo.
echo     echo   [OK] Trawler scan complete
echo     echo   Results: %%SCAN_PREFIX%%-Trawler.csv
echo ^) else ^(
echo     echo   [SKIP] Trawler not found
echo ^)
echo.
echo echo.
echo pause
echo.
echo :: ----------------------------------------------------------------------------
echo :: STEP 4: LOKI
echo :: ----------------------------------------------------------------------------
echo cls
echo echo.
echo echo  ================================================================================
echo echo   STEP 4/6: LOKI - IOC and YARA Scanner
echo echo  ================================================================================
echo echo.
echo echo   Deep scan for indicators of compromise using YARA signatures...
echo echo   This may take several minutes.
echo echo   Output: %%SCAN_PREFIX%%-Loki.log
echo echo.
echo echo  --------------------------------------------------------------------------------
echo echo.
echo.
echo set "LOKI_EXE=%%TOOLKIT_DIR%%Loki\loki\loki.exe"
echo if not exist "%%LOKI_EXE%%" set "LOKI_EXE=%%TOOLKIT_DIR%%Loki\loki.exe"
echo.
echo if exist "%%LOKI_EXE%%" ^(
echo     pushd "%%TOOLKIT_DIR%%Loki"
echo     if exist "loki" cd loki
echo     loki.exe --noprocscan --dontwait -l "%%SCAN_PREFIX%%-Loki.log"
echo     popd
echo     echo.
echo     echo   [OK] LOKI scan complete
echo     echo   Results: %%SCAN_PREFIX%%-Loki.log
echo ^) else ^(
echo     echo   [SKIP] LOKI not found
echo ^)
echo.
echo echo.
echo pause
echo.
echo :: ============================================================================
echo :: DETECTION SUMMARY
echo :: ============================================================================
echo cls
echo echo.
echo echo  ================================================================================
echo echo   PHASE 1 COMPLETE - DETECTION SUMMARY
echo echo  ================================================================================
echo echo.
echo echo   The following reports have been generated:
echo echo.
echo if exist "%%SCAN_PREFIX%%-Autoruns.csv" echo     [OK] Autoruns:          %%SCAN_PREFIX%%-Autoruns.csv
echo if exist "%%SCAN_PREFIX%%-PersistenceSniper.csv" echo     [OK] PersistenceSniper: %%SCAN_PREFIX%%-PersistenceSniper.csv
echo if exist "%%SCAN_PREFIX%%-Trawler.csv" echo     [OK] Trawler:           %%SCAN_PREFIX%%-Trawler.csv
echo if exist "%%SCAN_PREFIX%%-Loki.log" echo     [OK] LOKI:              %%SCAN_PREFIX%%-Loki.log
echo echo.
echo echo   RECOMMENDATION: Review the reports above before proceeding with remediation.
echo echo.
echo echo   Look for:
echo echo     - Unknown executables in auto-start locations
echo echo     - Suspicious scheduled tasks
echo echo     - Unsigned or tampered binaries
echo echo     - Known malware signatures ^(LOKI alerts^)
echo echo.
echo echo  ================================================================================
echo echo.
echo.
echo :: ============================================================================
echo :: PHASE 2: REMEDIATION
echo :: ============================================================================
echo.
echo :ASK_REMEDIATION
echo set /p "RUN_REMEDIATION=  Proceed to PHASE 2 - REMEDIATION? [Y/N]: "
echo if /i "%%RUN_REMEDIATION%%"=="N" goto :SKIP_REMEDIATION
echo if /i "%%RUN_REMEDIATION%%"=="Y" goto :DO_REMEDIATION
echo echo   Please enter Y or N.
echo goto :ASK_REMEDIATION
echo.
echo :SKIP_REMEDIATION
echo echo.
echo echo   Remediation skipped. Reports saved to: %%REPORTS_DIR%%
echo echo.
echo pause
echo exit /b 0
echo.
echo :DO_REMEDIATION
echo.
echo :: ----------------------------------------------------------------------------
echo :: STEP 5: MICROSOFT MRT ^(Optional^)
echo :: ----------------------------------------------------------------------------
echo cls
echo echo.
echo echo  ================================================================================
echo echo   STEP 5/6: MICROSOFT MRT - Malicious Software Removal Tool
echo echo  ================================================================================
echo echo.
echo echo   MRT scans for and removes common malware families.
echo echo   This is OPTIONAL - skip if LOKI found no significant threats.
echo echo.
echo echo  --------------------------------------------------------------------------------
echo echo.
echo.
echo :ASK_MRT
echo set /p "RUN_MRT=  Run Microsoft MRT scan? [Y/N]: "
echo if /i "%%RUN_MRT%%"=="N" goto :SKIP_MRT
echo if /i "%%RUN_MRT%%"=="Y" goto :DO_MRT
echo echo   Please enter Y or N.
echo goto :ASK_MRT
echo.
echo :SKIP_MRT
echo echo   MRT scan skipped.
echo goto :RAT_REMOVAL
echo.
echo :DO_MRT
echo set "MRT_EXE=%%TOOLKIT_DIR%%MRT.exe"
echo if exist "%%MRT_EXE%%" ^(
echo     echo   Launching MRT... ^(Follow the GUI prompts^)
echo     start /wait "" "%%MRT_EXE%%"
echo     echo   [OK] MRT scan complete
echo ^) else ^(
echo     echo   [SKIP] MRT not found
echo ^)
echo.
echo :RAT_REMOVAL
echo echo.
echo pause
echo.
echo :: ----------------------------------------------------------------------------
echo :: STEP 6: RAT REMOVAL
echo :: ----------------------------------------------------------------------------
echo cls
echo echo.
echo echo  ================================================================================
echo echo   STEP 6/6: RAT REMOVAL - Remove Unauthorized Remote Access Tools
echo echo  ================================================================================
echo echo.
echo echo   This will scan for and optionally remove unauthorized RATs.
echo echo   The tool runs in two phases:
echo echo     - Phase 1: WhatIf scan ^(no changes^)
echo echo     - Phase 2: Removal ^(only if you confirm^)
echo echo.
echo echo  --------------------------------------------------------------------------------
echo echo.
echo.
echo :ASK_RAT
echo set /p "RUN_RAT=  Run RAT Removal tool? [Y/N]: "
echo if /i "%%RUN_RAT%%"=="N" goto :SKIP_RAT
echo if /i "%%RUN_RAT%%"=="Y" goto :DO_RAT
echo echo   Please enter Y or N.
echo goto :ASK_RAT
echo.
echo :SKIP_RAT
echo echo   RAT removal skipped.
echo goto :FINISHED
echo.
echo :DO_RAT
echo set "RAT_LAUNCHER=%%TOOLKIT_DIR%%RAT-Removal\Remove-AllRATs-Launcher.cmd"
echo if exist "%%RAT_LAUNCHER%%" ^(
echo     call "%%RAT_LAUNCHER%%"
echo ^) else ^(
echo     echo   [SKIP] RAT Removal Launcher not found
echo ^)
echo.
echo :FINISHED
echo echo.
echo echo  ================================================================================
echo echo   SECURITY SCAN COMPLETE
echo echo  ================================================================================
echo echo.
echo echo   All reports saved to: %%REPORTS_DIR%%
echo echo.
echo echo   NEXT STEPS:
echo echo     1. Review all CSV/LOG files in the Reports folder
echo echo     2. Investigate any flagged items
echo echo     3. If issues found, consider running additional targeted scans
echo echo     4. Document findings for incident response
echo echo.
echo echo  ================================================================================
echo echo.
echo pause
echo exit /b 0
) > "%TOOLKIT_ROOT%\Run-SecurityScan.cmd"

echo   [OK] Run-SecurityScan.cmd created

:: ============================================================================
:: CREATE README
:: ============================================================================
echo.
echo   Creating README.txt...

(
echo ================================================================================
echo SECURITY TOOLKIT
echo ================================================================================
echo.
echo This USB drive contains a comprehensive security toolkit for Windows systems.
echo All tools are configured to run OFFLINE after initial download.
echo.
echo ================================================================================
echo QUICK START
echo ================================================================================
echo.
echo 1. Insert this USB into the target computer
echo 2. RIGHT-CLICK "Run-SecurityScan.cmd"
echo 3. Select "Run as administrator"
echo 4. Follow the on-screen prompts
echo.
echo The orchestrator runs tools in optimal order:
echo   Detection first, then remediation only if needed.
echo.
echo ================================================================================
echo FOLDER STRUCTURE
echo ================================================================================
echo.
echo Security-Toolkit\
echo +-- Run-SecurityScan.cmd      ^<-- MAIN ENTRY POINT - Run this!
echo +-- MRT.exe                   Microsoft Malicious Software Removal Tool
echo +-- README.txt                This file
echo +--
echo +-- Autoruns\                 Sysinternals Autoruns
echo ^|   +-- autorunsc.exe        Command-line version
echo ^|   +-- Autoruns.exe         GUI version
echo ^|
echo +-- PersistenceSniper\        PowerShell persistence detector
echo ^|   +-- PersistenceSniper.psm1
echo ^|
echo +-- Trawler\                  IR-focused persistence scanner
echo ^|   +-- trawler.ps1
echo ^|
echo +-- Loki\                     IOC and YARA scanner
echo ^|   +-- loki.exe
echo ^|   +-- signature-base\      YARA signatures
echo ^|
echo +-- RAT-Removal\              Remote Access Tool removal
echo ^|   +-- Remove-AllRATs-Launcher.cmd
echo ^|   +-- Remove-AllRATs-Standalone.ps1
echo ^|   +-- Logs\
echo ^|
echo +-- Reports\                  Scan results saved here
echo     +-- Scan-YYYY-MM-DD_HHMMSS-Autoruns.csv
echo     +-- Scan-YYYY-MM-DD_HHMMSS-PersistenceSniper.csv
echo     +-- Scan-YYYY-MM-DD_HHMMSS-Trawler.csv
echo     +-- Scan-YYYY-MM-DD_HHMMSS-Loki.log
echo.
echo ================================================================================
echo SCAN ORDER RATIONALE
echo ================================================================================
echo.
echo The orchestrator runs scans in this specific order for good reason:
echo.
echo PHASE 1 - DETECTION ^(No system changes^)
echo.
echo   1. AUTORUNS ^(Fast, ~30 seconds^)
echo      - Creates baseline of ALL auto-start locations
echo      - Scheduled tasks, services, drivers, browser extensions, etc.
echo      - Output is comprehensive but requires manual review
echo.
echo   2. PERSISTENCESNIPER ^(Medium, ~2-5 minutes^)
echo      - Specifically targets known persistence techniques
echo      - MITRE ATT^&CK mapped detections
echo      - Returns all findings for analyst review
echo.
echo   3. TRAWLER ^(Medium, ~2-5 minutes^)
echo      - Similar to PersistenceSniper but with built-in allow lists
echo      - Reduces false positives from legitimate Windows components
echo      - Better for quick triage
echo.
echo   4. LOKI ^(Slow, ~10-30 minutes^)
echo      - Deep file and memory scan using YARA signatures
echo      - Checks file hashes against known malware
echo      - Detects C2 callbacks from running processes
echo      - Most thorough but slowest
echo.
echo PHASE 2 - REMEDIATION ^(Only after review^)
echo.
echo   5. MICROSOFT MRT ^(Optional^)
echo      - Only run if LOKI found malware signatures
echo      - Removes common malware families
echo      - Microsoft-signed and trusted
echo.
echo   6. RAT REMOVAL ^(Optional^)
echo      - Removes unauthorized remote access tools
echo      - Always runs WhatIf first to show what would be removed
echo      - Requires explicit confirmation before removal
echo.
echo ================================================================================
echo INDIVIDUAL TOOL USAGE
echo ================================================================================
echo.
echo You can run tools individually if needed:
echo.
echo AUTORUNS ^(GUI^):
echo   Right-click Autoruns\Autoruns.exe, Run as administrator
echo.
echo AUTORUNS ^(Command-line^):
echo   Autoruns\autorunsc.exe -a * -c -h ^> output.csv
echo.
echo PERSISTENCESNIPER:
echo   powershell -ExecutionPolicy Bypass -Command "Import-Module .\PersistenceSniper\PersistenceSniper.psm1; Find-AllPersistence"
echo.
echo TRAWLER:
echo   powershell -ExecutionPolicy Bypass -File .\Trawler\trawler.ps1
echo.
echo LOKI:
echo   Loki\loki\loki.exe --help        ^(see all options^)
echo   Loki\loki\loki.exe -p C:\Users   ^(scan specific path^)
echo.
echo MRT:
echo   Right-click MRT.exe, Run as administrator
echo.
echo RAT REMOVAL:
echo   Right-click RAT-Removal\Remove-AllRATs-Launcher.cmd, Run as administrator
echo.
echo ================================================================================
echo WHAT EACH TOOL DETECTS
echo ================================================================================
echo.
echo AUTORUNS:
echo   - Registry run keys ^(HKLM/HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run^)
echo   - Scheduled tasks
echo   - Services
echo   - Drivers
echo   - Winlogon entries
echo   - Browser helper objects
echo   - Explorer shell extensions
echo   - And 20+ more auto-start locations
echo.
echo PERSISTENCESNIPER:
echo   - Run/RunOnce keys
echo   - Scheduled tasks ^(including hidden^)
echo   - Services with suspicious paths
echo   - WMI event subscriptions
echo   - Accessibility tool backdoors ^(sethc, utilman, etc.^)
echo   - PowerShell profiles
echo   - AMSI providers
echo   - AppInit DLLs
echo   - Image File Execution Options
echo   - And 30+ more persistence techniques
echo.
echo TRAWLER:
echo   - Similar to PersistenceSniper
echo   - Built-in allow lists reduce noise
echo   - MITRE ATT^&CK technique mapping
echo   - CSV output with investigation guidance
echo.
echo LOKI:
echo   - File hash matching ^(MD5, SHA1, SHA256^)
echo   - YARA signature matching
echo   - Filename pattern matching
echo   - Process memory scanning
echo   - C2 callback detection
echo.
echo RAT REMOVAL:
echo   - 70+ remote access tools
echo   - AnyDesk, TeamViewer, Splashtop, RustDesk
echo   - VNC variants, LogMeIn, RemotePC
echo   - Malicious RATs ^(Remcos, QuasarRAT, AsyncRAT, etc.^)
echo   - Skips Level.io ^(authorized RMM^)
echo   - Verifies ScreenConnect instances
echo.
echo ================================================================================
echo OFFLINE OPERATION
echo ================================================================================
echo.
echo All tools on this USB are designed to work offline:
echo.
echo - Autoruns: Fully offline, reads local registry/files
echo - PersistenceSniper: Fully offline PowerShell
echo - Trawler: Fully offline PowerShell
echo - LOKI: Offline with pre-downloaded signatures
echo   ^(Run loki-upgrader.exe while online to update signatures^)
echo - MRT: Fully offline, signatures embedded in executable
echo - RAT Removal: Fully offline
echo.
echo To update LOKI signatures when online:
echo   Loki\loki\loki-upgrader.exe
echo.
echo ================================================================================
echo INTERPRETING RESULTS
echo ================================================================================
echo.
echo AUTORUNS CSV:
echo   - Review "Image Path" column for suspicious locations
echo   - Check "Publisher" - unsigned entries are suspicious
echo   - "Signer" column shows if code signing is valid
echo.
echo PERSISTENCESNIPER CSV:
echo   - "Technique" column shows MITRE ATT^&CK ID
echo   - "Classification" indicates severity
echo   - "Source" shows where the persistence was found
echo.
echo TRAWLER CSV:
echo   - "Detection" column describes the finding
echo   - "Risk" column indicates severity
echo   - Items not in allow list are more suspicious
echo.
echo LOKI LOG:
echo   - "[ALERT]" lines indicate confirmed threats
echo   - "[WARNING]" lines need investigation
echo   - "[NOTICE]" lines are informational
echo   - Check "Reasons" for why item was flagged
echo.
echo ================================================================================
echo Generated: %DATE% %TIME%
echo Copyright ^(c^) COOLNETWORKS - https://github.com/coolnetworks/COOLForge
echo ================================================================================
) > "%TOOLKIT_ROOT%\README.txt"

echo   [OK] README.txt created

:: ============================================================================
:: SUMMARY
:: ============================================================================
echo.
echo  ================================================================================
echo   COMPLETE!
echo  ================================================================================
echo.
echo   Security Toolkit created at: %TOOLKIT_ROOT%
echo.
echo   Contents:
echo     - Run-SecurityScan.cmd       ^<-- Main entry point
echo     - Autoruns                   Sysinternals auto-start enumerator
echo     - PersistenceSniper          PowerShell persistence detector
echo     - Trawler                    IR-focused persistence scanner
echo     - LOKI                       IOC/YARA scanner
echo     - MRT.exe                    Microsoft Malware Removal Tool
echo     - RAT-Removal\               RAT removal toolkit
echo     - Reports\                   Scan results saved here
echo     - README.txt                 Documentation
echo.
echo   TO USE:
echo     1. Insert USB into target computer
echo     2. Right-click "Run-SecurityScan.cmd"
echo     3. Select "Run as administrator"
echo     4. Follow prompts
echo.
echo  ================================================================================
echo.
pause
exit /b 0
