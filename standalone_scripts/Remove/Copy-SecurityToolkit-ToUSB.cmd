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
echo     - Security Baseline Checker   Defender, exclusions, UAC, keyloggers
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
:: Reports saved directly to TOOLKIT_ROOT

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
for %%F in ("%TOOLKIT_ROOT%" "%RAT_FOLDER%" "%RAT_FOLDER%\Logs" "%AUTORUNS_FOLDER%" "%PERSISTENCE_FOLDER%" "%TRAWLER_FOLDER%" "%LOKI_FOLDER%") do (
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

:: Copy Security Baseline Checker to toolkit root
copy /Y "%SCRIPT_DIR%Check-SecurityBaseline.ps1" "%TOOLKIT_ROOT%\" >nul && echo   [OK] Check-SecurityBaseline.ps1

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
echo ::   1. Security Baseline - Defender, exclusions, UAC, keyloggers, firewall
echo ::   2. Autoruns      - Fast snapshot of all auto-start locations
echo ::   3. PersistenceSniper - Comprehensive persistence detection
echo ::   4. Trawler       - IR-focused persistence scanner with allow lists
echo ::   5. LOKI          - Deep IOC/YARA scan of files and memory
echo ::   6. MRT           - Microsoft malware scan ^(optional^)
echo ::   7. RAT Removal   - Remove unauthorized remote access ^(if needed^)
echo ::   8. System Integrity - SFC, DISM, CHKDSK ^(final cleanup^)
echo :: ============================================================================
echo.
echo title Security Toolkit - Comprehensive Scan
echo.
echo :: Get script directory - reports saved in same folder
echo set "TOOLKIT_DIR=%%~dp0"
echo set "REPORTS_DIR=%%TOOLKIT_DIR%%"
echo.
echo :: Generate timestamp
echo for /f "tokens=2 delims==" %%%%I in ^('wmic os get localdatetime /value'^) do set "DT=%%%%I"
echo set "TIMESTAMP=%%DT:~0,4%%-%%DT:~4,2%%-%%DT:~6,2%%_%%DT:~8,2%%%%DT:~10,2%%%%DT:~12,2%%"
echo set "SCAN_PREFIX=%%REPORTS_DIR%%\Scan-%%TIMESTAMP%%"
echo.
echo :: Reports saved in toolkit root directory
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
echo echo     Step 1: Security Baseline - Defender, exclusions, UAC, keyloggers
echo echo     Step 2: Autoruns          - Enumerate all auto-start locations
echo echo     Step 3: PersistenceSniper - Detect persistence mechanisms
echo echo     Step 4: Trawler           - IR-focused persistence scan
echo echo     Step 5: LOKI              - IOC and YARA signature scan
echo echo.
echo echo   PHASE 2 - REMEDIATION ^(Optional, requires confirmation^)
echo echo     Step 6: Microsoft MRT     - Malware removal ^(optional^)
echo echo     Step 7: RAT Removal       - Remove unauthorized remote access
echo echo.
echo echo   PHASE 3 - SYSTEM INTEGRITY ^(Repair and verify^)
echo echo     Step 8: SFC/DISM/CHKDSK   - System file and disk repair
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
echo :: STEP 1: SECURITY BASELINE
echo :: ----------------------------------------------------------------------------
echo cls
echo echo.
echo echo  ================================================================================
echo echo   STEP 1/8: SECURITY BASELINE - System Security Check
echo echo  ================================================================================
echo echo.
echo echo   Checking Defender status, exclusions, UAC, firewall, keyloggers...
echo echo   Output: %%SCAN_PREFIX%%-SecurityBaseline.txt
echo echo.
echo echo  --------------------------------------------------------------------------------
echo echo.
echo.
echo set "BASELINE_PS=%%TOOLKIT_DIR%%Check-SecurityBaseline.ps1"
echo if exist "%%BASELINE_PS%%" ^(
echo     powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%%BASELINE_PS%%" -OutputPath "%%REPORTS_DIR%%"
echo     echo.
echo     echo   [OK] Security Baseline check complete
echo ^) else ^(
echo     echo   [SKIP] Check-SecurityBaseline.ps1 not found
echo ^)
echo.
echo echo.
echo pause
echo.
echo :: ----------------------------------------------------------------------------
echo :: STEP 2: AUTORUNS
echo :: ----------------------------------------------------------------------------
echo cls
echo echo.
echo echo  ================================================================================
echo echo   STEP 2/8: AUTORUNS - Enumerating Auto-Start Locations
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
echo :: STEP 3: PERSISTENCESNIPER
echo :: ----------------------------------------------------------------------------
echo cls
echo echo.
echo echo  ================================================================================
echo echo   STEP 3/8: PERSISTENCESNIPER - Comprehensive Persistence Detection
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
echo :: STEP 4: TRAWLER
echo :: ----------------------------------------------------------------------------
echo cls
echo echo.
echo echo  ================================================================================
echo echo   STEP 4/8: TRAWLER - IR-Focused Persistence Scanner
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
echo :: STEP 5: LOKI
echo :: ----------------------------------------------------------------------------
echo cls
echo echo.
echo echo  ================================================================================
echo echo   STEP 5/8: LOKI - IOC and YARA Scanner
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
echo for %%%%f in ^("%%REPORTS_DIR%%\SecurityBaseline-*.txt"^) do echo     [OK] Security Baseline: %%%%f
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
echo :: STEP 6: MICROSOFT MRT ^(Optional^)
echo :: ----------------------------------------------------------------------------
echo cls
echo echo.
echo echo  ================================================================================
echo echo   STEP 6/8: MICROSOFT MRT - Malicious Software Removal Tool
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
echo :: STEP 7: RAT REMOVAL
echo :: ----------------------------------------------------------------------------
echo cls
echo echo.
echo echo  ================================================================================
echo echo   STEP 7/8: RAT REMOVAL - Remove Unauthorized Remote Access Tools
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
echo :: ----------------------------------------------------------------------------
echo :: STEP 8: SYSTEM INTEGRITY ^(SFC, DISM, CHKDSK^)
echo :: ----------------------------------------------------------------------------
echo :SYSTEM_INTEGRITY
echo cls
echo echo.
echo echo  ================================================================================
echo echo   STEP 8/8: SYSTEM INTEGRITY - SFC, DISM, CHKDSK
echo echo  ================================================================================
echo echo.
echo echo   This step verifies and repairs Windows system files and disk integrity.
echo echo   Run order:
echo echo     1. DISM CheckHealth  - Quick Windows image check
echo echo     2. DISM ScanHealth   - Thorough Windows image scan
echo echo     3. DISM RestoreHealth - Repair Windows image ^(may need internet^)
echo echo     4. SFC /scannow      - System File Checker
echo echo     5. CHKDSK /R         - Deep disk check ^(REQUIRES REBOOT^)
echo echo.
echo echo   NOTE: CHKDSK /R on the system drive requires a reboot to run.
echo echo         The scan will run automatically on next restart.
echo echo.
echo echo  --------------------------------------------------------------------------------
echo echo.
echo.
echo :ASK_INTEGRITY
echo set /p "RUN_INTEGRITY=  Run System Integrity checks? [Y/N]: "
echo if /i "%%RUN_INTEGRITY%%"=="N" goto :FINISHED
echo if /i "%%RUN_INTEGRITY%%"=="Y" goto :DO_INTEGRITY
echo echo   Please enter Y or N.
echo goto :ASK_INTEGRITY
echo.
echo :DO_INTEGRITY
echo echo.
echo echo  --------------------------------------------------------------------------------
echo echo   DISM - Deployment Image Servicing and Management
echo echo  --------------------------------------------------------------------------------
echo echo.
echo echo   [1/5] DISM /CheckHealth - Quick health check...
echo echo.
echo DISM /Online /Cleanup-Image /CheckHealth
echo echo.
echo.
echo echo   [2/5] DISM /ScanHealth - Scanning for component store corruption...
echo echo         ^(This may take several minutes^)
echo echo.
echo DISM /Online /Cleanup-Image /ScanHealth
echo echo.
echo.
echo :ASK_RESTORE
echo set /p "RUN_RESTORE=  Run DISM /RestoreHealth? ^(may need internet^) [Y/N]: "
echo if /i "%%RUN_RESTORE%%"=="N" goto :SKIP_RESTORE
echo if /i "%%RUN_RESTORE%%"=="Y" goto :DO_RESTORE
echo echo   Please enter Y or N.
echo goto :ASK_RESTORE
echo.
echo :DO_RESTORE
echo echo.
echo echo   [3/5] DISM /RestoreHealth - Repairing Windows image...
echo echo         ^(This may take 15-30 minutes^)
echo echo.
echo DISM /Online /Cleanup-Image /RestoreHealth
echo echo.
echo goto :DO_SFC
echo.
echo :SKIP_RESTORE
echo echo   DISM /RestoreHealth skipped.
echo echo.
echo.
echo :DO_SFC
echo echo  --------------------------------------------------------------------------------
echo echo   SFC - System File Checker
echo echo  --------------------------------------------------------------------------------
echo echo.
echo echo   [4/5] SFC /scannow - Scanning and repairing system files...
echo echo         ^(This may take 10-20 minutes^)
echo echo.
echo sfc /scannow
echo echo.
echo echo   SFC complete. Check %%SystemRoot%%\Logs\CBS\CBS.log for details.
echo echo.
echo.
echo echo  --------------------------------------------------------------------------------
echo echo   CHKDSK - Disk Check
echo echo  --------------------------------------------------------------------------------
echo echo.
echo echo   [5/5] CHKDSK - Deep disk integrity check
echo echo.
echo echo   IMPORTANT: CHKDSK /R on the system drive ^(C:^) cannot run while Windows
echo echo   is running. It will be SCHEDULED to run on the next reboot.
echo echo.
echo echo   Options:
echo echo     /R = Locates bad sectors and recovers readable information
echo echo          ^(includes /F functionality - fixes errors^)
echo echo.
echo.
echo :ASK_CHKDSK
echo set /p "RUN_CHKDSK=  Schedule CHKDSK /R for next reboot? [Y/N]: "
echo if /i "%%RUN_CHKDSK%%"=="N" goto :SKIP_CHKDSK
echo if /i "%%RUN_CHKDSK%%"=="Y" goto :DO_CHKDSK
echo echo   Please enter Y or N.
echo goto :ASK_CHKDSK
echo.
echo :DO_CHKDSK
echo echo.
echo echo   Scheduling CHKDSK /R for C: drive...
echo echo Y ^| chkdsk C: /R
echo echo.
echo echo   CHKDSK has been scheduled. It will run automatically on next reboot.
echo echo   The scan may take 1-3 hours depending on disk size.
echo echo.
echo goto :INTEGRITY_DONE
echo.
echo :SKIP_CHKDSK
echo echo   CHKDSK skipped.
echo echo.
echo.
echo :INTEGRITY_DONE
echo echo  --------------------------------------------------------------------------------
echo echo   System Integrity checks complete.
echo echo  --------------------------------------------------------------------------------
echo echo.
echo pause
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
echo echo     1. Review all CSV/LOG files in the toolkit folder
echo echo     2. Investigate any flagged items
echo echo     3. If CHKDSK was scheduled, REBOOT to run disk check
echo echo     4. After reboot, verify system stability
echo echo     5. Document findings for incident response
echo echo.
echo echo   If system integrity issues were found:
echo echo     - Review %%SystemRoot%%\Logs\CBS\CBS.log for SFC details
echo echo     - Review %%SystemRoot%%\Logs\DISM\dism.log for DISM details
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
echo +-- Check-SecurityBaseline.ps1   Security baseline checker
echo +-- MRT.exe                   Microsoft Malicious Software Removal Tool
echo +-- README.txt                This file
echo +-- SecurityBaseline-*.txt    ^(generated - security check results^)
echo +-- Scan-*-Autoruns.csv       ^(generated - autoruns results^)
echo +-- Scan-*-PersistenceSniper.csv  ^(generated^)
echo +-- Scan-*-Trawler.csv        ^(generated^)
echo +-- Scan-*-Loki.log           ^(generated^)
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
echo     +-- Remove-AllRATs-Launcher.cmd
echo     +-- Remove-AllRATs-Standalone.ps1
echo     +-- Logs\
echo.
echo ================================================================================
echo SCAN ORDER RATIONALE
echo ================================================================================
echo.
echo The orchestrator runs scans in this specific order for good reason:
echo.
echo PHASE 1 - DETECTION ^(No system changes^)
echo.
echo   1. SECURITY BASELINE ^(~5-10 minutes^)
echo      36 comprehensive security checks including:
echo      - Windows Defender, exclusions, firewall, UAC, accounts
echo      - Keylogger indicators, credential protection
echo      - DNS hijacking, proxy hijacking, rogue certificates
echo      - WMI/IFEO/AppInit persistence, Volume Shadow Copy
echo      - Browser extensions and hijacking detection
echo      - Alternate Data Streams, Print/SSP/Netsh DLLs
echo      - Event log analysis ^(failed logons, new services^)
echo      - Temp files, executables in suspicious locations
echo      - Ransomware indicators ^(encrypted files, ransom notes^)
echo      - PowerShell history, file association hijacking
echo      - USB device history, network indicators
echo      - SMART disk health, broken shortcuts
echo      - Policy hijacking ^(disabled Task Manager, etc.^)
echo.
echo   2. AUTORUNS ^(Fast, ~30 seconds^)
echo      - Creates baseline of ALL auto-start locations
echo      - Scheduled tasks, services, drivers, browser extensions, etc.
echo      - Output is comprehensive but requires manual review
echo.
echo   3. PERSISTENCESNIPER ^(Medium, ~2-5 minutes^)
echo      - Specifically targets known persistence techniques
echo      - MITRE ATT^&CK mapped detections
echo      - Returns all findings for analyst review
echo.
echo   4. TRAWLER ^(Medium, ~2-5 minutes^)
echo      - Similar to PersistenceSniper but with built-in allow lists
echo      - Reduces false positives from legitimate Windows components
echo      - Better for quick triage
echo.
echo   5. LOKI ^(Slow, ~10-30 minutes^)
echo      - Deep file and memory scan using YARA signatures
echo      - Checks file hashes against known malware
echo      - Detects C2 callbacks from running processes
echo      - Most thorough but slowest
echo.
echo PHASE 2 - REMEDIATION ^(Only after review^)
echo.
echo   6. MICROSOFT MRT ^(Optional^)
echo      - Only run if LOKI found malware signatures
echo      - Removes common malware families
echo      - Microsoft-signed and trusted
echo.
echo   7. RAT REMOVAL ^(Optional^)
echo      - Removes unauthorized remote access tools
echo      - Always runs WhatIf first to show what would be removed
echo      - Requires explicit confirmation before removal
echo.
echo PHASE 3 - SYSTEM INTEGRITY ^(Final cleanup and verification^)
echo.
echo   8. SFC / DISM / CHKDSK
echo      - DISM CheckHealth: Quick Windows image health check
echo      - DISM ScanHealth: Thorough component store scan
echo      - DISM RestoreHealth: Repair Windows image ^(may need internet^)
echo      - SFC /scannow: Scan and repair protected system files
echo      - CHKDSK /R: Deep disk check ^(scheduled for reboot^)
echo      - This ensures system integrity before going back online
echo.
echo ================================================================================
echo INDIVIDUAL TOOL USAGE
echo ================================================================================
echo.
echo You can run tools individually if needed:
echo.
echo SECURITY BASELINE:
echo   powershell -ExecutionPolicy Bypass -File .\Check-SecurityBaseline.ps1
echo   powershell -ExecutionPolicy Bypass -File .\Check-SecurityBaseline.ps1 -OutputPath "C:\Reports"
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
echo SYSTEM INTEGRITY ^(run as administrator^):
echo   DISM /Online /Cleanup-Image /CheckHealth    ^(quick check^)
echo   DISM /Online /Cleanup-Image /ScanHealth     ^(thorough scan^)
echo   DISM /Online /Cleanup-Image /RestoreHealth  ^(repair - needs internet^)
echo   sfc /scannow                                ^(system file checker^)
echo   chkdsk C: /R                                ^(deep disk check - needs reboot^)
echo.
echo ================================================================================
echo WHAT EACH TOOL DETECTS
echo ================================================================================
echo.
echo SECURITY BASELINE ^(36 Sections^):
echo.
echo   CORE SECURITY ^(1-14^):
echo   Section 1:  Windows Defender status ^(real-time, signatures, tamper^)
echo   Section 2:  Defender exclusions ^(suspicious paths, hidden exclusions^)
echo   Section 3:  Windows Firewall ^(Domain, Private, Public profiles^)
echo   Section 4:  UAC configuration and level
echo   Section 5:  User accounts ^(Guest, Admin, suspicious accounts^)
echo   Section 6:  Keylogger indicators ^(processes, hooks, drivers^)
echo   Section 7:  Additional security ^(SMBv1, RDP, Secure Boot, BitLocker^)
echo   Section 8:  Network security ^(DNS hijacking, hosts file, proxy^)
echo   Section 9:  Certificate trust ^(rogue certs: Superfish, eDellRoot^)
echo   Section 10: Credential protection ^(LSA, Credential Guard, WDigest^)
echo   Section 11: Advanced persistence ^(WMI, IFEO, AppInit_DLLs^)
echo   Section 12: System recovery ^(VSS, Windows RE^)
echo   Section 13: Suspicious scheduled tasks
echo   Section 14: Startup items
echo.
echo   ADVANCED CHECKS ^(15-22^):
echo   Section 15: Browser extensions ^(Chrome, Edge, Firefox permissions^)
echo   Section 16: Recently modified executables ^(unsigned in system^)
echo   Section 17: Alternate Data Streams ^(ADS hidden data^)
echo   Section 18: Print Monitor DLLs
echo   Section 19: Security Support Providers ^(SSP/mimikatz^)
echo   Section 20: Netsh Helper DLLs
echo   Section 21: Office Add-ins ^(COM, VSTO, startup^)
echo   Section 22: Recently accessed files and Prefetch
echo.
echo   INCIDENT RESPONSE ^(23-36^):
echo   Section 23: Temp files audit ^(user, system, browser cache^)
echo   Section 24: Proxy hijacking ^(system, Chrome, Firefox, WPAD^)
echo   Section 25: Browser hijacking ^(shortcut tampering, homepage^)
echo   Section 26: File association hijacking ^(EXE, COM, BAT, etc.^)
echo   Section 27: Event log analysis ^(logon failures, new accounts^)
echo   Section 28: SMART disk health and space
echo   Section 29: Executables in suspicious locations
echo   Section 30: Network indicators ^(connections, listeners, ARP^)
echo   Section 31: USB/external device history
echo   Section 32: Ransomware indicators ^(encrypted files, notes^)
echo   Section 33: PowerShell command history analysis
echo   Section 34: IFEO extended ^(GlobalFlag, SilentProcessExit^)
echo   Section 35: Broken shortcuts and orphaned directories
echo   Section 36: Windows policies hijacking ^(disabled Task Manager^)
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
echo SYSTEM INTEGRITY ^(SFC/DISM/CHKDSK^):
echo   - DISM CheckHealth: Quick component store corruption check
echo   - DISM ScanHealth: Full component store scan
echo   - DISM RestoreHealth: Repairs Windows image from Windows Update
echo   - SFC /scannow: Scans/repairs protected Windows system files
echo   - CHKDSK /R: Checks file system integrity and disk sectors
echo   - Repairs malware damage to Windows system files
echo   - Detects bad disk sectors that could indicate hardware failure
echo.
echo ================================================================================
echo OFFLINE OPERATION
echo ================================================================================
echo.
echo All tools on this USB are designed to work offline:
echo.
echo - Security Baseline: Fully offline PowerShell
echo - Autoruns: Fully offline, reads local registry/files
echo - PersistenceSniper: Fully offline PowerShell
echo - Trawler: Fully offline PowerShell
echo - LOKI: Offline with pre-downloaded signatures
echo   ^(Run loki-upgrader.exe while online to update signatures^)
echo - MRT: Fully offline, signatures embedded in executable
echo - RAT Removal: Fully offline
echo - SFC/CHKDSK: Fully offline ^(built into Windows^)
echo - DISM RestoreHealth: Needs internet OR can use local install.wim
echo.
echo To update LOKI signatures when online:
echo   Loki\loki\loki-upgrader.exe
echo.
echo For DISM RestoreHealth without internet, use a Windows ISO:
echo   DISM /Online /Cleanup-Image /RestoreHealth /Source:D:\sources\install.wim
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
echo     - Scan results saved here    ^(in toolkit root^)
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
