@echo off
setlocal EnableDelayedExpansion

:: ============================================================================
:: Copy RAT Removal Tools to USB Drive
:: ============================================================================
:: This script:
::   1. Asks for the target USB drive letter
::   2. Creates a RAT-Removal-Tools folder
::   3. Copies all removal scripts
::   4. Downloads latest Microsoft Malicious Software Removal Tool (MRT)
::   5. Creates a README with instructions
:: ============================================================================

title Copy RAT Removal Tools to USB

:: Get the directory where this script is located
set "SCRIPT_DIR=%~dp0"

cls
echo.
echo  ================================================================================
echo              COPY RAT REMOVAL TOOLS TO USB DRIVE
echo  ================================================================================
echo.
echo   This will copy the RAT removal toolkit to a USB drive, including:
echo.
echo     - Remove-AllRATs-Launcher.cmd     (main launcher)
echo     - Remove-AllRATs-Standalone.ps1   (removal script)
echo     - Microsoft MRT                   (Malicious Software Removal Tool)
echo     - Supporting scripts and README
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

if exist "%SCRIPT_DIR%Remove-AnyDesk-Standalone.ps1" (
    echo   [OK] Remove-AnyDesk-Standalone.ps1 (optional)
) else (
    echo   [--] Remove-AnyDesk-Standalone.ps1 (optional - skipped)
)

if exist "%SCRIPT_DIR%Remove-NonMspScreenConnect-Standalone.ps1" (
    echo   [OK] Remove-NonMspScreenConnect-Standalone.ps1 (optional)
) else (
    echo   [--] Remove-NonMspScreenConnect-Standalone.ps1 (optional - skipped)
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
set "TARGET_FOLDER=%TARGET_DRIVE%\RAT-Removal-Tools"
set "LOGS_FOLDER=%TARGET_FOLDER%\Logs"

:: Check if drive exists
if not exist "%TARGET_DRIVE%\" (
    echo.
    echo   ERROR: Drive %TARGET_DRIVE% does not exist or is not accessible.
    echo.
    goto :ASK_DRIVE
)

echo.
echo   Target folder: %TARGET_FOLDER%
echo.

:: Confirm
set /p "CONFIRM=  Proceed with copy? [Y/N]: "
if /i not "%CONFIRM%"=="Y" (
    echo.
    echo   Cancelled.
    echo.
    pause
    exit /b 0
)

echo.
echo  ================================================================================
echo   COPYING FILES
echo  ================================================================================
echo.

:: Create target folder
if not exist "%TARGET_FOLDER%" (
    mkdir "%TARGET_FOLDER%"
    echo   Created: %TARGET_FOLDER%
)

:: Create Logs folder
if not exist "%LOGS_FOLDER%" (
    mkdir "%LOGS_FOLDER%"
    echo   Created: %LOGS_FOLDER%
)

:: Copy required files
echo.
echo   Copying scripts...

copy /Y "%SCRIPT_DIR%Remove-AllRATs-Standalone.ps1" "%TARGET_FOLDER%\" >nul
if %errorlevel% equ 0 (
    echo   [OK] Remove-AllRATs-Standalone.ps1
) else (
    echo   [FAIL] Remove-AllRATs-Standalone.ps1
)

copy /Y "%SCRIPT_DIR%Remove-AllRATs-Launcher.cmd" "%TARGET_FOLDER%\" >nul
if %errorlevel% equ 0 (
    echo   [OK] Remove-AllRATs-Launcher.cmd
) else (
    echo   [FAIL] Remove-AllRATs-Launcher.cmd
)

:: Copy optional files if they exist
if exist "%SCRIPT_DIR%Remove-AnyDesk-Standalone.ps1" (
    copy /Y "%SCRIPT_DIR%Remove-AnyDesk-Standalone.ps1" "%TARGET_FOLDER%\" >nul
    echo   [OK] Remove-AnyDesk-Standalone.ps1
)

if exist "%SCRIPT_DIR%Remove-NonMspScreenConnect-Standalone.ps1" (
    copy /Y "%SCRIPT_DIR%Remove-NonMspScreenConnect-Standalone.ps1" "%TARGET_FOLDER%\" >nul
    echo   [OK] Remove-NonMspScreenConnect-Standalone.ps1
)

:: Download Microsoft Malicious Software Removal Tool
echo.
echo  ================================================================================
echo   DOWNLOADING MICROSOFT MALICIOUS SOFTWARE REMOVAL TOOL (MRT)
echo  ================================================================================
echo.
echo   Downloading latest MRT from Microsoft...
echo   (This may take a minute depending on your connection)
echo.

:: Detect system architecture
if "%PROCESSOR_ARCHITECTURE%"=="AMD64" (
    set "MRT_URL=https://go.microsoft.com/fwlink/?LinkId=212732"
    set "MRT_ARCH=64-bit"
) else (
    set "MRT_URL=https://go.microsoft.com/fwlink/?LinkId=212733"
    set "MRT_ARCH=32-bit"
)

set "MRT_FILE=%TARGET_FOLDER%\MRT.exe"

echo   Architecture: %MRT_ARCH%
echo   URL: %MRT_URL%
echo   Destination: %MRT_FILE%
echo.

:: Download using PowerShell
powershell -NoProfile -Command "try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri '%MRT_URL%' -OutFile '%MRT_FILE%' -UseBasicParsing; Write-Host '   [OK] MRT.exe downloaded successfully' -ForegroundColor Green } catch { Write-Host '   [FAIL] Download failed:' $_.Exception.Message -ForegroundColor Red; exit 1 }"

if %errorlevel% neq 0 (
    echo.
    echo   WARNING: MRT download failed. You can manually download it from:
    echo   https://www.microsoft.com/en-us/download/details.aspx?id=9905
    echo.
)

:: Create README
echo.
echo   Creating README.txt...

(
echo ================================================================================
echo RAT REMOVAL TOOLKIT
echo ================================================================================
echo.
echo This USB drive contains tools to detect and remove unauthorized remote access
echo tools ^(RATs^) from Windows computers.
echo.
echo ================================================================================
echo HOW TO USE - RAT REMOVAL
echo ================================================================================
echo.
echo 1. Insert this USB drive into the target computer
echo 2. Open this folder in File Explorer
echo 3. RIGHT-CLICK on "Remove-AllRATs-Launcher.cmd"
echo 4. Select "Run as administrator"
echo 5. Follow the on-screen prompts
echo.
echo The tool will:
echo   - First SCAN the system ^(no changes made^) to show what's installed
echo   - Ask if you want to proceed with removal
echo   - If confirmed, remove all detected unauthorized RATs
echo.
echo ================================================================================
echo HOW TO USE - MICROSOFT MRT ^(Malicious Software Removal Tool^)
echo ================================================================================
echo.
echo MRT scans for and removes common malware from Windows computers.
echo.
echo 1. RIGHT-CLICK on "MRT.exe"
echo 2. Select "Run as administrator"
echo 3. Choose scan type:
echo    - Quick scan: Scans common malware locations ^(fastest^)
echo    - Full scan: Scans entire computer ^(thorough but slow^)
echo    - Customized scan: Choose specific folder to scan
echo 4. Wait for scan to complete
echo 5. Review results and remove any threats found
echo.
echo ================================================================================
echo FILES INCLUDED
echo ================================================================================
echo.
echo RAT Removal:
echo   - Remove-AllRATs-Launcher.cmd     Main launcher ^(RUN THIS^)
echo   - Remove-AllRATs-Standalone.ps1   PowerShell removal script
echo   - Remove-AnyDesk-Standalone.ps1   Single-tool AnyDesk remover
echo   - Remove-NonMspScreenConnect...   Single-tool ScreenConnect remover
echo.
echo Microsoft Tools:
echo   - MRT.exe                         Malicious Software Removal Tool
echo.
echo Output:
echo   - Logs\                           Scan and removal logs saved here
echo.
echo ================================================================================
echo WHAT GETS REMOVED ^(RAT Removal^)
echo ================================================================================
echo.
echo - AnyDesk, TeamViewer, RustDesk, Splashtop
echo - VNC variants ^(RealVNC, TightVNC, UltraVNC, TigerVNC^)
echo - LogMeIn, GoToAssist, GoToMyPC, RemotePC
echo - Meshcentral, DWService, Ammyy Admin, Supremo
echo - And 50+ other remote access tools
echo - Known malicious RATs ^(Remcos, QuasarRAT, AsyncRAT, etc.^)
echo.
echo ================================================================================
echo WHAT IS KEPT
echo ================================================================================
echo.
echo - Level.io ^(authorized RMM^)
echo - ScreenConnect ^(if you confirm it's your authorized instance^)
echo.
echo ================================================================================
echo Generated: %DATE% %TIME%
echo Copyright ^(c^) COOLNETWORKS - https://github.com/coolnetworks/COOLForge
echo ================================================================================
) > "%TARGET_FOLDER%\README.txt"

echo   [OK] README.txt

:: Summary
echo.
echo  ================================================================================
echo   COMPLETE!
echo  ================================================================================
echo.
echo   Files copied to: %TARGET_FOLDER%
echo.
echo   Contents:
echo     - Remove-AllRATs-Launcher.cmd   ^<-- Run this as Admin on target PC
echo     - Remove-AllRATs-Standalone.ps1
echo     - MRT.exe                       ^<-- Microsoft Malicious Software Removal Tool
echo     - README.txt
echo     - Logs\                         ^<-- Logs will be saved here
echo.
echo   TO USE:
echo     1. Insert USB into target computer
echo     2. Right-click "Remove-AllRATs-Launcher.cmd"
echo     3. Select "Run as administrator"
echo.
echo  ================================================================================
echo.
pause
exit /b 0
