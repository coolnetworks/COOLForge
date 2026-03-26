<#
.SYNOPSIS
    Deploys RedOxygen Office SMS (Outlook add-in) for all users on a machine.

.DESCRIPTION
    Downloads and silently installs RedOxygen Office SMS. The installer is
    run with /S (silent) and /ALLUSERS flags to install for every user.
    Users will need to configure their own RedOxygen credentials in Outlook
    after installation.

    This is a one-shot deploy script, not a policy script — it installs
    once and exits. Re-running on a machine where Office SMS is already
    installed will skip the install.

.NOTES
    Version:          2026.03.26.01
    Target Platform:  Level.io RMM (via Script Launcher)
    Exit Codes:       0 = Success | 1 = Alert (Failure)

    Level.io Variables Used (passed from Script Launcher):
    - $MspScratchFolder   : MSP-defined scratch folder for persistent storage
    - $DeviceHostname     : Device hostname from Level.io

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# Deploy - RedOxygen Office SMS
# Version: 2026.03.26.01
# Target: Level.io (via Script Launcher)
# Exit 0 = Success | Exit 1 = Alert
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge

# ============================================================
# CONFIGURATION
# ============================================================
$SoftwareName = "RedOxygen OfficeSMS"
$InstallerUrl = "https://www.completesms.com/Downloads/RedOxygen_OfficeSMS_4.2.0.4676.exe"
$InstallerName = "RedOxygen_OfficeSMS_Setup.exe"

# ============================================================
# INITIALIZE
# ============================================================
$Init = Initialize-LevelScript -ScriptName "Deploy-RedOxygen-OfficeSMS" `
                               -MspScratchFolder $MspScratchFolder `
                               -DeviceHostname $DeviceHostname `
                               -DeviceTags $DeviceTags

if (-not $Init.Success) {
    exit 0
}

if ($Init.DebugTagDetected) {
    $DebugLevel = $Init.DebugLevel
    $DebugScripts = $Init.DebugMode
}

# ============================================================
# SOFTWARE DETECTION
# ============================================================
function Test-OfficeSMSInstalled {
    # Check registry for Office SMS
    $RegPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    foreach ($Path in $RegPaths) {
        $Found = Get-ItemProperty $Path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like "*Office SMS*" -or $_.DisplayName -like "*OfficeSMS*" -or $_.DisplayName -like "*Red Oxygen*" -or $_.DisplayName -like "*RedOxygen*" }
        if ($Found) {
            if ($DebugScripts) {
                Write-Host "  [DEBUG] Office SMS detected: $($Found[0].DisplayName)" -ForegroundColor Green
            }
            return $true
        }
    }

    # Check common install paths
    $InstallPaths = @(
        "$env:ProgramFiles\Red Oxygen\Office SMS\",
        "${env:ProgramFiles(x86)}\Red Oxygen\Office SMS\",
        "$env:ProgramFiles\CompleteSMS\Office SMS\",
        "${env:ProgramFiles(x86)}\CompleteSMS\Office SMS\",
        "$env:ProgramFiles\RedOxygen\OfficeSMS\",
        "${env:ProgramFiles(x86)}\RedOxygen\OfficeSMS\"
    )
    foreach ($Path in $InstallPaths) {
        if (Test-Path $Path) {
            if ($DebugScripts) {
                Write-Host "  [DEBUG] Office SMS detected at: $Path" -ForegroundColor Green
            }
            return $true
        }
    }

    # Check for Outlook add-in registration
    $AddinPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Office\Outlook\Addins\OfficeSMS*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\Outlook\Addins\OfficeSMS*",
        "HKLM:\SOFTWARE\Microsoft\Office\Outlook\Addins\RedOxygen*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\Outlook\Addins\RedOxygen*"
    )
    foreach ($Path in $AddinPaths) {
        if (Get-Item $Path -ErrorAction SilentlyContinue) {
            if ($DebugScripts) {
                Write-Host "  [DEBUG] Office SMS Outlook add-in detected in registry" -ForegroundColor Green
            }
            return $true
        }
    }

    return $false
}

# ============================================================
# INSTALL FUNCTION
# ============================================================
function Install-OfficeSMS {
    param([string]$ScratchFolder)

    # Validate scratch folder
    if ([string]::IsNullOrWhiteSpace($ScratchFolder) -or $ScratchFolder -like "*{{*") {
        Write-Host "Alert: Invalid scratch folder path"
        Write-LevelLog "Invalid scratch folder - template variable not resolved" -Level "ERROR"
        return $false
    }

    $InstallersFolder = Join-Path $ScratchFolder "Installers"
    if (-not (Test-Path $InstallersFolder)) {
        New-Item -ItemType Directory -Path $InstallersFolder -Force | Out-Null
    }
    $InstallerPath = Join-Path $InstallersFolder $InstallerName

    # Close Outlook if running (required for add-in install)
    $OutlookProcs = Get-Process -Name "OUTLOOK" -ErrorAction SilentlyContinue
    if ($OutlookProcs) {
        Write-LevelLog "Closing Outlook for installation..." -Level "INFO"
        $OutlookProcs | ForEach-Object {
            try {
                $_.CloseMainWindow() | Out-Null
            } catch {}
        }
        Start-Sleep -Seconds 5
        # Force kill if still running
        $OutlookProcs = Get-Process -Name "OUTLOOK" -ErrorAction SilentlyContinue
        if ($OutlookProcs) {
            $OutlookProcs | Stop-Process -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
        }
    }

    # Download installer
    Write-LevelLog "Downloading RedOxygen Office SMS installer..." -Level "INFO"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $MaxRetries = 2
    $MinFileSize = 1MB

    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            if (Test-Path $InstallerPath) {
                Remove-Item $InstallerPath -Force -ErrorAction SilentlyContinue
            }
            Invoke-WebRequest -Uri $InstallerUrl -OutFile $InstallerPath -UseBasicParsing -ErrorAction Stop

            if ((Test-Path $InstallerPath) -and (Get-Item $InstallerPath).Length -ge $MinFileSize) {
                $FileSize = [math]::Round((Get-Item $InstallerPath).Length / 1MB, 2)
                Write-LevelLog "Downloaded: $FileSize MB" -Level "INFO"
                break
            }
            Write-LevelLog "Download too small, retrying..." -Level "WARN"
        } catch {
            Write-LevelLog "Download attempt $attempt failed: $($_.Exception.Message)" -Level "WARN"
        }

        if ($attempt -ge $MaxRetries) {
            Write-Host "Alert: Failed to download Office SMS installer"
            Write-Host "  URL: $InstallerUrl"
            Write-LevelLog "Download failed after $MaxRetries attempts" -Level "ERROR"
            return $false
        }
        Start-Sleep -Seconds 3
    }

    # Run silent install for all users
    # Try /S (NSIS), then /VERYSILENT (InnoSetup), then /silent
    $InstallSuccess = $false
    $InstallArgs = @(
        "/S /ALLUSERS",
        "/S",
        "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /ALLUSERS",
        "/silent /norestart"
    )

    foreach ($Args in $InstallArgs) {
        Write-LevelLog "Attempting install with: $Args" -Level "INFO"
        try {
            $Process = Start-Process -FilePath $InstallerPath -ArgumentList $Args -Wait -PassThru -ErrorAction Stop
            if ($Process.ExitCode -eq 0 -or $Process.ExitCode -eq 3010) {
                $InstallSuccess = $true
                if ($Process.ExitCode -eq 3010) {
                    Write-LevelLog "Install succeeded - reboot may be required" -Level "WARN"
                }
                break
            }
            Write-LevelLog "Exit code $($Process.ExitCode) with args '$Args'" -Level "DEBUG"
        } catch {
            Write-LevelLog "Install error with '$Args': $($_.Exception.Message)" -Level "WARN"
        }
    }

    # Verify installation actually worked
    Start-Sleep -Seconds 5
    if (-not $InstallSuccess) {
        # Check if it installed despite non-zero exit code
        if (Test-OfficeSMSInstalled) {
            Write-LevelLog "Install appears successful despite exit code" -Level "INFO"
            $InstallSuccess = $true
        }
    }

    # Cleanup installer
    if (Test-Path $InstallerPath) {
        Remove-Item $InstallerPath -Force -ErrorAction SilentlyContinue
    }

    if ($InstallSuccess) {
        Write-LevelLog "RedOxygen Office SMS installed successfully" -Level "SUCCESS"
        Write-LevelLog "Users will need to configure their RedOxygen credentials in Outlook" -Level "INFO"
        return $true
    }

    Write-Host "Alert: RedOxygen Office SMS installation failed"
    Write-Host "  All silent install methods attempted"
    Write-LevelLog "Installation failed - all methods exhausted" -Level "ERROR"
    return $false
}

# ============================================================
# MAIN SCRIPT LOGIC
# ============================================================
$ScriptVersion = "2026.03.26.01"
$ExitCode = 0

$InvokeParams = @{ ScriptBlock = {

    Write-LevelLog "Deploy: $SoftwareName (v$ScriptVersion)"

    $DeviceInfo = Get-LevelDeviceInfo
    Write-LevelLog "Device: $($DeviceInfo.Hostname) | OS: $($DeviceInfo.OS)"

    # Check if already installed
    $IsInstalled = Test-OfficeSMSInstalled
    if ($IsInstalled) {
        Write-LevelLog "RedOxygen Office SMS is already installed - skipping" -Level "SUCCESS"
        return 0
    }

    # Check Outlook is installed
    $OutlookInstalled = $false
    $OutlookPaths = @(
        "$env:ProgramFiles\Microsoft Office\root\Office16\OUTLOOK.EXE",
        "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\OUTLOOK.EXE",
        "$env:ProgramFiles\Microsoft Office\Office16\OUTLOOK.EXE",
        "${env:ProgramFiles(x86)}\Microsoft Office\Office16\OUTLOOK.EXE"
    )
    foreach ($Path in $OutlookPaths) {
        if (Test-Path $Path) { $OutlookInstalled = $true; break }
    }
    # Also check registry
    if (-not $OutlookInstalled) {
        $OutlookReg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\OUTLOOK.EXE" -ErrorAction SilentlyContinue
        if ($OutlookReg) { $OutlookInstalled = $true }
    }

    if (-not $OutlookInstalled) {
        Write-LevelLog "Microsoft Outlook not detected - Office SMS requires Outlook" -Level "WARN"
        Write-Host "Alert: Outlook not installed on this device - skipping Office SMS deployment"
        return 0
    }

    Write-LevelLog "Outlook detected - proceeding with install" -Level "INFO"

    # Install
    $Success = Install-OfficeSMS -ScratchFolder $MspScratchFolder
    if (-not $Success) {
        $script:ExitCode = 1
    }

    Write-Host ""
    if ($Success) {
        Write-LevelLog "Deployment complete" -Level "SUCCESS"
        Write-Host "[*] Users should open Outlook and configure their RedOxygen credentials"
    } else {
        Write-Host "Alert: RedOxygen Office SMS deployment failed on $($DeviceInfo.Hostname)"
    }

    return $(if ($Success) { 0 } else { 1 })
}}
if ($RunningFromLauncher) { $InvokeParams.NoExit = $true }
Invoke-LevelScript @InvokeParams

exit $ExitCode
