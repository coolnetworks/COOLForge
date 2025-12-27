<#
.SYNOPSIS
    Displays version information for LevelLib components.

.DESCRIPTION
    This test script displays the current versions of all LevelLib components
    to verify the library is properly loaded and functioning. Useful for:

    - Verifying library installation on endpoints
    - Confirming scripts are running the expected versions
    - Debugging version mismatch issues

    When run via Script Launcher, this script inherits all Level.io variables
    and the library is already loaded.

.NOTES
    Version:          2025.12.27.01
    Target Platform:  Level.io RMM (via Script Launcher)
    Exit Codes:       0 = Success | 1 = Alert (Failure)

    Level.io Variables Used (passed from Script Launcher):
    - $MspScratchFolder  : MSP-defined scratch folder for persistent storage
    - $LibraryUrl        : URL to download LevelIO-Common.psm1 library
    - $DeviceHostname    : Device hostname from Level.io
    - $DeviceTags        : Comma-separated list of device tags

    Copyright (c) COOLNETWORKS
    https://coolnetworks.au
    https://github.com/coolnetworks/LevelLib

.LINK
    https://github.com/coolnetworks/LevelLib
#>

# Test Show Versions
# Version: 2025.12.27.01
# Target: Level.io (via Script Launcher)
# Exit 0 = Success | Exit 1 = Alert (Failure)
#
# Copyright (c) COOLNETWORKS
# https://coolnetworks.au
# https://github.com/coolnetworks/LevelLib

# ============================================================
# INITIALIZE
# ============================================================
# Script Launcher has already loaded the library and passed variables
# We just need to initialize with the passed-through variables

$Init = Initialize-LevelScript -ScriptName "TestShowVersions" `
                               -MspScratchFolder $MspScratchFolder `
                               -DeviceHostname $DeviceHostname `
                               -DeviceTags $DeviceTags `
                               -BlockingTags @("❌") `
                               -SkipLockFile

if (-not $Init.Success) {
    exit 0
}

# ============================================================
# MAIN SCRIPT LOGIC
# ============================================================
Invoke-LevelScript -ScriptBlock {

    Write-LevelLog "=== LevelLib Version Information ===" -Level "INFO"
    Write-Host ""

    # Get device info
    $DeviceInfo = Get-LevelDeviceInfo

    # Display device info
    Write-LevelLog "Device Information:" -Level "INFO"
    Write-Host "  Hostname:   $($DeviceInfo.Hostname)"
    Write-Host "  Username:   $($DeviceInfo.Username)"
    Write-Host "  Domain:     $($DeviceInfo.Domain)"
    Write-Host "  OS:         $($DeviceInfo.OS)"
    Write-Host "  OS Version: $($DeviceInfo.OSVersion)"
    Write-Host "  PowerShell: $($DeviceInfo.PowerShell)"
    Write-Host "  Is Admin:   $($DeviceInfo.IsAdmin)"
    Write-Host ""

    # Display library version (from module scope)
    Write-LevelLog "Library Version:" -Level "INFO"
    $LibraryPath = Join-Path -Path $MspScratchFolder -ChildPath "Libraries\LevelIO-Common.psm1"
    if (Test-Path $LibraryPath) {
        $LibContent = Get-Content -Path $LibraryPath -Raw -ErrorAction SilentlyContinue
        if ($LibContent -match 'Version:\s*([\d\.]+)') {
            Write-Host "  LevelIO-Common.psm1: v$($Matches[1])"
        }
    }
    Write-Host ""

    # Display cached scripts
    Write-LevelLog "Cached Scripts:" -Level "INFO"
    $ScriptsFolder = Join-Path -Path $MspScratchFolder -ChildPath "Scripts"
    if (Test-Path $ScriptsFolder) {
        $scripts = Get-ChildItem -Path $ScriptsFolder -Filter "*.ps1" -ErrorAction SilentlyContinue
        if ($scripts) {
            foreach ($script in $scripts) {
                $scriptContent = Get-Content -Path $script.FullName -Raw -ErrorAction SilentlyContinue
                if ($scriptContent -match 'Version:\s*([\d\.]+)') {
                    Write-Host "  $($script.Name): v$($Matches[1])"
                }
                else {
                    Write-Host "  $($script.Name): (no version)"
                }
            }
        }
        else {
            Write-Host "  (no cached scripts)"
        }
    }
    else {
        Write-Host "  (scripts folder not found)"
    }
    Write-Host ""

    # Display configuration
    Write-LevelLog "Configuration:" -Level "INFO"
    Write-Host "  Scratch Folder: $MspScratchFolder"
    Write-Host "  Library URL:    $LibraryUrl"
    Write-Host "  Device Tags:    $DeviceTags"
    Write-Host ""

    # Display folder structure
    Write-LevelLog "Folder Structure:" -Level "INFO"
    if (Test-Path $MspScratchFolder) {
        $items = Get-ChildItem -Path $MspScratchFolder -ErrorAction SilentlyContinue
        foreach ($item in $items) {
            if ($item.PSIsContainer) {
                $subItems = (Get-ChildItem -Path $item.FullName -ErrorAction SilentlyContinue | Measure-Object).Count
                Write-Host "  [$($item.Name)/] ($subItems items)"
            }
            else {
                Write-Host "  $($item.Name)"
            }
        }
    }
    else {
        Write-Host "  (scratch folder not found)"
    }
    Write-Host ""

    Write-LevelLog "Version check completed successfully" -Level "SUCCESS"
}
