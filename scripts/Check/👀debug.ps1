<#
.SYNOPSIS
    Debug script for testing software policy enforcement.

.DESCRIPTION
    This script demonstrates the COOLForge policy check pattern. It reads
    device tags from Level.io, resolves the policy action, and reports
    what would happen.

    SUPPORTED POLICY TAGS:
    - 🙏DEBUG = Install/reinstall
    - ⛔DEBUG = Remove if present
    - 🚫DEBUG or 🛑DEBUG = Block install
    - 📌DEBUG = Pin (lock state)
    - ✅DEBUG = Has (verify installed)
    - ❌DEBUG = Skip (hands off)

.NOTES
    Version:          2026.01.21.01
    Target Platform:  Level.io RMM (via Script Launcher)
    Exit Codes:       0 = Success | 1 = Alert (Failure)

    Level.io Variables Used (passed from Script Launcher):
    - $MspScratchFolder  : MSP-defined scratch folder for persistent storage
    - $DeviceHostname    : Device hostname from Level.io
    - $DeviceTags        : Comma-separated list of device tags

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# Debug Policy Check Script
# Version: 2026.01.21.01
# Target: Level.io (via Script Launcher)
# Exit 0 = Success | Exit 1 = Alert (Failure)
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge

# ============================================================
# CONFIGURATION
# ============================================================
$SoftwareName = "DEBUG"

# Install mode: "Reinstall" = always uninstall first (for config updates)
#               "Install"   = only install if missing
$InstallMode = "Reinstall"

# ============================================================
# SOFTWARE-SPECIFIC ROUTINES
# ============================================================

function Install-Software {
    Write-LevelLog "ROUTINE: Install-Software" -Level "INFO"
    Write-Host "  - Download DEBUG installer"
    Write-Host "  - Run silent install with current config"
    Write-Host "  - Verify installation"
}

function Remove-Software {
    Write-LevelLog "ROUTINE: Remove-Software" -Level "INFO"
    Write-Host "  - Find uninstaller"
    Write-Host "  - Run silent uninstall"
    Write-Host "  - Clean up remnants"
}

function Test-SoftwareInstalled {
    Write-LevelLog "ROUTINE: Test-SoftwareInstalled" -Level "INFO"
    Write-Host "  - Check registry for DEBUG"
    Write-Host "  - Check Program Files"
    return $false  # Placeholder - would return actual state
}

function Test-SoftwareHealthy {
    Write-LevelLog "ROUTINE: Test-SoftwareHealthy" -Level "INFO"
    Write-Host "  - Check if services running"
    Write-Host "  - Verify config files"
    return $true  # Placeholder - would return actual state
}

# ============================================================
# INITIALIZE
# ============================================================
$Init = Initialize-LevelScript -ScriptName "SoftwarePolicy-$SoftwareName" `
                               -MspScratchFolder $MspScratchFolder `
                               -DeviceHostname $DeviceHostname `
                               -DeviceTags $DeviceTags

if (-not $Init.Success) {
    exit 0
}

# ============================================================
# MAIN SCRIPT LOGIC
# ============================================================
$ScriptVersion = "2026.01.21.01"
$InvokeParams = @{ ScriptBlock = {

    Write-LevelLog "Debug Script (v$ScriptVersion)"

    # ============================================================
    # DUMP ALL LEVEL.IO SYSTEM VARIABLES
    # ============================================================
    Write-Host ""
    Write-LevelLog "========================================" -Level "INFO"
    Write-LevelLog "LEVEL.IO SYSTEM VARIABLES" -Level "INFO"
    Write-LevelLog "========================================" -Level "INFO"
    Write-Host ""

    $LevelVars = @(
        @{ Name = "LevelDeviceId";         Desc = "Device ID" }
        @{ Name = "LevelDeviceHostname";   Desc = "Device Hostname (detected)" }
        @{ Name = "LevelDeviceNickname";   Desc = "Device Nickname (display name)" }
        @{ Name = "LevelDevicePublicIp";   Desc = "Public IP" }
        @{ Name = "LevelDevicePrivateIps"; Desc = "Private IPs" }
        @{ Name = "LevelGroupId";          Desc = "Group ID" }
        @{ Name = "LevelGroupName";        Desc = "Group Name" }
        @{ Name = "LevelGroupPath";        Desc = "Group Path" }
        @{ Name = "LevelTagNames";         Desc = "Tag Names" }
        @{ Name = "LevelTagIds";           Desc = "Tag IDs" }
    )

    foreach ($v in $LevelVars) {
        $Value = Get-Variable -Name $v.Name -ValueOnly -ErrorAction SilentlyContinue
        $Display = if ([string]::IsNullOrWhiteSpace($Value) -or $Value -like "{{*}}") { "(not set)" } else { $Value }
        Write-Host ("  {0,-30} : {1}" -f $v.Desc, $Display)
    }

    Write-Host ""
    Write-LevelLog "========================================" -Level "INFO"
    Write-LevelLog "POLICY CHECK TEST" -Level "INFO"
    Write-LevelLog "========================================" -Level "INFO"

    Write-LevelLog "Policy Check Script (v$ScriptVersion)"
    Write-LevelLog "Install Mode: $InstallMode"
    Write-Host ""

    # Run the policy check - detects tags and resolves action
    $Policy = Invoke-SoftwarePolicyCheck -SoftwareName $SoftwareName -DeviceTags $DeviceTags

    Write-Host ""
    Write-LevelLog "========================================" -Level "INFO"
    Write-LevelLog "EXECUTION PLAN" -Level "INFO"
    Write-LevelLog "========================================" -Level "INFO"
    Write-Host ""

    # Execute based on resolved action
    switch ($Policy.ResolvedAction) {
        "Skip" {
            Write-LevelLog "ACTION: SKIP - No routines will run" -Level "INFO"
        }
        "Install" {
            Write-LevelLog "ACTION: INSTALL" -Level "INFO"

            # Check if already installed
            $Installed = Test-SoftwareInstalled

            if ($InstallMode -eq "Reinstall") {
                if ($Installed) {
                    Write-LevelLog "Reinstall mode - removing existing first..." -Level "INFO"
                    Remove-Software
                }
                Install-Software
            }
            else {
                # InstallMode = "Install" - only if missing
                if ($Installed) {
                    Write-LevelLog "Already installed, skipping install" -Level "INFO"
                }
                else {
                    Install-Software
                }
            }
        }
        "Remove" {
            Write-LevelLog "ACTION: REMOVE" -Level "INFO"
            Remove-Software
        }
        $null {
            if ($Policy.IsPinned) {
                Write-LevelLog "ACTION: PINNED - State locked, no changes" -Level "INFO"
            }
            elseif ($Policy.IsBlocked) {
                Write-LevelLog "ACTION: BLOCKED - Install prevented" -Level "INFO"
            }
            else {
                Write-LevelLog "ACTION: NONE - No policy tags found" -Level "INFO"
            }
        }
    }

    Write-Host ""

    # Run verification if needed
    if ($Policy.ShouldVerify) {
        Write-LevelLog "VERIFY: Running health check" -Level "INFO"
        $Installed = Test-SoftwareInstalled
        if ($Installed) {
            $Healthy = Test-SoftwareHealthy
            if ($Healthy) {
                Write-LevelLog "Health check: PASSED" -Level "SUCCESS"
            } else {
                Write-LevelLog "Health check: FAILED - Would remediate" -Level "WARNING"
            }
        } else {
            Write-LevelLog "Health check: NOT INSTALLED" -Level "WARNING"
        }
    }

    Write-Host ""
    Write-LevelLog "Policy check completed" -Level "SUCCESS"
}}
if ($RunningFromLauncher) { $InvokeParams.NoExit = $true }
Invoke-LevelScript @InvokeParams
