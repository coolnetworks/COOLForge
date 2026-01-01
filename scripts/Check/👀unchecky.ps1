<#
.SYNOPSIS
    Multi-launch software policy enforcement check for Unchecky.

.DESCRIPTION
    This script demonstrates the COOLForge multilaunch pattern - a tag-based approach
    to software policy enforcement. By using the Get-SoftwarePolicy library function,
    this single script pattern can be reused for ANY software package.

    HOW IT WORKS:
    1. Reads device tags from Level.io
    2. Uses Get-SoftwarePolicy to detect policy tags for the software
    3. Reports what actions are required based on the emoji prefix

    SUPPORTED POLICY TAGS:
    - 🙏unchecky = Request/Recommend installation
    - ⛔unchecky = Block/Must not be installed
    - 🛑unchecky = Stop/Remove if present
    - 📌unchecky = Pin/Must be installed (enforce presence)
    - ✅unchecky = Installed/Already present

    INITIAL VERSION:
    This initial implementation simply reports which policy tags are active.
    Future versions will check actual software installation status and report
    compliance/non-compliance.

    MULTILAUNCH PATTERN:
    To use this pattern for other software:
    1. Copy this script
    2. Change $SoftwareName to match your software (e.g., "7zip", "vlc")
    3. Update the tags in your Level.io device configuration
    4. Deploy via launcher - the same script handles all software packages!

.NOTES
    Version:          2026.01.01.04
    Target Platform:  Level.io RMM (via Script Launcher)
    Exit Codes:       0 = Success | 1 = Alert (Failure)

    Level.io Variables Used (passed from Script Launcher):
    - $MspScratchFolder  : MSP-defined scratch folder for persistent storage
    - $DeviceHostname    : Device hostname from Level.io
    - $DeviceTags        : Comma-separated list of device tags

    Copyright (c) COOLNETWORKS
    https://coolnetworks.au
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# Multi-launch Software Policy Check
# Version: 2026.01.01.04
# Target: Level.io (via Script Launcher)
# Exit 0 = Success | Exit 1 = Alert (Failure)
#
# Copyright (c) COOLNETWORKS
# https://coolnetworks.au
# https://github.com/coolnetworks/COOLForge

# ============================================================
# CONFIGURATION
# ============================================================
# SOFTWARE TO CHECK: Change this value to check policy for different software
# Examples: "unchecky", "7zip", "vlc", "chrome", "firefox"
$SoftwareName = "unchecky"

# ============================================================
# INITIALIZE
# ============================================================
# Script Launcher has already loaded the library and passed variables
# We just need to initialize with the passed-through variables

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
# Use -NoExit when running from launcher so it can show log file afterwards
$ScriptVersion = "2026.01.01.04"
$InvokeParams = @{ ScriptBlock = {

    Write-LevelLog "Software Policy Check - $SoftwareName (v$ScriptVersion)"
    Write-Host ""

    # Log device info
    $DeviceInfo = Get-LevelDeviceInfo
    Write-LevelLog "Device: $($DeviceInfo.Hostname) | OS: $($DeviceInfo.OS)"
    Write-Host ""

    # Show all device tags
    Write-LevelLog "Device Tags:"
    if ($DeviceTags) {
        $TagArray = $DeviceTags -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        if ($TagArray.Count -gt 0) {
            foreach ($tag in $TagArray) {
                Write-Host "  - $tag"
            }
        } else {
            Write-Host "  (no tags)"
        }
    } else {
        Write-Host "  (no tags)"
    }
    Write-Host ""

    # Get software policy from device tags
    Write-LevelLog "Checking for '$SoftwareName' policy tags..."
    $Policy = Get-SoftwarePolicy -SoftwareName $SoftwareName -DeviceTags $DeviceTags -ShowDebug

    # Display results
    Write-Host ""
    Write-LevelLog "========================================" -Level "INFO"
    Write-LevelLog "Software Policy Detection Results" -Level "INFO"
    Write-LevelLog "========================================" -Level "INFO"
    Write-Host ""
    Write-LevelLog "Software: $($Policy.SoftwareName)" -Level "INFO"
    Write-Host ""

    if (-not $Policy.HasPolicy) {
        Write-LevelLog "No policy tags found for this software" -Level "INFO"
        Write-Host ""
        Write-LevelLog "To set a policy, add one of these tags in Level.io:" -Level "INFO"
        Write-Host "  🙏$SoftwareName - Request/Recommend installation"
        Write-Host "  ⛔$SoftwareName - Block/Must not be installed"
        Write-Host "  🛑$SoftwareName - Stop/Remove if present"
        Write-Host "  📌$SoftwareName - Pin/Must be installed"
        Write-Host "  ✅$SoftwareName - Installed/Already present"
        Write-Host ""
        Write-LevelLog "No action required" -Level "SUCCESS"
    }
    else {
        Write-LevelLog "Policy tags detected: $($Policy.MatchedTags.Count)" -Level "SUCCESS"
        Write-Host ""

        foreach ($Tag in $Policy.MatchedTags) {
            Write-Host "  Tag: $Tag"
        }
        Write-Host ""

        Write-LevelLog "Required actions:" -Level "INFO"
        foreach ($Action in $Policy.PolicyActions) {
            $ActionDescription = switch ($Action) {
                "Request"   { "Request/Recommend installation" }
                "Block"     { "Block - Must not be installed" }
                "Remove"    { "Remove - Stop if present" }
                "Pin"       { "Pin - Must be installed (enforce)" }
                "Installed" { "Installed - Already present" }
            }
            Write-Host "  - $Action : $ActionDescription"
        }
        Write-Host ""

        # Debug: Show all device tags
        Write-LevelLog "All device tags ($($Policy.RawTags.Count)):" -Level "DEBUG"
        if ($Policy.RawTags.Count -gt 0) {
            foreach ($Tag in $Policy.RawTags) {
                Write-Host "  - $Tag"
            }
        } else {
            Write-Host "  (no tags set)"
        }
        Write-Host ""

        Write-LevelLog "Policy detection complete" -Level "SUCCESS"
        Write-Host ""
        Write-LevelLog "NOTE: This is the initial version - it only detects policy tags." -Level "INFO"
        Write-LevelLog "Future versions will check actual software installation status." -Level "INFO"
    }

    Write-Host ""
    Write-LevelLog "Check completed successfully" -Level "SUCCESS"
}}
if ($RunningFromLauncher) { $InvokeParams.NoExit = $true }
Invoke-LevelScript @InvokeParams
