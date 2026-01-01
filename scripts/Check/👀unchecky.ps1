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
    Version:          2026.01.01.05
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
# Version: 2026.01.01.05
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
$ScriptVersion = "2026.01.01.05"
$InvokeParams = @{ ScriptBlock = {

    Write-LevelLog "Software Policy Check (v$ScriptVersion)"
    Write-Host ""

    # Run the policy check - all logic is in the library
    $Policy = Invoke-SoftwarePolicyCheck -SoftwareName $SoftwareName -DeviceTags $DeviceTags

    Write-Host ""
    Write-LevelLog "Check completed successfully" -Level "SUCCESS"
}}
if ($RunningFromLauncher) { $InvokeParams.NoExit = $true }
Invoke-LevelScript @InvokeParams
