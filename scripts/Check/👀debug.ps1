<#
.SYNOPSIS
    Debug script for testing all emoji tag patterns in Level.io.

.DESCRIPTION
    This script tests the COOLForge emoji tag matching system by checking
    for DEBUG tags with all supported emoji prefixes. Use this to verify
    that emoji tags are being correctly parsed from Level.io.

    SUPPORTED POLICY TAGS:
    - 🙏DEBUG = Request/Recommend installation
    - ⛔DEBUG = Block/Must not be installed
    - 🛑DEBUG = Stop/Remove if present
    - 📌DEBUG = Pin/Must be installed (enforce presence)
    - ✅DEBUG = Installed/Already present
    - ❌DEBUG = Denied/Not allowed

.NOTES
    Version:          2026.01.01.01
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

# Debug Tag Pattern Test Script
# Version: 2026.01.01.01
# Target: Level.io (via Script Launcher)
# Exit 0 = Success | Exit 1 = Alert (Failure)
#
# Copyright (c) COOLNETWORKS
# https://coolnetworks.au
# https://github.com/coolnetworks/COOLForge

# ============================================================
# CONFIGURATION
# ============================================================
# SOFTWARE TO CHECK: This tests all emoji patterns for "DEBUG"
$SoftwareName = "DEBUG"

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
$ScriptVersion = "2026.01.01.01"
$InvokeParams = @{ ScriptBlock = {

    Write-LevelLog "Emoji Tag Debug Test (v$ScriptVersion)"
    Write-Host ""

    # Run the policy check - all logic is in the library
    $Policy = Invoke-SoftwarePolicyCheck -SoftwareName $SoftwareName -DeviceTags $DeviceTags

    Write-Host ""
    Write-LevelLog "Debug test completed successfully" -Level "SUCCESS"
}}
if ($RunningFromLauncher) { $InvokeParams.NoExit = $true }
Invoke-LevelScript @InvokeParams
