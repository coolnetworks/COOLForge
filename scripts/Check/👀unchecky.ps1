<#
.SYNOPSIS
    Software policy enforcement check for Unchecky.

.DESCRIPTION
    Implements the COOLForge 5-tag policy model for Unchecky software management.
    See docs/POLICY-TAGS.md for the complete policy specification.

    POLICY FLOW (per POLICY-TAGS.md):
    1. Check global control tags (device must have checkmark to be managed)
    2. Check software-specific override tags (highest priority)
    3. Fall back to custom field policy (policy_unchecky)
    4. Execute resolved action

    GLOBAL CONTROL TAGS (standalone):
    - U+2705 = Device is managed (required to process)
    - U+274C = Device is excluded from management
    - Both = Device is globally pinned (no changes)

    SOFTWARE-SPECIFIC OVERRIDE TAGS (with "unchecky" suffix):
    - U+1F64F unchecky = Install if missing (transient)
    - U+1F6AB unchecky = Remove if present (transient)
    - U+1F4CC unchecky = Pin - no changes allowed (persistent)
    - U+1F504 unchecky = Reinstall - remove + install (transient)
    - U+2705 unchecky  = Status: software is installed (set by script)

    CUSTOM FIELD POLICY (inherited Group->Folder->Device):
    - policy_unchecky = "install" | "remove" | "pin" | ""

.NOTES
    Version:          2026.01.12
    Target Platform:  Level.io RMM (via Script Launcher)
    Exit Codes:       0 = Success | 1 = Alert (Failure)

    Level.io Variables Used (passed from Script Launcher):
    - $MspScratchFolder   : MSP-defined scratch folder for persistent storage
    - $DeviceHostname     : Device hostname from Level.io
    - $DeviceTags         : Comma-separated list of device tags
    - $policy_unchecky    : Custom field policy value (inherited)

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# Software Policy Check - Unchecky
# Version: 2026.01.12
# Target: Level.io (via Script Launcher)
# Exit 0 = Success | Exit 1 = Alert (Failure)
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge

# ============================================================
# CONFIGURATION
# ============================================================
$SoftwareName = "unchecky"

# ============================================================
# INITIALIZE
# ============================================================
$Init = Initialize-LevelScript -ScriptName "Policy-$SoftwareName" `
                               -MspScratchFolder $MspScratchFolder `
                               -DeviceHostname $DeviceHostname `
                               -DeviceTags $DeviceTags

if (-not $Init.Success) {
    exit 0
}

# ============================================================
# MAIN SCRIPT LOGIC
# ============================================================
$ScriptVersion = "2026.01.12"
$InvokeParams = @{ ScriptBlock = {

    Write-LevelLog "Policy Check: $SoftwareName (v$ScriptVersion)"
    Write-Host ""

    # Get custom field policy if available (passed from launcher)
    # Variable name: policy_<softwarename> (e.g., $policy_unchecky)
    $CustomFieldPolicyVar = "policy_$SoftwareName"
    $CustomFieldPolicy = Get-Variable -Name $CustomFieldPolicyVar -ValueOnly -ErrorAction SilentlyContinue
    if ($CustomFieldPolicy) {
        Write-LevelLog "Custom field policy: $CustomFieldPolicy"
    }

    # Run the policy check with the 5-tag model
    $Policy = Invoke-SoftwarePolicyCheck -SoftwareName $SoftwareName `
                                         -DeviceTags $DeviceTags `
                                         -CustomFieldPolicy $CustomFieldPolicy

    Write-Host ""

    # Take action based on resolved policy
    if ($Policy.ShouldProcess) {
        switch ($Policy.ResolvedAction) {
            "Install" {
                Write-LevelLog "ACTION: Would install $SoftwareName" -Level "INFO"
                # TODO: Implement actual installation
                # Install-Unchecky
            }
            "Remove" {
                Write-LevelLog "ACTION: Would remove $SoftwareName" -Level "INFO"
                # TODO: Implement actual removal
                # Remove-Unchecky
            }
            "Reinstall" {
                Write-LevelLog "ACTION: Would reinstall $SoftwareName" -Level "INFO"
                # TODO: Implement removal then installation
                # Remove-Unchecky
                # Install-Unchecky
            }
            "Pin" {
                Write-LevelLog "ACTION: Pinned - no changes allowed" -Level "INFO"
            }
            "None" {
                Write-LevelLog "ACTION: None required" -Level "INFO"
            }
        }

        # TODO: After action, update status tag
        # - If installed: ensure U+2705 unchecky tag is set
        # - If removed: ensure U+2705 unchecky tag is removed
        # - Clean up transient action tags (U+1F64F, U+1F6AB, U+1F504)
    }

    Write-Host ""
    Write-LevelLog "Policy check completed" -Level "SUCCESS"
}}
if ($RunningFromLauncher) { $InvokeParams.NoExit = $true }
Invoke-LevelScript @InvokeParams
