<#
.SYNOPSIS
    Syncs Level.io-provided data to local registry cache.

.DESCRIPTION
    This script captures data that Level.io provides via variable substitution
    and stores it in the local registry cache. This allows other scripts to
    read from cache instead of making API calls.

    THIS SCRIPT MAKES ZERO API CALLS.

    All data comes from Level.io's variable system:
    - Device ID, hostname, group path
    - Device tags
    - Custom field values

    Run this script frequently (every 5-30 minutes) to keep cache fresh.

.NOTES
    Version:          2026.01.20.01
    Target Platform:  Level.io RMM (via Script Launcher)
    Exit Codes:       0 = Success | 1 = Alert (Failure)

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge
#>

# COOLForge Cache Sync
# Version: 2026.01.20.01
# Target: Level.io (via Script Launcher)
# Exit 0 = Success | Exit 1 = Alert (Failure)
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge

# ============================================================
# CONFIGURATION
# ============================================================
$ScriptVersion = "2026.01.20.01"

# ============================================================
# INITIALIZE
# ============================================================
$Init = Initialize-LevelScript -ScriptName "COOLForge-CacheSync" `
                               -MspScratchFolder $MspScratchFolder `
                               -DeviceHostname $DeviceHostname `
                               -DeviceTags $DeviceTags

# ============================================================
# MAIN SCRIPT LOGIC
# ============================================================
$ExitCode = 0

$InvokeParams = @{ ScriptBlock = {

    Write-LevelLog "COOLForge Cache Sync v$ScriptVersion"
    Write-LevelLog "Syncing Level.io data to local registry cache..."

    # Collect device info from launcher variables
    $deviceId = $null
    $hostname = $null
    $groupPath = $null
    $tags = $null

    # These should be passed from the launcher via LauncherVariables
    if ($LauncherVars) {
        $deviceId = $LauncherVars["level_device_id"]
        $hostname = $LauncherVars["DeviceHostname"]
        $groupPath = $LauncherVars["level_group_path"]
        $tags = $LauncherVars["DeviceTags"]
    }

    # Fall back to script-level variables if LauncherVars not populated
    if ([string]::IsNullOrWhiteSpace($deviceId) -and (Test-Path variable:level_device_id)) {
        $deviceId = $level_device_id
    }
    if ([string]::IsNullOrWhiteSpace($hostname) -and (Test-Path variable:DeviceHostname)) {
        $hostname = $DeviceHostname
    }
    if ([string]::IsNullOrWhiteSpace($groupPath) -and (Test-Path variable:level_group_path)) {
        $groupPath = $level_group_path
    }
    if ([string]::IsNullOrWhiteSpace($tags) -and (Test-Path variable:DeviceTags)) {
        $tags = $DeviceTags
    }

    # Collect custom field values (non-sensitive only)
    $customFieldValues = @{}

    # Policy fields - add all policy_* fields
    Get-Variable -Name "policy_*" -ErrorAction SilentlyContinue | ForEach-Object {
        if (-not [string]::IsNullOrWhiteSpace($_.Value) -and $_.Value -notlike "{{*}}") {
            $customFieldValues[$_.Name] = $_.Value
        }
    }

    # Add other non-sensitive fields from LauncherVars
    if ($LauncherVars) {
        $LauncherVars.Keys | Where-Object { $_ -like "policy_*" } | ForEach-Object {
            $val = $LauncherVars[$_]
            if (-not [string]::IsNullOrWhiteSpace($val) -and $val -notlike "{{*}}") {
                $customFieldValues[$_] = $val
            }
        }
    }

    # Collect sensitive fields (will be encrypted with DPAPI)
    $sensitiveValues = @{}
    if ($LauncherVars) {
        $LauncherVars.Keys | Where-Object { $_ -like "sensitive_*" } | ForEach-Object {
            $val = $LauncherVars[$_]
            if (-not [string]::IsNullOrWhiteSpace($val) -and $val -notlike "{{*}}") {
                $sensitiveValues[$_] = $val
            }
        }
    }

    # Update the cache
    Update-LevelCache -DeviceId $deviceId `
                      -DeviceHostname $hostname `
                      -DeviceTags $tags `
                      -CustomFieldValues $customFieldValues `
                      -ProtectedFieldValues $sensitiveValues

    # Log what we cached
    Write-LevelLog "Cache updated:"
    if (-not [string]::IsNullOrWhiteSpace($deviceId)) {
        Write-LevelLog "  DeviceId: $deviceId"
    }
    if (-not [string]::IsNullOrWhiteSpace($hostname)) {
        Write-LevelLog "  Hostname: $hostname"
    }
    if (-not [string]::IsNullOrWhiteSpace($tags)) {
        $tagCount = ($tags -split ',').Count
        Write-LevelLog "  DeviceTags: $tagCount tags"
    }
    if ($customFieldValues.Count -gt 0) {
        Write-LevelLog "  CustomFields: $($customFieldValues.Count) values"
    }
    if ($sensitiveValues.Count -gt 0) {
        Write-LevelLog "  ProtectedFields: $($sensitiveValues.Count) values (DPAPI encrypted)"
    }

    # Debug output
    if ($DebugScripts) {
        Write-Host ""
        Write-Host "============================================================" -ForegroundColor Cyan
        Write-Host " DEBUG: Cache Contents" -ForegroundColor Cyan
        Write-Host "============================================================" -ForegroundColor Cyan

        $cachePath = Get-LevelCachePath
        if (Test-Path $cachePath) {
            $props = Get-ItemProperty -Path $cachePath -ErrorAction SilentlyContinue
            $props.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
                $val = $_.Value
                if ($val.Length -gt 100) { $val = $val.Substring(0, 100) + "..." }
                Write-Host "  $($_.Name): $val"
            }
        } else {
            Write-Host "  Cache not found at $cachePath" -ForegroundColor Yellow
        }
    }

    Write-LevelLog "Cache sync complete" -Level "SUCCESS"

}}

Invoke-LevelScript @InvokeParams

exit $ExitCode
