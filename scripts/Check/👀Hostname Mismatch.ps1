<#
.SYNOPSIS
    Detects hostname mismatch between Level.io device name and Windows hostname.

.DESCRIPTION
    Monitors for hostname mismatches and allows resolution via action tags or auto-sync.

    POLICY VALUES (policy_sync_hostnames custom field):
    - "monitor" (default) = Tag mismatch, wait for operator to apply action tag
    - "auto-hostname"     = Auto-sync Level.io device name to Windows hostname
    - "auto-level"        = Auto-sync Windows hostname to Level.io name (requires reboot)

    ACTION TAGS (apply to device to trigger rename):
    - "Rename Level to Hostname" -> Updates Level.io device name to match Windows
    - "Rename Hostname to Level" -> Renames Windows computer to match Level.io
      (Windows rename requires reboot)

    Designed to run as a daily check script.

.NOTES
    Version:          2026.01.21.13
    Target Platform:  Level.io RMM (via Script Launcher)
    Recommended Timeout: 300 seconds (5 minutes)
    Exit Codes:       0 = Success | 1 = Error

    Level.io Variables Used (passed from Script Launcher):
    - $MspScratchFolder      : MSP-defined scratch folder for persistent storage
    - $DeviceHostname        : Device hostname from Level.io
    - $DeviceTags            : Comma-separated list of device tags
    - $LevelApiKey           : Level.io API key for tag/device operations
    - $policy_sync_hostnames : Policy mode (monitor/auto-hostname/auto-level)

    Tags Created Automatically:
    - Warning tag for hostname mismatch detection
    - Action tags for manual override control
    - Reboot tag set after Windows hostname change

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# Hostname Mismatch Monitor
# Version: 2026.01.21.13
# Target: Level.io (via Script Launcher)
# Exit 0 = Success | Exit 1 = Error
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge

# ============================================================
# POLICY CONFIGURATION
# ============================================================
$PolicyFieldName = "policy_sync_hostnames"

# Get policy value from custom field (passed from launcher)
# Cache valid values to registry for fallback
$PolicyValue = Get-Variable -Name $PolicyFieldName -ValueOnly -ErrorAction SilentlyContinue
if (-not [string]::IsNullOrWhiteSpace($PolicyValue) -and $PolicyValue -notlike "{{*}}") {
    # Valid value from Level.io - cache it
    Set-LevelCacheValue -Name $PolicyFieldName -Value $PolicyValue.Trim().ToLower()
} else {
    # No value from Level.io - try cache fallback
    $PolicyValue = Get-LevelCacheValue -Name $PolicyFieldName
}

# Default to monitor if still empty
if ([string]::IsNullOrWhiteSpace($PolicyValue)) {
    $PolicyValue = "monitor"
}
$PolicyValue = $PolicyValue.Trim().ToLower()

# Parse policy mode
$PolicyMode = switch ($PolicyValue) {
    "auto-hostname" { "AutoHostname" }
    "auto-level"    { "AutoLevel" }
    default         { "Monitor" }
}

# ============================================================
# CACHE LEVEL.IO VARIABLES
# ============================================================
# Cache valid Level.io variables to registry for fallback when values aren't passed
# This ensures the script can still function even if Level.io doesn't provide values

# Cache DeviceHostname (level_device_hostname)
if (-not [string]::IsNullOrWhiteSpace($DeviceHostname) -and $DeviceHostname -notlike "{{*}}") {
    Set-LevelCacheValue -Name "DeviceHostname" -Value $DeviceHostname
} else {
    $DeviceHostname = Get-LevelCacheValue -Name "DeviceHostname"
}

# Cache DeviceTags (level_tag_names)
if (-not [string]::IsNullOrWhiteSpace($DeviceTags) -and $DeviceTags -notlike "{{*}}") {
    Set-LevelCacheValue -Name "DeviceTags" -Value $DeviceTags
} else {
    $DeviceTags = Get-LevelCacheValue -Name "DeviceTags"
}

# Cache MspScratchFolder (cf_coolforge_msp_scratch_folder)
if (-not [string]::IsNullOrWhiteSpace($MspScratchFolder) -and $MspScratchFolder -notlike "{{*}}") {
    Set-LevelCacheValue -Name "MspScratchFolder" -Value $MspScratchFolder
} else {
    $CachedMspScratch = Get-LevelCacheValue -Name "MspScratchFolder"
    if (-not [string]::IsNullOrWhiteSpace($CachedMspScratch)) {
        $MspScratchFolder = $CachedMspScratch
    }
}

# Cache DeviceId (level_device_id)
if (-not [string]::IsNullOrWhiteSpace($DeviceId) -and $DeviceId -notlike "{{*}}") {
    Set-LevelCacheValue -Name "DeviceId" -Value $DeviceId
} else {
    $DeviceId = Get-LevelCacheValue -Name "DeviceId"
}

# ============================================================
# TAG DEFINITIONS
# ============================================================
$TagMismatch = "HOSTNAME MISMATCH"
$TagRenameLevel = "Rename Level to Hostname"
$TagRenameWindows = "Rename Hostname to Level"
$TagReboot = "REBOOT TONIGHT"

# Get emoji patterns from library (single source of truth)
$E = Get-EmojiBytePatterns

# Full tag names using library emojis
$FullTagMismatch = "$($E.Warning)$TagMismatch"
$FullTagRenameLevel = "$($E.Wrench)$TagRenameLevel"
$FullTagRenameWindows = "$($E.Wrench)$TagRenameWindows"
$FullTagReboot = "$($E.Pray)$($E.Arrows)$TagReboot"

# ============================================================
# INITIALIZE
# ============================================================
$Init = Initialize-LevelScript -ScriptName "HostnameMismatch" `
                               -MspScratchFolder $MspScratchFolder `
                               -DeviceHostname $DeviceHostname `
                               -DeviceTags $DeviceTags `
                               -SkipTagCheck `
                               -DebugMode $DebugScripts

if (-not $Init.Success) {
    exit 0
}

# ============================================================
# HELPER FUNCTIONS
# ============================================================

function Test-ValidWindowsHostname {
    param([string]$Name)

    # Windows hostname rules:
    # - 1-15 characters
    # - Alphanumeric and hyphens only
    # - Cannot start or end with hyphen
    # - Cannot be all digits

    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    if ($Name.Length -lt 1 -or $Name.Length -gt 15) { return $false }
    if ($Name -notmatch '^[a-zA-Z0-9-]+$') { return $false }
    if ($Name.StartsWith('-') -or $Name.EndsWith('-')) { return $false }
    if ($Name -match '^\d+$') { return $false }

    return $true
}

function Find-TagInList {
    param(
        [string]$TagList,
        [string]$SearchTag
    )

    if ([string]::IsNullOrWhiteSpace($TagList)) { return $false }

    $Tags = $TagList -split '\s*,\s*'
    foreach ($Tag in $Tags) {
        # Case-insensitive match, allowing for emoji variations
        if ($Tag -like "*$SearchTag*") {
            return $true
        }
    }
    return $false
}

# ============================================================
# MAIN SCRIPT LOGIC
# ============================================================
Invoke-LevelScript -ScriptBlock {

    Write-LevelLog "Starting Hostname Mismatch Check"
    Write-Host "  Policy Mode: $PolicyMode"

    # ============================================================
    # AUTO-BOOTSTRAP: Create required tags and custom field
    # ============================================================
    if ($LevelApiKey) {
        # Create tags
        $TagsToCreate = @(
            @{ Name = $FullTagMismatch; Description = "Warning tag for hostname mismatch" }
            @{ Name = $FullTagRenameLevel; Description = "Action tag to rename Level device" }
            @{ Name = $FullTagRenameWindows; Description = "Action tag to rename Windows hostname" }
        )

        foreach ($TagDef in $TagsToCreate) {
            $ExistingTag = Find-LevelTag -ApiKey $LevelApiKey -TagName $TagDef.Name
            if (-not $ExistingTag) {
                Write-LevelLog "Creating tag: $($TagDef.Name)" -Level "INFO"
                $NewTag = New-LevelTag -ApiKey $LevelApiKey -TagName $TagDef.Name
                if ($NewTag) {
                    Write-LevelLog "Tag created: $($TagDef.Name)" -Level "SUCCESS"
                } else {
                    Write-LevelLog "Failed to create tag: $($TagDef.Name)" -Level "WARN"
                }
            }
        }

        # Create custom field for policy
        $ExistingField = Find-LevelCustomField -ApiKey $LevelApiKey -FieldName $PolicyFieldName
        if (-not $ExistingField) {
            Write-LevelLog "Creating custom field: $PolicyFieldName" -Level "INFO"
            $NewField = New-LevelCustomField -ApiKey $LevelApiKey -Name $PolicyFieldName -DefaultValue "monitor"
            if ($NewField) {
                Write-LevelLog "Custom field created: $PolicyFieldName (default=monitor)" -Level "SUCCESS"
            } else {
                Write-LevelLog "Failed to create custom field: $PolicyFieldName" -Level "WARN"
            }
        }
    }

    # ============================================================
    # GET HOSTNAMES
    # ============================================================
    $WindowsHostname = $env:COMPUTERNAME
    $LevelHostname = $DeviceHostname
    $TagSource = $DeviceTags

    Write-Host ""
    Write-Host "  Windows Hostname:  $WindowsHostname"
    Write-Host "  Level.io Name:     $LevelHostname"
    Write-Host ""

    # Validate we have Level hostname
    if ([string]::IsNullOrWhiteSpace($LevelHostname)) {
        Write-LevelLog "Level.io device hostname not available (launcher and cache empty)" -Level "WARN"
        Write-Host "[Alert] Cannot determine Level.io device name - skipping check"
        Complete-LevelScript -ExitCode 0 -Message "Level hostname not available"
        return
    }

    # Compare (case-insensitive)
    $HostnamesMatch = $WindowsHostname -ieq $LevelHostname

    if ($HostnamesMatch) {
        Write-Host "[OK] Hostnames match" -ForegroundColor Green
        Write-LevelLog "Hostnames match: $WindowsHostname" -Level "SUCCESS"

        # Remove mismatch tag if present
        if (Find-TagInList -TagList $TagSource -SearchTag $TagMismatch) {
            Write-Host "  Removing stale mismatch tag..."

            if ($LevelApiKey) {
                if ($DeviceId) {
                    $Tag = Find-LevelTag -ApiKey $LevelApiKey -TagName $FullTagMismatch
                    if ($Tag) {
                        Remove-LevelTagFromDevice -ApiKey $LevelApiKey -TagId $Tag.id -DeviceId $DeviceId -TagName $FullTagMismatch | Out-Null
                        Write-LevelLog "Removed $FullTagMismatch tag" -Level "INFO"
                    }
                }
            }
        }

        Complete-LevelScript -ExitCode 0 -Message "Hostnames match"
        return
    }

    # Mismatch detected - check for action tags before alerting
    $HasRenameLevelTag = Find-TagInList -TagList $TagSource -SearchTag $TagRenameLevel
    $HasRenameWindowsTag = Find-TagInList -TagList $TagSource -SearchTag $TagRenameWindows

    if ($HasRenameLevelTag -or $HasRenameWindowsTag -or $PolicyMode -ne "Monitor") {
        # Action tag or auto mode will handle this - informational only
        Write-Host ""
        Write-Host "  Windows Hostname:  $WindowsHostname"
        Write-Host "  Level.io Name:     $LevelHostname"
        Write-LevelLog "Hostname mismatch: Windows='$WindowsHostname' Level='$LevelHostname' (resolving)" -Level "INFO"
    } else {
        Write-Host "[Alert] Hostname mismatch: Windows='$WindowsHostname' Level='$LevelHostname'" -ForegroundColor Yellow
        Write-LevelLog "Hostname mismatch: Windows='$WindowsHostname' Level='$LevelHostname'" -Level "WARN"
    }

    if ($HasRenameLevelTag) {
        # Rename Level.io device to match Windows hostname
        Write-Host ""
        Write-Host "  Action: Rename Level.io device to '$WindowsHostname'" -ForegroundColor Cyan
        Write-LevelLog "Action tag found: Renaming Level device to '$WindowsHostname'"

        if (-not $LevelApiKey) {
            Write-Host "[Alert] Cannot rename: No API key available" -ForegroundColor Red
            Write-LevelLog "Cannot rename Level device: No API key" -Level "ERROR"
            Complete-LevelScript -ExitCode 1 -Message "No API key for rename"
            return
        }

        if (-not $DeviceId) {
            Write-Host "[Alert] Device ID not available" -ForegroundColor Red
            Write-LevelLog "Device ID not available from Level.io" -Level "ERROR"
            Complete-LevelScript -ExitCode 1 -Message "Device ID not available"
            return
        }

        $RenameResult = Set-LevelDeviceName -ApiKey $LevelApiKey -DeviceId $DeviceId -NewName $WindowsHostname

        if ($RenameResult) {
            Write-Host "[OK] Level.io device renamed successfully" -ForegroundColor Green

            # Remove action tag
            $ActionTag = Find-LevelTag -ApiKey $LevelApiKey -TagName $FullTagRenameLevel
            if ($ActionTag) {
                Remove-LevelTagFromDevice -ApiKey $LevelApiKey -TagId $ActionTag.id -DeviceId $DeviceId -TagName $FullTagRenameLevel | Out-Null
                Write-LevelLog "Removed action tag: $FullTagRenameLevel"
            }

            # Remove mismatch tag
            $MismatchTag = Find-LevelTag -ApiKey $LevelApiKey -TagName $FullTagMismatch
            if ($MismatchTag) {
                Remove-LevelTagFromDevice -ApiKey $LevelApiKey -TagId $MismatchTag.id -DeviceId $DeviceId -TagName $FullTagMismatch | Out-Null
                Write-LevelLog "Removed mismatch tag: $FullTagMismatch"
            }

            Complete-LevelScript -ExitCode 0 -Message "Level device renamed to $WindowsHostname"
        } else {
            Write-Host "[Alert] Failed to rename Level.io device" -ForegroundColor Red
            Complete-LevelScript -ExitCode 1 -Message "Failed to rename Level device"
        }
        return
    }

    if ($HasRenameWindowsTag) {
        # Rename Windows hostname to match Level.io
        Write-Host ""
        Write-Host "  Action: Rename Windows hostname to '$LevelHostname'" -ForegroundColor Cyan
        Write-LevelLog "Action tag found: Renaming Windows to '$LevelHostname'"

        # Validate the Level hostname is valid for Windows
        if (-not (Test-ValidWindowsHostname -Name $LevelHostname)) {
            Write-Host "[Alert] Invalid Windows hostname: '$LevelHostname'" -ForegroundColor Red
            Write-Host "    Windows hostnames must be 1-15 characters, alphanumeric/hyphens only"
            Write-LevelLog "Cannot rename Windows: '$LevelHostname' is not a valid hostname" -Level "ERROR"
            Complete-LevelScript -ExitCode 1 -Message "Invalid hostname for Windows"
            return
        }

        try {
            Rename-Computer -NewName $LevelHostname -Force -ErrorAction Stop
            Write-Host "[OK] Windows hostname changed to '$LevelHostname'" -ForegroundColor Green
            Write-Host "    REBOOT REQUIRED for change to take effect" -ForegroundColor Yellow
            Write-LevelLog "Windows hostname changed to '$LevelHostname' - reboot required" -Level "SUCCESS"

            if ($LevelApiKey) {
                if ($DeviceId) {
                    # Remove action tag
                    $ActionTag = Find-LevelTag -ApiKey $LevelApiKey -TagName $FullTagRenameWindows
                    if ($ActionTag) {
                        Remove-LevelTagFromDevice -ApiKey $LevelApiKey -TagId $ActionTag.id -DeviceId $DeviceId -TagName $FullTagRenameWindows | Out-Null
                        Write-LevelLog "Removed action tag: $FullTagRenameWindows"
                    }

                    # Remove mismatch tag
                    $MismatchTag = Find-LevelTag -ApiKey $LevelApiKey -TagName $FullTagMismatch
                    if ($MismatchTag) {
                        Remove-LevelTagFromDevice -ApiKey $LevelApiKey -TagId $MismatchTag.id -DeviceId $DeviceId -TagName $FullTagMismatch | Out-Null
                        Write-LevelLog "Removed mismatch tag: $FullTagMismatch"
                    }

                    # Add reboot tag
                    $RebootTag = Find-LevelTag -ApiKey $LevelApiKey -TagName $FullTagReboot
                    if ($RebootTag) {
                        Add-LevelTagToDevice -ApiKey $LevelApiKey -TagId $RebootTag.id -DeviceId $DeviceId -TagName $FullTagReboot | Out-Null
                        Write-LevelLog "Added reboot tag: $FullTagReboot"
                        Write-Host "    Reboot scheduled via automation" -ForegroundColor Cyan
                    } else {
                        Write-Host "    Note: Reboot tag not found - schedule reboot manually" -ForegroundColor Yellow
                    }
                }
            }

            Complete-LevelScript -ExitCode 0 -Message "Windows renamed to $LevelHostname (reboot required)"
        }
        catch {
            Write-Host "[Alert] Failed to rename Windows hostname: $_" -ForegroundColor Red
            Write-LevelLog "Failed to rename Windows: $_" -Level "ERROR"
            Complete-LevelScript -ExitCode 1 -Message "Failed to rename Windows"
        }
        return
    }

    # No action tag - behavior depends on policy mode
    Write-Host ""

    switch ($PolicyMode) {
        "AutoHostname" {
            # Auto-hostname mode: Rename Level.io device to match Windows hostname
            Write-Host "  Policy Action: Auto-syncing Level.io device name to Windows hostname" -ForegroundColor Cyan
            Write-LevelLog "Policy=AutoHostname: Renaming Level device to '$WindowsHostname'"

            if (-not $LevelApiKey) {
                Write-Host "[Alert] Cannot auto-sync: No API key available" -ForegroundColor Red
                Write-LevelLog "Cannot auto-sync Level device: No API key" -Level "ERROR"
                Complete-LevelScript -ExitCode 1 -Message "No API key for auto-sync"
                return
            }

            if (-not $DeviceId) {
                Write-Host "[Alert] Device ID not available" -ForegroundColor Red
                Write-LevelLog "Device ID not available from Level.io" -Level "ERROR"
                Complete-LevelScript -ExitCode 1 -Message "Device ID not available"
                return
            }

            $RenameResult = Set-LevelDeviceName -ApiKey $LevelApiKey -DeviceId $DeviceId -NewName $WindowsHostname

            if ($RenameResult) {
                Write-Host "[OK] Level.io device renamed to '$WindowsHostname'" -ForegroundColor Green
                Write-LevelLog "Auto-sync: Level device renamed to '$WindowsHostname'" -Level "SUCCESS"

                # Remove mismatch tag if present
                $MismatchTag = Find-LevelTag -ApiKey $LevelApiKey -TagName $FullTagMismatch
                if ($MismatchTag) {
                    Remove-LevelTagFromDevice -ApiKey $LevelApiKey -TagId $MismatchTag.id -DeviceId $DeviceId -TagName $FullTagMismatch | Out-Null
                    Write-LevelLog "Removed mismatch tag: $FullTagMismatch"
                }

                Complete-LevelScript -ExitCode 0 -Message "Auto-synced Level device to $WindowsHostname"
            } else {
                Write-Host "[Alert] Failed to rename Level.io device" -ForegroundColor Red
                Write-LevelLog "Auto-sync failed: Could not rename Level device" -Level "ERROR"

                # Set mismatch tag for visibility
                $MismatchTag = Find-LevelTag -ApiKey $LevelApiKey -TagName $FullTagMismatch
                if ($MismatchTag) {
                    Add-LevelTagToDevice -ApiKey $LevelApiKey -TagId $MismatchTag.id -DeviceId $DeviceId -TagName $FullTagMismatch | Out-Null
                }

                Complete-LevelScript -ExitCode 1 -Message "Failed to auto-sync Level device"
            }
        }

        "AutoLevel" {
            # Auto-level mode: Rename Windows hostname to match Level.io name
            Write-Host "  Policy Action: Auto-syncing Windows hostname to Level.io device name" -ForegroundColor Cyan
            Write-LevelLog "Policy=AutoLevel: Renaming Windows to '$LevelHostname'"

            # Validate the Level hostname is valid for Windows
            if (-not (Test-ValidWindowsHostname -Name $LevelHostname)) {
                Write-Host "[Alert] Invalid Windows hostname: '$LevelHostname'" -ForegroundColor Red
                Write-Host "    Windows hostnames must be 1-15 characters, alphanumeric/hyphens only"
                Write-LevelLog "Cannot rename Windows: '$LevelHostname' is not a valid hostname" -Level "ERROR"
                Complete-LevelScript -ExitCode 1 -Message "Invalid hostname for Windows"
                return
            }

            try {
                Rename-Computer -NewName $LevelHostname -Force -ErrorAction Stop
                Write-Host "[OK] Windows hostname changed to '$LevelHostname'" -ForegroundColor Green
                Write-Host "    REBOOT REQUIRED for change to take effect" -ForegroundColor Yellow
                Write-LevelLog "Windows hostname changed to '$LevelHostname' - reboot required" -Level "SUCCESS"

                if ($LevelApiKey -and $DeviceId) {
                    # Remove mismatch tag
                    $MismatchTag = Find-LevelTag -ApiKey $LevelApiKey -TagName $FullTagMismatch
                    if ($MismatchTag) {
                        Remove-LevelTagFromDevice -ApiKey $LevelApiKey -TagId $MismatchTag.id -DeviceId $DeviceId -TagName $FullTagMismatch | Out-Null
                        Write-LevelLog "Removed mismatch tag: $FullTagMismatch"
                    }

                    # Add reboot tag
                    $RebootTag = Find-LevelTag -ApiKey $LevelApiKey -TagName $FullTagReboot
                    if ($RebootTag) {
                        Add-LevelTagToDevice -ApiKey $LevelApiKey -TagId $RebootTag.id -DeviceId $DeviceId -TagName $FullTagReboot | Out-Null
                        Write-LevelLog "Added reboot tag: $FullTagReboot"
                        Write-Host "    Reboot scheduled via automation" -ForegroundColor Cyan
                    } else {
                        Write-Host "    Note: Reboot tag not found - schedule reboot manually" -ForegroundColor Yellow
                    }
                }

                Complete-LevelScript -ExitCode 0 -Message "Windows renamed to $LevelHostname (reboot required)"
            }
            catch {
                Write-Host "[Alert] Failed to rename Windows hostname: $_" -ForegroundColor Red
                Write-LevelLog "Failed to rename Windows: $_" -Level "ERROR"
                Complete-LevelScript -ExitCode 1 -Message "Failed to rename Windows"
            }
        }

        default {
            # Monitor mode: Set mismatch tag, wait for operator to apply action tag
            Write-Host "  Policy Mode: Monitor (waiting for action tag)"
            Write-Host "  To resolve, apply one of these tags to the device:"
            Write-Host "    - $FullTagRenameLevel  (rename Level.io to match Windows)"
            Write-Host "    - $FullTagRenameWindows (rename Windows to match Level.io)"
            Write-Host ""

            if ($LevelApiKey) {
                if ($DeviceId) {
                    # Ensure mismatch tag exists and is applied
                    $MismatchTag = Find-LevelTag -ApiKey $LevelApiKey -TagName $FullTagMismatch
                    if (-not $MismatchTag) {
                        Write-LevelLog "Mismatch tag '$FullTagMismatch' not found - create it in Level.io" -Level "WARN"
                    } else {
                        Add-LevelTagToDevice -ApiKey $LevelApiKey -TagId $MismatchTag.id -DeviceId $DeviceId -TagName $FullTagMismatch | Out-Null
                        Write-LevelLog "Added mismatch tag: $FullTagMismatch"
                        Write-Host "[*] Mismatch tag applied" -ForegroundColor Yellow
                    }
                }
            }

            Complete-LevelScript -ExitCode 0 -Message "Mismatch detected: Windows='$WindowsHostname' Level='$LevelHostname'"
        }
    }
}
