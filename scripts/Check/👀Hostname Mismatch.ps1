<#
.SYNOPSIS
    Policy script for hostname synchronization between Level.io and Windows.

.DESCRIPTION
    Implements hostname sync policy using the custom field: policy_sync_hostnames

    POLICY VALUES:
    - "yes" / "enable" / "on"  = Auto-sync Level device name to Windows hostname
    - "no" / "disable" / "off" = Disabled - script does nothing
    - "pin" / "lock"           = Report only - detect but don't modify anything
    - "" (empty)               = Same as "yes" (active by default)

    BEHAVIOR:
    - When enabled: Detects mismatch, auto-renames Level device to match Windows
    - When pinned: Detects mismatch, sets warning tag, but no auto-rename
    - When disabled: Exits immediately, no checks performed

    MANUAL OVERRIDE TAGS:
    - "Rename Level to Hostname" -> Updates Level.io device name to match Windows
    - "Rename Hostname to Level" -> Renames Windows computer to match Level.io
      (Windows rename requires reboot)

    Designed to run as a daily policy script to maintain hostname consistency.

.NOTES
    Version:          2026.01.21.05
    Target Platform:  Level.io RMM (via Script Launcher)
    Recommended Timeout: 300 seconds (5 minutes)
    Exit Codes:       0 = Success | 1 = Error

    Level.io Variables Used (passed from Script Launcher):
    - $MspScratchFolder      : MSP-defined scratch folder for persistent storage
    - $DeviceHostname        : Device hostname from Level.io
    - $DeviceTags            : Comma-separated list of device tags
    - $LevelApiKey           : Level.io API key for tag/device operations
    - $policy_sync_hostnames : Policy value (yes/no/pin/empty)

    Tags Created Automatically:
    - Warning tag for hostname mismatch detection
    - Action tags for manual override control
    - Reboot tag set after Windows hostname change

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# Hostname Sync Policy
# Version: 2026.01.21.05
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
$PolicyValue = Get-Variable -Name $PolicyFieldName -ValueOnly -ErrorAction SilentlyContinue
if ([string]::IsNullOrWhiteSpace($PolicyValue) -or $PolicyValue -like "{{*}}") {
    $PolicyValue = ""
}
$PolicyValue = $PolicyValue.Trim().ToLower()

# Parse policy value
$PolicyAction = switch ($PolicyValue) {
    { $_ -in @("yes", "enable", "on", "true", "1", "") } { "Enable" }
    { $_ -in @("no", "disable", "off", "false", "0") } { "Disable" }
    { $_ -in @("pin", "lock", "freeze", "hold", "report") } { "Pin" }
    default { "Enable" }  # Unknown values default to enabled
}

# Handle disabled policy - exit immediately
if ($PolicyAction -eq "Disable") {
    Write-Host "[*] Hostname sync policy is disabled"
    exit 0
}

# ============================================================
# TAG DEFINITIONS
# ============================================================
$TagMismatch = "HOSTNAME MISMATCH"
$TagRenameLevel = "Rename Level to Hostname"
$TagRenameWindows = "Rename Hostname to Level"
$TagReboot = "REBOOT TONIGHT"

# Emoji prefixes for tag operations
$EmojiWarning = [char]0x26A0 + [char]0xFE0F  # Warning sign
$EmojiFix = [char]0x1F527                     # Wrench
$EmojiReboot = [char]0x1F64F + [char]0x1F504  # Pray + arrows (matching existing)

# Full tag names
$FullTagMismatch = "$EmojiWarning$TagMismatch"
$FullTagRenameLevel = "$EmojiFix$TagRenameLevel"
$FullTagRenameWindows = "$EmojiFix$TagRenameWindows"
$FullTagReboot = "$EmojiReboot$TagReboot"

# ============================================================
# INITIALIZE
# ============================================================
$Init = Initialize-LevelScript -ScriptName "HostnameMismatch" `
                               -MspScratchFolder $MspScratchFolder `
                               -DeviceHostname $DeviceHostname `
                               -DeviceTags $DeviceTags `
                               -SkipTagGate

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
    Write-Host "  Policy Mode: $PolicyAction"

    # ============================================================
    # AUTO-BOOTSTRAP: Create required tags if they don't exist
    # ============================================================
    if ($LevelApiKey) {
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
    }

    # ============================================================
    # GET HOSTNAMES
    # ============================================================
    # Get Windows hostname
    $WindowsHostname = $env:COMPUTERNAME

    # Get Level hostname - from launcher variable or cache fallback
    $LevelHostname = $DeviceHostname
    $UsingCachedHostname = $false
    if ([string]::IsNullOrWhiteSpace($LevelHostname) -or $LevelHostname -like "{{*}}") {
        $LevelHostname = Get-LevelCacheValue -Name "DeviceHostname"
        $UsingCachedHostname = $true
    }

    # Get device tags - from launcher variable or cache fallback
    $TagSource = $DeviceTags
    $UsingCachedTags = $false
    if ([string]::IsNullOrWhiteSpace($TagSource) -or $TagSource -like "{{*}}") {
        $CachedTags = Get-CachedDeviceTags
        if ($CachedTags -and $CachedTags.Count -gt 0) {
            $TagSource = $CachedTags -join ", "
            $UsingCachedTags = $true
        }
    }

    Write-Host ""
    Write-Host "  Windows Hostname:  $WindowsHostname"
    Write-Host "  Level.io Name:     $LevelHostname$(if ($UsingCachedHostname) { ' (from cache)' })"
    if ($UsingCachedTags) {
        Write-Host "  Tags Source:       Registry cache"
    }
    Write-Host ""

    # Validate we have Level hostname
    if ([string]::IsNullOrWhiteSpace($LevelHostname)) {
        Write-LevelLog "Level.io device hostname not available (launcher and cache empty)" -Level "WARN"
        Write-Host "[!] Cannot determine Level.io device name - skipping check"
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
                $Device = Find-LevelDevice -ApiKey $LevelApiKey -Hostname $LevelHostname
                if ($Device) {
                    $Tag = Find-LevelTag -ApiKey $LevelApiKey -TagName $FullTagMismatch
                    if ($Tag) {
                        Remove-LevelTagFromDevice -ApiKey $LevelApiKey -TagId $Tag.id -DeviceId $Device.id -TagName $FullTagMismatch | Out-Null
                        Write-LevelLog "Removed $FullTagMismatch tag" -Level "INFO"
                    }
                }
            }
        }

        Complete-LevelScript -ExitCode 0 -Message "Hostnames match"
        return
    }

    # Mismatch detected
    Write-Host "[!!] HOSTNAME MISMATCH DETECTED" -ForegroundColor Yellow
    Write-LevelLog "Hostname mismatch: Windows='$WindowsHostname' Level='$LevelHostname'" -Level "WARN"

    # Check for action tags
    $HasRenameLevelTag = Find-TagInList -TagList $TagSource -SearchTag $TagRenameLevel
    $HasRenameWindowsTag = Find-TagInList -TagList $TagSource -SearchTag $TagRenameWindows

    if ($HasRenameLevelTag) {
        # Rename Level.io device to match Windows hostname
        Write-Host ""
        Write-Host "  Action: Rename Level.io device to '$WindowsHostname'" -ForegroundColor Cyan
        Write-LevelLog "Action tag found: Renaming Level device to '$WindowsHostname'"

        if (-not $LevelApiKey) {
            Write-Host "[!] Cannot rename: No API key available" -ForegroundColor Red
            Write-LevelLog "Cannot rename Level device: No API key" -Level "ERROR"
            Complete-LevelScript -ExitCode 1 -Message "No API key for rename"
            return
        }

        $Device = Find-LevelDevice -ApiKey $LevelApiKey -Hostname $LevelHostname
        if (-not $Device) {
            Write-Host "[!] Cannot find device in Level.io" -ForegroundColor Red
            Write-LevelLog "Cannot find device '$LevelHostname' in Level.io" -Level "ERROR"
            Complete-LevelScript -ExitCode 1 -Message "Device not found in Level.io"
            return
        }

        $RenameResult = Set-LevelDeviceName -ApiKey $LevelApiKey -DeviceId $Device.id -NewName $WindowsHostname

        if ($RenameResult) {
            Write-Host "[OK] Level.io device renamed successfully" -ForegroundColor Green

            # Remove action tag
            $ActionTag = Find-LevelTag -ApiKey $LevelApiKey -TagName $FullTagRenameLevel
            if ($ActionTag) {
                Remove-LevelTagFromDevice -ApiKey $LevelApiKey -TagId $ActionTag.id -DeviceId $Device.id -TagName $FullTagRenameLevel | Out-Null
                Write-LevelLog "Removed action tag: $FullTagRenameLevel"
            }

            # Remove mismatch tag
            $MismatchTag = Find-LevelTag -ApiKey $LevelApiKey -TagName $FullTagMismatch
            if ($MismatchTag) {
                Remove-LevelTagFromDevice -ApiKey $LevelApiKey -TagId $MismatchTag.id -DeviceId $Device.id -TagName $FullTagMismatch | Out-Null
                Write-LevelLog "Removed mismatch tag: $FullTagMismatch"
            }

            Complete-LevelScript -ExitCode 0 -Message "Level device renamed to $WindowsHostname"
        } else {
            Write-Host "[!] Failed to rename Level.io device" -ForegroundColor Red
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
            Write-Host "[!] Invalid Windows hostname: '$LevelHostname'" -ForegroundColor Red
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
                $Device = Find-LevelDevice -ApiKey $LevelApiKey -Hostname $LevelHostname
                if ($Device) {
                    # Remove action tag
                    $ActionTag = Find-LevelTag -ApiKey $LevelApiKey -TagName $FullTagRenameWindows
                    if ($ActionTag) {
                        Remove-LevelTagFromDevice -ApiKey $LevelApiKey -TagId $ActionTag.id -DeviceId $Device.id -TagName $FullTagRenameWindows | Out-Null
                        Write-LevelLog "Removed action tag: $FullTagRenameWindows"
                    }

                    # Remove mismatch tag
                    $MismatchTag = Find-LevelTag -ApiKey $LevelApiKey -TagName $FullTagMismatch
                    if ($MismatchTag) {
                        Remove-LevelTagFromDevice -ApiKey $LevelApiKey -TagId $MismatchTag.id -DeviceId $Device.id -TagName $FullTagMismatch | Out-Null
                        Write-LevelLog "Removed mismatch tag: $FullTagMismatch"
                    }

                    # Add reboot tag
                    $RebootTag = Find-LevelTag -ApiKey $LevelApiKey -TagName $FullTagReboot
                    if ($RebootTag) {
                        Add-LevelTagToDevice -ApiKey $LevelApiKey -TagId $RebootTag.id -DeviceId $Device.id -TagName $FullTagReboot | Out-Null
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
            Write-Host "[!] Failed to rename Windows hostname: $_" -ForegroundColor Red
            Write-LevelLog "Failed to rename Windows: $_" -Level "ERROR"
            Complete-LevelScript -ExitCode 1 -Message "Failed to rename Windows"
        }
        return
    }

    # No action tag - behavior depends on policy
    Write-Host ""

    if ($PolicyAction -eq "Enable") {
        # Auto-sync: Rename Level.io device to match Windows hostname
        Write-Host "  Policy Action: Auto-syncing Level.io device name to Windows hostname" -ForegroundColor Cyan
        Write-LevelLog "Policy=Enable: Auto-renaming Level device to '$WindowsHostname'"

        if (-not $LevelApiKey) {
            Write-Host "[!] Cannot auto-sync: No API key available" -ForegroundColor Red
            Write-LevelLog "Cannot auto-sync Level device: No API key" -Level "ERROR"
            Complete-LevelScript -ExitCode 1 -Message "No API key for auto-sync"
            return
        }

        $Device = Find-LevelDevice -ApiKey $LevelApiKey -Hostname $LevelHostname
        if (-not $Device) {
            Write-Host "[!] Cannot find device in Level.io" -ForegroundColor Red
            Write-LevelLog "Cannot find device '$LevelHostname' in Level.io" -Level "ERROR"
            Complete-LevelScript -ExitCode 1 -Message "Device not found in Level.io"
            return
        }

        $RenameResult = Set-LevelDeviceName -ApiKey $LevelApiKey -DeviceId $Device.id -NewName $WindowsHostname

        if ($RenameResult) {
            Write-Host "[OK] Level.io device renamed to '$WindowsHostname'" -ForegroundColor Green
            Write-LevelLog "Auto-sync: Level device renamed to '$WindowsHostname'" -Level "SUCCESS"

            # Remove mismatch tag if present
            $MismatchTag = Find-LevelTag -ApiKey $LevelApiKey -TagName $FullTagMismatch
            if ($MismatchTag) {
                Remove-LevelTagFromDevice -ApiKey $LevelApiKey -TagId $MismatchTag.id -DeviceId $Device.id -TagName $FullTagMismatch | Out-Null
                Write-LevelLog "Removed mismatch tag: $FullTagMismatch"
            }

            Complete-LevelScript -ExitCode 0 -Message "Auto-synced Level device to $WindowsHostname"
        } else {
            Write-Host "[!] Failed to rename Level.io device" -ForegroundColor Red
            Write-LevelLog "Auto-sync failed: Could not rename Level device" -Level "ERROR"

            # Set mismatch tag for visibility
            $MismatchTag = Find-LevelTag -ApiKey $LevelApiKey -TagName $FullTagMismatch
            if ($MismatchTag) {
                Add-LevelTagToDevice -ApiKey $LevelApiKey -TagId $MismatchTag.id -DeviceId $Device.id -TagName $FullTagMismatch | Out-Null
            }

            Complete-LevelScript -ExitCode 1 -Message "Failed to auto-sync Level device"
        }
    }
    else {
        # Pin mode: Report only - set mismatch tag but don't auto-rename
        Write-Host "  Policy Mode: Pin (report only - no auto-rename)"
        Write-Host "  To resolve, apply one of these tags to the device:"
        Write-Host "    - $FullTagRenameLevel  (rename Level.io to match Windows)"
        Write-Host "    - $FullTagRenameWindows (rename Windows to match Level.io)"
        Write-Host ""

        if ($LevelApiKey) {
            $Device = Find-LevelDevice -ApiKey $LevelApiKey -Hostname $LevelHostname
            if ($Device) {
                # Ensure mismatch tag exists and is applied
                $MismatchTag = Find-LevelTag -ApiKey $LevelApiKey -TagName $FullTagMismatch
                if (-not $MismatchTag) {
                    Write-LevelLog "Mismatch tag '$FullTagMismatch' not found - create it in Level.io" -Level "WARN"
                } else {
                    Add-LevelTagToDevice -ApiKey $LevelApiKey -TagId $MismatchTag.id -DeviceId $Device.id -TagName $FullTagMismatch | Out-Null
                    Write-LevelLog "Added mismatch tag: $FullTagMismatch"
                    Write-Host "[*] Mismatch tag applied" -ForegroundColor Yellow
                }
            }
        }

        Complete-LevelScript -ExitCode 0 -Message "Mismatch detected (pinned): Windows='$WindowsHostname' Level='$LevelHostname'"
    }
}
