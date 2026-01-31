<#
.SYNOPSIS
    Configuration policy enforcement for Chrome & Edge Location Services.

.DESCRIPTION
    Implements the COOLForge 5-tag policy model for browser geolocation policy management.
    See docs/POLICY-TAGS.md for the complete policy specification.

    This script manages Chrome AND Edge DefaultGeolocationSetting policy:
    - 1 = Allow sites to ask for location
    - 2 = Block all sites from requesting location

    IMPORTANT: When enabling location (install), this script will:
    - Enable Windows Location Services if disabled (required for browsers)
    - Set CloudPolicyOverridesPlatformPolicy = 0 (local registry wins over cloud)
    - Remove any GeolocationBlockedForUrls entries that may override the setting
    - Apply settings to BOTH Chrome and Edge browsers

    POLICY FLOW (per POLICY-TAGS.md):
    1. Check global control tags (device must have checkmark to be managed)
    2. Check config-specific override tags (highest priority)
    3. Fall back to custom field policy (policy_chrome_locationservices)
    4. Execute resolved action (enable/disable)

    GLOBAL CONTROL TAGS (standalone):
    - U+2705 = Device is managed (required to process)
    - U+274C = Device is excluded from management
    - Both = Device is globally pinned (no changes)

    CONFIG-SPECIFIC OVERRIDE TAGS (with "CHROME_LOCATIONSERVICES" suffix):
    - U+1F64F CHROME_LOCATIONSERVICES = Enable Chrome location (transient)
    - U+1F6AB CHROME_LOCATIONSERVICES = Disable Chrome location (transient)
    - U+1F4CC CHROME_LOCATIONSERVICES = Pin - no changes allowed (persistent)
    - U+1F504 CHROME_LOCATIONSERVICES = Re-apply current policy (transient)
    - U+2705 CHROME_LOCATIONSERVICES  = Status: Chrome location is enabled (set by script)

    CUSTOM FIELD POLICY (inherited Group->Folder->Device):
    - policy_chrome_locationservices = "install" | "remove" | "pin" | ""
      (install = allow/ask, remove = block)

.NOTES
    Version:          2026.01.20.01
    Target Platform:  Level.io RMM (via Script Launcher)
    Exit Codes:       0 = Success | 1 = Alert (Failure)

    Level.io Variables Used (passed from Script Launcher):
    - $MspScratchFolder   : MSP-defined scratch folder for persistent storage
    - $DeviceHostname     : Device hostname from Level.io
    - $DeviceTags         : Comma-separated list of device tags

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# Configuration Policy - Chrome & Edge Location Services
# Version: 2026.01.20.01
# Target: Level.io (via Script Launcher)
# Exit 0 = Success | Exit 1 = Alert (Failure)
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge

# ============================================================
# DEBUG OUTPUT HELPER
# ============================================================

function Write-DebugChromeLocationCheck {
    param([int]$CurrentSetting)
    if (-not $DebugScripts) { return }

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " DEBUG: Browser Location Policy Check (Chrome & Edge)" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    # Check both browsers
    foreach ($browser in $BrowserPolicies) {
        $name = $browser.Name
        $key = $browser.Key

        Write-Host ""
        Write-Host "  --- $name Policy ---" -ForegroundColor Yellow
        Write-Host "  Registry Path: $key"

        $setting = (Get-ItemProperty -Path $key -Name 'DefaultGeolocationSetting' -ErrorAction SilentlyContinue).DefaultGeolocationSetting
        $settingText = switch ($setting) {
            1 { 'Allow (1) - Sites can ask for location' }
            2 { 'Block (2) - Sites cannot request location' }
            3 { 'Ask (3) - Default browser behavior' }
            default { 'Not Set - Using browser default' }
        }
        Write-Host "  DefaultGeolocationSetting: $settingText" -ForegroundColor $(if ($setting -eq 1) { 'Green' } elseif ($setting -eq 2) { 'Yellow' } else { 'DarkGray' })

        $cloudOverride = (Get-ItemProperty -Path $key -Name 'CloudPolicyOverridesPlatformPolicy' -ErrorAction SilentlyContinue).CloudPolicyOverridesPlatformPolicy
        $cloudText = switch ($cloudOverride) {
            0 { 'Local wins (0) - Good' }
            1 { 'Cloud wins (1) - May override local!' }
            default { 'Not Set - Cloud may override' }
        }
        Write-Host "  CloudPolicyOverridesPlatformPolicy: $cloudText" -ForegroundColor $(if ($cloudOverride -eq 0) { 'Green' } else { 'Yellow' })

        # Check for blocked URLs
        $blockKey = "$key\GeolocationBlockedForUrls"
        if (Test-Path $blockKey) {
            $blocked = Get-ItemProperty -Path $blockKey -ErrorAction SilentlyContinue
            $blockedUrls = $blocked.PSObject.Properties | Where-Object { $_.Name -match '^\d+$' } | ForEach-Object { $_.Value }
            if ($blockedUrls) {
                Write-Host "  GeolocationBlockedForUrls: $($blockedUrls.Count) entries (BLOCKING!)" -ForegroundColor Red
                $blockedUrls | ForEach-Object { Write-Host "    - $_" -ForegroundColor Red }
            }
        }
    }

    # Device location status
    Write-Host ""
    Write-Host "  --- Windows Location Status ---" -ForegroundColor Yellow
    $winPolicyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'
    $disableLocation = (Get-ItemProperty -Path $winPolicyKey -Name 'DisableLocation' -ErrorAction SilentlyContinue).DisableLocation
    $deviceEnabled = ($disableLocation -ne 1)
    Write-Host "  Windows Location: $(if ($deviceEnabled) { 'Enabled' } else { 'Disabled' })" -ForegroundColor $(if ($deviceEnabled) { 'Green' } else { 'Yellow' })

    Write-Host ""
    Write-Host "  BROWSER LOCATION ENABLED: $(if ($CurrentSetting -eq 1) { 'YES (Allow)' } elseif ($CurrentSetting -eq 2) { 'NO (Block)' } else { 'DEFAULT' })" -ForegroundColor $(if ($CurrentSetting -eq 1) { 'Green' } else { 'Yellow' })
}

# ============================================================
# CONFIGURATION
# ============================================================
$SoftwareName = "CHROME_LOCATIONSERVICES"
$DisplayName = "Chrome & Edge Location Services"
$CustomFieldName = "policy_chrome_locationservices"

# Browser policy registry keys
$BrowserPolicies = @(
    @{ Name = "Chrome"; Key = 'HKLM:\SOFTWARE\Policies\Google\Chrome' },
    @{ Name = "Edge";   Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' }
)
$GeolocationSettingName = 'DefaultGeolocationSetting'

# Legacy compatibility
$ChromePolicyKey = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
$ChromePolicyName = 'DefaultGeolocationSetting'

# ============================================================
# INITIALIZE
# ============================================================
$Init = Initialize-LevelScript -ScriptName "Policy-Chrome-LocationServices" `
                               -MspScratchFolder $MspScratchFolder `
                               -DeviceHostname $DeviceHostname `
                               -DeviceTags $DeviceTags

if (-not $Init.Success) {
    exit 0
}

# Sync script-level debug variables if a debug tag overrode the custom field
if ($Init.DebugTagDetected) {
    $DebugLevel = $Init.DebugLevel
    $DebugScripts = $Init.DebugMode
}

# ============================================================
# HELPER FUNCTIONS
# ============================================================

function Set-RegistryValue {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][ValidateSet('String','DWord','QWord','Binary','MultiString','ExpandString')]$Type,
        [Parameter(Mandatory=$true)]$Value
    )

    $changed = $false

    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
        $changed = $true
    }

    $existing = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name

    if ($null -eq $existing -or $existing -ne $Value) {
        New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
        $changed = $true
    }

    return $changed
}

# ============================================================
# DEVICE LOCATION SERVICES (dependency)
# ============================================================

function Test-DeviceLocationEnabled {
    $winPolicyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'
    $disableLocation = (Get-ItemProperty -Path $winPolicyKey -Name 'DisableLocation' -ErrorAction SilentlyContinue).DisableLocation
    return ($disableLocation -ne 1)
}

function Enable-DeviceLocationServices {
    Write-LevelLog "Enabling Windows Location Services (required for browsers)..."

    # Windows OS policy keys
    $winPolicyKeys = @(
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors',
        'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\LocationAndSensors'
    )

    foreach ($key in $winPolicyKeys) {
        $changed1 = Set-RegistryValue -Path $key -Name 'DisableLocation' -Type DWord -Value 0
        $changed2 = Set-RegistryValue -Path $key -Name 'DisableLocationScripting' -Type DWord -Value 0
        Write-LevelLog "  Windows Policy [$key]: $(if ($changed1 -or $changed2) { 'Enabled' } else { 'Already enabled' })"
    }

    # ConsentStore
    $capabilityKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'
    try {
        if (-not (Test-Path $capabilityKey)) {
            New-Item -Path $capabilityKey -Force | Out-Null
        }
        $changed = Set-RegistryValue -Path $capabilityKey -Name 'Value' -Type String -Value 'Allow'
        Write-LevelLog "  ConsentStore: $(if ($changed) { 'Set to Allow' } else { 'Already Allow' })"
    } catch {
        Write-LevelLog "  ConsentStore: $($_.Exception.Message)" -Level "WARN"
    }

    # Start service
    try {
        $svc = Get-Service -Name 'lfsvc' -ErrorAction Stop
        Set-Service -Name 'lfsvc' -StartupType Manual -ErrorAction Stop
        if ($svc.Status -ne 'Running') {
            Start-Service -Name 'lfsvc' -ErrorAction Stop
        }
        Write-LevelLog "  Geolocation Service: Running"
    } catch {
        Write-LevelLog "  Geolocation Service: $($_.Exception.Message)" -Level "WARN"
    }

    return $true
}

# ============================================================
# CHROME LOCATION DETECTION
# ============================================================

function Get-ChromeLocationSetting {
    $setting = (Get-ItemProperty -Path $ChromePolicyKey -Name $ChromePolicyName -ErrorAction SilentlyContinue).$ChromePolicyName
    return $setting
}

function Test-ChromeLocationEnabled {
    # Returns true if Chrome is set to Allow (1)
    $setting = Get-ChromeLocationSetting
    return ($setting -eq 1)
}

# ============================================================
# ENABLE/DISABLE FUNCTIONS
# ============================================================

function Enable-ChromeLocation {
    Write-LevelLog "Enabling browser geolocation policies (Chrome & Edge)..."

    # First, ensure device location is enabled
    if (-not (Test-DeviceLocationEnabled)) {
        Write-LevelLog "Device location is disabled - enabling it first..."
        Enable-DeviceLocationServices
    }

    # Apply to both Chrome and Edge
    foreach ($browser in $BrowserPolicies) {
        $name = $browser.Name
        $key = $browser.Key

        Write-LevelLog "  --- $name ---"

        # Create policy key if needed
        if (-not (Test-Path $key)) {
            New-Item -Path $key -Force | Out-Null
            Write-LevelLog "    Created policy key"
        }

        # CRITICAL: Make local registry win over cloud policies
        $cloudChanged = Set-RegistryValue -Path $key -Name 'CloudPolicyOverridesPlatformPolicy' -Type DWord -Value 0
        Write-LevelLog "    CloudPolicyOverridesPlatformPolicy: $(if ($cloudChanged) { 'Set to 0 (local wins)' } else { 'Already 0' })"

        # Set geolocation to Allow (1)
        $geoChanged = Set-RegistryValue -Path $key -Name $GeolocationSettingName -Type DWord -Value 1
        Write-LevelLog "    $GeolocationSettingName : $(if ($geoChanged) { 'Set to 1 (Allow)' } else { 'Already 1 (Allow)' })"

        # Remove any GeolocationBlockedForUrls that might override
        $blockKey = "$key\GeolocationBlockedForUrls"
        if (Test-Path $blockKey) {
            Remove-Item -Path $blockKey -Recurse -Force -ErrorAction SilentlyContinue
            Write-LevelLog "    GeolocationBlockedForUrls: Removed" -Level "SUCCESS"
        }
    }

    Write-LevelLog "Browser Location Services ENABLED (Chrome & Edge)" -Level "SUCCESS"
    Write-LevelLog "Note: Users may need to restart browsers to pick up policy changes"
    return $true
}

function Disable-ChromeLocation {
    Write-LevelLog "Disabling browser geolocation policies (Chrome & Edge)..."

    # Apply to both Chrome and Edge
    foreach ($browser in $BrowserPolicies) {
        $name = $browser.Name
        $key = $browser.Key

        Write-LevelLog "  --- $name ---"

        # Create policy key if needed
        if (-not (Test-Path $key)) {
            New-Item -Path $key -Force | Out-Null
        }

        # Make local registry win over cloud policies
        $cloudChanged = Set-RegistryValue -Path $key -Name 'CloudPolicyOverridesPlatformPolicy' -Type DWord -Value 0
        Write-LevelLog "    CloudPolicyOverridesPlatformPolicy: $(if ($cloudChanged) { 'Set to 0 (local wins)' } else { 'Already 0' })"

        # Set geolocation to Block (2)
        $geoChanged = Set-RegistryValue -Path $key -Name $GeolocationSettingName -Type DWord -Value 2
        Write-LevelLog "    $GeolocationSettingName : $(if ($geoChanged) { 'Set to 2 (Block)' } else { 'Already 2 (Block)' })"
    }

    # Note: We do NOT disable device location here, as other apps may need it
    Write-LevelLog "Browser Location Services DISABLED (Chrome & Edge)" -Level "SUCCESS"
    Write-LevelLog "Note: Device location services left unchanged (other apps may need it)"
    return $true
}

# ============================================================
# MAIN SCRIPT LOGIC
# ============================================================
$ScriptVersion = "2026.01.20.01"
$ExitCode = 0

$InvokeParams = @{ ScriptBlock = {

    Write-LevelLog "Policy Enforcement: $DisplayName (v$ScriptVersion)"

    # Debug header
    if ($DebugScripts) {
        Write-Host ""
        Write-Host "============================================================" -ForegroundColor Magenta
        Write-Host " DEBUG MODE ENABLED (debug_coolforge = verbose)" -ForegroundColor Magenta
        Write-Host " Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Magenta
        Write-Host " Computer:  $env:COMPUTERNAME" -ForegroundColor Magenta
        Write-Host "============================================================" -ForegroundColor Magenta
    }

    # Debug: Show all launcher variables
    Write-DebugSection -Title "Launcher Variables" -Data @{
        'MspScratchFolder' = $MspScratchFolder
        'DeviceHostname' = $DeviceHostname
        'DeviceTags' = $DeviceTags
        'LevelApiKey' = $LevelApiKey
    } -MaskApiKey

    Write-Host ""

    # Get custom field policy if available
    $CustomFieldPolicy = Get-Variable -Name $CustomFieldName -ValueOnly -ErrorAction SilentlyContinue
    if ($CustomFieldPolicy) {
        Write-LevelLog "Custom field policy: $CustomFieldPolicy"
    }

    # Debug: Show custom field policy
    Write-DebugSection -Title "Custom Field Policy" -Data @{
        $CustomFieldName = $CustomFieldPolicy
    }

    # Debug: Analyze device tags
    Write-DebugTags -TagString $DeviceTags -SoftwareName $SoftwareName

    # ============================================================
    # AUTO-BOOTSTRAP: Ensure policy infrastructure exists
    # ============================================================
    if ($LevelApiKey) {
        $KeyLength = $LevelApiKey.Length
        $KeyPreview = if ($KeyLength -gt 4) { $LevelApiKey.Substring(0, 4) + "****" } else { "(invalid)" }
        Write-LevelLog "API key: $KeyPreview (length: $KeyLength)" -Level "DEBUG"

        # Pass launcher variable value to skip API calls for field existence check
        $PolicyFieldValue = Get-Variable -Name $CustomFieldName -ValueOnly -ErrorAction SilentlyContinue

        $InfraResult = Initialize-SoftwarePolicyInfrastructure -ApiKey $LevelApiKey `
            -SoftwareName $SoftwareName `
            -RequireUrl $false `
            -CustomFieldName $CustomFieldName `
            -DefaultPolicyValue "pin | uses pin/install/remove (install=allow, remove=block)" `
            -PolicyFieldValue $PolicyFieldValue

        if ($InfraResult.Success) {
            if ($InfraResult.TagsCreated -gt 0 -or $InfraResult.FieldsCreated -gt 0) {
                Write-LevelLog "Created $($InfraResult.TagsCreated) tags, $($InfraResult.FieldsCreated) fields" -Level "SUCCESS"
                Write-Host ""
                Write-Host "Alert: Policy infrastructure created - configure to activate"
                Write-Host "  Field: $CustomFieldName"
                Write-Host "  Default: 'pin' (no changes until configured)"
                Write-Host "  Set to 'install' to allow Chrome location prompts"
                Write-Host "  Set to 'remove' to block Chrome location requests"
                Write-Host ""
                Write-LevelLog "Infrastructure created - exiting for configuration" -Level "INFO"
                $script:ExitCode = 1
                return 1
            }
        }
        else {
            Write-LevelLog "Infrastructure setup warning: $($InfraResult.Error)" -Level "WARN"
        }
    }

    # Check current state
    $CurrentSetting = Get-ChromeLocationSetting
    $IsEnabled = ($CurrentSetting -eq 1)
    Write-LevelLog "Current Chrome geolocation: $(if ($IsEnabled) { 'Allow (1)' } elseif ($CurrentSetting -eq 2) { 'Block (2)' } else { 'Not set' })"
    Write-LevelLog "Device location: $(if (Test-DeviceLocationEnabled) { 'Enabled' } else { 'Disabled' })"

    # Debug: Show check details
    Write-DebugChromeLocationCheck -CurrentSetting $CurrentSetting

    Write-Host ""

    # Run the policy check with the 5-tag model
    if ($DebugScripts) {
        Write-Host ""
        Write-Host "============================================================" -ForegroundColor Cyan
        Write-Host " DEBUG: Get-SoftwarePolicy Internal Trace" -ForegroundColor Cyan
        Write-Host "============================================================" -ForegroundColor Cyan
        $null = Get-SoftwarePolicy -SoftwareName $SoftwareName -DeviceTags $DeviceTags -CustomFieldPolicy $CustomFieldPolicy -ShowDebug
    }
    $Policy = Invoke-SoftwarePolicyCheck -SoftwareName $SoftwareName `
                                         -DeviceTags $DeviceTags `
                                         -CustomFieldPolicy $CustomFieldPolicy

    # Debug: Show policy resolution details
    Write-DebugPolicy -Policy $Policy

    # Debug: Show tag management readiness
    Write-DebugTagManagement -HasApiKey ([bool]$LevelApiKey) -DeviceHostname $DeviceHostname -ApiKeyValue $LevelApiKey

    Write-Host ""

    # Take action based on resolved policy
    $ActionSuccess = $false
    if ($Policy.ShouldProcess) {
        switch ($Policy.ResolvedAction) {
            "Install" {
                # Install = Enable Chrome location (Allow)
                if ($Policy.ActionSource -eq "Tag" -and $LevelApiKey) {
                    $Device = Find-LevelDevice -ApiKey $LevelApiKey -Hostname $DeviceHostname
                    if ($Device) {
                        $SetResult = Set-LevelCustomFieldValue -ApiKey $LevelApiKey -EntityType "device" -EntityId $Device.id -FieldReference $CustomFieldName -Value "install"
                        if ($SetResult) {
                            Write-LevelLog "Set device custom field '$CustomFieldName' = 'install'" -Level "SUCCESS"
                        }
                    }
                }
                if ($IsEnabled) {
                    Write-LevelLog "Chrome location already set to Allow - no action needed" -Level "SUCCESS"
                    $ActionSuccess = $true
                }
                else {
                    Write-LevelLog "ACTION: Enabling $DisplayName" -Level "INFO"
                    $ActionSuccess = Enable-ChromeLocation
                    if (-not $ActionSuccess) {
                        Write-Host "Alert: Failed to enable $DisplayName"
                        Write-LevelLog "FAILED: Enable unsuccessful" -Level "ERROR"
                        $script:ExitCode = 1
                    }
                }
            }
            "Remove" {
                # Remove = Disable Chrome location (Block)
                if ($Policy.ActionSource -eq "Tag" -and $LevelApiKey) {
                    $Device = Find-LevelDevice -ApiKey $LevelApiKey -Hostname $DeviceHostname
                    if ($Device) {
                        $SetResult = Set-LevelCustomFieldValue -ApiKey $LevelApiKey -EntityType "device" -EntityId $Device.id -FieldReference $CustomFieldName -Value "remove"
                        if ($SetResult) {
                            Write-LevelLog "Set device custom field '$CustomFieldName' = 'remove'" -Level "SUCCESS"
                        }
                    }
                }

                $CurrentSetting = Get-ChromeLocationSetting
                if ($CurrentSetting -eq 2) {
                    Write-LevelLog "Chrome location already set to Block - no action needed" -Level "SUCCESS"
                    $ActionSuccess = $true
                }
                else {
                    Write-LevelLog "ACTION: Disabling $DisplayName" -Level "INFO"
                    $ActionSuccess = Disable-ChromeLocation
                    if (-not $ActionSuccess) {
                        Write-Host "Alert: Failed to disable $DisplayName"
                        Write-LevelLog "FAILED: Disable unsuccessful" -Level "ERROR"
                        $script:ExitCode = 1
                    }
                }
            }
            "Reinstall" {
                # Reinstall = Re-apply current policy
                Write-LevelLog "ACTION: Re-applying $DisplayName policy" -Level "INFO"
                if ($CustomFieldPolicy -eq "install" -or $Policy.PolicyActions -contains "Install") {
                    $ActionSuccess = Enable-ChromeLocation
                } elseif ($CustomFieldPolicy -eq "remove" -or $Policy.PolicyActions -contains "Remove") {
                    $ActionSuccess = Disable-ChromeLocation
                } else {
                    Write-LevelLog "No base policy to re-apply" -Level "INFO"
                    $ActionSuccess = $true
                }
            }
            "Pin" {
                Write-LevelLog "Pinned - no changes allowed" -Level "INFO"
                if ($LevelApiKey) {
                    $Device = Find-LevelDevice -ApiKey $LevelApiKey -Hostname $DeviceHostname
                    if ($Device) {
                        $FieldValue = if ("Remove" -in $Policy.PolicyActions) { "remove" } else { "pin" }
                        $SetResult = Set-LevelCustomFieldValue -ApiKey $LevelApiKey -EntityType "device" -EntityId $Device.id -FieldReference $CustomFieldName -Value $FieldValue
                        if ($SetResult) {
                            Write-LevelLog "Set device custom field '$CustomFieldName' = '$FieldValue'" -Level "SUCCESS"
                        }
                    }
                }
                $ActionSuccess = $true
            }
            "None" {
                $CurrentSetting = Get-ChromeLocationSetting
                if ($Policy.HasInstalled -and $CurrentSetting -ne 1) {
                    Write-LevelLog "WARNING: Status tag says enabled but Chrome location is not set to Allow" -Level "WARN"
                }
                elseif (-not $Policy.HasInstalled -and $CurrentSetting -eq 1) {
                    Write-LevelLog "INFO: Chrome location is Allow (no policy action)" -Level "INFO"
                }
                else {
                    Write-LevelLog "No action required" -Level "INFO"
                }
                $ActionSuccess = $true
            }
        }
    }

    # ============================================================
    # TAG MANAGEMENT
    # ============================================================
    if ($LevelApiKey) {
        Write-Host ""
        Write-LevelLog "Updating tags..." -Level "INFO"

        # Debug: Get device ID and tags BEFORE changes
        $DeviceForTags = $null
        $TagsBefore = @()
        if ($DebugScripts) {
            $DeviceForTags = Find-LevelDevice -ApiKey $LevelApiKey -Hostname $DeviceHostname
            if ($DeviceForTags) {
                Write-LevelLog "Device ID: $($DeviceForTags.id)" -Level "DEBUG"
                $TagsBefore = Get-LevelDeviceTagNames -ApiKey $LevelApiKey -DeviceId $DeviceForTags.id
                Write-LevelLog "Tags BEFORE: $($TagsBefore -join ', ')" -Level "DEBUG"
            }
        }

        # Check final state
        $FinalState = (Get-ChromeLocationSetting) -eq 1

        # Tag cleanup based on action and success
        if ($ActionSuccess -and $Policy.ShouldProcess) {
            switch ($Policy.ResolvedAction) {
                "Install" {
                    Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareName -EmojiPrefix "Install" -DeviceHostname $DeviceHostname
                    if ($FinalState) {
                        Add-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareName -EmojiPrefix "Has" -DeviceHostname $DeviceHostname
                    }
                }
                "Remove" {
                    Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareName -EmojiPrefix "Remove" -DeviceHostname $DeviceHostname
                    Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareName -EmojiPrefix "Has" -DeviceHostname $DeviceHostname
                }
                "Reinstall" {
                    Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareName -EmojiPrefix "Reinstall" -DeviceHostname $DeviceHostname
                    if ($FinalState) {
                        Add-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareName -EmojiPrefix "Has" -DeviceHostname $DeviceHostname
                    }
                }
                "Pin" {
                    Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareName -EmojiPrefix "Pin" -DeviceHostname $DeviceHostname
                    Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareName -EmojiPrefix "Remove" -DeviceHostname $DeviceHostname
                }
            }
        }
        elseif (-not $Policy.ShouldProcess) {
            # No policy action - reconcile Has tag with actual state
            if ($FinalState) {
                Add-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareName -EmojiPrefix "Has" -DeviceHostname $DeviceHostname
            } else {
                Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareName -EmojiPrefix "Has" -DeviceHostname $DeviceHostname
            }
        }

        # Debug: Show tags AFTER changes
        if ($DebugScripts -and $DeviceForTags) {
            $TagsAfter = Get-LevelDeviceTagNames -ApiKey $LevelApiKey -DeviceId $DeviceForTags.id
            Write-LevelLog "Tags AFTER: $($TagsAfter -join ', ')" -Level "DEBUG"
        }
    }

    Write-Host ""
    Write-LevelLog "Policy enforcement complete" -Level "INFO"

}}

Invoke-LevelScript @InvokeParams

exit $ExitCode
