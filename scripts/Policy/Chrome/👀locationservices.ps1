<#
.SYNOPSIS
    Configuration policy enforcement for Chrome Location Services.

.DESCRIPTION
    Implements the COOLForge 5-tag policy model for Chrome geolocation policy management.
    See docs/POLICY-TAGS.md for the complete policy specification.

    This script manages Chrome's DefaultGeolocationSetting policy:
    - 1 = Allow sites to ask for location
    - 2 = Block all sites from requesting location

    IMPORTANT: When enabling Chrome location (install), this script will also
    enable Windows Location Services if they are disabled, since Chrome requires
    OS-level location access to function.

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
    Version:          2026.01.19.01
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

# Configuration Policy - Chrome Location Services
# Version: 2026.01.19.01
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
    Write-Host " DEBUG: Chrome Location Policy Check" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    $chromePolicyKey = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
    $setting = (Get-ItemProperty -Path $chromePolicyKey -Name 'DefaultGeolocationSetting' -ErrorAction SilentlyContinue).DefaultGeolocationSetting

    Write-Host "  --- Chrome Policy ---"
    Write-Host "  Registry Path: $chromePolicyKey"
    $settingText = switch ($setting) {
        1 { 'Allow (1) - Sites can ask for location' }
        2 { 'Block (2) - Sites cannot request location' }
        3 { 'Ask (3) - Default browser behavior' }
        default { 'Not Set - Using browser default' }
    }
    Write-Host "  DefaultGeolocationSetting: $settingText" -ForegroundColor $(if ($setting -eq 1) { 'Green' } elseif ($setting -eq 2) { 'Yellow' } else { 'DarkGray' })

    # Also check device location status
    Write-Host ""
    Write-Host "  --- Device Location Status ---"
    $winPolicyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'
    $disableLocation = (Get-ItemProperty -Path $winPolicyKey -Name 'DisableLocation' -ErrorAction SilentlyContinue).DisableLocation
    $deviceEnabled = ($disableLocation -ne 1)
    Write-Host "  Windows Location: $(if ($deviceEnabled) { 'Enabled' } else { 'Disabled' })" -ForegroundColor $(if ($deviceEnabled) { 'Green' } else { 'Yellow' })

    Write-Host ""
    Write-Host "  CHROME LOCATION ENABLED: $(if ($CurrentSetting -eq 1) { 'YES (Allow)' } elseif ($CurrentSetting -eq 2) { 'NO (Block)' } else { 'DEFAULT' })" -ForegroundColor $(if ($CurrentSetting -eq 1) { 'Green' } else { 'Yellow' })
}

# ============================================================
# CONFIGURATION
# ============================================================
$SoftwareName = "CHROME_LOCATIONSERVICES"
$DisplayName = "Chrome Location Services"
$CustomFieldName = "policy_chrome_locationservices"

# Chrome policy registry
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
    Write-LevelLog "Enabling Windows Location Services (required for Chrome)..."

    # Windows OS policy keys
    $winPolicyKeys = @(
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors',
        'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\LocationAndSensors'
    )

    foreach ($key in $winPolicyKeys) {
        $changed = Set-RegistryValue -Path $key -Name 'DisableLocation' -Type DWord -Value 0
        Write-LevelLog "  Windows Policy [$key]: $(if ($changed) { 'Enabled' } else { 'Already enabled' })"
    }

    # ConsentStore
    $capabilityKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'
    try {
        if (Test-Path $capabilityKey) {
            $changed = Set-RegistryValue -Path $capabilityKey -Name 'Value' -Type String -Value 'Allow'
            Write-LevelLog "  ConsentStore: $(if ($changed) { 'Set to Allow' } else { 'Already Allow' })"
        }
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
    Write-LevelLog "Enabling Chrome geolocation policy..."

    # First, ensure device location is enabled
    if (-not (Test-DeviceLocationEnabled)) {
        Write-LevelLog "Device location is disabled - enabling it first..."
        Enable-DeviceLocationServices
    }

    # Set Chrome policy: DefaultGeolocationSetting = 1 (Allow/Ask)
    $changed = Set-RegistryValue -Path $ChromePolicyKey -Name $ChromePolicyName -Type DWord -Value 1
    Write-LevelLog "  Chrome DefaultGeolocationSetting: $(if ($changed) { 'Set to 1 (Allow)' } else { 'Already 1 (Allow)' })"

    Write-LevelLog "Chrome Location Services ENABLED" -Level "SUCCESS"
    Write-LevelLog "Note: Users may need to restart Chrome to pick up policy changes"
    return $true
}

function Disable-ChromeLocation {
    Write-LevelLog "Disabling Chrome geolocation policy..."

    # Set Chrome policy: DefaultGeolocationSetting = 2 (Block)
    $changed = Set-RegistryValue -Path $ChromePolicyKey -Name $ChromePolicyName -Type DWord -Value 2
    Write-LevelLog "  Chrome DefaultGeolocationSetting: $(if ($changed) { 'Set to 2 (Block)' } else { 'Already 2 (Block)' })"

    # Note: We do NOT disable device location here, as other apps may need it
    Write-LevelLog "Chrome Location Services DISABLED" -Level "SUCCESS"
    Write-LevelLog "Note: Device location services left unchanged (other apps may need it)"
    return $true
}

# ============================================================
# MAIN SCRIPT LOGIC
# ============================================================
$ScriptVersion = "2026.01.19.01"
$ExitCode = 0

$InvokeParams = @{ ScriptBlock = {

    Write-LevelLog "Policy Enforcement: $DisplayName (v$ScriptVersion)"

    # Debug header
    if ($DebugScripts) {
        Write-Host ""
        Write-Host "============================================================" -ForegroundColor Magenta
        Write-Host " DEBUG MODE ENABLED (cf_debug_scripts = true)" -ForegroundColor Magenta
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

        $InfraResult = Initialize-SoftwarePolicyInfrastructure -ApiKey $LevelApiKey `
            -SoftwareName $SoftwareName `
            -RequireUrl $false `
            -CustomFieldName $CustomFieldName `
            -DefaultPolicyValue "pin | uses pin/install/remove (install=allow, remove=block)"

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
