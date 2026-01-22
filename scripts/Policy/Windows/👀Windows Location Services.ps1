<#
.SYNOPSIS
    Configuration policy enforcement for Windows Location Services.

.DESCRIPTION
    Implements the COOLForge 5-tag policy model for Windows Location Services management.
    See docs/POLICY-TAGS.md for the complete policy specification.

    POLICY FLOW (per POLICY-TAGS.md):
    1. Check global control tags (device must have checkmark to be managed)
    2. Check config-specific override tags (highest priority)
    3. Fall back to custom field policy (policy_device_locationservices)
    4. Execute resolved action (enable/disable)

    GLOBAL CONTROL TAGS (standalone):
    - U+2705 = Device is managed (required to process)
    - U+274C = Device is excluded from management
    - Both = Device is globally pinned (no changes)

    CONFIG-SPECIFIC OVERRIDE TAGS (with "LOCATIONSERVICES" suffix):
    - U+1F64F LOCATIONSERVICES = Enable location services (transient)
    - U+1F6AB LOCATIONSERVICES = Disable location services (transient)
    - U+1F4CC LOCATIONSERVICES = Pin - no changes allowed (persistent)
    - U+1F504 LOCATIONSERVICES = Re-apply current policy (transient)
    - U+2705 LOCATIONSERVICES  = Status: location is enabled (set by script)

    CUSTOM FIELD POLICY (inherited Group->Folder->Device):
    - policy_device_locationservices = "install" | "remove" | "pin" | ""
      (install = enable, remove = disable)

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

# Configuration Policy - Windows Location Services
# Version: 2026.01.20.01
# Target: Level.io (via Script Launcher)
# Exit 0 = Success | Exit 1 = Alert (Failure)
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge

# ============================================================
# DEBUG OUTPUT HELPER
# ============================================================

function Write-DebugLocationCheck {
    param([bool]$IsEnabled)
    if (-not $DebugScripts) { return }

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " DEBUG: Location Services Check" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    # Check Windows policy
    $winPolicyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'
    $disableLocation = (Get-ItemProperty -Path $winPolicyKey -Name 'DisableLocation' -ErrorAction SilentlyContinue).DisableLocation

    Write-Host "  --- Windows Policy ---"
    Write-Host "  DisableLocation: $(if ($null -eq $disableLocation) { 'Not Set' } else { $disableLocation })" -ForegroundColor $(if ($disableLocation -eq 0) { 'Green' } elseif ($disableLocation -eq 1) { 'Yellow' } else { 'DarkGray' })

    # Check ConsentStore
    $capabilityKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'
    if (Test-Path $capabilityKey) {
        $consentValue = (Get-ItemProperty -Path $capabilityKey -Name 'Value' -ErrorAction SilentlyContinue).Value
        Write-Host "  ConsentStore: $consentValue" -ForegroundColor $(if ($consentValue -eq 'Allow') { 'Green' } else { 'Yellow' })
    } else {
        Write-Host "  ConsentStore: N/A (key not present)" -ForegroundColor DarkGray
    }

    # Check service
    Write-Host ""
    Write-Host "  --- Geolocation Service (lfsvc) ---"
    try {
        $svc = Get-Service -Name 'lfsvc' -ErrorAction Stop
        Write-Host "  Status: $($svc.Status)" -ForegroundColor $(if ($svc.Status -eq 'Running') { 'Green' } else { 'Yellow' })
        Write-Host "  StartType: $($svc.StartType)" -ForegroundColor $(if ($svc.StartType -ne 'Disabled') { 'Green' } else { 'Yellow' })
    } catch {
        Write-Host "  Service not found" -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "  LOCATION ENABLED: $(if ($IsEnabled) { 'YES' } else { 'NO' })" -ForegroundColor $(if ($IsEnabled) { 'Green' } else { 'Yellow' })
}

# ============================================================
# CONFIGURATION
# ============================================================
$SoftwareName = "LOCATIONSERVICES"
$DisplayName = "Windows Location Services"
$CustomFieldName = "policy_device_locationservices"

# ============================================================
# INITIALIZE
# ============================================================
$Init = Initialize-LevelScript -ScriptName "Policy-Device-LocationServices" `
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

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        $val = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
        return $val
    } catch {
        return $null
    }
}

# ============================================================
# COMPREHENSIVE LOCATION DIAGNOSTIC
# ============================================================

function Get-LocationDiagnostic {
    $issues = @()

    # 1. Check for empty/blocking policy keys
    $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'
    if (Test-Path $policyPath) {
        $props = Get-ItemProperty -Path $policyPath -ErrorAction SilentlyContinue
        $propNames = $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | Select-Object -ExpandProperty Name

        if ($propNames.Count -eq 0) {
            $issues += @{ Type = 'EmptyPolicyKey'; Path = $policyPath; Current = 'Empty key exists'; Fix = 'Delete key' }
        } else {
            $disableLoc = Get-RegValue $policyPath 'DisableLocation'
            $disableSensors = Get-RegValue $policyPath 'DisableSensors'
            $disableScripting = Get-RegValue $policyPath 'DisableLocationScripting'

            if ($null -ne $disableLoc) {
                if ($disableLoc -eq 1) {
                    $issues += @{ Type = 'PolicyBlock'; Path = $policyPath; Name = 'DisableLocation'; Current = 1; Fix = 'Delete value' }
                } else {
                    $issues += @{ Type = 'PolicyExists'; Path = $policyPath; Name = 'DisableLocation'; Current = $disableLoc; Fix = 'Delete value (causes managed banner)' }
                }
            }
            if ($null -ne $disableSensors) {
                $issues += @{ Type = 'PolicyBlock'; Path = $policyPath; Name = 'DisableSensors'; Current = $disableSensors; Fix = 'Delete value' }
            }
            if ($null -ne $disableScripting) {
                $issues += @{ Type = 'PolicyBlock'; Path = $policyPath; Name = 'DisableLocationScripting'; Current = $disableScripting; Fix = 'Delete value' }
            }
        }
    }

    # 2. Check AppPrivacy policy
    $appPrivacyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
    if (Test-Path $appPrivacyPath) {
        $letApps = Get-RegValue $appPrivacyPath 'LetAppsAccessLocation'
        if ($letApps -eq 2) {
            $issues += @{ Type = 'PolicyBlock'; Path = $appPrivacyPath; Name = 'LetAppsAccessLocation'; Current = 2; Fix = 'Delete value (ForceDeny)' }
        } elseif ($null -ne $letApps) {
            $issues += @{ Type = 'PolicyExists'; Path = $appPrivacyPath; Name = 'LetAppsAccessLocation'; Current = $letApps; Fix = 'Delete value' }
        }
    }

    # 3. Check MDM policies (can't fix, just report)
    $mdmSystemPath = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System'
    $mdmPrivacyPath = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Privacy'

    if (Test-Path $mdmSystemPath) {
        $mdmAllow = Get-RegValue $mdmSystemPath 'AllowLocation'
        if ($null -ne $mdmAllow -and $mdmAllow -eq 0) {
            $issues += @{ Type = 'MDMBlock'; Path = $mdmSystemPath; Name = 'AllowLocation'; Current = 0; Fix = 'Fix in Intune/MDM console' }
        }
    }
    if (Test-Path $mdmPrivacyPath) {
        $mdmLetApps = Get-RegValue $mdmPrivacyPath 'LetAppsAccessLocation'
        if ($null -ne $mdmLetApps -and $mdmLetApps -eq 2) {
            $issues += @{ Type = 'MDMBlock'; Path = $mdmPrivacyPath; Name = 'LetAppsAccessLocation'; Current = 2; Fix = 'Fix in Intune/MDM console' }
        }
    }

    # 4. Check Master Switch
    $masterPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration'
    $masterStatus = Get-RegValue $masterPath 'Status'
    if ($masterStatus -ne 1) {
        $issues += @{ Type = 'MasterSwitch'; Path = $masterPath; Name = 'Status'; Current = $masterStatus; Fix = 'Set to 1' }
    }

    # 5. Check Device Consent (HKLM)
    $hklmConsentPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'
    $hklmConsent = Get-RegValue $hklmConsentPath 'Value'
    if ($hklmConsent -ne 'Allow') {
        $issues += @{ Type = 'DeviceConsent'; Path = $hklmConsentPath; Name = 'Value'; Current = $hklmConsent; Fix = 'Set to Allow' }
    }

    # 6. Check Sensor Permission State
    $sensorPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}'
    $sensorState = Get-RegValue $sensorPath 'SensorPermissionState'
    if ($sensorState -ne 1) {
        $issues += @{ Type = 'SensorPermission'; Path = $sensorPath; Name = 'SensorPermissionState'; Current = $sensorState; Fix = 'Set to 1' }
    }

    # 7. Check User Consent (all loaded user hives)
    $userSIDs = @()
    try {
        $userSIDs = Get-ChildItem -Path 'Registry::HKU' -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$' } |
            Select-Object -ExpandProperty PSChildName
    } catch {}

    foreach ($sid in $userSIDs) {
        $hkuPath = "Registry::HKU\$sid\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
        $userConsent = Get-RegValue $hkuPath 'Value'
        if ($userConsent -ne 'Allow') {
            $issues += @{ Type = 'UserConsent'; Path = $hkuPath; Name = 'Value'; Current = $userConsent; SID = $sid; Fix = 'Set to Allow' }
        }
    }

    # 7b. Check OFFLINE user profiles (not currently logged in)
    $profileListPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    $allProfileSIDs = @()
    try {
        $allProfileSIDs = Get-ChildItem -Path $profileListPath -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -match '^S-1-5-21-' } |
            Select-Object -ExpandProperty PSChildName
    } catch {}

    $offlineSIDs = $allProfileSIDs | Where-Object { $_ -notin $userSIDs }

    foreach ($sid in $offlineSIDs) {
        $profilePath = Get-RegValue "$profileListPath\$sid" 'ProfileImagePath'
        if ($profilePath -and (Test-Path "$profilePath\NTUSER.DAT")) {
            $issues += @{
                Type = 'OfflineUserConsent'
                SID = $sid
                ProfilePath = $profilePath
                NTUserPath = "$profilePath\NTUSER.DAT"
                Fix = 'Load hive and set to Allow'
            }
        }
    }

    # 8. Check lfsvc service
    try {
        $svc = Get-Service -Name lfsvc -ErrorAction Stop
        if ($svc.StartType -eq 'Disabled') {
            $issues += @{ Type = 'ServiceDisabled'; Service = 'lfsvc'; Current = $svc.StartType; Fix = 'Set to Manual' }
        }
    } catch {
        $issues += @{ Type = 'ServiceMissing'; Service = 'lfsvc'; Current = 'Not found'; Fix = 'Reinstall Windows component' }
    }

    return $issues
}

# ============================================================
# COMPREHENSIVE FIX FUNCTION
# ============================================================

function Invoke-LocationFix {
    param([array]$Issues)

    $fixed = @()
    $failed = @()
    $skipped = @()

    foreach ($issue in $Issues) {
        $action = $null

        switch ($issue.Type) {
            'EmptyPolicyKey' {
                $action = "Delete empty policy key: $($issue.Path)"
                try {
                    Remove-Item -Path $issue.Path -Force -Recurse -ErrorAction Stop
                    $fixed += $action
                    Write-LevelLog "  $action" -Level "SUCCESS"
                } catch {
                    $failed += "$action - Error: $_"
                    Write-LevelLog "  $action - Error: $_" -Level "WARN"
                }
            }

            'PolicyBlock' {
                $action = "Delete blocking policy value: $($issue.Path)\$($issue.Name)"
                try {
                    Remove-ItemProperty -Path $issue.Path -Name $issue.Name -Force -ErrorAction Stop
                    $fixed += $action
                    Write-LevelLog "  $action" -Level "SUCCESS"

                    # Check if key is now empty and delete it
                    $remaining = Get-ItemProperty -Path $issue.Path -ErrorAction SilentlyContinue
                    $propNames = $remaining.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }
                    if ($propNames.Count -eq 0) {
                        Remove-Item -Path $issue.Path -Force -ErrorAction SilentlyContinue
                        $fixed += "Deleted now-empty key: $($issue.Path)"
                        Write-LevelLog "  Deleted now-empty key: $($issue.Path)" -Level "SUCCESS"
                    }
                } catch {
                    $failed += "$action - Error: $_"
                    Write-LevelLog "  $action - Error: $_" -Level "WARN"
                }
            }

            'PolicyExists' {
                $action = "Delete policy value (causes managed banner): $($issue.Path)\$($issue.Name)"
                try {
                    Remove-ItemProperty -Path $issue.Path -Name $issue.Name -Force -ErrorAction Stop
                    $fixed += $action
                    Write-LevelLog "  $action" -Level "SUCCESS"

                    # Check if key is now empty and delete it
                    $remaining = Get-ItemProperty -Path $issue.Path -ErrorAction SilentlyContinue
                    $propNames = $remaining.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }
                    if ($propNames.Count -eq 0) {
                        Remove-Item -Path $issue.Path -Force -ErrorAction SilentlyContinue
                        $fixed += "Deleted now-empty key: $($issue.Path)"
                        Write-LevelLog "  Deleted now-empty key: $($issue.Path)" -Level "SUCCESS"
                    }
                } catch {
                    $failed += "$action - Error: $_"
                    Write-LevelLog "  $action - Error: $_" -Level "WARN"
                }
            }

            'MDMBlock' {
                $action = "MDM policy blocking - must fix in Intune/MDM console: $($issue.Name)=$($issue.Current)"
                $skipped += $action
                Write-LevelLog "  $action" -Level "WARN"
            }

            'MasterSwitch' {
                $action = "Set master switch ON: Status = 1"
                try {
                    if (!(Test-Path $issue.Path)) {
                        New-Item -Path $issue.Path -Force | Out-Null
                    }
                    Set-ItemProperty -Path $issue.Path -Name 'Status' -Value 1 -Type DWord -Force -ErrorAction Stop
                    $fixed += $action
                    Write-LevelLog "  $action" -Level "SUCCESS"
                } catch {
                    $failed += "$action - Error: $_"
                    Write-LevelLog "  $action - Error: $_" -Level "WARN"
                }
            }

            'DeviceConsent' {
                $action = "Set device consent: Value = Allow"
                try {
                    if (!(Test-Path $issue.Path)) {
                        New-Item -Path $issue.Path -Force | Out-Null
                    }
                    Set-ItemProperty -Path $issue.Path -Name 'Value' -Value 'Allow' -Type String -Force -ErrorAction Stop
                    $fixed += $action
                    Write-LevelLog "  $action" -Level "SUCCESS"
                } catch {
                    $failed += "$action - Error: $_"
                    Write-LevelLog "  $action - Error: $_" -Level "WARN"
                }
            }

            'SensorPermission' {
                $action = "Set sensor permission: SensorPermissionState = 1"
                try {
                    if (!(Test-Path $issue.Path)) {
                        New-Item -Path $issue.Path -Force | Out-Null
                    }
                    Set-ItemProperty -Path $issue.Path -Name 'SensorPermissionState' -Value 1 -Type DWord -Force -ErrorAction Stop
                    $fixed += $action
                    Write-LevelLog "  $action" -Level "SUCCESS"
                } catch {
                    $failed += "$action - Error: $_"
                    Write-LevelLog "  $action - Error: $_" -Level "WARN"
                }
            }

            'UserConsent' {
                $action = "Set user consent for $($issue.SID): Value = Allow"
                try {
                    if (!(Test-Path $issue.Path)) {
                        New-Item -Path $issue.Path -Force | Out-Null
                    }
                    Set-ItemProperty -Path $issue.Path -Name 'Value' -Value 'Allow' -Type String -Force -ErrorAction Stop
                    $fixed += $action
                    Write-LevelLog "  $action" -Level "SUCCESS"
                } catch {
                    $failed += "$action - Error: $_"
                    Write-LevelLog "  $action - Error: $_" -Level "WARN"
                }
            }

            'OfflineUserConsent' {
                $userName = $issue.SID
                try {
                    $sidObj = New-Object System.Security.Principal.SecurityIdentifier($issue.SID)
                    $account = $sidObj.Translate([System.Security.Principal.NTAccount])
                    $userName = $account.Value
                } catch {}

                $action = "Fix offline user consent for $userName"
                $tempHive = "HKU\TempHive_$([guid]::NewGuid().ToString('N').Substring(0,8))"
                try {
                    $regLoadResult = & reg.exe load $tempHive $issue.NTUserPath 2>&1
                    if ($LASTEXITCODE -ne 0) {
                        throw "reg load failed: $regLoadResult"
                    }

                    $consentPath = "Registry::$tempHive\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
                    $currentConsent = $null
                    if (Test-Path $consentPath) {
                        $currentConsent = (Get-ItemProperty -Path $consentPath -Name 'Value' -ErrorAction SilentlyContinue).Value
                    }

                    if ($currentConsent -eq 'Allow') {
                        $skipped += "$userName already has consent=Allow"
                        Write-LevelLog "  $userName already has consent=Allow" -Level "INFO"
                    } else {
                        $parentPath = "Registry::$tempHive\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
                        if (!(Test-Path $parentPath)) {
                            New-Item -Path $parentPath -Force | Out-Null
                        }
                        if (!(Test-Path $consentPath)) {
                            New-Item -Path $consentPath -Force | Out-Null
                        }
                        Set-ItemProperty -Path $consentPath -Name 'Value' -Value 'Allow' -Type String -Force -ErrorAction Stop
                        $fixed += "Set consent=Allow for $userName (was: $currentConsent)"
                        Write-LevelLog "  Set consent=Allow for $userName (was: $currentConsent)" -Level "SUCCESS"
                    }

                    [gc]::Collect()
                    Start-Sleep -Milliseconds 500
                    & reg.exe unload $tempHive 2>&1 | Out-Null
                    if ($LASTEXITCODE -ne 0) {
                        Start-Sleep -Seconds 2
                        [gc]::Collect()
                        & reg.exe unload $tempHive 2>&1 | Out-Null
                    }
                } catch {
                    try { & reg.exe unload $tempHive 2>&1 | Out-Null } catch {}
                    $failed += "$action - Error: $_"
                    Write-LevelLog "  $action - Error: $_" -Level "WARN"
                }
            }

            'ServiceDisabled' {
                $action = "Enable lfsvc service (set to Manual)"
                try {
                    Set-Service -Name lfsvc -StartupType Manual -ErrorAction Stop
                    $fixed += $action
                    Write-LevelLog "  $action" -Level "SUCCESS"
                } catch {
                    $failed += "$action - Error: $_"
                    Write-LevelLog "  $action - Error: $_" -Level "WARN"
                }
            }

            'ServiceMissing' {
                $action = "lfsvc service missing - cannot fix automatically"
                $skipped += $action
                Write-LevelLog "  $action" -Level "WARN"
            }
        }
    }

    return @{
        Fixed = $fixed
        Failed = $failed
        Skipped = $skipped
    }
}

# ============================================================
# TOGGLE CYCLE (emulates admin clicking location toggle OFF then ON)
# ============================================================

function Invoke-LocationToggleCycle {
    Write-LevelLog "Emulating admin toggle cycle (OFF -> ON)..."

    $masterPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration'
    $deviceConsentPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'
    $sensorPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}'

    try {
        # PHASE A: Toggle OFF (briefly)
        Write-LevelLog "  Setting location OFF..."
        if (Test-Path $masterPath) {
            Set-ItemProperty -Path $masterPath -Name 'Status' -Value 0 -Type DWord -Force -ErrorAction Stop
        }
        if (Test-Path $deviceConsentPath) {
            Set-ItemProperty -Path $deviceConsentPath -Name 'Value' -Value 'Deny' -Type String -Force -ErrorAction Stop
        }
        $svc = Get-Service -Name lfsvc -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') {
            Stop-Service -Name lfsvc -Force -ErrorAction SilentlyContinue
        }
        Start-Sleep -Milliseconds 500

        # PHASE B: Toggle ON
        Write-LevelLog "  Setting location ON..."
        if (!(Test-Path $masterPath)) {
            New-Item -Path $masterPath -Force | Out-Null
        }
        Set-ItemProperty -Path $masterPath -Name 'Status' -Value 1 -Type DWord -Force -ErrorAction Stop
        if (!(Test-Path $deviceConsentPath)) {
            New-Item -Path $deviceConsentPath -Force | Out-Null
        }
        Set-ItemProperty -Path $deviceConsentPath -Name 'Value' -Value 'Allow' -Type String -Force -ErrorAction Stop
        if (!(Test-Path $sensorPath)) {
            New-Item -Path $sensorPath -Force | Out-Null
        }
        Set-ItemProperty -Path $sensorPath -Name 'SensorPermissionState' -Value 1 -Type DWord -Force -ErrorAction Stop

        Set-Service -Name lfsvc -StartupType Manual -ErrorAction SilentlyContinue
        Start-Service -Name lfsvc -ErrorAction SilentlyContinue

        Write-LevelLog "  Toggle cycle complete" -Level "SUCCESS"
        return $true
    } catch {
        Write-LevelLog "  Toggle cycle failed: $_" -Level "WARN"
        return $false
    }
}

# ============================================================
# LOCATION SERVICES DETECTION
# ============================================================

function Test-LocationServicesEnabled {
    # Check Windows policy - DisableLocation = 0 means enabled
    $winPolicyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'
    $disableLocation = (Get-ItemProperty -Path $winPolicyKey -Name 'DisableLocation' -ErrorAction SilentlyContinue).DisableLocation

    # If DisableLocation is 1, location is disabled
    if ($disableLocation -eq 1) {
        return $false
    }

    # Check if service exists and is not disabled
    try {
        $svc = Get-Service -Name 'lfsvc' -ErrorAction Stop
        if ($svc.StartType -eq 'Disabled') {
            return $false
        }
    } catch {
        # Service doesn't exist - can't determine
        return $false
    }

    # If we get here, location is enabled (or at least not explicitly disabled)
    return $true
}

# ============================================================
# ENABLE/DISABLE FUNCTIONS
# ============================================================

function Enable-LocationServices {
    Write-LevelLog "Enabling Windows Location Services (comprehensive fix)..."

    # Run comprehensive diagnostic
    $issues = Get-LocationDiagnostic

    if ($issues.Count -eq 0) {
        Write-LevelLog "No issues found - location services already properly configured" -Level "SUCCESS"
        return $true
    }

    # Report what we found
    $mdmIssues = $issues | Where-Object { $_.Type -match 'MDM' }
    $fixableIssues = $issues | Where-Object { $_.Type -notmatch 'MDM' }

    Write-LevelLog "Found $($issues.Count) issue(s) ($($fixableIssues.Count) fixable, $($mdmIssues.Count) MDM)"

    if ($mdmIssues.Count -gt 0) {
        Write-LevelLog "WARNING: MDM/Intune policies detected - these cannot be fixed locally" -Level "WARN"
        foreach ($mdm in $mdmIssues) {
            Write-LevelLog "  MDM: $($mdm.Name) = $($mdm.Current)" -Level "WARN"
        }
    }

    # Apply fixes for all fixable issues
    if ($fixableIssues.Count -gt 0) {
        Write-LevelLog "Applying fixes..."
        $results = Invoke-LocationFix -Issues $issues

        Write-LevelLog "Fixed: $($results.Fixed.Count), Failed: $($results.Failed.Count), Skipped: $($results.Skipped.Count)"
    }

    # Run toggle cycle to reset cached state
    Invoke-LocationToggleCycle | Out-Null

    # Verify fixes
    $afterIssues = Get-LocationDiagnostic
    $remainingFixable = $afterIssues | Where-Object { $_.Type -notmatch 'MDM' }

    if ($remainingFixable.Count -eq 0) {
        Write-LevelLog "Windows Location Services ENABLED" -Level "SUCCESS"
        return $true
    } else {
        Write-LevelLog "Some issues remain after fix attempt" -Level "WARN"
        foreach ($issue in $remainingFixable) {
            Write-LevelLog "  Remaining: $($issue.Type) - $($issue.Name)" -Level "WARN"
        }
        return $false
    }
}

function Disable-LocationServices {
    Write-LevelLog "Disabling Windows Location Services..."

    # Windows OS policy keys to disable Location
    $winPolicyKeys = @(
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors',
        'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\LocationAndSensors'
    )

    # Set DisableLocation = 1 (disabled)
    foreach ($key in $winPolicyKeys) {
        $changed = Set-RegistryValue -Path $key -Name 'DisableLocation' -Type DWord -Value 1
        Write-LevelLog "  Policy [$key]: $(if ($changed) { 'Updated' } else { 'Already set' })"
    }

    # ConsentStore (modern Windows builds)
    $capabilityKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'
    try {
        if (Test-Path $capabilityKey) {
            $changed = Set-RegistryValue -Path $capabilityKey -Name 'Value' -Type String -Value 'Deny'
            Write-LevelLog "  ConsentStore: $(if ($changed) { 'Set to Deny' } else { 'Already Deny' })"
        } else {
            Write-LevelLog "  ConsentStore: Key not present (older Windows build)" -Level "INFO"
        }
    } catch {
        Write-LevelLog "  ConsentStore error: $($_.Exception.Message)" -Level "WARN"
    }

    # Geolocation Service (lfsvc) - Stop and Disable
    try {
        $svc = Get-Service -Name 'lfsvc' -ErrorAction Stop

        if ($svc.Status -eq 'Running') {
            Stop-Service -Name 'lfsvc' -Force -ErrorAction Stop
            Write-LevelLog "  Service status: Stopped"
        } else {
            Write-LevelLog "  Service status: Already stopped"
        }

        Set-Service -Name 'lfsvc' -StartupType Disabled -ErrorAction Stop
        Write-LevelLog "  Service startup: Set to Disabled"
    } catch {
        Write-LevelLog "  Service error: $($_.Exception.Message)" -Level "WARN"
        return $false
    }

    Write-LevelLog "Windows Location Services DISABLED" -Level "SUCCESS"
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

    # Get custom field policy if available (passed from launcher)
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
            -DefaultPolicyValue "pin | uses pin/install/remove (install=enable, remove=disable)" `
            -PolicyFieldValue $PolicyFieldValue

        if ($InfraResult.Success) {
            if ($InfraResult.TagsCreated -gt 0 -or $InfraResult.FieldsCreated -gt 0) {
                Write-LevelLog "Created $($InfraResult.TagsCreated) tags, $($InfraResult.FieldsCreated) fields" -Level "SUCCESS"
                Write-Host ""
                Write-Host "Alert: Policy infrastructure created - configure to activate"
                Write-Host "  Field: $CustomFieldName"
                Write-Host "  Default: 'pin' (no changes until configured)"
                Write-Host "  Set to 'install' to enable location services"
                Write-Host "  Set to 'remove' to disable location services"
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
    $IsEnabled = Test-LocationServicesEnabled
    Write-LevelLog "Current state: $(if ($IsEnabled) { 'Enabled' } else { 'Disabled' })"

    # Debug: Show check details
    Write-DebugLocationCheck -IsEnabled $IsEnabled

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
                # Install = Enable location services
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
                    Write-LevelLog "Already enabled - no action needed" -Level "SUCCESS"
                    $ActionSuccess = $true
                }
                else {
                    Write-LevelLog "ACTION: Enabling $DisplayName" -Level "INFO"
                    $ActionSuccess = Enable-LocationServices
                    if (-not $ActionSuccess) {
                        Write-Host "Alert: Failed to enable $DisplayName"
                        Write-LevelLog "FAILED: Enable unsuccessful" -Level "ERROR"
                        $script:ExitCode = 1
                    }
                }
            }
            "Remove" {
                # Remove = Disable location services
                if ($Policy.ActionSource -eq "Tag" -and $LevelApiKey) {
                    $Device = Find-LevelDevice -ApiKey $LevelApiKey -Hostname $DeviceHostname
                    if ($Device) {
                        $SetResult = Set-LevelCustomFieldValue -ApiKey $LevelApiKey -EntityType "device" -EntityId $Device.id -FieldReference $CustomFieldName -Value "remove"
                        if ($SetResult) {
                            Write-LevelLog "Set device custom field '$CustomFieldName' = 'remove'" -Level "SUCCESS"
                        }
                    }
                }

                if (-not $IsEnabled) {
                    Write-LevelLog "Already disabled - no action needed" -Level "SUCCESS"
                    $ActionSuccess = $true
                }
                else {
                    Write-LevelLog "ACTION: Disabling $DisplayName" -Level "INFO"
                    $ActionSuccess = Disable-LocationServices
                    if (-not $ActionSuccess) {
                        Write-Host "Alert: Failed to disable $DisplayName"
                        Write-LevelLog "FAILED: Disable unsuccessful" -Level "ERROR"
                        $script:ExitCode = 1
                    }
                }
            }
            "Reinstall" {
                # Reinstall = Re-apply current policy (enable if install policy, else no-op)
                Write-LevelLog "ACTION: Re-applying $DisplayName policy" -Level "INFO"
                if ($CustomFieldPolicy -eq "install" -or $Policy.PolicyActions -contains "Install") {
                    $ActionSuccess = Enable-LocationServices
                } elseif ($CustomFieldPolicy -eq "remove" -or $Policy.PolicyActions -contains "Remove") {
                    $ActionSuccess = Disable-LocationServices
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
                if ($Policy.HasInstalled -and -not $IsEnabled) {
                    Write-LevelLog "WARNING: Status tag says enabled but location is disabled" -Level "WARN"
                }
                elseif (-not $Policy.HasInstalled -and $IsEnabled) {
                    Write-LevelLog "INFO: Location is enabled (no policy action)" -Level "INFO"
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
        $FinalState = Test-LocationServicesEnabled

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
