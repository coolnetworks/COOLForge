<#
COOLNETWORKS - Fix Windows Location Services (Comprehensive)

Purpose:
  - Diagnoses all possible blockers for Windows Location Services
  - Applies fixes for each blocker found
  - Verifies fixes were successful
  - Reports what was changed

Parameters:
  -WhatIf           Preview changes without applying
  -ShowDiagnostics  Show verbose diagnostic output (GPO, MDM, Azure AD, etc.)

  When run via Level.io, $DebugScripts (from cf_debug_scripts) also enables
  verbose diagnostics.

Root Causes Handled:
  1. Empty policy keys (cause "managed by admin" even without values)
  2. Policy keys with blocking values (DisableLocation=1, etc.)
  3. Master switch off (lfsvc Status)
  4. Device consent not set (HKLM ConsentStore)
  5. Sensor permission state
  6. User consent not set (HKU/HKCU ConsentStore)
  7. lfsvc service disabled/stopped

Note: MDM/Intune policies cannot be fixed locally - script will report these

Standalone Usage:
  .\Fix Windows Location Services.ps1                    # Fix with minimal output
  .\Fix Windows Location Services.ps1 -ShowDiagnostics   # Fix with verbose diagnostics
  .\Fix Windows Location Services.ps1 -WhatIf            # Preview only
#>

param(
    [switch]$WhatIf,          # Show what would be changed without making changes
    [switch]$ShowDiagnostics  # Show verbose diagnostic output (like Check script)
)

$ErrorActionPreference = 'SilentlyContinue'

# Debug mode: enabled by parameter OR by Level.io custom field ($DebugScripts)
$ShowDebug = $ShowDiagnostics -or $DebugScripts

# Check for admin/SYSTEM rights
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$isSystem = $currentUser.IsSystem -or ($currentUser.User.Value -eq 'S-1-5-18')
$isAdmin = $isSystem -or ([Security.Principal.WindowsPrincipal]$currentUser).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[Alert] This script requires Administrator or SYSTEM privileges" -ForegroundColor Red
    exit 1
}

# Verbose diagnostic output function (from Check script)
function LogStep {
    param([string]$Message, [string]$Level = 'INFO')
    if (-not $ShowDebug) { return }
    $ts = (Get-Date).ToString('HH:mm:ss')
    $color = switch ($Level.ToUpper()) {
        'INFO'   { 'Gray' }
        'OK'     { 'Green' }
        'WARN'   { 'Yellow' }
        'FAIL'   { 'Yellow' }
        'HEADER' { 'Cyan' }
        default  { 'Gray' }
    }
    Write-Host ("[{0}] {1}" -f $ts, $Message) -ForegroundColor $color
}

function IfNull {
    param($Value, $Default)
    if ($null -eq $Value) { $Default } else { $Value }
}

function Write-Status {
    param([string]$Message, [string]$Level = 'INFO')
    $color = switch ($Level) {
        'OK'      { 'Green' }
        'FIXED'   { 'Green' }
        'FAIL'    { 'Red' }
        'WARN'    { 'Yellow' }
        'INFO'    { 'Gray' }
        'CHECK'   { 'Cyan' }
        'HEADER'  { 'Cyan' }
        default   { 'Gray' }
    }
    $prefix = switch ($Level) {
        'OK'      { '[OK]' }
        'FIXED'   { '[FIXED]' }
        'FAIL'    { '[FAIL]' }
        'WARN'    { '[WARN]' }
        'INFO'    { '[.]' }
        'CHECK'   { '[?]' }
        'HEADER'  { '===' }
        default   { '[.]' }
    }
    Write-Host "$prefix $Message" -ForegroundColor $color
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

# Emulates what happens when admin clicks location toggle OFF then ON in Settings UI
function Invoke-LocationToggleCycle {
    Write-Status "Emulating admin toggle cycle (OFF -> ON)..." 'INFO'

    $masterPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration'
    $deviceConsentPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'
    $sensorPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}'

    try {
        # PHASE A: Toggle OFF (briefly)
        Write-Status "  Setting location OFF..." 'INFO'

        # Master switch OFF
        if (Test-Path $masterPath) {
            Set-ItemProperty -Path $masterPath -Name 'Status' -Value 0 -Type DWord -Force -ErrorAction Stop
        }

        # Device consent OFF
        if (Test-Path $deviceConsentPath) {
            Set-ItemProperty -Path $deviceConsentPath -Name 'Value' -Value 'Deny' -Type String -Force -ErrorAction Stop
        }

        # Stop lfsvc if running
        $svc = Get-Service -Name lfsvc -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') {
            Stop-Service -Name lfsvc -Force -ErrorAction SilentlyContinue
        }

        # Brief pause to let system register the change
        Start-Sleep -Milliseconds 500

        # PHASE B: Toggle ON
        Write-Status "  Setting location ON..." 'INFO'

        # Master switch ON
        if (!(Test-Path $masterPath)) {
            New-Item -Path $masterPath -Force | Out-Null
        }
        Set-ItemProperty -Path $masterPath -Name 'Status' -Value 1 -Type DWord -Force -ErrorAction Stop

        # Device consent ON
        if (!(Test-Path $deviceConsentPath)) {
            New-Item -Path $deviceConsentPath -Force | Out-Null
        }
        Set-ItemProperty -Path $deviceConsentPath -Name 'Value' -Value 'Allow' -Type String -Force -ErrorAction Stop

        # Sensor permission ON
        if (!(Test-Path $sensorPath)) {
            New-Item -Path $sensorPath -Force | Out-Null
        }
        Set-ItemProperty -Path $sensorPath -Name 'SensorPermissionState' -Value 1 -Type DWord -Force -ErrorAction Stop

        # Ensure lfsvc is enabled and start it
        Set-Service -Name lfsvc -StartupType Manual -ErrorAction SilentlyContinue
        Start-Service -Name lfsvc -ErrorAction SilentlyContinue

        Write-Status "  Toggle cycle complete" 'OK'
        return $true
    } catch {
        Write-Status "  Toggle cycle failed: $_" 'FAIL'
        return $false
    }
}

# ============================================================
# DIAGNOSTIC FUNCTION
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

    # Find profiles that are NOT loaded
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
        if ($svc.Status -ne 'Running' -and $svc.Status -ne 'Stopped') {
            # Stopped is OK - it starts on demand
        }
    } catch {
        $issues += @{ Type = 'ServiceMissing'; Service = 'lfsvc'; Current = 'Not found'; Fix = 'Reinstall Windows component' }
    }

    return $issues
}

# ============================================================
# FIX FUNCTION
# ============================================================
function Invoke-LocationFix {
    param([array]$Issues, [switch]$WhatIf)

    $fixed = @()
    $failed = @()
    $skipped = @()

    foreach ($issue in $Issues) {
        $action = $null

        switch ($issue.Type) {
            'EmptyPolicyKey' {
                $action = "Delete empty policy key: $($issue.Path)"
                if (-not $WhatIf) {
                    try {
                        Remove-Item -Path $issue.Path -Force -Recurse -ErrorAction Stop
                        $fixed += $action
                    } catch {
                        $failed += "$action - Error: $_"
                    }
                } else {
                    $skipped += $action
                }
            }

            'PolicyBlock' {
                $action = "Delete blocking policy value: $($issue.Path)\$($issue.Name)"
                if (-not $WhatIf) {
                    try {
                        Remove-ItemProperty -Path $issue.Path -Name $issue.Name -Force -ErrorAction Stop
                        $fixed += $action

                        # Check if key is now empty and delete it
                        $remaining = Get-ItemProperty -Path $issue.Path -ErrorAction SilentlyContinue
                        $propNames = $remaining.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }
                        if ($propNames.Count -eq 0) {
                            Remove-Item -Path $issue.Path -Force -ErrorAction SilentlyContinue
                            $fixed += "Deleted now-empty key: $($issue.Path)"
                        }
                    } catch {
                        $failed += "$action - Error: $_"
                    }
                } else {
                    $skipped += $action
                }
            }

            'PolicyExists' {
                $action = "Delete policy value (causes managed banner): $($issue.Path)\$($issue.Name)"
                if (-not $WhatIf) {
                    try {
                        Remove-ItemProperty -Path $issue.Path -Name $issue.Name -Force -ErrorAction Stop
                        $fixed += $action

                        # Check if key is now empty and delete it
                        $remaining = Get-ItemProperty -Path $issue.Path -ErrorAction SilentlyContinue
                        $propNames = $remaining.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }
                        if ($propNames.Count -eq 0) {
                            Remove-Item -Path $issue.Path -Force -ErrorAction SilentlyContinue
                            $fixed += "Deleted now-empty key: $($issue.Path)"
                        }
                    } catch {
                        $failed += "$action - Error: $_"
                    }
                } else {
                    $skipped += $action
                }
            }

            'MDMBlock' {
                $action = "MDM policy blocking location - must fix in Intune/MDM console: $($issue.Name)=$($issue.Current)"
                $skipped += $action
            }

            'MasterSwitch' {
                $action = "Set master switch ON: $($issue.Path)\Status = 1"
                if (-not $WhatIf) {
                    try {
                        if (!(Test-Path $issue.Path)) {
                            New-Item -Path $issue.Path -Force | Out-Null
                        }
                        Set-ItemProperty -Path $issue.Path -Name 'Status' -Value 1 -Type DWord -Force -ErrorAction Stop
                        $fixed += $action
                    } catch {
                        $failed += "$action - Error: $_"
                    }
                } else {
                    $skipped += $action
                }
            }

            'DeviceConsent' {
                $action = "Set device consent: $($issue.Path)\Value = Allow"
                if (-not $WhatIf) {
                    try {
                        if (!(Test-Path $issue.Path)) {
                            New-Item -Path $issue.Path -Force | Out-Null
                        }
                        Set-ItemProperty -Path $issue.Path -Name 'Value' -Value 'Allow' -Type String -Force -ErrorAction Stop
                        $fixed += $action
                    } catch {
                        $failed += "$action - Error: $_"
                    }
                } else {
                    $skipped += $action
                }
            }

            'SensorPermission' {
                $action = "Set sensor permission: $($issue.Path)\SensorPermissionState = 1"
                if (-not $WhatIf) {
                    try {
                        if (!(Test-Path $issue.Path)) {
                            New-Item -Path $issue.Path -Force | Out-Null
                        }
                        Set-ItemProperty -Path $issue.Path -Name 'SensorPermissionState' -Value 1 -Type DWord -Force -ErrorAction Stop
                        $fixed += $action
                    } catch {
                        $failed += "$action - Error: $_"
                    }
                } else {
                    $skipped += $action
                }
            }

            'UserConsent' {
                $action = "Set user consent for $($issue.SID): Value = Allow"
                if (-not $WhatIf) {
                    try {
                        if (!(Test-Path $issue.Path)) {
                            New-Item -Path $issue.Path -Force | Out-Null
                        }
                        Set-ItemProperty -Path $issue.Path -Name 'Value' -Value 'Allow' -Type String -Force -ErrorAction Stop
                        $fixed += $action
                    } catch {
                        $failed += "$action - Error: $_"
                    }
                } else {
                    $skipped += $action
                }
            }

            'OfflineUserConsent' {
                # Resolve username for display
                $userName = $issue.SID
                try {
                    $sidObj = New-Object System.Security.Principal.SecurityIdentifier($issue.SID)
                    $account = $sidObj.Translate([System.Security.Principal.NTAccount])
                    $userName = $account.Value
                } catch {}

                $action = "Check/fix offline user consent for $userName"
                if (-not $WhatIf) {
                    $tempHive = "HKU\TempHive_$([guid]::NewGuid().ToString('N').Substring(0,8))"
                    try {
                        # Load the user's NTUSER.DAT
                        $regLoadResult = & reg.exe load $tempHive $issue.NTUserPath 2>&1
                        if ($LASTEXITCODE -ne 0) {
                            throw "reg load failed: $regLoadResult"
                        }

                        $consentPath = "Registry::$tempHive\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"

                        # Check current value
                        $currentConsent = $null
                        if (Test-Path $consentPath) {
                            $currentConsent = (Get-ItemProperty -Path $consentPath -Name 'Value' -ErrorAction SilentlyContinue).Value
                        }

                        if ($currentConsent -eq 'Allow') {
                            # Already set correctly, no fix needed
                            $skipped += "$userName already has consent=Allow"
                        } else {
                            # Need to fix - create parent keys if needed
                            $parentPath = "Registry::$tempHive\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
                            if (!(Test-Path $parentPath)) {
                                New-Item -Path $parentPath -Force | Out-Null
                            }
                            if (!(Test-Path $consentPath)) {
                                New-Item -Path $consentPath -Force | Out-Null
                            }

                            # Set the consent value
                            Set-ItemProperty -Path $consentPath -Name 'Value' -Value 'Allow' -Type String -Force -ErrorAction Stop
                            $fixed += "Set consent=Allow for $userName (was: $currentConsent)"
                        }

                        # Unload the hive
                        [gc]::Collect()
                        Start-Sleep -Milliseconds 500
                        & reg.exe unload $tempHive 2>&1 | Out-Null
                        if ($LASTEXITCODE -ne 0) {
                            # Try again after a longer delay
                            Start-Sleep -Seconds 2
                            [gc]::Collect()
                            & reg.exe unload $tempHive 2>&1 | Out-Null
                        }
                    } catch {
                        # Make sure we try to unload on error
                        try { & reg.exe unload $tempHive 2>&1 | Out-Null } catch {}
                        $failed += "$action - Error: $_"
                    }
                } else {
                    $skipped += "$action (profile: $($issue.ProfilePath))"
                }
            }

            'ServiceDisabled' {
                $action = "Enable lfsvc service (set to Manual)"
                if (-not $WhatIf) {
                    try {
                        Set-Service -Name lfsvc -StartupType Manual -ErrorAction Stop
                        $fixed += $action
                    } catch {
                        $failed += "$action - Error: $_"
                    }
                } else {
                    $skipped += $action
                }
            }

            'ServiceMissing' {
                $action = "lfsvc service missing - cannot fix automatically"
                $skipped += $action
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
# MAIN EXECUTION
# ============================================================
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Fix Windows Location Services" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

$contextName = if ($isSystem) { "SYSTEM" } else { $env:USERNAME }
Write-Status "Running as: $contextName (Elevated: $isAdmin)" 'INFO'
Write-Host ""

if ($WhatIf) {
    Write-Status "WHATIF MODE - No changes will be made" 'WARN'
    Write-Host ""
}

# ============================================================
# VERBOSE DIAGNOSTIC OUTPUT (when -ShowDiagnostics or $DebugScripts)
# ============================================================
if ($ShowDebug) {
    Write-Host ""
    LogStep "=== Location Services Verbose Diagnostic ===" 'HEADER'
    LogStep ("Context: User={0}, Elevation={1}" -f $env:USERNAME, $isAdmin)

    # GPO Policies
    LogStep "Checking admin (GPO) policies under HKLM:\SOFTWARE\Policies..." 'HEADER'

    $Pol_DisableLocation = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' 'DisableLocation'
    $Pol_DisableSensors = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' 'DisableSensors'
    $Pol_DisableLocationScripting = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' 'DisableLocationScripting'
    $Pol_AppPrivacy = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' 'LetAppsAccessLocation'

    if ($Pol_DisableLocation -eq 1) {
        LogStep "Policy: DisableLocation=1 (admin enforced) - BLOCKS location" 'FAIL'
    } elseif ($null -ne $Pol_DisableLocation) {
        LogStep "Policy: DisableLocation=$Pol_DisableLocation (policy EXISTS - Settings shows 'managed by admin')" 'WARN'
    } else {
        LogStep "Policy: DisableLocation=NotConfigured" 'OK'
    }

    if ($Pol_DisableSensors -eq 1) {
        LogStep "Policy: DisableSensors=1 - BLOCKS sensors/location stack" 'FAIL'
    } elseif ($null -ne $Pol_DisableSensors) {
        LogStep "Policy: DisableSensors=$Pol_DisableSensors (policy EXISTS)" 'WARN'
    } else {
        LogStep "Policy: DisableSensors=NotConfigured" 'OK'
    }

    if ($Pol_DisableLocationScripting -eq 1) {
        LogStep "Policy: DisableLocationScripting=1 - location scripting off" 'FAIL'
    } elseif ($null -ne $Pol_DisableLocationScripting) {
        LogStep "Policy: DisableLocationScripting=$Pol_DisableLocationScripting (policy EXISTS)" 'WARN'
    } else {
        LogStep "Policy: DisableLocationScripting=NotConfigured" 'OK'
    }

    if ($Pol_AppPrivacy -eq 2) {
        LogStep "Policy: LetAppsAccessLocation=2 (ForceDeny) - all apps blocked" 'FAIL'
    } elseif ($null -ne $Pol_AppPrivacy) {
        LogStep "Policy: LetAppsAccessLocation=$Pol_AppPrivacy (policy EXISTS)" 'WARN'
    } else {
        LogStep "Policy: LetAppsAccessLocation=NotConfigured" 'OK'
    }

    # MDM/Intune Policies
    LogStep "Checking MDM/Intune policies under HKLM:\SOFTWARE\Microsoft\PolicyManager..." 'HEADER'

    $MDM_AllowLocation = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System' 'AllowLocation'
    $MDM_LetAppsAccessLocation = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Privacy' 'LetAppsAccessLocation'

    # Check for MDM enrollment
    $MDM_Providers = @()
    $provPath = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers'
    if (Test-Path $provPath) {
        $MDM_Providers = @(Get-ChildItem -Path $provPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName)
    }

    if ($MDM_Providers.Count -gt 0) {
        LogStep ("MDM: Device is MDM-managed (Providers={0})" -f $MDM_Providers.Count) 'INFO'
    }

    if ($MDM_AllowLocation -eq 0) {
        LogStep "MDM: System\AllowLocation=0 - MDM BLOCKS location" 'FAIL'
    } elseif ($null -ne $MDM_AllowLocation) {
        LogStep "MDM: System\AllowLocation=$MDM_AllowLocation (policy EXISTS)" 'WARN'
    } else {
        LogStep "MDM: System\AllowLocation=NotConfigured" 'OK'
    }

    if ($MDM_LetAppsAccessLocation -eq 2) {
        LogStep "MDM: Privacy\LetAppsAccessLocation=2 (ForceDeny) - MDM blocks all apps" 'FAIL'
    } elseif ($null -ne $MDM_LetAppsAccessLocation) {
        LogStep "MDM: Privacy\LetAppsAccessLocation=$MDM_LetAppsAccessLocation (policy EXISTS)" 'WARN'
    } else {
        LogStep "MDM: Privacy\LetAppsAccessLocation=NotConfigured" 'OK'
    }

    # Azure AD / Domain Join Status
    LogStep "Checking Azure AD / Domain join status..." 'HEADER'

    $AzureADJoined = $false
    $DomainJoined = $false
    $MDMEnrolled = $false
    $TenantName = $null

    try {
        $dsregOutput = dsregcmd /status 2>&1
        foreach ($line in $dsregOutput) {
            if ($line -match '^\s*AzureAdJoined\s*:\s*(\S+)') { $AzureADJoined = ($Matches[1] -eq 'YES') }
            if ($line -match '^\s*DomainJoined\s*:\s*(\S+)') { $DomainJoined = ($Matches[1] -eq 'YES') }
            if ($line -match '^\s*MdmUrl\s*:\s*(\S+)') { $MDMEnrolled = (-not [string]::IsNullOrWhiteSpace($Matches[1])) }
            if ($line -match '^\s*TenantName\s*:\s*(.+)$') { $TenantName = $Matches[1].Trim() }
        }
    } catch {
        LogStep "Azure AD: Failed to run dsregcmd" 'WARN'
    }

    if ($AzureADJoined) {
        $tenantInfo = if ($TenantName) { " ($TenantName)" } else { "" }
        if ($MDMEnrolled) {
            LogStep ("Azure AD: Joined{0}, MDM enrolled - device is fully managed" -f $tenantInfo) 'INFO'
        } else {
            LogStep ("Azure AD: Joined{0}, but NOT MDM enrolled (may show cosmetic managed banner)" -f $tenantInfo) 'WARN'
        }
    } elseif ($DomainJoined) {
        LogStep "Azure AD: Not joined (domain-joined traditional AD)" 'INFO'
    } else {
        LogStep "Azure AD: Not joined (standalone/workgroup device)" 'OK'
    }

    # Provisioning Packages
    LogStep "Checking for provisioning packages..." 'HEADER'

    $ProvPackages = @()
    try {
        $ProvPackages = @(Get-ProvisioningPackage -AllInstalledPackages -ErrorAction SilentlyContinue)
    } catch {}

    if ($ProvPackages.Count -gt 0) {
        LogStep ("Provisioning: {0} package(s) installed (may set privacy defaults)" -f $ProvPackages.Count) 'WARN'
        foreach ($pkg in $ProvPackages) {
            LogStep ("  - {0} (v{1})" -f $pkg.PackageName, $pkg.Version) 'INFO'
        }
    } else {
        LogStep "Provisioning: No packages detected" 'OK'
    }

    # Device Settings Summary
    LogStep "Checking device settings..." 'HEADER'

    $Master_Status = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration' 'Status'
    $HKLM_DeviceConsent = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' 'Value'

    LogStep ("Device: MasterSwitch={0}, Consent={1}" -f (IfNull $Master_Status 'NotSet'), (IfNull $HKLM_DeviceConsent 'NotSet'))

    # Service Status
    try {
        $svc = Get-Service -Name lfsvc -ErrorAction Stop
        LogStep ("Service: lfsvc StartType={0}, Status={1}" -f $svc.StartType, $svc.Status)
    } catch {
        LogStep "Service: lfsvc NOT FOUND" 'FAIL'
    }

    Write-Host ""
}

# PHASE 1: Initial Diagnostic
Write-Status "PHASE 1: Initial Diagnostic" 'HEADER'
Write-Host ""

$beforeIssues = Get-LocationDiagnostic

if ($beforeIssues.Count -eq 0) {
    Write-Status "No issues found - location services should be working" 'OK'
    Write-Host ""
    Write-Host "If location still shows 'managed by admin', try:" -ForegroundColor Yellow
    Write-Host "  1. Close and reopen Settings app"
    Write-Host "  2. Sign out and back in"
    Write-Host "  3. Reboot the device"
    Write-Host ""
    exit 0
}

Write-Status "Found $($beforeIssues.Count) issue(s):" 'CHECK'
foreach ($issue in $beforeIssues) {
    $desc = switch ($issue.Type) {
        'EmptyPolicyKey'    { "Empty policy key exists (causes managed banner): $($issue.Path)" }
        'PolicyBlock'       { "Policy blocking location: $($issue.Path)\$($issue.Name) = $($issue.Current)" }
        'PolicyExists'      { "Policy key exists (causes managed banner): $($issue.Path)\$($issue.Name) = $($issue.Current)" }
        'MDMBlock'          { "MDM policy blocking: $($issue.Name) = $($issue.Current) [CANNOT FIX LOCALLY]" }
        'MasterSwitch'      { "Master switch OFF: Status = $($issue.Current)" }
        'DeviceConsent'     { "Device consent not Allow: Value = $($issue.Current)" }
        'SensorPermission'  { "Sensor permission not enabled: SensorPermissionState = $($issue.Current)" }
        'UserConsent'       { "User consent not Allow for $($issue.SID): Value = $($issue.Current)" }
        'OfflineUserConsent' {
            $userName = $issue.SID
            try {
                $sidObj = New-Object System.Security.Principal.SecurityIdentifier($issue.SID)
                $account = $sidObj.Translate([System.Security.Principal.NTAccount])
                $userName = $account.Value
            } catch {}
            "Offline user to check: $userName"
        }
        'ServiceDisabled'   { "lfsvc service disabled: StartType = $($issue.Current)" }
        'ServiceMissing'    { "lfsvc service missing" }
        default             { "Unknown issue: $($issue.Type)" }
    }

    if ($issue.Type -eq 'MDMBlock') {
        Write-Status "  $desc" 'WARN'
    } elseif ($issue.Type -eq 'OfflineUserConsent') {
        Write-Status "  $desc" 'INFO'
    } else {
        Write-Status "  $desc" 'FAIL'
    }
}
Write-Host ""

# PHASE 2: Apply Fixes
Write-Status "PHASE 2: Applying Fixes" 'HEADER'
Write-Host ""

$results = Invoke-LocationFix -Issues $beforeIssues -WhatIf:$WhatIf

if ($results.Fixed.Count -gt 0) {
    foreach ($fix in $results.Fixed) {
        Write-Status $fix 'FIXED'
    }
}

if ($results.Failed.Count -gt 0) {
    foreach ($fail in $results.Failed) {
        Write-Status $fail 'FAIL'
    }
}

if ($results.Skipped.Count -gt 0) {
    foreach ($skip in $results.Skipped) {
        Write-Status $skip 'WARN'
    }
}

Write-Host ""

# PHASE 2b: Emulate admin toggle cycle (resets any cached state)
if (-not $WhatIf) {
    Write-Status "PHASE 2b: Emulating Admin Toggle" 'HEADER'
    Write-Host ""
    Invoke-LocationToggleCycle | Out-Null
    Write-Host ""
}

# PHASE 3: Verify Fixes
Write-Status "PHASE 3: Verification" 'HEADER'
Write-Host ""

$afterIssues = Get-LocationDiagnostic

# Filter out MDM issues (can't fix those)
$fixableAfter = $afterIssues | Where-Object { $_.Type -notmatch 'MDM' }
$mdmIssues = $afterIssues | Where-Object { $_.Type -match 'MDM' }

if ($fixableAfter.Count -eq 0) {
    Write-Status "All fixable issues resolved!" 'OK'
} else {
    Write-Status "Some issues remain:" 'WARN'
    foreach ($issue in $fixableAfter) {
        Write-Status "  $($issue.Type): $($issue.Name) at $($issue.Path)" 'FAIL'
    }
}

if ($mdmIssues.Count -gt 0) {
    Write-Host ""
    Write-Status "MDM/Intune policies still blocking (fix in admin console):" 'WARN'
    foreach ($issue in $mdmIssues) {
        Write-Status "  $($issue.Name) = $($issue.Current)" 'WARN'
    }
}

# SUMMARY
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  SUMMARY" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Issues found:    $($beforeIssues.Count)"
Write-Host "  Fixed:           $($results.Fixed.Count)"
Write-Host "  Failed:          $($results.Failed.Count)"
Write-Host "  Skipped/MDM:     $($results.Skipped.Count)"
Write-Host "  Remaining:       $($afterIssues.Count)"
Write-Host ""

if ($results.Fixed.Count -gt 0 -and $fixableAfter.Count -eq 0) {
    Write-Host "Location services should now be enabled." -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "  1. Close and reopen Settings app"
    Write-Host "  2. If still showing 'managed', sign out and back in"
    Write-Host "  3. If still not working, reboot the device"
    Write-Host ""
}

if ($mdmIssues.Count -gt 0) {
    Write-Host "WARNING: MDM policies are blocking location." -ForegroundColor Red
    Write-Host "These must be fixed in the Intune/MDM admin console." -ForegroundColor Red
    Write-Host ""
}

# Exit code based on remaining fixable issues
if ($fixableAfter.Count -eq 0) {
    exit 0
} else {
    exit 1
}
