<#
COOLNETWORKS - Verbose Location Services Diagnostic (Windows 10/11)
Purpose:
  - Verbosely checks every lever that affects Location:
      * Admin policies: DisableLocation, DisableSensors, DisableLocationScripting
      * AppPrivacy gate: LetAppsAccessLocation (ForceDeny)
      * Device master switch: lfsvc\Service\Configuration\Status
      * Device-level ConsentStore (HKLM)
      * User ConsentStore (HKCU)
      * Geolocation service (lfsvc) StartType/Status
      * Per-app (packaged + NonPackaged) Deny overrides (HKCU)
  - Prints each step, result, and recommendations
  - Produces a Summary with PrimaryReason and RecommendedFix

Notes / References (general behavior):
  - HKLM\SOFTWARE\Policies\...\LocationAndSensors\DisableLocation controls device-wide admin block
  - HKLM\SOFTWARE\Policies\...\AppPrivacy\LetAppsAccessLocation = 2 forces Deny for all apps
  - Device master switch is HKLM\SYSTEM\CCS\Services\lfsvc\Service\Configuration\Status (1=On)
  - ConsentStore per-user is HKCU\...\ConsentStore\location (Value='Allow' or 'Deny');
    device-level exists under HKLM for some setups and can drive the Settings banner

#>

param(
  [switch]$ShowPerAppOverrides  # include enumeration of per-app denies
)

$ErrorActionPreference = 'SilentlyContinue'
$start = Get-Date
$blockers = @()
$steps = @()

function LogStep {
    param([string]$Message,[string]$Level='INFO')
    $ts = (Get-Date).ToString('HH:mm:ss')
    $color = switch ($Level.ToUpper()) {
        'INFO'     { 'Gray' }
        'OK'       { 'Green' }
        'WARN'     { 'Yellow' }
        'FAIL'     { 'Yellow' }
        'HEADER'   { 'Cyan' }
        default    { 'Gray' }
    }
    Write-Host ("[{0}] {1}" -f $ts, $Message) -ForegroundColor $color
    $script:steps += ("{0} {1}" -f $ts, $Message)
}

function GetRegVal {
    param($Path,$Name)
    try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

function IfNull {
    param($Value, $Default)
    if ($null -eq $Value) { $Default } else { $Value }
}

Write-Host ""
LogStep "=== Location Services Verbose Diagnostic (Windows 10/11) ===" 'HEADER'
LogStep ("Context: User={0}, Elevation={1}" -f $env:USERNAME, ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))

# ---------------------------
# STEP 1: Read Admin Policies
# ---------------------------
LogStep "Step 1: Checking admin (GPO/MDM) policies under HKLM:\SOFTWARE\Policies..." 'HEADER'

$Pol_DisableLocation          = GetRegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' 'DisableLocation'
$Pol_DisableSensors           = GetRegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' 'DisableSensors'
$Pol_DisableLocationScripting = GetRegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' 'DisableLocationScripting'
$Pol_AppPrivacy               = GetRegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' 'LetAppsAccessLocation'

# Note: When a policy KEY EXISTS (even set to 0), Windows shows "managed by admin" in Settings UI
# The key must be ABSENT (not just 0) for user to have full control
if ($Pol_DisableLocation -eq 1) {
    LogStep "Policy: DisableLocation=1 (admin enforced) - BLOCKS location" 'FAIL'
    $blockers += 'Admin policy DisableLocation=1'
} elseif ($null -ne $Pol_DisableLocation) {
    LogStep "Policy: DisableLocation=$Pol_DisableLocation (policy EXISTS - Settings shows 'managed by admin')" 'WARN'
    $blockers += 'Admin policy DisableLocation exists (shows managed message)'
} else {
    LogStep "Policy: DisableLocation=NotConfigured" 'OK'
}

if ($Pol_DisableSensors -eq 1) {
    LogStep "Policy: DisableSensors=1 - BLOCKS sensors/location stack" 'FAIL'
    $blockers += 'Admin policy DisableSensors=1'
} elseif ($null -ne $Pol_DisableSensors) {
    LogStep "Policy: DisableSensors=$Pol_DisableSensors (policy EXISTS)" 'WARN'
} else {
    LogStep "Policy: DisableSensors=NotConfigured" 'OK'
}

if ($Pol_DisableLocationScripting -eq 1) {
    LogStep "Policy: DisableLocationScripting=1 - location scripting off" 'FAIL'
    $blockers += 'Admin policy DisableLocationScripting=1'
} elseif ($null -ne $Pol_DisableLocationScripting) {
    LogStep "Policy: DisableLocationScripting=$Pol_DisableLocationScripting (policy EXISTS)" 'WARN'
} else {
    LogStep "Policy: DisableLocationScripting=NotConfigured" 'OK'
}

if ($Pol_AppPrivacy -eq 2) {
    LogStep "Policy: LetAppsAccessLocation=2 (ForceDeny) - all apps blocked" 'FAIL'
    $blockers += 'AppPrivacy LetAppsAccessLocation=2 (ForceDeny)'
} elseif ($null -ne $Pol_AppPrivacy) {
    LogStep "Policy: LetAppsAccessLocation=$Pol_AppPrivacy (policy EXISTS)" 'WARN'
} else {
    LogStep "Policy: LetAppsAccessLocation=NotConfigured" 'OK'
}

# ----------------------------------
# STEP 2: Device Master Switch (OS)
# ----------------------------------
LogStep "Step 2: Checking device master switch (lfsvc\Service\Configuration\Status)..." 'HEADER'
$Master_Status = GetRegVal 'HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration' 'Status' # 1=On, 0/NotSet=Off
if ($Master_Status -eq 1) { LogStep "Master switch: ON (Status=1)" 'OK' } else { LogStep ("Master switch: Off/NotSet (Status={0})" -f (IfNull $Master_Status 'NotSet')) 'FAIL'; $blockers += 'Master switch Off/NotSet' }

# ---------------------------------------------------
# STEP 3: Device-level ConsentStore (HKLM) & HKCU
# ---------------------------------------------------
LogStep "Step 3: Checking ConsentStore (device HKLM + user HKCU)..." 'HEADER'
$HKLM_DeviceConsent = GetRegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' 'Value'
$HKCU_UserConsent   = GetRegVal 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' 'Value'

if ($HKLM_DeviceConsent) {
    if ($HKLM_DeviceConsent -eq 'Deny') { LogStep "Device Consent (HKLM): Deny - Settings may show 'turned off by admin'" 'FAIL'; $blockers += 'Device HKLM Consent=Deny' }
    else { LogStep "Device Consent (HKLM): $HKLM_DeviceConsent" 'OK' }
} else {
    LogStep "Device Consent (HKLM): NotSet" 'INFO'
}

if ($HKCU_UserConsent) {
    if ($HKCU_UserConsent -eq 'Deny') { LogStep "User Consent (HKCU): Deny - user has denied location" 'FAIL'; $blockers += 'User HKCU Consent=Deny' }
    elseif ($HKCU_UserConsent -ne 'Allow') { LogStep "User Consent (HKCU): $HKCU_UserConsent - not 'Allow'" 'WARN' }
    else { LogStep "User Consent (HKCU): Allow" 'OK' }
} else {
    LogStep "User Consent (HKCU): NotSet - user toggle not established" 'WARN'
    $blockers += 'User HKCU Consent NotSet'
}

# -------------------------------------
# STEP 4: Geolocation Service (lfsvc)
# -------------------------------------
LogStep "Step 4: Checking Geolocation service (lfsvc)..." 'HEADER'
$svc = $null; try { $svc = Get-Service -Name lfsvc -ErrorAction Stop } catch {}
$SvcStatus = if ($svc) { [string]$svc.Status } else { 'NotFound' }
$SvcStart  = if ($svc) { [string]$svc.StartType } else { 'NotFound' }

if (($SvcStatus -eq 'NotFound') -or ($SvcStart -eq 'Disabled')) {
    LogStep ("lfsvc: missing/Disabled (StartType={0}, Status={1})" -f $SvcStart, $SvcStatus) 'FAIL'
    $blockers += 'lfsvc missing or Disabled'
} else {
    LogStep ("lfsvc: present and not Disabled (StartType={0}, Status={1})" -f $SvcStart, $SvcStatus) 'OK'
}

# -----------------------------------------------------
# STEP 5 (Optional): Per-app Deny overrides (current user)
# -----------------------------------------------------
$PerAppDenies = @()
if ($ShowPerAppOverrides.IsPresent) {
    LogStep "Step 5: Enumerating per-app ConsentStore 'Deny' entries for current user..." 'HEADER'
    try {
        $base = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'
        if (Test-Path $base) {
            # Packaged apps
            Get-ChildItem -Path $base -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -ne 'NonPackaged' } | ForEach-Object {
                $v = GetRegVal $_.PsPath 'Value'
                if ($v -eq 'Deny') { $PerAppDenies += $_.PSChildName }
            }
            # Desktop apps (NonPackaged)
            $np = Join-Path $base 'NonPackaged'
            if (Test-Path $np) {
                Get-ChildItem -Path $np -ErrorAction SilentlyContinue | ForEach-Object {
                    $v = GetRegVal $_.PsPath 'Value'
                    if ($v -eq 'Deny') { $PerAppDenies += ("NonPackaged::" + $_.PSChildName) }
                }
            }
        }
    } catch {}
    if ($PerAppDenies.Count -gt 0) {
        LogStep ("Per-app Denies: {0}" -f ($PerAppDenies -join ', ')) 'WARN'
        $blockers += 'Per-app Deny overrides present'
    } else {
        LogStep "Per-app Denies: none detected" 'OK'
    }
}

# ---------------------------
# SUMMARY & PRIMARY REASON
# ---------------------------
Write-Host ""
LogStep "==== SUMMARY ====" 'HEADER'

# Choose primary reason by priority
$primary = $null
$priority = @(
    'Admin policy DisableLocation=1',
    'Admin policy DisableSensors=1',
    'Admin policy DisableLocationScripting=1',
    'AppPrivacy LetAppsAccessLocation=2 (ForceDeny)',
    'Device HKLM Consent=Deny',
    'Master switch Off/NotSet',
    'lfsvc missing or Disabled',
    'User HKCU Consent=Deny',
    'User HKCU Consent NotSet',
    'Admin policy DisableLocation exists (shows managed message)',
    'Per-app Deny overrides present'
)
foreach ($reason in $priority) {
    if ($blockers -contains $reason) { $primary = $reason; break }
}
if (-not $primary) {
    if ($blockers.Count -gt 0) { $primary = $blockers[0] } else { $primary = 'No blocking condition detected' }
}

# Map recommended fix
$recommend = switch -Regex ($primary) {
    'DisableLocation=1'             { 'Fix at policy source (GPO/Intune): set DisableLocation to Not configured/0, then gpupdate or Intune Sync.' }
    'DisableSensors=1'              { 'Fix at policy source (GPO/Intune): set DisableSensors to Not configured/0, refresh policy.' }
    'DisableLocationScripting=1'    { 'Fix at policy source (GPO/Intune): set DisableLocationScripting to Not configured/0, refresh policy.' }
    'ForceDeny'                     { 'Fix at policy source (GPO/Intune): set AppPrivacy LetAppsAccessLocation to 0 (User) or 1 (ForceAllow).' }
    'Device HKLM Consent=Deny'      { 'Set HKLM:\...\ConsentStore\location\Value=Allow (admin), then close/reopen Settings or sign out/in.' }
    'Master switch Off/NotSet'      { 'Set HKLM:\SYSTEM\CCS\Services\lfsvc\Service\Configuration\Status=1 (admin), then close/reopen Settings.' }
    'lfsvc missing or Disabled'     { 'Ensure lfsvc exists; Set-Service lfsvc -StartupType Manual; Start-Service lfsvc.' }
    'User HKCU Consent=Deny'        { 'Set HKCU:\...\ConsentStore\location\Value=Allow (run as the logged-in user).' }
    'User HKCU Consent NotSet'      { 'Create HKCU key and set Value=Allow (run as the logged-in user).' }
    'shows managed message'         { 'DELETE the policy key from GPO/Intune (setting to 0 still shows "managed by admin"). Remove: HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors\DisableLocation' }
    'Per-app Deny overrides present'{ 'Set affected per-app ConsentStore entries to Allow or remove the entries (HKCU).' }
    default                         { 'No action needed; if an app still fails, inspect its per-app ConsentStore entry.' }
}

# Print collected values for quick view
$elapsed = (Get-Date) - $start
LogStep ("Admin: DisableLocation={0}; DisableSensors={1}; DisableLocationScripting={2}; AppPrivacy={3}" -f `
    (IfNull $Pol_DisableLocation 'NotConfigured'), (IfNull $Pol_DisableSensors 'NotConfigured'), (IfNull $Pol_DisableLocationScripting 'NotConfigured'), (IfNull $Pol_AppPrivacy 'NotConfigured'))
LogStep ("Device: MasterStatus={0}; HKLM_Consent={1}; lfsvc(StartType={2},Status={3})" -f `
    (IfNull $Master_Status 'NotSet'), (IfNull $HKLM_DeviceConsent 'NotSet'), $SvcStart, $SvcStatus)
LogStep ("User: HKCU_Consent={0}; PerAppDenies={1}" -f (IfNull $HKCU_UserConsent 'NotSet'), ($PerAppDenies.Count))

Write-Host ""
LogStep ("PrimaryReason: {0}" -f $primary) 'HEADER'
LogStep ("RecommendedFix: {0}" -f $recommend) 'HEADER'
LogStep ("Elapsed: {0} ms" -f [int]$elapsed.TotalMilliseconds) 'INFO'

# Exit code
if ($blockers.Count -gt 0) { exit 1 } else { exit 0 }
