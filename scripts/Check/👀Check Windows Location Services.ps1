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

# ---------------------------------------------
# STEP 1b: MDM/Intune Policies (PolicyManager)
# ---------------------------------------------
LogStep "Step 1b: Checking MDM/Intune policies under HKLM:\SOFTWARE\Microsoft\PolicyManager..." 'HEADER'

# MDM System\AllowLocation: 0=Off, 1=On, 2=ForceOn
$MDM_AllowLocation = GetRegVal 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System' 'AllowLocation'
# MDM Privacy\LetAppsAccessLocation: 0=User, 1=ForceAllow, 2=ForceDeny
$MDM_LetAppsAccessLocation = GetRegVal 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Privacy' 'LetAppsAccessLocation'

# Check for MDM enrollment (indicates device is MDM-managed)
$MDM_Providers = @()
$provPath = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers'
if (Test-Path $provPath) {
    $MDM_Providers = @(Get-ChildItem -Path $provPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName)
}
$enrollPath = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
$MDM_Enrollments = @()
if (Test-Path $enrollPath) {
    $MDM_Enrollments = @(Get-ChildItem -Path $enrollPath -ErrorAction SilentlyContinue | Where-Object {
        $_.PSChildName -match '^[0-9a-f]{8}-' # GUID-like enrollment IDs
    } | Select-Object -ExpandProperty PSChildName)
}

if ($MDM_Providers.Count -gt 0 -or $MDM_Enrollments.Count -gt 0) {
    LogStep ("MDM: Device is MDM-managed (Providers={0}, Enrollments={1})" -f $MDM_Providers.Count, $MDM_Enrollments.Count) 'INFO'
}

if ($MDM_AllowLocation -eq 0) {
    LogStep "MDM: System\AllowLocation=0 - MDM BLOCKS location" 'FAIL'
    $blockers += 'MDM System AllowLocation=0 (blocked)'
} elseif ($null -ne $MDM_AllowLocation) {
    LogStep "MDM: System\AllowLocation=$MDM_AllowLocation (policy EXISTS)" 'WARN'
    $blockers += 'MDM System AllowLocation exists (shows managed message)'
} else {
    LogStep "MDM: System\AllowLocation=NotConfigured" 'OK'
}

if ($MDM_LetAppsAccessLocation -eq 2) {
    LogStep "MDM: Privacy\LetAppsAccessLocation=2 (ForceDeny) - MDM blocks all apps" 'FAIL'
    $blockers += 'MDM Privacy LetAppsAccessLocation=2 (ForceDeny)'
} elseif ($null -ne $MDM_LetAppsAccessLocation) {
    LogStep "MDM: Privacy\LetAppsAccessLocation=$MDM_LetAppsAccessLocation (policy EXISTS)" 'WARN'
} else {
    LogStep "MDM: Privacy\LetAppsAccessLocation=NotConfigured" 'OK'
}

# ---------------------------------------------
# STEP 1c: Azure AD Join Status (dsregcmd)
# ---------------------------------------------
LogStep "Step 1c: Checking Azure AD / Domain join status..." 'HEADER'

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
        LogStep ("Azure AD: Joined{0}, but NOT MDM enrolled" -f $tenantInfo) 'WARN'
        # This is the scenario where Settings shows "managed by admin" without actual policies
        $blockers += 'Azure AD joined without MDM (cosmetic managed banner)'
    }
} elseif ($DomainJoined) {
    LogStep "Azure AD: Not joined (domain-joined traditional AD)" 'INFO'
} else {
    LogStep "Azure AD: Not joined (standalone/workgroup device)" 'OK'
}

# ---------------------------------------------
# STEP 1d: Provisioning Packages
# ---------------------------------------------
LogStep "Step 1d: Checking for provisioning packages..." 'HEADER'

$ProvPackages = @()
try {
    $ProvPackages = @(Get-ProvisioningPackage -AllInstalledPackages -ErrorAction SilentlyContinue)
} catch {}

if ($ProvPackages.Count -gt 0) {
    LogStep ("Provisioning: {0} package(s) installed" -f $ProvPackages.Count) 'WARN'
    foreach ($pkg in $ProvPackages) {
        LogStep ("  - {0} (v{1})" -f $pkg.PackageName, $pkg.Version) 'INFO'
    }
    $blockers += 'Provisioning package(s) installed (may set privacy defaults)'
} else {
    LogStep "Provisioning: No packages detected" 'OK'
}

# ----------------------------------
# STEP 2: Device Master Switch (OS)
# ----------------------------------
LogStep "Step 2: Checking device master switch (lfsvc\Service\Configuration\Status)..." 'HEADER'
$Master_Status = GetRegVal 'HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration' 'Status' # 1=On, 0/NotSet=Off
if ($Master_Status -eq 1) { LogStep "Master switch: ON (Status=1)" 'OK' } else { LogStep ("Master switch: Off/NotSet (Status={0})" -f (IfNull $Master_Status 'NotSet')) 'FAIL'; $blockers += 'Master switch Off/NotSet' }

# ---------------------------------------------------
# STEP 3: Device-level ConsentStore (HKLM) & All Users
# ---------------------------------------------------
LogStep "Step 3: Checking ConsentStore (device HKLM + all users)..." 'HEADER'
$HKLM_DeviceConsent = GetRegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' 'Value'

if ($HKLM_DeviceConsent) {
    if ($HKLM_DeviceConsent -eq 'Deny') { LogStep "Device Consent (HKLM): Deny - Settings may show 'turned off by admin'" 'FAIL'; $blockers += 'Device HKLM Consent=Deny' }
    else { LogStep "Device Consent (HKLM): $HKLM_DeviceConsent" 'OK' }
} else {
    LogStep "Device Consent (HKLM): NotSet" 'INFO'
}

# Check all user profiles via HKU
$UserConsentResults = @()
$AnyUserDeny = $false
$AnyUserNotSet = $false

# Get all loaded user hives (SIDs that look like user accounts, not system)
$userSIDs = @()
try {
    $userSIDs = Get-ChildItem -Path 'Registry::HKU' -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$' } |
        Select-Object -ExpandProperty PSChildName
} catch {}

# Also check if any profiles exist that aren't loaded
$profileListPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
$allProfileSIDs = @()
try {
    $allProfileSIDs = Get-ChildItem -Path $profileListPath -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -match '^S-1-5-21-' } |
        Select-Object -ExpandProperty PSChildName
} catch {}

LogStep ("Found {0} loaded user hives, {1} total profiles" -f $userSIDs.Count, $allProfileSIDs.Count) 'INFO'

foreach ($sid in $userSIDs) {
    $hkuPath = "Registry::HKU\$sid\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
    $userConsent = GetRegVal $hkuPath 'Value'

    # Try to resolve SID to username
    $userName = $sid
    try {
        $sidObj = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $account = $sidObj.Translate([System.Security.Principal.NTAccount])
        $userName = $account.Value
    } catch {}

    if ($userConsent -eq 'Deny') {
        LogStep ("  User {0}: Deny" -f $userName) 'FAIL'
        $AnyUserDeny = $true
        $UserConsentResults += @{ User = $userName; Value = 'Deny' }
    } elseif ($userConsent -eq 'Allow') {
        LogStep ("  User {0}: Allow" -f $userName) 'OK'
        $UserConsentResults += @{ User = $userName; Value = 'Allow' }
    } elseif ($null -eq $userConsent) {
        LogStep ("  User {0}: NotSet" -f $userName) 'WARN'
        $AnyUserNotSet = $true
        $UserConsentResults += @{ User = $userName; Value = 'NotSet' }
    } else {
        LogStep ("  User {0}: {1}" -f $userName, $userConsent) 'WARN'
        $UserConsentResults += @{ User = $userName; Value = $userConsent }
    }
}

if ($userSIDs.Count -eq 0) {
    LogStep "No user hives loaded (no users logged in)" 'WARN'
    $AnyUserNotSet = $true
}

if ($AnyUserDeny) { $blockers += 'User HKCU Consent=Deny' }
if ($AnyUserNotSet) { $blockers += 'User HKCU Consent NotSet' }

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
    'MDM System AllowLocation=0 (blocked)',
    'MDM Privacy LetAppsAccessLocation=2 (ForceDeny)',
    'Device HKLM Consent=Deny',
    'Master switch Off/NotSet',
    'lfsvc missing or Disabled',
    'User HKCU Consent=Deny',
    'User HKCU Consent NotSet',
    'Admin policy DisableLocation exists (shows managed message)',
    'MDM System AllowLocation exists (shows managed message)',
    'Provisioning package(s) installed (may set privacy defaults)',
    'Azure AD joined without MDM (cosmetic managed banner)',
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
    'AppPrivacy.*ForceDeny'         { 'Fix at policy source (GPO/Intune): set AppPrivacy LetAppsAccessLocation to 0 (User) or 1 (ForceAllow).' }
    'MDM System AllowLocation=0'    { 'Fix in MDM/Intune console: System > Allow Location = 1 (On) or Not configured. Then sync device.' }
    'MDM Privacy.*ForceDeny'        { 'Fix in MDM/Intune console: Privacy > Let Apps Access Location = User In Control or Force Allow. Then sync device.' }
    'MDM.*shows managed'            { 'Remove MDM policy from Intune console (set to Not configured). Local deletion will be re-applied on sync.' }
    'Device HKLM Consent=Deny'      { 'Set HKLM:\...\ConsentStore\location\Value=Allow (admin), then close/reopen Settings or sign out/in.' }
    'Master switch Off/NotSet'      { 'Set HKLM:\SYSTEM\CCS\Services\lfsvc\Service\Configuration\Status=1 (admin), then close/reopen Settings.' }
    'lfsvc missing or Disabled'     { 'Ensure lfsvc exists; Set-Service lfsvc -StartupType Manual; Start-Service lfsvc.' }
    'User HKCU Consent=Deny'        { 'Set HKCU:\...\ConsentStore\location\Value=Allow (run as the logged-in user).' }
    'User HKCU Consent NotSet'      { 'Create HKCU key and set Value=Allow (run as the logged-in user).' }
    'Admin.*shows managed'          { 'DELETE the policy key from GPO/Intune (setting to 0 still shows "managed by admin"). Remove: HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' }
    'Provisioning package'          { 'Provisioning package may have set privacy defaults. Use Get-ProvisioningPackage to list, Remove-ProvisioningPackage to remove. May need to re-run OOBE or reset privacy settings.' }
    'Azure AD joined without MDM'   { 'COSMETIC ONLY - toggle should still work. To remove banner: enroll in Intune and set AllowLocation=1, or check for provisioning packages (Get-ProvisioningPackage).' }
    'Per-app Deny overrides present'{ 'Set affected per-app ConsentStore entries to Allow or remove the entries (HKCU).' }
    default                         { 'No action needed; if an app still fails, inspect its per-app ConsentStore entry.' }
}

# Print collected values for quick view
$elapsed = (Get-Date) - $start
LogStep ("GPO: DisableLocation={0}; DisableSensors={1}; DisableLocationScripting={2}; AppPrivacy={3}" -f `
    (IfNull $Pol_DisableLocation 'NotConfigured'), (IfNull $Pol_DisableSensors 'NotConfigured'), (IfNull $Pol_DisableLocationScripting 'NotConfigured'), (IfNull $Pol_AppPrivacy 'NotConfigured'))
LogStep ("MDM: AllowLocation={0}; LetAppsAccessLocation={1}; Managed={2}" -f `
    (IfNull $MDM_AllowLocation 'NotConfigured'), (IfNull $MDM_LetAppsAccessLocation 'NotConfigured'), ($MDM_Providers.Count -gt 0 -or $MDM_Enrollments.Count -gt 0))
LogStep ("AzureAD: Joined={0}; MDMEnrolled={1}; Tenant={2}; ProvPkgs={3}" -f `
    $AzureADJoined, $MDMEnrolled, (IfNull $TenantName 'N/A'), $ProvPackages.Count)
LogStep ("Device: MasterStatus={0}; HKLM_Consent={1}; lfsvc(StartType={2},Status={3})" -f `
    (IfNull $Master_Status 'NotSet'), (IfNull $HKLM_DeviceConsent 'NotSet'), $SvcStart, $SvcStatus)
LogStep ("User: HKCU_Consent={0}; PerAppDenies={1}" -f (IfNull $HKCU_UserConsent 'NotSet'), ($PerAppDenies.Count))

Write-Host ""
LogStep ("PrimaryReason: {0}" -f $primary) 'HEADER'
LogStep ("RecommendedFix: {0}" -f $recommend) 'HEADER'
LogStep ("Elapsed: {0} ms" -f [int]$elapsed.TotalMilliseconds) 'INFO'

# Exit code
if ($blockers.Count -gt 0) { exit 1 } else { exit 0 }
