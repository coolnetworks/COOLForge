<#
.SYNOPSIS
    Creates a WiFi profile and force-connects to the specified SSID.

.DESCRIPTION
    This script reads WiFi SSID and password from Level.io custom fields, creates
    a WPA2PSK/AES WiFi profile, and force-connects the device to that network.

    Connection logic:
    - Ethernet active: Adds WiFi profile only, skips connect (profile ready for later)
    - WiFi active (different SSID): Adds profile, disconnects, connects to new SSID,
      verifies connection, falls back to previous SSID on failure
    - WiFi active (already on target): No action needed, exits success
    - No connection: Adds profile and attempts to connect

.NOTES
    Version:          2026.03.18.03
    Target Platform:  Windows 10, Windows 11
    Exit Codes:       0 = Success | 1 = Failure (Alert)

.EXAMPLE
    .\Set WiFi SSID.ps1
    Creates WiFi profile and connects to the SSID specified in Level.io custom fields.

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# Set WiFi SSID
# Version: 2026.03.18.03
# Target: Level.io
# Exit 0 = Success | Exit 1 = Alert (Failure)

function Test-IsUnresolved {
    param([string]$Value)
    return ($Value -match '^\{\{cf_')
}

function Get-WlanState {
    $output = netsh wlan show interfaces 2>&1
    $ssid = ($output | Select-String -Pattern '^\s+SSID\s+:\s+(.+)$' | ForEach-Object { $_.Matches.Groups[1].Value.Trim() }) | Select-Object -First 1
    $state = ($output | Select-String -Pattern '^\s+State\s+:\s+(.+)$' | ForEach-Object { $_.Matches.Groups[1].Value.Trim() }) | Select-Object -First 1
    return @{ State = $state; SSID = $ssid }
}

# ============================================
# AUTO-BOOTSTRAP: Ensure WiFi custom fields exist
# ============================================
if ($LevelApiKey) {
    $WifiFields = @(
        @{ Name = "policy_wifi_setup";          DefaultValue = "no";  Description = "Enable WiFi SSID force-connect (yes/no)" }
        @{ Name = "policy_wifi_ssid";           DefaultValue = "";    Description = "Target WiFi SSID name" }
        @{ Name = "policy_wifi_ssid_password";  DefaultValue = "";    Description = "WPA2 passphrase for target SSID" }
    )

    $FieldsCreated = 0
    foreach ($Field in $WifiFields) {
        $Existing = Find-LevelCustomField -ApiKey $LevelApiKey -FieldName $Field.Name
        if (-not $Existing) {
            Write-Host "[INFO] Creating custom field: $($Field.Name)"
            $NewField = New-LevelCustomField -ApiKey $LevelApiKey -Name $Field.Name -DefaultValue $Field.DefaultValue
            if ($NewField) {
                if (-not [string]::IsNullOrWhiteSpace($Field.DefaultValue) -and $NewField.id) {
                    $null = Set-LevelCustomFieldDefaultValue -ApiKey $LevelApiKey -FieldId $NewField.id -Value $Field.DefaultValue
                }
                Write-Host "[OK] Created custom field: $($Field.Name)"
                $FieldsCreated++
            }
        }
    }
    if ($FieldsCreated -gt 0) {
        Write-Host "[OK] WiFi infrastructure: $FieldsCreated fields created"
    }
}

Write-Host "========================================"
Write-Host "  WiFi SSID Configuration"
Write-Host "========================================"
Write-Host "  Computer: $env:COMPUTERNAME"
Write-Host "  Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host ""

# Check if WiFi setup is enabled
if ([string]::IsNullOrWhiteSpace($policy_wifi_setup) -or $policy_wifi_setup -ne 'yes') {
    Write-Host "[INFO] WiFi setup not enabled (policy_wifi_setup is not 'yes')"
    Write-Host "[INFO] Skipping"
    exit 0
}

# Validate SSID
if ([string]::IsNullOrWhiteSpace($policy_wifi_ssid) -or (Test-IsUnresolved $policy_wifi_ssid)) {
    Write-Host "[Alert] WiFi SSID is not set or unresolved"
    Write-Host "[Alert] Set cf_policy_wifi_ssid in Level.io custom fields"
    exit 1
}

# Validate password
if ([string]::IsNullOrWhiteSpace($policy_wifi_ssid_password) -or (Test-IsUnresolved $policy_wifi_ssid_password)) {
    Write-Host "[Alert] WiFi password is not set or unresolved"
    Write-Host "[Alert] Set cf_policy_wifi_ssid_password in Level.io custom fields"
    exit 1
}

$SSID = $policy_wifi_ssid.Trim()
$Key = $policy_wifi_ssid_password.Trim()

Write-Host "[INFO] Target SSID: $SSID"

# ============================================
# DETECT NETWORK STATE
# ============================================

Write-Host ""
Write-Host "[NETWORK STATE]"

# Check for active ethernet connection
$ethernetUp = Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object { $_.Status -eq 'Up' -and $_.PhysicalMediaType -match 'Ethernet|802\.3' -and $_.InterfaceDescription -notmatch 'Bluetooth|Hyper-V|VMware|VirtualBox|Loopback|WAN Miniport|TAP-Windows|Tunnel|Npcap' }

$hasWifiAdapter = Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object { $_.InterfaceDescription -match 'Wireless|Wi-Fi|WiFi|WLAN|802\.11' }

if (-not $hasWifiAdapter) {
    Write-Host "[Alert] No WiFi adapter found on this device"
    exit 1
}

# Get current WiFi state
$wlan = Get-WlanState
$previousSSID = $wlan.SSID
$onWifi = ($wlan.State -eq 'connected')

if ($onWifi) {
    Write-Host "  [INFO] WiFi connected to: $previousSSID"
} else {
    Write-Host "  [INFO] WiFi not connected"
}

if ($ethernetUp) {
    Write-Host "  [INFO] Ethernet active: $($ethernetUp.Name -join ', ')"
}

# Already on target SSID?
if ($onWifi -and $previousSSID -eq $SSID) {
    Write-Host ""
    Write-Host "[OK] Already connected to target SSID '$SSID'"
    exit 0
}

# ============================================
# ADD WIFI PROFILE
# ============================================

Write-Host ""
Write-Host "[WIFI PROFILE]"

$ProfileXml = @"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>$SSID</name>
    <SSIDConfig>
        <SSID>
            <name>$SSID</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>$Key</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>
"@

$TempProfilePath = [System.IO.Path]::Combine($env:TEMP, "$SSID.xml")
try {
    $ProfileXml | Out-File -Encoding UTF8 -FilePath $TempProfilePath -Force
    $addResult = netsh wlan add profile filename="$TempProfilePath" user=all 2>&1
    Write-Host "[OK] WiFi profile added for '$SSID'"
    Write-Host "  $addResult"
}
catch {
    Write-Host "[Alert] Failed to add WiFi profile: $_"
    Remove-Item $TempProfilePath -Force -ErrorAction SilentlyContinue
    exit 1
}
finally {
    Remove-Item $TempProfilePath -Force -ErrorAction SilentlyContinue
}

# ============================================
# ETHERNET: PROFILE ONLY, SKIP CONNECT
# ============================================

if ($ethernetUp) {
    Write-Host ""
    Write-Host "[OK] Device is on ethernet - profile added, skipping WiFi connect"
    Write-Host "[INFO] Device will auto-connect to '$SSID' when on WiFi"
    exit 0
}

# ============================================
# CONNECT TO NEW SSID
# ============================================

Write-Host ""
Write-Host "[CONNECTING]"

if ($onWifi) {
    Write-Host "[INFO] Disconnecting from '$previousSSID'..."
    $null = netsh wlan disconnect 2>&1
    Start-Sleep -Seconds 1
}

Write-Host "[INFO] Connecting to '$SSID'..."
$connectResult = netsh wlan connect name="$SSID" 2>&1
Write-Host "  $connectResult"

Write-Host "[INFO] Waiting 5 seconds for connection..."
Start-Sleep -Seconds 5

# ============================================
# VERIFY CONNECTION
# ============================================

Write-Host ""
Write-Host "[VERIFICATION]"
$wlan = Get-WlanState

Write-Host "  State: $($wlan.State)"
Write-Host "  SSID:  $($wlan.SSID)"

if ($wlan.State -eq 'connected' -and $wlan.SSID -eq $SSID) {
    Write-Host ""
    Write-Host "[OK] Successfully connected to '$SSID'"
    exit 0
}

# ============================================
# FALLBACK: RECONNECT TO PREVIOUS SSID
# ============================================

Write-Host ""
Write-Host "[Alert] Failed to connect to '$SSID'"

if ($previousSSID) {
    Write-Host "[INFO] Attempting to reconnect to previous SSID '$previousSSID'..."
    $null = netsh wlan disconnect 2>&1
    Start-Sleep -Seconds 1
    $fallbackResult = netsh wlan connect name="$previousSSID" 2>&1
    Write-Host "  $fallbackResult"
    Start-Sleep -Seconds 5

    $wlan = Get-WlanState
    if ($wlan.State -eq 'connected' -and $wlan.SSID -eq $previousSSID) {
        Write-Host "[OK] Restored connection to '$previousSSID'"
    }
    else {
        Write-Host "[Alert] Could not restore previous connection either"
        Write-Host "[Alert] State: $($wlan.State) | SSID: $($wlan.SSID)"
    }
}

Write-Host "[Alert] WiFi switch to '$SSID' failed - check SSID name and password"
exit 1
