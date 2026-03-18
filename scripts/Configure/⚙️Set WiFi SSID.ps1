<#
.SYNOPSIS
    Creates a WiFi profile and force-connects to the specified SSID.

.DESCRIPTION
    This script reads WiFi SSID and password from Level.io custom fields, creates
    a WPA2PSK/AES WiFi profile, and force-connects the device to that network.

    Steps performed:
    1. Validates policy_wifi_setup is "yes" (skips otherwise)
    2. Validates SSID and password are set and not unresolved placeholders
    3. Creates a WPA2PSK/AES WiFi profile XML
    4. Adds the profile via netsh wlan add profile
    5. Disconnects from current WiFi network
    6. Connects to the target SSID
    7. Verifies connection after a brief wait

.NOTES
    Version:          2026.03.18.01
    Target Platform:  Windows 10, Windows 11
    Exit Codes:       0 = Success | 1 = Failure (Alert)

.EXAMPLE
    .\Set WiFi SSID.ps1
    Creates WiFi profile and connects to the SSID specified in Level.io custom fields.

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# Set WiFi SSID
# Version: 2026.03.18.01
# Target: Level.io
# Exit 0 = Success | Exit 1 = Alert (Failure)

function Test-IsUnresolved {
    param([string]$Value)
    return ($Value -match '^\{\{cf_')
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

# Build WPA2PSK/AES profile XML
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

# Save profile XML to temp file
$TempProfilePath = [System.IO.Path]::Combine($env:TEMP, "$SSID.xml")
try {
    $ProfileXml | Out-File -Encoding UTF8 -FilePath $TempProfilePath -Force
    Write-Host "[OK] Profile XML created"
}
catch {
    Write-Host "[Alert] Failed to create profile XML: $_"
    exit 1
}

# Add WiFi profile
try {
    $addResult = netsh wlan add profile filename="$TempProfilePath" user=all 2>&1
    Write-Host "[OK] WiFi profile added for '$SSID'"
    Write-Host "  $addResult"
}
catch {
    Write-Host "[Alert] Failed to add WiFi profile: $_"
    Remove-Item $TempProfilePath -Force -ErrorAction SilentlyContinue
    exit 1
}

# Clean up temp file
Remove-Item $TempProfilePath -Force -ErrorAction SilentlyContinue

# Disconnect from current WiFi
Write-Host ""
Write-Host "[INFO] Disconnecting from current WiFi..."
$disconnectResult = netsh wlan disconnect 2>&1
Write-Host "  $disconnectResult"

# Connect to target SSID
Write-Host "[INFO] Connecting to '$SSID'..."
$connectResult = netsh wlan connect name="$SSID" 2>&1
Write-Host "  $connectResult"

# Wait for connection to establish
Write-Host "[INFO] Waiting 5 seconds for connection..."
Start-Sleep -Seconds 5

# Verify connection
Write-Host ""
Write-Host "[VERIFICATION]"
$interfaces = netsh wlan show interfaces 2>&1
$connectedSSID = ($interfaces | Select-String -Pattern '^\s+SSID\s+:\s+(.+)$' | ForEach-Object { $_.Matches.Groups[1].Value.Trim() }) | Select-Object -First 1
$state = ($interfaces | Select-String -Pattern '^\s+State\s+:\s+(.+)$' | ForEach-Object { $_.Matches.Groups[1].Value.Trim() }) | Select-Object -First 1

Write-Host "  State: $state"
Write-Host "  SSID:  $connectedSSID"

Write-Host ""
if ($state -eq 'connected' -and $connectedSSID -eq $SSID) {
    Write-Host "[OK] Successfully connected to '$SSID'"
    exit 0
}
else {
    Write-Host "[Alert] Failed to connect to '$SSID'"
    Write-Host "[Alert] State: $state | Connected SSID: $connectedSSID"
    exit 1
}
