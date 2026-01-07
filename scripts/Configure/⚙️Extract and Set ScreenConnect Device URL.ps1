<#
.SYNOPSIS
    Extracts the ScreenConnect GUID from registry and sets the device URL custom field.

.DESCRIPTION
    This script extracts the ScreenConnect client GUID from the local Windows registry
    and constructs the full ScreenConnect connection URL. The URL is then output in
    Level.io custom field format to automatically populate the device's
    coolforge_screenconnect_device_url field.

    The script searches through Windows services for ScreenConnect Client entries,
    parses the ImagePath to extract the session GUID, and builds the Host#Access URL.

.NOTES
    Version:       2026.01.07.01
    Target:        Level.io RMM
    Exit Codes:    0 = Success | 1 = Alert (Failure)

    Level.io Variables Used:
    - {{cf_coolforge_screenconnect_baseurl}} : ScreenConnect server base URL

    Custom Fields Set:
    - cf_coolforge_screenconnect_device_url : Per-device ScreenConnect URL

.EXAMPLE
    # Run via Level.io launcher to auto-populate the ScreenConnect URL field
    .\Extract and Set ScreenConnect Device URL.ps1

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# Extract and Set ScreenConnect Device URL
# Version: 2026.01.07.01
# Target: Level.io
# Exit 0 = Success | Exit 1 = Alert (Failure)

$ErrorActionPreference = "Stop"

#region Configuration
# ScreenConnect base URL - can be set via custom field or hardcoded
$ScreenConnectBaseUrl = "{{cf_coolforge_screenconnect_baseurl}}"
if ([string]::IsNullOrWhiteSpace($ScreenConnectBaseUrl) -or $ScreenConnectBaseUrl -eq "{{cf_coolforge_screenconnect_baseurl}}") {
    # Default - update this to your ScreenConnect domain
    $ScreenConnectBaseUrl = "support.cool.net.au"
}

# Clean up the base URL (remove protocol if present, we'll add https://)
$ScreenConnectBaseUrl = $ScreenConnectBaseUrl -replace '^https?://', ''
$ScreenConnectBaseUrl = $ScreenConnectBaseUrl.TrimEnd('/')
#endregion Configuration

#region Main Logic

Write-Host "[*] Searching for ScreenConnect Client service..."

$Guid = $null

try {
    # Get all services under ControlSet001
    $ServiceKeys = Get-ChildItem "HKLM:\System\ControlSet001\Services" -ErrorAction SilentlyContinue

    foreach ($ServiceKey in $ServiceKeys) {
        if ($ServiceKey.PSChildName -like "*ScreenConnect Client*") {
            $ServiceName = $ServiceKey.PSChildName
            Write-Host "[*] Found ScreenConnect service: $ServiceName"

            $ServiceProps = Get-ItemProperty "HKLM:\SYSTEM\ControlSet001\Services\$ServiceName" -ErrorAction SilentlyContinue
            $ImagePath = $ServiceProps.ImagePath

            if ($ImagePath) {
                # Extract GUID from ImagePath using &s= parameter
                # Format: "path\ScreenConnect.ClientService.exe" "?e=Access&y=Guest&h=host&p=443&s=GUID&k=..."
                $GuidParser1 = $ImagePath -split "&s="
                if ($GuidParser1.Count -gt 1) {
                    $GuidParser2 = $GuidParser1[1] -split "&k="
                    $Guid = $GuidParser2[0]
                    Write-Host "[+] Extracted GUID: $Guid"
                    break
                }
            }
        }
    }
}
catch {
    Write-Host "[!] Error accessing registry: $($_.Exception.Message)"
}

#endregion Main Logic

#region Output

if ($Guid) {
    # Construct the full ScreenConnect URL
    $ScreenConnectUrl = "https://$ScreenConnectBaseUrl/Host#Access/All%20Machines//$Guid/Join"

    Write-Host "[+] ScreenConnect URL: $ScreenConnectUrl"
    Write-Host ""

    # Output in Level.io custom field format
    # This will automatically set the device's custom field value
    "{{cf_coolforge_screenconnect_device_url=$ScreenConnectUrl}}"

    exit 0
}
else {
    Write-Host "[!] ScreenConnect GUID could not be found in the registry."
    Write-Host "[!] Possible reasons:"
    Write-Host "    - ScreenConnect client is not installed"
    Write-Host "    - Service is registered under a different name"
    Write-Host "    - Registry permissions issue"
    exit 1
}

#endregion Output
