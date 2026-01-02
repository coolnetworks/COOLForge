<#
.SYNOPSIS
    Install ScreenConnect with Level.io integration and duplicate session cleanup.

.DESCRIPTION
    This script installs ScreenConnect with the following features:

    1. Pre-install API check for existing sessions (by Level.io device ID)
    2. Automatic deletion of duplicate/stale sessions before install
    3. Embeds Level.io metadata into ScreenConnect CustomProperties:
       - CP1: Level folder path (normalized) - for session grouping
       - CP3: Level device ID - for unique identification
    4. Stores Level folder path in registry as source of truth
    5. Downloads and installs MSI with proper custom properties

.NOTES
    Version: 2026.01.02.01 (WIP)

    Level.io Custom Fields Required:
    - cf_screenconnect_baseurl        : https://your-server.com
    - cf_screenconnect_instance_id    : Your instance ID (e.g., 983fa4f3c185dd21)
    - cf_screenconnect_api_user       : API username (needs session delete permission)
    - cf_screenconnect_api_password   : API password
    - level_group_path                : Level.io group path
    - level_device_id                 : Level.io unique device identifier

.PARAMETER BaseUrl
    ScreenConnect server base URL

.PARAMETER InstanceId
    Your MSP's ScreenConnect instance ID

.PARAMETER ApiUser
    API username for ScreenConnect server

.PARAMETER ApiPassword
    API password for ScreenConnect server

.PARAMETER LevelGroupPath
    Level.io group path (will be normalized and stored in registry)

.PARAMETER LevelDeviceId
    Level.io unique device identifier (stored in CustomProperty3)

.PARAMETER Force
    Force reinstall even if already installed

.PARAMETER SkipApiCheck
    Skip the API duplicate check (useful if API not configured)
#>

param(
    [string]$BaseUrl = "{{cf_screenconnect_baseurl}}",
    [string]$InstanceId = "{{cf_screenconnect_instance_id}}",
    [string]$ApiUser = "{{cf_screenconnect_api_user}}",
    [string]$ApiPassword = "{{cf_screenconnect_api_password}}",
    [string]$LevelGroupPath = "{{level_group_path}}",
    [string]$LevelDeviceId = "{{level_device_id}}",
    [switch]$Force,
    [switch]$SkipApiCheck
)

$ErrorActionPreference = 'Stop'

# ============================================================
# CONFIGURATION
# ============================================================

$RegistryPath = "HKLM:\SOFTWARE\COOLNETWORKS\SystemInfo"
$TempFolder = $env:TEMP

# ============================================================
# HELPER FUNCTIONS
# ============================================================

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $prefix = switch ($Level) {
        "INFO"    { "[INFO]" }
        "WARN"    { "[WARN]" }
        "ERROR"   { "[ERROR]" }
        "SUCCESS" { "[OK]" }
    }

    $color = switch ($Level) {
        "INFO"    { "White" }
        "WARN"    { "Yellow" }
        "ERROR"   { "Red" }
        "SUCCESS" { "Green" }
    }

    Write-Host "$timestamp $prefix $Message" -ForegroundColor $color
}

function Test-ConfigValid {
    param([string]$Value, [string]$Name)

    if ($Value -match '^\{\{') {
        Write-Log "$Name not configured (template variable)" -Level "ERROR"
        return $false
    }
    if ([string]::IsNullOrWhiteSpace($Value)) {
        Write-Log "$Name is empty" -Level "ERROR"
        return $false
    }
    return $true
}

function Get-NormalizedFolderPath {
    param([string]$RawPath)

    # Transform Level.io group path:
    # 1. Replace slashes (with surrounding spaces) with single space
    # 2. Strip leading non-alpha characters
    # 3. Normalize whitespace

    $normalized = $RawPath -replace "\s*/\s*", " "
    $normalized = $normalized -replace '^[^A-Za-z]*', ''
    $normalized = ($normalized -replace '\s+', ' ').Trim()

    return $normalized
}

function Initialize-ScreenConnectApiSession {
    param(
        [string]$User,
        [string]$Password,
        [string]$ServerUrl
    )

    $encodedCredentials = [System.Convert]::ToBase64String(
        [System.Text.Encoding]::ASCII.GetBytes("${User}:${Password}")
    )

    $Headers = @{
        'authorization' = "Basic $encodedCredentials"
        'content-type' = "application/json; charset=utf-8"
        'origin' = $ServerUrl
    }

    # Create session object to handle cookies
    $Session = New-Object Microsoft.PowerShell.Commands.WebRequestSession

    # Authenticate by fetching front page with credentials
    try {
        $FrontPage = Invoke-WebRequest -Uri $ServerUrl -Headers $Headers -WebSession $Session -UseBasicParsing -TimeoutSec 30

        # Check if login succeeded
        $loginResult = $FrontPage.Headers['X-Login-Result']
        if ($loginResult -and $loginResult -notin @('Success', $null)) {
            Write-Log "Authentication failed: $loginResult" -Level "ERROR"
            return $null
        }

        # Extract anti-forgery token
        $Regex = [Regex]'(?<=antiForgeryToken":")(.*)(?=","isUserAdministrator)'
        $Match = $Regex.Match($FrontPage.Content)
        if ($Match.Success) {
            $Headers['x-anti-forgery-token'] = $Match.Value.ToString()
        }

        return @{
            Headers = $Headers
            Session = $Session
            BaseUrl = $ServerUrl
        }
    } catch {
        Write-Log "Failed to initialize API session: $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

function Find-ExistingSessionsByDeviceId {
    param(
        [hashtable]$ApiSession,
        [string]$DeviceId
    )

    Write-Log "Searching for existing sessions with Level Device ID: $DeviceId"

    try {
        # Search by CustomProperty3 (Level Device ID) using GetLiveData endpoint
        $Filter = "CustomProperty3 = '$DeviceId'"
        $BodyObject = @(
            @{
                HostSessionInfo = @{
                    sessionType = 2  # Access
                    sessionGroupPathParts = @("All Machines")
                    filter = $Filter
                    findSessionID = $null
                    sessionLimit = 100
                }
                ActionCenterInfo = @{}
            },
            0
        )
        $Body = ConvertTo-Json $BodyObject -Depth 5

        $ApiUrl = "$($ApiSession.BaseUrl)/Services/PageService.ashx/GetLiveData"
        $Result = Invoke-WebRequest -Uri $ApiUrl -Method Post -Headers $ApiSession.Headers `
            -Body $Body -WebSession $ApiSession.Session -UseBasicParsing -TimeoutSec 30

        $Response = $Result.Content | ConvertFrom-Json
        $Sessions = $Response.ResponseInfoMap.HostSessionInfo.Sessions

        if ($Sessions -and $Sessions.Count -gt 0) {
            Write-Log "Found $($Sessions.Count) existing session(s) with this device ID" -Level "WARN"
            return $Sessions
        } else {
            Write-Log "No existing sessions found with this device ID" -Level "SUCCESS"
            return @()
        }
    } catch {
        Write-Log "API query failed: $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

function Find-ExistingSessionsByHostname {
    param(
        [hashtable]$ApiSession,
        [string]$Hostname
    )

    Write-Log "Searching for existing sessions with hostname: $Hostname"

    try {
        # Search by GuestMachineName using GetLiveData endpoint
        $Filter = "GuestMachineName = '$Hostname'"
        $BodyObject = @(
            @{
                HostSessionInfo = @{
                    sessionType = 2  # Access
                    sessionGroupPathParts = @("All Machines")
                    filter = $Filter
                    findSessionID = $null
                    sessionLimit = 100
                }
                ActionCenterInfo = @{}
            },
            0
        )
        $Body = ConvertTo-Json $BodyObject -Depth 5

        $ApiUrl = "$($ApiSession.BaseUrl)/Services/PageService.ashx/GetLiveData"
        $Result = Invoke-WebRequest -Uri $ApiUrl -Method Post -Headers $ApiSession.Headers `
            -Body $Body -WebSession $ApiSession.Session -UseBasicParsing -TimeoutSec 30

        $Response = $Result.Content | ConvertFrom-Json
        $Sessions = $Response.ResponseInfoMap.HostSessionInfo.Sessions

        if ($Sessions -and $Sessions.Count -gt 0) {
            Write-Log "Found $($Sessions.Count) session(s) matching hostname" -Level "WARN"
            return $Sessions
        } else {
            Write-Log "No sessions found matching hostname" -Level "INFO"
            return @()
        }
    } catch {
        Write-Log "API query failed: $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

function Remove-ScreenConnectSession {
    param(
        [hashtable]$ApiSession,
        [string]$SessionId,
        [string]$SessionName
    )

    Write-Log "Deleting session: $SessionName ($SessionId)"

    try {
        # Parameters: sessionGroupPathOrName, sessionIDs[], eventType, data
        # EventType 21 = End/Delete Session
        $Body = ConvertTo-Json @("All Machines", @($SessionId), 21, "")

        $ApiUrl = "$($ApiSession.BaseUrl)/Services/PageService.ashx/AddEventToSessions"
        $null = Invoke-WebRequest -Uri $ApiUrl -Method Post -Headers $ApiSession.Headers `
            -Body $Body -WebSession $ApiSession.Session -UseBasicParsing -TimeoutSec 30

        Write-Log "Session deleted successfully" -Level "SUCCESS"
        return $true
    } catch {
        Write-Log "Failed to delete session: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Test-LocalScreenConnectInstalled {
    param([string]$InstanceId)

    $services = Get-ChildItem HKLM:\SYSTEM\ControlSet001\Services -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -like "*ScreenConnect Client*$InstanceId*" }

    return ($null -ne $services -and $services.Count -gt 0)
}

function Get-LocalScreenConnectGuid {
    param([string]$InstanceId)

    $services = Get-ChildItem HKLM:\SYSTEM\ControlSet001\Services -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -like "*ScreenConnect Client*$InstanceId*" }

    if ($services) {
        $svcName = $services[0].PSChildName
        $props = Get-ItemProperty "HKLM:\SYSTEM\ControlSet001\Services\$svcName" -ErrorAction SilentlyContinue
        $imagePath = $props.ImagePath

        if ($imagePath -match '&s=([^&]+)') {
            return $Matches[1]
        }
    }

    return $null
}

function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [string]$Value
    )

    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }

    Set-ItemProperty -Path $Path -Name $Name -Value $Value
    Write-Log "Registry set: $Name = $Value" -Level "SUCCESS"
}

function Install-ScreenConnectMsi {
    param(
        [string]$BaseUrl,
        [string]$CompanyName,
        [string]$LevelDeviceId
    )

    # URL encode custom properties
    $CP1 = [uri]::EscapeDataString($CompanyName)
    $CP3 = [uri]::EscapeDataString($LevelDeviceId)

    # Build MSI URL with custom properties
    # c= parameters are positional: CP1, CP2, CP3, CP4, CP5, CP6, CP7, CP8
    $MsiUrl = "$BaseUrl/Bin/ScreenConnect.ClientSetup.msi?e=Access&y=Guest&c=$CP1&c=&c=$CP3&c=&c=&c=&c=&c="

    Write-Log "MSI URL: $MsiUrl"
    Write-Log "  CustomProperty1 (Company): $CompanyName"
    Write-Log "  CustomProperty3 (Level ID): $LevelDeviceId"

    $MsiPath = Join-Path $TempFolder "ScreenConnect.ClientSetup.msi"

    # Download MSI
    Write-Log "Downloading MSI..."
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $MsiUrl -OutFile $MsiPath -UseBasicParsing -TimeoutSec 120
        Write-Log "MSI downloaded to: $MsiPath" -Level "SUCCESS"
    } catch {
        Write-Log "Failed to download MSI: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }

    # Install MSI
    Write-Log "Installing ScreenConnect..."
    try {
        $process = Start-Process -FilePath "msiexec.exe" `
            -ArgumentList "/i `"$MsiPath`" /qn /norestart" `
            -Wait -PassThru

        if ($process.ExitCode -eq 0) {
            Write-Log "ScreenConnect installed successfully" -Level "SUCCESS"
            return $true
        } else {
            Write-Log "MSI install returned exit code: $($process.ExitCode)" -Level "ERROR"
            return $false
        }
    } catch {
        Write-Log "Failed to install MSI: $($_.Exception.Message)" -Level "ERROR"
        return $false
    } finally {
        # Cleanup
        if (Test-Path $MsiPath) {
            Remove-Item $MsiPath -Force -ErrorAction SilentlyContinue
        }
    }
}

# ============================================================
# MAIN SCRIPT
# ============================================================

Write-Log "=========================================="
Write-Log "ScreenConnect Install Script"
Write-Log "=========================================="
Write-Log ""

# Validate configuration
Write-Log "Validating configuration..."

$configValid = $true
$configValid = (Test-ConfigValid -Value $BaseUrl -Name "BaseUrl") -and $configValid
$configValid = (Test-ConfigValid -Value $InstanceId -Name "InstanceId") -and $configValid
$configValid = (Test-ConfigValid -Value $LevelGroupPath -Name "LevelGroupPath") -and $configValid
$configValid = (Test-ConfigValid -Value $LevelDeviceId -Name "LevelDeviceId") -and $configValid

$apiConfigured = $true
if (-not (Test-ConfigValid -Value $ApiUser -Name "ApiUser")) { $apiConfigured = $false }
if (-not (Test-ConfigValid -Value $ApiPassword -Name "ApiPassword")) { $apiConfigured = $false }

if (-not $configValid) {
    Write-Log "Required configuration missing. Cannot proceed." -Level "ERROR"
    exit 1
}

if (-not $apiConfigured -and -not $SkipApiCheck) {
    Write-Log "API credentials not configured. Use -SkipApiCheck to proceed without duplicate cleanup." -Level "WARN"
    $SkipApiCheck = $true
}

# Normalize the Level folder path
$NormalizedPath = Get-NormalizedFolderPath -RawPath $LevelGroupPath
Write-Log "Level Group Path: $LevelGroupPath"
Write-Log "Normalized Path:  $NormalizedPath"

# Check if already installed
$alreadyInstalled = Test-LocalScreenConnectInstalled -InstanceId $InstanceId
if ($alreadyInstalled -and -not $Force) {
    Write-Log "ScreenConnect is already installed for this instance" -Level "SUCCESS"
    Write-Log "Use -Force to reinstall"

    # Still update registry with current path
    Set-RegistryValue -Path $RegistryPath -Name "LevelFolderPath" -Value $NormalizedPath
    exit 0
}

if ($alreadyInstalled -and $Force) {
    Write-Log "Force reinstall requested - will uninstall existing first" -Level "WARN"
}

# API duplicate check and cleanup
if (-not $SkipApiCheck) {
    Write-Log ""
    Write-Log "=========================================="
    Write-Log "Pre-Install API Check"
    Write-Log "=========================================="

    $ApiSession = Initialize-ScreenConnectApiSession -User $ApiUser -Password $ApiPassword -ServerUrl $BaseUrl

    if ($null -eq $ApiSession) {
        Write-Log "Failed to initialize API session - proceeding without cleanup" -Level "WARN"
    } else {
        Write-Log "API session initialized successfully" -Level "SUCCESS"

        # First, search by Level Device ID (most reliable)
        $existingByDeviceId = Find-ExistingSessionsByDeviceId -ApiSession $ApiSession -DeviceId $LevelDeviceId

        if ($null -eq $existingByDeviceId) {
            Write-Log "API check failed - proceeding without cleanup" -Level "WARN"
        } elseif ($existingByDeviceId.Count -gt 0) {
            Write-Log ""
            Write-Log "Found duplicate sessions to clean up:"
            foreach ($session in $existingByDeviceId) {
                Write-Log "  - $($session.Name) | $($session.GuestMachineName) | ID: $($session.SessionID)"
            }

            Write-Log ""
            Write-Log "Deleting duplicate sessions..."
            foreach ($session in $existingByDeviceId) {
                $deleted = Remove-ScreenConnectSession -ApiSession $ApiSession `
                    -SessionId $session.SessionID -SessionName $session.Name

                if (-not $deleted) {
                    Write-Log "Warning: Failed to delete session $($session.SessionID)" -Level "WARN"
                }
            }

            # Brief pause for server to process deletions
            Start-Sleep -Seconds 2
        }

        # Also check by hostname as fallback (catch sessions without Level ID)
        $existingByHostname = Find-ExistingSessionsByHostname -ApiSession $ApiSession -Hostname $env:COMPUTERNAME

        if ($existingByHostname -and $existingByHostname.Count -gt 0) {
            # Filter out any we already deleted
            $alreadyDeleted = $existingByDeviceId | ForEach-Object { $_.SessionID }
            $remaining = $existingByHostname | Where-Object { $_.SessionID -notin $alreadyDeleted }

            if ($remaining.Count -gt 0) {
                Write-Log ""
                Write-Log "Found additional sessions by hostname (no Level ID match):"
                foreach ($session in $remaining) {
                    Write-Log "  - $($session.Name) | CP3: $($session.CustomProperty3)"
                }

                # Only delete these if they don't have a different Level Device ID
                foreach ($session in $remaining) {
                    if ([string]::IsNullOrWhiteSpace($session.CustomProperty3)) {
                        Write-Log "Deleting orphaned session: $($session.Name)" -Level "WARN"
                        Remove-ScreenConnectSession -ApiSession $ApiSession `
                            -SessionId $session.SessionID -SessionName $session.Name
                    } else {
                        Write-Log "Skipping session with different Level ID: $($session.CustomProperty3)" -Level "INFO"
                    }
                }
            }
        }
    }
}

# Uninstall existing if Force
if ($alreadyInstalled -and $Force) {
    Write-Log ""
    Write-Log "=========================================="
    Write-Log "Uninstalling Existing Installation"
    Write-Log "=========================================="

    # Stop services
    $services = Get-Service | Where-Object { $_.DisplayName -like "*ScreenConnect*$InstanceId*" }
    foreach ($svc in $services) {
        Write-Log "Stopping service: $($svc.DisplayName)"
        Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
    }

    # Run uninstaller
    $scFolders = Get-Item -Path "${env:ProgramFiles}\ScreenConnect Client*$InstanceId*" -ErrorAction SilentlyContinue
    foreach ($folder in $scFolders) {
        $uninstaller = Join-Path $folder.FullName "ScreenConnect.ClientService.exe"
        if (Test-Path $uninstaller) {
            Write-Log "Running uninstaller: $uninstaller"
            Start-Process -FilePath $uninstaller -ArgumentList "?e=Uninstall" -Wait -ErrorAction SilentlyContinue
        }
    }

    Start-Sleep -Seconds 3
}

# Install ScreenConnect
Write-Log ""
Write-Log "=========================================="
Write-Log "Installing ScreenConnect"
Write-Log "=========================================="

$installSuccess = Install-ScreenConnectMsi -BaseUrl $BaseUrl -CompanyName $NormalizedPath -LevelDeviceId $LevelDeviceId

if (-not $installSuccess) {
    Write-Log "ScreenConnect installation failed" -Level "ERROR"
    exit 1
}

# Store Level folder path in registry
Write-Log ""
Write-Log "=========================================="
Write-Log "Updating Registry"
Write-Log "=========================================="

Set-RegistryValue -Path $RegistryPath -Name "LevelFolderPath" -Value $NormalizedPath
Set-RegistryValue -Path $RegistryPath -Name "LevelDeviceId" -Value $LevelDeviceId

# Verify installation
Write-Log ""
Write-Log "=========================================="
Write-Log "Verifying Installation"
Write-Log "=========================================="

Start-Sleep -Seconds 5

$verified = Test-LocalScreenConnectInstalled -InstanceId $InstanceId
if ($verified) {
    $guid = Get-LocalScreenConnectGuid -InstanceId $InstanceId
    Write-Log "ScreenConnect installed and verified" -Level "SUCCESS"
    Write-Log "  Instance ID: $InstanceId"
    Write-Log "  Session GUID: $guid"
    Write-Log "  Company (CP1): $NormalizedPath"
    Write-Log "  Level ID (CP3): $LevelDeviceId"
    exit 0
} else {
    Write-Log "Installation verification failed - service not found" -Level "ERROR"
    exit 1
}
