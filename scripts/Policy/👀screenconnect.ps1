<#
.SYNOPSIS
    Software policy enforcement for ScreenConnect (ConnectWise Control).

.DESCRIPTION
    Implements the COOLForge 5-tag policy model for ScreenConnect client management.
    See docs/POLICY-TAGS.md for the complete policy specification.

    POLICY FLOW (per POLICY-TAGS.md):
    1. Check global control tags (device must have checkmark to be managed)
    2. Check software-specific override tags (highest priority)
    3. Fall back to custom field policy (policy_screenconnect)
    4. Execute resolved action (install/remove/reinstall)

    GLOBAL CONTROL TAGS (standalone):
    - U+2705 = Device is managed (required to process)
    - U+274C = Device is excluded from management
    - Both = Device is globally pinned (no changes)

    SOFTWARE-SPECIFIC OVERRIDE TAGS (with "sc" suffix):
    - U+1F64F sc = Install if missing (transient)
    - U+1F6AB sc = Remove if present (transient)
    - U+1F4CC sc = Pin - no changes allowed (persistent)
    - U+1F504 sc = Reinstall - remove + install (transient)
    - U+2705 sc  = Status: software is installed (set by script)

    CUSTOM FIELD POLICY (inherited Group->Folder->Device):
    - policy_screenconnect = "install" | "remove" | "pin" | ""

.NOTES
    Version:          2026.01.19.01
    Target Platform:  Level.io RMM (via Script Launcher)
    Exit Codes:       0 = Success | 1 = Alert (Failure)

    Level.io Variables Used (passed from Script Launcher):
    - $MspScratchFolder   : MSP-defined scratch folder for persistent storage
    - $DeviceHostname     : Device hostname from Level.io
    - $DeviceTags         : Comma-separated list of device tags

    Custom Fields:
    - $policy_screenconnect            : Policy action (install/remove/pin)
    - $policy_screenconnect_instance   : ScreenConnect instance name (service display name)
    - $policy_screenconnect_baseurl    : ScreenConnect server base URL (e.g., support.company.com)

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# Software Policy - ScreenConnect
# Version: 2026.01.19.01
# Target: Level.io (via Script Launcher)
# Exit 0 = Success | Exit 1 = Alert (Failure)
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge

# ============================================================
# CONFIGURATION
# ============================================================
$SoftwareName = "screenconnect"  # Used for custom fields (policy_screenconnect)
$TagName = "sc"                   # Used for tags (SC)
$LockFileName = "ScreenConnect_Deployment.lock"

# Retry settings for communication checks
$RetryIntervalSeconds = 60
$MaxRetries = 3
$MinMsiSizeKB = 100

# ScreenConnect configuration from custom fields
$InstanceNameVar = "policy_screenconnect_instance"
$InstanceName = Get-Variable -Name $InstanceNameVar -ValueOnly -ErrorAction SilentlyContinue
if ([string]::IsNullOrWhiteSpace($InstanceName) -or $InstanceName -like "{{*}}") {
    $InstanceName = $null
}

$BaseUrlVar = "policy_screenconnect_baseurl"
$BaseUrl = Get-Variable -Name $BaseUrlVar -ValueOnly -ErrorAction SilentlyContinue
if ([string]::IsNullOrWhiteSpace($BaseUrl) -or $BaseUrl -like "{{*}}") {
    $BaseUrl = $null
} else {
    # Clean up base URL
    $BaseUrl = $BaseUrl -replace '^https?://', ''
    $BaseUrl = $BaseUrl.TrimEnd('/')
}

# Company name from Level.io group path (flattened)
$CompanyName = $null
$GroupPath = Get-Variable -Name "level_group_path" -ValueOnly -ErrorAction SilentlyContinue
if (-not [string]::IsNullOrWhiteSpace($GroupPath) -and $GroupPath -notlike "{{*}}") {
    $CompanyName = ($GroupPath -replace "\s*/\s*", " ").Trim()
}

# ============================================================
# DEBUG OUTPUT HELPER (Software-specific)
# ============================================================

function Write-DebugInstallCheck {
    param([bool]$IsInstalled, [string]$ServiceStatus, [bool]$IsCommunicating)
    if (-not $DebugScripts) { return }

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " DEBUG: Installation Check" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    Write-Host "  --- Service Detection ---"
    if ($InstanceName) {
        Write-Host "  Expected Instance: $InstanceName" -ForegroundColor Gray
    } else {
        Write-Host "  Expected Instance: (not configured - checking any ScreenConnect)" -ForegroundColor Yellow
    }

    $Services = Get-Service | Where-Object {
        $_.Name -like "*ScreenConnect*" -or
        $_.DisplayName -like "*ScreenConnect*" -or
        $_.DisplayName -like "*ConnectWise Control*"
    }

    if ($Services) {
        foreach ($Svc in $Services) {
            $StatusColor = if ($Svc.Status -eq 'Running') { 'Green' } else { 'Yellow' }
            $MatchNote = if ($InstanceName -and $Svc.DisplayName -eq $InstanceName) { " [MATCHES INSTANCE]" } else { "" }
            Write-Host "  [FOUND] $($Svc.DisplayName) - $($Svc.Status)$MatchNote" -ForegroundColor $StatusColor
        }
    } else {
        Write-Host "  [    ] No ScreenConnect services found" -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "  SERVICE STATUS: $ServiceStatus" -ForegroundColor $(if ($ServiceStatus -eq 'Running') { 'Green' } elseif ($ServiceStatus -eq 'Stopped') { 'Yellow' } else { 'DarkGray' })
    Write-Host "  COMMUNICATING: $(if ($IsCommunicating) { 'YES' } else { 'NO' })" -ForegroundColor $(if ($IsCommunicating) { 'Green' } else { 'Yellow' })
    Write-Host "  SOFTWARE INSTALLED: $(if ($IsInstalled) { 'YES' } else { 'NO' })" -ForegroundColor $(if ($IsInstalled) { 'Green' } else { 'Yellow' })
}

# ============================================================
# INITIALIZE
# ============================================================
$Init = Initialize-LevelScript -ScriptName "Policy-$SoftwareName" `
                               -MspScratchFolder $MspScratchFolder `
                               -DeviceHostname $DeviceHostname `
                               -DeviceTags $DeviceTags

if (-not $Init.Success) {
    exit 0
}

# ============================================================
# LOCKFILE MANAGEMENT
# ============================================================
$LockFilePath = Join-Path -Path $MspScratchFolder -ChildPath "lockfiles"
$LockFile = Join-Path -Path $LockFilePath -ChildPath $LockFileName

if (!(Test-Path $LockFilePath)) {
    New-Item -Path $LockFilePath -ItemType Directory -Force | Out-Null
}

if (Test-Path $LockFile) {
    $LockContent = Get-Content -Path $LockFile -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
    if ($LockContent.PID) {
        $ExistingProcess = Get-Process -Id $LockContent.PID -ErrorAction SilentlyContinue
        if ($ExistingProcess) {
            Write-LevelLog "Script already running (PID: $($LockContent.PID)). Exiting gracefully."
            exit 0
        }
    }
    Remove-Item -Path $LockFile -Force -ErrorAction SilentlyContinue
}

$LockData = @{
    PID       = $PID
    StartedAt = (Get-Date).ToString("o")
    Hostname  = $env:COMPUTERNAME
} | ConvertTo-Json
Set-Content -Path $LockFile -Value $LockData -Force

function Remove-Lock {
    Remove-Item -Path $LockFile -Force -ErrorAction SilentlyContinue
}

# ============================================================
# SCREENCONNECT-SPECIFIC FUNCTIONS
# ============================================================

function Get-ScreenConnectService {
    <#
    .SYNOPSIS
        Finds the ScreenConnect service, preferring exact match to instance name.
    #>
    try {
        if ($InstanceName) {
            # Try exact match first
            $svc = Get-Service | Where-Object { $_.DisplayName -eq $InstanceName }
            if ($svc) { return $svc | Select-Object -First 1 }
        }

        # Fallback to pattern match
        $svc = Get-Service | Where-Object {
            $_.DisplayName -like "ScreenConnect Client*" -or
            $_.DisplayName -like "ConnectWise Control Client*"
        }
        return $svc | Select-Object -First 1
    } catch {
        Write-LevelLog "Failed to query services: $($_.Exception.Message)" -Level "WARN"
        return $null
    }
}

function Get-ServiceProcessId {
    <#
    .SYNOPSIS
        Gets the process ID of the ScreenConnect service.
    #>
    param([string]$ServiceDisplayName)
    try {
        $cim = Get-CimInstance Win32_Service | Where-Object { $_.DisplayName -eq $ServiceDisplayName }
        if (-not $cim) {
            $cim = Get-CimInstance Win32_Service | Where-Object {
                $_.DisplayName -like "ScreenConnect Client*" -or
                $_.DisplayName -like "ConnectWise Control Client*"
            }
        }
        $pid = ($cim | Select-Object -First 1).ProcessId
        if ($null -eq $pid) { return 0 }
        return [int]$pid
    } catch {
        return 0
    }
}

function Test-ScreenConnectCommunicating {
    <#
    .SYNOPSIS
        Tests if the ScreenConnect service has established TCP connections.
    #>
    param([int]$SvcPid)
    try {
        if ($SvcPid -le 0) { return $false }
        $netConnections = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.OwningProcess -eq $SvcPid }
        $established = $netConnections | Where-Object { $_.State -eq 'Established' }
        $count = ($established | Measure-Object).Count

        if ($DebugScripts) {
            Write-Host "  [DEBUG] PID $SvcPid has $count established TCP connection(s)" -ForegroundColor Gray
            foreach ($conn in $established) {
                Write-Host "    - $($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort)" -ForegroundColor DarkGray
            }
        }

        return ($count -gt 0)
    } catch {
        Write-LevelLog "Communication check failed: $($_.Exception.Message)" -Level "WARN"
        return $false
    }
}

function Test-ScreenConnectInstalled {
    <#
    .SYNOPSIS
        Checks if ScreenConnect is installed and returns installation info.
    .RETURNS
        Hashtable with IsInstalled, Service, ServiceStatus, IsCommunicating
    #>
    $result = @{
        IsInstalled = $false
        Service = $null
        ServiceStatus = "NotFound"
        IsCommunicating = $false
    }

    $service = Get-ScreenConnectService
    if ($service) {
        $result.IsInstalled = $true
        $result.Service = $service
        $result.ServiceStatus = $service.Status.ToString()

        if ($service.Status -eq 'Running') {
            $svcPid = Get-ServiceProcessId -ServiceDisplayName $service.DisplayName
            if ($svcPid -gt 0) {
                $result.IsCommunicating = Test-ScreenConnectCommunicating -SvcPid $svcPid
            }
        }
    }

    return $result
}

function Test-ScreenConnectHealthy {
    <#
    .SYNOPSIS
        Checks if ScreenConnect is running and communicating.
    #>
    $state = Test-ScreenConnectInstalled
    return ($state.IsInstalled -and $state.ServiceStatus -eq 'Running' -and $state.IsCommunicating)
}

function Repair-ScreenConnectService {
    <#
    .SYNOPSIS
        Attempts to restart the ScreenConnect service and wait for communication.
    .RETURNS
        $true if service becomes healthy, $false otherwise.
    #>
    $service = Get-ScreenConnectService
    if (-not $service) {
        Write-LevelLog "No ScreenConnect service to repair" -Level "WARN"
        return $false
    }

    Write-LevelLog "Attempting to repair service: $($service.DisplayName)"

    # Try restart
    try {
        Stop-Service -Name $service.Name -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        Start-Service -Name $service.Name -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
    } catch {
        Write-LevelLog "Service restart failed: $($_.Exception.Message)" -Level "WARN"
    }

    # Wait for communication with retries
    for ($i = 1; $i -le $MaxRetries; $i++) {
        Write-LevelLog "Checking communication (attempt $i of $MaxRetries)..."

        $service.Refresh()
        if ($service.Status -eq 'Running') {
            $svcPid = Get-ServiceProcessId -ServiceDisplayName $service.DisplayName
            if ($svcPid -gt 0 -and (Test-ScreenConnectCommunicating -SvcPid $svcPid)) {
                Write-LevelLog "Service is now communicating" -Level "SUCCESS"
                return $true
            }
        }

        if ($i -lt $MaxRetries) {
            Write-LevelLog "Not communicating yet, waiting $RetryIntervalSeconds seconds..."
            Start-Sleep -Seconds $RetryIntervalSeconds
        }
    }

    Write-LevelLog "Service failed to establish communication after $MaxRetries attempts" -Level "WARN"
    return $false
}

function Install-ScreenConnect {
    <#
    .SYNOPSIS
        Downloads and installs the ScreenConnect client.
    #>
    param([string]$ScratchFolder)

    # Validate configuration
    if ([string]::IsNullOrWhiteSpace($BaseUrl)) {
        Write-Host "Alert: ScreenConnect install failed - policy_screenconnect_baseurl not configured"
        Write-LevelLog "Base URL not configured - set policy_screenconnect_baseurl custom field" -Level "ERROR"
        return $false
    }

    if ([string]::IsNullOrWhiteSpace($InstanceName)) {
        Write-Host "Alert: ScreenConnect install failed - policy_screenconnect_instance not configured"
        Write-LevelLog "Instance name not configured - set policy_screenconnect_instance custom field" -Level "ERROR"
        return $false
    }

    Write-LevelLog "Base URL: $BaseUrl"
    Write-LevelLog "Instance: $InstanceName"
    Write-LevelLog "Company: $(if ($CompanyName) { $CompanyName } else { '(not set)' })"

    # Ensure TLS 1.2
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch {
        Write-LevelLog "TLS 1.2 hint failed: $($_.Exception.Message)" -Level "WARN"
    }

    # Build download URL
    $encodedCompany = if ($CompanyName) { [uri]::EscapeDataString($CompanyName) } else { "" }
    $downloadUrl = "https://$BaseUrl/Bin/ScreenConnect.ClientSetup.msi?e=Access&y=Guest&c=$encodedCompany"
    $downloadPath = Join-Path $ScratchFolder "ScreenConnect.ClientSetup.msi"

    Write-LevelLog "Download URL: $downloadUrl"

    # Download MSI
    $downloadSuccess = $false
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            Write-LevelLog "Downloading MSI (attempt $attempt of $MaxRetries)..."
            if (Test-Path $downloadPath) {
                Remove-Item $downloadPath -Force -ErrorAction SilentlyContinue
            }
            Invoke-WebRequest -Uri $downloadUrl -OutFile $downloadPath -TimeoutSec 120 -UseBasicParsing
            $downloadSuccess = $true
            break
        } catch {
            Write-LevelLog "Download attempt $attempt failed: $($_.Exception.Message)" -Level "WARN"
            if ($attempt -lt $MaxRetries) {
                Start-Sleep -Seconds 10
            }
        }
    }

    if (-not $downloadSuccess) {
        Write-Host "Alert: Failed to download ScreenConnect installer after $MaxRetries attempts"
        Write-LevelLog "All download attempts failed" -Level "ERROR"
        return $false
    }

    # Validate MSI size
    if (-not (Test-Path $downloadPath)) {
        Write-Host "Alert: Installer file not found after download"
        Write-LevelLog "Installer not found after download" -Level "ERROR"
        return $false
    }

    $fileSize = (Get-Item $downloadPath).Length
    if ($fileSize -lt ($MinMsiSizeKB * 1024)) {
        Write-Host "Alert: Downloaded MSI is too small ($fileSize bytes) - may be invalid"
        Write-LevelLog "MSI file too small: $fileSize bytes" -Level "ERROR"
        return $false
    }

    Write-LevelLog "Downloaded MSI: $fileSize bytes"

    # Install
    try {
        Write-LevelLog "Installing ScreenConnect client..."
        $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList @("/i", "`"$downloadPath`"", "/qn", "/norestart") -PassThru -Wait
        Write-LevelLog "Installer exit code: $($proc.ExitCode)"
    } catch {
        Write-Host "Alert: Failed to install ScreenConnect client"
        Write-LevelLog "Installation failed: $($_.Exception.Message)" -Level "ERROR"
        Remove-Item $downloadPath -Force -ErrorAction SilentlyContinue
        return $false
    }

    # Cleanup installer
    Remove-Item $downloadPath -Force -ErrorAction SilentlyContinue

    # Wait for service to start
    Write-LevelLog "Waiting for service to start..."
    Start-Sleep -Seconds 10

    # Verify installation and communication
    $state = Test-ScreenConnectInstalled
    if (-not $state.IsInstalled) {
        Write-Host "Alert: ScreenConnect installation verification failed - service not found"
        Write-LevelLog "Installation verification failed - service not found" -Level "ERROR"
        return $false
    }

    Write-LevelLog "Service found: $($state.Service.DisplayName) ($($state.ServiceStatus))"

    if ($state.ServiceStatus -ne 'Running') {
        Write-LevelLog "Service not running - attempting to start..."
        try {
            Start-Service -Name $state.Service.Name -ErrorAction Stop
            Start-Sleep -Seconds 5
            $state = Test-ScreenConnectInstalled
        } catch {
            Write-LevelLog "Failed to start service: $($_.Exception.Message)" -Level "WARN"
        }
    }

    # Check communication
    if ($state.IsCommunicating) {
        Write-LevelLog "ScreenConnect installed and communicating" -Level "SUCCESS"
        return $true
    }

    # Not communicating - try repair
    Write-LevelLog "Service installed but not communicating - attempting repair..." -Level "WARN"
    $repaired = Repair-ScreenConnectService
    if ($repaired) {
        Write-LevelLog "ScreenConnect installed successfully" -Level "SUCCESS"
        return $true
    }

    Write-Host "Alert: ScreenConnect installed but not communicating"
    Write-LevelLog "Installation complete but service not communicating" -Level "WARN"
    return $true  # Still consider it "installed" even if not communicating
}

function Remove-ScreenConnect {
    <#
    .SYNOPSIS
        Uninstalls ScreenConnect client.
    #>
    Write-LevelLog "Starting ScreenConnect removal..."

    # Stop processes
    Write-LevelLog "Stopping ScreenConnect processes..."
    Get-Process -Name "ScreenConnect*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    # Find and uninstall via registry
    $uninstallRoots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )

    $uninstalled = $false
    foreach ($root in $uninstallRoots) {
        try {
            $items = Get-ChildItem -Path $root -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                $props = Get-ItemProperty -Path $item.PSPath -ErrorAction SilentlyContinue
                if ($props.DisplayName -and (
                    $props.DisplayName -like "ScreenConnect Client*" -or
                    $props.DisplayName -like "ConnectWise Control Client*" -or
                    ($InstanceName -and $props.DisplayName -eq $InstanceName)
                )) {
                    Write-LevelLog "Found: $($props.DisplayName)"

                    $uninstallString = $props.UninstallString
                    if ($uninstallString -match '\{[0-9A-Fa-f\-]{36}\}') {
                        $guid = $Matches[0]
                        Write-LevelLog "Uninstalling via GUID: $guid"
                        $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList @("/x", $guid, "/qn", "/norestart") -PassThru -Wait
                        Write-LevelLog "Uninstaller exit code: $($proc.ExitCode)"
                        $uninstalled = $true
                    } elseif ($uninstallString) {
                        Write-LevelLog "Running uninstall string..."
                        $parts = $uninstallString -split '\s+', 2
                        $exe = $parts[0]
                        $args = if ($parts.Count -gt 1) { $parts[1] } else { "" }
                        Start-Process -FilePath $exe -ArgumentList $args -Wait -ErrorAction SilentlyContinue
                        $uninstalled = $true
                    }
                }
            }
        } catch {
            Write-LevelLog "Error searching registry: $($_.Exception.Message)" -Level "WARN"
        }
    }

    # Also try direct uninstaller if present
    $folderLocations = @(
        "${env:ProgramFiles}\ScreenConnect Client*",
        "${env:ProgramFiles(x86)}\ScreenConnect Client*"
    )
    foreach ($pattern in $folderLocations) {
        $folders = Get-Item -Path $pattern -ErrorAction SilentlyContinue
        foreach ($folder in $folders) {
            $uninstaller = Join-Path $folder.FullName "ScreenConnect.ClientService.exe"
            if (Test-Path $uninstaller) {
                Write-LevelLog "Running direct uninstaller: $uninstaller"
                Start-Process -FilePath $uninstaller -ArgumentList "?e=Uninstall" -Wait -ErrorAction SilentlyContinue
                $uninstalled = $true
            }
        }
    }

    Start-Sleep -Seconds 3

    # Cleanup leftover folders
    foreach ($pattern in $folderLocations) {
        $folders = Get-Item -Path $pattern -ErrorAction SilentlyContinue
        foreach ($folder in $folders) {
            Write-LevelLog "Removing folder: $($folder.FullName)"
            Remove-Item $folder.FullName -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # Remove services
    $services = Get-Service | Where-Object {
        $_.Name -like "*ScreenConnect*" -or
        $_.DisplayName -like "*ScreenConnect*" -or
        $_.DisplayName -like "*ConnectWise Control*"
    }
    foreach ($svc in $services) {
        Write-LevelLog "Removing service: $($svc.Name)"
        Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
        & sc.exe delete $svc.Name 2>$null
    }

    # Verify removal
    Start-Sleep -Seconds 2
    $state = Test-ScreenConnectInstalled
    if ($state.IsInstalled) {
        Write-LevelLog "Removal verification failed - ScreenConnect still present" -Level "ERROR"
        return $false
    }

    Write-LevelLog "ScreenConnect removed successfully" -Level "SUCCESS"
    return $true
}

# ============================================================
# MAIN SCRIPT LOGIC
# ============================================================
$ScriptVersion = "2026.01.19.01"
$ExitCode = 0

$InvokeParams = @{ ScriptBlock = {

    Write-LevelLog "Policy Enforcement: $SoftwareName (v$ScriptVersion)"

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
        'InstanceName' = if ($InstanceName) { $InstanceName } else { '(not set)' }
        'BaseUrl' = if ($BaseUrl) { $BaseUrl } else { '(not set)' }
        'CompanyName' = if ($CompanyName) { $CompanyName } else { '(not set)' }
    } -MaskApiKey

    Write-Host ""

    # Get custom field policy if available
    $CustomFieldPolicyVar = "policy_$SoftwareName"
    $CustomFieldPolicy = Get-Variable -Name $CustomFieldPolicyVar -ValueOnly -ErrorAction SilentlyContinue
    if ($CustomFieldPolicy) {
        Write-LevelLog "Custom field policy: $CustomFieldPolicy"
    }

    # Debug: Show custom field policy
    Write-DebugSection -Title "Custom Field Policy" -Data @{
        "policy_$SoftwareName" = $CustomFieldPolicy
    }

    # Debug: Analyze device tags
    Write-DebugTags -TagString $DeviceTags -SoftwareName $TagName

    # ============================================================
    # AUTO-BOOTSTRAP: Ensure policy infrastructure exists
    # ============================================================
    if ($LevelApiKey) {
        $KeyLength = $LevelApiKey.Length
        $KeyPreview = if ($KeyLength -gt 4) { $LevelApiKey.Substring(0, 4) + "****" } else { "(invalid)" }
        Write-LevelLog "API key: $KeyPreview (length: $KeyLength)" -Level "DEBUG"

        # Use $TagName for tags (creates SC tags) but create custom fields manually
        $InfraResult = Initialize-SoftwarePolicyInfrastructure -ApiKey $LevelApiKey `
            -SoftwareName $TagName `
            -RequireUrl $false

        # Create ScreenConnect-specific custom fields (using "screenconnect" not "sc")
        $ScFieldsCreated = 0

        # Main policy field
        $PolicyFieldName = "policy_screenconnect"
        $ExistingPolicyField = Find-LevelCustomField -ApiKey $LevelApiKey -FieldName $PolicyFieldName
        if (-not $ExistingPolicyField) {
            $NewField = New-LevelCustomField -ApiKey $LevelApiKey -Name $PolicyFieldName -DefaultValue "pin | uses pin/install/remove (change to activate policy)"
            if ($NewField) {
                Write-LevelLog "Created custom field: $PolicyFieldName" -Level "SUCCESS"
                $ScFieldsCreated++
            }
        }

        $InstanceFieldName = "policy_screenconnect_instance"
        $ExistingInstanceField = Find-LevelCustomField -ApiKey $LevelApiKey -FieldName $InstanceFieldName
        if (-not $ExistingInstanceField) {
            $NewField = New-LevelCustomField -ApiKey $LevelApiKey -Name $InstanceFieldName -DefaultValue ""
            if ($NewField) {
                Write-LevelLog "Created custom field: $InstanceFieldName" -Level "SUCCESS"
                $ScFieldsCreated++
            }
        }

        $BaseUrlFieldName = "policy_screenconnect_baseurl"
        $ExistingBaseUrlField = Find-LevelCustomField -ApiKey $LevelApiKey -FieldName $BaseUrlFieldName
        if (-not $ExistingBaseUrlField) {
            $NewField = New-LevelCustomField -ApiKey $LevelApiKey -Name $BaseUrlFieldName -DefaultValue ""
            if ($NewField) {
                Write-LevelLog "Created custom field: $BaseUrlFieldName" -Level "SUCCESS"
                $ScFieldsCreated++
            }
        }

        $TotalFieldsCreated = $InfraResult.FieldsCreated + $ScFieldsCreated

        if ($InfraResult.Success) {
            if ($InfraResult.TagsCreated -gt 0 -or $TotalFieldsCreated -gt 0) {
                Write-LevelLog "Created $($InfraResult.TagsCreated) tags, $TotalFieldsCreated fields" -Level "SUCCESS"
                Write-Host ""
                Write-Host "Alert: Policy infrastructure created - please configure custom fields"
                Write-Host "  Set the following custom fields in Level.io:"
                Write-Host "  - policy_screenconnect: Set to 'install', 'remove', or 'pin' at Group/Folder/Device level"
                Write-Host "  - policy_screenconnect_instance: The ScreenConnect service display name"
                Write-Host "  - policy_screenconnect_baseurl: Your ScreenConnect server URL (e.g., support.company.com)"
                Write-Host ""
                Write-LevelLog "Infrastructure created - exiting for configuration" -Level "INFO"
                Remove-Lock
                $script:ExitCode = 1
                return 1
            }
        }
        else {
            Write-LevelLog "Infrastructure setup warning: $($InfraResult.Error)" -Level "WARN"
        }
    }

    # Check current installation state
    $State = Test-ScreenConnectInstalled
    $IsInstalled = $State.IsInstalled
    Write-LevelLog "Current state: $(if ($IsInstalled) { "Installed ($($State.Service.DisplayName) - $($State.ServiceStatus))" } else { 'Not installed' })"
    if ($IsInstalled -and $State.IsCommunicating) {
        Write-LevelLog "Communication: OK" -Level "SUCCESS"
    } elseif ($IsInstalled) {
        Write-LevelLog "Communication: NOT ESTABLISHED" -Level "WARN"
    }

    # Debug: Show installation check details
    Write-DebugInstallCheck -IsInstalled $IsInstalled -ServiceStatus $State.ServiceStatus -IsCommunicating $State.IsCommunicating

    Write-Host ""

    # Run the policy check with the 5-tag model
    if ($DebugScripts) {
        Write-Host ""
        Write-Host "============================================================" -ForegroundColor Cyan
        Write-Host " DEBUG: Get-SoftwarePolicy Internal Trace" -ForegroundColor Cyan
        Write-Host "============================================================" -ForegroundColor Cyan
        $null = Get-SoftwarePolicy -SoftwareName $TagName -DeviceTags $DeviceTags -CustomFieldPolicy $CustomFieldPolicy -ShowDebug
    }
    $Policy = Invoke-SoftwarePolicyCheck -SoftwareName $TagName `
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
                # If triggered by tag, set device custom field to "install"
                if ($Policy.ActionSource -eq "Tag" -and $LevelApiKey) {
                    $Device = Find-LevelDevice -ApiKey $LevelApiKey -Hostname $DeviceHostname
                    if ($Device) {
                        $FieldRef = "policy_$SoftwareName"
                        $SetResult = Set-LevelCustomFieldValue -ApiKey $LevelApiKey -EntityType "device" -EntityId $Device.id -FieldReference $FieldRef -Value "install"
                        if ($SetResult) {
                            Write-LevelLog "Set device custom field '$FieldRef' = 'install'" -Level "SUCCESS"
                        }
                    }
                }
                if ($IsInstalled) {
                    # Already installed - check health
                    if (Test-ScreenConnectHealthy) {
                        Write-LevelLog "Already installed and healthy - no action needed" -Level "SUCCESS"
                        $ActionSuccess = $true
                    } else {
                        Write-LevelLog "Installed but unhealthy - attempting repair" -Level "WARN"
                        $repaired = Repair-ScreenConnectService
                        if ($repaired) {
                            Write-LevelLog "Services repaired successfully" -Level "SUCCESS"
                            $ActionSuccess = $true
                        } else {
                            Write-Host "Alert: ScreenConnect services unhealthy after repair attempt"
                            Write-LevelLog "Services still unhealthy after repair" -Level "ERROR"
                            $script:ExitCode = 1
                            $ActionSuccess = $false
                        }
                    }
                }
                else {
                    Write-LevelLog "ACTION: Installing $SoftwareName" -Level "INFO"
                    $ActionSuccess = Install-ScreenConnect -ScratchFolder $MspScratchFolder
                    if (-not $ActionSuccess) {
                        Write-LevelLog "FAILED: Installation unsuccessful" -Level "ERROR"
                        $script:ExitCode = 1
                    }
                }
            }
            "Remove" {
                # If triggered by tag, set device custom field to "remove"
                if ($Policy.ActionSource -eq "Tag" -and $LevelApiKey) {
                    $Device = Find-LevelDevice -ApiKey $LevelApiKey -Hostname $DeviceHostname
                    if ($Device) {
                        $FieldRef = "policy_$SoftwareName"
                        $SetResult = Set-LevelCustomFieldValue -ApiKey $LevelApiKey -EntityType "device" -EntityId $Device.id -FieldReference $FieldRef -Value "remove"
                        if ($SetResult) {
                            Write-LevelLog "Set device custom field '$FieldRef' = 'remove'" -Level "SUCCESS"
                        }
                    }
                }

                if (-not $IsInstalled) {
                    Write-LevelLog "Not installed - no action needed" -Level "SUCCESS"
                    $ActionSuccess = $true
                }
                else {
                    Write-LevelLog "ACTION: Removing $SoftwareName" -Level "INFO"
                    $RemoveResult = Remove-ScreenConnect

                    # Verify removal
                    Start-Sleep -Seconds 3
                    $StillInstalled = (Test-ScreenConnectInstalled).IsInstalled

                    if (-not $StillInstalled) {
                        Write-LevelLog "ScreenConnect removed successfully" -Level "SUCCESS"
                        $ActionSuccess = $true
                    }
                    else {
                        Write-LevelLog "FAILED: Removal unsuccessful" -Level "ERROR"
                        $script:ExitCode = 1
                        $ActionSuccess = $false
                    }
                }
            }
            "Reinstall" {
                Write-LevelLog "ACTION: Reinstalling $SoftwareName" -Level "INFO"
                if ($IsInstalled) {
                    $RemoveSuccess = Remove-ScreenConnect
                    if (-not $RemoveSuccess) {
                        Write-LevelLog "FAILED: Could not remove for reinstall" -Level "ERROR"
                        $script:ExitCode = 1
                        break
                    }
                }
                $ActionSuccess = Install-ScreenConnect -ScratchFolder $MspScratchFolder
                if (-not $ActionSuccess) {
                    Write-LevelLog "FAILED: Reinstallation unsuccessful" -Level "ERROR"
                    $script:ExitCode = 1
                }
            }
            "Pin" {
                Write-LevelLog "Pinned - no changes allowed" -Level "INFO"
                if ($LevelApiKey) {
                    $Device = Find-LevelDevice -ApiKey $LevelApiKey -Hostname $DeviceHostname
                    if ($Device) {
                        $FieldRef = "policy_$SoftwareName"
                        $FieldValue = if ("Remove" -in $Policy.PolicyActions) { "remove" } else { "pin" }
                        $SetResult = Set-LevelCustomFieldValue -ApiKey $LevelApiKey -EntityType "device" -EntityId $Device.id -FieldReference $FieldRef -Value $FieldValue
                        if ($SetResult) {
                            Write-LevelLog "Set device custom field '$FieldRef' = '$FieldValue'" -Level "SUCCESS"
                        }
                    }
                }
                $ActionSuccess = $true
            }
            "None" {
                if ($Policy.HasInstalled -and -not $IsInstalled) {
                    Write-LevelLog "WARNING: Status tag says installed but software not found" -Level "WARN"
                }
                elseif (-not $Policy.HasInstalled -and $IsInstalled) {
                    Write-LevelLog "INFO: Software is installed (no policy action)" -Level "INFO"
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

        $DeviceForTags = $null
        $TagsBefore = @()
        if ($DebugScripts) {
            $DeviceForTags = Find-LevelDevice -ApiKey $LevelApiKey -Hostname $DeviceHostname
            if ($DeviceForTags) {
                Write-LevelLog "Device ID: $($DeviceForTags.id)" -Level "DEBUG"
                $TagsBefore = Get-LevelDeviceTagNames -ApiKey $LevelApiKey -DeviceId $DeviceForTags.id
                Write-LevelLog "Tags BEFORE: $($TagsBefore -join ', ')" -Level "DEBUG"
            } else {
                Write-LevelLog "Could not find device for tag verification" -Level "WARN"
            }
        }

        $FinalInstallState = (Test-ScreenConnectInstalled).IsInstalled

        if ($ActionSuccess -and $Policy.ShouldProcess) {
            $SoftwareNameUpper = $TagName.ToUpper()

            switch ($Policy.ResolvedAction) {
                "Install" {
                    Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Install" -DeviceHostname $DeviceHostname
                    if ($FinalInstallState) {
                        Add-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Has" -DeviceHostname $DeviceHostname
                    }
                }
                "Remove" {
                    Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Remove" -DeviceHostname $DeviceHostname
                    Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Has" -DeviceHostname $DeviceHostname
                }
                "Reinstall" {
                    Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Reinstall" -DeviceHostname $DeviceHostname
                    if ($FinalInstallState) {
                        Add-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Has" -DeviceHostname $DeviceHostname
                    }
                }
                "Pin" {
                    Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Pin" -DeviceHostname $DeviceHostname
                    if ("Remove" -in $Policy.PolicyActions) {
                        Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Remove" -DeviceHostname $DeviceHostname
                    }
                    if ($FinalInstallState -and -not $Policy.HasInstalled) {
                        Add-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Has" -DeviceHostname $DeviceHostname
                    }
                    elseif (-not $FinalInstallState -and $Policy.HasInstalled) {
                        Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Has" -DeviceHostname $DeviceHostname
                    }
                }
                "None" {
                    if ($FinalInstallState -and -not $Policy.HasInstalled) {
                        Add-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Has" -DeviceHostname $DeviceHostname
                    }
                    elseif (-not $FinalInstallState -and $Policy.HasInstalled) {
                        Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Has" -DeviceHostname $DeviceHostname
                    }
                }
            }
        }
        elseif (-not $Policy.ShouldProcess) {
            Write-LevelLog "Skipped - no tag updates needed" -Level "INFO"
        }
        else {
            Write-LevelLog "Action failed - tags not updated" -Level "WARN"
        }

        if ($DebugScripts -and $DeviceForTags) {
            $TagsAfter = Get-LevelDeviceTagNames -ApiKey $LevelApiKey -DeviceId $DeviceForTags.id
            Write-LevelLog "Tags AFTER: $($TagsAfter -join ', ')" -Level "DEBUG"

            $Added = $TagsAfter | Where-Object { $_ -notin $TagsBefore }
            $Removed = $TagsBefore | Where-Object { $_ -notin $TagsAfter }
            if ($Added.Count -gt 0) {
                Write-LevelLog "Tags ADDED: $($Added -join ', ')" -Level "DEBUG"
            }
            if ($Removed.Count -gt 0) {
                Write-LevelLog "Tags REMOVED: $($Removed -join ', ')" -Level "DEBUG"
            }
        }
    }
    else {
        Write-LevelLog "No API key - tag updates skipped" -Level "DEBUG"
    }

    Write-Host ""

    if ($ActionSuccess) {
        Write-LevelLog "Policy enforcement completed successfully" -Level "SUCCESS"
    }
    else {
        Write-Host ""
        Write-Host "Alert: Policy enforcement failed for $SoftwareName"
        Write-Host "  Device: $DeviceHostname"
        Write-Host "  Action: $($Policy.ResolvedAction)"
        Write-Host "  See details above for specific error"
        Write-LevelLog "Policy enforcement completed with errors" -Level "ERROR"
    }

    # Debug footer
    if ($DebugScripts) {
        Write-Host ""
        Write-Host "============================================================" -ForegroundColor Magenta
        Write-Host " END OF DEBUG OUTPUT" -ForegroundColor Magenta
        Write-Host "============================================================" -ForegroundColor Magenta
    }

    Remove-Lock
    return $(if ($ActionSuccess) { 0 } else { 1 })
}}
if ($RunningFromLauncher) { $InvokeParams.NoExit = $true }
Invoke-LevelScript @InvokeParams

exit $ExitCode
