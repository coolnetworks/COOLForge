<#
.SYNOPSIS
    Software policy enforcement for MeshCentral Agent.

.DESCRIPTION
    Implements the COOLForge 5-tag policy model for MeshCentral Agent management.
    See docs/POLICY-TAGS.md for the complete policy specification.

    POLICY FLOW (per POLICY-TAGS.md):
    1. Check global control tags (device must have checkmark to be managed)
    2. Check software-specific override tags (highest priority)
    3. Fall back to custom field policy (policy_meshcentral)
    4. Execute resolved action (install/remove/reinstall)

    GLOBAL CONTROL TAGS (standalone):
    - U+2705 = Device is managed (required to process)
    - U+274C = Device is excluded from management
    - Both = Device is globally pinned (no changes)

    SOFTWARE-SPECIFIC OVERRIDE TAGS (with "meshcentral" suffix):
    - U+1F64F meshcentral = Install if missing (transient)
    - U+1F6AB meshcentral = Remove if present (transient)
    - U+1F4CC meshcentral = Pin - no changes allowed (persistent)
    - U+1F504 meshcentral = Reinstall - remove + install (transient)
    - U+2705 meshcentral  = Status: software is installed (set by script)

    CUSTOM FIELD POLICY (inherited Group->Folder->Device):
    - policy_meshcentral = "install" | "remove" | "pin" | ""

.NOTES
    Version:          2026.01.19.01
    Target Platform:  Level.io RMM (via Script Launcher)
    Exit Codes:       0 = Success | 1 = Alert (Failure)

    Level.io Variables Used (passed from Script Launcher):
    - $MspScratchFolder   : MSP-defined scratch folder for persistent storage
    - $DeviceHostname     : Device hostname from Level.io
    - $DeviceTags         : Comma-separated list of device tags

    Custom Fields:
    - $policy_meshcentral            : Policy action (install/remove/pin)
    - $policy_meshcentral_server_url : Expected server URL (e.g., mc.cool.net.au)
    - $policy_meshcentral_download_url : Windows installer download URL
    - $policy_meshcentral_linux_install  : Linux install command (one-liner)
    - $policy_meshcentral_mac_download_url : Mac installer download URL

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# Software Policy - MeshCentral
# Version: 2026.01.19.01
# Target: Level.io (via Script Launcher)
# Exit 0 = Success | Exit 1 = Alert (Failure)
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge

# ============================================================
# DEBUG OUTPUT HELPER (Software-specific)
# ============================================================

function Write-DebugInstallCheck {
    param([bool]$IsInstalled)
    if (-not $DebugScripts) { return }

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " DEBUG: Installation Check" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    $MeshAgentPaths = @(
        "$env:ProgramFiles\Mesh Agent\MeshAgent.exe",
        "${env:ProgramFiles(x86)}\Mesh Agent\MeshAgent.exe"
    )

    Write-Host "  --- File Paths ---"
    foreach ($Path in $MeshAgentPaths) {
        Write-Host "  $(if (Test-Path $Path) { '[FOUND]' } else { '[    ]' }) $Path" -ForegroundColor $(if (Test-Path $Path) { 'Green' } else { 'DarkGray' })
    }

    Write-Host ""
    Write-Host "  --- Services ---"
    $Services = @("Mesh Agent", "MeshAgent")
    foreach ($Svc in $Services) {
        $Service = Get-Service -Name $Svc -ErrorAction SilentlyContinue
        if ($Service) {
            $StatusColor = if ($Service.Status -eq 'Running') { 'Green' } else { 'Yellow' }
            Write-Host "  [FOUND] $Svc - $($Service.Status)" -ForegroundColor $StatusColor
        } else {
            Write-Host "  [    ] $Svc - not found" -ForegroundColor DarkGray
        }
    }

    Write-Host ""
    Write-Host "  SOFTWARE INSTALLED: $(if ($IsInstalled) { 'YES' } else { 'NO' })" -ForegroundColor $(if ($IsInstalled) { 'Green' } else { 'Yellow' })
}

# ============================================================
# CONFIGURATION
# ============================================================
$SoftwareName = "meshcentral"
$LockFileName = "MeshCentral_Deployment.lock"

# MeshCentral paths and service names
$MeshAgentServiceNames = @("Mesh Agent", "MeshAgent")
$InstallerName = "meshagent.msh"

# MeshCentral configuration from custom fields
$ServerUrlVar = "policy_meshcentral_server_url"
$ServerUrl = Get-Variable -Name $ServerUrlVar -ValueOnly -ErrorAction SilentlyContinue
if ([string]::IsNullOrWhiteSpace($ServerUrl) -or $ServerUrl -like "{{*}}") {
    $ServerUrl = $null
}

$DownloadUrlVar = "policy_meshcentral_download_url"
$DownloadUrl = Get-Variable -Name $DownloadUrlVar -ValueOnly -ErrorAction SilentlyContinue
if ([string]::IsNullOrWhiteSpace($DownloadUrl) -or $DownloadUrl -like "{{*}}") {
    $DownloadUrl = $null
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
# MESHCENTRAL-SPECIFIC FUNCTIONS
# ============================================================

function Get-MeshAgentPath {
    # Check both Program Files locations
    $Paths = @(
        "$env:ProgramFiles\Mesh Agent",
        "${env:ProgramFiles(x86)}\Mesh Agent"
    )
    foreach ($Path in $Paths) {
        if (Test-Path (Join-Path $Path "MeshAgent.exe")) {
            return $Path
        }
    }
    # Default to Program Files
    return "$env:ProgramFiles\Mesh Agent"
}

function Test-MeshcentralInstalled {
    $Paths = @(
        "$env:ProgramFiles\Mesh Agent\MeshAgent.exe",
        "${env:ProgramFiles(x86)}\Mesh Agent\MeshAgent.exe"
    )
    foreach ($Path in $Paths) {
        if (Test-Path $Path) {
            if ($DebugScripts) {
                Write-Host "  [DEBUG] MeshCentral detected - agent executable found at $Path" -ForegroundColor Green
            }
            return $true
        }
    }
    return $false
}

function Get-MeshcentralServerUrl {
    <#
    .SYNOPSIS
        Extracts the Meshcentral server URL from the Mesh Agent configuration.
    .RETURNS
        The server URL string, or $null if not found.
    #>

    # Check common Mesh Agent locations for config
    $MeshAgentPaths = @(
        "$env:ProgramFiles\Mesh Agent",
        "${env:ProgramFiles(x86)}\Mesh Agent",
        "$env:ProgramData\Mesh Agent"
    )

    foreach ($BasePath in $MeshAgentPaths) {
        # Check for MeshAgent.msh config file
        $ConfigFile = Join-Path $BasePath "MeshAgent.msh"
        if (Test-Path $ConfigFile) {
            $Content = Get-Content $ConfigFile -Raw -ErrorAction SilentlyContinue
            # Look for MeshServer setting (wss:// format)
            if ($Content -match 'MeshServer\s*=\s*wss?://([^/\s]+)') {
                return $Matches[1]
            }
            if ($Content -match 'ServerUrl\s*=\s*https?://([^/\s]+)') {
                return $Matches[1]
            }
        }

        # Check MeshAgent.db for server info
        $DbFile = Join-Path $BasePath "MeshAgent.db"
        if (Test-Path $DbFile) {
            $Content = Get-Content $DbFile -Raw -ErrorAction SilentlyContinue
            if ($Content -match 'wss?://([^/\s"]+)') {
                return $Matches[1]
            }
        }
    }

    # Check registry for Mesh Agent server
    $RegPaths = @(
        "HKLM:\SOFTWARE\Mesh Agent",
        "HKLM:\SOFTWARE\WOW6432Node\Mesh Agent"
    )
    foreach ($RegPath in $RegPaths) {
        if (Test-Path $RegPath) {
            $ServerUrlReg = Get-ItemProperty -Path $RegPath -Name "MeshServer" -ErrorAction SilentlyContinue
            if ($ServerUrlReg -and $ServerUrlReg.MeshServer -match 'wss?://([^/\s]+)') {
                return $Matches[1]
            }
        }
    }

    return $null
}

function Test-MeshcentralHealthy {
    $healthy = $true

    # Check if any Mesh Agent service is running
    $serviceRunning = $false
    foreach ($ServiceName in $MeshAgentServiceNames) {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq 'Running') {
            $serviceRunning = $true
            break
        }
    }

    if (-not $serviceRunning) {
        Write-LevelLog "Mesh Agent service not running" -Level "WARN"
        $healthy = $false
    }

    # Check if process is running
    $process = Get-Process -Name "MeshAgent*" -ErrorAction SilentlyContinue
    if (-not $process) {
        Write-LevelLog "Mesh Agent process not running" -Level "WARN"
        $healthy = $false
    }

    return $healthy
}

function Repair-MeshcentralServices {
    foreach ($ServiceName in $MeshAgentServiceNames) {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -ne 'Running') {
            Write-LevelLog "Starting service: $ServiceName"
            try {
                Start-Service $ServiceName -ErrorAction Stop
                Start-Sleep -Seconds 2
                $service.Refresh()
                if ($service.Status -eq 'Running') {
                    Write-LevelLog "Service started: $ServiceName" -Level "SUCCESS"
                } else {
                    Write-LevelLog "Service failed to start: $ServiceName" -Level "ERROR"
                }
            }
            catch {
                Write-LevelLog "Error starting $ServiceName : $($_.Exception.Message)" -Level "ERROR"
            }
        }
    }
}

function Stop-MeshcentralProcesses {
    Get-Process -Name "MeshAgent*", "meshagent*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

function Install-Meshcentral {
    param([string]$ScratchFolder)

    # Validate download URL
    if ([string]::IsNullOrWhiteSpace($DownloadUrl)) {
        Write-Host "Alert: MeshCentral install failed - policy_meshcentral_download_url custom field not configured"
        Write-LevelLog "Download URL not configured - set policy_meshcentral_download_url custom field" -Level "ERROR"
        return $false
    }

    Write-LevelLog "Download URL: $DownloadUrl"
    if ($ServerUrl) {
        Write-LevelLog "Expected Server: $ServerUrl"
    }

    # Determine installer path
    $InstallerPath = Join-Path $Env:TMP $InstallerName

    # Ensure TLS 1.2+
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
    }
    catch {
        Write-LevelLog "Failed to set TLS 1.2: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }

    # Download installer
    Write-LevelLog "Downloading MeshCentral installer..."
    if (Test-Path $InstallerPath) {
        Remove-Item $InstallerPath -Force -ErrorAction SilentlyContinue
    }

    try {
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($DownloadUrl, $InstallerPath)
    }
    catch {
        Write-Host "Alert: Failed to download MeshCentral installer"
        Write-Host "  Error: $($_.Exception.Message)"
        Write-LevelLog "Download failed: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }

    if (-not (Test-Path $InstallerPath)) {
        Write-Host "Alert: Installer not found after download"
        Write-LevelLog "Installer not found after download" -Level "ERROR"
        return $false
    }

    $FileSize = (Get-Item $InstallerPath).Length
    Write-LevelLog "Downloaded installer: $FileSize bytes"

    # Run installer (MSH file is self-installing)
    $maxAttempts = 2
    $installSuccess = $false

    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        Write-LevelLog "Installing MeshCentral (attempt $attempt of $maxAttempts)..."
        try {
            # MSH files are run directly - they contain the agent and config
            $proc = Start-Process $InstallerPath -ArgumentList "-fullinstall" -PassThru -Wait -WindowStyle Hidden

            # Check if process exited
            Write-LevelLog "Installer exit code: $($proc.ExitCode)"

            # Verify installation
            Write-LevelLog "Verifying installation..."
            Start-Sleep -Seconds 5

            if (Test-MeshcentralInstalled) {
                $installSuccess = $true
                break
            }

            # Installation may have failed - retry
            if ($attempt -lt $maxAttempts) {
                Write-LevelLog "Installation not verified - attempting cleanup and retry..." -Level "WARN"

                # Kill processes
                Stop-MeshcentralProcesses
                Start-Sleep -Seconds 3

                # Force remove directories
                $RemovePaths = @(
                    "$env:ProgramFiles\Mesh Agent",
                    "${env:ProgramFiles(x86)}\Mesh Agent",
                    "$env:ProgramData\Mesh Agent"
                )
                foreach ($Path in $RemovePaths) {
                    if (Test-Path $Path) {
                        Write-LevelLog "Force removing: $Path"
                        Remove-Item $Path -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }

                Write-LevelLog "Cleanup complete - retrying installation..."
                continue
            }
        }
        catch {
            if ($proc) { Stop-Process $proc -Force -ErrorAction SilentlyContinue }
            Write-LevelLog "Installation error: $($_.Exception.Message)" -Level "WARN"

            if ($attempt -lt $maxAttempts) {
                Write-LevelLog "Attempting cleanup and retry..." -Level "WARN"
                Stop-MeshcentralProcesses
                Start-Sleep -Seconds 3
                continue
            }
        }

        # Final attempt failed
        Write-Host "Alert: MeshCentral installation failed after $maxAttempts attempts"
        Write-LevelLog "Installation failed after retries" -Level "ERROR"
    }

    # Cleanup installer
    Remove-Item $InstallerPath -Force -ErrorAction SilentlyContinue

    if (-not $installSuccess) {
        Write-Host "Alert: MeshCentral installation verification failed"
        Write-LevelLog "Installation verification failed - agent not found" -Level "ERROR"
        return $false
    }

    # Verify server URL if configured
    if ($ServerUrl) {
        $DetectedServer = Get-MeshcentralServerUrl
        if ($DetectedServer) {
            $NormalizedExpected = $ServerUrl -replace '^https?://', '' -replace '/$', ''
            $NormalizedDetected = $DetectedServer -replace '^https?://', '' -replace '/$', ''

            if ($NormalizedDetected -like "*$NormalizedExpected*" -or $NormalizedExpected -like "*$NormalizedDetected*") {
                Write-LevelLog "Server URL verified: $DetectedServer" -Level "SUCCESS"
            } else {
                Write-Host "Alert: MeshCentral agent pointing to wrong server ($DetectedServer instead of $ServerUrl)"
                Write-LevelLog "WARNING: Installed agent points to '$DetectedServer' but expected '$ServerUrl'" -Level "WARN"
            }
        }
    }

    Write-LevelLog "MeshCentral installed successfully" -Level "SUCCESS"
    return $true
}

function Remove-Meshcentral {
    Write-LevelLog "Starting MeshCentral removal..."

    # Stop processes first
    Write-LevelLog "Stopping MeshCentral processes..."
    Stop-MeshcentralProcesses
    Start-Sleep -Seconds 2

    # Stop and remove services
    foreach ($ServiceName in $MeshAgentServiceNames) {
        $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($Service) {
            Write-LevelLog "Stopping service: $ServiceName"
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            & sc.exe delete $ServiceName 2>$null
        }
    }

    # Run uninstaller
    $UninstallPaths = @(
        "$env:ProgramFiles\Mesh Agent\MeshAgent.exe",
        "${env:ProgramFiles(x86)}\Mesh Agent\MeshAgent.exe"
    )
    foreach ($Path in $UninstallPaths) {
        if (Test-Path $Path) {
            Write-LevelLog "Running MeshCentral uninstaller at $Path..."
            try {
                $proc = Start-Process $Path -ArgumentList "-uninstall" -PassThru -Wait -WindowStyle Hidden
                Write-LevelLog "Uninstaller exit code: $($proc.ExitCode)"
            }
            catch {
                Write-LevelLog "Uninstaller error: $($_.Exception.Message)" -Level "WARN"
            }
            Start-Sleep -Seconds 3
        }
    }

    # Force remove directories
    $RemovePaths = @(
        "$env:ProgramFiles\Mesh Agent",
        "${env:ProgramFiles(x86)}\Mesh Agent",
        "$env:ProgramData\Mesh Agent"
    )
    foreach ($Path in $RemovePaths) {
        if (Test-Path $Path) {
            Write-LevelLog "Removing directory: $Path"
            Remove-Item $Path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # Verify removal
    Start-Sleep -Seconds 2
    if (Test-MeshcentralInstalled) {
        Write-LevelLog "Removal verification failed - MeshCentral still present" -Level "ERROR"
        return $false
    }

    Write-LevelLog "MeshCentral removed successfully" -Level "SUCCESS"
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
        'ServerUrl' = if ($ServerUrl) { $ServerUrl } else { '(not set)' }
        'DownloadUrl' = if ($DownloadUrl) { '(configured)' } else { '(not set)' }
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
    Write-DebugTags -TagString $DeviceTags -SoftwareName $SoftwareName

    # ============================================================
    # AUTO-BOOTSTRAP: Ensure policy infrastructure exists
    # ============================================================
    if ($LevelApiKey) {
        # Debug: Show API key info (obfuscated - first 4 chars only)
        $KeyLength = $LevelApiKey.Length
        $KeyPreview = if ($KeyLength -gt 4) { $LevelApiKey.Substring(0, 4) + "****" } else { "(invalid)" }
        Write-LevelLog "API key: $KeyPreview (length: $KeyLength)" -Level "DEBUG"

        # Pass launcher variable to skip API calls for field existence check
        $PolicyFieldValue = Get-Variable -Name "policy_$SoftwareName" -ValueOnly -ErrorAction SilentlyContinue

        $InfraResult = Initialize-SoftwarePolicyInfrastructure -ApiKey $LevelApiKey `
            -SoftwareName $SoftwareName `
            -RequireUrl $false `
            -PolicyFieldValue $PolicyFieldValue

        # Also create the MeshCentral-specific custom fields if they don't exist
        $MeshFieldsCreated = 0

        $ServerUrlFieldName = "policy_meshcentral_server_url"
        $ExistingServerUrlField = Find-LevelCustomField -ApiKey $LevelApiKey -FieldName $ServerUrlFieldName
        if (-not $ExistingServerUrlField) {
            $NewField = New-LevelCustomField -ApiKey $LevelApiKey -Name $ServerUrlFieldName -DefaultValue ""
            if ($NewField) {
                Write-LevelLog "Created custom field: $ServerUrlFieldName" -Level "SUCCESS"
                $MeshFieldsCreated++
            }
        }

        $DownloadUrlFieldName = "policy_meshcentral_download_url"
        $ExistingDownloadUrlField = Find-LevelCustomField -ApiKey $LevelApiKey -FieldName $DownloadUrlFieldName
        if (-not $ExistingDownloadUrlField) {
            $NewField = New-LevelCustomField -ApiKey $LevelApiKey -Name $DownloadUrlFieldName -DefaultValue ""
            if ($NewField) {
                Write-LevelLog "Created custom field: $DownloadUrlFieldName" -Level "SUCCESS"
                $MeshFieldsCreated++
            }
        }

        $LinuxInstallFieldName = "policy_meshcentral_linux_install"
        $ExistingLinuxField = Find-LevelCustomField -ApiKey $LevelApiKey -FieldName $LinuxInstallFieldName
        if (-not $ExistingLinuxField) {
            $NewField = New-LevelCustomField -ApiKey $LevelApiKey -Name $LinuxInstallFieldName -DefaultValue ""
            if ($NewField) {
                Write-LevelLog "Created custom field: $LinuxInstallFieldName" -Level "SUCCESS"
                $MeshFieldsCreated++
            }
        }

        $MacDownloadUrlFieldName = "policy_meshcentral_mac_download_url"
        $ExistingMacField = Find-LevelCustomField -ApiKey $LevelApiKey -FieldName $MacDownloadUrlFieldName
        if (-not $ExistingMacField) {
            $NewField = New-LevelCustomField -ApiKey $LevelApiKey -Name $MacDownloadUrlFieldName -DefaultValue ""
            if ($NewField) {
                Write-LevelLog "Created custom field: $MacDownloadUrlFieldName" -Level "SUCCESS"
                $MeshFieldsCreated++
            }
        }

        $TotalFieldsCreated = $InfraResult.FieldsCreated + $MeshFieldsCreated

        if ($InfraResult.Success) {
            if ($InfraResult.TagsCreated -gt 0 -or $TotalFieldsCreated -gt 0) {
                Write-LevelLog "Created $($InfraResult.TagsCreated) tags, $TotalFieldsCreated fields" -Level "SUCCESS"
                Write-Host ""
                Write-Host "Alert: Policy infrastructure created - please configure custom fields"
                Write-Host "  Set the following custom fields in Level.io:"
                Write-Host "  - policy_meshcentral: Set to 'install', 'remove', or 'pin' at Group/Folder/Device level"
                Write-Host "  - policy_meshcentral_server_url: Your MeshCentral server (e.g., mc.cool.net.au)"
                Write-Host "  - policy_meshcentral_download_url: Windows installer download URL from MeshCentral"
                Write-Host "  - policy_meshcentral_linux_install: (Optional) Linux install command (one-liner)"
                Write-Host "  - policy_meshcentral_mac_download_url: (Optional) Mac installer download URL"
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
    $IsInstalled = Test-MeshcentralInstalled
    Write-LevelLog "Current state: $(if ($IsInstalled) { 'Installed' } else { 'Not installed' })"

    # If installed, show detected server
    if ($IsInstalled) {
        $DetectedServer = Get-MeshcentralServerUrl
        if ($DetectedServer) {
            Write-LevelLog "Detected server: $DetectedServer"
        }
    }

    # Debug: Show installation check details
    Write-DebugInstallCheck -IsInstalled $IsInstalled

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
                    if (Test-MeshcentralHealthy) {
                        Write-LevelLog "Already installed and healthy - no action needed" -Level "SUCCESS"
                        $ActionSuccess = $true
                    } else {
                        Write-LevelLog "Installed but unhealthy - attempting repair" -Level "WARN"
                        Repair-MeshcentralServices
                        Start-Sleep -Seconds 3
                        if (Test-MeshcentralHealthy) {
                            Write-LevelLog "Services repaired successfully" -Level "SUCCESS"
                            $ActionSuccess = $true
                        } else {
                            Write-Host "Alert: MeshCentral services unhealthy after repair attempt"
                            Write-Host "  Device may need a restart to restore services"
                            Write-LevelLog "Services still unhealthy after repair" -Level "ERROR"
                            $script:ExitCode = 1
                            $ActionSuccess = $false
                        }
                    }
                }
                else {
                    Write-LevelLog "ACTION: Installing $SoftwareName" -Level "INFO"
                    $ActionSuccess = Install-Meshcentral -ScratchFolder $MspScratchFolder
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
                    $RemoveResult = Remove-Meshcentral

                    # Verify removal
                    Start-Sleep -Seconds 3
                    $StillInstalled = Test-MeshcentralInstalled

                    if (-not $StillInstalled) {
                        Write-LevelLog "MeshCentral removed successfully" -Level "SUCCESS"
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
                    $RemoveSuccess = Remove-Meshcentral
                    if (-not $RemoveSuccess) {
                        Write-LevelLog "FAILED: Could not remove for reinstall" -Level "ERROR"
                        $script:ExitCode = 1
                        break
                    }
                }
                $ActionSuccess = Install-Meshcentral -ScratchFolder $MspScratchFolder
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

        $FinalInstallState = Test-MeshcentralInstalled

        if ($ActionSuccess -and $Policy.ShouldProcess) {
            $SoftwareNameUpper = $SoftwareName.ToUpper()

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
