<#
.SYNOPSIS
    Software policy enforcement for Huntress Agent.

.DESCRIPTION
    Implements the COOLForge 5-tag policy model for Huntress Agent management.
    See docs/POLICY-TAGS.md for the complete policy specification.

    POLICY FLOW (per POLICY-TAGS.md):
    1. Check global control tags (device must have checkmark to be managed)
    2. Check software-specific override tags (highest priority)
    3. Fall back to custom field policy (policy_huntress)
    4. Execute resolved action (install/remove/reinstall)

    GLOBAL CONTROL TAGS (standalone):
    - U+2705 = Device is managed (required to process)
    - U+274C = Device is excluded from management
    - Both = Device is globally pinned (no changes)

    SOFTWARE-SPECIFIC OVERRIDE TAGS (with "huntress" suffix):
    - U+1F64F huntress = Install if missing (transient)
    - U+1F6AB huntress = Remove if present (transient)
    - U+1F4CC huntress = Pin - no changes allowed (persistent)
    - U+1F504 huntress = Reinstall - remove + install (transient)
    - U+2705 huntress  = Status: software is installed (set by script)

    CUSTOM FIELD POLICY (inherited Group->Folder->Device):
    - policy_huntress = "install" | "remove" | "pin" | ""

    TAMPER PROTECTION:
    When removing, the script checks if tamper protection may be enabled.
    If TP blocks removal, it outputs instructions and exits gracefully.
    The policy will retry on the next cycle after TP is disabled.

.NOTES
    Version:          2026.01.16.01
    Target Platform:  Level.io RMM (via Script Launcher)
    Exit Codes:       0 = Success | 1 = Alert (Failure)

    Level.io Variables Used (passed from Script Launcher):
    - $MspScratchFolder   : MSP-defined scratch folder for persistent storage
    - $DeviceHostname     : Device hostname from Level.io
    - $DeviceTags         : Comma-separated list of device tags
    - $policy_huntress    : Custom field policy value (inherited)

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# Software Policy - Huntress
# Version: 2026.01.16.01
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

    $HuntressPath = Get-HuntressPath
    $AgentExe = Join-Path $HuntressPath "HuntressAgent.exe"

    Write-Host "  --- File Paths ---"
    Write-Host "  $(if (Test-Path $AgentExe) { '[FOUND]' } else { '[    ]' }) $AgentExe" -ForegroundColor $(if (Test-Path $AgentExe) { 'Green' } else { 'DarkGray' })

    Write-Host ""
    Write-Host "  --- Services ---"
    $Services = @("HuntressAgent", "HuntressUpdater", "HuntressRio")
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
$SoftwareName = "huntress"
$LockFileName = "Huntress_Deployment.lock"

# Huntress paths and service names
$HuntressAgentServiceName   = "HuntressAgent"
$HuntressUpdaterServiceName = "HuntressUpdater"
$HuntressEDRServiceName     = "HuntressRio"
$HuntressRegKey             = "HKLM:\SOFTWARE\Huntress Labs"
$InstallerName              = "HuntressInstaller.exe"

# Huntress credentials from custom fields
$AccountKeyVar = "policy_huntress_account_key"
$AccountKey = Get-Variable -Name $AccountKeyVar -ValueOnly -ErrorAction SilentlyContinue
if ([string]::IsNullOrWhiteSpace($AccountKey) -or $AccountKey -like "{{*}}") {
    $AccountKey = $null
}

$OrgKeyVar = "policy_huntress_org_key"
$OrgKey = Get-Variable -Name $OrgKeyVar -ValueOnly -ErrorAction SilentlyContinue
if ([string]::IsNullOrWhiteSpace($OrgKey) -or $OrgKey -like "{{*}}") {
    $OrgKey = $null
}

$HuntressTagsVar = "policy_huntress_tags"
$HuntressTags = Get-Variable -Name $HuntressTagsVar -ValueOnly -ErrorAction SilentlyContinue
if ([string]::IsNullOrWhiteSpace($HuntressTags) -or $HuntressTags -like "{{*}}") {
    $HuntressTags = $null
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
# HUNTRESS-SPECIFIC FUNCTIONS
# ============================================================

function Get-HuntressPath {
    if ($env:ProgramW6432) {
        return Join-Path $Env:ProgramW6432 "Huntress"
    } else {
        return Join-Path $Env:ProgramFiles "Huntress"
    }
}

function Test-HuntressInstalled {
    $path = Get-HuntressPath
    $agentExe = Join-Path $path "HuntressAgent.exe"
    $result = Test-Path $agentExe
    if ($DebugScripts -and $result) {
        Write-Host "  [DEBUG] Huntress detected - agent executable found" -ForegroundColor Green
    }
    return $result
}

function Test-TamperProtectionEnabled {
    $result = @{
        MayBeEnabled = $false
        Reason = ""
    }

    $huntressPath = Get-HuntressPath

    if (-not (Test-Path $huntressPath)) {
        $result.Reason = "Huntress not installed"
        return $result
    }

    # Check if EDR (Rio) service is running - TP requires Rio
    $rioService = Get-Service -Name $HuntressEDRServiceName -ErrorAction SilentlyContinue
    $rioRunning = $rioService -and $rioService.Status -eq 'Running'

    if (-not $rioRunning) {
        $result.Reason = "HuntressRio not running - TP not active"
        return $result
    }

    $result.MayBeEnabled = $true
    $result.Reason = "HuntressRio running - TP may be enabled"
    return $result
}

function Stop-HuntressProcesses {
    $processes = @("HuntressAgent", "HuntressUpdater", "HuntressRio", "hUpdate")
    foreach ($proc in $processes) {
        Get-Process -Name $proc -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
}

function Test-HuntressHealthy {
    $healthy = $true

    $agentService = Get-Service -Name $HuntressAgentServiceName -ErrorAction SilentlyContinue
    if (-not $agentService -or $agentService.Status -ne 'Running') {
        Write-LevelLog "HuntressAgent service not running" -Level "WARN"
        $healthy = $false
    }

    $updaterService = Get-Service -Name $HuntressUpdaterServiceName -ErrorAction SilentlyContinue
    if (-not $updaterService -or $updaterService.Status -ne 'Running') {
        Write-LevelLog "HuntressUpdater service not running" -Level "WARN"
        $healthy = $false
    }

    return $healthy
}

function Repair-HuntressServices {
    $services = @($HuntressAgentServiceName, $HuntressUpdaterServiceName, $HuntressEDRServiceName)

    foreach ($svc in $services) {
        $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($service -and $service.Status -ne 'Running') {
            Write-LevelLog "Starting service: $svc"
            try {
                Start-Service $svc -ErrorAction Stop
                Start-Sleep -Seconds 2
                $service.Refresh()
                if ($service.Status -eq 'Running') {
                    Write-LevelLog "Service started: $svc" -Level "SUCCESS"
                } else {
                    Write-LevelLog "Service failed to start: $svc" -Level "ERROR"
                }
            }
            catch {
                Write-LevelLog "Error starting $svc : $($_.Exception.Message)" -Level "ERROR"
            }
        }
    }
}

function Install-Huntress {
    param([string]$ScratchFolder)

    # Validate credentials
    if ([string]::IsNullOrWhiteSpace($AccountKey)) {
        Write-Host "Alert: Huntress install failed - policy_huntress_account_key custom field not configured"
        Write-LevelLog "Account key not configured - set policy_huntress_account_key custom field" -Level "ERROR"
        return $false
    }

    if ($AccountKey.Length -ne 32) {
        Write-Host "Alert: Huntress install failed - account key must be 32 characters"
        Write-LevelLog "Invalid account key length (expected 32 chars, got $($AccountKey.Length))" -Level "ERROR"
        return $false
    }

    if ([string]::IsNullOrWhiteSpace($OrgKey)) {
        Write-Host "Alert: Huntress install failed - policy_huntress_org_key custom field not configured"
        Write-LevelLog "Organization key not configured - set policy_huntress_org_key custom field" -Level "ERROR"
        return $false
    }

    $maskedKey = $AccountKey.Substring(0,4) + "************************" + $AccountKey.Substring(28,4)
    Write-LevelLog "Account Key: $maskedKey"
    Write-LevelLog "Organization: $OrgKey"

    # Build download URL
    $DownloadURL = "https://update.huntress.io/download/$AccountKey/$InstallerName"
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
    Write-LevelLog "Downloading Huntress installer..."
    if (Test-Path $InstallerPath) {
        Remove-Item $InstallerPath -Force -ErrorAction SilentlyContinue
    }

    try {
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($DownloadURL, $InstallerPath)
    }
    catch {
        Write-Host "Alert: Failed to download Huntress installer"
        Write-Host "  Error: $($_.Exception.Message)"
        Write-LevelLog "Download failed: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }

    if (-not (Test-Path $InstallerPath)) {
        Write-Host "Alert: Installer not found after download"
        Write-LevelLog "Installer not found after download" -Level "ERROR"
        return $false
    }

    # Verify digital signature
    Write-LevelLog "Verifying installer signature..."
    try {
        $sig = Get-AuthenticodeSignature -FilePath $InstallerPath
        if ($sig.Status -ne 'Valid') {
            Write-Host "Alert: Invalid installer signature: $($sig.Status)"
            Write-LevelLog "Invalid installer signature: $($sig.Status)" -Level "ERROR"
            return $false
        }
    }
    catch {
        Write-LevelLog "Signature verification failed: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }

    # Build install arguments
    $installArgs = "/ACCT_KEY=`"$AccountKey`" /ORG_KEY=`"$OrgKey`" /S"
    if (-not [string]::IsNullOrWhiteSpace($HuntressTags)) {
        $installArgs = "/ACCT_KEY=`"$AccountKey`" /ORG_KEY=`"$OrgKey`" /TAGS=`"$HuntressTags`" /S"
        Write-LevelLog "Tags: $HuntressTags"
    }

    # Run installer (with retry on failure)
    $maxAttempts = 2
    $installSuccess = $false

    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        Write-LevelLog "Installing Huntress (attempt $attempt of $maxAttempts)..."
        try {
            $proc = Start-Process $InstallerPath -ArgumentList $installArgs -PassThru
            $proc | Wait-Process -Timeout 120 -ErrorAction Stop

            # Check if process exited successfully (exit code 0)
            if ($proc.ExitCode -eq 0) {
                # Verify installation
                Write-LevelLog "Verifying installation..."
                Start-Sleep -Seconds 5

                if (Test-HuntressInstalled) {
                    $installSuccess = $true
                    break
                }
            }

            # Installation failed - attempt cleanup and retry
            if ($attempt -lt $maxAttempts) {
                Write-LevelLog "Installation failed (exit code: $($proc.ExitCode)) - attempting cleanup and retry..." -Level "WARN"

                # Kill all Huntress processes
                Stop-HuntressProcesses
                Start-Sleep -Seconds 3

                # Force remove Huntress directory
                $huntressPath = Get-HuntressPath
                if (Test-Path $huntressPath) {
                    Write-LevelLog "Force removing: $huntressPath"
                    Remove-Item -LiteralPath $huntressPath -Force -Recurse -ErrorAction SilentlyContinue
                }

                # Clear registry keys
                if (Test-Path $HuntressRegKey) {
                    Write-LevelLog "Cleaning up registry keys..."
                    Remove-Item -Path $HuntressRegKey -Recurse -Force -ErrorAction SilentlyContinue
                }

                # Re-download installer in case it was corrupted
                Write-LevelLog "Re-downloading installer..."
                Remove-Item $InstallerPath -Force -ErrorAction SilentlyContinue
                try {
                    $webClient = New-Object System.Net.WebClient
                    $webClient.DownloadFile($DownloadURL, $InstallerPath)
                }
                catch {
                    Write-LevelLog "Re-download failed: $($_.Exception.Message)" -Level "WARN"
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
                Stop-HuntressProcesses
                Start-Sleep -Seconds 3
                continue
            }
        }

        # Final attempt failed
        Write-Host "Alert: Huntress installation failed after $maxAttempts attempts"
        Write-Host "  Exit code: $($proc.ExitCode)"
        Write-LevelLog "Installation failed after retries" -Level "ERROR"
    }

    # Cleanup installer
    Remove-Item $InstallerPath -Force -ErrorAction SilentlyContinue

    if (-not $installSuccess) {
        Write-Host "Alert: Huntress installation verification failed"
        Write-LevelLog "Installation verification failed - agent not found" -Level "ERROR"
        return $false
    }

    Write-LevelLog "Huntress installed successfully" -Level "SUCCESS"
    return $true
}

function Remove-Huntress {
    Write-LevelLog "Starting Huntress removal..."

    $agentPath = Get-HuntressPath
    $uninstallerPath = Join-Path $agentPath "Uninstall.exe"
    $agentExePath = Join-Path $agentPath "HuntressAgent.exe"
    $updaterPath = Join-Path $agentPath "HuntressUpdater.exe"

    # Stop services first
    Write-LevelLog "Stopping Huntress services..."
    Stop-Service $HuntressEDRServiceName -Force -ErrorAction SilentlyContinue
    Stop-Service $HuntressUpdaterServiceName -Force -ErrorAction SilentlyContinue
    Stop-Service $HuntressAgentServiceName -Force -ErrorAction SilentlyContinue

    Stop-HuntressProcesses

    # Run uninstaller
    $uninstallSuccess = $false
    if (Test-Path $uninstallerPath) {
        Write-LevelLog "Running Uninstall.exe..."
        $proc = Start-Process $uninstallerPath -ArgumentList "/S" -PassThru -Wait
        $uninstallSuccess = $true
    }
    elseif (Test-Path $agentExePath) {
        Write-LevelLog "Running HuntressAgent.exe uninstaller..."
        $proc = Start-Process $agentExePath -ArgumentList "/S" -PassThru -Wait
        $uninstallSuccess = $true
    }
    elseif (Test-Path $updaterPath) {
        Write-LevelLog "Running HuntressUpdater.exe uninstaller..."
        $proc = Start-Process $updaterPath -ArgumentList "/S" -PassThru -Wait
        $uninstallSuccess = $true
    }

    # Wait for uninstall to complete
    if ($uninstallSuccess) {
        for ($i = 0; $i -le 15; $i++) {
            if ((Test-Path $agentExePath) -or (Test-Path $HuntressRegKey)) {
                Start-Sleep -Seconds 1
            }
            else {
                Write-LevelLog "Uninstaller completed in $i seconds"
                break
            }
        }
    }

    # Manual cleanup - folder
    if (Test-Path $agentPath) {
        Write-LevelLog "Cleaning up Huntress folder..."
        Remove-Item -LiteralPath $agentPath -Force -Recurse -ErrorAction SilentlyContinue
    }

    # Manual cleanup - registry
    if (Test-Path $HuntressRegKey) {
        Write-LevelLog "Cleaning up registry keys..."
        Remove-Item -Path $HuntressRegKey -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Remove leftover services
    $services = @("HuntressRio", "HuntressAgent", "HuntressUpdater", "Huntmon")
    foreach ($svc in $services) {
        $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($service) {
            Write-LevelLog "Removing leftover service: $svc"
            & sc.exe stop $svc 2>$null
            & sc.exe delete $svc 2>$null
        }
    }

    # Verify removal
    Start-Sleep -Seconds 2
    if (Test-HuntressInstalled) {
        Write-LevelLog "Removal verification failed - Huntress still present" -Level "ERROR"
        return $false
    }

    Write-LevelLog "Huntress removed successfully" -Level "SUCCESS"
    return $true
}

# ============================================================
# MAIN SCRIPT LOGIC
# ============================================================
$ScriptVersion = "2026.01.16.01"
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
        'AccountKey' = if ($AccountKey) { '(configured)' } else { '(not set)' }
        'OrgKey' = if ($OrgKey) { $OrgKey } else { '(not set)' }
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

        # Also create the Huntress-specific custom fields if they don't exist
        $HuntressFieldsCreated = 0

        $AccountKeyFieldName = "policy_huntress_account_key"
        $ExistingAccountKeyField = Find-LevelCustomField -ApiKey $LevelApiKey -FieldName $AccountKeyFieldName
        if (-not $ExistingAccountKeyField) {
            $NewField = New-LevelCustomField -ApiKey $LevelApiKey -Name $AccountKeyFieldName -DefaultValue ""
            if ($NewField) {
                Write-LevelLog "Created custom field: $AccountKeyFieldName" -Level "SUCCESS"
                $HuntressFieldsCreated++
            }
        }

        $OrgKeyFieldName = "policy_huntress_org_key"
        $ExistingOrgKeyField = Find-LevelCustomField -ApiKey $LevelApiKey -FieldName $OrgKeyFieldName
        if (-not $ExistingOrgKeyField) {
            $NewField = New-LevelCustomField -ApiKey $LevelApiKey -Name $OrgKeyFieldName -DefaultValue ""
            if ($NewField) {
                Write-LevelLog "Created custom field: $OrgKeyFieldName" -Level "SUCCESS"
                $HuntressFieldsCreated++
            }
        }

        $TagsFieldName = "policy_huntress_tags"
        $ExistingTagsField = Find-LevelCustomField -ApiKey $LevelApiKey -FieldName $TagsFieldName
        if (-not $ExistingTagsField) {
            $NewField = New-LevelCustomField -ApiKey $LevelApiKey -Name $TagsFieldName -DefaultValue ""
            if ($NewField) {
                Write-LevelLog "Created custom field: $TagsFieldName (optional)" -Level "SUCCESS"
                $HuntressFieldsCreated++
            }
        }

        $TotalFieldsCreated = $InfraResult.FieldsCreated + $HuntressFieldsCreated

        if ($InfraResult.Success) {
            if ($InfraResult.TagsCreated -gt 0 -or $TotalFieldsCreated -gt 0) {
                Write-LevelLog "Created $($InfraResult.TagsCreated) tags, $TotalFieldsCreated fields" -Level "SUCCESS"
                Write-Host ""
                Write-Host "Alert: Policy infrastructure created - please configure custom fields"
                Write-Host "  Set the following custom fields in Level.io:"
                Write-Host "  - policy_huntress: Set to 'install', 'remove', or 'pin' at Group/Folder/Device level"
                Write-Host "  - policy_huntress_account_key: Your 32-character Huntress account key"
                Write-Host "  - policy_huntress_org_key: Organization name for this device"
                Write-Host "  - policy_huntress_tags: (Optional) Tags for Huntress agent"
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
    $IsInstalled = Test-HuntressInstalled
    Write-LevelLog "Current state: $(if ($IsInstalled) { 'Installed' } else { 'Not installed' })"

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
                    if (Test-HuntressHealthy) {
                        Write-LevelLog "Already installed and healthy - no action needed" -Level "SUCCESS"
                        $ActionSuccess = $true
                    } else {
                        Write-LevelLog "Installed but unhealthy - attempting repair" -Level "WARN"
                        Repair-HuntressServices
                        Start-Sleep -Seconds 3
                        if (Test-HuntressHealthy) {
                            Write-LevelLog "Services repaired successfully" -Level "SUCCESS"
                            $ActionSuccess = $true
                        } else {
                            Write-Host "Alert: Huntress services unhealthy after repair attempt"
                            Write-Host "  Device may need a restart to restore services"
                            Write-LevelLog "Services still unhealthy after repair" -Level "ERROR"
                            $script:ExitCode = 1
                            $ActionSuccess = $false
                        }
                    }
                }
                else {
                    Write-LevelLog "ACTION: Installing $SoftwareName" -Level "INFO"
                    $ActionSuccess = Install-Huntress -ScratchFolder $MspScratchFolder
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
                    # Check if TP might be active
                    $tpStatus = Test-TamperProtectionEnabled
                    if ($tpStatus.MayBeEnabled) {
                        Write-LevelLog "Note: $($tpStatus.Reason)" -Level "WARN"
                    }

                    Write-LevelLog "ACTION: Removing $SoftwareName" -Level "INFO"
                    $RemoveResult = Remove-Huntress

                    # Verify removal
                    Start-Sleep -Seconds 3
                    $StillInstalled = Test-HuntressInstalled

                    if (-not $StillInstalled) {
                        Write-LevelLog "Huntress removed successfully" -Level "SUCCESS"
                        $ActionSuccess = $true
                    }
                    elseif ($tpStatus.MayBeEnabled) {
                        # TP likely blocked it
                        Write-Host ""
                        Write-Host "Alert: Tamper Protection is blocking uninstall"
                        Write-Host "  ACTION REQUIRED:"
                        Write-Host "  1. Go to Huntress Dashboard"
                        Write-Host "  2. Settings -> Tamper Protection -> Exclusions"
                        Write-Host "  3. Add this device: $env:COMPUTERNAME"
                        Write-Host "  4. Wait ~30 minutes for settings to sync"
                        Write-Host "  5. Policy will retry automatically on next run"
                        Write-Host ""
                        Write-LevelLog "Removal blocked by Tamper Protection - waiting for TP disable" -Level "WARN"
                        # Don't set exit code 1 - this is expected, will retry
                        $ActionSuccess = $true  # Consider it "handled" - will retry next cycle
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
                    $RemoveSuccess = Remove-Huntress
                    if (-not $RemoveSuccess) {
                        # Check if TP blocked it
                        $tpStatus = Test-TamperProtectionEnabled
                        if ($tpStatus.MayBeEnabled -and (Test-HuntressInstalled)) {
                            Write-Host "Alert: Tamper Protection blocking reinstall - disable TP first"
                            Write-LevelLog "Reinstall blocked by Tamper Protection" -Level "WARN"
                        } else {
                            Write-LevelLog "FAILED: Could not remove for reinstall" -Level "ERROR"
                        }
                        $script:ExitCode = 1
                        break
                    }
                }
                $ActionSuccess = Install-Huntress -ScratchFolder $MspScratchFolder
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

        $FinalInstallState = Test-HuntressInstalled

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
