<#
.SYNOPSIS
    Huntress software policy enforcement script.

.DESCRIPTION
    Tag-based policy script for Huntress agent management.
    Handles install, uninstall (with tamper protection awareness), and verification.

    SUPPORTED POLICY TAGS:
    - U+1F64F huntress = Install Huntress agent
    - U+26D4 huntress  = Remove Huntress agent (checks tamper protection first)
    - U+2705 huntress  = Verify Huntress is installed and healthy
    - U+1F4CC huntress = Pin (lock state, no changes)
    - U+1F6AB huntress = Block installs (allow remove)

    TAMPER PROTECTION HANDLING:
    When removing, the script checks if tamper protection is enabled.
    If TP is on, it outputs TP_ENABLED status and exits - the policy will
    retry on the next cycle. Once TP is disabled in the Huntress dashboard,
    the next policy run will complete the uninstall.

.NOTES
    Version:          2026.01.08.01
    Target Platform:  Level.io RMM (via Script Launcher)
    Exit Codes:       0 = Success | 1 = Alert (Failure)

    Level.io Custom Fields Required:
    - cf_huntress_account_key      : Huntress account key (32 chars)
    - cf_huntress_organization_key : Organization name
    - cf_huntress_tags             : Optional tags for Huntress

    Copyright (c) COOLNETWORKS
#>

# ============================================================
# CONFIGURATION
# ============================================================
$SoftwareName = "huntress"

# Level.io custom field defaults
$AccountKey      = '{{cf_huntress_account_key}}'
$OrganizationKey = '{{cf_huntress_organization_key}}'
$HuntressTags    = '{{cf_huntress_tags}}'

# Huntress paths and service names
$HuntressAgentServiceName   = "HuntressAgent"
$HuntressUpdaterServiceName = "HuntressUpdater"
$HuntressEDRServiceName     = "HuntressRio"
$HuntressRegKey             = "HKLM:\SOFTWARE\Huntress Labs"
$HuntressKeyPath            = "HKLM:\SOFTWARE\Huntress Labs\Huntress"
$InstallerName              = "HuntressInstaller.exe"
$InstallerPath              = Join-Path $Env:TMP $InstallerName

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
    return (Test-Path $agentExe)
}

function Test-ServiceExists {
    param([string]$ServiceName)
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    return ($null -ne $svc)
}

function Test-ServiceRunning {
    param([string]$ServiceName)
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -eq $svc) { return $false }
    return ($svc.Status -eq 'Running')
}

function Test-TamperProtectionEnabled {
    <#
    .SYNOPSIS
        Detects if Huntress Tamper Protection is enabled.
    .DESCRIPTION
        TP detection is tricky because scripts run as SYSTEM, which TP allows.
        We can't reliably detect TP status before attempting uninstall.

        This function checks prerequisites only:
        - Is Huntress installed?
        - Is HuntressRio (EDR) running? (TP requires Rio)

        The actual TP detection happens AFTER uninstall attempt - if files
        still exist, TP blocked it.
    .OUTPUTS
        Returns hashtable with:
        - MayBeEnabled: $true if TP could be active (Rio running)
        - Reason: Description
    #>

    $result = @{
        MayBeEnabled = $false
        Reason = ""
    }

    $huntressPath = Get-HuntressPath

    # If Huntress isn't installed, TP can't be enabled
    if (-not (Test-Path $huntressPath)) {
        $result.Reason = "Huntress not installed"
        return $result
    }

    # Check if EDR (Rio) service is running - TP requires Rio
    $rioRunning = Test-ServiceRunning $HuntressEDRServiceName
    if (-not $rioRunning) {
        $result.Reason = "HuntressRio not running - TP not active"
        return $result
    }

    # Rio is running, TP may be enabled
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

function Remove-Huntress {
    <#
    .SYNOPSIS
        Uninstalls the Huntress agent.
    .DESCRIPTION
        Stops services, runs uninstaller, cleans up files and registry.
        Based on the official Huntress uninstallHuntress function.
    .OUTPUTS
        Returns $true on success, $false on failure.
    #>

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

    # Kill any lingering processes
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
        if (Test-ServiceExists $svc) {
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

function Install-Huntress {
    <#
    .SYNOPSIS
        Downloads and installs the Huntress agent.
    .DESCRIPTION
        Downloads installer from Huntress, verifies signature, installs with
        provided account key, org key, and tags.
    .OUTPUTS
        Returns $true on success, $false on failure.
    #>

    # Validate configuration
    if ($AccountKey -match '^\{\{' -or [string]::IsNullOrWhiteSpace($AccountKey)) {
        Write-LevelLog "Account key not configured" -Level "ERROR"
        return $false
    }
    if ($AccountKey.Length -ne 32) {
        Write-LevelLog "Invalid account key length (expected 32 chars)" -Level "ERROR"
        return $false
    }
    if ($OrganizationKey -match '^\{\{' -or [string]::IsNullOrWhiteSpace($OrganizationKey)) {
        Write-LevelLog "Organization key not configured" -Level "ERROR"
        return $false
    }

    $maskedKey = $AccountKey.Substring(0,4) + "************************" + $AccountKey.Substring(28,4)
    Write-LevelLog "Account Key: $maskedKey"
    Write-LevelLog "Organization: $OrganizationKey"

    # Build download URL
    $DownloadURL = "https://update.huntress.io/download/$AccountKey/$InstallerName"

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
        Write-LevelLog "Download failed: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }

    if (-not (Test-Path $InstallerPath)) {
        Write-LevelLog "Installer not found after download" -Level "ERROR"
        return $false
    }

    # Verify digital signature
    Write-LevelLog "Verifying installer signature..."
    try {
        $sig = Get-AuthenticodeSignature -FilePath $InstallerPath
        if ($sig.Status -ne 'Valid') {
            Write-LevelLog "Invalid installer signature: $($sig.Status)" -Level "ERROR"
            return $false
        }
    }
    catch {
        Write-LevelLog "Signature verification failed: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }

    # Build install arguments
    $installArgs = "/ACCT_KEY=`"$AccountKey`" /ORG_KEY=`"$OrganizationKey`" /S"
    if ($HuntressTags -notmatch '^\{\{' -and -not [string]::IsNullOrWhiteSpace($HuntressTags)) {
        $installArgs = "/ACCT_KEY=`"$AccountKey`" /ORG_KEY=`"$OrganizationKey`" /TAGS=`"$HuntressTags`" /S"
        Write-LevelLog "Tags: $HuntressTags"
    }

    # Run installer
    Write-LevelLog "Installing Huntress..."
    try {
        $proc = Start-Process $InstallerPath -ArgumentList $installArgs -PassThru
        $proc | Wait-Process -Timeout 120 -ErrorAction Stop
    }
    catch {
        if ($proc) { Stop-Process $proc -Force -ErrorAction SilentlyContinue }
        Write-LevelLog "Installation timed out or failed: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
    finally {
        # Cleanup installer
        Remove-Item $InstallerPath -Force -ErrorAction SilentlyContinue
    }

    # Verify installation
    Write-LevelLog "Verifying installation..."
    Start-Sleep -Seconds 5

    if (-not (Test-HuntressInstalled)) {
        Write-LevelLog "Installation verification failed - agent not found" -Level "ERROR"
        return $false
    }

    # Check services
    $servicesOk = $true
    foreach ($svc in @($HuntressAgentServiceName, $HuntressUpdaterServiceName)) {
        if (-not (Test-ServiceExists $svc)) {
            Write-LevelLog "Service not found: $svc" -Level "WARN"
            $servicesOk = $false
        }
        elseif (-not (Test-ServiceRunning $svc)) {
            Write-LevelLog "Service not running, attempting start: $svc" -Level "WARN"
            Start-Service $svc -ErrorAction SilentlyContinue
        }
    }

    Write-LevelLog "Huntress installed successfully" -Level "SUCCESS"
    return $true
}

function Test-HuntressHealthy {
    <#
    .SYNOPSIS
        Checks if Huntress services are running and healthy.
    .OUTPUTS
        Returns $true if healthy, $false otherwise.
    #>

    $healthy = $true

    # Check agent service
    if (-not (Test-ServiceRunning $HuntressAgentServiceName)) {
        Write-LevelLog "HuntressAgent service not running" -Level "WARN"
        $healthy = $false
    }

    # Check updater service
    if (-not (Test-ServiceRunning $HuntressUpdaterServiceName)) {
        Write-LevelLog "HuntressUpdater service not running" -Level "WARN"
        $healthy = $false
    }

    # Check EDR service (optional - may not be installed yet on new installs)
    if (Test-ServiceExists $HuntressEDRServiceName) {
        if (-not (Test-ServiceRunning $HuntressEDRServiceName)) {
            Write-LevelLog "HuntressRio service exists but not running" -Level "WARN"
        }
    }

    return $healthy
}

function Repair-HuntressServices {
    <#
    .SYNOPSIS
        Attempts to start stopped Huntress services.
    #>

    $services = @($HuntressAgentServiceName, $HuntressUpdaterServiceName, $HuntressEDRServiceName)

    foreach ($svc in $services) {
        if ((Test-ServiceExists $svc) -and (-not (Test-ServiceRunning $svc))) {
            Write-LevelLog "Starting service: $svc"
            try {
                Start-Service $svc -ErrorAction Stop
                Start-Sleep -Seconds 2
                if (Test-ServiceRunning $svc) {
                    Write-LevelLog "Service started: $svc" -Level "SUCCESS"
                }
                else {
                    Write-LevelLog "Service failed to start: $svc" -Level "ERROR"
                }
            }
            catch {
                Write-LevelLog "Error starting $svc : $($_.Exception.Message)" -Level "ERROR"
            }
        }
    }
}

# ============================================================
# INITIALIZE
# ============================================================

$Init = Initialize-LevelScript -ScriptName "SoftwarePolicy-$SoftwareName" `
                               -MspScratchFolder $MspScratchFolder `
                               -DeviceHostname $DeviceHostname `
                               -DeviceTags $DeviceTags

if (-not $Init.Success) {
    exit 0
}

# ============================================================
# MAIN SCRIPT LOGIC
# ============================================================

$ScriptVersion = "2026.01.08.01"
$InvokeParams = @{ ScriptBlock = {

    Write-LevelLog "Huntress Policy Check (v$ScriptVersion)"
    Write-Host ""

    # Get policy from tags
    $Policy = Invoke-SoftwarePolicyCheck -SoftwareName $SoftwareName -DeviceTags $DeviceTags

    # Current state
    $isInstalled = Test-HuntressInstalled
    Write-LevelLog "Huntress installed: $isInstalled"

    # Execute based on resolved action
    switch ($Policy.ResolvedAction) {
        "Skip" {
            Write-LevelLog "SKIP: Hands-off mode"
            Write-Output "STATUS: SKIPPED"
        }

        "Install" {
            if ($isInstalled) {
                Write-LevelLog "Huntress already installed - checking health"
                if (Test-HuntressHealthy) {
                    Write-LevelLog "Huntress is healthy" -Level "SUCCESS"
                    Write-Output "STATUS: INSTALLED_HEALTHY"
                }
                else {
                    Write-LevelLog "Attempting service repair..."
                    Repair-HuntressServices
                    Write-Output "STATUS: REPAIRED"
                }
            }
            else {
                Write-LevelLog "Installing Huntress..."
                $success = Install-Huntress
                if ($success) {
                    Write-Output "STATUS: INSTALLED"
                }
                else {
                    Write-Output "STATUS: INSTALL_FAILED"
                    exit 1
                }
            }
        }

        "Remove" {
            if (-not $isInstalled) {
                Write-LevelLog "Huntress not installed - nothing to remove"
                Write-Output "STATUS: NOT_INSTALLED"
            }
            else {
                # Check if TP might be active (Rio running)
                $tpStatus = Test-TamperProtectionEnabled
                if ($tpStatus.MayBeEnabled) {
                    Write-LevelLog "Note: $($tpStatus.Reason)"
                    Write-LevelLog "Attempting uninstall - will verify if TP blocks it..."
                }

                # Attempt the uninstall
                Write-LevelLog "Starting Huntress removal..."
                $success = Remove-Huntress

                # Verify: Did it actually work?
                Start-Sleep -Seconds 3
                $stillInstalled = Test-HuntressInstalled

                if (-not $stillInstalled) {
                    # Success - Huntress is gone
                    Write-LevelLog "Huntress removed successfully" -Level "SUCCESS"
                    Write-Output "STATUS: REMOVED"
                }
                elseif ($tpStatus.MayBeEnabled) {
                    # Failed and Rio was running - TP likely blocked it
                    Write-LevelLog ""
                    Write-LevelLog "============================================" -Level "WARN"
                    Write-LevelLog "TAMPER PROTECTION IS BLOCKING UNINSTALL" -Level "WARN"
                    Write-LevelLog "============================================" -Level "WARN"
                    Write-LevelLog ""
                    Write-LevelLog "Huntress files still exist after uninstall attempt."
                    Write-LevelLog "This indicates Tamper Protection is enabled."
                    Write-LevelLog ""
                    Write-LevelLog "ACTION REQUIRED:" -Level "WARN"
                    Write-LevelLog "1. Go to Huntress Dashboard" -Level "WARN"
                    Write-LevelLog "2. Settings -> Tamper Protection -> Exclusions" -Level "WARN"
                    Write-LevelLog "3. Add this device: $env:COMPUTERNAME" -Level "WARN"
                    Write-LevelLog "4. Wait ~30 minutes for settings to sync" -Level "WARN"
                    Write-LevelLog "5. Policy will retry automatically on next run" -Level "WARN"
                    Write-LevelLog ""
                    Write-Output "STATUS: TP_ENABLED"
                    # Exit 0 - not a failure, just waiting for TP disable
                    exit 0
                }
                else {
                    # Failed but Rio wasn't running - something else went wrong
                    Write-LevelLog "Removal failed - Huntress still present" -Level "ERROR"
                    Write-LevelLog "TP was not detected, investigate manually"
                    Write-Output "STATUS: REMOVE_FAILED"
                    exit 1
                }
            }
        }

        $null {
            if ($Policy.IsPinned) {
                Write-LevelLog "PINNED: State locked, no changes"
                Write-Output "STATUS: PINNED"
            }
            elseif ($Policy.IsBlocked) {
                Write-LevelLog "BLOCKED: Install prevented"
                Write-Output "STATUS: BLOCKED"
            }
            else {
                Write-LevelLog "NO POLICY: No tags found for huntress"
                Write-Output "STATUS: NO_POLICY"
            }
        }
    }

    # Run verification if needed (and not removing)
    if ($Policy.ShouldVerify -and $Policy.ResolvedAction -ne "Remove") {
        Write-Host ""
        Write-LevelLog "Running verification check..."

        if (-not $isInstalled) {
            Write-LevelLog "Verification failed: Huntress not installed" -Level "ERROR"
            exit 1
        }

        if (-not (Test-HuntressHealthy)) {
            Write-LevelLog "Services not healthy - attempting repair..."
            Repair-HuntressServices
            Start-Sleep -Seconds 5

            if (-not (Test-HuntressHealthy)) {
                Write-LevelLog "Repair failed - services still not healthy" -Level "ERROR"
                exit 1
            }
        }

        Write-LevelLog "Verification passed" -Level "SUCCESS"
    }

    Write-Host ""
    Write-LevelLog "Policy check completed" -Level "SUCCESS"
}}

if ($RunningFromLauncher) { $InvokeParams.NoExit = $true }
Invoke-LevelScript @InvokeParams
