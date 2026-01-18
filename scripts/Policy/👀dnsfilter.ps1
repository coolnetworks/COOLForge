<#
.SYNOPSIS
    Software policy enforcement for DNSFilter Agent.

.DESCRIPTION
    Implements the COOLForge 5-tag policy model for DNSFilter Agent management.
    See docs/POLICY-TAGS.md for the complete policy specification.

    POLICY FLOW (per POLICY-TAGS.md):
    1. Check global control tags (device must have checkmark to be managed)
    2. Check software-specific override tags (highest priority)
    3. Fall back to custom field policy (policy_dnsfilter)
    4. Execute resolved action (install/remove/reinstall)

    GLOBAL CONTROL TAGS (standalone):
    - U+2705 = Device is managed (required to process)
    - U+274C = Device is excluded from management
    - Both = Device is globally pinned (no changes)

    SOFTWARE-SPECIFIC OVERRIDE TAGS (with "dnsfilter" suffix):
    - U+1F64F dnsfilter = Install if missing (transient)
    - U+1F6AB dnsfilter = Remove if present (transient)
    - U+1F4CC dnsfilter = Pin - no changes allowed (persistent)
    - U+1F504 dnsfilter = Reinstall - remove + install (transient)
    - U+2705 dnsfilter  = Status: software is installed (set by script)

    CUSTOM FIELD POLICY (inherited Group->Folder->Device):
    - policy_dnsfilter = "install" | "remove" | "pin" | ""

.NOTES
    Version:          2026.01.18.01
    Target Platform:  Level.io RMM (via Script Launcher)
    Exit Codes:       0 = Success | 1 = Alert (Failure)

    Level.io Variables Used (passed from Script Launcher):
    - $MspScratchFolder   : MSP-defined scratch folder for persistent storage
    - $DeviceHostname     : Device hostname from Level.io
    - $DeviceTags         : Comma-separated list of device tags
    - $policy_dnsfilter   : Custom field policy value (inherited)

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# Software Policy - DNSFilter
# Version: 2026.01.18.01
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

    $ServiceName = "DNS Agent"
    $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

    Write-Host "  --- Service Check ---"
    if ($Service) {
        Write-Host "  [FOUND] Service: $ServiceName" -ForegroundColor Green
        Write-Host "          Status: $($Service.Status)" -ForegroundColor $(if ($Service.Status -eq 'Running') { 'Green' } else { 'Yellow' })
    } else {
        Write-Host "  [    ] Service: $ServiceName not found" -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "  --- Registry Check ---"
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $existingInstall = $uninstallPaths | ForEach-Object {
        Get-ItemProperty $_ -ErrorAction SilentlyContinue
    } | Where-Object { $_.DisplayName -like "*DNS Agent*" -or $_.DisplayName -like "*DNSFilter*" }

    if ($existingInstall) {
        foreach ($install in $existingInstall) {
            Write-Host "  [FOUND] $($install.DisplayName)" -ForegroundColor Green
        }
    } else {
        Write-Host "  [    ] No DNSFilter registry entries found" -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "  SOFTWARE INSTALLED: $(if ($IsInstalled) { 'YES' } else { 'NO' })" -ForegroundColor $(if ($IsInstalled) { 'Green' } else { 'Yellow' })
}

# ============================================================
# CONFIGURATION
# ============================================================
$SoftwareName = "dnsfilter"
$ServiceName = "DNS Agent"
$LockFileName = "DNSFilter_Deployment.lock"

# Site key from custom field (required for installation)
$SiteKeyVar = "policy_dnsfilter_sitekey"
$SiteKey = Get-Variable -Name $SiteKeyVar -ValueOnly -ErrorAction SilentlyContinue
if ([string]::IsNullOrWhiteSpace($SiteKey) -or $SiteKey -like "{{*}}") {
    $SiteKey = $null
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
# SOFTWARE DETECTION
# ============================================================

function Test-DNSFilterInstalled {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    $result = $service -and $service.Status -eq 'Running'

    if ($DebugScripts -and $result) {
        Write-Host "  [DEBUG] DNSFilter Agent detected - service running" -ForegroundColor Green
    }
    return $result
}

function Install-DNSFilter {
    param([string]$ScratchFolder)

    # Validate site key is configured
    if ([string]::IsNullOrWhiteSpace($SiteKey)) {
        Write-Host "Alert: DNSFilter install failed - policy_dnsfilter_sitekey custom field not configured"
        Write-LevelLog "Site key not configured - set policy_dnsfilter_sitekey custom field" -Level "ERROR"
        return $false
    }

    # FIRST: Stop existing service and kill processes before any uninstall/install
    $dnsService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($dnsService) {
        Write-LevelLog "Stopping DNS Agent service..."
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
    }

    # Kill any DNSFilter-related processes
    $dnsProcesses = Get-Process -Name "DNS_Agent*", "dnsfilter*", "dnscrypt*" -ErrorAction SilentlyContinue
    if ($dnsProcesses) {
        Write-LevelLog "Killing DNSFilter processes..."
        $dnsProcesses | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }

    # Check for existing installation via registry
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $existingInstall = $uninstallPaths | ForEach-Object {
        Get-ItemProperty $_ -ErrorAction SilentlyContinue
    } | Where-Object { $_.DisplayName -like "*DNS Agent*" -or $_.DisplayName -like "*DNSFilter*" }

    if ($existingInstall) {
        Write-LevelLog "Existing DNSFilter installation found. Removing first..."
        foreach ($install in $existingInstall) {
            $uninstallString = $install.UninstallString
            if ($uninstallString -match 'msiexec') {
                if ($uninstallString -match '\{[A-Fa-f0-9\-]+\}') {
                    $productCode = $matches[0]
                    Write-LevelLog "Uninstalling product: $productCode"
                    $uninstallProcess = Start-Process msiexec.exe -ArgumentList "/x $productCode /qn /norestart" -Wait -PassThru -WindowStyle Hidden
                    if ($uninstallProcess.ExitCode -eq 0) {
                        Write-LevelLog "Successfully uninstalled existing installation" -Level "SUCCESS"
                    } else {
                        Write-LevelLog "Uninstall returned exit code: $($uninstallProcess.ExitCode)" -Level "WARN"
                    }
                }
            }
        }

        # Wait for uninstall to complete
        Write-LevelLog "Waiting for uninstall to complete..."
        Start-Sleep -Seconds 10

        # Kill any lingering processes after uninstall
        $dnsProcesses = Get-Process -Name "DNS_Agent*", "dnsfilter*", "dnscrypt*" -ErrorAction SilentlyContinue
        if ($dnsProcesses) {
            Write-LevelLog "Killing lingering DNSFilter processes..."
            $dnsProcesses | Stop-Process -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
    }

    # Download MSI
    $msiUrl = "https://download.dnsfilter.com/User_Agent/Windows/DNS_Agent_Setup.msi"
    $tempMsi = Join-Path $env:TEMP "DNS_Agent_Setup.msi"

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    Write-LevelLog "Downloading DNSFilter Agent MSI..."
    $downloadSuccess = $false
    $downloadTimeout = 300

    for ($i = 1; $i -le 3; $i++) {
        try {
            if (Test-Path $tempMsi) {
                Remove-Item $tempMsi -Force -ErrorAction SilentlyContinue
            }

            $ProgressPreference = 'SilentlyContinue'
            Write-LevelLog "Download attempt $i of 3 (timeout: ${downloadTimeout}s)..."

            Invoke-WebRequest -Uri $msiUrl -OutFile $tempMsi -TimeoutSec $downloadTimeout -UseBasicParsing -ErrorAction Stop

            if (Test-Path $tempMsi) {
                $fileSize = (Get-Item $tempMsi).Length
                if ($fileSize -gt 1MB) {
                    $fileSizeMB = [math]::Round($fileSize / 1MB, 2)
                    Write-LevelLog "Download complete. File size: ${fileSizeMB}MB" -Level "SUCCESS"
                    $downloadSuccess = $true
                    break
                } else {
                    Write-LevelLog "Downloaded file too small (${fileSize} bytes). Retrying..." -Level "WARN"
                }
            }
        } catch {
            Write-LevelLog "Download attempt $i failed: $($_.Exception.Message)" -Level "WARN"
        }

        if ($i -lt 3) {
            Start-Sleep -Seconds 15
        }
    }

    if (-not $downloadSuccess) {
        Write-Host "Alert: Failed to download DNSFilter MSI after 3 attempts"
        Write-LevelLog "Failed to download MSI after 3 attempts" -Level "ERROR"
        return $false
    }

    # Install
    Write-LevelLog "Installing DNSFilter Agent..."
    $installArgs = "/i `"$tempMsi`" /qn /norestart NKEY=`"$SiteKey`""
    $installProcess = Start-Process msiexec.exe -ArgumentList $installArgs -Wait -PassThru -WindowStyle Hidden

    # Clean up temp file
    Remove-Item $tempMsi -Force -ErrorAction SilentlyContinue

    if ($installProcess.ExitCode -ne 0 -and $installProcess.ExitCode -ne 3010) {
        Write-Host "Alert: DNSFilter installation failed with exit code: $($installProcess.ExitCode)"
        Write-LevelLog "Installation failed with exit code: $($installProcess.ExitCode)" -Level "ERROR"
        return $false
    }

    # Verify installation
    Start-Sleep -Seconds 5
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

    if (-not $service) {
        Write-Host "Alert: DNSFilter Agent service not found after installation"
        Write-LevelLog "Service not found after installation" -Level "ERROR"
        return $false
    }

    # Start service if not running
    if ($service.Status -ne 'Running') {
        Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        $service.Refresh()
    }

    if ($service.Status -eq 'Running') {
        Write-LevelLog "DNSFilter Agent installed and running successfully" -Level "SUCCESS"
        return $true
    } else {
        Write-Host "Alert: DNSFilter Agent installed but service not running. Status: $($service.Status)"
        Write-LevelLog "Service not running after install. Status: $($service.Status)" -Level "ERROR"
        return $false
    }
}

function Remove-DNSFilter {
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $existingInstall = $uninstallPaths | ForEach-Object {
        Get-ItemProperty $_ -ErrorAction SilentlyContinue
    } | Where-Object { $_.DisplayName -like "*DNS Agent*" -or $_.DisplayName -like "*DNSFilter*" }

    if (-not $existingInstall) {
        Write-LevelLog "DNSFilter not found - nothing to remove" -Level "INFO"
        return $true
    }

    # Stop service first
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Write-LevelLog "Stopping DNSFilter service..."
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }

    $success = $true
    foreach ($install in $existingInstall) {
        $uninstallString = $install.UninstallString
        if ($uninstallString -match 'msiexec') {
            if ($uninstallString -match '\{[A-Fa-f0-9\-]+\}') {
                $productCode = $matches[0]
                Write-LevelLog "Uninstalling: $($install.DisplayName) ($productCode)"
                $uninstallProcess = Start-Process msiexec.exe -ArgumentList "/x $productCode /qn /norestart" -Wait -PassThru -WindowStyle Hidden
                if ($uninstallProcess.ExitCode -ne 0) {
                    Write-LevelLog "Uninstall returned code: $($uninstallProcess.ExitCode)" -Level "WARN"
                    $success = $false
                } else {
                    Write-LevelLog "Successfully uninstalled $($install.DisplayName)" -Level "SUCCESS"
                }
            }
        }
    }

    return $success
}

# ============================================================
# MAIN SCRIPT LOGIC
# ============================================================
$ScriptVersion = "2026.01.18.01"
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
        'SiteKey' = if ($SiteKey) { '(configured)' } else { '(not set)' }
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
    # Always check and create missing tags/custom fields
    # Initialize-SoftwarePolicyInfrastructure is idempotent
    if ($LevelApiKey) {
        # Debug: Show API key info (obfuscated - first 4 chars only)
        $KeyLength = $LevelApiKey.Length
        $KeyPreview = if ($KeyLength -gt 4) { $LevelApiKey.Substring(0, 4) + "****" } else { "(invalid)" }
        Write-LevelLog "API key: $KeyPreview (length: $KeyLength)" -Level "DEBUG"

        $InfraResult = Initialize-SoftwarePolicyInfrastructure -ApiKey $LevelApiKey `
            -SoftwareName $SoftwareName `
            -RequireUrl $false

        # Also create the site key custom field if it doesn't exist
        $SiteKeyFieldName = "policy_dnsfilter_sitekey"
        $SiteKeyFieldCreated = $false
        $ExistingSiteKeyField = Find-LevelCustomField -ApiKey $LevelApiKey -FieldName $SiteKeyFieldName
        if (-not $ExistingSiteKeyField) {
            $NewSiteKeyField = New-LevelCustomField -ApiKey $LevelApiKey -Name $SiteKeyFieldName -DefaultValue ""
            if ($NewSiteKeyField) {
                Write-LevelLog "Created custom field: $SiteKeyFieldName (for DNSFilter NKEY)" -Level "SUCCESS"
                $SiteKeyFieldCreated = $true
            }
        }

        $TotalFieldsCreated = $InfraResult.FieldsCreated + $(if ($SiteKeyFieldCreated) { 1 } else { 0 })

        if ($InfraResult.Success) {
            if ($InfraResult.TagsCreated -gt 0 -or $TotalFieldsCreated -gt 0) {
                Write-LevelLog "Created $($InfraResult.TagsCreated) tags, $TotalFieldsCreated fields" -Level "SUCCESS"
                # Alert user to configure the new custom fields on first run
                Write-Host ""
                Write-Host "Alert: Policy infrastructure created - please configure custom fields"
                Write-Host "  Set the following custom fields in Level.io:"
                Write-Host "  - policy_dnsfilter: Set to 'install', 'remove', or 'pin' at Group/Folder/Device level"
                Write-Host "  - policy_dnsfilter_sitekey: Set your DNSFilter site key (NKEY from DNSFilter portal)"
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
    $IsInstalled = Test-DNSFilterInstalled
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
                    Write-LevelLog "Already installed - no action needed" -Level "SUCCESS"
                    $ActionSuccess = $true
                }
                else {
                    Write-LevelLog "ACTION: Installing $SoftwareName" -Level "INFO"
                    $ActionSuccess = Install-DNSFilter -ScratchFolder $MspScratchFolder
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
                    $ActionSuccess = Remove-DNSFilter
                    if (-not $ActionSuccess) {
                        Write-LevelLog "FAILED: Removal unsuccessful" -Level "ERROR"
                        $script:ExitCode = 1
                    }
                }
            }
            "Reinstall" {
                Write-LevelLog "ACTION: Reinstalling $SoftwareName" -Level "INFO"
                if ($IsInstalled) {
                    $RemoveSuccess = Remove-DNSFilter
                    if (-not $RemoveSuccess) {
                        Write-LevelLog "FAILED: Could not remove for reinstall" -Level "ERROR"
                        $script:ExitCode = 1
                        break
                    }
                }
                $ActionSuccess = Install-DNSFilter -ScratchFolder $MspScratchFolder
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

        $FinalInstallState = Test-DNSFilterInstalled

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
