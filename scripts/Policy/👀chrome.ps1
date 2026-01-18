<#
.SYNOPSIS
    Software policy enforcement for Google Chrome Enterprise.

.DESCRIPTION
    Implements the COOLForge 5-tag policy model for Google Chrome Enterprise management.
    See docs/POLICY-TAGS.md for the complete policy specification.

    This script ensures the ENTERPRISE version of Chrome is installed (64-bit MSI-based
    installation in Program Files) rather than the consumer per-user installation.

    POLICY FLOW (per POLICY-TAGS.md):
    1. Check global control tags (device must have checkmark to be managed)
    2. Check software-specific override tags (highest priority)
    3. Fall back to custom field policy (policy_chrome)
    4. Execute resolved action (install/remove/reinstall)

    GLOBAL CONTROL TAGS (standalone):
    - U+2705 = Device is managed (required to process)
    - U+274C = Device is excluded from management
    - Both = Device is globally pinned (no changes)

    SOFTWARE-SPECIFIC OVERRIDE TAGS (with "chrome" suffix):
    - U+1F64F chrome = Install if missing (transient)
    - U+1F6AB chrome = Remove if present (transient)
    - U+1F4CC chrome = Pin - no changes allowed (persistent)
    - U+1F504 chrome = Reinstall - remove + install (transient)
    - U+2705 chrome  = Status: software is installed (set by script)

    CUSTOM FIELD POLICY (inherited Group->Folder->Device):
    - policy_chrome = "install" | "remove" | "pin" | ""

.NOTES
    Version:          2026.01.18.01
    Target Platform:  Level.io RMM (via Script Launcher)
    Exit Codes:       0 = Success | 1 = Alert (Failure)

    Level.io Variables Used (passed from Script Launcher):
    - $MspScratchFolder   : MSP-defined scratch folder for persistent storage
    - $DeviceHostname     : Device hostname from Level.io
    - $DeviceTags         : Comma-separated list of device tags

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# Software Policy - Chrome Enterprise
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
    param([bool]$IsInstalled, [bool]$IsEnterprise)
    if (-not $DebugScripts) { return }

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " DEBUG: Installation Check" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    # Check enterprise installation path
    $EnterprisePath = "C:\Program Files\Google\Chrome\Application\chrome.exe"
    $ConsumerPath = "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
    $UserPath = "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"

    Write-Host "  --- File System Check ---"
    if (Test-Path $EnterprisePath) {
        $version = (Get-Item $EnterprisePath).VersionInfo.ProductVersion
        Write-Host "  [FOUND] Enterprise (64-bit): $EnterprisePath" -ForegroundColor Green
        Write-Host "          Version: $version" -ForegroundColor Green
    } else {
        Write-Host "  [    ] Enterprise path not found" -ForegroundColor DarkGray
    }

    if (Test-Path $ConsumerPath) {
        Write-Host "  [FOUND] Consumer (32-bit): $ConsumerPath" -ForegroundColor Yellow
    }

    if (Test-Path $UserPath) {
        Write-Host "  [FOUND] User install: $UserPath" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "  --- Registry Check ---"
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $existingInstall = $uninstallPaths | ForEach-Object {
        Get-ItemProperty $_ -ErrorAction SilentlyContinue
    } | Where-Object { $_.DisplayName -like "*Google Chrome*" }

    if ($existingInstall) {
        foreach ($install in $existingInstall) {
            $installType = if ($install.PSPath -notlike "*WOW6432Node*") { "64-bit (Enterprise)" } else { "32-bit" }
            Write-Host "  [FOUND] $($install.DisplayName) - $installType" -ForegroundColor Green
            Write-Host "          Version: $($install.DisplayVersion)" -ForegroundColor Green
        }
    } else {
        Write-Host "  [    ] No Chrome registry entries found in HKLM" -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "  SOFTWARE INSTALLED: $(if ($IsInstalled) { 'YES' } else { 'NO' })" -ForegroundColor $(if ($IsInstalled) { 'Green' } else { 'Yellow' })
    Write-Host "  ENTERPRISE VERSION: $(if ($IsEnterprise) { 'YES' } else { 'NO' })" -ForegroundColor $(if ($IsEnterprise) { 'Green' } else { 'Yellow' })
}

# ============================================================
# CONFIGURATION
# ============================================================
$SoftwareName = "chrome"
$DisplayName = "Google Chrome Enterprise"
$EnterprisePath = "C:\Program Files\Google\Chrome\Application\chrome.exe"
$LockFileName = "Chrome_Deployment.lock"

# Enterprise MSI download URL (64-bit)
$ChromeMsiUrl = "https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi"

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

function Test-ChromeEnterpriseInstalled {
    # Check for enterprise installation (64-bit in Program Files)
    $isEnterprise = Test-Path $EnterprisePath

    if ($DebugScripts -and $isEnterprise) {
        $version = (Get-Item $EnterprisePath).VersionInfo.ProductVersion
        Write-Host "  [DEBUG] Chrome Enterprise detected - version $version" -ForegroundColor Green
    }

    return $isEnterprise
}

function Test-ChromeInstalled {
    # Check if ANY Chrome is installed (enterprise or consumer)
    $paths = @(
        $EnterprisePath,
        "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
    )

    foreach ($path in $paths) {
        if (Test-Path $path) {
            return $true
        }
    }

    # Also check registry for system-wide installations
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $existingInstall = $uninstallPaths | ForEach-Object {
        Get-ItemProperty $_ -ErrorAction SilentlyContinue
    } | Where-Object { $_.DisplayName -like "*Google Chrome*" }

    return ($existingInstall.Count -gt 0)
}

function Install-ChromeEnterprise {
    param([string]$ScratchFolder)

    # FIRST: Kill all Chrome processes before doing anything else
    $chromeProcesses = Get-Process -Name "chrome", "GoogleUpdate", "GoogleCrashHandler", "GoogleCrashHandler64" -ErrorAction SilentlyContinue
    if ($chromeProcesses) {
        Write-LevelLog "Closing Chrome and related processes..."
        $chromeProcesses | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
    }

    # Check for existing non-enterprise installation
    $existingNonEnterprise = $false
    $consumerPath = "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"

    if ((Test-Path $consumerPath) -and -not (Test-Path $EnterprisePath)) {
        Write-LevelLog "Consumer Chrome installation detected - will remove before installing enterprise version"
        $existingNonEnterprise = $true
    }

    # Remove existing installation if present (consumer or old enterprise)
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $existingInstall = $uninstallPaths | ForEach-Object {
        Get-ItemProperty $_ -ErrorAction SilentlyContinue
    } | Where-Object { $_.DisplayName -like "*Google Chrome*" }

    if ($existingInstall -and $existingNonEnterprise) {
        Write-LevelLog "Removing existing Chrome installation..."
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
            } elseif ($uninstallString) {
                # Handle non-MSI uninstall (setup.exe based)
                $setupPath = $uninstallString -replace '"', '' -replace '--uninstall.*', ''
                if (Test-Path $setupPath.Trim()) {
                    Write-LevelLog "Running setup uninstaller..."
                    $uninstallArgs = "--uninstall --system-level --force-uninstall"
                    $uninstallProcess = Start-Process $setupPath.Trim() -ArgumentList $uninstallArgs -Wait -PassThru -WindowStyle Hidden
                }
            }
        }

        # Wait for uninstall to complete and verify
        Write-LevelLog "Waiting for uninstall to complete..."
        Start-Sleep -Seconds 10

        # Kill any lingering processes after uninstall
        $chromeProcesses = Get-Process -Name "chrome", "GoogleUpdate", "GoogleCrashHandler", "GoogleCrashHandler64" -ErrorAction SilentlyContinue
        if ($chromeProcesses) {
            Write-LevelLog "Killing lingering Chrome processes..."
            $chromeProcesses | Stop-Process -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
        }

        # Verify uninstall completed
        if (Test-Path $consumerPath) {
            Write-LevelLog "Consumer Chrome still present after uninstall - attempting forced removal" -Level "WARN"
            Remove-Item "C:\Program Files (x86)\Google\Chrome" -Recurse -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
    }

    # Download Enterprise MSI
    $tempMsi = Join-Path $env:TEMP "googlechromestandaloneenterprise64.msi"

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    Write-LevelLog "Downloading Chrome Enterprise MSI (64-bit)..."
    $downloadSuccess = $false
    $downloadTimeout = 300

    for ($i = 1; $i -le 3; $i++) {
        try {
            if (Test-Path $tempMsi) {
                Remove-Item $tempMsi -Force -ErrorAction SilentlyContinue
            }

            $ProgressPreference = 'SilentlyContinue'
            Write-LevelLog "Download attempt $i of 3 (timeout: ${downloadTimeout}s)..."

            Invoke-WebRequest -Uri $ChromeMsiUrl -OutFile $tempMsi -TimeoutSec $downloadTimeout -UseBasicParsing -ErrorAction Stop

            if (Test-Path $tempMsi) {
                $fileSize = (Get-Item $tempMsi).Length
                if ($fileSize -gt 50MB) {
                    $fileSizeMB = [math]::Round($fileSize / 1MB, 2)
                    Write-LevelLog "Download complete. File size: ${fileSizeMB}MB" -Level "SUCCESS"
                    $downloadSuccess = $true
                    break
                } else {
                    Write-LevelLog "Downloaded file too small (${fileSize} bytes). Expected >50MB. Retrying..." -Level "WARN"
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
        Write-Host "Alert: Failed to download Chrome Enterprise MSI after 3 attempts"
        Write-LevelLog "Failed to download MSI after 3 attempts" -Level "ERROR"
        return $false
    }

    # Install Chrome Enterprise
    Write-LevelLog "Installing Chrome Enterprise..."
    $installArgs = "/i `"$tempMsi`" /qn /norestart"
    $installProcess = Start-Process msiexec.exe -ArgumentList $installArgs -Wait -PassThru -WindowStyle Hidden

    # Clean up temp file
    Remove-Item $tempMsi -Force -ErrorAction SilentlyContinue

    if ($installProcess.ExitCode -ne 0 -and $installProcess.ExitCode -ne 3010) {
        Write-Host "Alert: Chrome Enterprise installation failed with exit code: $($installProcess.ExitCode)"
        Write-LevelLog "Installation failed with exit code: $($installProcess.ExitCode)" -Level "ERROR"
        return $false
    }

    # Verify installation
    Start-Sleep -Seconds 3
    if (Test-Path $EnterprisePath) {
        $version = (Get-Item $EnterprisePath).VersionInfo.ProductVersion
        Write-LevelLog "Chrome Enterprise $version installed successfully" -Level "SUCCESS"
        return $true
    } else {
        Write-Host "Alert: Chrome executable not found after installation"
        Write-LevelLog "Chrome executable not found at $EnterprisePath after installation" -Level "ERROR"
        return $false
    }
}

function Remove-Chrome {
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $existingInstall = $uninstallPaths | ForEach-Object {
        Get-ItemProperty $_ -ErrorAction SilentlyContinue
    } | Where-Object { $_.DisplayName -like "*Google Chrome*" }

    if (-not $existingInstall) {
        Write-LevelLog "Chrome not found - nothing to remove" -Level "INFO"
        return $true
    }

    # Close Chrome if running
    $chromeProcesses = Get-Process -Name "chrome" -ErrorAction SilentlyContinue
    if ($chromeProcesses) {
        Write-LevelLog "Closing Chrome processes..."
        $chromeProcesses | Stop-Process -Force -ErrorAction SilentlyContinue
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
        } elseif ($uninstallString) {
            # Handle setup.exe based uninstall
            $setupPath = $uninstallString -replace '"', '' -replace '--uninstall.*', ''
            if (Test-Path $setupPath.Trim()) {
                Write-LevelLog "Running setup uninstaller for $($install.DisplayName)..."
                $uninstallArgs = "--uninstall --system-level --force-uninstall"
                $uninstallProcess = Start-Process $setupPath.Trim() -ArgumentList $uninstallArgs -Wait -PassThru -WindowStyle Hidden
                if ($uninstallProcess.ExitCode -eq 0) {
                    Write-LevelLog "Successfully uninstalled $($install.DisplayName)" -Level "SUCCESS"
                } else {
                    Write-LevelLog "Uninstall returned code: $($uninstallProcess.ExitCode)" -Level "WARN"
                }
            }
        }
    }

    # Verify removal
    Start-Sleep -Seconds 3
    if (-not (Test-ChromeInstalled)) {
        Write-LevelLog "Chrome successfully removed" -Level "SUCCESS"
        return $true
    } else {
        Write-LevelLog "Chrome may still be present after uninstall" -Level "WARN"
        return $success
    }
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
        $KeyLength = $LevelApiKey.Length
        $KeyPreview = if ($KeyLength -gt 4) { $LevelApiKey.Substring(0, 4) + "****" } else { "(invalid)" }
        Write-LevelLog "API key: $KeyPreview (length: $KeyLength)" -Level "DEBUG"

        $InfraResult = Initialize-SoftwarePolicyInfrastructure -ApiKey $LevelApiKey `
            -SoftwareName $SoftwareName `
            -RequireUrl $false

        if ($InfraResult.Success) {
            if ($InfraResult.TagsCreated -gt 0 -or $InfraResult.FieldsCreated -gt 0) {
                Write-LevelLog "Created $($InfraResult.TagsCreated) tags, $($InfraResult.FieldsCreated) fields" -Level "SUCCESS"
                Write-Host ""
                Write-Host "Alert: Policy infrastructure created - please configure custom fields"
                Write-Host "  Set the following custom field in Level.io:"
                Write-Host "  - policy_chrome: Set to 'install', 'remove', or 'pin' at Group/Folder/Device level"
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
    $IsInstalled = Test-ChromeInstalled
    $IsEnterprise = Test-ChromeEnterpriseInstalled
    Write-LevelLog "Current state: $(if ($IsEnterprise) { 'Enterprise installed' } elseif ($IsInstalled) { 'Consumer installed (needs upgrade)' } else { 'Not installed' })"

    # Debug: Show installation check details
    Write-DebugInstallCheck -IsInstalled $IsInstalled -IsEnterprise $IsEnterprise

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
    # For Chrome, we consider "installed" only if ENTERPRISE version is present
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
                if ($IsEnterprise) {
                    Write-LevelLog "Enterprise Chrome already installed - no action needed" -Level "SUCCESS"
                    $ActionSuccess = $true
                }
                elseif ($IsInstalled) {
                    Write-LevelLog "Consumer Chrome detected - upgrading to Enterprise version" -Level "INFO"
                    Write-LevelLog "ACTION: Installing $DisplayName" -Level "INFO"
                    $ActionSuccess = Install-ChromeEnterprise -ScratchFolder $MspScratchFolder
                    if (-not $ActionSuccess) {
                        Write-LevelLog "FAILED: Installation unsuccessful" -Level "ERROR"
                        $script:ExitCode = 1
                    }
                }
                else {
                    Write-LevelLog "ACTION: Installing $DisplayName" -Level "INFO"
                    $ActionSuccess = Install-ChromeEnterprise -ScratchFolder $MspScratchFolder
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
                    Write-LevelLog "ACTION: Removing Chrome" -Level "INFO"
                    $ActionSuccess = Remove-Chrome
                    if (-not $ActionSuccess) {
                        Write-LevelLog "FAILED: Removal unsuccessful" -Level "ERROR"
                        $script:ExitCode = 1
                    }
                }
            }
            "Reinstall" {
                Write-LevelLog "ACTION: Reinstalling $DisplayName" -Level "INFO"
                if ($IsInstalled) {
                    $RemoveSuccess = Remove-Chrome
                    if (-not $RemoveSuccess) {
                        Write-LevelLog "FAILED: Could not remove for reinstall" -Level "ERROR"
                        $script:ExitCode = 1
                        break
                    }
                }
                $ActionSuccess = Install-ChromeEnterprise -ScratchFolder $MspScratchFolder
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
                if ($Policy.HasInstalled -and -not $IsEnterprise) {
                    Write-LevelLog "WARNING: Status tag says installed but enterprise Chrome not found" -Level "WARN"
                }
                elseif (-not $Policy.HasInstalled -and $IsEnterprise) {
                    Write-LevelLog "INFO: Enterprise Chrome is installed (no policy action)" -Level "INFO"
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

        # Use enterprise detection for final state
        $FinalInstallState = Test-ChromeEnterpriseInstalled

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
