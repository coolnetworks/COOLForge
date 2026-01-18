<#
.SYNOPSIS
    Software policy enforcement for Unchecky.

.DESCRIPTION
    Implements the COOLForge 5-tag policy model for Unchecky software management.
    See docs/POLICY-TAGS.md for the complete policy specification.

    POLICY FLOW (per POLICY-TAGS.md):
    1. Check global control tags (device must have checkmark to be managed)
    2. Check software-specific override tags (highest priority)
    3. Fall back to custom field policy (policy_unchecky)
    4. Execute resolved action (install/remove/reinstall)

    GLOBAL CONTROL TAGS (standalone):
    - U+2705 = Device is managed (required to process)
    - U+274C = Device is excluded from management
    - Both = Device is globally pinned (no changes)

    SOFTWARE-SPECIFIC OVERRIDE TAGS (with "unchecky" suffix):
    - U+1F64F unchecky = Install if missing (transient)
    - U+1F6AB unchecky = Remove if present (transient)
    - U+1F4CC unchecky = Pin - no changes allowed (persistent)
    - U+1F504 unchecky = Reinstall - remove + install (transient)
    - U+2705 unchecky  = Status: software is installed (set by script)

    CUSTOM FIELD POLICY (inherited Group->Folder->Device):
    - policy_unchecky = "install" | "remove" | "pin" | ""

.NOTES
    Version:          2026.01.16.01
    Target Platform:  Level.io RMM (via Script Launcher)
    Exit Codes:       0 = Success | 1 = Alert (Failure)

    Level.io Variables Used (passed from Script Launcher):
    - $MspScratchFolder   : MSP-defined scratch folder for persistent storage
    - $DeviceHostname     : Device hostname from Level.io
    - $DeviceTags         : Comma-separated list of device tags
    - $policy_unchecky    : Custom field policy value (inherited)

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# Software Policy - Unchecky
# Version: 2026.01.16.01
# Target: Level.io (via Script Launcher)
# Exit 0 = Success | Exit 1 = Alert (Failure)
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge

# ============================================================
# DEBUG OUTPUT HELPER (Software-specific)
# ============================================================
# Generic debug functions (Write-DebugSection, Write-DebugTags, Write-DebugPolicy,
# Write-DebugTagManagement) are in COOLForge-Common.psm1. This function is
# Unchecky-specific with hardcoded paths.

function Write-DebugInstallCheck {
    param([bool]$IsInstalled)
    if (-not $DebugScripts) { return }

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " DEBUG: Installation Check" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    $FilePaths = @(
        "$env:ProgramFiles\Unchecky\unchecky.exe",
        "${env:ProgramFiles(x86)}\Unchecky\unchecky.exe"
    )
    $RegPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Unchecky",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Unchecky"
    )

    Write-Host "  --- File Paths ---"
    $FileFound = $false
    foreach ($Path in $FilePaths) {
        $Exists = Test-Path $Path
        if ($Exists) { $FileFound = $true }
        Write-Host "  $(if ($Exists) { '[FOUND]' } else { '[    ]' }) $Path" -ForegroundColor $(if ($Exists) { 'Green' } else { 'DarkGray' })
    }

    Write-Host ""
    Write-Host "  --- Registry Keys ---"
    $RegFound = $false
    foreach ($Path in $RegPaths) {
        $Exists = Test-Path $Path
        if ($Exists) { $RegFound = $true }
        Write-Host "  $(if ($Exists) { '[FOUND]' } else { '[    ]' }) $Path" -ForegroundColor $(if ($Exists) { 'Green' } else { 'DarkGray' })
    }

    Write-Host ""
    Write-Host "  SOFTWARE INSTALLED: $(if ($IsInstalled) { 'YES' } else { 'NO' })" -ForegroundColor $(if ($IsInstalled) { 'Green' } else { 'Yellow' })
}

# ============================================================
# CONFIGURATION
# ============================================================
$SoftwareName = "unchecky"
$InstallerName = "unchecky_setup.exe"

# Installer URL - MUST be set via custom field (no default)
# Download from https://www.fosshub.com/Unchecky.html and host on your own publicly accessible URL
$CustomUrlVar = "policy_${SoftwareName}_url"
$InstallerUrl = Get-Variable -Name $CustomUrlVar -ValueOnly -ErrorAction SilentlyContinue
if ([string]::IsNullOrWhiteSpace($InstallerUrl) -or $InstallerUrl -like "{{*}}") {
    $InstallerUrl = $null
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
# SOFTWARE DETECTION (uses library functions)
# ============================================================

$UncheckyInstallPaths = @(
    "$env:ProgramFiles\Unchecky\unchecky.exe",
    "${env:ProgramFiles(x86)}\Unchecky\unchecky.exe"
)

function Test-UncheckyInstalled {
    $result = Test-SoftwareInstalled -SoftwareName "Unchecky" `
                                     -InstallPaths $UncheckyInstallPaths `
                                     -SkipProcessCheck `
                                     -SkipServiceCheck
    if ($DebugScripts -and $result) {
        Write-Host "  [DEBUG] Unchecky detected via library function" -ForegroundColor Green
    }
    return $result
}

function Install-Unchecky {
    param([string]$ScratchFolder)

    # Validate installer URL is configured
    if ([string]::IsNullOrWhiteSpace($InstallerUrl)) {
        Write-Host "Alert: Unchecky install failed - policy_unchecky_url custom field not configured"
        Write-Host "  To fix this:"
        Write-Host "  1. Download installer from: https://www.fosshub.com/Unchecky.html"
        Write-Host "  2. Host the file on a publicly accessible URL (S3, Azure Blob, web server)"
        Write-Host "  3. Set the 'policy_unchecky_url' custom field to your hosted URL"
        Write-LevelLog "Installer URL not configured - set policy_unchecky_url custom field" -Level "ERROR"
        return $false
    }

    # Validate scratch folder path
    if ([string]::IsNullOrWhiteSpace($ScratchFolder) -or $ScratchFolder -like "*{{*") {
        Write-Host "Alert: Invalid scratch folder path"
        Write-Host "  ScratchFolder: $ScratchFolder"
        Write-LevelLog "Invalid scratch folder - template variable not resolved" -Level "ERROR"
        return $false
    }

    # Store installers in dedicated subfolder under scratch folder
    $InstallersFolder = Join-Path $ScratchFolder "Installers"
    if (-not (Test-Path $InstallersFolder)) {
        New-Item -ItemType Directory -Path $InstallersFolder -Force | Out-Null
    }
    $InstallerPath = Join-Path $InstallersFolder $InstallerName

    # Download installer with retry for small/corrupt files
    $MinFileSize = 1MB
    $MaxRetries = 2
    $RetryCount = 0

    while ($RetryCount -le $MaxRetries) {
        Write-LevelLog "Downloading Unchecky installer$(if ($RetryCount -gt 0) { " (retry $RetryCount)" })..."
        try {
            # Remove existing file if present
            if (Test-Path $InstallerPath) {
                Remove-Item $InstallerPath -Force -ErrorAction SilentlyContinue
            }

            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $InstallerUrl -OutFile $InstallerPath -UseBasicParsing -ErrorAction Stop

            # Validate file exists and size
            if (Test-Path $InstallerPath) {
                $FileSize = (Get-Item $InstallerPath).Length
                if ($FileSize -ge $MinFileSize) {
                    Write-LevelLog "Downloaded installer: $([math]::Round($FileSize/1MB, 2)) MB"
                    break  # Success
                }
                else {
                    Write-LevelLog "Downloaded file too small ($FileSize bytes), expected >= $MinFileSize - retrying..." -Level "WARN"
                    $RetryCount++
                }
            }
            else {
                Write-LevelLog "File not found after download - retrying..." -Level "WARN"
                $RetryCount++
            }
        }
        catch {
            Write-LevelLog "Download failed: $($_.Exception.Message)" -Level "WARN"
            $RetryCount++
        }

        if ($RetryCount -gt $MaxRetries) {
            Write-Host "Alert: Failed to download Unchecky installer after $MaxRetries retries"
            Write-Host "  URL: $InstallerUrl"
            Write-Host "  Target: $InstallerPath"
            Write-LevelLog "Failed to download installer after retries" -Level "ERROR"
            return $false
        }

        Start-Sleep -Seconds 2
    }

    if (-not (Test-Path $InstallerPath)) {
        Write-Host "Alert: Installer file not found after download"
        Write-Host "  Expected path: $InstallerPath"
        Write-LevelLog "Installer not found after download" -Level "ERROR"
        return $false
    }

    # Run silent install (with retry on failure)
    $InstallArgs = "-install -no_desktop_icon"
    $maxAttempts = 2
    $installSuccess = $false

    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        Write-LevelLog "Installing Unchecky (attempt $attempt of $maxAttempts)..."
        try {
            $Process = Start-Process -FilePath $InstallerPath -ArgumentList $InstallArgs -Wait -PassThru -ErrorAction Stop

            if ($Process.ExitCode -eq 0) {
                $installSuccess = $true
                break
            }

            # Installation failed - attempt cleanup and retry
            if ($attempt -lt $maxAttempts) {
                Write-LevelLog "Installation failed (exit code: $($Process.ExitCode)) - attempting cleanup and retry..." -Level "WARN"

                # Kill Unchecky processes
                $uncheckyProcs = Get-Process -Name "unchecky*", "unchecky_bg*", "unchecky_svc*" -ErrorAction SilentlyContinue
                if ($uncheckyProcs) {
                    Write-LevelLog "Killing Unchecky processes..."
                    $uncheckyProcs | Stop-Process -Force -ErrorAction SilentlyContinue
                    Start-Sleep -Seconds 3
                }

                # Force remove Unchecky directories
                $uncheckyPaths = @(
                    "$env:ProgramFiles\Unchecky",
                    "${env:ProgramFiles(x86)}\Unchecky"
                )
                foreach ($path in $uncheckyPaths) {
                    if (Test-Path $path) {
                        Write-LevelLog "Force removing: $path"
                        Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }

                # Clear temp files
                Get-ChildItem "$env:TEMP\*unchecky*" -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

                Write-LevelLog "Cleanup complete - retrying installation..."
                continue
            }

            # Final attempt failed
            Write-Host "Alert: Unchecky installer failed after $maxAttempts attempts"
            Write-Host "  Installer: $InstallerPath"
            Write-Host "  Arguments: $InstallArgs"
            Write-Host "  Exit code: $($Process.ExitCode)"
            Write-LevelLog "Installer exited with code: $($Process.ExitCode)" -Level "ERROR"
        }
        catch {
            Write-LevelLog "Installation error: $($_.Exception.Message)" -Level "WARN"

            if ($attempt -lt $maxAttempts) {
                Write-LevelLog "Attempting cleanup and retry..." -Level "WARN"
                # Kill processes and retry
                Get-Process -Name "unchecky*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
                continue
            }

            Write-Host "Alert: Unchecky installation exception"
            Write-Host "  Installer: $InstallerPath"
            Write-Host "  Error: $($_.Exception.Message)"
            Write-LevelLog "Installation failed: $($_.Exception.Message)" -Level "ERROR"
        }
    }

    # Cleanup installer
    if (Test-Path $InstallerPath) {
        Remove-Item $InstallerPath -Force -ErrorAction SilentlyContinue
    }

    if ($installSuccess) {
        Write-LevelLog "Unchecky installed successfully" -Level "SUCCESS"
        return $true
    }

    return $false
}

function Remove-Unchecky {
    # Find the Unchecky install folder
    $InstallPaths = @(
        "${env:ProgramFiles(x86)}\Unchecky",
        "$env:ProgramFiles\Unchecky"
    )

    $InstallPath = $null
    foreach ($Path in $InstallPaths) {
        if (Test-Path $Path) {
            $InstallPath = $Path
            break
        }
    }

    if (-not $InstallPath) {
        Write-LevelLog "Unchecky install folder not found" -Level "WARN"
        return $true  # Not installed = success
    }

    $Uninstaller = Join-Path $InstallPath "uninstall.exe"
    if (-not (Test-Path $Uninstaller)) {
        Write-LevelLog "Unchecky uninstaller not found at $Uninstaller" -Level "WARN"
        return $true  # Uninstaller missing = consider uninstalled
    }

    Write-LevelLog "Uninstalling Unchecky..."
    try {
        # Copy uninstaller to temp folder (required for proper uninstall)
        $TempFolder = Join-Path $env:TEMP "Unchecky_Uninstall"
        if (-not (Test-Path $TempFolder)) {
            New-Item -ItemType Directory -Path $TempFolder -Force | Out-Null
        }
        $TempUninstaller = Join-Path $TempFolder "uninstall.exe"
        Copy-Item -Path $Uninstaller -Destination $TempUninstaller -Force

        # Run silent uninstall with proper arguments
        $UninstallArgs = "-uninstall -path `"$InstallPath`" -delsettings 1"
        $Process = Start-Process -FilePath $TempUninstaller -ArgumentList $UninstallArgs -Wait -PassThru -ErrorAction Stop

        if ($Process.ExitCode -eq 0) {
            Write-LevelLog "Unchecky uninstalled successfully" -Level "SUCCESS"
            # Cleanup temp folder
            Remove-Item $TempFolder -Recurse -Force -ErrorAction SilentlyContinue
            return $true
        }
        else {
            Write-Host "Alert: Unchecky uninstaller failed"
            Write-Host "  Uninstaller: $TempUninstaller"
            Write-Host "  Arguments: $UninstallArgs"
            Write-Host "  Exit code: $($Process.ExitCode)"
            Write-LevelLog "Uninstaller exited with code: $($Process.ExitCode)" -Level "ERROR"
            return $false
        }
    }
    catch {
        Write-Host "Alert: Unchecky uninstallation exception"
        Write-Host "  Install path: $InstallPath"
        Write-Host "  Error: $($_.Exception.Message)"
        Write-LevelLog "Uninstallation failed: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
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
    } -MaskApiKey

    Write-Host ""

    # Get custom field policy if available (passed from launcher)
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
            -RequireUrl $true

        if ($InfraResult.Success) {
            if ($InfraResult.TagsCreated -gt 0 -or $InfraResult.FieldsCreated -gt 0) {
                Write-LevelLog "Created $($InfraResult.TagsCreated) tags, $($InfraResult.FieldsCreated) fields" -Level "SUCCESS"
                # Alert user to configure the new custom fields on first run
                Write-Host ""
                Write-Host "Alert: Policy infrastructure created - please configure custom fields"
                Write-Host "  Set the following custom fields in Level.io:"
                Write-Host "  - policy_unchecky: Set to 'install', 'remove', or 'pin' at Group/Folder/Device level"
                Write-Host "  - policy_unchecky_url: Set to your hosted Unchecky installer URL"
                Write-Host "    (Download from https://www.fosshub.com/Unchecky.html and host it yourself)"
                Write-Host ""
                Write-LevelLog "Infrastructure created - exiting for configuration" -Level "INFO"
                $script:ExitCode = 1
                return 1
            }
        }
        else {
            Write-LevelLog "Infrastructure setup warning: $($InfraResult.Error)" -Level "WARN"
        }
    }

    # Check current installation state
    $IsInstalled = Test-UncheckyInstalled
    Write-LevelLog "Current state: $(if ($IsInstalled) { 'Installed' } else { 'Not installed' })"

    # Debug: Show installation check details
    Write-DebugInstallCheck -IsInstalled $IsInstalled

    Write-Host ""

    # Run the policy check with the 5-tag model
    # For deep debugging, call Get-SoftwarePolicy directly with -ShowDebug
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
                # If triggered by tag, set device custom field to "install" so intent persists
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
                    $ActionSuccess = Install-Unchecky -ScratchFolder $MspScratchFolder
                    if (-not $ActionSuccess) {
                        Write-LevelLog "FAILED: Installation unsuccessful" -Level "ERROR"
                        $script:ExitCode = 1
                    }
                }
            }
            "Remove" {
                # If triggered by tag, set device custom field to "remove" so intent persists
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
                    $ActionSuccess = Remove-Unchecky
                    if (-not $ActionSuccess) {
                        Write-LevelLog "FAILED: Removal unsuccessful" -Level "ERROR"
                        $script:ExitCode = 1
                    }
                }
            }
            "Reinstall" {
                Write-LevelLog "ACTION: Reinstalling $SoftwareName" -Level "INFO"
                if ($IsInstalled) {
                    $RemoveSuccess = Remove-Unchecky
                    if (-not $RemoveSuccess) {
                        Write-LevelLog "FAILED: Could not remove for reinstall" -Level "ERROR"
                        $script:ExitCode = 1
                        break
                    }
                }
                $ActionSuccess = Install-Unchecky -ScratchFolder $MspScratchFolder
                if (-not $ActionSuccess) {
                    Write-LevelLog "FAILED: Reinstallation unsuccessful" -Level "ERROR"
                    $script:ExitCode = 1
                }
            }
            "Pin" {
                Write-LevelLog "Pinned - no changes allowed" -Level "INFO"
                # Set device-level custom field based on intent:
                # - If Remove tag also present, set to "remove" (block installs)
                # - Otherwise set to "pin" (preserve current state)
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
                # Verify current state matches expected
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
    # TAG MANAGEMENT (per POLICY-TAGS.md Tag Cleanup Rules)
    # ============================================================
    # Only update tags if we have an API key
    if ($LevelApiKey) {
        Write-Host ""
        Write-LevelLog "Updating tags..." -Level "INFO"

        # Debug: Get device ID and tags BEFORE changes
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

        # Check final install state
        $FinalInstallState = Test-UncheckyInstalled

        # Tag cleanup based on action and success
        if ($ActionSuccess -and $Policy.ShouldProcess) {
            $SoftwareNameUpper = $SoftwareName.ToUpper()

            switch ($Policy.ResolvedAction) {
                "Install" {
                    # Remove Install tag, set Has tag
                    Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Install" -DeviceHostname $DeviceHostname
                    if ($FinalInstallState) {
                        Add-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Has" -DeviceHostname $DeviceHostname
                    }
                }
                "Remove" {
                    # Remove Remove tag, remove Has tag
                    Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Remove" -DeviceHostname $DeviceHostname
                    Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Has" -DeviceHostname $DeviceHostname
                }
                "Reinstall" {
                    # Remove Reinstall tag, set Has tag
                    Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Reinstall" -DeviceHostname $DeviceHostname
                    if ($FinalInstallState) {
                        Add-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Has" -DeviceHostname $DeviceHostname
                    }
                }
                "Pin" {
                    # Remove Pin tag (intent now captured in custom field)
                    Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Pin" -DeviceHostname $DeviceHostname
                    # Also remove Remove tag if present (intent captured in custom field as "remove")
                    if ("Remove" -in $Policy.PolicyActions) {
                        Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Remove" -DeviceHostname $DeviceHostname
                    }
                    # Ensure Has tag reflects actual state
                    if ($FinalInstallState -and -not $Policy.HasInstalled) {
                        Add-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Has" -DeviceHostname $DeviceHostname
                    }
                    elseif (-not $FinalInstallState -and $Policy.HasInstalled) {
                        Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Has" -DeviceHostname $DeviceHostname
                    }
                }
                "None" {
                    # Reconcile Has tag with actual install state
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

        # Debug: Get tags AFTER changes
        if ($DebugScripts -and $DeviceForTags) {
            $TagsAfter = Get-LevelDeviceTagNames -ApiKey $LevelApiKey -DeviceId $DeviceForTags.id
            Write-LevelLog "Tags AFTER: $($TagsAfter -join ', ')" -Level "DEBUG"

            # Show what changed
            $Added = $TagsAfter | Where-Object { $_ -notin $TagsBefore }
            $Removed = $TagsBefore | Where-Object { $_ -notin $TagsAfter }
            if ($Added.Count -gt 0) {
                Write-LevelLog "Tags ADDED: $($Added -join ', ')" -Level "DEBUG"
            }
            if ($Removed.Count -gt 0) {
                Write-LevelLog "Tags REMOVED: $($Removed -join ', ')" -Level "DEBUG"
            }
            if ($Added.Count -eq 0 -and $Removed.Count -eq 0) {
                Write-LevelLog "No tag changes detected" -Level "DEBUG"
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

    # Return exit code based on action success
    return $(if ($ActionSuccess) { 0 } else { 1 })
}}
if ($RunningFromLauncher) { $InvokeParams.NoExit = $true }
Invoke-LevelScript @InvokeParams

exit $ExitCode
