<#
.SYNOPSIS
    Software policy enforcement for {{SOFTWARE_DISPLAY_NAME}}.

.DESCRIPTION
    Implements the COOLForge 5-tag policy model for {{SOFTWARE_DISPLAY_NAME}} management.
    See docs/POLICY-TAGS.md for the complete policy specification.

    POLICY FLOW (per POLICY-TAGS.md):
    1. Check global control tags (device must have checkmark to be managed)
    2. Check software-specific override tags (highest priority)
    3. Fall back to custom field policy (policy_{{SOFTWARE_NAME}})
    4. Execute resolved action (install/remove/reinstall)

    GLOBAL CONTROL TAGS (standalone):
    - U+2705 = Device is managed (required to process)
    - U+274C = Device is excluded from management
    - Both = Device is globally pinned (no changes)

    SOFTWARE-SPECIFIC OVERRIDE TAGS (with "{{SOFTWARE_NAME}}" suffix):
    - U+1F64F {{SOFTWARE_NAME}} = Install if missing (transient)
    - U+1F6AB {{SOFTWARE_NAME}} = Remove if present (transient)
    - U+1F4CC {{SOFTWARE_NAME}} = Pin - no changes allowed (persistent)
    - U+1F504 {{SOFTWARE_NAME}} = Reinstall - remove + install (transient)
    - U+2705 {{SOFTWARE_NAME}}  = Status: software is installed (set by script)

    CUSTOM FIELD POLICY (inherited Group->Folder->Device):
    - policy_{{SOFTWARE_NAME}} = "install" | "remove" | "pin" | ""

.NOTES
    Version:          {{VERSION}}
    Target Platform:  Level.io RMM (via Script Launcher)
    Exit Codes:       0 = Success | 1 = Alert (Failure)

    Level.io Variables Used (passed from Script Launcher):
    - $MspScratchFolder   : MSP-defined scratch folder for persistent storage
    - $DeviceHostname     : Device hostname from Level.io
    - $DeviceTags         : Comma-separated list of device tags
    - $policy_{{SOFTWARE_NAME}}    : Custom field policy value (inherited)

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# Software Policy - {{SOFTWARE_DISPLAY_NAME}}
# Version: {{VERSION}}
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
# software-specific and shows detection paths/methods.

function Write-DebugInstallCheck {
    param([bool]$IsInstalled)
    if (-not $DebugScripts) { return }

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " DEBUG: Installation Check" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    # {{CUSTOMIZE: Add file paths, registry paths, service names to check}}
    # Example file paths:
    $FilePaths = @(
        "$env:ProgramFiles\{{SOFTWARE_FOLDER}}\{{EXECUTABLE}}",
        "${env:ProgramFiles(x86)}\{{SOFTWARE_FOLDER}}\{{EXECUTABLE}}"
    )

    # Example registry paths:
    $RegPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{{REGISTRY_KEY}}",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{{REGISTRY_KEY}}"
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

    # {{OPTIONAL: Add service check for service-based software}}
    # $ServiceName = "{{SERVICE_NAME}}"
    # $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    # Write-Host ""
    # Write-Host "  --- Service Check ---"
    # if ($Service) {
    #     Write-Host "  [FOUND] Service: $ServiceName" -ForegroundColor Green
    #     Write-Host "          Status: $($Service.Status)" -ForegroundColor $(if ($Service.Status -eq 'Running') { 'Green' } else { 'Yellow' })
    # } else {
    #     Write-Host "  [    ] Service: $ServiceName not found" -ForegroundColor DarkGray
    # }

    Write-Host ""
    Write-Host "  SOFTWARE INSTALLED: $(if ($IsInstalled) { 'YES' } else { 'NO' })" -ForegroundColor $(if ($IsInstalled) { 'Green' } else { 'Yellow' })
}

# ============================================================
# CONFIGURATION
# ============================================================
$SoftwareName = "{{SOFTWARE_NAME}}"
$InstallerName = "{{INSTALLER_FILENAME}}"

# {{CHOOSE ONE: URL-based or SiteKey-based installation}}

# OPTION A: Installer URL from custom field (for self-hosted installers)
# $CustomUrlVar = "policy_${SoftwareName}_url"
# $InstallerUrl = Get-Variable -Name $CustomUrlVar -ValueOnly -ErrorAction SilentlyContinue
# if ([string]::IsNullOrWhiteSpace($InstallerUrl) -or $InstallerUrl -like "{{*}}") {
#     $InstallerUrl = $null
# }

# OPTION B: Site key from custom field (for cloud-based agents with fixed download URL)
# $SiteKeyVar = "policy_${SoftwareName}_sitekey"
# $SiteKey = Get-Variable -Name $SiteKeyVar -ValueOnly -ErrorAction SilentlyContinue
# if ([string]::IsNullOrWhiteSpace($SiteKey) -or $SiteKey -like "{{*}}") {
#     $SiteKey = $null
# }

# OPTION C: Fixed public download URL (no custom field needed)
# $InstallerUrl = "https://example.com/installer.exe"

# {{OPTIONAL: For service-based software}}
# $ServiceName = "{{SERVICE_NAME}}"
# $LockFileName = "{{SOFTWARE_NAME}}_Deployment.lock"

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
# LOCKFILE MANAGEMENT (Optional - for long-running installs)
# ============================================================
# {{OPTIONAL: Uncomment for software with long install times to prevent concurrent runs}}
# $LockFilePath = Join-Path -Path $MspScratchFolder -ChildPath "lockfiles"
# $LockFile = Join-Path -Path $LockFilePath -ChildPath $LockFileName
#
# if (!(Test-Path $LockFilePath)) {
#     New-Item -Path $LockFilePath -ItemType Directory -Force | Out-Null
# }
#
# if (Test-Path $LockFile) {
#     $LockContent = Get-Content -Path $LockFile -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
#     if ($LockContent.PID) {
#         $ExistingProcess = Get-Process -Id $LockContent.PID -ErrorAction SilentlyContinue
#         if ($ExistingProcess) {
#             Write-LevelLog "Script already running (PID: $($LockContent.PID)). Exiting gracefully."
#             exit 0
#         }
#     }
#     Remove-Item -Path $LockFile -Force -ErrorAction SilentlyContinue
# }
#
# $LockData = @{
#     PID       = $PID
#     StartedAt = (Get-Date).ToString("o")
#     Hostname  = $env:COMPUTERNAME
# } | ConvertTo-Json
# Set-Content -Path $LockFile -Value $LockData -Force
#
# function Remove-Lock {
#     Remove-Item -Path $LockFile -Force -ErrorAction SilentlyContinue
# }

# ============================================================
# SOFTWARE DETECTION
# ============================================================

# {{CUSTOMIZE: Define install paths for detection}}
$InstallPaths = @(
    "$env:ProgramFiles\{{SOFTWARE_FOLDER}}\{{EXECUTABLE}}",
    "${env:ProgramFiles(x86)}\{{SOFTWARE_FOLDER}}\{{EXECUTABLE}}"
)

function Test-{{SOFTWARE_FUNCTION_NAME}}Installed {
    # {{CHOOSE detection method based on software type}}

    # OPTION A: File-based detection (simplest)
    $result = Test-SoftwareInstalled -SoftwareName "{{SOFTWARE_DISPLAY_NAME}}" `
                                     -InstallPaths $InstallPaths `
                                     -SkipProcessCheck `
                                     -SkipServiceCheck
    if ($DebugScripts -and $result) {
        Write-Host "  [DEBUG] {{SOFTWARE_DISPLAY_NAME}} detected via library function" -ForegroundColor Green
    }
    return $result

    # OPTION B: Service-based detection (for agents/daemons)
    # $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    # $result = $service -and $service.Status -eq 'Running'
    # if ($DebugScripts -and $result) {
    #     Write-Host "  [DEBUG] {{SOFTWARE_DISPLAY_NAME}} detected - service running" -ForegroundColor Green
    # }
    # return $result

    # OPTION C: Registry-based detection
    # $uninstallPaths = @(
    #     "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    #     "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    # )
    # $existingInstall = $uninstallPaths | ForEach-Object {
    #     Get-ItemProperty $_ -ErrorAction SilentlyContinue
    # } | Where-Object { $_.DisplayName -like "*{{SOFTWARE_DISPLAY_NAME}}*" }
    # return $null -ne $existingInstall
}

function Install-{{SOFTWARE_FUNCTION_NAME}} {
    param([string]$ScratchFolder)

    # {{CUSTOMIZE: Validate required configuration}}
    # For URL-based installs:
    # if ([string]::IsNullOrWhiteSpace($InstallerUrl)) {
    #     Write-Host "Alert: {{SOFTWARE_DISPLAY_NAME}} install failed - policy_{{SOFTWARE_NAME}}_url custom field not configured"
    #     Write-LevelLog "Installer URL not configured" -Level "ERROR"
    #     return $false
    # }

    # For site key-based installs:
    # if ([string]::IsNullOrWhiteSpace($SiteKey)) {
    #     Write-Host "Alert: {{SOFTWARE_DISPLAY_NAME}} install failed - policy_{{SOFTWARE_NAME}}_sitekey custom field not configured"
    #     Write-LevelLog "Site key not configured" -Level "ERROR"
    #     return $false
    # }

    # Validate scratch folder
    if ([string]::IsNullOrWhiteSpace($ScratchFolder) -or $ScratchFolder -like "*{{*") {
        Write-Host "Alert: Invalid scratch folder path"
        Write-LevelLog "Invalid scratch folder - template variable not resolved" -Level "ERROR"
        return $false
    }

    # Setup installers folder
    $InstallersFolder = Join-Path $ScratchFolder "Installers"
    if (-not (Test-Path $InstallersFolder)) {
        New-Item -ItemType Directory -Path $InstallersFolder -Force | Out-Null
    }
    $InstallerPath = Join-Path $InstallersFolder $InstallerName

    # Download installer with retry
    $MinFileSize = 1MB  # {{CUSTOMIZE: Adjust minimum expected file size}}
    $MaxRetries = 2
    $RetryCount = 0

    while ($RetryCount -le $MaxRetries) {
        Write-LevelLog "Downloading {{SOFTWARE_DISPLAY_NAME}} installer$(if ($RetryCount -gt 0) { " (retry $RetryCount)" })..."
        try {
            if (Test-Path $InstallerPath) {
                Remove-Item $InstallerPath -Force -ErrorAction SilentlyContinue
            }

            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $InstallerUrl -OutFile $InstallerPath -UseBasicParsing -ErrorAction Stop

            if (Test-Path $InstallerPath) {
                $FileSize = (Get-Item $InstallerPath).Length
                if ($FileSize -ge $MinFileSize) {
                    Write-LevelLog "Downloaded installer: $([math]::Round($FileSize/1MB, 2)) MB"
                    break  # Success
                }
                else {
                    Write-LevelLog "Downloaded file too small ($FileSize bytes) - retrying..." -Level "WARN"
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
            Write-Host "Alert: Failed to download {{SOFTWARE_DISPLAY_NAME}} installer after $MaxRetries retries"
            Write-LevelLog "Failed to download installer after retries" -Level "ERROR"
            return $false
        }

        Start-Sleep -Seconds 2
    }

    # Run installer
    Write-LevelLog "Installing {{SOFTWARE_DISPLAY_NAME}}..."
    try {
        # {{CUSTOMIZE: Installer arguments - examples below}}

        # EXE with silent switches:
        # $InstallArgs = "/S"  # or "-install -no_desktop_icon" etc.
        # $Process = Start-Process -FilePath $InstallerPath -ArgumentList $InstallArgs -Wait -PassThru -ErrorAction Stop

        # MSI installer:
        # $InstallArgs = "/i `"$InstallerPath`" /qn /norestart"
        # $Process = Start-Process msiexec.exe -ArgumentList $InstallArgs -Wait -PassThru -WindowStyle Hidden

        # MSI with site key:
        # $InstallArgs = "/i `"$InstallerPath`" /qn /norestart NKEY=`"$SiteKey`""
        # $Process = Start-Process msiexec.exe -ArgumentList $InstallArgs -Wait -PassThru -WindowStyle Hidden

        if ($Process.ExitCode -eq 0 -or $Process.ExitCode -eq 3010) {
            Write-LevelLog "{{SOFTWARE_DISPLAY_NAME}} installed successfully" -Level "SUCCESS"
            return $true
        }
        else {
            Write-Host "Alert: {{SOFTWARE_DISPLAY_NAME}} installer failed"
            Write-Host "  Exit code: $($Process.ExitCode)"
            Write-LevelLog "Installer exited with code: $($Process.ExitCode)" -Level "ERROR"
            return $false
        }
    }
    catch {
        Write-Host "Alert: {{SOFTWARE_DISPLAY_NAME}} installation exception"
        Write-Host "  Error: $($_.Exception.Message)"
        Write-LevelLog "Installation failed: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
    finally {
        # Cleanup installer
        if (Test-Path $InstallerPath) {
            Remove-Item $InstallerPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Remove-{{SOFTWARE_FUNCTION_NAME}} {
    # {{CUSTOMIZE: Implement uninstall logic}}

    # OPTION A: EXE with built-in uninstaller
    # $InstallPaths = @(
    #     "${env:ProgramFiles(x86)}\{{SOFTWARE_FOLDER}}",
    #     "$env:ProgramFiles\{{SOFTWARE_FOLDER}}"
    # )
    #
    # $InstallPath = $null
    # foreach ($Path in $InstallPaths) {
    #     if (Test-Path $Path) {
    #         $InstallPath = $Path
    #         break
    #     }
    # }
    #
    # if (-not $InstallPath) {
    #     Write-LevelLog "{{SOFTWARE_DISPLAY_NAME}} install folder not found" -Level "WARN"
    #     return $true  # Not installed = success
    # }
    #
    # $Uninstaller = Join-Path $InstallPath "uninstall.exe"
    # if (-not (Test-Path $Uninstaller)) {
    #     Write-LevelLog "Uninstaller not found" -Level "WARN"
    #     return $true
    # }
    #
    # Write-LevelLog "Uninstalling {{SOFTWARE_DISPLAY_NAME}}..."
    # $UninstallArgs = "/S"  # {{CUSTOMIZE: Silent uninstall args}}
    # $Process = Start-Process -FilePath $Uninstaller -ArgumentList $UninstallArgs -Wait -PassThru -ErrorAction Stop
    # return $Process.ExitCode -eq 0

    # OPTION B: MSI uninstall via registry lookup
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $existingInstall = $uninstallPaths | ForEach-Object {
        Get-ItemProperty $_ -ErrorAction SilentlyContinue
    } | Where-Object { $_.DisplayName -like "*{{SOFTWARE_DISPLAY_NAME}}*" }

    if (-not $existingInstall) {
        Write-LevelLog "{{SOFTWARE_DISPLAY_NAME}} not found - nothing to remove" -Level "INFO"
        return $true
    }

    # {{OPTIONAL: Stop service first}}
    # if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    #     Write-LevelLog "Stopping service..."
    #     Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    #     Start-Sleep -Seconds 2
    # }

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
$ScriptVersion = "{{VERSION}}"
$ExitCode = 0

$InvokeParams = @{ ScriptBlock = {

    Write-LevelLog "Policy Enforcement: $SoftwareName (v$ScriptVersion)"

    # Debug header
    if ($DebugScripts) {
        Write-Host ""
        Write-Host "============================================================" -ForegroundColor Magenta
        Write-Host " DEBUG MODE ENABLED (debug_coolforge = verbose)" -ForegroundColor Magenta
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
        # {{OPTIONAL: Add software-specific config}}
        # 'SiteKey' = if ($SiteKey) { '(configured)' } else { '(not set)' }
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
    if ($LevelApiKey) {
        $KeyLength = $LevelApiKey.Length
        $KeyPreview = if ($KeyLength -gt 4) { $LevelApiKey.Substring(0, 4) + "****" } else { "(invalid)" }
        Write-LevelLog "API key: $KeyPreview (length: $KeyLength)" -Level "DEBUG"

        # {{CUSTOMIZE: Set RequireUrl based on whether you need a custom URL field}}
        $InfraResult = Initialize-SoftwarePolicyInfrastructure -ApiKey $LevelApiKey `
            -SoftwareName $SoftwareName `
            -RequireUrl $true  # Set to $false if using fixed URL or site key

        # {{OPTIONAL: Create additional custom fields (e.g., site key)}}
        # $SiteKeyFieldName = "policy_${SoftwareName}_sitekey"
        # $SiteKeyFieldCreated = $false
        # $ExistingSiteKeyField = Find-LevelCustomField -ApiKey $LevelApiKey -FieldName $SiteKeyFieldName
        # if (-not $ExistingSiteKeyField) {
        #     $NewSiteKeyField = New-LevelCustomField -ApiKey $LevelApiKey -Name $SiteKeyFieldName -DefaultValue ""
        #     if ($NewSiteKeyField) {
        #         Write-LevelLog "Created custom field: $SiteKeyFieldName" -Level "SUCCESS"
        #         $SiteKeyFieldCreated = $true
        #     }
        # }
        # $TotalFieldsCreated = $InfraResult.FieldsCreated + $(if ($SiteKeyFieldCreated) { 1 } else { 0 })

        if ($InfraResult.Success) {
            if ($InfraResult.TagsCreated -gt 0 -or $InfraResult.FieldsCreated -gt 0) {
                Write-LevelLog "Created $($InfraResult.TagsCreated) tags, $($InfraResult.FieldsCreated) fields" -Level "SUCCESS"
                Write-Host ""
                Write-Host "Alert: Policy infrastructure created - please configure custom fields"
                Write-Host "  Set the following custom fields in Level.io:"
                Write-Host "  - policy_{{SOFTWARE_NAME}}: Set to 'install', 'remove', or 'pin' at Group/Folder/Device level"
                # {{CUSTOMIZE: List additional custom fields}}
                # Write-Host "  - policy_{{SOFTWARE_NAME}}_url: Set to your hosted installer URL"
                # Write-Host "  - policy_{{SOFTWARE_NAME}}_sitekey: Set your site/license key"
                Write-Host ""
                Write-LevelLog "Infrastructure created - exiting for configuration" -Level "INFO"
                # {{OPTIONAL: Remove-Lock}}
                $script:ExitCode = 1
                return 1
            }
        }
        else {
            Write-LevelLog "Infrastructure setup warning: $($InfraResult.Error)" -Level "WARN"
        }
    }

    # Check current installation state
    $IsInstalled = Test-{{SOFTWARE_FUNCTION_NAME}}Installed
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
                # If triggered by tag, set device custom field to persist intent
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
                    $ActionSuccess = Install-{{SOFTWARE_FUNCTION_NAME}} -ScratchFolder $MspScratchFolder
                    if (-not $ActionSuccess) {
                        Write-LevelLog "FAILED: Installation unsuccessful" -Level "ERROR"
                        $script:ExitCode = 1
                    }
                }
            }
            "Remove" {
                # If triggered by tag, set device custom field to persist intent
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
                    $ActionSuccess = Remove-{{SOFTWARE_FUNCTION_NAME}}
                    if (-not $ActionSuccess) {
                        Write-LevelLog "FAILED: Removal unsuccessful" -Level "ERROR"
                        $script:ExitCode = 1
                    }
                }
            }
            "Reinstall" {
                Write-LevelLog "ACTION: Reinstalling $SoftwareName" -Level "INFO"
                if ($IsInstalled) {
                    $RemoveSuccess = Remove-{{SOFTWARE_FUNCTION_NAME}}
                    if (-not $RemoveSuccess) {
                        Write-LevelLog "FAILED: Could not remove for reinstall" -Level "ERROR"
                        $script:ExitCode = 1
                        break
                    }
                }
                $ActionSuccess = Install-{{SOFTWARE_FUNCTION_NAME}} -ScratchFolder $MspScratchFolder
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
    # TAG MANAGEMENT (per POLICY-TAGS.md Tag Cleanup Rules)
    # ============================================================
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
        $FinalInstallState = Test-{{SOFTWARE_FUNCTION_NAME}}Installed

        # Tag cleanup based on action and success
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

    # {{OPTIONAL: Remove-Lock}}
    return $(if ($ActionSuccess) { 0 } else { 1 })
}}
if ($RunningFromLauncher) { $InvokeParams.NoExit = $true }
Invoke-LevelScript @InvokeParams

exit $ExitCode
