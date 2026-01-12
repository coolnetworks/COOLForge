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
    Version:          2026.01.12.11
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
# Version: 2026.01.12.11
# Target: Level.io (via Script Launcher)
# Exit 0 = Success | Exit 1 = Alert (Failure)
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge

# ============================================================
# DEBUG OUTPUT HELPER
# ============================================================
# When $DebugScripts is true (from cf_debug_scripts custom field),
# outputs verbose diagnostic information for troubleshooting.

function Write-DebugSection {
    param(
        [string]$Title,
        [hashtable]$Data,
        [switch]$MaskApiKey
    )
    if (-not $DebugScripts) { return }

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " DEBUG: $Title" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    foreach ($Key in $Data.Keys) {
        $Value = $Data[$Key]
        $DisplayValue = if ([string]::IsNullOrWhiteSpace($Value)) {
            "(empty)"
        }
        elseif ($Value -like "{{*}}") {
            "(unresolved: $Value)"
        }
        elseif ($MaskApiKey -and $Key -like "*ApiKey*" -and $Value.Length -gt 3) {
            ("*" * ($Value.Length - 3)) + $Value.Substring($Value.Length - 3)
        }
        else {
            $Value
        }

        $Status = if ([string]::IsNullOrWhiteSpace($Value) -or $Value -like "{{*}}") {
            "[MISSING]"
        } else {
            "[OK]"
        }
        $Color = if ($Status -eq "[OK]") { "Green" } else { "Red" }

        Write-Host "  ${Key}: " -NoNewline
        Write-Host "$Status " -ForegroundColor $Color -NoNewline
        Write-Host "$DisplayValue"
    }
}

function Write-DebugTags {
    param([string]$TagString, [string]$SoftwareName)
    if (-not $DebugScripts) { return }

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " DEBUG: Device Tags Analysis" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    if ([string]::IsNullOrWhiteSpace($TagString) -or $TagString -like "{{*}}") {
        Write-Host "  [WARNING] No device tags available" -ForegroundColor Red
        return
    }

    $TagArray = $TagString -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    Write-Host "  Total tags: $($TagArray.Count)"
    Write-Host ""

    # Get emoji map for reference
    $EmojiMap = Get-EmojiMap

    # Check for global and software-specific tags
    $HasGlobalCheckmark = $false
    $HasGlobalCross = $false
    $SoftwareSpecificTags = @()
    $SoftwareNameUpper = $SoftwareName.ToUpper()

    foreach ($Tag in $TagArray) {
        $TagBytes = [System.Text.Encoding]::UTF8.GetBytes($Tag)
        $HexBytes = ($TagBytes | ForEach-Object { "{0:X2}" -f $_ }) -join " "

        # Check global tags
        if ($EmojiMap[$Tag] -eq "GlobalManaged") { $HasGlobalCheckmark = $true }
        if ($EmojiMap[$Tag] -eq "GlobalExcluded") { $HasGlobalCross = $true }

        # Check software-specific
        if ($Tag.ToUpper() -match $SoftwareNameUpper) {
            $SoftwareSpecificTags += $Tag
        }

        Write-Host "  Tag: '$Tag'"
        Write-Host "       Bytes: $HexBytes" -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "  --- Global Control Tags ---"
    Write-Host "  Global Checkmark: $(if ($HasGlobalCheckmark) { '[FOUND]' } else { '[NOT FOUND]' })" -ForegroundColor $(if ($HasGlobalCheckmark) { 'Green' } else { 'Yellow' })
    Write-Host "  Global Cross: $(if ($HasGlobalCross) { '[FOUND]' } else { '[NOT FOUND]' })" -ForegroundColor $(if ($HasGlobalCross) { 'Green' } else { 'DarkGray' })

    Write-Host ""
    Write-Host "  --- Software-Specific Tags ($SoftwareName) ---"
    if ($SoftwareSpecificTags.Count -eq 0) {
        Write-Host "  (none found)" -ForegroundColor DarkGray
    } else {
        foreach ($Tag in $SoftwareSpecificTags) {
            Write-Host "  - $Tag"
        }
    }
}

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

function Write-DebugPolicy {
    param($Policy)
    if (-not $DebugScripts) { return }

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " DEBUG: Policy Resolution" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    Write-Host "  GlobalStatus:    $($Policy.GlobalStatus)" -ForegroundColor $(if ($Policy.GlobalStatus -eq 'Managed') { 'Green' } else { 'Yellow' })
    Write-Host "  ShouldProcess:   $($Policy.ShouldProcess)" -ForegroundColor $(if ($Policy.ShouldProcess) { 'Green' } else { 'Yellow' })
    Write-Host "  ResolvedAction:  $($Policy.ResolvedAction)"
    Write-Host "  ActionSource:    $($Policy.ActionSource)"
    Write-Host "  HasInstalled:    $($Policy.HasInstalled) (refers to tag, not actual install)"
    Write-Host "  IsPinned:        $($Policy.IsPinned)"

    if ($Policy.SkipReason) {
        Write-Host "  SkipReason:      $($Policy.SkipReason)" -ForegroundColor Yellow
    }

    if ($Policy.MatchedTags.Count -gt 0) {
        Write-Host "  MatchedTags:     $($Policy.MatchedTags -join ', ')"
    }
}

function Write-DebugTagManagement {
    param([bool]$HasApiKey, [string]$DeviceHostname)
    if (-not $DebugScripts) { return }

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " DEBUG: Tag Management Readiness" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    $HostnameReady = -not [string]::IsNullOrWhiteSpace($DeviceHostname) -and $DeviceHostname -notlike "{{*}}"

    Write-Host "  API Key Present:     $(if ($HasApiKey) { '[YES]' } else { '[NO] - Tag updates will be SKIPPED!' })" -ForegroundColor $(if ($HasApiKey) { 'Green' } else { 'Red' })
    Write-Host "  Device Hostname:     $(if ($HostnameReady) { "[YES] $DeviceHostname" } else { '[NO]' })" -ForegroundColor $(if ($HostnameReady) { 'Green' } else { 'Red' })

    if ($HasApiKey -and $HostnameReady) {
        Write-Host ""
        Write-Host "  [OK] Tag management is READY" -ForegroundColor Green
    } else {
        Write-Host ""
        Write-Host "  [WARNING] Tag management will be SKIPPED" -ForegroundColor Red
        if (-not $HasApiKey) {
            Write-Host "  -> Create 'apikey' custom field in Level.io (admin-only)" -ForegroundColor Yellow
            Write-Host "  -> Set value to your Level.io API key" -ForegroundColor Yellow
        }
    }
}

# ============================================================
# CONFIGURATION
# ============================================================
$SoftwareName = "unchecky"
$InstallerUrl = "https://s3.ap-southeast-2.wasabisys.com/levelfiles/unchecky_setup.exe"
$InstallerName = "unchecky_setup.exe"

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
# SOFTWARE DETECTION FUNCTIONS
# ============================================================

function Test-UncheckyInstalled {
    # Check common install locations
    $Paths = @(
        "$env:ProgramFiles\Unchecky\unchecky.exe",
        "${env:ProgramFiles(x86)}\Unchecky\unchecky.exe"
    )
    foreach ($Path in $Paths) {
        if (Test-Path $Path) {
            if ($DebugScripts) { Write-Host "  [DEBUG] Found: $Path" -ForegroundColor Green }
            return $true
        }
    }

    # Check registry
    $RegPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Unchecky",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Unchecky"
    )
    foreach ($RegPath in $RegPaths) {
        if (Test-Path $RegPath) {
            if ($DebugScripts) { Write-Host "  [DEBUG] Found registry: $RegPath" -ForegroundColor Green }
            return $true
        }
    }

    return $false
}

function Get-UncheckyUninstallString {
    $RegPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Unchecky",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Unchecky"
    )
    foreach ($RegPath in $RegPaths) {
        if (Test-Path $RegPath) {
            $Uninstall = Get-ItemProperty -Path $RegPath -ErrorAction SilentlyContinue
            if ($Uninstall.UninstallString) {
                return $Uninstall.UninstallString
            }
        }
    }
    return $null
}

function Install-Unchecky {
    param([string]$ScratchFolder)

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
                    Write-LevelLog "Downloaded file too small ($FileSize bytes), expected >= $MinFileSize - retrying..." -Level "WARNING"
                    $RetryCount++
                }
            }
            else {
                Write-LevelLog "File not found after download - retrying..." -Level "WARNING"
                $RetryCount++
            }
        }
        catch {
            Write-LevelLog "Download failed: $($_.Exception.Message)" -Level "WARNING"
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

    # Run silent install (uses -install -no_desktop_icon syntax)
    Write-LevelLog "Installing Unchecky..."
    try {
        $InstallArgs = "-install -no_desktop_icon"
        $Process = Start-Process -FilePath $InstallerPath -ArgumentList $InstallArgs -Wait -PassThru -ErrorAction Stop
        if ($Process.ExitCode -eq 0) {
            Write-LevelLog "Unchecky installed successfully" -Level "SUCCESS"
            return $true
        }
        else {
            Write-Host "Alert: Unchecky installer failed"
            Write-Host "  Installer: $InstallerPath"
            Write-Host "  Arguments: $InstallArgs"
            Write-Host "  Exit code: $($Process.ExitCode)"
            Write-LevelLog "Installer exited with code: $($Process.ExitCode)" -Level "ERROR"
            return $false
        }
    }
    catch {
        Write-Host "Alert: Unchecky installation exception"
        Write-Host "  Installer: $InstallerPath"
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
        Write-LevelLog "Unchecky install folder not found" -Level "WARNING"
        return $true  # Not installed = success
    }

    $Uninstaller = Join-Path $InstallPath "uninstall.exe"
    if (-not (Test-Path $Uninstaller)) {
        Write-LevelLog "Unchecky uninstaller not found at $Uninstaller" -Level "WARNING"
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
$ScriptVersion = "2026.01.12.10"
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
    # AUTO-BOOTSTRAP: Create policy infrastructure if needed
    # ============================================================
    # If no custom field policy AND no override tags, bootstrap the policy
    # This allows first-run setup without manual configuration
    if ($LevelApiKey -and [string]::IsNullOrWhiteSpace($CustomFieldPolicy)) {
        # Quick check for override tags before bootstrapping
        $QuickPolicy = Get-SoftwarePolicy -SoftwareName $SoftwareName -DeviceTags $DeviceTags
        if ($QuickPolicy.ShouldProcess -and $QuickPolicy.ResolvedAction -eq "None" -and $QuickPolicy.MatchedTags.Count -eq 0) {
            Write-LevelLog "No policy configured - auto-bootstrapping..." -Level "INFO"
            $Bootstrap = Initialize-LevelSoftwarePolicy -ApiKey $LevelApiKey `
                -SoftwareName $SoftwareName `
                -DeviceHostname $DeviceHostname `
                -DefaultAction "install"

            if ($Bootstrap.Success) {
                Write-LevelLog "Created policy_$SoftwareName custom field with default 'install'" -Level "SUCCESS"
                $CustomFieldPolicy = $Bootstrap.Action
            }
            else {
                Write-LevelLog "Auto-bootstrap failed: $($Bootstrap.Error)" -Level "WARNING"
            }
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
    Write-DebugTagManagement -HasApiKey ([bool]$LevelApiKey) -DeviceHostname $DeviceHostname

    Write-Host ""

    # Take action based on resolved policy
    $ActionSuccess = $false
    if ($Policy.ShouldProcess) {
        switch ($Policy.ResolvedAction) {
            "Install" {
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
                $ActionSuccess = $true
            }
            "None" {
                # Verify current state matches expected
                if ($Policy.HasInstalled -and -not $IsInstalled) {
                    Write-LevelLog "WARNING: Status tag says installed but software not found" -Level "WARNING"
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
                    # Pin tag stays, just ensure Has tag reflects actual state
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
            Write-LevelLog "Action failed - tags not updated" -Level "WARNING"
        }
    }
    else {
        Write-LevelLog "No API key - tag updates skipped" -Level "DEBUG"
    }

    Write-Host ""

    if ($script:ExitCode -eq 0) {
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

    # Return exit code to Invoke-LevelScript
    return $script:ExitCode
}}
if ($RunningFromLauncher) { $InvokeParams.NoExit = $true }
Invoke-LevelScript @InvokeParams

exit $ExitCode
