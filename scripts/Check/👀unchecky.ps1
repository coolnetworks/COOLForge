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
    Version:          2026.01.12.3
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
# Version: 2026.01.12.3
# Target: Level.io (via Script Launcher)
# Exit 0 = Success | Exit 1 = Alert (Failure)
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge

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

    # Store installers in dedicated subfolder under scratch folder
    $InstallersFolder = Join-Path $ScratchFolder "Installers"
    if (-not (Test-Path $InstallersFolder)) {
        New-Item -ItemType Directory -Path $InstallersFolder -Force | Out-Null
    }
    $InstallerPath = Join-Path $InstallersFolder $InstallerName

    # Download installer
    Write-LevelLog "Downloading Unchecky installer..."
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $InstallerUrl -OutFile $InstallerPath -UseBasicParsing -ErrorAction Stop
    }
    catch {
        Write-LevelLog "Failed to download installer: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }

    if (-not (Test-Path $InstallerPath)) {
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
            Write-LevelLog "Installer exited with code: $($Process.ExitCode)" -Level "ERROR"
            return $false
        }
    }
    catch {
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
            Write-LevelLog "Uninstaller exited with code: $($Process.ExitCode)" -Level "ERROR"
            return $false
        }
    }
    catch {
        Write-LevelLog "Uninstallation failed: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

# ============================================================
# MAIN SCRIPT LOGIC
# ============================================================
$ScriptVersion = "2026.01.12.3"
$ExitCode = 0

$InvokeParams = @{ ScriptBlock = {

    Write-LevelLog "Policy Enforcement: $SoftwareName (v$ScriptVersion)"
    Write-Host ""

    # Get custom field policy if available (passed from launcher)
    $CustomFieldPolicyVar = "policy_$SoftwareName"
    $CustomFieldPolicy = Get-Variable -Name $CustomFieldPolicyVar -ValueOnly -ErrorAction SilentlyContinue
    if ($CustomFieldPolicy) {
        Write-LevelLog "Custom field policy: $CustomFieldPolicy"
    }

    # Check current installation state
    $IsInstalled = Test-UncheckyInstalled
    Write-LevelLog "Current state: $(if ($IsInstalled) { 'Installed' } else { 'Not installed' })"
    Write-Host ""

    # Run the policy check with the 5-tag model
    $Policy = Invoke-SoftwarePolicyCheck -SoftwareName $SoftwareName `
                                         -DeviceTags $DeviceTags `
                                         -CustomFieldPolicy $CustomFieldPolicy

    Write-Host ""

    # Take action based on resolved policy
    if ($Policy.ShouldProcess) {
        switch ($Policy.ResolvedAction) {
            "Install" {
                if ($IsInstalled) {
                    Write-LevelLog "Already installed - no action needed" -Level "SUCCESS"
                }
                else {
                    Write-LevelLog "ACTION: Installing $SoftwareName" -Level "INFO"
                    $Success = Install-Unchecky -ScratchFolder $script:ScratchFolder
                    if (-not $Success) {
                        Write-LevelLog "FAILED: Installation unsuccessful" -Level "ERROR"
                        $script:ExitCode = 1
                    }
                }
            }
            "Remove" {
                if (-not $IsInstalled) {
                    Write-LevelLog "Not installed - no action needed" -Level "SUCCESS"
                }
                else {
                    Write-LevelLog "ACTION: Removing $SoftwareName" -Level "INFO"
                    $Success = Remove-Unchecky
                    if (-not $Success) {
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
                $InstallSuccess = Install-Unchecky -ScratchFolder $script:ScratchFolder
                if (-not $InstallSuccess) {
                    Write-LevelLog "FAILED: Reinstallation unsuccessful" -Level "ERROR"
                    $script:ExitCode = 1
                }
            }
            "Pin" {
                Write-LevelLog "Pinned - no changes allowed" -Level "INFO"
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
            }
        }
    }

    Write-Host ""

    if ($script:ExitCode -eq 0) {
        Write-LevelLog "Policy enforcement completed successfully" -Level "SUCCESS"
    }
    else {
        Write-LevelLog "Policy enforcement completed with errors" -Level "ERROR"
    }
}}
if ($RunningFromLauncher) { $InvokeParams.NoExit = $true }
Invoke-LevelScript @InvokeParams

exit $ExitCode
