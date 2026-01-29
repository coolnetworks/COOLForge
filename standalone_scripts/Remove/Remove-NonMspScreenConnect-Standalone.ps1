<#
.SYNOPSIS
    Standalone script to remove unauthorized ScreenConnect while preserving your MSP instance.

.DESCRIPTION
    This script performs complete removal of ScreenConnect installations that don't match
    your whitelisted instance ID. It uses multiple removal methods:
    1. Stops non-whitelisted ScreenConnect services and processes
    2. Attempts winget uninstall
    3. Uses Windows Installer (registry-based uninstall)
    4. Executes direct folder-based uninstaller
    5. Cleans up leftover files, registry entries, firewall rules, scheduled tasks

    STANDALONE VERSION - No COOLForge library required.

.PARAMETER ScreenConnectInstanceId
    Your MSP's ScreenConnect instance ID to preserve (whitelist).

.PARAMETER IsScreenConnectServer
    Set to "true" to skip removal if this device hosts the ScreenConnect server.

.NOTES
    Version:          2025.01.07.01 (Standalone)
    Exit Codes:       0 = Success | 1 = Alert (Failure)
    Requires:         Administrator privileges

    License:          AGPL-3.0 (see LICENSE)
    Copyright (c) 2025-2026 COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge

.EXAMPLE
    .\Remove-NonMspScreenConnect-Standalone.ps1
#>

#region Configuration
# ============================================================
# CONFIGURATION
# ============================================================
# These values are populated via Level.io custom field variable substitution.
# Set these custom fields in Level.io:
#   - cf_policy_screenconnect_instance_id : Your MSP's ScreenConnect instance ID to preserve
#   - cf_policy_screenconnect_machine_hosts_screenconnect_server : Set to "true" if device hosts ScreenConnect server
$ScreenConnectInstanceId = "{{cf_policy_screenconnect_instance_id}}"
$IsScreenConnectServer = "{{cf_policy_screenconnect_machine_hosts_screenconnect_server}}"

# Normalize empty/unsubstituted values
if ($ScreenConnectInstanceId -like "{{*}}") { $ScreenConnectInstanceId = "" }
if ($IsScreenConnectServer -like "{{*}}") { $IsScreenConnectServer = "" }
#endregion Configuration

#region Embedded Functions
function Write-Log {
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "SKIP", "DEBUG")]
        [string]$Level = "INFO"
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Prefix = switch ($Level) {
        "INFO"    { "[*]" }
        "WARN"    { "[!]" }
        "ERROR"   { "[X]" }
        "SUCCESS" { "[+]" }
        "SKIP"    { "[-]" }
        "DEBUG"   { "[D]" }
    }
    Write-Host "$Timestamp $Prefix $Message"
}

function Test-ScreenConnectWhitelisted {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($ScreenConnectInstanceId)) {
        return $false
    }

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return $false
    }

    return $Name -like "*$ScreenConnectInstanceId*"
}

function Test-ScreenConnectInstalled {
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    foreach ($path in $uninstallPaths) {
        if (Test-Path $path) {
            $found = Get-ChildItem -Path $path | Where-Object {
                $displayName = (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue).DisplayName
                $displayName -like "*ScreenConnect*" -and -not (Test-ScreenConnectWhitelisted -Name $displayName)
            }
            if ($found) { return $true }
        }
    }

    $services = Get-Service | Where-Object {
        ($_.Name -like "*ScreenConnect*" -or $_.DisplayName -like "*ScreenConnect*") -and
        -not (Test-ScreenConnectWhitelisted -Name $_.Name) -and
        -not (Test-ScreenConnectWhitelisted -Name $_.DisplayName)
    }
    if ($services) { return $true }

    $folderPatterns = @(
        "${env:ProgramFiles}\ScreenConnect Client*",
        "${env:ProgramFiles(x86)}\ScreenConnect Client*"
    )
    foreach ($pattern in $folderPatterns) {
        $folders = Get-Item -Path $pattern -ErrorAction SilentlyContinue | Where-Object {
            -not (Test-ScreenConnectWhitelisted -Name $_.Name)
        }
        if ($folders) { return $true }
    }

    return $false
}
#endregion Embedded Functions

#region Main Execution
Write-Host ""
Write-Host "============================================================"
Write-Host "  ScreenConnect Removal Script (Standalone)"
Write-Host "  Preserves Your MSP Instance"
Write-Host "============================================================"
Write-Host ""

$ErrorActionPreference = "SilentlyContinue"

# Check for Administrator privileges
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Log "This script requires Administrator privileges" -Level "ERROR"
    exit 1
}

Write-Log "Starting ScreenConnect removal process"
Write-Log "Device: $env:COMPUTERNAME"

# Check if this device hosts the ScreenConnect Server
if ($IsScreenConnectServer -eq "true") {
    Write-Log "This device hosts ScreenConnect Server - skipping removal" -Level "SKIP"
    exit 0
}

Write-Log "Whitelisted Instance ID: $(if ($ScreenConnectInstanceId) { $ScreenConnectInstanceId } else { '(none - all will be removed)' })"

# Initial check
if (-not (Test-ScreenConnectInstalled)) {
    Write-Log "No unauthorized ScreenConnect installations found" -Level "SUCCESS"
    exit 0
}

Write-Log "Unauthorized ScreenConnect installation(s) detected - beginning removal"

# PHASE 1: Stop Services and Processes
Write-Log "Phase 1: Stopping ScreenConnect services and processes"

$allServices = Get-Service | Where-Object { $_.Name -like "*ScreenConnect*" -or $_.DisplayName -like "*ScreenConnect*" }
foreach ($svc in $allServices) {
    if ((Test-ScreenConnectWhitelisted -Name $svc.Name) -or (Test-ScreenConnectWhitelisted -Name $svc.DisplayName)) {
        Write-Log "  SKIPPED (whitelisted): $($svc.DisplayName)" -Level "SKIP"
        continue
    }
    Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
    Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction SilentlyContinue
    Write-Log "  Stopped service: $($svc.DisplayName)" -Level "SUCCESS"
}

$processes = @("ScreenConnect.ClientService", "ScreenConnect.WindowsClient", "ScreenConnect.WindowsBackstageShell", "ScreenConnect.Client")
foreach ($proc in $processes) {
    Get-Process -Name $proc -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}
Write-Log "  Stopped ScreenConnect processes" -Level "SUCCESS"

# PHASE 2: Winget Uninstall
Write-Log "Phase 2: Attempting winget uninstall"

$winget = Get-Command winget -ErrorAction SilentlyContinue
if ($winget) {
    $wingetList = winget list --name "ScreenConnect" --accept-source-agreements 2>$null | Out-String
    if ($wingetList -match "ScreenConnect" -and $wingetList -notmatch $ScreenConnectInstanceId) {
        winget uninstall --name "ScreenConnect Client" --silent --force 2>$null
        Write-Log "  Winget uninstall attempted" -Level "SUCCESS"
    } else {
        Write-Log "  Skipped winget (whitelisted or not found)" -Level "SKIP"
    }
} else {
    Write-Log "  Winget not available" -Level "SKIP"
}

# PHASE 3: Windows Installer Uninstall
Write-Log "Phase 3: Attempting Windows Installer uninstall"

$uninstallPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
)

foreach ($path in $uninstallPaths) {
    if (Test-Path $path) {
        Get-ChildItem -Path $path | ForEach-Object {
            $displayName = (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue).DisplayName
            $installLocation = (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue).InstallLocation

            if ($displayName -like "*ScreenConnect*") {
                if ((Test-ScreenConnectWhitelisted -Name $displayName) -or (Test-ScreenConnectWhitelisted -Name $installLocation)) {
                    Write-Log "  SKIPPED (whitelisted): $displayName" -Level "SKIP"
                    return
                }

                $uninstallString = (Get-ItemProperty -Path $_.PSPath).UninstallString
                $quietUninstall = (Get-ItemProperty -Path $_.PSPath).QuietUninstallString

                if ($quietUninstall) {
                    Write-Log "  Running quiet uninstall: $displayName"
                    cmd /c $quietUninstall 2>$null
                } elseif ($uninstallString) {
                    Write-Log "  Running uninstall: $displayName"
                    if ($uninstallString -match "msiexec") {
                        $uninstallString = $uninstallString -replace "/I", "/X"
                        $uninstallString = "$uninstallString /qn /norestart"
                    }
                    cmd /c $uninstallString 2>$null
                }
            }
        }
    }
}

Start-Sleep -Seconds 5

# PHASE 4: Direct Uninstaller Execution
Write-Log "Phase 4: Attempting direct uninstaller execution"

$scFolderLocations = @(
    "${env:ProgramFiles}\ScreenConnect Client*",
    "${env:ProgramFiles(x86)}\ScreenConnect Client*"
)

foreach ($location in $scFolderLocations) {
    $folders = Get-Item -Path $location -ErrorAction SilentlyContinue
    foreach ($folder in $folders) {
        if (Test-ScreenConnectWhitelisted -Name $folder.Name) {
            Write-Log "  SKIPPED (whitelisted): $($folder.Name)" -Level "SKIP"
            continue
        }

        $uninstaller = Join-Path $folder.FullName "ScreenConnect.ClientService.exe"
        if (Test-Path $uninstaller) {
            Write-Log "  Uninstalling: $($folder.Name)"
            Start-Process -FilePath $uninstaller -ArgumentList "?e=Uninstall" -Wait -ErrorAction SilentlyContinue
        }
    }
}

Start-Sleep -Seconds 3

# PHASE 5: Cleanup
Write-Log "Phase 5: Cleaning up leftover files, registry, and services"

# Remove folders
$foldersToCheck = @(
    "${env:ProgramFiles}\ScreenConnect Client*",
    "${env:ProgramFiles(x86)}\ScreenConnect Client*",
    "${env:ProgramData}\ScreenConnect Client*",
    "C:\Windows\Temp\ScreenConnect*"
)

foreach ($folderPattern in $foldersToCheck) {
    $folders = Get-Item -Path $folderPattern -ErrorAction SilentlyContinue
    foreach ($folder in $folders) {
        if (Test-ScreenConnectWhitelisted -Name $folder.Name) {
            Write-Log "  SKIPPED (whitelisted): $($folder.FullName)" -Level "SKIP"
            continue
        }
        Remove-Item -Path $folder.FullName -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "  Removed folder: $($folder.FullName)" -Level "SUCCESS"
    }
}

# Check user profiles
$userProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue
foreach ($userProfile in $userProfiles) {
    $userFolders = @("$($userProfile.FullName)\AppData\Local\ScreenConnect Client*")
    foreach ($folderPattern in $userFolders) {
        $folders = Get-Item -Path $folderPattern -ErrorAction SilentlyContinue
        foreach ($folder in $folders) {
            if (Test-ScreenConnectWhitelisted -Name $folder.Name) { continue }
            Remove-Item -Path $folder.FullName -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log "  Removed: $($folder.FullName)" -Level "SUCCESS"
        }
    }
}

# Cleanup registry
$registryPaths = @(
    "HKLM:\SOFTWARE\ScreenConnect Client*",
    "HKLM:\SOFTWARE\WOW6432Node\ScreenConnect Client*",
    "HKCU:\SOFTWARE\ScreenConnect Client*"
)

foreach ($regPattern in $registryPaths) {
    $keys = Get-Item -Path $regPattern -ErrorAction SilentlyContinue
    foreach ($key in $keys) {
        if (Test-ScreenConnectWhitelisted -Name $key.PSChildName) {
            Write-Log "  SKIPPED (whitelisted): $($key.PSChildName)" -Level "SKIP"
            continue
        }
        Remove-Item -Path $key.PSPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "  Removed registry: $($key.PSChildName)" -Level "SUCCESS"
    }
}

# Remove firewall rules
$fwRules = Get-NetFirewallRule -DisplayName "*ScreenConnect*" -ErrorAction SilentlyContinue
foreach ($rule in $fwRules) {
    if (Test-ScreenConnectWhitelisted -Name $rule.DisplayName) {
        Write-Log "  SKIPPED firewall (whitelisted): $($rule.DisplayName)" -Level "SKIP"
        continue
    }
    Remove-NetFirewallRule -Name $rule.Name -ErrorAction SilentlyContinue
    Write-Log "  Removed firewall rule: $($rule.DisplayName)" -Level "SUCCESS"
}

# Remove services
$remainingServices = Get-Service | Where-Object { $_.Name -like "*ScreenConnect*" }
foreach ($svc in $remainingServices) {
    if ((Test-ScreenConnectWhitelisted -Name $svc.Name) -or (Test-ScreenConnectWhitelisted -Name $svc.DisplayName)) {
        continue
    }
    sc.exe delete "$($svc.Name)" 2>$null
    Write-Log "  Deleted service: $($svc.Name)" -Level "SUCCESS"
}

# Remove scheduled tasks
$scTasks = Get-ScheduledTask -TaskName "*ScreenConnect*" -ErrorAction SilentlyContinue
foreach ($task in $scTasks) {
    if (Test-ScreenConnectWhitelisted -Name $task.TaskName) { continue }
    Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Log "  Removed scheduled task: $($task.TaskName)" -Level "SUCCESS"
}

# VERIFICATION
Write-Log "Verifying removal..."

$remainingInstalls = @()
$whitelistedInstalls = @()

foreach ($path in $uninstallPaths) {
    if (Test-Path $path) {
        Get-ChildItem -Path $path | ForEach-Object {
            $displayName = (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue).DisplayName
            if ($displayName -like "*ScreenConnect*") {
                if (Test-ScreenConnectWhitelisted -Name $displayName) {
                    $whitelistedInstalls += $displayName
                } else {
                    $remainingInstalls += $displayName
                }
            }
        }
    }
}

Write-Host ""
if ($whitelistedInstalls.Count -gt 0) {
    Write-Log "Your MSP instance preserved:" -Level "SUCCESS"
    $whitelistedInstalls | ForEach-Object { Write-Log "  - $_" -Level "SUCCESS" }
}

if ($remainingInstalls.Count -eq 0) {
    Write-Log "All unauthorized ScreenConnect instances removed" -Level "SUCCESS"
    exit 0
} else {
    Write-Log "Some ScreenConnect components may still be present:" -Level "WARN"
    $remainingInstalls | ForEach-Object { Write-Log "  - $_" -Level "WARN" }
    exit 1
}
#endregion Main Execution
