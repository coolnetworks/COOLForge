<#
.SYNOPSIS
    Removes unauthorized ScreenConnect (ConnectWise Control) instances while preserving your MSP instance.

.DESCRIPTION
    This script performs complete removal of ScreenConnect installations that don't match
    your whitelisted instance ID. It uses multiple removal methods:

    1. Stops non-whitelisted ScreenConnect services and processes
    2. Attempts winget uninstall
    3. Uses Windows Installer (registry-based uninstall)
    4. Executes direct folder-based uninstaller
    5. Cleans up leftover files, registry entries, firewall rules, scheduled tasks

    Your MSP's ScreenConnect instance is preserved by matching against the instance ID
    in the custom field. Devices hosting the ScreenConnect server are automatically skipped.

    When run via Script Launcher, this script inherits all Level.io variables
    and the library is already loaded.

.NOTES
    Version:          2025.12.27.01
    Target Platform:  Level.io RMM (via Script Launcher)
    Exit Codes:       0 = Success | 1 = Alert (Failure)

    Level.io Variables Used (passed from Script Launcher):
    - $MspScratchFolder  : MSP-defined scratch folder for persistent storage
    - $LibraryUrl        : URL to download COOLForge-Common.psm1 library
    - $DeviceHostname    : Device hostname from Level.io
    - $DeviceTags        : Comma-separated list of device tags

    Additional Custom Fields Required:
    - $ScreenConnectInstanceId : Your MSP's ScreenConnect instance ID to whitelist
    - $IsScreenConnectServer   : Set to "true" if device hosts ScreenConnect server

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# ⛔Force Remove Non MSP ScreenConnect
# Version: 2025.12.27.01
# Target: Level.io (via Script Launcher)
# Exit 0 = Success | Exit 1 = Alert (Failure)
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge

# ============================================================
# ADDITIONAL CUSTOM FIELDS
# ============================================================
# These should be passed from the launcher or set here
# $ScreenConnectInstanceId - Your MSP's instance ID to whitelist
# $IsScreenConnectServer - Set to "true" if this device hosts the server

# ============================================================
# INITIALIZE
# ============================================================
$Init = Initialize-LevelScript -ScriptName "ForceRemoveNonMspScreenConnect" `
                               -MspScratchFolder $MspScratchFolder `
                               -DeviceHostname $DeviceHostname `
                               -DeviceTags $DeviceTags `
                               -BlockingTags @("❌")

if (-not $Init.Success) {
    exit 0
}

# ============================================================
# HELPER FUNCTIONS
# ============================================================

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
    # Check for any non-whitelisted ScreenConnect installations
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

    # Check for non-whitelisted services
    $services = Get-Service | Where-Object {
        ($_.Name -like "*ScreenConnect*" -or $_.DisplayName -like "*ScreenConnect*") -and
        -not (Test-ScreenConnectWhitelisted -Name $_.Name) -and
        -not (Test-ScreenConnectWhitelisted -Name $_.DisplayName)
    }
    if ($services) { return $true }

    # Check for non-whitelisted folders
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

# ============================================================
# MAIN SCRIPT LOGIC
# ============================================================
Invoke-LevelScript -ScriptBlock {

    Write-LevelLog "Starting ScreenConnect removal process"

    # Log device info
    $DeviceInfo = Get-LevelDeviceInfo
    Write-LevelLog "Device: $($DeviceInfo.Hostname) | OS: $($DeviceInfo.OS) | Admin: $($DeviceInfo.IsAdmin)"

    # Check if admin
    if (-not (Test-LevelAdmin)) {
        Write-LevelLog "This script requires administrator privileges" -Level "ERROR"
        Complete-LevelScript -ExitCode 1 -Message "Admin privileges required"
    }

    # Check if this device hosts the ScreenConnect Server
    if ($IsScreenConnectServer -eq "true") {
        Write-LevelLog "This device hosts ScreenConnect Server - skipping removal" -Level "SKIP"
        Complete-LevelScript -ExitCode 0 -Message "ScreenConnect server host - skipped"
    }

    Write-LevelLog "Whitelisted Instance ID: $ScreenConnectInstanceId"

    # Initial check
    if (-not (Test-ScreenConnectInstalled)) {
        Write-LevelLog "No unauthorized ScreenConnect installations found" -Level "SUCCESS"
        Complete-LevelScript -ExitCode 0 -Message "No unauthorized ScreenConnect found"
    }

    Write-LevelLog "Unauthorized ScreenConnect installation(s) detected - beginning removal"

    # ============================================================
    # PHASE 1: Stop Services and Processes
    # ============================================================
    Write-LevelLog "Phase 1: Stopping ScreenConnect services and processes"

    $allServices = Get-Service | Where-Object { $_.Name -like "*ScreenConnect*" -or $_.DisplayName -like "*ScreenConnect*" }
    foreach ($svc in $allServices) {
        if ((Test-ScreenConnectWhitelisted -Name $svc.Name) -or (Test-ScreenConnectWhitelisted -Name $svc.DisplayName)) {
            Write-LevelLog "  SKIPPED (whitelisted): $($svc.DisplayName)" -Level "SKIP"
            continue
        }
        Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
        Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction SilentlyContinue
        Write-LevelLog "  Stopped service: $($svc.DisplayName)" -Level "SUCCESS"
    }

    $processes = @("ScreenConnect.ClientService", "ScreenConnect.WindowsClient", "ScreenConnect.WindowsBackstageShell", "ScreenConnect.Client")
    foreach ($proc in $processes) {
        Get-Process -Name $proc -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    Write-LevelLog "  Stopped ScreenConnect processes" -Level "SUCCESS"

    # ============================================================
    # PHASE 2: Winget Uninstall
    # ============================================================
    Write-LevelLog "Phase 2: Attempting winget uninstall"

    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        $wingetList = winget list --name "ScreenConnect" --accept-source-agreements 2>$null | Out-String
        if ($wingetList -match "ScreenConnect" -and $wingetList -notmatch $ScreenConnectInstanceId) {
            winget uninstall --name "ScreenConnect Client" --silent --force 2>$null
            Write-LevelLog "  Winget uninstall attempted" -Level "SUCCESS"
        } else {
            Write-LevelLog "  Skipped winget (whitelisted or not found)" -Level "SKIP"
        }
    } else {
        Write-LevelLog "  Winget not available" -Level "SKIP"
    }

    # ============================================================
    # PHASE 3: Windows Installer Uninstall
    # ============================================================
    Write-LevelLog "Phase 3: Attempting Windows Installer uninstall"

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
                        Write-LevelLog "  SKIPPED (whitelisted): $displayName" -Level "SKIP"
                        return
                    }

                    $uninstallString = (Get-ItemProperty -Path $_.PSPath).UninstallString
                    $quietUninstall = (Get-ItemProperty -Path $_.PSPath).QuietUninstallString

                    if ($quietUninstall) {
                        Write-LevelLog "  Running quiet uninstall: $displayName"
                        cmd /c $quietUninstall 2>$null
                    } elseif ($uninstallString) {
                        Write-LevelLog "  Running uninstall: $displayName"
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

    # ============================================================
    # PHASE 4: Direct Uninstaller Execution
    # ============================================================
    Write-LevelLog "Phase 4: Attempting direct uninstaller execution"

    $scFolderLocations = @(
        "${env:ProgramFiles}\ScreenConnect Client*",
        "${env:ProgramFiles(x86)}\ScreenConnect Client*"
    )

    foreach ($location in $scFolderLocations) {
        $folders = Get-Item -Path $location -ErrorAction SilentlyContinue
        foreach ($folder in $folders) {
            if (Test-ScreenConnectWhitelisted -Name $folder.Name) {
                Write-LevelLog "  SKIPPED (whitelisted): $($folder.Name)" -Level "SKIP"
                continue
            }

            $uninstaller = Join-Path $folder.FullName "ScreenConnect.ClientService.exe"
            if (Test-Path $uninstaller) {
                Write-LevelLog "  Uninstalling: $($folder.Name)"
                Start-Process -FilePath $uninstaller -ArgumentList "?e=Uninstall" -Wait -ErrorAction SilentlyContinue
            }
        }
    }

    Start-Sleep -Seconds 3

    # ============================================================
    # PHASE 5: Cleanup
    # ============================================================
    Write-LevelLog "Phase 5: Cleaning up leftover files, registry, and services"

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
                Write-LevelLog "  SKIPPED (whitelisted): $($folder.FullName)" -Level "SKIP"
                continue
            }
            Remove-Item -Path $folder.FullName -Recurse -Force -ErrorAction SilentlyContinue
            Write-LevelLog "  Removed folder: $($folder.FullName)" -Level "SUCCESS"
        }
    }

    # Check user profiles
    $userProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue
    foreach ($profile in $userProfiles) {
        $userFolders = @("$($profile.FullName)\AppData\Local\ScreenConnect Client*")
        foreach ($folderPattern in $userFolders) {
            $folders = Get-Item -Path $folderPattern -ErrorAction SilentlyContinue
            foreach ($folder in $folders) {
                if (Test-ScreenConnectWhitelisted -Name $folder.Name) { continue }
                Remove-Item -Path $folder.FullName -Recurse -Force -ErrorAction SilentlyContinue
                Write-LevelLog "  Removed: $($folder.FullName)" -Level "SUCCESS"
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
                Write-LevelLog "  SKIPPED (whitelisted): $($key.PSChildName)" -Level "SKIP"
                continue
            }
            Remove-Item -Path $key.PSPath -Recurse -Force -ErrorAction SilentlyContinue
            Write-LevelLog "  Removed registry: $($key.PSChildName)" -Level "SUCCESS"
        }
    }

    # Remove firewall rules
    $fwRules = Get-NetFirewallRule -DisplayName "*ScreenConnect*" -ErrorAction SilentlyContinue
    foreach ($rule in $fwRules) {
        if (Test-ScreenConnectWhitelisted -Name $rule.DisplayName) {
            Write-LevelLog "  SKIPPED firewall (whitelisted): $($rule.DisplayName)" -Level "SKIP"
            continue
        }
        Remove-NetFirewallRule -Name $rule.Name -ErrorAction SilentlyContinue
        Write-LevelLog "  Removed firewall rule: $($rule.DisplayName)" -Level "SUCCESS"
    }

    # Remove services
    $remainingServices = Get-Service | Where-Object { $_.Name -like "*ScreenConnect*" }
    foreach ($svc in $remainingServices) {
        if ((Test-ScreenConnectWhitelisted -Name $svc.Name) -or (Test-ScreenConnectWhitelisted -Name $svc.DisplayName)) {
            continue
        }
        sc.exe delete "$($svc.Name)" 2>$null
        Write-LevelLog "  Deleted service: $($svc.Name)" -Level "SUCCESS"
    }

    # Remove scheduled tasks
    $scTasks = Get-ScheduledTask -TaskName "*ScreenConnect*" -ErrorAction SilentlyContinue
    foreach ($task in $scTasks) {
        if (Test-ScreenConnectWhitelisted -Name $task.TaskName) { continue }
        Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-LevelLog "  Removed scheduled task: $($task.TaskName)" -Level "SUCCESS"
    }

    # ============================================================
    # VERIFICATION
    # ============================================================
    Write-LevelLog "Verifying removal..."

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

    if ($whitelistedInstalls.Count -gt 0) {
        Write-LevelLog "Your MSP instance preserved:" -Level "SUCCESS"
        $whitelistedInstalls | ForEach-Object { Write-LevelLog "  - $_" -Level "SUCCESS" }
    }

    if ($remainingInstalls.Count -eq 0) {
        Write-LevelLog "All unauthorized ScreenConnect instances removed" -Level "SUCCESS"
    } else {
        Write-LevelLog "Some ScreenConnect components may still be present:" -Level "WARN"
        $remainingInstalls | ForEach-Object { Write-LevelLog "  - $_" -Level "WARN" }
        Complete-LevelScript -ExitCode 1 -Message "ScreenConnect removal incomplete"
    }
}
