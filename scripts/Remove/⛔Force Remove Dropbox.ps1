<#
.SYNOPSIS
    Removes Dropbox from the system.

.DESCRIPTION
    This script performs complete removal of Dropbox:

    Phase 1: Stop Dropbox processes
    Phase 2: WMI/CIM uninstall and registry-based uninstall
    Phase 3: Remove Dropbox files and folders (including all user profiles)
    Phase 4: Clean up registry entries, shortcuts, and scheduled tasks
    Phase 5: Verify complete removal

    When run via Script Launcher, this script inherits all Level.io variables
    and the library is already loaded.

.NOTES
    Version:          2026.02.01.01
    Target Platform:  Level.io RMM (via Script Launcher)
    Exit Codes:       0 = Success | 1 = Alert (Failure)

    Level.io Variables Used (passed from Script Launcher):
    - $MspScratchFolder  : MSP-defined scratch folder for persistent storage
    - $LibraryUrl        : URL to download COOLForge-Common.psm1 library
    - $DeviceHostname    : Device hostname from Level.io
    - $DeviceTags        : Comma-separated list of device tags

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# U+26D4 No Entry - Force Remove Dropbox
# Version: 2026.02.01.01
# Target: Level.io (via Script Launcher)
# Exit 0 = Success | Exit 1 = Alert (Failure)
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge

# ============================================================
# INITIALIZE
# ============================================================
$Init = Initialize-LevelScript -ScriptName "ForceRemoveDropbox" `
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

function Test-DropboxInstalled {
    # Check registry uninstall entries
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    foreach ($regPath in $uninstallPaths) {
        $entries = Get-ItemProperty $regPath -ErrorAction SilentlyContinue |
                   Where-Object { $_.DisplayName -like "*Dropbox*" }
        if ($entries) { return $true }
    }

    # Check file paths
    $filePaths = @(
        "$env:ProgramFiles\Dropbox",
        "${env:ProgramFiles(x86)}\Dropbox",
        "$env:LOCALAPPDATA\Dropbox",
        "$env:APPDATA\Dropbox",
        "$env:ProgramData\Dropbox",
        "$env:USERPROFILE\Dropbox"
    )
    foreach ($path in $filePaths) {
        if (Test-Path $path) { return $true }
    }

    # Check services
    $svcs = Get-Service -Name "*Dropbox*" -ErrorAction SilentlyContinue
    if ($svcs) { return $true }

    return $false
}

# ============================================================
# MAIN SCRIPT LOGIC
# ============================================================
Invoke-LevelScript -ScriptBlock {

    Write-LevelLog "Starting Dropbox removal process"

    # Log device info
    $DeviceInfo = Get-LevelDeviceInfo
    Write-LevelLog "Device: $($DeviceInfo.Hostname) | OS: $($DeviceInfo.OS) | Admin: $($DeviceInfo.IsAdmin)"

    # Check if admin
    if (-not (Test-LevelAdmin)) {
        Write-LevelLog "This script requires administrator privileges" -Level "ERROR"
        Complete-LevelScript -ExitCode 1 -Message "Admin privileges required"
    }

    # Initial check
    if (-not (Test-DropboxInstalled)) {
        Write-LevelLog "Dropbox is not installed on this system" -Level "SUCCESS"
        Complete-LevelScript -ExitCode 0 -Message "Dropbox not found - nothing to remove"
    }

    Write-LevelLog "Dropbox installation detected - beginning removal"

    # ============================================================
    # PHASE 1: Stop Processes
    # ============================================================
    Write-LevelLog "Phase 1: Stopping Dropbox processes"

    $processNames = @("Dropbox", "DropboxUpdate")
    foreach ($procName in $processNames) {
        Get-Process -Name $procName -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    # Catch any remaining Dropbox-related processes via wildcard
    Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "Dropbox*" } | Stop-Process -Force -ErrorAction SilentlyContinue
    Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "DropboxUpdate*" } | Stop-Process -Force -ErrorAction SilentlyContinue

    # Stop Dropbox services
    $dbxServices = Get-Service -Name "*Dropbox*" -ErrorAction SilentlyContinue
    foreach ($svc in $dbxServices) {
        Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
        Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction SilentlyContinue
        Write-LevelLog "  Stopped service: $($svc.DisplayName)"
    }

    # Also stop the dbupdate services
    $dbxUpdate = Get-Service -Name "dbupdate*" -ErrorAction SilentlyContinue
    foreach ($svc in $dbxUpdate) {
        Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
        Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction SilentlyContinue
        Write-LevelLog "  Stopped update service: $($svc.Name)"
    }

    Write-LevelLog "  Stopped Dropbox processes and services" -Level "SUCCESS"
    Start-Sleep -Seconds 3

    # ============================================================
    # PHASE 2: Standard Uninstall
    # ============================================================
    Write-LevelLog "Phase 2: Attempting standard uninstall (WMI/CIM + Registry)"

    # WMI/CIM uninstall
    try {
        $products = Get-CimInstance -ClassName Win32_Product -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -like "*Dropbox*" }

        foreach ($product in $products) {
            Write-LevelLog "  Found CIM product: $($product.Name) ($($product.Version))"
            try {
                $result = Invoke-CimMethod -InputObject $product -MethodName Uninstall -ErrorAction Stop
                if ($result.ReturnValue -eq 0) {
                    Write-LevelLog "  CIM uninstall successful: $($product.Name)" -Level "SUCCESS"
                } else {
                    Write-LevelLog "  CIM uninstall returned code: $($result.ReturnValue)" -Level "WARN"
                }
                Start-Sleep -Seconds 3
            }
            catch {
                Write-LevelLog "  CIM uninstall failed: $($_.Exception.Message)" -Level "WARN"
            }
        }
    }
    catch {
        Write-LevelLog "  CIM query failed: $($_.Exception.Message)" -Level "WARN"
    }

    # Registry-based uninstall
    $uninstallRegPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    foreach ($regPath in $uninstallRegPaths) {
        if (-not (Test-Path $regPath)) { continue }

        Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue | ForEach-Object {
            $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
            if ($props.DisplayName -like "*Dropbox*") {
                $displayName = $props.DisplayName
                $uninstallString = $props.UninstallString
                $quietUninstall = $props.QuietUninstallString

                if ($quietUninstall) {
                    Write-LevelLog "  Running quiet uninstall: $displayName"
                    cmd /c $quietUninstall 2>$null
                    Start-Sleep -Seconds 5
                }
                elseif ($uninstallString) {
                    Write-LevelLog "  Running uninstall: $displayName"

                    if ($uninstallString -match '"(.+)"(.*)') {
                        $exe = $Matches[1]
                        $uninstallArgs = $Matches[2].Trim()
                    }
                    elseif ($uninstallString -match '^(.+\.exe)(.*)$') {
                        $exe = $Matches[1]
                        $uninstallArgs = $Matches[2].Trim()
                    }
                    else {
                        $exe = $uninstallString
                        $uninstallArgs = ""
                    }

                    # Add silent flags if not present
                    if ($uninstallArgs -notmatch '/S|/quiet|/qn|/silent') {
                        $uninstallArgs = "$uninstallArgs /S"
                    }

                    try {
                        $process = Start-Process -FilePath $exe -ArgumentList $uninstallArgs -Wait -PassThru -ErrorAction Stop
                        Write-LevelLog "  Uninstaller exited with code: $($process.ExitCode)"
                    }
                    catch {
                        Write-LevelLog "  Uninstall failed: $($_.Exception.Message)" -Level "WARN"
                    }
                    Start-Sleep -Seconds 5
                }
            }
        }
    }

    Start-Sleep -Seconds 5

    # ============================================================
    # PHASE 3: Force File Removal
    # ============================================================
    Write-LevelLog "Phase 3: Removing Dropbox files and folders"

    # Stop processes again in case uninstall respawned them
    Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "Dropbox*" } | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    $pathsToRemove = @(
        "$env:ProgramFiles\Dropbox",
        "${env:ProgramFiles(x86)}\Dropbox",
        "$env:LOCALAPPDATA\Dropbox",
        "$env:APPDATA\Dropbox",
        "$env:ProgramData\Dropbox",
        "$env:USERPROFILE\Dropbox"
    )

    foreach ($path in $pathsToRemove) {
        if (Test-Path $path) {
            try {
                Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
                Write-LevelLog "  Removed: $path" -Level "SUCCESS"
            }
            catch {
                Write-LevelLog "  Failed to remove: $path - $($_.Exception.Message)" -Level "WARN"
            }
        }
    }

    # Check all user profiles
    $userProfiles = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') }

    foreach ($profile in $userProfiles) {
        $userPaths = @(
            "$($profile.FullName)\AppData\Local\Dropbox",
            "$($profile.FullName)\AppData\Roaming\Dropbox",
            "$($profile.FullName)\Dropbox"
        )

        foreach ($path in $userPaths) {
            if (Test-Path $path) {
                try {
                    Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
                    Write-LevelLog "  Removed from $($profile.Name): $path" -Level "SUCCESS"
                }
                catch {
                    Write-LevelLog "  Failed to remove from $($profile.Name): $path" -Level "WARN"
                }
            }
        }
    }

    # ============================================================
    # PHASE 4: Registry Cleanup
    # ============================================================
    Write-LevelLog "Phase 4: Cleaning registry entries, shortcuts, and scheduled tasks"

    # Remove Dropbox-specific registry keys
    $dropboxRegKeys = @(
        "HKCU:\Software\Dropbox",
        "HKLM:\Software\Dropbox",
        "HKLM:\Software\Wow6432Node\Dropbox"
    )

    foreach ($key in $dropboxRegKeys) {
        if (Test-Path $key) {
            try {
                Remove-Item -Path $key -Recurse -Force -ErrorAction Stop
                Write-LevelLog "  Removed registry key: $key" -Level "SUCCESS"
            }
            catch {
                Write-LevelLog "  Failed to remove registry key: $key" -Level "WARN"
            }
        }
    }

    # Clean uninstall entries
    foreach ($regPath in $uninstallRegPaths) {
        if (-not (Test-Path $regPath)) { continue }
        Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue | ForEach-Object {
            $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
            if ($props.DisplayName -like "*Dropbox*" -or $props.Publisher -like "*Dropbox*") {
                try {
                    Remove-Item -Path $_.PSPath -Recurse -Force -ErrorAction Stop
                    Write-LevelLog "  Removed uninstall entry: $($props.DisplayName)" -Level "SUCCESS"
                }
                catch {
                    Write-LevelLog "  Failed to remove uninstall entry: $($_.PSPath)" -Level "WARN"
                }
            }
        }
    }

    # Clean up Run keys
    $runKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    )
    foreach ($runKey in $runKeys) {
        $props = Get-ItemProperty -Path $runKey -ErrorAction SilentlyContinue
        if ($props) {
            $props.PSObject.Properties | Where-Object { $_.Value -like "*Dropbox*" } | ForEach-Object {
                try {
                    Remove-ItemProperty -Path $runKey -Name $_.Name -Force -ErrorAction Stop
                    Write-LevelLog "  Removed run entry: $($_.Name)" -Level "SUCCESS"
                }
                catch {
                    Write-LevelLog "  Failed to remove run entry: $($_.Name)" -Level "WARN"
                }
            }
        }
    }

    # Remove shortcuts (Desktop, Start Menu)
    $shortcutPaths = @(
        "$env:PUBLIC\Desktop\Dropbox*.lnk",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Dropbox*",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\Dropbox*"
    )

    $userProfiles = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue
    foreach ($profile in $userProfiles) {
        $shortcutPaths += "$($profile.FullName)\Desktop\Dropbox*.lnk"
        $shortcutPaths += "$($profile.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Dropbox*"
        $shortcutPaths += "$($profile.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Dropbox*"
    }

    foreach ($pattern in $shortcutPaths) {
        $items = Get-Item -Path $pattern -ErrorAction SilentlyContinue
        foreach ($item in $items) {
            try {
                if ($item.PSIsContainer) {
                    Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction Stop
                } else {
                    Remove-Item -Path $item.FullName -Force -ErrorAction Stop
                }
                Write-LevelLog "  Removed shortcut: $($item.FullName)" -Level "SUCCESS"
            }
            catch {
                Write-LevelLog "  Failed to remove shortcut: $($item.FullName)" -Level "WARN"
            }
        }
    }

    # Remove scheduled tasks matching *Dropbox*
    $dbxTasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $_.TaskName -like "*Dropbox*" -or $_.TaskPath -like "*Dropbox*"
    }
    foreach ($task in $dbxTasks) {
        try {
            Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false -ErrorAction Stop
            Write-LevelLog "  Removed scheduled task: $($task.TaskName)" -Level "SUCCESS"
        }
        catch {
            Write-LevelLog "  Failed to remove task $($task.TaskName): $($_.Exception.Message)" -Level "WARN"
        }
    }

    # ============================================================
    # PHASE 5: Verification
    # ============================================================
    Write-LevelLog "Phase 5: Verifying removal"

    Start-Sleep -Seconds 3

    # Check uninstall registry for remaining entries
    $remainingEntries = @()
    foreach ($regPath in $uninstallRegPaths) {
        if (-not (Test-Path $regPath)) { continue }
        Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue | ForEach-Object {
            $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
            if ($props.DisplayName -like "*Dropbox*") {
                $remainingEntries += $props.DisplayName
            }
        }
    }

    # Check processes
    $remainingProcs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "Dropbox*" }

    if ($remainingEntries.Count -gt 0 -or $remainingProcs) {
        Write-LevelLog "Dropbox removal incomplete - traces still detected" -Level "WARN"

        if ($remainingEntries.Count -gt 0) {
            Write-LevelLog "Remaining registry entries:" -Level "WARN"
            foreach ($entry in $remainingEntries) {
                Write-LevelLog "  - $entry" -Level "WARN"
            }
        }
        if ($remainingProcs) {
            Write-LevelLog "Remaining processes: $($remainingProcs.Name -join ', ')" -Level "WARN"
        }

        Complete-LevelScript -ExitCode 1 -Message "Dropbox removal incomplete"
    }
    else {
        Write-LevelLog "Dropbox has been completely removed from this system" -Level "SUCCESS"
    }
}
