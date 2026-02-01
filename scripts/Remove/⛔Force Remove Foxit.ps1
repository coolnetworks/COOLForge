<#
.SYNOPSIS
    Removes Foxit PDF Reader from the system.

.DESCRIPTION
    This script performs complete removal of Foxit PDF Reader:

    Phase 1: Stop Foxit processes and services
    Phase 2: Winget and MSI-based uninstall
    Phase 3: Force remove Foxit files and folders (with takeown/icacls for locked files)
    Phase 4: Clean up registry entries, shortcuts, scheduled tasks, and services
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

# U+26D4 No Entry - Force Remove Foxit
# Version: 2026.02.01.01
# Target: Level.io (via Script Launcher)
# Exit 0 = Success | Exit 1 = Alert (Failure)
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge

# ============================================================
# INITIALIZE
# ============================================================
$Init = Initialize-LevelScript -ScriptName "ForceRemoveFoxit" `
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

function Test-FoxitInstalled {
    # Check registry uninstall entries
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    foreach ($regPath in $uninstallPaths) {
        $entries = Get-ItemProperty $regPath -ErrorAction SilentlyContinue |
                   Where-Object { $_.DisplayName -like "*Foxit*" }
        if ($entries) { return $true }
    }

    # Check file paths
    $filePaths = @(
        "$env:ProgramFiles\Foxit Software",
        "${env:ProgramFiles(x86)}\Foxit Software",
        "$env:LOCALAPPDATA\Foxit Software",
        "$env:APPDATA\Foxit Software",
        "$env:ProgramData\Foxit Software",
        "$env:PUBLIC\Documents\Foxit Software"
    )
    foreach ($path in $filePaths) {
        if (Test-Path $path) { return $true }
    }

    # Check services
    $svcs = Get-Service -Name "*Foxit*" -ErrorAction SilentlyContinue
    if ($svcs) { return $true }

    return $false
}

# ============================================================
# MAIN SCRIPT LOGIC
# ============================================================
Invoke-LevelScript -ScriptBlock {

    Write-LevelLog "Starting Foxit PDF Reader removal process"

    # Log device info
    $DeviceInfo = Get-LevelDeviceInfo
    Write-LevelLog "Device: $($DeviceInfo.Hostname) | OS: $($DeviceInfo.OS) | Admin: $($DeviceInfo.IsAdmin)"

    # Check if admin
    if (-not (Test-LevelAdmin)) {
        Write-LevelLog "This script requires administrator privileges" -Level "ERROR"
        Complete-LevelScript -ExitCode 1 -Message "Admin privileges required"
    }

    # Initial check
    if (-not (Test-FoxitInstalled)) {
        Write-LevelLog "Foxit PDF Reader is not installed on this system" -Level "SUCCESS"
        Complete-LevelScript -ExitCode 0 -Message "Foxit not found - nothing to remove"
    }

    Write-LevelLog "Foxit installation detected - beginning removal"

    # ============================================================
    # PHASE 1: Stop Processes
    # ============================================================
    Write-LevelLog "Phase 1: Stopping Foxit processes"

    $foxitProcs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*Foxit*" }
    $procCount = 0
    foreach ($proc in $foxitProcs) {
        try {
            Stop-Process -Id $proc.Id -Force -ErrorAction Stop
            Write-LevelLog "  Stopped process: $($proc.Name) (PID: $($proc.Id))"
            $procCount++
        }
        catch {
            Write-LevelLog "  Failed to stop $($proc.Name): $($_.Exception.Message)" -Level "WARN"
        }
    }
    Write-LevelLog "  Stopped $procCount Foxit process(es)" -Level "SUCCESS"

    Start-Sleep -Seconds 3

    # ============================================================
    # PHASE 2: Standard Uninstall
    # ============================================================
    Write-LevelLog "Phase 2: Attempting standard uninstall (Winget + MSI)"

    # Winget uninstall
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        $foxitIds = @(
            "Foxit.FoxitReader",
            "Foxit PDF Reader",
            "Foxit Reader"
        )

        foreach ($id in $foxitIds) {
            Write-LevelLog "  Attempting winget uninstall: $id"
            try {
                $output = winget uninstall --id $id --silent --force --accept-source-agreements 2>&1 | Out-String
                if ($output -notmatch "No installed package found") {
                    Write-LevelLog "  Winget uninstall attempted for: $id" -Level "SUCCESS"
                    Start-Sleep -Seconds 3
                }
            }
            catch {
                Write-LevelLog "  Winget uninstall failed for $id : $($_.Exception.Message)" -Level "WARN"
            }
        }
    } else {
        Write-LevelLog "  Winget not available - skipping" -Level "SKIP"
    }

    # MSI uninstall from registry (look for PSChildName matching GUID pattern)
    $uninstallRegPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    foreach ($regPath in $uninstallRegPaths) {
        if (-not (Test-Path $regPath)) { continue }

        Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue | ForEach-Object {
            $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
            if ($props.DisplayName -like "*Foxit*") {
                $displayName = $props.DisplayName
                $uninstallString = $props.UninstallString

                # Check if this is an MSI product (PSChildName matches GUID pattern)
                if ($_.PSChildName -match '^\{[A-F0-9\-]+\}$') {
                    $productCode = $_.PSChildName
                    Write-LevelLog "  Found MSI product: $displayName ($productCode)"
                    try {
                        $msiArgs = "/x $productCode /qn /norestart"
                        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru -ErrorAction Stop
                        Write-LevelLog "  MSI uninstall exit code: $($process.ExitCode)"
                        Start-Sleep -Seconds 3
                    }
                    catch {
                        Write-LevelLog "  MSI uninstall failed: $($_.Exception.Message)" -Level "WARN"
                    }
                }
                elseif ($uninstallString) {
                    Write-LevelLog "  Found uninstaller for: $displayName"
                    if ($uninstallString -match "msiexec") {
                        $uninstallString = $uninstallString -replace "/I", "/X"
                        if ($uninstallString -notmatch "/qn") {
                            $uninstallString = "$uninstallString /qn /norestart"
                        }
                    }
                    try {
                        cmd /c $uninstallString 2>$null
                        Start-Sleep -Seconds 3
                    }
                    catch {
                        Write-LevelLog "  Registry uninstall failed: $($_.Exception.Message)" -Level "WARN"
                    }
                }
            }
        }
    }

    Start-Sleep -Seconds 5

    # ============================================================
    # PHASE 3: Force File Removal with Privilege Escalation
    # ============================================================
    Write-LevelLog "Phase 3: Force removing Foxit files and folders"

    # Stop processes again in case uninstall respawned them
    Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*Foxit*" } | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    $pathsToRemove = @(
        "$env:ProgramFiles\Foxit Software",
        "${env:ProgramFiles(x86)}\Foxit Software",
        "$env:LOCALAPPDATA\Foxit Software",
        "$env:APPDATA\Foxit Software",
        "$env:ProgramData\Foxit Software",
        "$env:PUBLIC\Documents\Foxit Software"
    )

    foreach ($folder in $pathsToRemove) {
        if (-not (Test-Path $folder)) { continue }

        try {
            Remove-Item -Path $folder -Recurse -Force -ErrorAction Stop
            Write-LevelLog "  Removed: $folder" -Level "SUCCESS"
        }
        catch {
            Write-LevelLog "  Standard removal failed for $folder - attempting takeown/icacls" -Level "WARN"

            # Force ownership and permissions for locked files
            try {
                $null = takeown /f "$folder" /r /d y 2>$null
                $null = icacls "$folder" /grant administrators:F /t 2>$null
                Remove-Item -Path $folder -Recurse -Force -ErrorAction Stop
                Write-LevelLog "  Removed with takeown: $folder" -Level "SUCCESS"
            }
            catch {
                Write-LevelLog "  Failed to remove even with takeown: $folder - $($_.Exception.Message)" -Level "WARN"

                # Last resort: cmd /c rd
                try {
                    $null = cmd /c rd /s /q "`"$folder`"" 2>&1
                    if (-not (Test-Path $folder)) {
                        Write-LevelLog "  Removed via cmd: $folder" -Level "SUCCESS"
                    }
                }
                catch {
                    Write-LevelLog "  All removal methods failed for: $folder" -Level "WARN"
                }
            }
        }
    }

    # Clean all user profiles
    $userProfiles = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') }

    foreach ($profile in $userProfiles) {
        $userPaths = @(
            "$($profile.FullName)\AppData\Local\Foxit Software",
            "$($profile.FullName)\AppData\Roaming\Foxit Software"
        )

        foreach ($path in $userPaths) {
            if (-not (Test-Path $path)) { continue }
            try {
                Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
                Write-LevelLog "  Removed from $($profile.Name): $path" -Level "SUCCESS"
            }
            catch {
                Write-LevelLog "  Failed to remove from $($profile.Name): $path" -Level "WARN"
            }
        }
    }

    # ============================================================
    # PHASE 4: Registry Cleanup
    # ============================================================
    Write-LevelLog "Phase 4: Cleaning registry, shortcuts, tasks, and services"

    # Remove Foxit-specific registry keys
    $foxitRegKeys = @(
        "HKLM:\SOFTWARE\Foxit Software",
        "HKLM:\SOFTWARE\WOW6432Node\Foxit Software",
        "HKCU:\SOFTWARE\Foxit Software"
    )

    foreach ($key in $foxitRegKeys) {
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
            if ($props.DisplayName -like "*Foxit*" -or $props.Publisher -like "*Foxit*") {
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

    # Remove scheduled tasks (*Foxit*)
    $foxitTasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $_.TaskName -like "*Foxit*" -or $_.TaskPath -like "*Foxit*"
    }
    foreach ($task in $foxitTasks) {
        try {
            Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false -ErrorAction Stop
            Write-LevelLog "  Removed scheduled task: $($task.TaskName)" -Level "SUCCESS"
        }
        catch {
            Write-LevelLog "  Failed to remove task $($task.TaskName): $($_.Exception.Message)" -Level "WARN"
        }
    }

    # Remove shortcuts (Start Menu, Desktop)
    $shortcutPaths = @(
        "$env:PUBLIC\Desktop\Foxit*.lnk",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Foxit*"
    )

    $userProfiles = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue
    foreach ($profile in $userProfiles) {
        $shortcutPaths += "$($profile.FullName)\Desktop\Foxit*.lnk"
        $shortcutPaths += "$($profile.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Foxit*"
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

    # Remove services (*Foxit*)
    $foxitServices = Get-Service -Name "*Foxit*" -ErrorAction SilentlyContinue
    foreach ($svc in $foxitServices) {
        try {
            Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
            $null = sc.exe delete "$($svc.Name)" 2>&1
            Write-LevelLog "  Deleted service: $($svc.Name)" -Level "SUCCESS"
        }
        catch {
            Write-LevelLog "  Failed to delete service $($svc.Name): $($_.Exception.Message)" -Level "WARN"
        }
    }

    # ============================================================
    # PHASE 5: Verification
    # ============================================================
    Write-LevelLog "Phase 5: Verifying removal"

    Start-Sleep -Seconds 3

    # Check registry uninstall entries
    $remainingEntries = @()
    foreach ($regPath in $uninstallRegPaths) {
        if (-not (Test-Path $regPath)) { continue }
        Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue | ForEach-Object {
            $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
            if ($props.DisplayName -like "*Foxit*") {
                $remainingEntries += $props.DisplayName
            }
        }
    }

    # Check file paths
    $remainingDirs = @(
        "$env:ProgramFiles\Foxit Software",
        "${env:ProgramFiles(x86)}\Foxit Software",
        "$env:LOCALAPPDATA\Foxit Software",
        "$env:APPDATA\Foxit Software",
        "$env:ProgramData\Foxit Software",
        "$env:PUBLIC\Documents\Foxit Software"
    ) | Where-Object { Test-Path $_ }

    # Check services
    $remainingSvcs = Get-Service -Name "*Foxit*" -ErrorAction SilentlyContinue

    if ($remainingEntries.Count -gt 0 -or $remainingDirs -or $remainingSvcs) {
        Write-LevelLog "Foxit removal incomplete - traces still detected" -Level "WARN"

        if ($remainingEntries.Count -gt 0) {
            Write-LevelLog "Remaining registry entries:" -Level "WARN"
            foreach ($entry in $remainingEntries) {
                Write-LevelLog "  - $entry" -Level "WARN"
            }
        }
        if ($remainingDirs) {
            Write-LevelLog "Remaining directories:" -Level "WARN"
            foreach ($dir in $remainingDirs) {
                Write-LevelLog "  - $dir" -Level "WARN"
            }
        }
        if ($remainingSvcs) {
            Write-LevelLog "Remaining services: $($remainingSvcs.Name -join ', ')" -Level "WARN"
        }

        Complete-LevelScript -ExitCode 1 -Message "Foxit removal incomplete"
    }
    else {
        Write-LevelLog "Foxit PDF Reader has been completely removed from this system" -Level "SUCCESS"
    }
}
