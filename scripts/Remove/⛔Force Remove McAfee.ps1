<#
.SYNOPSIS
    Removes McAfee security products from the system.

.DESCRIPTION
    This script performs complete removal of McAfee products:

    Phase 1: Stop McAfee services and processes
    Phase 2: Registry-based uninstall (MSI and exe uninstallers with silent flags)
    Phase 3: MCPR fallback (download and run McAfee Consumer Product Removal tool)
    Phase 4: Force file removal, registry cleanup, firewall rules, tasks, services
    Phase 5: Verify complete removal

    If standard removal methods fail, this script downloads and runs the
    McAfee Consumer Product Removal tool (MCPR) as a fallback.

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

# U+26D4 No Entry - Force Remove McAfee
# Version: 2026.02.01.01
# Target: Level.io (via Script Launcher)
# Exit 0 = Success | Exit 1 = Alert (Failure)
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge

# ============================================================
# INITIALIZE
# ============================================================
$Init = Initialize-LevelScript -ScriptName "ForceRemoveMcAfee" `
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

function Test-McAfeeInstalled {
    # Check services
    $svcs = Get-Service -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match '^(mfe|McAfee)' -or $_.DisplayName -like '*McAfee*'
    }
    if ($svcs) { return $true }

    # Check registry uninstall entries
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    foreach ($regPath in $uninstallPaths) {
        $entries = Get-ItemProperty $regPath -ErrorAction SilentlyContinue |
                   Where-Object { $_.DisplayName -like "*McAfee*" }
        if ($entries) { return $true }
    }

    return $false
}

# ============================================================
# MAIN SCRIPT LOGIC
# ============================================================
Invoke-LevelScript -ScriptBlock {

    Write-LevelLog "Starting McAfee removal process"

    # Log device info
    $DeviceInfo = Get-LevelDeviceInfo
    Write-LevelLog "Device: $($DeviceInfo.Hostname) | OS: $($DeviceInfo.OS) | Admin: $($DeviceInfo.IsAdmin)"

    # Check if admin
    if (-not (Test-LevelAdmin)) {
        Write-LevelLog "This script requires administrator privileges" -Level "ERROR"
        Complete-LevelScript -ExitCode 1 -Message "Admin privileges required"
    }

    # Initial check
    if (-not (Test-McAfeeInstalled)) {
        Write-LevelLog "McAfee is not installed on this system" -Level "SUCCESS"
        Complete-LevelScript -ExitCode 0 -Message "McAfee not found - nothing to remove"
    }

    Write-LevelLog "McAfee installation detected - beginning removal"

    # ============================================================
    # PHASE 1: Stop Services and Processes
    # ============================================================
    Write-LevelLog "Phase 1: Stopping McAfee services and processes"

    # Multiple passes since McAfee services restart each other
    for ($i = 1; $i -le 3; $i++) {
        Write-LevelLog "  --- Stop pass $i of 3 ---"

        # Stop services matching ^(mfe|McAfee) name or McAfee DisplayName
        $mcafeeServices = Get-Service -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -match '^(mfe|McAfee)' -or $_.DisplayName -like '*McAfee*'
        }

        foreach ($svc in $mcafeeServices) {
            try {
                if ($svc.Status -eq 'Running') {
                    Stop-Service -Name $svc.Name -Force -ErrorAction Stop
                    Write-LevelLog "  Stopped service: $($svc.Name) ($($svc.DisplayName))"
                }
                Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction SilentlyContinue
            }
            catch {
                # Fallback via sc.exe
                $null = sc.exe stop $svc.Name 2>&1
                $null = sc.exe config $svc.Name start= disabled 2>&1
                Write-LevelLog "  Stopped via sc.exe: $($svc.Name)"
            }
        }

        Start-Sleep -Seconds 2

        # Stop processes matching *McAfee* and *mfe*
        $mcafeeProcs = Get-Process -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -like "*McAfee*" -or $_.Name -like "*mfe*"
        }

        foreach ($proc in $mcafeeProcs) {
            try {
                Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                Write-LevelLog "  Terminated: $($proc.Name) (PID: $($proc.Id))"
            }
            catch {
                $null = taskkill /F /PID $proc.Id 2>&1
                Write-LevelLog "  Killed via taskkill: $($proc.Name)"
            }
        }

        Start-Sleep -Seconds 3

        # Check if anything is still running
        $remainingSvcs = Get-Service -ErrorAction SilentlyContinue | Where-Object {
            ($_.Name -match '^(mfe|McAfee)' -or $_.DisplayName -like '*McAfee*') -and $_.Status -eq 'Running'
        }
        $remainingProcs = Get-Process -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -like "*McAfee*" -or $_.Name -like "*mfe*"
        }

        if (-not $remainingSvcs -and -not $remainingProcs) {
            Write-LevelLog "  All McAfee services and processes stopped" -Level "SUCCESS"
            break
        }
    }

    # ============================================================
    # PHASE 2: Standard Uninstall
    # ============================================================
    Write-LevelLog "Phase 2: Registry-based uninstall"

    $uninstallRegPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($regPath in $uninstallRegPaths) {
        $entries = Get-ItemProperty $regPath -ErrorAction SilentlyContinue |
                   Where-Object { $_.DisplayName -like "*McAfee*" }

        foreach ($entry in $entries) {
            $displayName = $entry.DisplayName
            $uninstallString = $entry.UninstallString

            if (-not $uninstallString) { continue }

            Write-LevelLog "  Found uninstaller for: $displayName"

            try {
                if ($uninstallString -match "msiexec" -or $uninstallString -match "MsiExec") {
                    # Handle MsiExec uninstallers separately with silent flags
                    $uninstallString = $uninstallString -replace "/I", "/X"
                    if ($uninstallString -notmatch "/qn") {
                        $uninstallString = "$uninstallString /qn /norestart"
                    }
                    Write-LevelLog "  Running MSI uninstall: $uninstallString"
                    cmd /c $uninstallString 2>$null
                }
                else {
                    # Handle exe uninstallers separately with silent flags
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

                    if ($uninstallArgs -notmatch '/silent|/quiet|/qn|/S') {
                        $uninstallArgs = "$uninstallArgs /silent /qn /norestart"
                    }

                    Write-LevelLog "  Running exe uninstall: $exe $uninstallArgs"
                    $process = Start-Process -FilePath $exe -ArgumentList $uninstallArgs -Wait -PassThru -ErrorAction Stop
                    Write-LevelLog "  Exit code: $($process.ExitCode)"
                }

                Start-Sleep -Seconds 5
            }
            catch {
                Write-LevelLog "  Uninstall failed for $displayName : $($_.Exception.Message)" -Level "WARN"
            }
        }
    }

    # Stop processes that may have started during uninstall
    Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -like "*McAfee*" -or $_.Name -like "*mfe*"
    } | Stop-Process -Force -ErrorAction SilentlyContinue

    Start-Sleep -Seconds 5

    # ============================================================
    # PHASE 3: MCPR Fallback
    # ============================================================
    Write-LevelLog "Phase 3: MCPR fallback check"

    # Check if McAfee services still present after standard uninstall
    $remainingMcAfeeServices = Get-Service -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match '^(mfe|McAfee)' -or $_.DisplayName -like '*McAfee*'
    }

    if ($remainingMcAfeeServices) {
        Write-LevelLog "  McAfee services still detected - downloading MCPR fallback tool" -Level "WARN"

        $MCPRUrl = "https://download.mcafee.com/molbin/iss-loc/SupportTools/MCPR/MCPR.exe"
        $installersDir = Join-Path $MspScratchFolder "Installers"
        if (-not (Test-Path $installersDir)) {
            New-Item -Path $installersDir -ItemType Directory -Force | Out-Null
        }
        $MCPRPath = Join-Path $installersDir "MCPR.exe"

        try {
            $webClient = New-Object System.Net.WebClient
            $webClient.DownloadFile($MCPRUrl, $MCPRPath)
            Write-LevelLog "  Downloaded MCPR to: $MCPRPath"

            if (Test-Path $MCPRPath) {
                Write-LevelLog "  Running MCPR (this may take several minutes)..."
                $process = Start-Process -FilePath $MCPRPath -ArgumentList "/qn" -Wait -PassThru -ErrorAction Stop
                Write-LevelLog "  MCPR exited with code: $($process.ExitCode)"

                # Clean up MCPR
                Remove-Item -Path $MCPRPath -Force -ErrorAction SilentlyContinue
                Write-LevelLog "  Cleaned up MCPR installer" -Level "SUCCESS"
            } else {
                Write-LevelLog "  MCPR download failed - file not found" -Level "WARN"
            }
        }
        catch {
            Write-LevelLog "  MCPR failed: $($_.Exception.Message)" -Level "WARN"
            if (Test-Path $MCPRPath) {
                Remove-Item -Path $MCPRPath -Force -ErrorAction SilentlyContinue
            }
        }

        Start-Sleep -Seconds 10
    } else {
        Write-LevelLog "  No McAfee services remaining - skipping MCPR" -Level "SUCCESS"
    }

    # ============================================================
    # PHASE 4: Force File Removal and Cleanup
    # ============================================================
    Write-LevelLog "Phase 4: Force file removal, registry cleanup, firewall, tasks, services"

    # Stop any remaining processes
    Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -like "*McAfee*" -or $_.Name -like "*mfe*"
    } | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    # Force file removal
    $pathsToRemove = @(
        "$env:ProgramFiles\McAfee*",
        "${env:ProgramFiles(x86)}\McAfee*",
        "$env:ProgramData\McAfee*",
        "$env:LOCALAPPDATA\McAfee*"
    )

    foreach ($pattern in $pathsToRemove) {
        $items = Get-Item -Path $pattern -ErrorAction SilentlyContinue
        foreach ($item in $items) {
            try {
                if ($item.PSIsContainer) {
                    Get-ChildItem -Path $item.FullName -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                        $_.Attributes = 'Normal'
                    }
                    Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction Stop
                    Write-LevelLog "  Removed folder: $($item.FullName)" -Level "SUCCESS"
                }
                else {
                    $item.Attributes = 'Normal'
                    Remove-Item -Path $item.FullName -Force -ErrorAction Stop
                    Write-LevelLog "  Removed file: $($item.FullName)" -Level "SUCCESS"
                }
            }
            catch {
                Write-LevelLog "  Failed to remove: $($item.FullName) - $($_.Exception.Message)" -Level "WARN"

                # Fallback with cmd /c rd for folders
                if ($item.PSIsContainer) {
                    try {
                        $null = cmd /c rd /s /q "`"$($item.FullName)`"" 2>&1
                        if (-not (Test-Path $item.FullName)) {
                            Write-LevelLog "  Removed via cmd: $($item.FullName)" -Level "SUCCESS"
                        }
                    }
                    catch {
                        Write-LevelLog "  cmd also failed: $($_.Exception.Message)" -Level "WARN"
                    }
                }
            }
        }
    }

    # Clean user profiles
    $userProfiles = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') }

    foreach ($profile in $userProfiles) {
        $userPaths = @(
            "$($profile.FullName)\AppData\Local\McAfee*",
            "$($profile.FullName)\AppData\Roaming\McAfee*"
        )

        foreach ($path in $userPaths) {
            $items = Get-Item -Path $path -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                try {
                    if ($item.PSIsContainer) {
                        Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction Stop
                    } else {
                        Remove-Item -Path $item.FullName -Force -ErrorAction Stop
                    }
                    Write-LevelLog "  Removed from $($profile.Name): $($item.Name)" -Level "SUCCESS"
                }
                catch {
                    Write-LevelLog "  Failed to remove from $($profile.Name): $($item.Name)" -Level "WARN"
                }
            }
        }
    }

    # Registry cleanup
    $mcafeeRegKeys = @(
        "HKLM:\SOFTWARE\McAfee",
        "HKLM:\SOFTWARE\WOW6432Node\McAfee",
        "HKLM:\SOFTWARE\McAfee.com",
        "HKLM:\SOFTWARE\WOW6432Node\McAfee.com"
    )

    foreach ($key in $mcafeeRegKeys) {
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
    $uninstallCleanupPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    foreach ($regPath in $uninstallCleanupPaths) {
        if (-not (Test-Path $regPath)) { continue }
        Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue | ForEach-Object {
            $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
            if ($props.DisplayName -like "*McAfee*" -or $props.Publisher -like "*McAfee*") {
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

    # Remove McAfee service registry keys
    $serviceKeys = Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services" -ErrorAction SilentlyContinue |
                   Where-Object { $_.Name -match '(McAfee|mfe)' }

    foreach ($key in $serviceKeys) {
        try {
            Remove-Item -Path $key.PSPath -Recurse -Force -ErrorAction Stop
            Write-LevelLog "  Removed service registry key: $($key.PSChildName)" -Level "SUCCESS"
        }
        catch {
            Write-LevelLog "  Failed to remove service key: $($key.PSChildName)" -Level "WARN"
        }
    }

    # Clean up Run keys
    $runKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    )
    foreach ($runKey in $runKeys) {
        $props = Get-ItemProperty -Path $runKey -ErrorAction SilentlyContinue
        if ($props) {
            $props.PSObject.Properties | Where-Object { $_.Value -like "*McAfee*" } | ForEach-Object {
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

    # Remove firewall rules (*McAfee*)
    $fwRules = Get-NetFirewallRule -DisplayName "*McAfee*" -ErrorAction SilentlyContinue
    foreach ($rule in $fwRules) {
        try {
            Remove-NetFirewallRule -Name $rule.Name -ErrorAction Stop
            Write-LevelLog "  Removed firewall rule: $($rule.DisplayName)" -Level "SUCCESS"
        }
        catch {
            Write-LevelLog "  Failed to remove firewall rule: $($rule.DisplayName)" -Level "WARN"
        }
    }

    # Remove scheduled tasks (*McAfee*)
    $mcafeeTasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $_.TaskName -like "*McAfee*" -or $_.TaskPath -like "*McAfee*"
    }
    foreach ($task in $mcafeeTasks) {
        try {
            Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false -ErrorAction Stop
            Write-LevelLog "  Removed scheduled task: $($task.TaskName)" -Level "SUCCESS"
        }
        catch {
            Write-LevelLog "  Failed to remove task $($task.TaskName): $($_.Exception.Message)" -Level "WARN"
        }
    }

    # Remove services
    $remainingServices = Get-Service -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match '^(mfe|McAfee)' -or $_.DisplayName -like '*McAfee*'
    }
    foreach ($svc in $remainingServices) {
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

    # Check if any McAfee services remain
    $remainingSvcs = Get-Service -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match '^(mfe|McAfee)' -or $_.DisplayName -like '*McAfee*'
    }

    # Check registry uninstall entries
    $remainingEntries = @()
    foreach ($regPath in $uninstallRegPaths) {
        $entries = Get-ItemProperty $regPath -ErrorAction SilentlyContinue |
                   Where-Object { $_.DisplayName -like "*McAfee*" }
        foreach ($entry in $entries) {
            $remainingEntries += $entry.DisplayName
        }
    }

    if ($remainingSvcs -or $remainingEntries.Count -gt 0) {
        Write-LevelLog "McAfee removal incomplete - traces still detected" -Level "WARN"

        if ($remainingSvcs) {
            Write-LevelLog "Remaining services:" -Level "WARN"
            foreach ($svc in $remainingSvcs) {
                Write-LevelLog "  - $($svc.Name) ($($svc.DisplayName))" -Level "WARN"
            }
        }
        if ($remainingEntries.Count -gt 0) {
            Write-LevelLog "Remaining registry entries:" -Level "WARN"
            foreach ($entry in $remainingEntries) {
                Write-LevelLog "  - $entry" -Level "WARN"
            }
        }

        Write-LevelLog "A reboot may be required to complete removal" -Level "WARN"
        Complete-LevelScript -ExitCode 1 -Message "McAfee removal incomplete"
    }
    else {
        Write-LevelLog "McAfee has been completely removed from this system" -Level "SUCCESS"
    }
}
