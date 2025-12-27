<#
.SYNOPSIS
    Removes AnyDesk remote access software from the system.

.DESCRIPTION
    This script attempts to remove AnyDesk using progressively forceful methods:

    Phase 1: Standard uninstall via registry uninstall strings
    Phase 2: Stop AnyDesk services and processes
    Phase 3: Remove AnyDesk files and folders
    Phase 4: Clean up registry entries
    Phase 5: Verify complete removal

    Each phase logs its actions and the script continues until AnyDesk
    is verified as completely removed from the system.

.NOTES
    Version:          2025.12.27.03
    Target Platform:  Level.io RMM
    Exit Codes:       0 = Success | 1 = Failure

    Level.io Variables Used:
    - {{cf_msp_scratch_folder}}      : MSP-defined scratch folder for persistent storage
    - {{cf_ps_module_library_source}}: URL to download LevelIO-Common.psm1 library
    - {{level_device_hostname}}      : Device hostname from Level.io
    - {{level_tag_names}}            : Comma-separated list of device tags

    Copyright (c) COOLNETWORKS
    https://coolnetworks.au
    https://github.com/coolnetworks/LevelLib

.LINK
    https://github.com/coolnetworks/LevelLib
#>

# ⛔Force Remove Anydesk
# Version: 2025.12.27.03
# Target: Level.io
# Exit 0 = Success | Exit 1 = Failure
#
# Copyright (c) COOLNETWORKS
# https://coolnetworks.au
# https://github.com/coolnetworks/LevelLib
$ErrorActionPreference = "SilentlyContinue"

# ============================================================
# LIBRARY AUTO-UPDATE & IMPORT
# ============================================================
$MspScratchFolder = "{{cf_msp_scratch_folder}}"
$LibraryUrl = "{{cf_ps_module_library_source}}"

$LibraryFolder = Join-Path -Path $MspScratchFolder -ChildPath "Libraries"
$LibraryPath = Join-Path -Path $LibraryFolder -ChildPath "LevelIO-Common.psm1"

if (!(Test-Path $LibraryFolder)) {
    New-Item -Path $LibraryFolder -ItemType Directory -Force | Out-Null
}

function Get-ModuleVersion {
    param([string]$Content, [string]$Source = "unknown")
    if ($Content -match 'Version:\s*([\d\.]+)') {
        return $Matches[1]
    }
    throw "Could not parse version from $Source - invalid or corrupt library content"
}

$NeedsUpdate = $false
$LocalVersion = $null
$LocalContent = $null
$BackupPath = "$LibraryPath.backup"

if (Test-Path $LibraryPath) {
    try {
        $LocalContent = Get-Content -Path $LibraryPath -Raw -ErrorAction Stop
        $LocalVersion = Get-ModuleVersion -Content $LocalContent -Source "local file"
    }
    catch {
        Write-Host "[!] Local library corrupt - will redownload"
        $NeedsUpdate = $true
    }
}
else {
    $NeedsUpdate = $true
    Write-Host "[*] Library not found - downloading..."
}

try {
    $RemoteContent = (Invoke-WebRequest -Uri $LibraryUrl -UseBasicParsing -TimeoutSec 10).Content
    $RemoteVersion = Get-ModuleVersion -Content $RemoteContent -Source "remote URL"

    if ($null -eq $LocalVersion -or [version]$RemoteVersion -gt [version]$LocalVersion) {
        $NeedsUpdate = $true
        if ($LocalVersion) {
            Write-Host "[*] Update available: $LocalVersion -> $RemoteVersion"
        }
    }

    if ($NeedsUpdate) {
        # Backup working local copy before updating (if we have a valid one)
        if ($LocalVersion -and $LocalContent) {
            Set-Content -Path $BackupPath -Value $LocalContent -Force -ErrorAction Stop
        }

        # Write new version
        Set-Content -Path $LibraryPath -Value $RemoteContent -Force -ErrorAction Stop

        # Verify the new file is valid before removing backup
        try {
            $VerifyContent = Get-Content -Path $LibraryPath -Raw -ErrorAction Stop
            $null = Get-ModuleVersion -Content $VerifyContent -Source "downloaded file"
            # Success - remove backup
            if (Test-Path $BackupPath) {
                Remove-Item -Path $BackupPath -Force -ErrorAction SilentlyContinue
            }
            Write-Host "[+] Library updated to v$RemoteVersion"
        }
        catch {
            # New file is corrupt - restore backup
            if (Test-Path $BackupPath) {
                Write-Host "[!] Downloaded file corrupt - restoring backup"
                Move-Item -Path $BackupPath -Destination $LibraryPath -Force
            }
            throw "Downloaded library failed verification"
        }
    }
}
catch {
    # GitHub unreachable or remote content invalid
    # Clean up any leftover backup
    if (Test-Path $BackupPath) {
        Move-Item -Path $BackupPath -Destination $LibraryPath -Force -ErrorAction SilentlyContinue
    }

    if (!(Test-Path $LibraryPath) -or $null -eq $LocalVersion) {
        Write-Host "[X] FATAL: Cannot download library and no valid local copy exists"
        Write-Host "[X] Error: $($_.Exception.Message)"
        exit 1
    }
    Write-Host "[!] Could not check for updates (using local v$LocalVersion)"
}

$ModuleContent = Get-Content -Path $LibraryPath -Raw
New-Module -Name "LevelIO-Common" -ScriptBlock ([scriptblock]::Create($ModuleContent)) | Import-Module -Force

# ============================================================
# INITIALIZE
# ============================================================
$Init = Initialize-LevelScript -ScriptName "RemoveAnyDesk" `
                               -MspScratchFolder $MspScratchFolder `
                               -DeviceHostname "{{level_device_hostname}}" `
                               -DeviceTags "{{level_tag_names}}" `
                               -BlockingTags @("❌")

if (-not $Init.Success) {
    exit 0
}

# ============================================================
# ANYDESK REMOVAL FUNCTIONS
# ============================================================

function Test-AnyDeskInstalled {
    <#
    .SYNOPSIS
        Checks if AnyDesk is installed on the system.
    .RETURNS
        $true if AnyDesk is detected, $false otherwise.
    #>

    # Check for AnyDesk processes
    $processes = Get-Process -Name "AnyDesk*" -ErrorAction SilentlyContinue
    if ($processes) { return $true }

    # Check for AnyDesk services
    $services = Get-Service -Name "AnyDesk*" -ErrorAction SilentlyContinue
    if ($services) { return $true }

    # Check common installation paths
    $paths = @(
        "$env:ProgramFiles\AnyDesk",
        "$env:ProgramFiles(x86)\AnyDesk",
        "$env:LOCALAPPDATA\AnyDesk",
        "$env:ProgramData\AnyDesk",
        "$env:APPDATA\AnyDesk"
    )
    foreach ($path in $paths) {
        if (Test-Path $path) { return $true }
    }

    # Check registry for uninstall entries
    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    foreach ($regPath in $regPaths) {
        $entries = Get-ItemProperty $regPath -ErrorAction SilentlyContinue |
                   Where-Object { $_.DisplayName -like "*AnyDesk*" }
        if ($entries) { return $true }
    }

    return $false
}

function Stop-AnyDeskProcesses {
    <#
    .SYNOPSIS
        Stops all AnyDesk processes.
    .RETURNS
        Number of processes stopped.
    #>
    $count = 0
    $processes = Get-Process -Name "AnyDesk*" -ErrorAction SilentlyContinue
    foreach ($proc in $processes) {
        try {
            Stop-Process -Id $proc.Id -Force -ErrorAction Stop
            $count++
            Write-LevelLog "Stopped process: $($proc.Name) (PID: $($proc.Id))"
        }
        catch {
            Write-LevelLog "Failed to stop process: $($proc.Name) - $($_.Exception.Message)" -Level "WARN"
        }
    }
    return $count
}

function Stop-AnyDeskServices {
    <#
    .SYNOPSIS
        Stops and disables AnyDesk services.
    .RETURNS
        Number of services stopped.
    #>
    $count = 0
    $services = Get-Service -Name "AnyDesk*" -ErrorAction SilentlyContinue
    foreach ($svc in $services) {
        try {
            if ($svc.Status -eq 'Running') {
                Stop-Service -Name $svc.Name -Force -ErrorAction Stop
                Write-LevelLog "Stopped service: $($svc.Name)"
            }
            Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction Stop
            Write-LevelLog "Disabled service: $($svc.Name)"
            $count++
        }
        catch {
            Write-LevelLog "Failed to stop/disable service: $($svc.Name) - $($_.Exception.Message)" -Level "WARN"
        }
    }
    return $count
}

function Invoke-AnyDeskUninstall {
    <#
    .SYNOPSIS
        Attempts standard uninstall via registry uninstall strings.
    .RETURNS
        $true if uninstall was attempted, $false if no uninstaller found.
    #>
    $uninstalled = $false
    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($regPath in $regPaths) {
        $entries = Get-ItemProperty $regPath -ErrorAction SilentlyContinue |
                   Where-Object { $_.DisplayName -like "*AnyDesk*" }

        foreach ($entry in $entries) {
            $uninstallString = $entry.UninstallString
            if ($uninstallString) {
                Write-LevelLog "Found uninstaller: $uninstallString"

                # Handle different uninstall string formats
                if ($uninstallString -match '^"(.+)"(.*)$') {
                    $exe = $Matches[1]
                    $args = $Matches[2].Trim()
                }
                elseif ($uninstallString -match '^(.+\.exe)(.*)$') {
                    $exe = $Matches[1]
                    $args = $Matches[2].Trim()
                }
                else {
                    $exe = $uninstallString
                    $args = ""
                }

                # Add silent flags if not present
                if ($args -notmatch '/S|--silent|--remove') {
                    $args = "$args --remove --silent"
                }

                try {
                    Write-LevelLog "Executing: $exe $args"
                    $process = Start-Process -FilePath $exe -ArgumentList $args -Wait -PassThru -ErrorAction Stop
                    Write-LevelLog "Uninstaller exited with code: $($process.ExitCode)"
                    $uninstalled = $true
                    Start-Sleep -Seconds 3
                }
                catch {
                    Write-LevelLog "Uninstall failed: $($_.Exception.Message)" -Level "WARN"
                }
            }
        }
    }

    # Try AnyDesk's own uninstall command if executable exists
    $anyDeskPaths = @(
        "$env:ProgramFiles\AnyDesk\AnyDesk.exe",
        "$env:ProgramFiles(x86)\AnyDesk\AnyDesk.exe",
        "$env:LOCALAPPDATA\AnyDesk\AnyDesk.exe"
    )

    foreach ($adPath in $anyDeskPaths) {
        if (Test-Path $adPath) {
            try {
                Write-LevelLog "Trying direct uninstall: $adPath --remove --silent"
                $process = Start-Process -FilePath $adPath -ArgumentList "--remove --silent" -Wait -PassThru -ErrorAction Stop
                Write-LevelLog "Direct uninstall exited with code: $($process.ExitCode)"
                $uninstalled = $true
                Start-Sleep -Seconds 3
            }
            catch {
                Write-LevelLog "Direct uninstall failed: $($_.Exception.Message)" -Level "WARN"
            }
        }
    }

    return $uninstalled
}

function Remove-AnyDeskFiles {
    <#
    .SYNOPSIS
        Forcefully removes AnyDesk files and folders.
    .RETURNS
        Number of items removed.
    #>
    $count = 0
    $paths = @(
        "$env:ProgramFiles\AnyDesk",
        "$env:ProgramFiles(x86)\AnyDesk",
        "$env:LOCALAPPDATA\AnyDesk",
        "$env:ProgramData\AnyDesk",
        "$env:APPDATA\AnyDesk",
        "$env:TEMP\AnyDesk*",
        "$env:PUBLIC\Desktop\AnyDesk*.lnk",
        "$env:USERPROFILE\Desktop\AnyDesk*.lnk",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\AnyDesk*.lnk",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\AnyDesk*.lnk"
    )

    foreach ($path in $paths) {
        # Handle wildcard paths
        $items = Get-Item -Path $path -ErrorAction SilentlyContinue
        foreach ($item in $items) {
            try {
                if ($item.PSIsContainer) {
                    Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction Stop
                    Write-LevelLog "Removed folder: $($item.FullName)"
                }
                else {
                    Remove-Item -Path $item.FullName -Force -ErrorAction Stop
                    Write-LevelLog "Removed file: $($item.FullName)"
                }
                $count++
            }
            catch {
                Write-LevelLog "Failed to remove: $($item.FullName) - $($_.Exception.Message)" -Level "WARN"
            }
        }
    }

    # Also check all user profiles
    $userProfiles = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue
    foreach ($profile in $userProfiles) {
        $userPaths = @(
            "$($profile.FullName)\AppData\Local\AnyDesk",
            "$($profile.FullName)\AppData\Roaming\AnyDesk",
            "$($profile.FullName)\Desktop\AnyDesk*.lnk",
            "$($profile.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\AnyDesk*.lnk"
        )
        foreach ($path in $userPaths) {
            $items = Get-Item -Path $path -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                try {
                    if ($item.PSIsContainer) {
                        Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction Stop
                    }
                    else {
                        Remove-Item -Path $item.FullName -Force -ErrorAction Stop
                    }
                    Write-LevelLog "Removed from $($profile.Name): $($item.Name)"
                    $count++
                }
                catch {
                    Write-LevelLog "Failed to remove from $($profile.Name): $($item.Name)" -Level "WARN"
                }
            }
        }
    }

    return $count
}

function Remove-AnyDeskRegistry {
    <#
    .SYNOPSIS
        Removes AnyDesk registry entries.
    .RETURNS
        Number of registry entries removed.
    #>
    $count = 0

    # Uninstall entries
    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    foreach ($regPath in $regPaths) {
        $keys = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue
        foreach ($key in $keys) {
            $props = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
            if ($props.DisplayName -like "*AnyDesk*" -or $props.Publisher -like "*AnyDesk*") {
                try {
                    Remove-Item -Path $key.PSPath -Recurse -Force -ErrorAction Stop
                    Write-LevelLog "Removed registry key: $($key.PSPath)"
                    $count++
                }
                catch {
                    Write-LevelLog "Failed to remove registry key: $($key.PSPath)" -Level "WARN"
                }
            }
        }
    }

    # AnyDesk-specific registry keys
    $anyDeskKeys = @(
        "HKLM:\SOFTWARE\AnyDesk",
        "HKLM:\SOFTWARE\WOW6432Node\AnyDesk",
        "HKCU:\SOFTWARE\AnyDesk",
        "HKLM:\SYSTEM\CurrentControlSet\Services\AnyDesk"
    )

    foreach ($key in $anyDeskKeys) {
        if (Test-Path $key) {
            try {
                Remove-Item -Path $key -Recurse -Force -ErrorAction Stop
                Write-LevelLog "Removed registry key: $key"
                $count++
            }
            catch {
                Write-LevelLog "Failed to remove registry key: $key" -Level "WARN"
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
        $props.PSObject.Properties | Where-Object { $_.Value -like "*AnyDesk*" } | ForEach-Object {
            try {
                Remove-ItemProperty -Path $runKey -Name $_.Name -Force -ErrorAction Stop
                Write-LevelLog "Removed run entry: $($_.Name)"
                $count++
            }
            catch {
                Write-LevelLog "Failed to remove run entry: $($_.Name)" -Level "WARN"
            }
        }
    }

    return $count
}

function Remove-AnyDeskFirewallRules {
    <#
    .SYNOPSIS
        Removes AnyDesk firewall rules.
    .RETURNS
        Number of rules removed.
    #>
    $count = 0
    try {
        $rules = Get-NetFirewallRule -DisplayName "*AnyDesk*" -ErrorAction SilentlyContinue
        foreach ($rule in $rules) {
            Remove-NetFirewallRule -Name $rule.Name -ErrorAction Stop
            Write-LevelLog "Removed firewall rule: $($rule.DisplayName)"
            $count++
        }
    }
    catch {
        Write-LevelLog "Error removing firewall rules: $($_.Exception.Message)" -Level "WARN"
    }
    return $count
}

function Remove-AnyDeskScheduledTasks {
    <#
    .SYNOPSIS
        Removes AnyDesk scheduled tasks.
    .RETURNS
        Number of tasks removed.
    #>
    $count = 0
    try {
        $tasks = Get-ScheduledTask -TaskName "*AnyDesk*" -ErrorAction SilentlyContinue
        foreach ($task in $tasks) {
            Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction Stop
            Write-LevelLog "Removed scheduled task: $($task.TaskName)"
            $count++
        }
    }
    catch {
        Write-LevelLog "Error removing scheduled tasks: $($_.Exception.Message)" -Level "WARN"
    }
    return $count
}

# ============================================================
# MAIN SCRIPT LOGIC
# ============================================================
Invoke-LevelScript -ScriptBlock {

    Write-LevelLog "Starting AnyDesk removal process"

    # Check if admin
    if (-not (Test-LevelAdmin)) {
        Write-LevelLog "This script requires administrator privileges" -Level "ERROR"
        Complete-LevelScript -ExitCode 1 -Message "Admin privileges required"
    }

    # Initial check
    if (-not (Test-AnyDeskInstalled)) {
        Write-LevelLog "AnyDesk is not installed on this system" -Level "SUCCESS"
        Complete-LevelScript -ExitCode 0 -Message "AnyDesk not found - nothing to remove"
    }

    Write-LevelLog "AnyDesk detected - beginning removal phases"

    # --------------------------------------------------------
    # PHASE 1: Standard Uninstall
    # --------------------------------------------------------
    Write-LevelLog "=== PHASE 1: Standard Uninstall ===" -Level "INFO"

    # Stop processes first to allow clean uninstall
    $procsStopped = Stop-AnyDeskProcesses
    if ($procsStopped -gt 0) {
        Write-LevelLog "Stopped $procsStopped AnyDesk process(es)"
        Start-Sleep -Seconds 2
    }

    $uninstallAttempted = Invoke-AnyDeskUninstall
    if ($uninstallAttempted) {
        Start-Sleep -Seconds 5
        if (-not (Test-AnyDeskInstalled)) {
            Write-LevelLog "AnyDesk removed successfully via standard uninstall" -Level "SUCCESS"
            Complete-LevelScript -ExitCode 0 -Message "AnyDesk removed (standard uninstall)"
        }
    }
    else {
        Write-LevelLog "No standard uninstaller found - proceeding with force removal"
    }

    # --------------------------------------------------------
    # PHASE 2: Stop Services and Processes (Force)
    # --------------------------------------------------------
    Write-LevelLog "=== PHASE 2: Force Stop Services & Processes ===" -Level "INFO"

    $svcsStopped = Stop-AnyDeskServices
    $procsStopped = Stop-AnyDeskProcesses

    Write-LevelLog "Stopped $svcsStopped service(s) and $procsStopped process(es)"
    Start-Sleep -Seconds 3

    # --------------------------------------------------------
    # PHASE 3: Remove Files and Folders
    # --------------------------------------------------------
    Write-LevelLog "=== PHASE 3: Remove Files & Folders ===" -Level "INFO"

    $filesRemoved = Remove-AnyDeskFiles
    Write-LevelLog "Removed $filesRemoved file/folder item(s)"

    if (-not (Test-AnyDeskInstalled)) {
        Write-LevelLog "AnyDesk removed successfully via file deletion" -Level "SUCCESS"
        Complete-LevelScript -ExitCode 0 -Message "AnyDesk removed (file deletion)"
    }

    # --------------------------------------------------------
    # PHASE 4: Clean Registry
    # --------------------------------------------------------
    Write-LevelLog "=== PHASE 4: Clean Registry ===" -Level "INFO"

    $regRemoved = Remove-AnyDeskRegistry
    Write-LevelLog "Removed $regRemoved registry item(s)"

    # --------------------------------------------------------
    # PHASE 5: Clean Firewall & Scheduled Tasks
    # --------------------------------------------------------
    Write-LevelLog "=== PHASE 5: Clean Firewall & Scheduled Tasks ===" -Level "INFO"

    $fwRemoved = Remove-AnyDeskFirewallRules
    $tasksRemoved = Remove-AnyDeskScheduledTasks

    Write-LevelLog "Removed $fwRemoved firewall rule(s) and $tasksRemoved scheduled task(s)"

    # --------------------------------------------------------
    # FINAL VERIFICATION
    # --------------------------------------------------------
    Write-LevelLog "=== FINAL VERIFICATION ===" -Level "INFO"

    # Give system time to process all changes
    Start-Sleep -Seconds 3

    if (Test-AnyDeskInstalled) {
        Write-LevelLog "AnyDesk removal incomplete - traces still detected" -Level "ERROR"

        # Report what's still remaining
        $procs = Get-Process -Name "AnyDesk*" -ErrorAction SilentlyContinue
        if ($procs) {
            Write-LevelLog "Remaining processes: $($procs.Name -join ', ')" -Level "WARN"
        }

        $svcs = Get-Service -Name "AnyDesk*" -ErrorAction SilentlyContinue
        if ($svcs) {
            Write-LevelLog "Remaining services: $($svcs.Name -join ', ')" -Level "WARN"
        }

        Complete-LevelScript -ExitCode 1 -Message "AnyDesk removal incomplete"
    }
    else {
        Write-LevelLog "AnyDesk has been completely removed from this system" -Level "SUCCESS"
    }
}
