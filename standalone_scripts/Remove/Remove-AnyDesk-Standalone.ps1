<#
.SYNOPSIS
    Standalone script to remove AnyDesk remote access software from the system.

.DESCRIPTION
    This script attempts to remove AnyDesk using progressively forceful methods:
    Phase 1: Standard uninstall via registry uninstall strings
    Phase 2: Stop AnyDesk services and processes
    Phase 3: Remove AnyDesk files and folders
    Phase 4: Clean up registry entries
    Phase 5: Verify complete removal

    STANDALONE VERSION - No COOLForge library required.

.NOTES
    Version:          2025.01.07.01 (Standalone)
    Exit Codes:       0 = Success | 1 = Alert (Failure)
    Requires:         Administrator privileges

    License:          MIT License with Attribution
    Copyright (c) 2025 COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge

.EXAMPLE
    .\Remove-AnyDesk-Standalone.ps1
#>

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

function Test-AnyDeskInstalled {
    # Check for AnyDesk processes
    $processes = Get-Process -Name "AnyDesk*" -ErrorAction SilentlyContinue
    if ($processes) { return $true }

    # Check for AnyDesk services
    $services = Get-Service -Name "AnyDesk*" -ErrorAction SilentlyContinue
    if ($services) { return $true }

    # Check common installation paths
    $paths = @(
        "$env:ProgramFiles\AnyDesk",
        "${env:ProgramFiles(x86)}\AnyDesk",
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
    $count = 0
    $processes = Get-Process -Name "AnyDesk*" -ErrorAction SilentlyContinue
    foreach ($proc in $processes) {
        try {
            Stop-Process -Id $proc.Id -Force -ErrorAction Stop
            $count++
            Write-Log "Stopped process: $($proc.Name) (PID: $($proc.Id))"
        }
        catch {
            Write-Log "Failed to stop process: $($proc.Name) - $($_.Exception.Message)" -Level "WARN"
        }
    }
    return $count
}

function Stop-AnyDeskServices {
    $count = 0
    $services = Get-Service -Name "AnyDesk*" -ErrorAction SilentlyContinue
    foreach ($svc in $services) {
        try {
            if ($svc.Status -eq 'Running') {
                Stop-Service -Name $svc.Name -Force -ErrorAction Stop
                Write-Log "Stopped service: $($svc.Name)"
            }
            Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction Stop
            Write-Log "Disabled service: $($svc.Name)"
            $count++
        }
        catch {
            Write-Log "Failed to stop/disable service: $($svc.Name) - $($_.Exception.Message)" -Level "WARN"
        }
    }
    return $count
}

function Invoke-AnyDeskUninstall {
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
                Write-Log "Found uninstaller: $uninstallString"

                if ($uninstallString -match '^"(.+)"(.*)$') {
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

                if ($uninstallArgs -notmatch '/S|--silent|--remove') {
                    $uninstallArgs = "$uninstallArgs --remove --silent"
                }

                try {
                    Write-Log "Executing: $exe $uninstallArgs"
                    $process = Start-Process -FilePath $exe -ArgumentList $uninstallArgs -Wait -PassThru -ErrorAction Stop
                    Write-Log "Uninstaller exited with code: $($process.ExitCode)"
                    $uninstalled = $true
                    Start-Sleep -Seconds 3
                }
                catch {
                    Write-Log "Uninstall failed: $($_.Exception.Message)" -Level "WARN"
                }
            }
        }
    }

    # Try AnyDesk's own uninstall command if executable exists
    $anyDeskPaths = @(
        "$env:ProgramFiles\AnyDesk\AnyDesk.exe",
        "${env:ProgramFiles(x86)}\AnyDesk\AnyDesk.exe",
        "$env:LOCALAPPDATA\AnyDesk\AnyDesk.exe"
    )

    foreach ($adPath in $anyDeskPaths) {
        if (Test-Path $adPath) {
            try {
                Write-Log "Trying direct uninstall: $adPath --remove --silent"
                $process = Start-Process -FilePath $adPath -ArgumentList "--remove --silent" -Wait -PassThru -ErrorAction Stop
                Write-Log "Direct uninstall exited with code: $($process.ExitCode)"
                $uninstalled = $true
                Start-Sleep -Seconds 3
            }
            catch {
                Write-Log "Direct uninstall failed: $($_.Exception.Message)" -Level "WARN"
            }
        }
    }

    return $uninstalled
}

function Remove-AnyDeskFiles {
    $count = 0
    $paths = @(
        "$env:ProgramFiles\AnyDesk",
        "${env:ProgramFiles(x86)}\AnyDesk",
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
        $items = Get-Item -Path $path -ErrorAction SilentlyContinue
        foreach ($item in $items) {
            try {
                if ($item.PSIsContainer) {
                    Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction Stop
                    Write-Log "Removed folder: $($item.FullName)"
                }
                else {
                    Remove-Item -Path $item.FullName -Force -ErrorAction Stop
                    Write-Log "Removed file: $($item.FullName)"
                }
                $count++
            }
            catch {
                Write-Log "Failed to remove: $($item.FullName) - $($_.Exception.Message)" -Level "WARN"
            }
        }
    }

    # Also check all user profiles
    $userProfiles = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue
    foreach ($userProfile in $userProfiles) {
        $userPaths = @(
            "$($userProfile.FullName)\AppData\Local\AnyDesk",
            "$($userProfile.FullName)\AppData\Roaming\AnyDesk",
            "$($userProfile.FullName)\Desktop\AnyDesk*.lnk",
            "$($userProfile.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\AnyDesk*.lnk"
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
                    Write-Log "Removed from $($profile.Name): $($item.Name)"
                    $count++
                }
                catch {
                    Write-Log "Failed to remove from $($profile.Name): $($item.Name)" -Level "WARN"
                }
            }
        }
    }

    return $count
}

function Remove-AnyDeskRegistry {
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
                    Write-Log "Removed registry key: $($key.PSPath)"
                    $count++
                }
                catch {
                    Write-Log "Failed to remove registry key: $($key.PSPath)" -Level "WARN"
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
                Write-Log "Removed registry key: $key"
                $count++
            }
            catch {
                Write-Log "Failed to remove registry key: $key" -Level "WARN"
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
                Write-Log "Removed run entry: $($_.Name)"
                $count++
            }
            catch {
                Write-Log "Failed to remove run entry: $($_.Name)" -Level "WARN"
            }
        }
    }

    return $count
}

function Remove-AnyDeskFirewallRules {
    $count = 0
    try {
        $rules = Get-NetFirewallRule -DisplayName "*AnyDesk*" -ErrorAction SilentlyContinue
        foreach ($rule in $rules) {
            Remove-NetFirewallRule -Name $rule.Name -ErrorAction Stop
            Write-Log "Removed firewall rule: $($rule.DisplayName)"
            $count++
        }
    }
    catch {
        Write-Log "Error removing firewall rules: $($_.Exception.Message)" -Level "WARN"
    }
    return $count
}

function Remove-AnyDeskScheduledTasks {
    $count = 0
    try {
        $tasks = Get-ScheduledTask -TaskName "*AnyDesk*" -ErrorAction SilentlyContinue
        foreach ($task in $tasks) {
            Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction Stop
            Write-Log "Removed scheduled task: $($task.TaskName)"
            $count++
        }
    }
    catch {
        Write-Log "Error removing scheduled tasks: $($_.Exception.Message)" -Level "WARN"
    }
    return $count
}
#endregion Embedded Functions

#region Main Execution
Write-Host ""
Write-Host "============================================================"
Write-Host "  AnyDesk Removal Script (Standalone)"
Write-Host "============================================================"
Write-Host ""

$ErrorActionPreference = "SilentlyContinue"

# Check for Administrator privileges
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Log "This script requires Administrator privileges" -Level "ERROR"
    exit 1
}

Write-Log "Starting AnyDesk removal process"
Write-Log "Device: $env:COMPUTERNAME"

# Initial check
if (-not (Test-AnyDeskInstalled)) {
    Write-Log "AnyDesk is not installed on this system" -Level "SUCCESS"
    exit 0
}

Write-Log "AnyDesk detected - beginning removal phases"

# PHASE 1: Standard Uninstall
Write-Log "=== PHASE 1: Standard Uninstall ===" -Level "INFO"

$procsStopped = Stop-AnyDeskProcesses
if ($procsStopped -gt 0) {
    Write-Log "Stopped $procsStopped AnyDesk process(es)"
    Start-Sleep -Seconds 2
}

$uninstallAttempted = Invoke-AnyDeskUninstall
if ($uninstallAttempted) {
    Start-Sleep -Seconds 5
    if (-not (Test-AnyDeskInstalled)) {
        Write-Log "AnyDesk removed successfully via standard uninstall" -Level "SUCCESS"
        exit 0
    }
}
else {
    Write-Log "No standard uninstaller found - proceeding with force removal"
}

# PHASE 2: Stop Services and Processes (Force)
Write-Log "=== PHASE 2: Force Stop Services & Processes ===" -Level "INFO"

$svcsStopped = Stop-AnyDeskServices
$procsStopped = Stop-AnyDeskProcesses

Write-Log "Stopped $svcsStopped service(s) and $procsStopped process(es)"
Start-Sleep -Seconds 3

# PHASE 3: Remove Files and Folders
Write-Log "=== PHASE 3: Remove Files & Folders ===" -Level "INFO"

$filesRemoved = Remove-AnyDeskFiles
Write-Log "Removed $filesRemoved file/folder item(s)"

if (-not (Test-AnyDeskInstalled)) {
    Write-Log "AnyDesk removed successfully via file deletion" -Level "SUCCESS"
    exit 0
}

# PHASE 4: Clean Registry
Write-Log "=== PHASE 4: Clean Registry ===" -Level "INFO"

$regRemoved = Remove-AnyDeskRegistry
Write-Log "Removed $regRemoved registry item(s)"

# PHASE 5: Clean Firewall & Scheduled Tasks
Write-Log "=== PHASE 5: Clean Firewall & Scheduled Tasks ===" -Level "INFO"

$fwRemoved = Remove-AnyDeskFirewallRules
$tasksRemoved = Remove-AnyDeskScheduledTasks

Write-Log "Removed $fwRemoved firewall rule(s) and $tasksRemoved scheduled task(s)"

# FINAL VERIFICATION
Write-Log "=== FINAL VERIFICATION ===" -Level "INFO"

Start-Sleep -Seconds 3

if (Test-AnyDeskInstalled) {
    Write-Log "AnyDesk removal incomplete - traces still detected" -Level "ERROR"

    $procs = Get-Process -Name "AnyDesk*" -ErrorAction SilentlyContinue
    if ($procs) {
        Write-Log "Remaining processes: $($procs.Name -join ', ')" -Level "WARN"
    }

    $svcs = Get-Service -Name "AnyDesk*" -ErrorAction SilentlyContinue
    if ($svcs) {
        Write-Log "Remaining services: $($svcs.Name -join ', ')" -Level "WARN"
    }

    exit 1
}
else {
    Write-Log "AnyDesk has been completely removed from this system" -Level "SUCCESS"
    exit 0
}
#endregion Main Execution
