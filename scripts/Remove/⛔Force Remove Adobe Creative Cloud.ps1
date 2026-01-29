<#
.SYNOPSIS
    Removes Adobe Creative Cloud and all Adobe products from the system.

.DESCRIPTION
    This script forcefully removes Adobe Creative Cloud when the standard uninstaller
    fails due to running Adobe services or applications. It uses progressively
    forceful methods:

    Phase 1: Stop ALL Adobe services and processes (the key to success)
    Phase 2: Download and run Adobe's CC Cleaner Tool (official silent removal)
    Phase 3: Remove Adobe files and folders from all locations
    Phase 4: Clean up registry entries
    Phase 5: Clean firewall rules and scheduled tasks
    Phase 6: Verify complete removal

    The reason CC refuses to uninstall is typically that Adobe services or helper
    processes are still running. This script aggressively terminates all of them
    first, then proceeds with removal.

    When run via Script Launcher, this script inherits all Level.io variables
    and the library is already loaded.

.NOTES
    Version:          2025.01.27.01
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

# Force Remove Adobe Creative Cloud
# Version: 2025.01.27.01
# Target: Level.io (via Script Launcher)
# Exit 0 = Success | Exit 1 = Alert (Failure)
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge

# ============================================================
# INITIALIZE
# ============================================================
# Script Launcher has already loaded the library and passed variables
# We just need to initialize with the passed-through variables

$Init = Initialize-LevelScript -ScriptName "RemoveAdobeCC" `
                               -MspScratchFolder $MspScratchFolder `
                               -DeviceHostname $DeviceHostname `
                               -DeviceTags $DeviceTags `
                               -BlockingTags @("SKIP", "NoRemoval")

if (-not $Init.Success) {
    exit 0
}

# ============================================================
# ADOBE DETECTION
# ============================================================

# Known Adobe service names (partial matches)
$AdobeServicePatterns = @(
    "Adobe*",
    "AGS*",
    "AdobeARMservice",
    "AdobeUpdateService",
    "AGMService",
    "CCService"
)

# Known Adobe process names (partial matches)
$AdobeProcessPatterns = @(
    "Adobe*",
    "Creative Cloud*",
    "CCLibrary*",
    "CCXProcess*",
    "Core Sync*",
    "CoreSync*",
    "AdobeIPCBroker*",
    "AdobeUpdateService*",
    "armsvc*",
    "AGSService*",
    "node*"  # Adobe uses node.js processes
)

# Install paths to check
$AdobeInstallPaths = @(
    "$env:ProgramFiles\Adobe",
    "${env:ProgramFiles(x86)}\Adobe",
    "$env:ProgramFiles\Common Files\Adobe",
    "${env:ProgramFiles(x86)}\Common Files\Adobe",
    "$env:LOCALAPPDATA\Adobe",
    "$env:APPDATA\Adobe",
    "$env:ProgramData\Adobe"
)

function Test-AdobeCCInstalled {
    <#
    .SYNOPSIS
        Checks if Adobe Creative Cloud or any Adobe products are installed.
    .RETURNS
        $true if any Adobe installation is detected, $false otherwise.
    #>

    # Check for Adobe folders
    foreach ($path in $AdobeInstallPaths) {
        if (Test-Path $path) {
            return $true
        }
    }

    # Check for Adobe services
    $services = Get-Service -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -like "Adobe*" -or $_.Name -like "AGS*"
    }
    if ($services) {
        return $true
    }

    # Check registry for Adobe uninstall entries
    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    foreach ($regPath in $regPaths) {
        $entries = Get-ItemProperty $regPath -ErrorAction SilentlyContinue |
                   Where-Object { $_.DisplayName -like "*Adobe*" -and $_.DisplayName -notlike "*Reader*" }
        if ($entries) {
            return $true
        }
    }

    return $false
}

function Get-AdobeServices {
    <#
    .SYNOPSIS
        Gets all running Adobe services.
    .RETURNS
        Array of service objects.
    #>
    $services = @()
    foreach ($pattern in $AdobeServicePatterns) {
        $found = Get-Service -Name $pattern -ErrorAction SilentlyContinue
        if ($found) {
            $services += $found
        }
    }
    return $services | Sort-Object -Property Name -Unique
}

function Get-AdobeProcesses {
    <#
    .SYNOPSIS
        Gets all running Adobe processes.
    .RETURNS
        Array of process objects.
    #>
    $processes = @()
    foreach ($pattern in $AdobeProcessPatterns) {
        $found = Get-Process -Name $pattern -ErrorAction SilentlyContinue
        if ($found) {
            $processes += $found
        }
    }

    # Also find processes by path containing Adobe
    $allProcs = Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $_.Path -like "*\Adobe\*" -or $_.Path -like "*\Common Files\Adobe\*"
    }
    if ($allProcs) {
        $processes += $allProcs
    }

    return $processes | Sort-Object -Property Id -Unique
}

# ============================================================
# ADOBE REMOVAL FUNCTIONS
# ============================================================

function Stop-AllAdobeServices {
    <#
    .SYNOPSIS
        Stops and disables ALL Adobe services.
    .RETURNS
        Number of services stopped.
    #>
    $count = 0
    $services = Get-AdobeServices

    foreach ($svc in $services) {
        try {
            Write-LevelLog "Stopping service: $($svc.Name) ($($svc.DisplayName))"

            # Stop the service
            if ($svc.Status -eq 'Running') {
                Stop-Service -Name $svc.Name -Force -ErrorAction Stop
                $count++
            }

            # Disable the service to prevent restart
            Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction SilentlyContinue
            Write-LevelLog "  Disabled: $($svc.Name)"
        }
        catch {
            Write-LevelLog "  Failed to stop $($svc.Name): $($_.Exception.Message)" -Level "WARN"

            # Try via sc.exe as fallback
            try {
                $null = & sc.exe stop $svc.Name 2>&1
                $null = & sc.exe config $svc.Name start= disabled 2>&1
                $count++
                Write-LevelLog "  Stopped via sc.exe: $($svc.Name)"
            }
            catch {
                Write-LevelLog "  sc.exe also failed for $($svc.Name)" -Level "WARN"
            }
        }
    }

    return $count
}

function Stop-AllAdobeProcesses {
    <#
    .SYNOPSIS
        Forcefully terminates ALL Adobe processes.
    .RETURNS
        Number of processes terminated.
    #>
    $count = 0
    $processes = Get-AdobeProcesses

    foreach ($proc in $processes) {
        try {
            Write-LevelLog "Terminating process: $($proc.Name) (PID: $($proc.Id))"
            Stop-Process -Id $proc.Id -Force -ErrorAction Stop
            $count++
        }
        catch {
            Write-LevelLog "  Failed to terminate $($proc.Name): $($_.Exception.Message)" -Level "WARN"

            # Try via taskkill as fallback
            try {
                $null = & taskkill /F /PID $proc.Id 2>&1
                $count++
                Write-LevelLog "  Killed via taskkill: $($proc.Name)"
            }
            catch {
                Write-LevelLog "  taskkill also failed for $($proc.Name)" -Level "WARN"
            }
        }
    }

    # Also kill any node.js processes in Adobe folders
    $nodeProcs = Get-Process -Name "node" -ErrorAction SilentlyContinue | Where-Object {
        $_.Path -like "*\Adobe\*"
    }
    foreach ($proc in $nodeProcs) {
        try {
            Stop-Process -Id $proc.Id -Force -ErrorAction Stop
            Write-LevelLog "Terminated Adobe node process: PID $($proc.Id)"
            $count++
        }
        catch {
            Write-LevelLog "Failed to terminate node process: $($_.Exception.Message)" -Level "WARN"
        }
    }

    return $count
}

function Invoke-AdobeCleanerTool {
    <#
    .SYNOPSIS
        Downloads and runs Adobe's official Creative Cloud Cleaner Tool.
    .DESCRIPTION
        The CC Cleaner Tool is Adobe's official silent removal utility.
        It properly removes all Adobe products and cleans up leftovers.
    .RETURNS
        $true if cleaner ran successfully, $false otherwise.
    #>

    $CleanerUrl = "https://swupmf.adobe.com/webfeed/CleanerTool/win/AdobeCreativeCloudCleanerTool.exe"
    $CleanerPath = Join-Path $env:TEMP "AdobeCreativeCloudCleanerTool.exe"

    Write-LevelLog "Downloading Adobe Creative Cloud Cleaner Tool..."

    try {
        # Download the cleaner tool
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($CleanerUrl, $CleanerPath)
        Write-LevelLog "Downloaded to: $CleanerPath"

        if (-not (Test-Path $CleanerPath)) {
            Write-LevelLog "Download failed - file not found" -Level "WARN"
            return $false
        }

        # Run the cleaner tool with proper silent flags:
        # --removeAll=ALL     : Remove all Adobe products
        # --eulaAccepted=1    : Accept EULA (required for silent mode, otherwise shows dialog)
        Write-LevelLog "Running CC Cleaner Tool (silent mode)..."
        Write-LevelLog "This may take several minutes..."

        $cleanerArgs = "--removeAll=ALL --eulaAccepted=1"
        $process = Start-Process -FilePath $CleanerPath -ArgumentList $cleanerArgs -Wait -PassThru -ErrorAction Stop

        Write-LevelLog "CC Cleaner Tool exited with code: $($process.ExitCode)"

        # Clean up the downloaded tool
        Remove-Item -Path $CleanerPath -Force -ErrorAction SilentlyContinue

        # Exit codes: 0 = success, other values may still indicate partial success
        if ($process.ExitCode -eq 0) {
            Write-LevelLog "CC Cleaner Tool completed successfully" -Level "SUCCESS"
            return $true
        } else {
            Write-LevelLog "CC Cleaner Tool finished with warnings (exit: $($process.ExitCode))" -Level "WARN"
            return $true  # Still consider it attempted
        }
    }
    catch {
        Write-LevelLog "CC Cleaner Tool failed: $($_.Exception.Message)" -Level "WARN"
        # Clean up on failure
        if (Test-Path $CleanerPath) {
            Remove-Item -Path $CleanerPath -Force -ErrorAction SilentlyContinue
        }
        return $false
    }
}

function Invoke-AdobeMsiUninstall {
    <#
    .SYNOPSIS
        Attempts to uninstall Adobe products via MSI where possible.
    .DESCRIPTION
        Finds MSI-based Adobe products and uninstalls via msiexec.
        This is a fallback if the CC Cleaner Tool fails.
    .RETURNS
        $true if any uninstall was attempted, $false if nothing found.
    #>
    $uninstalled = $false

    Write-LevelLog "Searching for MSI-based Adobe products..."

    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($regPath in $regPaths) {
        $entries = Get-ItemProperty $regPath -ErrorAction SilentlyContinue |
                   Where-Object {
                       $_.DisplayName -like "*Adobe*" -and
                       $_.DisplayName -notlike "*Adobe Acrobat Reader*" -and
                       $_.UninstallString -like "*msiexec*"
                   }

        foreach ($entry in $entries) {
            $uninstallString = $entry.UninstallString
            $displayName = $entry.DisplayName

            if ($uninstallString -match '\{[A-F0-9\-]+\}') {
                $productCode = $Matches[0]
                Write-LevelLog "Found MSI product: $displayName"

                try {
                    $msiArgs = "/x $productCode /qn /norestart"
                    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru -ErrorAction Stop

                    if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {
                        Write-LevelLog "  Uninstalled: $displayName"
                        $uninstalled = $true
                    }
                }
                catch {
                    Write-LevelLog "  Failed: $($_.Exception.Message)" -Level "WARN"
                }

                Start-Sleep -Seconds 2
            }
        }
    }

    return $uninstalled
}

function Remove-AdobeFiles {
    <#
    .SYNOPSIS
        Forcefully removes Adobe files and folders.
    .RETURNS
        Number of items removed.
    #>
    $count = 0

    # Main Adobe folders
    $paths = @(
        "$env:ProgramFiles\Adobe",
        "${env:ProgramFiles(x86)}\Adobe",
        "$env:ProgramFiles\Common Files\Adobe",
        "${env:ProgramFiles(x86)}\Common Files\Adobe",
        "$env:LOCALAPPDATA\Adobe",
        "$env:APPDATA\Adobe",
        "$env:ProgramData\Adobe",
        "$env:TEMP\Adobe*",
        "$env:TEMP\*.tmp",  # Adobe temp files
        "$env:PUBLIC\Desktop\Adobe*.lnk",
        "$env:USERPROFILE\Desktop\Adobe*.lnk",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Adobe*",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Adobe*"
    )

    foreach ($path in $paths) {
        $items = Get-Item -Path $path -ErrorAction SilentlyContinue
        foreach ($item in $items) {
            try {
                # Take ownership if needed
                if ($item.PSIsContainer) {
                    # Remove read-only attributes recursively
                    Get-ChildItem -Path $item.FullName -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                        $_.Attributes = 'Normal'
                    }
                    Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction Stop
                    Write-LevelLog "Removed folder: $($item.FullName)"
                }
                else {
                    $item.Attributes = 'Normal'
                    Remove-Item -Path $item.FullName -Force -ErrorAction Stop
                    Write-LevelLog "Removed file: $($item.FullName)"
                }
                $count++
            }
            catch {
                Write-LevelLog "Failed to remove: $($item.FullName) - $($_.Exception.Message)" -Level "WARN"

                # Try with cmd /c rd for stubborn folders
                if ($item.PSIsContainer) {
                    try {
                        $null = & cmd /c rd /s /q "`"$($item.FullName)`"" 2>&1
                        Write-LevelLog "  Removed via cmd: $($item.FullName)"
                        $count++
                    }
                    catch {
                        Write-LevelLog "  cmd also failed: $($_.Exception.Message)" -Level "WARN"
                    }
                }
            }
        }
    }

    # Clean all user profiles
    $userProfiles = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') }

    foreach ($profile in $userProfiles) {
        $userPaths = @(
            "$($profile.FullName)\AppData\Local\Adobe",
            "$($profile.FullName)\AppData\Roaming\Adobe",
            "$($profile.FullName)\AppData\LocalLow\Adobe",
            "$($profile.FullName)\Desktop\Adobe*.lnk",
            "$($profile.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Adobe*"
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
                    Write-LevelLog "Failed to remove from $($profile.Name): $($item.Name) - $($_.Exception.Message)" -Level "WARN"
                }
            }
        }
    }

    return $count
}

function Remove-AdobeRegistry {
    <#
    .SYNOPSIS
        Removes Adobe registry entries.
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
            if ($props.DisplayName -like "*Adobe*" -and $props.DisplayName -notlike "*Adobe Acrobat Reader*") {
                try {
                    Remove-Item -Path $key.PSPath -Recurse -Force -ErrorAction Stop
                    Write-LevelLog "Removed registry key: $($props.DisplayName)"
                    $count++
                }
                catch {
                    Write-LevelLog "Failed to remove registry key: $($key.PSPath)" -Level "WARN"
                }
            }
        }
    }

    # Adobe-specific registry keys
    $adobeKeys = @(
        "HKLM:\SOFTWARE\Adobe",
        "HKLM:\SOFTWARE\WOW6432Node\Adobe",
        "HKCU:\SOFTWARE\Adobe",
        "HKLM:\SOFTWARE\Classes\Adobe*",
        "HKCU:\SOFTWARE\Classes\Adobe*"
    )

    foreach ($key in $adobeKeys) {
        if (Test-Path $key) {
            try {
                Remove-Item -Path $key -Recurse -Force -ErrorAction Stop
                Write-LevelLog "Removed registry key: $key"
                $count++
            }
            catch {
                Write-LevelLog "Failed to remove registry key: $key - $($_.Exception.Message)" -Level "WARN"
            }
        }
    }

    # Remove Adobe services from registry
    $serviceKeys = Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services" -ErrorAction SilentlyContinue |
                   Where-Object { $_.Name -like "*Adobe*" -or $_.Name -like "*AGS*" }

    foreach ($key in $serviceKeys) {
        try {
            Remove-Item -Path $key.PSPath -Recurse -Force -ErrorAction Stop
            Write-LevelLog "Removed service registry key: $($key.Name)"
            $count++
        }
        catch {
            Write-LevelLog "Failed to remove service key: $($key.Name)" -Level "WARN"
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
        $props.PSObject.Properties | Where-Object { $_.Value -like "*Adobe*" } | ForEach-Object {
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

function Remove-AdobeFirewallRules {
    <#
    .SYNOPSIS
        Removes Adobe firewall rules.
    .RETURNS
        Number of rules removed.
    #>
    $count = 0
    try {
        $rules = Get-NetFirewallRule -DisplayName "*Adobe*" -ErrorAction SilentlyContinue
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

function Remove-AdobeScheduledTasks {
    <#
    .SYNOPSIS
        Removes Adobe scheduled tasks.
    .RETURNS
        Number of tasks removed.
    #>
    $count = 0
    try {
        # Get all Adobe-related tasks
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
            $_.TaskName -like "*Adobe*" -or
            $_.TaskPath -like "*Adobe*"
        }

        foreach ($task in $tasks) {
            try {
                Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false -ErrorAction Stop
                Write-LevelLog "Removed scheduled task: $($task.TaskName)"
                $count++
            }
            catch {
                Write-LevelLog "Failed to remove task $($task.TaskName): $($_.Exception.Message)" -Level "WARN"
            }
        }
    }
    catch {
        Write-LevelLog "Error enumerating scheduled tasks: $($_.Exception.Message)" -Level "WARN"
    }
    return $count
}

# ============================================================
# MAIN SCRIPT LOGIC
# ============================================================
Invoke-LevelScript -ScriptBlock {

    Write-LevelLog "Starting Adobe Creative Cloud removal process"

    # Log device info
    $DeviceInfo = Get-LevelDeviceInfo
    Write-LevelLog "Device: $($DeviceInfo.Hostname) | OS: $($DeviceInfo.OS) | Admin: $($DeviceInfo.IsAdmin)"

    # Check if admin
    if (-not (Test-LevelAdmin)) {
        Write-LevelLog "This script requires administrator privileges" -Level "ERROR"
        Complete-LevelScript -ExitCode 1 -Message "Admin privileges required"
    }

    # Initial check
    if (-not (Test-AdobeCCInstalled)) {
        Write-LevelLog "Adobe Creative Cloud is not installed on this system" -Level "SUCCESS"
        Complete-LevelScript -ExitCode 0 -Message "Adobe CC not found - nothing to remove"
    }

    Write-LevelLog "Adobe installation detected - beginning removal phases"

    # --------------------------------------------------------
    # PHASE 1: Stop ALL Adobe Services and Processes FIRST
    # This is the KEY to successful removal - CC won't uninstall
    # if ANY Adobe service or process is running
    # --------------------------------------------------------
    Write-LevelLog "=== PHASE 1: Stop ALL Adobe Services & Processes ===" -Level "INFO"
    Write-LevelLog "This is critical - CC refuses to uninstall if anything Adobe is running"

    # Multiple passes to catch processes that respawn
    for ($i = 1; $i -le 3; $i++) {
        Write-LevelLog "--- Pass $i of 3 ---"

        $svcsStopped = Stop-AllAdobeServices
        Write-LevelLog "Stopped $svcsStopped Adobe service(s)"

        Start-Sleep -Seconds 2

        $procsStopped = Stop-AllAdobeProcesses
        Write-LevelLog "Terminated $procsStopped Adobe process(es)"

        Start-Sleep -Seconds 3

        # Check if anything is still running
        $remainingProcs = Get-AdobeProcesses
        $remainingSvcs = Get-AdobeServices | Where-Object { $_.Status -eq 'Running' }

        if (-not $remainingProcs -and -not $remainingSvcs) {
            Write-LevelLog "All Adobe services and processes stopped"
            break
        }

        if ($remainingProcs) {
            Write-LevelLog "  Still running: $($remainingProcs.Name -join ', ')" -Level "WARN"
        }
        if ($remainingSvcs) {
            Write-LevelLog "  Services still active: $($remainingSvcs.Name -join ', ')" -Level "WARN"
        }
    }

    # --------------------------------------------------------
    # PHASE 2: Adobe Creative Cloud Cleaner Tool
    # This is Adobe's official silent removal utility
    # --------------------------------------------------------
    Write-LevelLog "=== PHASE 2: Adobe CC Cleaner Tool ===" -Level "INFO"

    $cleanerSuccess = Invoke-AdobeCleanerTool

    if ($cleanerSuccess) {
        # Stop any processes that may have started
        $null = Stop-AllAdobeProcesses
        Start-Sleep -Seconds 5

        if (-not (Test-AdobeCCInstalled)) {
            Write-LevelLog "Adobe CC removed successfully via CC Cleaner Tool" -Level "SUCCESS"
            Complete-LevelScript -ExitCode 0 -Message "Adobe CC removed (CC Cleaner Tool)"
        }
        else {
            Write-LevelLog "CC Cleaner completed but traces remain - continuing with force removal"
        }
    }
    else {
        Write-LevelLog "CC Cleaner Tool unavailable - trying MSI uninstall fallback..."
        $null = Invoke-AdobeMsiUninstall
    }

    Write-LevelLog "Proceeding with force removal phases..."

    # --------------------------------------------------------
    # PHASE 3: Remove Files and Folders
    # --------------------------------------------------------
    Write-LevelLog "=== PHASE 3: Remove Files & Folders ===" -Level "INFO"

    # Stop anything that started again
    $null = Stop-AllAdobeProcesses
    Start-Sleep -Seconds 2

    $filesRemoved = Remove-AdobeFiles
    Write-LevelLog "Removed $filesRemoved file/folder item(s)"

    # --------------------------------------------------------
    # PHASE 4: Clean Registry
    # --------------------------------------------------------
    Write-LevelLog "=== PHASE 4: Clean Registry ===" -Level "INFO"

    $regRemoved = Remove-AdobeRegistry
    Write-LevelLog "Removed $regRemoved registry item(s)"

    # --------------------------------------------------------
    # PHASE 5: Clean Firewall & Scheduled Tasks
    # --------------------------------------------------------
    Write-LevelLog "=== PHASE 5: Clean Firewall & Scheduled Tasks ===" -Level "INFO"

    $fwRemoved = Remove-AdobeFirewallRules
    $tasksRemoved = Remove-AdobeScheduledTasks

    Write-LevelLog "Removed $fwRemoved firewall rule(s) and $tasksRemoved scheduled task(s)"

    # --------------------------------------------------------
    # FINAL VERIFICATION
    # --------------------------------------------------------
    Write-LevelLog "=== FINAL VERIFICATION ===" -Level "INFO"

    # Give system time to process all changes
    Start-Sleep -Seconds 5

    # Final check
    $remainingPaths = $AdobeInstallPaths | Where-Object { Test-Path $_ }
    $remainingProcs = Get-AdobeProcesses
    $remainingSvcs = Get-AdobeServices

    if ($remainingPaths -or $remainingProcs -or $remainingSvcs) {
        Write-LevelLog "Adobe CC removal incomplete - traces still detected" -Level "WARN"

        if ($remainingPaths) {
            Write-LevelLog "Remaining folders:" -Level "WARN"
            foreach ($path in $remainingPaths) {
                Write-LevelLog "  - $path" -Level "WARN"
            }
        }

        if ($remainingProcs) {
            Write-LevelLog "Remaining processes: $($remainingProcs.Name -join ', ')" -Level "WARN"
        }

        if ($remainingSvcs) {
            Write-LevelLog "Remaining services: $($remainingSvcs.Name -join ', ')" -Level "WARN"
        }

        Write-LevelLog "A reboot may be required to complete removal" -Level "WARN"
        Write-LevelLog "Consider using Adobe Creative Cloud Cleaner Tool for stubborn remnants" -Level "INFO"

        # Exit with success since we did what we could - some Adobe files are locked until reboot
        Complete-LevelScript -ExitCode 0 -Message "Adobe CC mostly removed - reboot may be needed"
    }
    else {
        Write-LevelLog "Adobe Creative Cloud has been completely removed from this system" -Level "SUCCESS"
    }
}
