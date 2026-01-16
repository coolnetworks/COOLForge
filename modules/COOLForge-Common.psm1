<#
.SYNOPSIS
    COOLForge-Common - Shared PowerShell module for Level.io automation scripts.

.DESCRIPTION
    This module provides a standardized set of functions for Level.io RMM automation scripts:
    - Tag gate system for device filtering
    - Lockfile management to prevent concurrent execution
    - Standardized logging with severity levels
    - Automatic error handling and cleanup
    - REST API helper with bearer token authentication
    - Device information utilities

.NOTES
    Version:    2026.01.13.10
    Target:     Level.io RMM
    Location:   {{cf_coolforge_msp_scratch_folder}}\Libraries\COOLForge-Common.psm1

    Level.io Custom Fields:
    - {{cf_coolforge_msp_scratch_folder}}       : (Required) Persistent storage folder (e.g., C:\ProgramData\MSP)
    - {{cf_coolforge_ps_module_library_source}} : (Optional) URL to download this module - defaults to official repo

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge

.EXAMPLE
    # Import and use the module
    Import-Module "C:\ProgramData\MSP\Libraries\COOLForge-Common.psm1" -Force

    $Init = Initialize-LevelScript -ScriptName "MyScript" -MspScratchFolder "C:\ProgramData\MSP"
    if ($Init.Success) {
        Invoke-LevelScript -ScriptBlock {
            Write-LevelLog "Hello from MyScript!"
        }
    }
#>

# ============================================================
# MODULE VARIABLES
# These are set via Initialize-LevelScript and used throughout
# ============================================================
$script:ScriptName = $null          # Unique identifier for the script
$script:LockFilePath = $null        # Directory containing lockfiles
$script:LockFile = $null            # Full path to this script's lockfile
$script:DeviceHostname = $null      # Device hostname for logging
$script:Initialized = $false        # Flag to ensure initialization

# ============================================================
# INITIALIZATION
# ============================================================

<#
.SYNOPSIS
    Initializes the script environment with tag gate and lockfile management.

.DESCRIPTION
    Must be called before using other library functions. Performs:
    1. Sets up module variables for the script session
    2. Checks device tags against blocking tags (tag gate)
    3. Creates a lockfile to prevent concurrent execution
    4. Handles stale lockfiles from crashed previous runs

.PARAMETER ScriptName
    Unique identifier for the script. Used for lockfile naming.
    Example: "CleanupTempFiles", "WindowsUpdate-Weekly"

.PARAMETER MspScratchFolder
    Base path for MSP files. Typically "{{cf_coolforge_msp_scratch_folder}}".
    Lockfiles are stored in: $MspScratchFolder\lockfiles\

.PARAMETER DeviceHostname
    Device hostname for logging. Defaults to $env:COMPUTERNAME.
    Typically "{{level_device_hostname}}" in Level.io scripts.

.PARAMETER DeviceTags
    Comma-separated list of device tags. Typically "{{level_tag_names}}".
    Used for tag gate checking.

.PARAMETER BlockingTags
    Array of tags that block script execution. Default: @() (empty - set your own)
    If any blocking tag is present in DeviceTags, script exits gracefully.

.PARAMETER SkipTagCheck
    Switch to bypass tag gate checking. Use cautiously.

.PARAMETER SkipLockFile
    Switch to skip lockfile creation. Use for scripts that can run concurrently.

.OUTPUTS
    Hashtable with Success, Reason, and additional properties:
    - Success: @{ Success = $true; Reason = "Initialized" }
    - Tag blocked: @{ Success = $false; Reason = "TagBlocked"; Tag = "BlockedTag" }
    - Already running: @{ Success = $false; Reason = "AlreadyRunning"; PID = 1234 }

.EXAMPLE
    $Init = Initialize-LevelScript -ScriptName "MyScript" `
                                   -MspScratchFolder "{{cf_coolforge_msp_scratch_folder}}" `
                                   -DeviceHostname "{{level_device_hostname}}" `
                                   -DeviceTags "{{level_tag_names}}"
    if (-not $Init.Success) { exit 0 }

.EXAMPLE
    # Multiple blocking tags
    $Init = Initialize-LevelScript -ScriptName "Maintenance" `
                                   -MspScratchFolder $MspFolder `
                                   -BlockingTags @("NoScript", "Maintenance", "SKIP")

.EXAMPLE
    # Skip all checks (use cautiously)
    $Init = Initialize-LevelScript -ScriptName "QuickCheck" `
                                   -MspScratchFolder $MspFolder `
                                   -SkipTagCheck -SkipLockFile
#>
function Initialize-LevelScript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptName,

        [Parameter(Mandatory = $true)]
        [string]$MspScratchFolder,

        [Parameter(Mandatory = $false)]
        [string]$DeviceHostname = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false)]
        [string]$DeviceTags = "",

        [Parameter(Mandatory = $false)]
        [string[]]$BlockingTags = @(),

        [Parameter(Mandatory = $false)]
        [switch]$SkipTagCheck,

        [Parameter(Mandatory = $false)]
        [switch]$SkipLockFile
    )

    # Set module variables
    $script:ScriptName = $ScriptName
    $script:DeviceHostname = $DeviceHostname
    $script:ScratchFolder = $MspScratchFolder
    $script:LockFilePath = Join-Path -Path $MspScratchFolder -ChildPath "lockfiles"
    $script:LockFile = Join-Path -Path $script:LockFilePath -ChildPath "$ScriptName.lock"

    Write-LevelLog "Initializing: $ScriptName on $DeviceHostname"

    # --- Tag Gate Check ---
    # If device has a blocking tag, exit gracefully without running
    if (-not $SkipTagCheck -and $DeviceTags) {
        $TagArray = $DeviceTags -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        foreach ($BlockTag in $BlockingTags) {
            if ($TagArray -contains $BlockTag) {
                Write-LevelLog "Tag '$BlockTag' is SET - script blocked" -Level "SKIP"
                Write-LevelLog "This device has the '$BlockTag' tag - all scripts using this blocking tag will skip this host" -Level "SKIP"
                return @{ Success = $false; Reason = "TagBlocked"; Tag = $BlockTag }
            }
        }
    }

    # --- Lockfile Setup ---
    # Prevents multiple instances of the same script running simultaneously
    if (-not $SkipLockFile) {
        # Ensure lockfile directory exists
        if (!(Test-Path $script:LockFilePath)) {
            New-Item -Path $script:LockFilePath -ItemType Directory -Force | Out-Null
        }

        # Check for existing lock
        if (Test-Path $script:LockFile) {
            $LockContent = Get-Content -Path $script:LockFile -Raw -ErrorAction SilentlyContinue |
                           ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($LockContent.PID) {
                # Check if the process is still running
                $ExistingProcess = Get-Process -Id $LockContent.PID -ErrorAction SilentlyContinue
                if ($ExistingProcess) {
                    Write-LevelLog "Already running (PID: $($LockContent.PID))" -Level "SKIP"
                    return @{ Success = $false; Reason = "AlreadyRunning"; PID = $LockContent.PID }
                }
            }
            # Stale lockfile from crashed run - remove it
            Remove-Item -Path $script:LockFile -Force -ErrorAction SilentlyContinue
        }

        # Create new lockfile with current process info
        $LockData = @{
            PID        = $PID
            ScriptName = $ScriptName
            StartedAt  = (Get-Date).ToString("o")
            Hostname   = $env:COMPUTERNAME
        } | ConvertTo-Json
        Set-Content -Path $script:LockFile -Value $LockData -Force
    }

    $script:Initialized = $true
    return @{ Success = $true; Reason = "Initialized" }
}

# ============================================================
# LOGGING
# ============================================================

<#
.SYNOPSIS
    Outputs a timestamped, formatted log message.

.DESCRIPTION
    Writes a log message with timestamp and severity prefix.
    All output goes to stdout for Level.io script output capture.

.PARAMETER Message
    The message to log.

.PARAMETER Level
    Severity level. Default: "INFO"
    - INFO:    [*] General information
    - WARN:    [!] Warnings (non-fatal issues)
    - ERROR:   [X] Errors and failures
    - SUCCESS: [+] Successful completions
    - SKIP:    [-] Skipped operations
    - DEBUG:   [D] Debug/verbose output

.EXAMPLE
    Write-LevelLog "Starting cleanup process"
    # Output: 2025-12-27 14:32:01 [*] Starting cleanup process

.EXAMPLE
    Write-LevelLog "File not found" -Level "ERROR"
    # Output: 2025-12-27 14:32:01 [X] File not found

.EXAMPLE
    Write-LevelLog "Operation complete" -Level "SUCCESS"
    # Output: 2025-12-27 14:32:01 [+] Operation complete
#>
function Write-LevelLog {
    [CmdletBinding()]
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

    $LogMessage = "$Timestamp $Prefix $Message"
    Write-Host $LogMessage

    # Also write to log file if scratch folder is available
    if ($script:ScratchFolder) {
        $LogFolder = Join-Path $script:ScratchFolder "Logs"
        if (-not (Test-Path $LogFolder)) {
            New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
        }

        # Log file named by date for daily rotation
        $LogDate = Get-Date -Format "yyyy-MM-dd"
        $LogFile = Join-Path $LogFolder "COOLForge_$LogDate.log"

        try {
            # Append to log file with UTF-8 encoding
            $LogMessage | Out-File -FilePath $LogFile -Append -Encoding UTF8 -ErrorAction SilentlyContinue
        }
        catch {
            # Silently ignore logging errors - don't break script execution
        }
    }
}

# ============================================================
# SCRIPT EXECUTION WRAPPER
# ============================================================

<#
.SYNOPSIS
    Wraps main script logic with automatic error handling and cleanup.

.DESCRIPTION
    Executes the provided script block with try/catch error handling.
    On completion (success or failure):
    - Logs the result
    - Removes the lockfile (unless -NoCleanup)
    - Exits with appropriate code (0 = success, 1 = alert/failure)

.PARAMETER ScriptBlock
    The code to execute. Use { } to define the script block.

.PARAMETER NoCleanup
    Switch to skip lockfile removal on completion.
    Use when you need manual control over cleanup.

.EXAMPLE
    Invoke-LevelScript -ScriptBlock {
        Write-LevelLog "Doing work..."
        # Your code here
    }

.EXAMPLE
    # Keep lockfile after completion
    Invoke-LevelScript -ScriptBlock {
        Write-LevelLog "Starting long-running task..."
    } -NoCleanup

.NOTES
    This function calls exit, so code after it will not execute.
    Initialize-LevelScript must be called before using this function.
#>
function Invoke-LevelScript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory = $false)]
        [switch]$NoCleanup,

        [Parameter(Mandatory = $false)]
        [switch]$NoExit
    )

    # Ensure initialization was called
    if (-not $script:Initialized) {
        Write-LevelLog "ERROR: Initialize-LevelScript must be called first!" -Level "ERROR"
        if ($NoExit) { return 1 } else { exit 1 }
    }

    try {
        # Execute the main script logic
        # The scriptblock can return an exit code, or we use $script:ExitCode if set
        $Result = & $ScriptBlock

        # Check for exit code from scriptblock return value or $script:ExitCode
        $FinalExitCode = 0
        if ($null -ne $Result -and $Result -is [int]) {
            $FinalExitCode = $Result
        } elseif ($null -ne $script:ExitCode -and $script:ExitCode -ne 0) {
            $FinalExitCode = $script:ExitCode
        }

        if ($FinalExitCode -eq 0) {
            Write-LevelLog "Script completed successfully" -Level "SUCCESS"
        } else {
            Write-LevelLog "Script completed with exit code: $FinalExitCode" -Level "WARN"
        }

        if (-not $NoCleanup) {
            Remove-LevelLockFile
        }
        if ($NoExit) { return $FinalExitCode } else { exit $FinalExitCode }
    }
    catch {
        Write-LevelLog "FATAL: $($_.Exception.Message)" -Level "ERROR"
        Write-LevelLog "Stack: $($_.ScriptStackTrace)" -Level "DEBUG"

        if (-not $NoCleanup) {
            Remove-LevelLockFile
        }
        if ($NoExit) { return 1 } else { exit 1 }
    }
}

# ============================================================
# CLEANUP
# ============================================================

<#
.SYNOPSIS
    Removes the current script's lockfile.

.DESCRIPTION
    Deletes the lockfile created by Initialize-LevelScript.
    Called automatically by Invoke-LevelScript and Complete-LevelScript.
    Use directly only when you need manual control.

.EXAMPLE
    Remove-LevelLockFile

.NOTES
    Safe to call even if lockfile doesn't exist.
#>
function Remove-LevelLockFile {
    if ($script:LockFile -and (Test-Path $script:LockFile)) {
        Remove-Item -Path $script:LockFile -Force -ErrorAction SilentlyContinue
        Write-LevelLog "Lockfile removed" -Level "DEBUG"
    }
}

<#
.SYNOPSIS
    Manually completes the script with a custom exit code and message.

.DESCRIPTION
    Use instead of Invoke-LevelScript when you need:
    - Custom exit codes
    - Custom completion messages
    - Early exit from the script

.PARAMETER ExitCode
    Exit code to return. Default: 0
    0 = success (logs as SUCCESS)
    Non-zero = failure (logs as ERROR)

.PARAMETER Message
    Final log message. Default: "Script completed"

.EXAMPLE
    Complete-LevelScript -ExitCode 0 -Message "All files processed"

.EXAMPLE
    Complete-LevelScript -ExitCode 1 -Message "Database connection failed"

.EXAMPLE
    # Early exit on error
    if (-not $result) {
        Complete-LevelScript -ExitCode 1 -Message "Operation failed"
    }

.NOTES
    This function calls exit, so code after it will not execute.
#>
function Complete-LevelScript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$ExitCode = 0,

        [Parameter(Mandatory = $false)]
        [string]$Message = "Script completed"
    )

    $Level = if ($ExitCode -eq 0) { "SUCCESS" } else { "ERROR" }
    Write-LevelLog $Message -Level $Level
    Remove-LevelLockFile
    exit $ExitCode
}

# ============================================================
# UTILITY FUNCTIONS
# ============================================================

<#
.SYNOPSIS
    Checks if the script is running with administrator privileges.

.DESCRIPTION
    Returns $true if the current process has administrator rights.
    Use to validate permissions before performing admin-only operations.

.OUTPUTS
    Boolean. $true if running as administrator, $false otherwise.

.EXAMPLE
    if (-not (Test-LevelAdmin)) {
        Write-LevelLog "Admin rights required!" -Level "ERROR"
        Complete-LevelScript -ExitCode 1 -Message "Admin required"
    }

.EXAMPLE
    $DeviceInfo = Get-LevelDeviceInfo
    Write-LevelLog "Running as admin: $($DeviceInfo.IsAdmin)"
#>
function Test-LevelAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

<#
.SYNOPSIS
    Returns a hashtable of common device information.

.DESCRIPTION
    Gathers system information useful for logging and diagnostics.
    All values are retrieved at call time.

.OUTPUTS
    Hashtable with the following keys:
    - Hostname:   Computer name ($env:COMPUTERNAME)
    - Username:   Current user ($env:USERNAME)
    - Domain:     User domain ($env:USERDOMAIN)
    - OS:         Operating system name (e.g., "Microsoft Windows 11 Pro")
    - OSVersion:  OS version number (e.g., "10.0.22631")
    - IsAdmin:    Boolean indicating admin privileges
    - PowerShell: PowerShell version string
    - ScriptPID:  Current process ID

.EXAMPLE
    $Info = Get-LevelDeviceInfo
    Write-LevelLog "Running on: $($Info.Hostname) - $($Info.OS)"

.EXAMPLE
    $Info = Get-LevelDeviceInfo
    if (-not $Info.IsAdmin) {
        Write-LevelLog "Not running as admin" -Level "WARN"
    }
#>
function Get-LevelDeviceInfo {
    return @{
        Hostname   = $env:COMPUTERNAME
        Username   = $env:USERNAME
        Domain     = $env:USERDOMAIN
        OS         = (Get-CimInstance Win32_OperatingSystem).Caption
        OSVersion  = (Get-CimInstance Win32_OperatingSystem).Version
        IsAdmin    = Test-LevelAdmin
        PowerShell = $PSVersionTable.PSVersion.ToString()
        ScriptPID  = $PID
    }
}

# ============================================================
# SOFTWARE DETECTION UTILITIES
# ============================================================

<#
.SYNOPSIS
    Checks if software is installed on the system.

.DESCRIPTION
    Generic software detection function that checks multiple locations:
    - Running processes (by name pattern)
    - Windows services (by name pattern)
    - File system paths (array of paths to check)
    - Registry uninstall entries (by DisplayName pattern)

    All parameters except SoftwareName are optional. The function returns
    $true if ANY check finds a match.

.PARAMETER SoftwareName
    The display name pattern to search for in registry uninstall entries.
    Supports wildcards (e.g., "*AnyDesk*").

.PARAMETER ProcessPattern
    Pattern to match against running process names. Default: same as SoftwareName.

.PARAMETER ServicePattern
    Pattern to match against service names. Default: same as SoftwareName.

.PARAMETER InstallPaths
    Array of file system paths to check for existence.

.PARAMETER SkipProcessCheck
    Skip checking for running processes.

.PARAMETER SkipServiceCheck
    Skip checking for services.

.PARAMETER SkipRegistryCheck
    Skip checking registry uninstall entries.

.OUTPUTS
    $true if software is detected, $false otherwise.

.EXAMPLE
    Test-SoftwareInstalled -SoftwareName "AnyDesk"

.EXAMPLE
    Test-SoftwareInstalled -SoftwareName "Unchecky" -InstallPaths @(
        "$env:ProgramFiles\Unchecky",
        "${env:ProgramFiles(x86)}\Unchecky"
    ) -SkipProcessCheck -SkipServiceCheck

.EXAMPLE
    Test-SoftwareInstalled -SoftwareName "Huntress" -InstallPaths @(
        "$env:ProgramFiles\Huntress\HuntressAgent.exe"
    ) -SkipProcessCheck -SkipServiceCheck -SkipRegistryCheck
#>
function Test-SoftwareInstalled {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SoftwareName,

        [string]$ProcessPattern,
        [string]$ServicePattern,
        [string[]]$InstallPaths,

        [switch]$SkipProcessCheck,
        [switch]$SkipServiceCheck,
        [switch]$SkipRegistryCheck
    )

    # Default patterns to SoftwareName if not specified
    if (-not $ProcessPattern) { $ProcessPattern = $SoftwareName }
    if (-not $ServicePattern) { $ServicePattern = $SoftwareName }

    # Check for running processes
    if (-not $SkipProcessCheck) {
        $processes = Get-Process -Name "$ProcessPattern*" -ErrorAction SilentlyContinue
        if ($processes) { return $true }
    }

    # Check for services
    if (-not $SkipServiceCheck) {
        $services = Get-Service -Name "$ServicePattern*" -ErrorAction SilentlyContinue
        if ($services) { return $true }
    }

    # Check file system paths
    if ($InstallPaths) {
        foreach ($path in $InstallPaths) {
            if (Test-Path $path) { return $true }
        }
    }

    # Check registry uninstall entries
    if (-not $SkipRegistryCheck) {
        $regPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        foreach ($regPath in $regPaths) {
            $entries = Get-ItemProperty $regPath -ErrorAction SilentlyContinue |
                       Where-Object { $_.DisplayName -like "*$SoftwareName*" }
            if ($entries) { return $true }
        }
    }

    return $false
}

<#
.SYNOPSIS
    Stops all processes matching a pattern.

.DESCRIPTION
    Finds and forcefully stops all processes matching the specified name pattern.
    Returns the count of processes that were successfully stopped.

.PARAMETER ProcessPattern
    Pattern to match against process names. Wildcards are appended automatically.

.PARAMETER Silent
    Suppress logging output.

.OUTPUTS
    Integer count of processes stopped.

.EXAMPLE
    $count = Stop-SoftwareProcesses -ProcessPattern "AnyDesk"
    Write-Host "Stopped $count processes"
#>
function Stop-SoftwareProcesses {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProcessPattern,

        [switch]$Silent
    )

    $count = 0
    $processes = Get-Process -Name "$ProcessPattern*" -ErrorAction SilentlyContinue

    foreach ($proc in $processes) {
        try {
            Stop-Process -Id $proc.Id -Force -ErrorAction Stop
            $count++
            if (-not $Silent) {
                Write-LevelLog "Stopped process: $($proc.Name) (PID: $($proc.Id))"
            }
        }
        catch {
            if (-not $Silent) {
                Write-LevelLog "Failed to stop process: $($proc.Name) - $($_.Exception.Message)" -Level "WARN"
            }
        }
    }

    return $count
}

<#
.SYNOPSIS
    Stops and optionally disables services matching a pattern.

.DESCRIPTION
    Finds and stops all services matching the specified name pattern.
    Optionally disables the services to prevent restart.
    Returns the count of services that were successfully stopped.

.PARAMETER ServicePattern
    Pattern to match against service names. Wildcards are appended automatically.

.PARAMETER Disable
    Also disable the services after stopping them.

.PARAMETER Silent
    Suppress logging output.

.OUTPUTS
    Integer count of services stopped.

.EXAMPLE
    $count = Stop-SoftwareServices -ServicePattern "AnyDesk" -Disable
#>
function Stop-SoftwareServices {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServicePattern,

        [switch]$Disable,
        [switch]$Silent
    )

    $count = 0
    $services = Get-Service -Name "$ServicePattern*" -ErrorAction SilentlyContinue

    foreach ($svc in $services) {
        try {
            if ($svc.Status -eq 'Running') {
                Stop-Service -Name $svc.Name -Force -ErrorAction Stop
                $count++
                if (-not $Silent) {
                    Write-LevelLog "Stopped service: $($svc.Name)"
                }
            }

            if ($Disable) {
                Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction Stop
                if (-not $Silent) {
                    Write-LevelLog "Disabled service: $($svc.Name)"
                }
            }
        }
        catch {
            if (-not $Silent) {
                Write-LevelLog "Failed to stop/disable service: $($svc.Name) - $($_.Exception.Message)" -Level "WARN"
            }
        }
    }

    return $count
}

<#
.SYNOPSIS
    Gets the uninstall string for software from the registry.

.DESCRIPTION
    Searches Windows registry uninstall entries for software matching
    the specified name and returns the UninstallString value.

.PARAMETER SoftwareName
    The display name pattern to search for. Supports wildcards.

.PARAMETER Quiet
    Use QuietUninstallString if available, otherwise fall back to UninstallString.

.OUTPUTS
    The uninstall string if found, $null otherwise.

.EXAMPLE
    $uninstall = Get-SoftwareUninstallString -SoftwareName "Unchecky"
    if ($uninstall) { Start-Process cmd -ArgumentList "/c $uninstall" }

.EXAMPLE
    $uninstall = Get-SoftwareUninstallString -SoftwareName "AnyDesk" -Quiet
#>
function Get-SoftwareUninstallString {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SoftwareName,

        [switch]$Quiet
    )

    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($regPath in $regPaths) {
        $entries = Get-ItemProperty $regPath -ErrorAction SilentlyContinue |
                   Where-Object { $_.DisplayName -like "*$SoftwareName*" }

        foreach ($entry in $entries) {
            if ($Quiet -and $entry.QuietUninstallString) {
                return $entry.QuietUninstallString
            }
            if ($entry.UninstallString) {
                return $entry.UninstallString
            }
        }
    }

    return $null
}

<#
.SYNOPSIS
    Tests if a Windows service exists.

.PARAMETER ServiceName
    The exact service name to check.

.OUTPUTS
    $true if the service exists, $false otherwise.

.EXAMPLE
    if (Test-ServiceExists -ServiceName "HuntressAgent") { ... }
#>
function Test-ServiceExists {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName
    )

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    return ($null -ne $svc)
}

<#
.SYNOPSIS
    Tests if a Windows service is running.

.PARAMETER ServiceName
    The exact service name to check.

.OUTPUTS
    $true if the service exists and is running, $false otherwise.

.EXAMPLE
    if (Test-ServiceRunning -ServiceName "HuntressAgent") { ... }
#>
function Test-ServiceRunning {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName
    )

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -eq $svc) { return $false }
    return ($svc.Status -eq 'Running')
}

# ============================================================
# EMOJI PATTERN DEFINITIONS (Single Source of Truth)
# ============================================================

<#
.SYNOPSIS
    Returns the centralized emoji-to-action mapping table.

.DESCRIPTION
    This function is the SINGLE SOURCE OF TRUTH for all emoji pattern handling.
    It returns a hashtable mapping both correct UTF-8 emojis and their Level.io
    corrupted byte patterns to action names.

    Level.io corrupts UTF-8 emojis when passing {{level_tag_names}} through
    double-encoding (UTF-8 -> Windows-1252 -> UTF-8).

    All functions that need to interpret emoji tags should call this function
    rather than maintaining their own emoji tables.

.OUTPUTS
    Hashtable mapping emoji patterns (correct and corrupted) to action names.

.EXAMPLE
    $EmojiMap = Get-EmojiMap
    foreach ($Emoji in $EmojiMap.Keys) {
        if ($Tag.StartsWith($Emoji)) {
            $Action = $EmojiMap[$Emoji]
        }
    }
#>
# ============================================================
# EMOJI BYTE PATTERNS (Private Helper - Single Source of Truth)
# ============================================================
# This private function centralizes all corrupted byte pattern definitions
# to avoid duplication between Get-EmojiMap and Get-EmojiLiterals.

function Get-EmojiBytePatterns {
    # Level.io corrupts UTF-8 emojis when passing them through its variable system.
    # Observed corruption patterns (UTF-8 bytes -> corrupted bytes):
    # U+2705  Checkmark -> CE 93 C2 A3 C3 A0
    # U+274C  Cross     -> CE 93 C2 A5 C3 AE
    # U+26D4  NoEntry   -> CE 93 C2 A2 C3 B6
    # U+1F64F Pray      -> E2 89 A1 C6 92 C3 96 C3 85
    # U+1F6AB Prohibit  -> E2 89 A1 C6 92 C2 A2 C3 A6 (variant 1)
    #                   -> E2 89 A1 C6 92 C3 9C C2 BD (variant 2 - observed 2026-01-13)
    # U+1F4CC Pin       -> E2 89 A1 C6 92 C3 B4 C3 AE
    # U+1F504 Arrows    -> TBD (will be logged to EmojiTags.log)
    # U+1FA9F Window    -> E2 89 A1 C6 92 C2 AC C6 92
    # U+1F6A8 Alert     -> E2 89 A1 C6 92 C3 9C C2 BF
    # U+1F427 Penguin   -> E2 89 A1 C6 92 C3 89 C2 BA
    # U+1F300 Cyclone   -> E2 89 A1 C6 92 C3 AE C3 87
    # U+1F6F0 Satellite -> E2 89 A1 C6 92 C2 A2 E2 96 91 E2 88 A9 E2 95 95 C3 85
    # U+1F34E Apple     -> TBD (will be logged to EmojiTags.log)

    return @{
        # Corrupted patterns (from Level.io byte sequences)
        CorruptedCheck     = [System.Text.Encoding]::UTF8.GetString([byte[]](0xCE, 0x93, 0xC2, 0xA3, 0xC3, 0xA0))
        CorruptedCross     = [System.Text.Encoding]::UTF8.GetString([byte[]](0xCE, 0x93, 0xC2, 0xA5, 0xC3, 0xAE))
        CorruptedNoEntry   = [System.Text.Encoding]::UTF8.GetString([byte[]](0xCE, 0x93, 0xC2, 0xA2, 0xC3, 0xB6))
        CorruptedPray      = [System.Text.Encoding]::UTF8.GetString([byte[]](0xE2, 0x89, 0xA1, 0xC6, 0x92, 0xC3, 0x96, 0xC3, 0x85))
        CorruptedProhibit  = [System.Text.Encoding]::UTF8.GetString([byte[]](0xE2, 0x89, 0xA1, 0xC6, 0x92, 0xC2, 0xA2, 0xC3, 0xA6))
        CorruptedProhibit2 = [System.Text.Encoding]::UTF8.GetString([byte[]](0xE2, 0x89, 0xA1, 0xC6, 0x92, 0xC3, 0x9C, 0xC2, 0xBD))
        CorruptedPin       = [System.Text.Encoding]::UTF8.GetString([byte[]](0xE2, 0x89, 0xA1, 0xC6, 0x92, 0xC3, 0xB4, 0xC3, 0xAE))
        CorruptedWindow    = [System.Text.Encoding]::UTF8.GetString([byte[]](0xE2, 0x89, 0xA1, 0xC6, 0x92, 0xC2, 0xAC, 0xC6, 0x92))
        CorruptedAlert     = [System.Text.Encoding]::UTF8.GetString([byte[]](0xE2, 0x89, 0xA1, 0xC6, 0x92, 0xC3, 0x9C, 0xC2, 0xBF))
        CorruptedPenguin   = [System.Text.Encoding]::UTF8.GetString([byte[]](0xE2, 0x89, 0xA1, 0xC6, 0x92, 0xC3, 0x89, 0xC2, 0xBA))
        CorruptedCyclone   = [System.Text.Encoding]::UTF8.GetString([byte[]](0xE2, 0x89, 0xA1, 0xC6, 0x92, 0xC3, 0xAE, 0xC3, 0x87))
        CorruptedSatellite = [System.Text.Encoding]::UTF8.GetString([byte[]](0xE2, 0x89, 0xA1, 0xC6, 0x92, 0xC2, 0xA2, 0xE2, 0x96, 0x91, 0xE2, 0x88, 0xA9, 0xE2, 0x95, 0x95, 0xC3, 0x85))

        # Clean emoji characters (built programmatically to avoid encoding issues)
        Check     = [char]0x2705
        Cross     = [char]0x274C
        NoEntry   = [char]::ConvertFromUtf32(0x26D4)
        Pray      = [char]::ConvertFromUtf32(0x1F64F)
        Prohibit  = [char]::ConvertFromUtf32(0x1F6AB)
        Pin       = [char]::ConvertFromUtf32(0x1F4CC)
        Arrows    = [char]::ConvertFromUtf32(0x1F504)
        Window    = [char]::ConvertFromUtf32(0x1FA9F)
        Alert     = [char]::ConvertFromUtf32(0x1F6A8)
        Penguin   = [char]::ConvertFromUtf32(0x1F427)
        Cyclone   = [char]::ConvertFromUtf32(0x1F300)
        Satellite = [char]::ConvertFromUtf32(0x1F6F0)
        Wrench    = [char]::ConvertFromUtf32(0x1F527)
        Eyes      = [char]::ConvertFromUtf32(0x1F440)
        Apple     = [char]::ConvertFromUtf32(0x1F34E)
        Technician = [char]::ConvertFromUtf32(0x1F9D1) + [char]0x200D + [char]::ConvertFromUtf32(0x1F4BB)
    }
}

function Get-EmojiMap {
    # 5-TAG POLICY MODEL (per POLICY-TAGS.md)
    # =========================================
    # Software-specific tags (with software suffix):
    #   U+1F64F Pray     = Install   (override: install if missing, transient)
    #   U+1F6AB Prohibit = Remove    (override: remove if present, transient)
    #   U+1F4CC Pushpin  = Pin       (override: no changes, persistent)
    #   U+1F504 Arrows   = Reinstall (override: remove + install, transient)
    #   U+2705  Check    = Installed (status: software is installed, set by script)
    #
    # Global control tags (standalone, no suffix):
    #   U+2705 Check = Managed  (device is verified for management)
    #   U+274C Cross = Excluded (device excluded from management)
    #   Both = GlobalPin (device pinned globally, no changes allowed)

    $E = Get-EmojiBytePatterns

    return @{
        # ============================================================
        # SOFTWARE POLICY TAGS (5-tag model per POLICY-TAGS.md)
        # ============================================================
        # Override tags (transient - removed after action)
        $E.Pray = "Install"
        $E.Prohibit = "Remove"
        $E.NoEntry = "Remove"
        $E.Arrows = "Reinstall"
        # Override tag (persistent - admin intent)
        $E.Pin = "Pin"
        # Status tag (set by script)
        $E.Check = "Installed"

        # ============================================================
        # GLOBAL CONTROL TAGS (standalone, no software suffix)
        # ============================================================
        $E.Cross = "Excluded"

        # ============================================================
        # PLATFORM/CATEGORY TAGS (informational)
        # ============================================================
        $E.Window = "Windows"
        $E.Alert = "Alert"
        $E.Penguin = "Linux"
        $E.Apple = "macOS"
        $E.Cyclone = "AdelaideMRI"
        $E.Satellite = "Satellite"
        $E.Wrench = "Fix"
        $E.Eyes = "Check"

        # ============================================================
        # LEVEL.IO CORRUPTED PATTERNS
        # ============================================================
        $E.CorruptedCheck = "Installed"
        $E.CorruptedPin = "Pin"
        $E.CorruptedPray = "Install"
        $E.CorruptedProhibit = "Remove"
        $E.CorruptedProhibit2 = "Remove"
        $E.CorruptedNoEntry = "Remove"
        $E.CorruptedCross = "Excluded"
        $E.CorruptedWindow = "Windows"
        $E.CorruptedAlert = "Alert"
        $E.CorruptedPenguin = "Linux"
        $E.CorruptedCyclone = "AdelaideMRI"
        $E.CorruptedSatellite = "Satellite"
    }
}

<#
.SYNOPSIS
    Returns emoji character literals for use in string building and comparisons.

.DESCRIPTION
    Provides clean emoji characters and their Level.io corrupted equivalents.
    Use this to get the actual emoji strings rather than their semantic meanings.
    Uses Get-EmojiBytePatterns internally as the single source of truth.

.OUTPUTS
    Hashtable with emoji characters keyed by their semantic name:
    - Check, Cross, Pray, Prohibit, NoEntry, Pin, Arrows (clean)
    - CorruptedCheck, CorruptedCross, etc. (Level.io corrupted patterns)

.EXAMPLE
    $Emojis = Get-EmojiLiterals
    if ($Tag -eq $Emojis.Check -or $Tag -eq $Emojis.CorruptedCheck) {
        Write-Host "Found checkmark!"
    }
#>
function Get-EmojiLiterals {
    # Use shared byte patterns (single source of truth)
    return Get-EmojiBytePatterns
}

# ============================================================
# SOFTWARE POLICY DETECTION
# ============================================================

<#
.SYNOPSIS
    Determines software policy requirements from device tags.

.DESCRIPTION
    Parses device tags to identify policy requirements for a specific software package.
    Supports tag-based policy enforcement using emoji prefixes:

    - 🙏 (pray)       = Request/Recommend installation
    - ⛔ (no entry)   = Block/Must not be installed
    - 🛑 (stop sign)  = Stop/Remove if present
    - 📌 (pin)        = Pin/Must be installed (enforce presence)
    - ✅ (check mark) = Approved/Verified (compliant state)

    This enables a single "multilaunch" script pattern where one script can handle
    any software package by simply changing the software name parameter.

.PARAMETER SoftwareName
    The name of the software to check policy for (e.g., "unchecky", "7zip", "vlc").
    Case-insensitive. Matched against tags in the format: {emoji}{softwarename}

.PARAMETER DeviceTags
    Comma-separated list of device tags. Typically "{{level_tag_names}}".
    Example: "🙏unchecky,📌7zip,✅chrome,production,windows"

.OUTPUTS
    Hashtable with policy information:
    - SoftwareName: The software being checked
    - HasPolicy: $true if any policy tag was found, $false otherwise
    - PolicyActions: Array of actions required (Request, Block, Remove, Pin, Installed)
    - MatchedTags: Array of full tag strings that matched
    - RawTags: Array of all device tags

.EXAMPLE
    # Check policy for Unchecky from Level.io tags
    $Policy = Get-SoftwarePolicy -SoftwareName "unchecky" -DeviceTags "{{level_tag_names}}"
    if ($Policy.HasPolicy) {
        Write-LevelLog "Policy actions: $($Policy.PolicyActions -join ', ')"
        Write-LevelLog "Matched tags: $($Policy.MatchedTags -join ', ')"
    }

.EXAMPLE
    # Check multiple software packages
    foreach ($Software in @("unchecky", "7zip", "vlc")) {
        $Policy = Get-SoftwarePolicy -SoftwareName $Software -DeviceTags $DeviceTags
        if ($Policy.HasPolicy) {
            Write-Host "$Software requires: $($Policy.PolicyActions -join ', ')"
        }
    }

.EXAMPLE
    # Use in a multilaunch check script
    $SoftwareName = "unchecky"  # Change this for different software
    $Policy = Get-SoftwarePolicy -SoftwareName $SoftwareName -DeviceTags $DeviceTags

    if ($Policy.HasPolicy) {
        if ("Pin" -in $Policy.PolicyActions) {
            # Check if software is installed
        }
        if ("Remove" -in $Policy.PolicyActions) {
            # Check if software needs removal
        }
    }

.NOTES
    Tag format is case-insensitive: "📌Unchecky", "📌unchecky", "📌UNCHECKY" all match.
    Multiple policy tags for the same software are supported and all will be returned.
#>
function Get-SoftwarePolicy {
    <#
    .SYNOPSIS
        Determines software policy from device tags following the 5-tag model.

    .DESCRIPTION
        Implements the policy flow from POLICY-TAGS.md:
        1. Check global control tags (standalone checkmark/cross)
        2. Check software-specific override tags (with software suffix)
        3. Return resolved action based on priority

        Priority order (first match wins):
        1. Pin (U+1F4CC) - No changes allowed
        2. Reinstall (U+1F504) - Remove + Install
        3. Remove (U+1F6AB) - Remove if present
        4. Install (U+1F64F) - Install if missing

    .PARAMETER SoftwareName
        The software name to check policy for (e.g., "unchecky").

    .PARAMETER DeviceTags
        Comma-separated list of device tags from Level.io.

    .PARAMETER CustomFieldPolicy
        Optional policy value from custom field (install/remove/pin/empty).

    .PARAMETER ShowDebug
        Enable verbose debug output.

    .OUTPUTS
        Hashtable with policy information including:
        - GlobalStatus: Managed/Excluded/GlobalPin/NotVerified
        - ResolvedAction: Pin/Reinstall/Remove/Install/None
        - ActionSource: Tag/CustomField/None
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SoftwareName,

        [Parameter(Mandatory = $false)]
        [string]$DeviceTags = "",

        [Parameter(Mandatory = $false)]
        [string]$CustomFieldPolicy = "",

        [Parameter(Mandatory = $false)]
        [switch]$ShowDebug
    )

    # Get centralized emoji map and literals (single source of truth)
    $EmojiMap = Get-EmojiMap
    $EmojiLiterals = Get-EmojiLiterals

    # Use centralized emoji definitions for global control tags
    $CheckmarkEmoji = $EmojiLiterals.Check
    $CrossEmoji = $EmojiLiterals.Cross
    $CorruptedCheckmark = $EmojiLiterals.CorruptedCheck
    $CorruptedCross = $EmojiLiterals.CorruptedCross

    # Parse tags into array
    $TagArray = if ($DeviceTags) {
        $DeviceTags -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    } else {
        @()
    }

    if ($ShowDebug) {
        Write-Host "[DEBUG] Checking $($TagArray.Count) tags for '$SoftwareName' policy"
    }

    # ============================================================
    # STEP 1: CHECK GLOBAL CONTROL TAGS
    # ============================================================
    # Look for standalone checkmark and cross (no software suffix)
    $HasGlobalCheckmark = $false
    $HasGlobalCross = $false

    foreach ($Tag in $TagArray) {
        if ($ShowDebug) {
            $TagBytes = [System.Text.Encoding]::UTF8.GetBytes($Tag)
            $TagHex = ($TagBytes | ForEach-Object { "{0:X2}" -f $_ }) -join " "
            $CheckBytes = [System.Text.Encoding]::UTF8.GetBytes($CorruptedCheckmark)
            $CheckHex = ($CheckBytes | ForEach-Object { "{0:X2}" -f $_ }) -join " "
            Write-Host "[DEBUG] Comparing tag '$Tag' ($TagHex) vs corrupted checkmark ($CheckHex)"
            Write-Host "[DEBUG]   Length: $($Tag.Length) vs $($CorruptedCheckmark.Length)"
            Write-Host "[DEBUG]   Equals: $($Tag -eq $CorruptedCheckmark)"
        }
        # Standalone checkmark (exactly the emoji, no suffix)
        if ($Tag -eq "$CheckmarkEmoji" -or $Tag -eq $CorruptedCheckmark) {
            $HasGlobalCheckmark = $true
            if ($ShowDebug) { Write-Host "[DEBUG] Found global checkmark (managed)" }
        }
        # Standalone cross (exactly the emoji, no suffix)
        if ($Tag -eq "$CrossEmoji" -or $Tag -eq $CorruptedCross) {
            $HasGlobalCross = $true
            if ($ShowDebug) { Write-Host "[DEBUG] Found global cross (excluded)" }
        }
    }

    # Determine global status per POLICY-TAGS.md
    $GlobalStatus = "NotVerified"  # Default: device not yet verified
    if ($HasGlobalCheckmark -and $HasGlobalCross) {
        $GlobalStatus = "GlobalPin"  # Both = globally pinned, no changes
    }
    elseif ($HasGlobalCross) {
        $GlobalStatus = "Excluded"   # Cross only = excluded from management
    }
    elseif ($HasGlobalCheckmark) {
        $GlobalStatus = "Managed"    # Checkmark only = managed device
    }

    # Early exit if device should be skipped
    if ($GlobalStatus -in @("NotVerified", "Excluded", "GlobalPin")) {
        if ($ShowDebug) { Write-Host "[DEBUG] Global status: $GlobalStatus - skipping policy checks" }
        return @{
            SoftwareName    = $SoftwareName
            GlobalStatus    = $GlobalStatus
            ShouldProcess   = $false
            ResolvedAction  = "None"
            ActionSource    = "GlobalTag"
            SkipReason      = switch ($GlobalStatus) {
                "NotVerified" { "Device not verified for management (no global checkmark)" }
                "Excluded"    { "Device excluded from management (global cross)" }
                "GlobalPin"   { "Device globally pinned (both checkmark and cross)" }
            }
            MatchedTags     = @()
            PolicyActions   = @()
            RawTags         = $TagArray
            HasInstalled    = $false
            IsPinned        = ($GlobalStatus -eq "GlobalPin")
        }
    }

    # ============================================================
    # STEP 2: CHECK SOFTWARE-SPECIFIC OVERRIDE TAGS
    # ============================================================
    $MatchedTags = @()
    $PolicyActions = @()
    $UnknownEmojiTags = @()

    foreach ($Tag in $TagArray) {
        if ($ShowDebug) {
            $tagBytes = [System.Text.Encoding]::UTF8.GetBytes($Tag)
            $hexBytes = ($tagBytes | ForEach-Object { "{0:X2}" -f $_ }) -join " "
            Write-Host "[DEBUG] Tag: '$Tag' | Bytes: $hexBytes"
        }

        # Check if tag starts with any policy emoji
        $MatchedKnownEmoji = $false
        foreach ($Emoji in $EmojiMap.Keys) {
            if ($Tag.StartsWith($Emoji)) {
                $MatchedKnownEmoji = $true
                # Extract software name from tag (everything after emoji)
                $TagSoftware = $Tag.Substring($Emoji.Length).Trim()

                if ($ShowDebug) {
                    Write-Host "[DEBUG]   Matched prefix -> software name: '$TagSoftware'"
                }

                # Case-insensitive match for this specific software
                if ($TagSoftware -ieq $SoftwareName) {
                    $MatchedTags += $Tag
                    $PolicyActions += $EmojiMap[$Emoji]
                    if ($ShowDebug) {
                        Write-Host "[DEBUG]   MATCH! Action: $($EmojiMap[$Emoji])"
                    }
                }
                break
            }
        }

        # Track unknown emoji patterns for debugging
        if (-not $MatchedKnownEmoji -and $Tag.Length -gt 0) {
            $FirstChar = $Tag[0]
            $FirstCharCode = [int][char]$FirstChar
            if ($FirstCharCode -gt 0x7F -or ($FirstCharCode -lt 0x20 -and $FirstCharCode -ne 0x09)) {
                $UnknownEmojiTags += $Tag
            }
        }
    }

    # Log unknown emoji patterns
    if ($UnknownEmojiTags.Count -gt 0) {
        foreach ($UnknownTag in $UnknownEmojiTags) {
            $tagBytes = [System.Text.Encoding]::UTF8.GetBytes($UnknownTag)
            $hexBytes = ($tagBytes | ForEach-Object { "{0:X2}" -f $_ }) -join " "
            Write-Host "[!] Unknown emoji pattern: '$UnknownTag'"
            Write-Host "[!]   Bytes: $hexBytes"
        }
    }

    # Log emoji tags to file for pattern discovery
    if ($script:ScratchFolder) {
        $EmojiTagLogPath = Join-Path $script:ScratchFolder "EmojiTags.log"
        $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        foreach ($Tag in $TagArray) {
            if ($Tag.Length -gt 0) {
                $FirstCharCode = [int][char]$Tag[0]
                if ($FirstCharCode -gt 0x7F -or ($FirstCharCode -lt 0x20 -and $FirstCharCode -ne 0x09)) {
                    $tagBytes = [System.Text.Encoding]::UTF8.GetBytes($Tag)
                    $hexBytes = ($tagBytes | ForEach-Object { "{0:X2}" -f $_ }) -join " "
                    $LogEntry = "$Timestamp | Tag: '$Tag' | Bytes: $hexBytes"

                    $ExistingContent = if (Test-Path $EmojiTagLogPath) { Get-Content $EmojiTagLogPath -Raw -ErrorAction SilentlyContinue } else { "" }
                    if ($ExistingContent -notmatch [regex]::Escape("Bytes: $hexBytes")) {
                        $LogEntry | Out-File -FilePath $EmojiTagLogPath -Append -Encoding UTF8 -ErrorAction SilentlyContinue
                    }
                }
            }
        }
    }

    # Get unique actions
    $UniqueActions = $PolicyActions | Select-Object -Unique

    # Warn about invalid tag combinations (Cross should never have software suffix)
    if ("Excluded" -in $UniqueActions) {
        Write-Host "[!] Invalid tag: Cross (U+274C) with software suffix is not valid"
        Write-Host "[!]   Use Pin (U+1F4CC) to exclude specific software from changes"
    }

    # ============================================================
    # STEP 3: RESOLVE ACTION (Priority order per POLICY-TAGS.md)
    # ============================================================
    # Priority: Pin > Reinstall > Remove > Install
    $IsPinned = "Pin" -in $UniqueActions
    $HasReinstall = "Reinstall" -in $UniqueActions
    $HasRemove = "Remove" -in $UniqueActions
    $HasInstall = "Install" -in $UniqueActions
    $HasInstalled = "Installed" -in $UniqueActions  # Status tag

    $ResolvedAction = "None"
    $ActionSource = "None"

    if ($IsPinned) {
        $ResolvedAction = "Pin"
        $ActionSource = "Tag"
    }
    elseif ($HasReinstall) {
        $ResolvedAction = "Reinstall"
        $ActionSource = "Tag"
    }
    elseif ($HasRemove) {
        $ResolvedAction = "Remove"
        $ActionSource = "Tag"
    }
    elseif ($HasInstall) {
        $ResolvedAction = "Install"
        $ActionSource = "Tag"
    }
    elseif (-not [string]::IsNullOrWhiteSpace($CustomFieldPolicy)) {
        # ============================================================
        # STEP 4: FALL BACK TO CUSTOM FIELD POLICY
        # ============================================================
        switch ($CustomFieldPolicy.ToLower()) {
            "install" {
                $ResolvedAction = "Install"
                $ActionSource = "CustomField"
            }
            "remove" {
                $ResolvedAction = "Remove"
                $ActionSource = "CustomField"
            }
            "pin" {
                $ResolvedAction = "Pin"
                $ActionSource = "CustomField"
            }
        }
    }

    # Return comprehensive policy information
    return @{
        # Identity
        SoftwareName    = $SoftwareName

        # Global state
        GlobalStatus    = $GlobalStatus
        ShouldProcess   = $true

        # Resolved action
        ResolvedAction  = $ResolvedAction
        ActionSource    = $ActionSource

        # Tag detection
        MatchedTags     = $MatchedTags
        PolicyActions   = $UniqueActions
        RawTags         = $TagArray

        # State flags
        HasInstalled    = $HasInstalled
        IsPinned        = $IsPinned

        # Custom field
        CustomFieldPolicy = $CustomFieldPolicy
    }
}

<#
.SYNOPSIS
    Performs a complete software policy check and outputs results.

.DESCRIPTION
    High-level function that checks device tags for software policy requirements
    and outputs formatted results. Implements the 5-tag model from POLICY-TAGS.md.

    The function:
    1. Displays device information
    2. Lists all device tags
    3. Checks global control tags (managed/excluded/pinned)
    4. Checks software-specific override tags
    5. Falls back to custom field policy if no override tags
    6. Reports resolved action

.PARAMETER SoftwareName
    The name of the software to check (e.g., "unchecky", "7zip").

.PARAMETER DeviceTags
    Comma-separated list of device tags from Level.io.

.PARAMETER CustomFieldPolicy
    Optional policy value from custom field (install/remove/pin/empty).

.EXAMPLE
    Invoke-SoftwarePolicyCheck -SoftwareName "unchecky" -DeviceTags $DeviceTags

.OUTPUTS
    Returns the policy hashtable from Get-SoftwarePolicy.
#>
function Invoke-SoftwarePolicyCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SoftwareName,

        [Parameter(Mandatory = $false)]
        [string]$DeviceTags = "",

        [Parameter(Mandatory = $false)]
        [string]$CustomFieldPolicy = ""
    )

    # Log device info
    $DeviceInfo = Get-LevelDeviceInfo
    Write-LevelLog "Device: $($DeviceInfo.Hostname) | OS: $($DeviceInfo.OS)"
    Write-Host ""

    # Show all device tags
    Write-LevelLog "Device Tags:"
    if ($DeviceTags) {
        $TagArray = $DeviceTags -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        if ($TagArray.Count -gt 0) {
            foreach ($tag in $TagArray) {
                Write-Host "  - $tag"
            }
        } else {
            Write-Host "  (no tags)"
        }
    } else {
        Write-Host "  (no tags)"
    }
    Write-Host ""

    # Get software policy from device tags and custom field
    Write-LevelLog "Checking policy for '$SoftwareName'..."
    $Policy = Get-SoftwarePolicy -SoftwareName $SoftwareName -DeviceTags $DeviceTags -CustomFieldPolicy $CustomFieldPolicy

    # Display results header
    Write-Host ""
    Write-LevelLog "========================================" -Level "INFO"
    Write-LevelLog "Policy Results: $SoftwareName" -Level "INFO"
    Write-LevelLog "========================================" -Level "INFO"
    Write-Host ""

    # Show global status first
    Write-LevelLog "Global Status: $($Policy.GlobalStatus)" -Level "INFO"

    # Handle early exit cases (device not processed)
    if (-not $Policy.ShouldProcess) {
        Write-Host ""
        Write-LevelLog "$($Policy.SkipReason)" -Level "WARN"
        Write-Host ""
        Write-LevelLog "Resolved Action: NONE (skipped)" -Level "INFO"
        return $Policy
    }

    Write-Host ""

    # Show matched software-specific tags
    if ($Policy.MatchedTags.Count -gt 0) {
        Write-LevelLog "Override Tags Found: $($Policy.MatchedTags.Count)" -Level "SUCCESS"
        foreach ($Tag in $Policy.MatchedTags) {
            Write-Host "  - $Tag"
        }
        Write-Host ""
    }

    # Show custom field policy if set
    if (-not [string]::IsNullOrWhiteSpace($CustomFieldPolicy)) {
        Write-LevelLog "Custom Field Policy: $CustomFieldPolicy" -Level "INFO"
    }

    # Show status flags
    Write-LevelLog "Status:" -Level "INFO"
    Write-Host "  - Installed: $($Policy.HasInstalled)"
    Write-Host "  - Pinned: $($Policy.IsPinned)"
    Write-Host ""

    # Show resolved action with description
    $ActionDesc = switch ($Policy.ResolvedAction) {
        "Pin"       { "PIN - No changes allowed (admin intent)" }
        "Reinstall" { "REINSTALL - Remove then install fresh" }
        "Remove"    { "REMOVE - Uninstall software" }
        "Install"   { "INSTALL - Install if not present" }
        "None"      { "NONE - No action required" }
        default     { "UNKNOWN - $($Policy.ResolvedAction)" }
    }

    $SourceDesc = switch ($Policy.ActionSource) {
        "Tag"         { "(from device tag)" }
        "CustomField" { "(from custom field policy)" }
        "GlobalTag"   { "(from global control)" }
        default       { "" }
    }

    Write-LevelLog "Resolved Action: $ActionDesc $SourceDesc" -Level "INFO"

    # Show available override tags if no action
    if ($Policy.ResolvedAction -eq "None" -and $Policy.MatchedTags.Count -eq 0) {
        Write-Host ""
        Write-LevelLog "To override policy, add one of these tags:" -Level "INFO"
        Write-Host "  Install if missing : [U+1F64F]$SoftwareName"
        Write-Host "  Remove if present  : [U+1F6AB]$SoftwareName"
        Write-Host "  Pin (no changes)   : [U+1F4CC]$SoftwareName"
        Write-Host "  Reinstall          : [U+1F504]$SoftwareName"
    }

    return $Policy
}

<#
.SYNOPSIS
    Makes authenticated REST API calls with standardized error handling.

.DESCRIPTION
    Wrapper for Invoke-RestMethod with:
    - API key authentication (Level.io style - no "Bearer" prefix)
    - JSON content type headers
    - Automatic body serialization
    - Standardized success/failure response format

.PARAMETER Uri
    Full API endpoint URL.

.PARAMETER ApiKey
    API key for authentication. Sent as "Authorization: $ApiKey".
    Note: Level.io v2 API does NOT use "Bearer" prefix.

.PARAMETER Method
    HTTP method. Default: "GET"
    Valid values: GET, POST, PUT, DELETE, PATCH

.PARAMETER Body
    Hashtable to send as JSON body. Ignored for GET requests.
    Automatically converted to JSON with depth 10.

.PARAMETER TimeoutSec
    Request timeout in seconds. Default: 30

.OUTPUTS
    Hashtable with:
    - Success: @{ Success = $true; Data = <response object> }
    - Failure: @{ Success = $false; Error = "error message" }

.EXAMPLE
    # GET request
    $Result = Invoke-LevelApiCall -Uri "https://api.example.com/status" -ApiKey $key
    if ($Result.Success) {
        $Status = $Result.Data
    }

.EXAMPLE
    # POST request with body
    $Result = Invoke-LevelApiCall -Uri "https://api.example.com/tickets" `
                                  -ApiKey "{{cf_apikey}}" `
                                  -Method "POST" `
                                  -Body @{
                                      title = "Alert"
                                      priority = "high"
                                  }

.EXAMPLE
    # Handle errors
    $Result = Invoke-LevelApiCall -Uri $endpoint -ApiKey $key
    if (-not $Result.Success) {
        Write-LevelLog "API Error: $($Result.Error)" -Level "ERROR"
    }
#>
function Invoke-LevelApiCall {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $false)]
        [ValidateSet("GET", "POST", "PUT", "DELETE", "PATCH")]
        [string]$Method = "GET",

        [Parameter(Mandatory = $false)]
        [hashtable]$Body,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSec = 30
    )

    # Set up headers with API key authentication
    # Note: Level.io v2 API does NOT use "Bearer" prefix - just the API key directly
    $Headers = @{
        "Authorization" = $ApiKey
        "Content-Type"  = "application/json; charset=utf-8"
        "Accept"        = "application/json"
    }

    # Build request parameters
    $Params = @{
        Uri             = $Uri
        Method          = $Method
        Headers         = $Headers
        TimeoutSec      = $TimeoutSec
        UseBasicParsing = $true
    }

    # Add body for non-GET requests - ensure UTF-8 encoding for emojis
    if ($Body -and $Method -ne "GET") {
        $JsonString = ($Body | ConvertTo-Json -Depth 10)
        # Explicitly encode as UTF-8 bytes to handle emojis correctly
        $Params.Body = [System.Text.Encoding]::UTF8.GetBytes($JsonString)
    }

    try {
        $Response = Invoke-RestMethod @Params
        return @{ Success = $true; Data = $Response }
    }
    catch {
        $StatusCode = $null
        $ResponseBody = $null
        if ($_.Exception.Response) {
            $StatusCode = [int]$_.Exception.Response.StatusCode
            # Try to read the response body for error details
            try {
                $Stream = $_.Exception.Response.GetResponseStream()
                $Reader = New-Object System.IO.StreamReader($Stream)
                $ResponseBody = $Reader.ReadToEnd()
                $Reader.Close()
                $Stream.Close()
            }
            catch {
                # Ignore stream read errors
            }
        }
        $ErrorMsg = $_.Exception.Message
        if ($ResponseBody) {
            $ErrorMsg = "$ErrorMsg - Response: $ResponseBody"
        }
        Write-LevelLog "API call failed: $ErrorMsg" -Level "ERROR"
        return @{ Success = $false; Error = $ErrorMsg; StatusCode = $StatusCode; ResponseBody = $ResponseBody }
    }
}

# ============================================================
# EMOJI ENCODING REPAIR
# ============================================================

<#
.SYNOPSIS
    Repairs corrupted UTF-8 emojis in strings.

.DESCRIPTION
    Level.io and other deployment systems may corrupt UTF-8 emojis when
    deploying PowerShell scripts. This function detects common corruption
    patterns and repairs them to the correct Unicode characters.

    Supports:
    - ⛔ Stop sign (U+26D4)
    - 👀 Eyes (U+1F440)
    - 🙏 Folded hands (U+1F64F)
    - 🚨 Police light (U+1F6A8)
    - 🛑 Stop sign octagon (U+1F6D1)
    - ✅ Check mark (U+2705)
    - 🔚 End arrow (U+1F51A)
    - 🆕 New button (U+1F195)

.PARAMETER Text
    The text string that may contain corrupted emojis.

.OUTPUTS
    String with emojis repaired to correct Unicode characters.

.EXAMPLE
    $ScriptToRun = Repair-LevelEmoji -Text $ScriptToRun

.EXAMPLE
    # Repair a filename before using it
    $FileName = Repair-LevelEmoji "⛔Force Remove Anydesk.ps1"
#>
function Repair-LevelEmoji {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Text
    )

    # Known emoji mappings: corrupted pattern -> correct Unicode
    # These patterns occur when UTF-8 bytes are interpreted as Windows-1252
    # or double-encoded through different code pages
    # Level.io corruption patterns: UTF-8 bytes interpreted as Windows-1252, then re-encoded as UTF-8
    # Pattern: F0 9F xx yy -> ð Ÿ (CP1252) -> C3 B0 C5 B8 (UTF-8 of those chars)
    # But observed: 👀 F0 9F 91 80 -> ≡ƒæÇ (2261 0192 00E6 00C7)
    # This suggests bytes are interpreted through a complex encoding chain

    $EmojiRepairs = @{
        # ========== BMP Characters (3-byte UTF-8) ==========

        # ⛔ Stop sign (U+26D4) - UTF-8: E2 9B 94
        "$([char]0xE2)$([char]0x9B)$([char]0x94)" = [char]0x26D4
        # ⛔ Stop sign - Alt corruption: Γ¢ö (observed from Level.io)
        "$([char]0x0393)$([char]0x00A2)$([char]0x00F6)" = [char]0x26D4

        # ✅ Check mark (U+2705) - UTF-8: E2 9C 85
        "$([char]0xE2)$([char]0x9C)$([char]0x85)" = [char]0x2705
        # ✅ Check mark - Alt corruption: Γ£à (predicted pattern)
        "$([char]0x0393)$([char]0x00A3)$([char]0x00E0)" = [char]0x2705

        # ========== Supplementary Characters (4-byte UTF-8) ==========

        # 👀 Eyes (U+1F440) - UTF-8: F0 9F 91 80
        "$([char]0xF0)$([char]0x9F)$([char]0x91)$([char]0x80)" = [char]::ConvertFromUtf32(0x1F440)
        # 👀 Eyes - Alt corruption: ≡ƒæÇ (observed from Level.io)
        "$([char]0x2261)$([char]0x0192)$([char]0x00E6)$([char]0x00C7)" = [char]::ConvertFromUtf32(0x1F440)

        # 🙏 Folded hands (U+1F64F) - UTF-8: F0 9F 99 8F
        "$([char]0xF0)$([char]0x9F)$([char]0x99)$([char]0x8F)" = [char]::ConvertFromUtf32(0x1F64F)
        # 🙏 Folded hands - Alt corruption: ≡ƒÖÅ (predicted pattern based on 👀)
        "$([char]0x2261)$([char]0x0192)$([char]0x00D6)$([char]0x00C5)" = [char]::ConvertFromUtf32(0x1F64F)

        # 🚨 Police light (U+1F6A8) - UTF-8: F0 9F 9A A8
        "$([char]0xF0)$([char]0x9F)$([char]0x9A)$([char]0xA8)" = [char]::ConvertFromUtf32(0x1F6A8)
        # 🚨 Police light - Alt corruption: ≡ƒÜ¿ (predicted pattern)
        "$([char]0x2261)$([char]0x0192)$([char]0x00DC)$([char]0x00BF)" = [char]::ConvertFromUtf32(0x1F6A8)

        # 🛑 Stop sign octagon (U+1F6D1) - UTF-8: F0 9F 9B 91
        "$([char]0xF0)$([char]0x9F)$([char]0x9B)$([char]0x91)" = [char]::ConvertFromUtf32(0x1F6D1)
        # 🛑 Stop sign octagon - Alt corruption: ≡ƒÜæ (predicted pattern)
        "$([char]0x2261)$([char]0x0192)$([char]0x00DC)$([char]0x00E6)" = [char]::ConvertFromUtf32(0x1F6D1)

        # 🔚 End arrow (U+1F51A) - UTF-8: F0 9F 94 9A
        "$([char]0xF0)$([char]0x9F)$([char]0x94)$([char]0x9A)" = [char]::ConvertFromUtf32(0x1F51A)
        # 🔚 End arrow - Alt corruption: ≡ƒöÜ (predicted pattern)
        "$([char]0x2261)$([char]0x0192)$([char]0x00F6)$([char]0x00DC)" = [char]::ConvertFromUtf32(0x1F51A)

        # 🆕 New button (U+1F195) - UTF-8: F0 9F 86 95
        "$([char]0xF0)$([char]0x9F)$([char]0x86)$([char]0x95)" = [char]::ConvertFromUtf32(0x1F195)
        # 🆕 New button - Alt corruption: ≡ƒåò (predicted pattern)
        "$([char]0x2261)$([char]0x0192)$([char]0x00E5)$([char]0x00F2)" = [char]::ConvertFromUtf32(0x1F195)

        # 🔧 Wrench (U+1F527) - UTF-8: F0 9F 94 A7
        "$([char]0xF0)$([char]0x9F)$([char]0x94)$([char]0xA7)" = [char]::ConvertFromUtf32(0x1F527)
        # 🔧 Wrench - Alt corruption: ≡ƒöº (predicted pattern)
        "$([char]0x2261)$([char]0x0192)$([char]0x00F6)$([char]0x00BA)" = [char]::ConvertFromUtf32(0x1F527)
    }

    foreach ($corrupted in $EmojiRepairs.Keys) {
        if ($Text.Contains($corrupted)) {
            $Text = $Text.Replace($corrupted, $EmojiRepairs[$corrupted])
        }
    }

    return $Text
}

<#
.SYNOPSIS
    URL-encodes a string with proper UTF-8 handling for emojis.

.DESCRIPTION
    Performs percent-encoding on a string, correctly handling Unicode
    characters including emojis. Unlike [System.Uri]::EscapeDataString(),
    this function properly encodes UTF-8 bytes for use in URLs.

.PARAMETER Text
    The text string to URL-encode.

.OUTPUTS
    URL-encoded string safe for use in HTTP requests.

.EXAMPLE
    $EncodedName = Get-LevelUrlEncoded -Text "👀Test Show Versions.ps1"
    # Returns: %F0%9F%91%80Test%20Show%20Versions.ps1

.EXAMPLE
    $ScriptUrl = "$BaseUrl/$(Get-LevelUrlEncoded $ScriptToRun)"
#>
function Get-LevelUrlEncoded {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Text
    )

    $Utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $Encoded = [System.Text.StringBuilder]::new()

    foreach ($byte in $Utf8Bytes) {
        if (($byte -ge 0x30 -and $byte -le 0x39) -or  # 0-9
            ($byte -ge 0x41 -and $byte -le 0x5A) -or  # A-Z
            ($byte -ge 0x61 -and $byte -le 0x7A) -or  # a-z
            $byte -eq 0x2D -or $byte -eq 0x2E -or $byte -eq 0x5F -or $byte -eq 0x7E) {  # - . _ ~
            [void]$Encoded.Append([char]$byte)
        } else {
            [void]$Encoded.Append(('%{0:X2}' -f $byte))
        }
    }

    return $Encoded.ToString()
}

# ============================================================
# LEVEL.IO API FUNCTIONS
# ============================================================

<#
.SYNOPSIS
    Retrieves all groups (folders) from Level.io with automatic pagination.

.DESCRIPTION
    Fetches all groups from the Level.io API, automatically handling pagination
    to retrieve complete results regardless of the total number of groups.

.PARAMETER ApiKey
    Level.io API key for authentication. Typically "{{cf_apikey}}".

.PARAMETER BaseUrl
    Base URL for the Level.io API. Default: "https://api.level.io/v2"

.OUTPUTS
    Array of group objects from the Level.io API, or $null on failure.
    Each group object contains: id, name, parent_id, and other properties.

.EXAMPLE
    $Groups = Get-LevelGroups -ApiKey "{{cf_apikey}}"
    Write-LevelLog "Found $($Groups.Count) groups"

.EXAMPLE
    $Groups = Get-LevelGroups -ApiKey $ApiKey
    $RootGroups = $Groups | Where-Object { -not $_.parent_id }
#>
function Get-LevelGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://api.level.io/v2"
    )

    $AllGroups = @()
    $StartingAfter = $null

    do {
        $Uri = "$BaseUrl/groups?limit=100"
        if ($StartingAfter) {
            $Uri += "&starting_after=$StartingAfter"
        }

        $Result = Invoke-LevelApiCall -Uri $Uri -ApiKey $ApiKey -Method "GET"

        if (-not $Result.Success) {
            Write-LevelLog "Failed to fetch groups: $($Result.Error)" -Level "ERROR"
            return $null
        }

        $AllGroups += $Result.Data.data

        # Handle pagination
        $StartingAfter = if ($Result.Data.has_more -and $Result.Data.data.Count -gt 0) {
            $Result.Data.data[-1].id
        } else {
            $null
        }
    } while ($StartingAfter)

    return $AllGroups
}

<#
.SYNOPSIS
    Retrieves devices from Level.io with optional filtering and pagination.

.DESCRIPTION
    Fetches devices from the Level.io API with support for:
    - Filtering by group ID
    - Including network interface data (for WOL, etc.)
    - Automatic pagination for large result sets

.PARAMETER ApiKey
    Level.io API key for authentication. Typically "{{cf_apikey}}".

.PARAMETER GroupId
    Optional group ID to filter devices. If not specified, returns all devices.

.PARAMETER IncludeNetworkInterfaces
    Switch to include network interface data in the response.
    Required for Wake-on-LAN functionality.

.PARAMETER BaseUrl
    Base URL for the Level.io API. Default: "https://api.level.io/v2"

.OUTPUTS
    Array of device objects from the Level.io API, or $null on failure.

.EXAMPLE
    # Get all devices
    $Devices = Get-LevelDevices -ApiKey "{{cf_apikey}}"

.EXAMPLE
    # Get devices in a specific group with network interfaces
    $Devices = Get-LevelDevices -ApiKey $ApiKey -GroupId $GroupId -IncludeNetworkInterfaces

.EXAMPLE
    # Get devices from multiple groups
    $AllDevices = @()
    foreach ($GroupId in $GroupIds) {
        $AllDevices += Get-LevelDevices -ApiKey $ApiKey -GroupId $GroupId
    }
#>
function Get-LevelDevices {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $false)]
        [string]$GroupId,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeNetworkInterfaces,

        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://api.level.io/v2"
    )

    $AllDevices = @()
    $StartingAfter = $null

    do {
        $Uri = "$BaseUrl/devices?limit=100"

        if ($GroupId) {
            $Uri += "&group_id=$GroupId"
        }

        if ($IncludeNetworkInterfaces) {
            $Uri += "&include_network_interfaces=true"
        }

        if ($StartingAfter) {
            $Uri += "&starting_after=$StartingAfter"
        }

        $Result = Invoke-LevelApiCall -Uri $Uri -ApiKey $ApiKey -Method "GET"

        if (-not $Result.Success) {
            Write-LevelLog "Failed to fetch devices: $($Result.Error)" -Level "ERROR"
            return $null
        }

        $AllDevices += $Result.Data.data

        # Handle pagination
        $StartingAfter = if ($Result.Data.has_more -and $Result.Data.data.Count -gt 0) {
            $Result.Data.data[-1].id
        } else {
            $null
        }
    } while ($StartingAfter)

    return $AllDevices
}

<#
.SYNOPSIS
    Finds a device in Level.io by hostname.

.DESCRIPTION
    Searches for a device by its hostname, automatically handling pagination
    to search through all devices if necessary.

.PARAMETER ApiKey
    Level.io API key for authentication. Typically "{{cf_apikey}}".

.PARAMETER Hostname
    The hostname to search for. Case-sensitive exact match.

.PARAMETER BaseUrl
    Base URL for the Level.io API. Default: "https://api.level.io/v2"

.OUTPUTS
    Device object if found, $null if not found or on error.

.EXAMPLE
    $Device = Find-LevelDevice -ApiKey "{{cf_apikey}}" -Hostname $env:COMPUTERNAME
    if ($Device) {
        Write-LevelLog "Found device in group: $($Device.group_id)"
    }

.EXAMPLE
    # Find current device and get its group
    $CurrentDevice = Find-LevelDevice -ApiKey $ApiKey -Hostname "{{level_device_hostname}}"
#>
function Find-LevelDevice {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $true)]
        [string]$Hostname,

        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://api.level.io/v2"
    )

    $StartingAfter = $null

    do {
        $Uri = "$BaseUrl/devices?limit=100"
        if ($StartingAfter) {
            $Uri += "&starting_after=$StartingAfter"
        }

        $Result = Invoke-LevelApiCall -Uri $Uri -ApiKey $ApiKey -Method "GET"

        if (-not $Result.Success) {
            Write-LevelLog "Failed to search for device: $($Result.Error)" -Level "ERROR"
            return $null
        }

        $Device = $Result.Data.data | Where-Object { $_.hostname -eq $Hostname } | Select-Object -First 1

        if ($Device) {
            return $Device
        }

        # Handle pagination
        $StartingAfter = if ($Result.Data.has_more -and $Result.Data.data.Count -gt 0) {
            $Result.Data.data[-1].id
        } else {
            $null
        }
    } while ($StartingAfter)

    return $null
}

<#
.SYNOPSIS
    Gets a device by ID from Level.io.

.DESCRIPTION
    Retrieves a single device by its ID. Returns the full device object
    including tag_ids array.

.PARAMETER ApiKey
    Level.io API key for authentication.

.PARAMETER DeviceId
    The ID of the device to retrieve.

.PARAMETER BaseUrl
    Base URL for the Level.io API. Default: "https://api.level.io/v2"

.OUTPUTS
    Device object if found, $null if not found or on error.

.EXAMPLE
    $Device = Get-LevelDeviceById -ApiKey $ApiKey -DeviceId "dev_123"
#>
function Get-LevelDeviceById {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $true)]
        [string]$DeviceId,

        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://api.level.io/v2"
    )

    $Uri = "$BaseUrl/devices/$DeviceId"
    $Result = Invoke-LevelApiCall -Uri $Uri -ApiKey $ApiKey -Method "GET"

    if (-not $Result.Success) {
        Write-LevelLog "Failed to get device by ID: $($Result.Error)" -Level "ERROR"
        return $null
    }

    # Check if response has data wrapper (like list endpoints) or is direct device object
    if ($Result.Data.data -and $Result.Data.data.id) {
        # Response is wrapped: { data: { ...device... } }
        return $Result.Data.data
    } elseif ($Result.Data.id) {
        # Response is direct device object
        return $Result.Data
    } else {
        Write-LevelLog "Unexpected device response structure" -Level "WARN"
        return $Result.Data
    }
}

<#
.SYNOPSIS
    Gets the tag names for a device from Level.io.

.DESCRIPTION
    Retrieves the tag names for a device by fetching the device object
    and resolving tag_ids to tag names. Useful for debugging tag operations.

.PARAMETER ApiKey
    Level.io API key for authentication.

.PARAMETER DeviceId
    The ID of the device to get tags for.

.PARAMETER BaseUrl
    Base URL for the Level.io API. Default: "https://api.level.io/v2"

.OUTPUTS
    Array of tag names, or empty array on error.

.EXAMPLE
    $Tags = Get-LevelDeviceTagNames -ApiKey $ApiKey -DeviceId $Device.id
    Write-Host "Device has tags: $($Tags -join ', ')"
#>
function Get-LevelDeviceTagNames {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $true)]
        [string]$DeviceId,

        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://api.level.io/v2"
    )

    # Get the device - API returns tags array directly with tag names
    $Device = Get-LevelDeviceById -ApiKey $ApiKey -DeviceId $DeviceId -BaseUrl $BaseUrl
    if (-not $Device) {
        Write-LevelLog "Get-LevelDeviceTagNames: No device returned" -Level "DEBUG"
        return @()
    }

    # API returns "tags" array with tag names directly (not tag_ids)
    $Tags = @($Device.tags)  # Force to array even if single value or null
    if ($Tags.Count -eq 0) {
        Write-LevelLog "Device has no tags" -Level "DEBUG"
        return @()
    }

    Write-LevelLog "Device has $($Tags.Count) tags: $($Tags -join ', ')" -Level "DEBUG"
    return $Tags
}

# ============================================================
# LEVEL.IO TAG MANAGEMENT
# ============================================================

<#
.SYNOPSIS
    Retrieves all tags from Level.io with automatic pagination.

.DESCRIPTION
    Fetches all tags from the Level.io API, automatically handling pagination.
    Tags are used to categorize devices and trigger policy actions.

.PARAMETER ApiKey
    Level.io API key for authentication.

.PARAMETER BaseUrl
    Base URL for the Level.io API. Default: "https://api.level.io/v2"

.OUTPUTS
    Array of tag objects from the Level.io API, or $null on failure.
    Each tag object contains: id, name, and other properties.

.EXAMPLE
    $Tags = Get-LevelTags -ApiKey "{{cf_apikey}}"
    Write-LevelLog "Found $($Tags.Count) tags"
#>
function Get-LevelTags {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://api.level.io/v2"
    )

    $AllTags = @()
    $StartingAfter = $null

    do {
        $Uri = "$BaseUrl/tags?limit=100"
        if ($StartingAfter) {
            $Uri += "&starting_after=$StartingAfter"
        }

        $Result = Invoke-LevelApiCall -Uri $Uri -ApiKey $ApiKey -Method "GET"

        if (-not $Result.Success) {
            Write-LevelLog "Failed to fetch tags: $($Result.Error)" -Level "ERROR"
            return $null
        }

        $AllTags += $Result.Data.data

        # Handle pagination
        $StartingAfter = if ($Result.Data.has_more -and $Result.Data.data.Count -gt 0) {
            $Result.Data.data[-1].id
        } else {
            $null
        }
    } while ($StartingAfter)

    return $AllTags
}

<#
.SYNOPSIS
    Finds a tag in Level.io by name.

.DESCRIPTION
    Searches for a tag by its name. Handles emoji tags by searching through
    all tags and matching the name exactly (case-sensitive).

.PARAMETER ApiKey
    Level.io API key for authentication.

.PARAMETER TagName
    The tag name to search for (e.g., "huntress" or full emoji tag).

.PARAMETER BaseUrl
    Base URL for the Level.io API. Default: "https://api.level.io/v2"

.OUTPUTS
    Tag object if found, $null if not found or on error.

.EXAMPLE
    $Tag = Find-LevelTag -ApiKey $ApiKey -TagName "huntress"
    if ($Tag) {
        Write-LevelLog "Found tag ID: $($Tag.id)"
    }
#>
function Find-LevelTag {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $true)]
        [string]$TagName,

        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://api.level.io/v2"
    )

    $Tags = Get-LevelTags -ApiKey $ApiKey -BaseUrl $BaseUrl
    if (-not $Tags) {
        return $null
    }

    # Case-insensitive match
    $MatchedTag = $Tags | Where-Object { $_.name -ieq $TagName } | Select-Object -First 1
    return $MatchedTag
}

<#
.SYNOPSIS
    Creates a new tag in Level.io.

.DESCRIPTION
    Creates a new tag using the Level.io API.
    Uses POST /v2/tags endpoint.

.PARAMETER ApiKey
    Level.io API key for authentication.

.PARAMETER TagName
    The name of the tag to create.

.PARAMETER BaseUrl
    Base URL for the Level.io API. Default: "https://api.level.io/v2"

.OUTPUTS
    The created tag object on success, $null on failure.

.EXAMPLE
    $Tag = New-LevelTag -ApiKey $ApiKey -TagName "✅UNCHECKY"
#>
function New-LevelTag {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $true)]
        [string]$TagName,

        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://api.level.io/v2"
    )

    $Uri = "$BaseUrl/tags"
    $Body = @{ name = $TagName }

    $Result = Invoke-LevelApiCall -Uri $Uri -ApiKey $ApiKey -Method "POST" -Body $Body

    if (-not $Result.Success) {
        Write-LevelLog "Failed to create tag '$TagName': $($Result.Error)" -Level "ERROR"
        return $null
    }

    Write-LevelLog "Created tag '$TagName'" -Level "SUCCESS"
    return $Result.Data
}

<#
.SYNOPSIS
    Adds a tag to a device in Level.io.

.DESCRIPTION
    Adds the specified tag to a device using the Level.io API.
    Uses POST /v2/tags/{tag_id}/devices endpoint.

.PARAMETER ApiKey
    Level.io API key for authentication.

.PARAMETER TagId
    The ID of the tag to add.

.PARAMETER DeviceId
    The ID of the device to add the tag to.

.PARAMETER BaseUrl
    Base URL for the Level.io API. Default: "https://api.level.io/v2"

.OUTPUTS
    $true on success, $false on failure.

.EXAMPLE
    $Success = Add-LevelTagToDevice -ApiKey $ApiKey -TagId $Tag.id -DeviceId $Device.id
#>
function Add-LevelTagToDevice {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $true)]
        [string]$TagId,

        [Parameter(Mandatory = $true)]
        [string]$DeviceId,

        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://api.level.io/v2"
    )

    $Uri = "$BaseUrl/tags/$TagId/devices"
    # API expects device_ids as an array (plural)
    $Body = @{ device_ids = @($DeviceId) }

    Write-LevelLog "POST $Uri (TagId: $TagId, DeviceId: $DeviceId)" -Level "DEBUG"

    $Result = Invoke-LevelApiCall -Uri $Uri -ApiKey $ApiKey -Method "POST" -Body $Body

    if (-not $Result.Success) {
        # 422 can mean:
        # - Device already has this tag (success for idempotent operation)
        # - Invalid request (actual failure)
        # Check the response body to distinguish
        if ($Result.StatusCode -eq 422) {
            $ResponseInfo = if ($Result.ResponseBody) { " - $($Result.ResponseBody)" } else { "" }
            Write-LevelLog "API returned 422$ResponseInfo" -Level "DEBUG"
            # Treat 422 as success (idempotent - tag is on device either way)
            return $true
        }
        Write-LevelLog "Failed to add tag to device: $($Result.Error)" -Level "ERROR"
        return $false
    }

    return $true
}

<#
.SYNOPSIS
    Removes a tag from a device in Level.io.

.DESCRIPTION
    Removes the specified tag from a device using the Level.io API.
    Uses DELETE /v2/tags/{tag_id}/devices endpoint with device_id in body.

.PARAMETER ApiKey
    Level.io API key for authentication.

.PARAMETER TagId
    The ID of the tag to remove.

.PARAMETER DeviceId
    The ID of the device to remove the tag from.

.PARAMETER BaseUrl
    Base URL for the Level.io API. Default: "https://api.level.io/v2"

.OUTPUTS
    $true on success, $false on failure.

.EXAMPLE
    $Success = Remove-LevelTagFromDevice -ApiKey $ApiKey -TagId $Tag.id -DeviceId $Device.id
#>
function Remove-LevelTagFromDevice {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $true)]
        [string]$TagId,

        [Parameter(Mandatory = $true)]
        [string]$DeviceId,

        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://api.level.io/v2"
    )

    $Uri = "$BaseUrl/tags/$TagId/devices"
    # API expects device_ids as an array (plural)
    $Body = @{ device_ids = @($DeviceId) }

    Write-LevelLog "DELETE $Uri (TagId: $TagId, DeviceId: $DeviceId)" -Level "DEBUG"

    $Result = Invoke-LevelApiCall -Uri $Uri -ApiKey $ApiKey -Method "DELETE" -Body $Body

    if (-not $Result.Success) {
        # 422 can mean:
        # - Device doesn't have this tag (success for idempotent operation)
        # - Invalid request (actual failure)
        if ($Result.StatusCode -eq 422) {
            $ResponseInfo = if ($Result.ResponseBody) { " - $($Result.ResponseBody)" } else { "" }
            Write-LevelLog "API returned 422$ResponseInfo" -Level "DEBUG"
            # Treat 422 as success (idempotent - tag is off device either way)
            return $true
        }
        Write-LevelLog "Failed to remove tag from device: $($Result.Error)" -Level "ERROR"
        return $false
    }

    return $true
}

<#
.SYNOPSIS
    Adds a policy tag to the current device after a successful action.

.DESCRIPTION
    High-level function that finds a tag by name (with emoji prefix) and adds
    it to the current device. Used to set status tags after policy actions
    complete successfully (e.g., adding Has tag after install).

    This function:
    1. Finds the current device by hostname
    2. Finds the tag by name
    3. Adds the tag to the device

.PARAMETER ApiKey
    Level.io API key for authentication.

.PARAMETER TagName
    The software name (e.g., "huntress" - emoji will be prefixed).

.PARAMETER EmojiPrefix
    The emoji prefix for the tag (e.g., "Install", "Remove", "Has").
    Will be converted to the appropriate emoji character.

.PARAMETER DeviceHostname
    The hostname of the current device. Typically "{{level_device_hostname}}".

.PARAMETER BaseUrl
    Base URL for the Level.io API. Default: "https://api.level.io/v2"

.OUTPUTS
    $true on success, $false on failure.

.EXAMPLE
    # Add the has tag after successful install
    Add-LevelPolicyTag -ApiKey $ApiKey -TagName "huntress" -EmojiPrefix "Has" -DeviceHostname $DeviceHostname
#>
function Add-LevelPolicyTag {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $true)]
        [string]$TagName,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Install", "Remove", "Reinstall", "Pin", "Has")]
        [string]$EmojiPrefix,

        [Parameter(Mandatory = $true)]
        [string]$DeviceHostname,

        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://api.level.io/v2"
    )

    # Get emoji characters from centralized source (5-tag model per POLICY-TAGS.md)
    $Emojis = Get-EmojiLiterals
    $EmojiChar = switch ($EmojiPrefix) {
        "Install"   { $Emojis.Pray }      # U+1F64F Pray - Install override
        "Remove"    { $Emojis.Prohibit }  # U+1F6AB Prohibit - Remove override
        "Reinstall" { $Emojis.Arrows }    # U+1F504 Arrows - Reinstall override
        "Pin"       { $Emojis.Pin }       # U+1F4CC Pushpin - Pin override
        "Has"       { $Emojis.Check }     # U+2705 Checkmark - Installed status
    }

    $FullTagName = "$EmojiChar$TagName"
    # Show tag bytes for debugging emoji issues
    $TagBytes = [System.Text.Encoding]::UTF8.GetBytes($FullTagName)
    $TagBytesHex = ($TagBytes | ForEach-Object { "{0:X2}" -f $_ }) -join " "
    Write-LevelLog "Adding tag '$FullTagName' (bytes: $TagBytesHex) to device..." -Level "DEBUG"

    # Find the device
    $Device = Find-LevelDevice -ApiKey $ApiKey -Hostname $DeviceHostname -BaseUrl $BaseUrl
    if (-not $Device) {
        Write-LevelLog "Could not find device '$DeviceHostname' in Level.io" -Level "WARN"
        return $false
    }

    # Find the tag, create if doesn't exist
    $Tag = Find-LevelTag -ApiKey $ApiKey -TagName $FullTagName -BaseUrl $BaseUrl
    if (-not $Tag) {
        Write-LevelLog "Tag '$FullTagName' not found in Level.io - creating..." -Level "DEBUG"
        $Tag = New-LevelTag -ApiKey $ApiKey -TagName $FullTagName -BaseUrl $BaseUrl
        if (-not $Tag) {
            Write-LevelLog "Failed to create tag '$FullTagName'" -Level "ERROR"
            return $false
        }
        Write-LevelLog "Created tag with ID: $($Tag.id)" -Level "DEBUG"
    } else {
        Write-LevelLog "Found existing tag with ID: $($Tag.id)" -Level "DEBUG"
    }

    # Add the tag
    $Success = Add-LevelTagToDevice -ApiKey $ApiKey -TagId $Tag.id -DeviceId $Device.id -BaseUrl $BaseUrl
    if ($Success) {
        Write-LevelLog "Added tag '$FullTagName' to device" -Level "SUCCESS"
    }

    return $Success
}

<#
.SYNOPSIS
    Removes a policy tag from the current device after a successful action.

.DESCRIPTION
    High-level function that finds a tag by name (with emoji prefix) and removes
    it from the current device. Used to auto-cleanup trigger tags after policy
    actions complete successfully.

    This function:
    1. Finds the current device by hostname
    2. Finds the tag by name
    3. Removes the tag from the device

.PARAMETER ApiKey
    Level.io API key for authentication.

.PARAMETER TagName
    The full tag name to remove (e.g., "huntress" - emoji will be prefixed).

.PARAMETER EmojiPrefix
    The emoji prefix for the tag (e.g., "Install", "Remove", "Has").
    Will be converted to the appropriate emoji character.

.PARAMETER DeviceHostname
    The hostname of the current device. Typically "{{level_device_hostname}}".

.PARAMETER BaseUrl
    Base URL for the Level.io API. Default: "https://api.level.io/v2"

.OUTPUTS
    $true on success, $false on failure.

.EXAMPLE
    # Remove the install tag after successful install
    Remove-LevelPolicyTag -ApiKey $ApiKey -TagName "huntress" -EmojiPrefix "Install" -DeviceHostname $DeviceHostname

.EXAMPLE
    # Remove the has tag when software is removed
    Remove-LevelPolicyTag -ApiKey $ApiKey -TagName "huntress" -EmojiPrefix "Has" -DeviceHostname $DeviceHostname
#>
function Remove-LevelPolicyTag {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $true)]
        [string]$TagName,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Install", "Remove", "Reinstall", "Pin", "Has")]
        [string]$EmojiPrefix,

        [Parameter(Mandatory = $true)]
        [string]$DeviceHostname,

        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://api.level.io/v2"
    )

    # Get emoji characters from centralized source (5-tag model per POLICY-TAGS.md)
    $Emojis = Get-EmojiLiterals
    $EmojiChar = switch ($EmojiPrefix) {
        "Install"   { $Emojis.Pray }      # U+1F64F Pray - Install override
        "Remove"    { $Emojis.Prohibit }  # U+1F6AB Prohibit - Remove override
        "Reinstall" { $Emojis.Arrows }    # U+1F504 Arrows - Reinstall override
        "Pin"       { $Emojis.Pin }       # U+1F4CC Pushpin - Pin override
        "Has"       { $Emojis.Check }     # U+2705 Checkmark - Installed status
    }

    $FullTagName = "$EmojiChar$TagName"
    # Show tag bytes for debugging emoji issues
    $TagBytes = [System.Text.Encoding]::UTF8.GetBytes($FullTagName)
    $TagBytesHex = ($TagBytes | ForEach-Object { "{0:X2}" -f $_ }) -join " "
    Write-LevelLog "Removing tag '$FullTagName' (bytes: $TagBytesHex) from device..." -Level "DEBUG"

    # Find the device
    $Device = Find-LevelDevice -ApiKey $ApiKey -Hostname $DeviceHostname -BaseUrl $BaseUrl
    if (-not $Device) {
        Write-LevelLog "Could not find device '$DeviceHostname' in Level.io" -Level "WARN"
        return $false
    }

    # Find the tag
    $Tag = Find-LevelTag -ApiKey $ApiKey -TagName $FullTagName -BaseUrl $BaseUrl
    if (-not $Tag) {
        Write-LevelLog "Tag '$FullTagName' not found in Level.io (may not exist)" -Level "DEBUG"
        return $true  # Not an error - tag may not exist
    }
    Write-LevelLog "Found tag with ID: $($Tag.id)" -Level "DEBUG"

    # Remove the tag
    $Success = Remove-LevelTagFromDevice -ApiKey $ApiKey -TagId $Tag.id -DeviceId $Device.id -BaseUrl $BaseUrl
    if ($Success) {
        Write-LevelLog "Removed tag '$FullTagName' from device" -Level "SUCCESS"
    }

    return $Success
}

# ============================================================
# CUSTOM FIELD MANAGEMENT
# ============================================================

<#
.SYNOPSIS
    Retrieves all custom field definitions from Level.io with pagination.

.DESCRIPTION
    Fetches all custom field definitions from the Level.io API, automatically
    handling pagination. Used for policy auto-bootstrapping.

.PARAMETER ApiKey
    Level.io API key for authentication.

.PARAMETER BaseUrl
    Base URL for the Level.io API. Default: "https://api.level.io/v2"

.OUTPUTS
    Array of custom field objects, or $null on failure.
    Each object contains: id, name, reference, admin_only, etc.

.EXAMPLE
    $Fields = Get-LevelCustomFields -ApiKey "{{cf_apikey}}"
    $PolicyField = $Fields | Where-Object { $_.name -eq "policy_unchecky" }
#>
function Get-LevelCustomFields {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://api.level.io/v2"
    )

    $AllFields = @()
    $StartingAfter = $null

    do {
        $Uri = "$BaseUrl/custom_fields?limit=100"
        if ($StartingAfter) {
            $Uri += "&starting_after=$StartingAfter"
        }

        $Result = Invoke-LevelApiCall -Uri $Uri -ApiKey $ApiKey -Method "GET"

        if (-not $Result.Success) {
            Write-LevelLog "Failed to fetch custom fields: $($Result.Error)" -Level "ERROR"
            return $null
        }

        $Data = $Result.Data
        $Fields = if ($Data.data) { $Data.data } else { @($Data) }

        if ($Fields -and $Fields.Count -gt 0) {
            $AllFields += $Fields

            # Handle pagination
            $HasMore = $Data.has_more -eq $true
            if ($HasMore) {
                $StartingAfter = $Fields[-1].id
            } else {
                break
            }
        } else {
            break
        }
    } while ($true)

    return $AllFields
}

<#
.SYNOPSIS
    Finds a custom field by name or reference.

.DESCRIPTION
    Searches through existing custom fields to find one matching
    the specified name or reference property.

.PARAMETER ApiKey
    Level.io API key for authentication.

.PARAMETER FieldName
    The name or reference to search for (e.g., "policy_unchecky").

.PARAMETER BaseUrl
    Base URL for the Level.io API. Default: "https://api.level.io/v2"

.OUTPUTS
    Custom field object if found, $null if not found.

.EXAMPLE
    $Field = Find-LevelCustomField -ApiKey $ApiKey -FieldName "policy_unchecky"
    if ($Field) {
        Write-LevelLog "Found field: $($Field.id)"
    }
#>
function Find-LevelCustomField {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $true)]
        [string]$FieldName,

        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://api.level.io/v2"
    )

    $Fields = Get-LevelCustomFields -ApiKey $ApiKey -BaseUrl $BaseUrl
    if (-not $Fields) {
        return $null
    }

    # Match by name or reference (case-insensitive)
    $Matched = $Fields | Where-Object {
        $_.name -ieq $FieldName -or $_.reference -ieq $FieldName
    } | Select-Object -First 1

    return $Matched
}

<#
.SYNOPSIS
    Creates a new custom field in Level.io.

.DESCRIPTION
    Creates a new custom field definition. Used for auto-bootstrapping
    when a policy custom field doesn't exist.

.PARAMETER ApiKey
    Level.io API key for authentication.

.PARAMETER Name
    The name for the custom field (e.g., "policy_unchecky").

.PARAMETER DefaultValue
    Optional default value for the field.

.PARAMETER AdminOnly
    If $true, field is only visible to admins. Default: $false

.PARAMETER BaseUrl
    Base URL for the Level.io API. Default: "https://api.level.io/v2"

.OUTPUTS
    Created custom field object on success, $null on failure.

.EXAMPLE
    $Field = New-LevelCustomField -ApiKey $ApiKey -Name "policy_unchecky" -DefaultValue ""
#>
function New-LevelCustomField {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [string]$DefaultValue = "",

        [Parameter(Mandatory = $false)]
        [bool]$AdminOnly = $false,

        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://api.level.io/v2"
    )

    $Body = @{
        name       = $Name
        admin_only = $AdminOnly
    }

    if (-not [string]::IsNullOrWhiteSpace($DefaultValue)) {
        $Body.default_value = $DefaultValue
    }

    Write-LevelLog "Creating custom field: $Name" -Level "DEBUG"
    $Result = Invoke-LevelApiCall -Uri "$BaseUrl/custom_fields" -ApiKey $ApiKey -Method "POST" -Body $Body

    if ($Result.Success) {
        Write-LevelLog "Created custom field: $Name" -Level "SUCCESS"
        return $Result.Data
    }
    else {
        Write-LevelLog "Failed to create custom field '$Name': $($Result.Error)" -Level "ERROR"
        return $null
    }
}

<#
.SYNOPSIS
    Sets a custom field value on an entity (organization, folder, or device).

.DESCRIPTION
    Updates the custom field value for a specific entity. Used for setting
    device-level policy values during auto-bootstrapping.

.PARAMETER ApiKey
    Level.io API key for authentication.

.PARAMETER EntityType
    Type of entity: "organization", "folder", or "device".

.PARAMETER EntityId
    The ID of the entity to update.

.PARAMETER FieldReference
    The reference/key of the custom field (e.g., "cf_policy_unchecky").

.PARAMETER Value
    The value to set.

.PARAMETER BaseUrl
    Base URL for the Level.io API. Default: "https://api.level.io/v2"

.OUTPUTS
    $true on success, $false on failure.

.EXAMPLE
    Set-LevelCustomFieldValue -ApiKey $ApiKey -EntityType "device" -EntityId $Device.id `
        -FieldReference "cf_policy_unchecky" -Value "install"
#>
function Set-LevelCustomFieldValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $true)]
        [ValidateSet("organization", "folder", "device")]
        [string]$EntityType,

        [Parameter(Mandatory = $true)]
        [string]$EntityId,

        [Parameter(Mandatory = $true)]
        [string]$FieldReference,

        [Parameter(Mandatory = $true)]
        [string]$Value,

        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://api.level.io/v2"
    )

    # First, find the custom field ID by name
    $Fields = Get-LevelCustomFields -ApiKey $ApiKey -BaseUrl $BaseUrl
    $Field = $Fields | Where-Object { $_.name -eq $FieldReference }

    if (-not $Field) {
        Write-LevelLog "ALERT: Custom field '$FieldReference' not found" -Level "ERROR"
        return $false
    }

    Write-LevelLog "Found custom field '$FieldReference' with ID: $($Field.id)" -Level "DEBUG"

    # Use the custom_field_values endpoint with assigned_to_id for entity-specific values
    $Body = @{
        custom_field_id = $Field.id
        assigned_to_id  = $EntityId
        value           = $Value
    }

    Write-LevelLog "PATCH $BaseUrl/custom_field_values with body: $($Body | ConvertTo-Json -Compress)" -Level "DEBUG"
    $Result = Invoke-LevelApiCall -Uri "$BaseUrl/custom_field_values" -ApiKey $ApiKey -Method "PATCH" -Body $Body

    if ($Result.Success) {
        Write-LevelLog "Set $EntityType custom field '$FieldReference' = '$Value'" -Level "DEBUG"
        return $true
    }
    else {
        Write-LevelLog "ALERT: Failed to set custom field '$FieldReference': $($Result.Error)" -Level "ERROR"
        return $false
    }
}

<#
.SYNOPSIS
    Ensures policy infrastructure exists for a software package.

.DESCRIPTION
    Auto-bootstrapping function that:
    1. Checks if policy custom field exists (e.g., "policy_unchecky")
    2. Creates the custom field if it doesn't exist
    3. Sets the device-level value to trigger installation

    This allows scripts to be deployed without manual setup of custom fields.

.PARAMETER ApiKey
    Level.io API key for authentication.

.PARAMETER SoftwareName
    The software name (e.g., "unchecky").

.PARAMETER DeviceHostname
    The hostname of the current device.

.PARAMETER DefaultAction
    Default action to set if creating new policy. Default: "install"

.PARAMETER BaseUrl
    Base URL for the Level.io API. Default: "https://api.level.io/v2"

.OUTPUTS
    Hashtable with:
    - Success: $true if ready to proceed
    - CustomFieldId: ID of the policy custom field
    - CustomFieldRef: Reference key (e.g., "cf_policy_unchecky")
    - Action: The resolved action for this device

.EXAMPLE
    $Bootstrap = Initialize-LevelSoftwarePolicy -ApiKey $ApiKey -SoftwareName "unchecky" `
        -DeviceHostname $DeviceHostname
    if ($Bootstrap.Success) {
        Write-LevelLog "Policy action: $($Bootstrap.Action)"
    }
#>
function Initialize-LevelSoftwarePolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $true)]
        [string]$SoftwareName,

        [Parameter(Mandatory = $true)]
        [string]$DeviceHostname,

        [Parameter(Mandatory = $false)]
        [string]$DefaultAction = "install",

        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://api.level.io/v2"
    )

    $FieldName = "policy_$($SoftwareName.ToLower())"
    Write-LevelLog "Checking policy infrastructure for '$SoftwareName'..." -Level "DEBUG"

    # Step 1: Check if custom field exists
    $ExistingField = Find-LevelCustomField -ApiKey $ApiKey -FieldName $FieldName -BaseUrl $BaseUrl

    if (-not $ExistingField) {
        # Step 2: Create custom field
        Write-LevelLog "Policy custom field '$FieldName' not found - creating..." -Level "INFO"
        $ExistingField = New-LevelCustomField -ApiKey $ApiKey -Name $FieldName -DefaultValue "" -BaseUrl $BaseUrl

        if (-not $ExistingField) {
            Write-LevelLog "Failed to create policy custom field" -Level "ERROR"
            return @{ Success = $false; Error = "Failed to create custom field" }
        }
    }

    # Determine the reference key (usually "cf_<name>")
    $FieldRef = $ExistingField.reference
    if (-not $FieldRef) {
        # Fallback - construct from name
        $FieldRef = "cf_$($FieldName -replace '[^a-zA-Z0-9_]', '_')"
    }

    # Step 3: Find the current device
    $Device = Find-LevelDevice -ApiKey $ApiKey -Hostname $DeviceHostname -BaseUrl $BaseUrl
    if (-not $Device) {
        Write-LevelLog "Could not find device '$DeviceHostname' in Level.io" -Level "WARN"
        return @{ Success = $false; Error = "Device not found" }
    }

    # Step 4: Check current device value
    $CurrentValue = ""
    if ($Device.custom_fields -and $Device.custom_fields.$FieldRef) {
        $CurrentValue = $Device.custom_fields.$FieldRef
    }

    # Step 5: If no value, set the default action on the device
    if ([string]::IsNullOrWhiteSpace($CurrentValue)) {
        Write-LevelLog "No policy value set on device - setting to '$DefaultAction'" -Level "INFO"
        $SetResult = Set-LevelCustomFieldValue -ApiKey $ApiKey -EntityType "device" `
            -EntityId $Device.id -FieldReference $FieldRef -Value $DefaultAction -BaseUrl $BaseUrl

        if ($SetResult) {
            $CurrentValue = $DefaultAction
        }
    }

    return @{
        Success        = $true
        CustomFieldId  = $ExistingField.id
        CustomFieldRef = $FieldRef
        Action         = $CurrentValue
        DeviceId       = $Device.id
    }
}

<#
.SYNOPSIS
    Ensures all required tags and custom fields exist for a software policy.

.DESCRIPTION
    Auto-creates the infrastructure needed for a software policy script:
    - 5 policy tags: Install, Remove, Pin, Reinstall, Has/Installed
    - Custom fields: policy_<software> and policy_<software>_url

    This function is idempotent - it only creates items that don't exist.
    Call it on first run to bootstrap the policy infrastructure.

.PARAMETER ApiKey
    Level.io API key for authentication.

.PARAMETER SoftwareName
    The software name (e.g., "unchecky", "huntress").

.PARAMETER RequireUrl
    If $true, creates the policy_<software>_url custom field. Default: $false

.PARAMETER BaseUrl
    Base URL for the Level.io API. Default: "https://api.level.io/v2"

.OUTPUTS
    Hashtable with:
    - Success: $true if infrastructure is ready
    - TagsCreated: Number of tags created
    - FieldsCreated: Number of custom fields created
    - Error: Error message if failed

.EXAMPLE
    $Result = Initialize-SoftwarePolicyInfrastructure -ApiKey $ApiKey -SoftwareName "unchecky" -RequireUrl $true
    if ($Result.Success) {
        Write-LevelLog "Policy infrastructure ready"
    }
#>
function Initialize-SoftwarePolicyInfrastructure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $true)]
        [string]$SoftwareName,

        [Parameter(Mandatory = $false)]
        [bool]$RequireUrl = $false,

        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://api.level.io/v2"
    )

    $SoftwareName = $SoftwareName.ToLower()
    $SoftwareNameUpper = $SoftwareName.ToUpper()
    $TagsCreated = 0
    $FieldsCreated = 0

    Write-LevelLog "Initializing policy infrastructure for '$SoftwareName'..." -Level "INFO"

    # ================================================================
    # STEP 1: Create policy tags (5-tag model)
    # ================================================================
    # Tag prefixes with their emoji characters
    # U+1F64F = Pray (Install), U+1F6AB = Prohibited (Remove), U+1F4CC = Pushpin (Pin)
    # U+1F504 = Arrows (Reinstall), U+2705 = Checkmark (Has/Installed)
    $PolicyTagPrefixes = @(
        @{ Emoji = [char]::ConvertFromUtf32(0x1F64F); Name = "Install" }
        @{ Emoji = [char]::ConvertFromUtf32(0x1F6AB); Name = "Remove" }
        @{ Emoji = [char]::ConvertFromUtf32(0x1F4CC); Name = "Pin" }
        @{ Emoji = [char]::ConvertFromUtf32(0x1F504); Name = "Reinstall" }
        @{ Emoji = [char]0x2705;                      Name = "Has" }
    )

    # Get existing tags
    $ExistingTags = Get-LevelTags -ApiKey $ApiKey -BaseUrl $BaseUrl
    if ($null -eq $ExistingTags) {
        Write-LevelLog "Could not fetch existing tags - API may not have Tags permission" -Level "WARN"
        # Continue anyway - will try to create tags
        $ExistingTags = @()
    }
    $ExistingTagNames = @($ExistingTags | ForEach-Object { $_.name })

    foreach ($Prefix in $PolicyTagPrefixes) {
        $FullTagName = "$($Prefix.Emoji)$SoftwareNameUpper"

        if ($ExistingTagNames -contains $FullTagName) {
            Write-LevelLog "Tag '$FullTagName' already exists" -Level "DEBUG"
        }
        else {
            $NewTag = New-LevelTag -ApiKey $ApiKey -TagName $FullTagName -BaseUrl $BaseUrl
            if ($NewTag) {
                Write-LevelLog "Created tag: $FullTagName" -Level "SUCCESS"
                $TagsCreated++
            }
            else {
                Write-LevelLog "Failed to create tag: $FullTagName" -Level "WARN"
            }
        }
    }

    # ================================================================
    # STEP 2: Create required system tags (checkmark and cross)
    # ================================================================
    $SystemTags = @(
        [char]0x2705  # Checkmark - device verified/managed
        [char]0x274C  # Cross - device excluded
    )

    foreach ($SystemTag in $SystemTags) {
        $TagName = [string]$SystemTag
        if ($ExistingTagNames -contains $TagName) {
            Write-LevelLog "System tag '$TagName' already exists" -Level "DEBUG"
        }
        else {
            $NewTag = New-LevelTag -ApiKey $ApiKey -TagName $TagName -BaseUrl $BaseUrl
            if ($NewTag) {
                Write-LevelLog "Created system tag: $TagName" -Level "SUCCESS"
                $TagsCreated++
            }
        }
    }

    # ================================================================
    # STEP 3: Create custom fields
    # ================================================================
    # Policy field (e.g., policy_unchecky)
    $PolicyFieldName = "policy_$SoftwareName"
    $ExistingPolicyField = Find-LevelCustomField -ApiKey $ApiKey -FieldName $PolicyFieldName -BaseUrl $BaseUrl

    if (-not $ExistingPolicyField) {
        Write-LevelLog "Creating custom field: $PolicyFieldName" -Level "INFO"
        $NewField = New-LevelCustomField -ApiKey $ApiKey -Name $PolicyFieldName -DefaultValue "" -BaseUrl $BaseUrl
        if ($NewField) {
            Write-LevelLog "Created custom field: $PolicyFieldName" -Level "SUCCESS"
            $FieldsCreated++
        }
        else {
            Write-LevelLog "Failed to create custom field: $PolicyFieldName" -Level "ERROR"
            return @{ Success = $false; Error = "Failed to create policy custom field" }
        }
    }
    else {
        Write-LevelLog "Custom field '$PolicyFieldName' already exists" -Level "DEBUG"
    }

    # URL field (e.g., policy_unchecky_url) - only if required
    if ($RequireUrl) {
        $UrlFieldName = "policy_${SoftwareName}_url"
        $ExistingUrlField = Find-LevelCustomField -ApiKey $ApiKey -FieldName $UrlFieldName -BaseUrl $BaseUrl

        if (-not $ExistingUrlField) {
            Write-LevelLog "Creating custom field: $UrlFieldName" -Level "INFO"
            $NewField = New-LevelCustomField -ApiKey $ApiKey -Name $UrlFieldName -DefaultValue "" -BaseUrl $BaseUrl
            if ($NewField) {
                Write-LevelLog "Created custom field: $UrlFieldName" -Level "SUCCESS"
                $FieldsCreated++
            }
            else {
                Write-LevelLog "Failed to create custom field: $UrlFieldName" -Level "WARN"
            }
        }
        else {
            Write-LevelLog "Custom field '$UrlFieldName' already exists" -Level "DEBUG"
        }
    }

    Write-LevelLog "Policy infrastructure ready: $TagsCreated tags created, $FieldsCreated fields created" -Level "SUCCESS"

    return @{
        Success       = $true
        TagsCreated   = $TagsCreated
        FieldsCreated = $FieldsCreated
    }
}

<#
.SYNOPSIS
    Gets a single custom field by ID with its default value.

.DESCRIPTION
    Fetches a custom field definition by ID and also retrieves its
    account-level default value from the custom_field_values endpoint.

.PARAMETER ApiKey
    Level.io API key for authentication.

.PARAMETER FieldId
    The ID of the custom field to retrieve.

.PARAMETER BaseUrl
    Base URL for the Level.io API. Default: "https://api.level.io/v2"

.OUTPUTS
    Custom field object with default_value property added, or $null on failure.

.EXAMPLE
    $Field = Get-LevelCustomFieldById -ApiKey $ApiKey -FieldId "cf_123"
    Write-Host "Default value: $($Field.default_value)"
#>
function Get-LevelCustomFieldById {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $true)]
        [string]$FieldId,

        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://api.level.io/v2"
    )

    $Result = Invoke-LevelApiCall -Uri "$BaseUrl/custom_fields/$FieldId" -ApiKey $ApiKey -Method "GET"
    if (-not $Result.Success) {
        return $null
    }

    $Field = $Result.Data

    # Get the account-level value from custom_field_values
    $ValueResult = Invoke-LevelApiCall -Uri "$BaseUrl/custom_field_values?limit=100" -ApiKey $ApiKey -Method "GET"
    if ($ValueResult.Success) {
        $Values = if ($ValueResult.Data.data) { $ValueResult.Data.data } else { @($ValueResult.Data) }
        $GlobalValue = $Values | Where-Object { $_.custom_field_id -eq $FieldId -and [string]::IsNullOrEmpty($_.assigned_to_id) } | Select-Object -First 1
        if ($GlobalValue) {
            $Field | Add-Member -NotePropertyName "default_value" -NotePropertyValue $GlobalValue.value -Force
        }
    }

    return $Field
}

<#
.SYNOPSIS
    Sets a custom field's global/account-level default value.

.DESCRIPTION
    Uses PATCH /custom_field_values with assigned_to_id=null to set the
    global organization-level default value for a custom field.

    NOTE: This sets the ACCOUNT-LEVEL default, not entity-specific values.
    For entity-specific values (org/folder/device), use Set-LevelCustomFieldValue.

.PARAMETER ApiKey
    Level.io API key for authentication.

.PARAMETER FieldId
    The ID of the custom field to update.

.PARAMETER Value
    The value to set as the global default.

.PARAMETER BaseUrl
    Base URL for the Level.io API. Default: "https://api.level.io/v2"

.OUTPUTS
    $true on success, $false on failure.

.EXAMPLE
    Set-LevelCustomFieldDefaultValue -ApiKey $ApiKey -FieldId "cf_123" -Value "C:\ProgramData\MSP"
#>
function Set-LevelCustomFieldDefaultValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $true)]
        [string]$FieldId,

        [Parameter(Mandatory = $true)]
        [string]$Value,

        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://api.level.io/v2"
    )

    $Body = @{
        custom_field_id = $FieldId
        assigned_to_id  = $null
        value           = $Value
    }

    $Result = Invoke-LevelApiCall -Uri "$BaseUrl/custom_field_values" -ApiKey $ApiKey -Method "PATCH" -Body $Body

    if ($Result.Success) {
        Write-LevelLog "Updated custom field $FieldId default value" -Level "DEBUG"
        return $true
    }
    else {
        Write-LevelLog "Failed to update custom field value: $($Result.Error)" -Level "ERROR"
        return $false
    }
}

<#
.SYNOPSIS
    Deletes a custom field by ID.

.DESCRIPTION
    Permanently removes a custom field definition from Level.io.
    WARNING: This will also remove all values associated with this field.

.PARAMETER ApiKey
    Level.io API key for authentication.

.PARAMETER FieldId
    The ID of the custom field to delete.

.PARAMETER BaseUrl
    Base URL for the Level.io API. Default: "https://api.level.io/v2"

.OUTPUTS
    $true on success, $false on failure.

.EXAMPLE
    Remove-LevelCustomField -ApiKey $ApiKey -FieldId "cf_123"
#>
function Remove-LevelCustomField {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $true)]
        [string]$FieldId,

        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://api.level.io/v2"
    )

    $Result = Invoke-LevelApiCall -Uri "$BaseUrl/custom_fields/$FieldId" -ApiKey $ApiKey -Method "DELETE"

    if ($Result.Success) {
        Write-LevelLog "Deleted custom field $FieldId" -Level "DEBUG"
        return $true
    }
    else {
        Write-LevelLog "Failed to delete custom field: $($Result.Error)" -Level "ERROR"
        return $false
    }
}

<#
.SYNOPSIS
    Gets all organizations accessible via the API.

.DESCRIPTION
    Fetches all organizations from Level.io with pagination support.

.PARAMETER ApiKey
    Level.io API key for authentication.

.PARAMETER BaseUrl
    Base URL for the Level.io API. Default: "https://api.level.io/v2"

.OUTPUTS
    Array of organization objects, or empty array on failure.

.EXAMPLE
    $Orgs = Get-LevelOrganizations -ApiKey $ApiKey
    foreach ($Org in $Orgs) { Write-Host $Org.name }
#>
function Get-LevelOrganizations {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://api.level.io/v2"
    )

    $AllOrgs = @()
    $StartingAfter = $null

    do {
        $Uri = "$BaseUrl/organizations?limit=100"
        if ($StartingAfter) {
            $Uri += "&starting_after=$StartingAfter"
        }

        $Result = Invoke-LevelApiCall -Uri $Uri -ApiKey $ApiKey -Method "GET"

        if (-not $Result.Success) {
            Write-LevelLog "Failed to fetch organizations: $($Result.Error)" -Level "ERROR"
            return @()
        }

        $Data = $Result.Data
        $Orgs = if ($Data.data) { $Data.data } else { @($Data) }

        if ($Orgs -and $Orgs.Count -gt 0) {
            $AllOrgs += $Orgs
            $HasMore = $Data.has_more -eq $true
            if ($HasMore) {
                $StartingAfter = $Orgs[-1].id
            } else {
                break
            }
        } else {
            break
        }
    } while ($true)

    return $AllOrgs
}

<#
.SYNOPSIS
    Gets all folders for an organization.

.DESCRIPTION
    Fetches all folders within a specific organization.

.PARAMETER ApiKey
    Level.io API key for authentication.

.PARAMETER OrgId
    The organization ID.

.PARAMETER BaseUrl
    Base URL for the Level.io API. Default: "https://api.level.io/v2"

.OUTPUTS
    Array of folder objects, or empty array on failure.

.EXAMPLE
    $Folders = Get-LevelOrganizationFolders -ApiKey $ApiKey -OrgId $Org.id
#>
function Get-LevelOrganizationFolders {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $true)]
        [string]$OrgId,

        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://api.level.io/v2"
    )

    $Result = Invoke-LevelApiCall -Uri "$BaseUrl/organizations/$OrgId/folders" -ApiKey $ApiKey -Method "GET"
    if ($Result.Success) {
        $Data = $Result.Data
        if ($Data.data) { return $Data.data }
        return @($Data)
    }
    return @()
}

<#
.SYNOPSIS
    Gets all devices in a folder.

.DESCRIPTION
    Fetches all devices within a specific folder of an organization.

.PARAMETER ApiKey
    Level.io API key for authentication.

.PARAMETER OrgId
    The organization ID.

.PARAMETER FolderId
    The folder ID.

.PARAMETER BaseUrl
    Base URL for the Level.io API. Default: "https://api.level.io/v2"

.OUTPUTS
    Array of device objects, or empty array on failure.

.EXAMPLE
    $Devices = Get-LevelFolderDevices -ApiKey $ApiKey -OrgId $Org.id -FolderId $Folder.id
#>
function Get-LevelFolderDevices {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $true)]
        [string]$OrgId,

        [Parameter(Mandatory = $true)]
        [string]$FolderId,

        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://api.level.io/v2"
    )

    $Result = Invoke-LevelApiCall -Uri "$BaseUrl/organizations/$OrgId/folders/$FolderId/devices" -ApiKey $ApiKey -Method "GET"
    if ($Result.Success) {
        $Data = $Result.Data
        if ($Data.data) { return $Data.data }
        return @($Data)
    }
    return @()
}

<#
.SYNOPSIS
    Gets custom field values for an entity (organization, folder, or device).

.DESCRIPTION
    Fetches the custom field values assigned to a specific entity.

.PARAMETER ApiKey
    Level.io API key for authentication.

.PARAMETER EntityType
    Type of entity: "organization", "folder", or "device".

.PARAMETER EntityId
    The ID of the entity.

.PARAMETER BaseUrl
    Base URL for the Level.io API. Default: "https://api.level.io/v2"

.OUTPUTS
    Hashtable of custom field key-value pairs, or empty hashtable on failure.

.EXAMPLE
    $Fields = Get-LevelEntityCustomFields -ApiKey $ApiKey -EntityType "device" -EntityId $Device.id
    Write-Host "Policy: $($Fields.cf_policy_unchecky)"
#>
function Get-LevelEntityCustomFields {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $true)]
        [ValidateSet("organization", "folder", "device")]
        [string]$EntityType,

        [Parameter(Mandatory = $true)]
        [string]$EntityId,

        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://api.level.io/v2"
    )

    $Endpoint = switch ($EntityType) {
        "organization" { "/organizations/$EntityId" }
        "folder"       { "/folders/$EntityId" }
        "device"       { "/devices/$EntityId" }
    }

    $Result = Invoke-LevelApiCall -Uri "$BaseUrl$Endpoint" -ApiKey $ApiKey -Method "GET"
    if ($Result.Success -and $Result.Data.custom_fields) {
        return $Result.Data.custom_fields
    }
    return @{}
}

# ============================================================
# WAKE-ON-LAN
# ============================================================

<#
.SYNOPSIS
    Sends Wake-on-LAN magic packets using all available methods to wake a device.

.DESCRIPTION
    Constructs and broadcasts WOL magic packets to wake a device from sleep
    or powered-off state. Uses multiple methods to maximize wake reliability:

    1. UDP broadcast on port 9 (standard WOL port)
    2. UDP broadcast on port 7 (echo port, fallback)
    3. Directed subnet broadcasts from all local network interfaces
    4. Global broadcast (255.255.255.255)

    The magic packet consists of 6 bytes of 0xFF followed by the target MAC
    address repeated 16 times (102 bytes total).

.PARAMETER MacAddress
    The MAC address of the target device. Accepts formats:
    - Colon-separated: XX:XX:XX:XX:XX:XX
    - Dash-separated: XX-XX-XX-XX-XX-XX
    - No delimiter: XXXXXXXXXXXX

.PARAMETER Attempts
    Number of magic packets to send per method. Default: 3
    Multiple attempts increase reliability on congested networks.

.PARAMETER DelayMs
    Milliseconds to wait between packet sends. Default: 100

.PARAMETER SecureOn
    Optional SecureOn password (6 bytes) for WOL with password.
    Format: XX:XX:XX:XX:XX:XX or XXXXXXXXXXXX

.OUTPUTS
    [bool] $true if packets were sent successfully, $false on error.

.EXAMPLE
    $Success = Send-LevelWakeOnLan -MacAddress "AA:BB:CC:DD:EE:FF"
    if ($Success) {
        Write-LevelLog "WOL packets sent via all methods"
    }

.EXAMPLE
    # Send with more attempts for unreliable network
    Send-LevelWakeOnLan -MacAddress $Mac -Attempts 5 -DelayMs 50

.NOTES
    - Device must have WOL enabled in BIOS/UEFI
    - Device should be on the same broadcast domain for best results
    - Directed broadcasts may reach devices across VLANs if routing allows
    - Some NICs require WOL to be enabled in device properties
#>
function Send-LevelWakeOnLan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MacAddress,

        [Parameter(Mandatory = $false)]
        [int]$Attempts = 3,

        [Parameter(Mandatory = $false)]
        [int]$DelayMs = 100,

        [Parameter(Mandatory = $false)]
        [string]$SecureOn = ""
    )

    # Normalize MAC address by removing delimiters
    $CleanMac = $MacAddress -replace '[:-]', ''

    if ($CleanMac.Length -ne 12) {
        Write-LevelLog "Invalid MAC address: $MacAddress" -Level "WARN"
        return $false
    }

    try {
        # Convert MAC string to byte array
        $MacBytes = [byte[]]::new(6)
        for ($i = 0; $i -lt 6; $i++) {
            $MacBytes[$i] = [Convert]::ToByte($CleanMac.Substring($i * 2, 2), 16)
        }

        # Build magic packet: 6 bytes of 0xFF + MAC repeated 16 times = 102 bytes (or 108 with SecureOn)
        $PacketSize = 102
        $SecureOnBytes = $null

        if ($SecureOn) {
            $CleanSecureOn = $SecureOn -replace '[:-]', ''
            if ($CleanSecureOn.Length -eq 12) {
                $SecureOnBytes = [byte[]]::new(6)
                for ($i = 0; $i -lt 6; $i++) {
                    $SecureOnBytes[$i] = [Convert]::ToByte($CleanSecureOn.Substring($i * 2, 2), 16)
                }
                $PacketSize = 108
            }
        }

        $MagicPacket = [byte[]]::new($PacketSize)

        # First 6 bytes are 0xFF (sync stream)
        for ($i = 0; $i -lt 6; $i++) {
            $MagicPacket[$i] = 0xFF
        }

        # Repeat MAC address 16 times
        for ($i = 0; $i -lt 16; $i++) {
            [Array]::Copy($MacBytes, 0, $MagicPacket, 6 + ($i * 6), 6)
        }

        # Append SecureOn password if provided
        if ($SecureOnBytes) {
            [Array]::Copy($SecureOnBytes, 0, $MagicPacket, 102, 6)
        }

        # Collect all broadcast addresses to use
        $BroadcastAddresses = @()

        # Method 1: Global broadcast (255.255.255.255)
        $BroadcastAddresses += [System.Net.IPAddress]::Broadcast

        # Method 2: Get subnet broadcast addresses from all network interfaces
        try {
            $NetworkConfigs = Get-NetIPConfiguration -ErrorAction SilentlyContinue |
                Where-Object { $_.IPv4Address -and $_.NetAdapter.Status -eq 'Up' }

            foreach ($Config in $NetworkConfigs) {
                foreach ($IpInfo in $Config.IPv4Address) {
                    $IpAddress = [System.Net.IPAddress]::Parse($IpInfo.IPAddress)
                    $PrefixLength = $IpInfo.PrefixLength

                    # Calculate subnet broadcast address
                    $IpBytes = $IpAddress.GetAddressBytes()
                    $MaskBits = [uint32]((-bnot 0) -shl (32 - $PrefixLength))
                    $MaskBytes = [System.BitConverter]::GetBytes($MaskBits)
                    [Array]::Reverse($MaskBytes)

                    $BroadcastBytes = [byte[]]::new(4)
                    for ($i = 0; $i -lt 4; $i++) {
                        $BroadcastBytes[$i] = $IpBytes[$i] -bor (-bnot $MaskBytes[$i] -band 0xFF)
                    }

                    $SubnetBroadcast = [System.Net.IPAddress]::new($BroadcastBytes)

                    # Only add if it's not already in the list and not the global broadcast
                    if ($SubnetBroadcast.ToString() -ne "255.255.255.255" -and
                        $BroadcastAddresses.ToString() -notcontains $SubnetBroadcast.ToString()) {
                        $BroadcastAddresses += $SubnetBroadcast
                    }
                }
            }
        }
        catch {
            # If we can't enumerate interfaces, continue with global broadcast only
        }

        # Standard WOL ports
        $WolPorts = @(9, 7)

        $PacketsSent = 0

        # Send to all broadcast addresses on all ports
        foreach ($BroadcastAddr in $BroadcastAddresses) {
            foreach ($Port in $WolPorts) {
                try {
                    $UdpClient = New-Object System.Net.Sockets.UdpClient
                    $UdpClient.EnableBroadcast = $true
                    $UdpClient.Client.SetSocketOption(
                        [System.Net.Sockets.SocketOptionLevel]::Socket,
                        [System.Net.Sockets.SocketOptionName]::Broadcast,
                        $true
                    )

                    $Endpoint = New-Object System.Net.IPEndPoint($BroadcastAddr, $Port)

                    for ($i = 1; $i -le $Attempts; $i++) {
                        $UdpClient.Send($MagicPacket, $MagicPacket.Length, $Endpoint) | Out-Null
                        $PacketsSent++
                        if ($i -lt $Attempts) {
                            Start-Sleep -Milliseconds $DelayMs
                        }
                    }

                    $UdpClient.Close()
                }
                catch {
                    # Continue with other addresses/ports even if one fails
                }
            }
        }

        if ($PacketsSent -gt 0) {
            return $true
        }
        else {
            Write-LevelLog "No WOL packets could be sent" -Level "WARN"
            return $false
        }
    }
    catch {
        Write-LevelLog "Failed to send WOL packet: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

# ============================================================
# TECHNICIAN ALERT FUNCTIONS
# ============================================================

# Module-level alert queue for Add-TechnicianAlert
$Script:TechnicianAlertQueue = @()

function Test-TechnicianWorkstation {
    <#
    .SYNOPSIS
        Checks if the current device is tagged as a technician workstation.

    .DESCRIPTION
        Searches device tags for the technician emoji (U+1F9D1 U+200D U+1F4BB).
        Used by scripts to determine if they're running on a tech's workstation.

    .PARAMETER DeviceTags
        Comma-separated list of device tags from {{level_tag_names}}.

    .OUTPUTS
        Boolean - $true if device has technician tag, $false otherwise.

    .EXAMPLE
        if (Test-TechnicianWorkstation -DeviceTags $DeviceTags) {
            Write-LevelLog "Running on technician workstation"
        }
    #>
    param(
        [Parameter(Mandatory = $false)]
        [string]$DeviceTags = ""
    )

    if ([string]::IsNullOrWhiteSpace($DeviceTags) -or $DeviceTags -match '^\{\{.*\}\}$') {
        return $false
    }

    # Get technician emoji from centralized source
    $Emojis = Get-EmojiLiterals
    $TechnicianEmoji = $Emojis.Technician

    $TagArray = $DeviceTags -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }

    foreach ($Tag in $TagArray) {
        if ($Tag.StartsWith($TechnicianEmoji)) {
            return $true
        }
    }
    return $false
}

function Get-TechnicianName {
    <#
    .SYNOPSIS
        Extracts the technician name from device tags.

    .DESCRIPTION
        Finds the technician tag (U+1F9D1 U+200D U+1F4BB + name) and extracts
        the name portion after the emoji.

    .PARAMETER DeviceTags
        Comma-separated list of device tags from {{level_tag_names}}.

    .OUTPUTS
        String - Technician name (e.g., "John" from "U+1F9D1 U+200D U+1F4BBJohn"), or empty string.

    .EXAMPLE
        $TechName = Get-TechnicianName -DeviceTags $DeviceTags
        if ($TechName) {
            Write-LevelLog "Tech: $TechName"
        }
    #>
    param(
        [Parameter(Mandatory = $false)]
        [string]$DeviceTags = ""
    )

    if ([string]::IsNullOrWhiteSpace($DeviceTags) -or $DeviceTags -match '^\{\{.*\}\}$') {
        return ""
    }

    # Get technician emoji from centralized source
    $Emojis = Get-EmojiLiterals
    $TechnicianEmoji = $Emojis.Technician

    $TagArray = $DeviceTags -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }

    foreach ($Tag in $TagArray) {
        if ($Tag.StartsWith($TechnicianEmoji)) {
            $Name = $Tag.Substring($TechnicianEmoji.Length).Trim()
            return $Name
        }
    }
    return ""
}

function Add-TechnicianAlert {
    <#
    .SYNOPSIS
        Queues an alert to be sent when the script completes.

    .DESCRIPTION
        Adds an alert to the module-level queue. Alerts are automatically sent
        when Invoke-LevelScript completes, or can be sent manually with
        Send-TechnicianAlertQueue.

    .PARAMETER Title
        Short title for the notification header.

    .PARAMETER Message
        Detailed message explaining the situation and required action.

    .PARAMETER ClientName
        Optional client/organization name for context.

    .PARAMETER Priority
        Alert priority: Low, Normal, High, or Critical.

    .PARAMETER TechnicianName
        Optional - route to specific technician. Empty = broadcast to all.

    .PARAMETER ExpiresInMinutes
        Alert expiration time in minutes. Default: 1440 (24 hours).

    .OUTPUTS
        Hashtable with Success, QueueLength, and AlertId.

    .EXAMPLE
        Add-TechnicianAlert -Title "Install Failed" `
            -Message "Huntress installer returned error 1603" `
            -Priority "High"
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [string]$ClientName = "",

        [Parameter(Mandatory = $false)]
        [ValidateSet("Low", "Normal", "High", "Critical")]
        [string]$Priority = "Normal",

        [Parameter(Mandatory = $false)]
        [string]$TechnicianName = "",

        [Parameter(Mandatory = $false)]
        [int]$ExpiresInMinutes = 1440
    )

    $AlertId = [guid]::NewGuid().ToString().Substring(0, 8)

    $Alert = @{
        id = $AlertId
        title = $Title
        message = $Message
        client = $ClientName
        device = $env:COMPUTERNAME
        priority = $Priority
        technician = $TechnicianName
        timestamp = (Get-Date).ToUniversalTime().ToString("o")
        expires = (Get-Date).AddMinutes($ExpiresInMinutes).ToUniversalTime().ToString("o")
    }

    $Script:TechnicianAlertQueue += $Alert

    return @{
        Success = $true
        QueueLength = $Script:TechnicianAlertQueue.Count
        AlertId = $AlertId
    }
}

function Send-TechnicianAlert {
    <#
    .SYNOPSIS
        Creates and sends an alert immediately to technician workstations.

    .DESCRIPTION
        Sends an alert directly to the cf_coolforge_technician_alerts custom field
        on the device running this script. Technician Alert Monitor scripts on
        tech workstations will pick up and display the alert.

    .PARAMETER ApiKey
        Level.io API key ({{cf_apikey}}).

    .PARAMETER Title
        Short title for the notification header.

    .PARAMETER Message
        Detailed message explaining the situation and required action.

    .PARAMETER ClientName
        Optional client/organization name for context.

    .PARAMETER DeviceHostname
        Source device hostname. Defaults to $env:COMPUTERNAME.

    .PARAMETER Priority
        Alert priority: Low, Normal, High, or Critical.

    .PARAMETER TechnicianName
        Optional - route to specific technician. Empty = broadcast to all.

    .PARAMETER ExpiresInMinutes
        Alert expiration time in minutes. Default: 1440 (24 hours).

    .PARAMETER BaseUrl
        Level.io API base URL. Default: https://api.level.io/v2

    .OUTPUTS
        Hashtable with Success, AlertId, and Error.

    .EXAMPLE
        Send-TechnicianAlert -ApiKey $LevelApiKey `
            -Title "Ransomware Detected" `
            -Message "Suspicious encryption activity on C:\Users" `
            -Priority "Critical"
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [string]$ClientName = "",

        [Parameter(Mandatory = $false)]
        [string]$DeviceHostname = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Low", "Normal", "High", "Critical")]
        [string]$Priority = "Normal",

        [Parameter(Mandatory = $false)]
        [string]$TechnicianName = "",

        [Parameter(Mandatory = $false)]
        [int]$ExpiresInMinutes = 1440,

        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://api.level.io/v2"
    )

    $AlertId = [guid]::NewGuid().ToString().Substring(0, 8)

    $Alert = @{
        id = $AlertId
        title = $Title
        message = $Message
        client = $ClientName
        device = $DeviceHostname
        priority = $Priority
        technician = $TechnicianName
        timestamp = (Get-Date).ToUniversalTime().ToString("o")
        expires = (Get-Date).AddMinutes($ExpiresInMinutes).ToUniversalTime().ToString("o")
    }

    try {
        # Find the device
        $DeviceResult = Find-LevelDevice -ApiKey $ApiKey -Hostname $DeviceHostname -BaseUrl $BaseUrl
        if (-not $DeviceResult) {
            return @{ Success = $false; AlertId = $null; Error = "Device not found: $DeviceHostname" }
        }

        # Find the custom field
        $Fields = Get-LevelCustomFields -ApiKey $ApiKey -BaseUrl $BaseUrl
        $AlertField = $Fields | Where-Object { $_.name -eq "coolforge_technician_alerts" }

        if (-not $AlertField) {
            return @{ Success = $false; AlertId = $null; Error = "Custom field 'coolforge_technician_alerts' not found" }
        }

        # Get existing alerts
        $ExistingAlerts = @()
        $CurrentValue = $DeviceResult.custom_fields | Where-Object { $_.custom_field_id -eq $AlertField.id } | Select-Object -ExpandProperty value -ErrorAction SilentlyContinue
        if ($CurrentValue) {
            try {
                $ExistingAlerts = $CurrentValue | ConvertFrom-Json -ErrorAction SilentlyContinue
                if ($null -eq $ExistingAlerts) { $ExistingAlerts = @() }
            }
            catch {
                $ExistingAlerts = @()
            }
        }

        # Add new alert
        $ExistingAlerts += $Alert
        $NewValue = $ExistingAlerts | ConvertTo-Json -Compress

        # Update the custom field
        $UpdateResult = Set-LevelCustomFieldValue -ApiKey $ApiKey -FieldId $AlertField.id -DeviceId $DeviceResult.id -Value $NewValue -BaseUrl $BaseUrl

        if ($UpdateResult) {
            return @{ Success = $true; AlertId = $AlertId; Error = $null }
        }
        else {
            return @{ Success = $false; AlertId = $null; Error = "Failed to update custom field" }
        }
    }
    catch {
        return @{ Success = $false; AlertId = $null; Error = $_.Exception.Message }
    }
}

function Send-TechnicianAlertQueue {
    <#
    .SYNOPSIS
        Sends all queued technician alerts.

    .DESCRIPTION
        Sends all alerts that were queued via Add-TechnicianAlert.
        Called automatically by Invoke-LevelScript on completion,
        or can be called manually.

    .PARAMETER ApiKey
        Level.io API key. If not specified, uses key from Initialize-LevelScript.

    .PARAMETER Force
        Send even if queue is empty (returns success with 0 alerts).

    .PARAMETER BaseUrl
        Level.io API base URL. Default: https://api.level.io/v2

    .OUTPUTS
        Hashtable with Success, AlertsSent, and Error.

    .EXAMPLE
        $Result = Send-TechnicianAlertQueue -ApiKey $LevelApiKey
        Write-LevelLog "Sent $($Result.AlertsSent) alerts"
    #>
    param(
        [Parameter(Mandatory = $false)]
        [string]$ApiKey = "",

        [Parameter(Mandatory = $false)]
        [switch]$Force,

        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://api.level.io/v2"
    )

    if ($Script:TechnicianAlertQueue.Count -eq 0) {
        if ($Force) {
            return @{ Success = $true; AlertsSent = 0; Error = $null }
        }
        return @{ Success = $true; AlertsSent = 0; Error = $null }
    }

    # Use provided API key or fall back to script-level key
    $EffectiveApiKey = if ($ApiKey) { $ApiKey } else { $Script:LevelApiKey }

    if ([string]::IsNullOrWhiteSpace($EffectiveApiKey)) {
        return @{ Success = $false; AlertsSent = 0; Error = "No API key provided" }
    }

    $SentCount = 0
    $Errors = @()

    foreach ($Alert in $Script:TechnicianAlertQueue) {
        $Result = Send-TechnicianAlert -ApiKey $EffectiveApiKey `
            -Title $Alert.title `
            -Message $Alert.message `
            -ClientName $Alert.client `
            -DeviceHostname $Alert.device `
            -Priority $Alert.priority `
            -TechnicianName $Alert.technician `
            -BaseUrl $BaseUrl

        if ($Result.Success) {
            $SentCount++
        }
        else {
            $Errors += $Result.Error
        }
    }

    # Clear the queue
    $Script:TechnicianAlertQueue = @()

    if ($Errors.Count -gt 0) {
        return @{ Success = $false; AlertsSent = $SentCount; Error = ($Errors -join "; ") }
    }

    return @{ Success = $true; AlertsSent = $SentCount; Error = $null }
}

# ============================================================
# UI HELPER FUNCTIONS (Admin Tools)
# ============================================================

function Write-Header {
    <#
    .SYNOPSIS
        Displays a section header for interactive tools.
    #>
    param([string]$Text)
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " $Text" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-LevelSuccess {
    <#
    .SYNOPSIS
        Displays a success message (green).
    #>
    param([string]$Text)
    Write-Host "[+] $Text" -ForegroundColor Green
}

function Write-LevelInfo {
    <#
    .SYNOPSIS
        Displays an info message (white).
    #>
    param([string]$Text)
    Write-Host "[*] $Text" -ForegroundColor White
}

function Write-LevelWarning {
    <#
    .SYNOPSIS
        Displays a warning message (yellow).
    #>
    param([string]$Text)
    Write-Host "[!] $Text" -ForegroundColor Yellow
}

function Write-LevelError {
    <#
    .SYNOPSIS
        Displays an error message (red).
    #>
    param([string]$Text)
    Write-Host "[X] $Text" -ForegroundColor Red
}

function Read-UserInput {
    <#
    .SYNOPSIS
        Prompts for user input with optional default value.
    #>
    param(
        [string]$Prompt,
        [string]$Default = ""
    )

    if ([string]::IsNullOrWhiteSpace($Default)) {
        $FullPrompt = "$Prompt`: "
    }
    else {
        $FullPrompt = "$Prompt [$Default]: "
    }

    Write-Host $FullPrompt -NoNewline -ForegroundColor Yellow
    $UserInput = Read-Host

    if ([string]::IsNullOrWhiteSpace($UserInput)) {
        return $Default
    }
    return $UserInput
}

function Read-YesNo {
    <#
    .SYNOPSIS
        Prompts for a yes/no answer.
    #>
    param(
        [string]$Prompt,
        [bool]$Default = $true
    )

    $DefaultText = if ($Default) { "Y/n" } else { "y/N" }
    Write-Host "$Prompt [$DefaultText]: " -NoNewline -ForegroundColor Yellow
    $UserInput = Read-Host

    if ([string]::IsNullOrWhiteSpace($UserInput)) {
        return $Default
    }

    return $UserInput.ToLower() -eq "y" -or $UserInput.ToLower() -eq "yes"
}

# ============================================================
# DEBUG OUTPUT HELPERS (Policy Scripts)
# ============================================================
# When $DebugScripts is true (from cf_debug_scripts custom field),
# outputs verbose diagnostic information for troubleshooting.

function Write-DebugSection {
    <#
    .SYNOPSIS
        Writes a debug section with key/value data when $DebugScripts is enabled.
    .DESCRIPTION
        Outputs a formatted debug section showing variable names and their values,
        with indicators for missing or unresolved Level.io variables.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][hashtable]$Data,
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
    <#
    .SYNOPSIS
        Outputs detailed tag analysis when $DebugScripts is enabled.
    .DESCRIPTION
        Shows all device tags with their byte representations and identifies
        global control tags and software-specific tags.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$TagString,
        [Parameter(Mandatory = $true)][string]$SoftwareName
    )
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

function Write-DebugPolicy {
    <#
    .SYNOPSIS
        Outputs policy resolution details when $DebugScripts is enabled.
    .DESCRIPTION
        Shows the resolved policy including global status, action source,
        and matched tags.
    #>
    param(
        [Parameter(Mandatory = $true)]$Policy
    )
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
    <#
    .SYNOPSIS
        Outputs tag management readiness when $DebugScripts is enabled.
    .DESCRIPTION
        Shows whether the script has the required API key and hostname
        to perform tag management operations.
    #>
    param(
        [Parameter(Mandatory = $true)][bool]$HasApiKey,
        [Parameter(Mandatory = $true)][string]$DeviceHostname,
        [string]$ApiKeyValue
    )
    if (-not $DebugScripts) { return }

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " DEBUG: Tag Management Readiness" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    $HostnameReady = -not [string]::IsNullOrWhiteSpace($DeviceHostname) -and $DeviceHostname -notlike "{{*}}"

    Write-Host "  API Key Present:     $(if ($HasApiKey) { '[YES]' } else { '[NO] - Tag updates will be SKIPPED!' })" -ForegroundColor $(if ($HasApiKey) { 'Green' } else { 'Red' })

    # Show API key diagnostics - masked format for security
    if ($ApiKeyValue) {
        $KeyLen = $ApiKeyValue.Length
        $HasWhitespace = $ApiKeyValue -match '^\s|\s$'
        $HasNewline = $ApiKeyValue -match '[\r\n]'
        # Show first 4 + ... + last 4 chars (or less if key is short)
        $MaskedKey = if ($KeyLen -gt 12) {
            $ApiKeyValue.Substring(0, 4) + "..." + $ApiKeyValue.Substring($KeyLen - 4)
        } elseif ($KeyLen -gt 4) {
            $ApiKeyValue.Substring(0, 2) + "..." + $ApiKeyValue.Substring($KeyLen - 2)
        } else {
            "****"
        }
        Write-Host "  API Key Length:      $KeyLen chars" -ForegroundColor $(if ($KeyLen -gt 20) { 'Green' } else { 'Yellow' })
        Write-Host "  API Key (masked):    $MaskedKey" -ForegroundColor Yellow
        if ($HasWhitespace) {
            Write-Host "  [WARNING] API key has leading/trailing whitespace!" -ForegroundColor Red
        }
        if ($HasNewline) {
            Write-Host "  [WARNING] API key contains newline characters!" -ForegroundColor Red
        }
    }

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

function Get-CompanyNameFromPath {
    <#
    .SYNOPSIS
        Extracts the company name from a scratch folder path.
    #>
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ""
    }

    $Path = $Path.Trim().TrimEnd('\', '/')

    if ($Path -match '^[A-Za-z]:\\ProgramData\\(.+)$') {
        return $Matches[1]
    }
    if ($Path -match '^[A-Za-z]:/ProgramData/(.+)$') {
        return $Matches[1]
    }

    return Split-Path $Path -Leaf
}

# ============================================================
# CONFIG/SECURITY FUNCTIONS (Admin Tools)
# ============================================================

function Get-SavedConfig {
    <#
    .SYNOPSIS
        Loads saved configuration from a config file.
    #>
    param([string]$Path = "")

    if ([string]::IsNullOrWhiteSpace($Path)) {
        $Path = Join-Path $PSScriptRoot ".COOLForge_Lib-setup.json"
    }

    if (Test-Path $Path) {
        try {
            $Content = Get-Content $Path -Raw -ErrorAction Stop
            return $Content | ConvertFrom-Json
        }
        catch {
            Write-LevelWarning "Could not load saved config: $($_.Exception.Message)"
            return $null
        }
    }
    return $null
}

function Save-Config {
    <#
    .SYNOPSIS
        Saves configuration to a config file.
    #>
    param(
        [hashtable]$Config,
        [string]$Path = ""
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        $Path = Join-Path $PSScriptRoot ".COOLForge_Lib-setup.json"
    }

    try {
        $Config | ConvertTo-Json -Depth 5 | Set-Content $Path -Encoding UTF8 -ErrorAction Stop
        return $true
    }
    catch {
        Write-LevelWarning "Could not save config: $($_.Exception.Message)"
        return $false
    }
}

function Protect-ApiKey {
    <#
    .SYNOPSIS
        Encrypts API key for storage (Windows DPAPI - user-specific).
    #>
    param([string]$PlainText)

    try {
        $SecureString = ConvertTo-SecureString $PlainText -AsPlainText -Force
        return ConvertFrom-SecureString $SecureString
    }
    catch {
        return $null
    }
}

function Unprotect-ApiKey {
    <#
    .SYNOPSIS
        Decrypts API key from storage.
    #>
    param([string]$EncryptedText)

    try {
        $SecureString = ConvertTo-SecureString $EncryptedText -ErrorAction Stop
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
        return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    }
    catch {
        return $null
    }
}

# ============================================================
# BACKUP/RESTORE FUNCTIONS (Admin Tools)
# ============================================================

function Backup-AllCustomFields {
    <#
    .SYNOPSIS
        Creates a complete backup of all custom field values across the hierarchy.
    #>
    param([switch]$IncludeDevices = $false)

    $Backup = @{
        Timestamp     = (Get-Date).ToString("o")
        Version       = "1.0"
        CustomFields  = @()
        Organizations = @()
    }

    Write-LevelInfo "Backing up custom field definitions..."
    $Fields = Get-LevelCustomFields -ApiKey $Script:LevelApiKey
    $Backup.CustomFields = $Fields

    Write-LevelInfo "Fetching organizations..."
    $Orgs = Get-LevelOrganizations -ApiKey $Script:LevelApiKey

    if (-not $Orgs -or $Orgs.Count -eq 0) {
        Write-LevelWarning "No organizations found."
        return $Backup
    }

    $OrgCount = if ($Orgs -is [array]) { $Orgs.Count } else { 1 }
    Write-LevelInfo "Found $OrgCount organization(s)."

    foreach ($Org in $Orgs) {
        Write-Host "  Processing: $($Org.name)" -ForegroundColor DarkGray

        $OrgBackup = @{
            Id           = $Org.id
            Name         = $Org.name
            CustomFields = Get-LevelEntityCustomFields -ApiKey $Script:LevelApiKey -EntityType "organization" -EntityId $Org.id
            Folders      = @()
        }

        $Folders = Get-LevelOrganizationFolders -ApiKey $Script:LevelApiKey -OrgId $Org.id
        $FolderCount = if ($Folders -is [array]) { $Folders.Count } else { if ($Folders) { 1 } else { 0 } }

        if ($FolderCount -gt 0) {
            Write-Host "    Found $FolderCount folder(s)" -ForegroundColor DarkGray
        }

        foreach ($Folder in $Folders) {
            $FolderBackup = @{
                Id           = $Folder.id
                Name         = $Folder.name
                ParentId     = $Folder.parent_id
                CustomFields = Get-LevelEntityCustomFields -ApiKey $Script:LevelApiKey -EntityType "folder" -EntityId $Folder.id
                Devices      = @()
            }

            if ($IncludeDevices) {
                $Devices = Get-LevelFolderDevices -ApiKey $Script:LevelApiKey -OrgId $Org.id -FolderId $Folder.id
                foreach ($Device in $Devices) {
                    $DeviceBackup = @{
                        Id           = $Device.id
                        Name         = $Device.name
                        CustomFields = Get-LevelEntityCustomFields -ApiKey $Script:LevelApiKey -EntityType "device" -EntityId $Device.id
                    }
                    $FolderBackup.Devices += $DeviceBackup
                }
            }

            $OrgBackup.Folders += $FolderBackup
        }

        $Backup.Organizations += $OrgBackup
    }

    return $Backup
}

function Save-Backup {
    <#
    .SYNOPSIS
        Saves a backup to a compressed zip file.
    #>
    param(
        [hashtable]$Backup,
        [string]$Path
    )

    try {
        $Backup | ConvertTo-Json -Depth 20 | Set-Content $Path -Encoding UTF8 -ErrorAction Stop
        $ZipPath = $Path -replace '\.json$', '.zip'
        Compress-Archive -Path $Path -DestinationPath $ZipPath -Force -ErrorAction Stop
        Remove-Item $Path -Force -ErrorAction SilentlyContinue
        return $true
    }
    catch {
        Write-LevelError "Failed to save backup: $($_.Exception.Message)"
        return $false
    }
}

function Import-Backup {
    <#
    .SYNOPSIS
        Imports a backup from a zip or JSON file.
    #>
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        Write-LevelError "Backup file not found: $Path"
        return $null
    }

    try {
        $JsonContent = $null

        if ($Path -match '\.zip$') {
            $TempDir = Join-Path $env:TEMP "coolforge_lib_backup_$(Get-Random)"
            New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
            Expand-Archive -Path $Path -DestinationPath $TempDir -Force -ErrorAction Stop
            $JsonFile = Get-ChildItem -Path $TempDir -Filter "*.json" | Select-Object -First 1
            if ($JsonFile) {
                $JsonContent = Get-Content $JsonFile.FullName -Raw -ErrorAction Stop
            }
            Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        else {
            $JsonContent = Get-Content $Path -Raw -ErrorAction Stop
        }

        if ($JsonContent) {
            return $JsonContent | ConvertFrom-Json
        }
        else {
            Write-LevelError "No JSON content found in backup."
            return $null
        }
    }
    catch {
        Write-LevelError "Failed to load backup: $($_.Exception.Message)"
        return $null
    }
}

function Restore-CustomFields {
    <#
    .SYNOPSIS
        Restores custom field values from a backup.
    #>
    param(
        [PSObject]$Backup,
        [switch]$DryRun = $false,
        [switch]$IncludeDevices = $false
    )

    if (-not $Backup) {
        Write-LevelError "No backup provided."
        return $false
    }

    Write-LevelInfo "Restoring from backup created: $($Backup.Timestamp)"
    $Changes = 0

    foreach ($Org in $Backup.Organizations) {
        Write-Host "  Restoring: $($Org.Name)" -ForegroundColor DarkGray

        foreach ($Field in $Org.CustomFields.PSObject.Properties) {
            if (-not [string]::IsNullOrWhiteSpace($Field.Value)) {
                if ($DryRun) {
                    Write-Host "    [DRY-RUN] Would set $($Field.Name) = $($Field.Value) on org" -ForegroundColor Yellow
                }
                else {
                    if (Set-LevelCustomFieldValue -ApiKey $Script:LevelApiKey -EntityType "organization" -EntityId $Org.Id -FieldReference $Field.Name -Value $Field.Value) {
                        $Changes++
                    }
                }
            }
        }

        foreach ($Folder in $Org.Folders) {
            foreach ($Field in $Folder.CustomFields.PSObject.Properties) {
                if (-not [string]::IsNullOrWhiteSpace($Field.Value)) {
                    if ($DryRun) {
                        Write-Host "    [DRY-RUN] Would set $($Field.Name) = $($Field.Value) on folder $($Folder.Name)" -ForegroundColor Yellow
                    }
                    else {
                        if (Set-LevelCustomFieldValue -ApiKey $Script:LevelApiKey -EntityType "folder" -EntityId $Folder.Id -FieldReference $Field.Name -Value $Field.Value) {
                            $Changes++
                        }
                    }
                }
            }

            if ($IncludeDevices) {
                foreach ($Device in $Folder.Devices) {
                    foreach ($Field in $Device.CustomFields.PSObject.Properties) {
                        if (-not [string]::IsNullOrWhiteSpace($Field.Value)) {
                            if ($DryRun) {
                                Write-Host "    [DRY-RUN] Would set $($Field.Name) = $($Field.Value) on device $($Device.Name)" -ForegroundColor Yellow
                            }
                            else {
                                if (Set-LevelCustomFieldValue -ApiKey $Script:LevelApiKey -EntityType "device" -EntityId $Device.Id -FieldReference $Field.Name -Value $Field.Value) {
                                    $Changes++
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if ($DryRun) {
        Write-LevelInfo "Dry run complete. No changes made."
    }
    else {
        Write-LevelSuccess "Restored $Changes custom field value(s)."
    }

    return $true
}

function Get-BackupPath {
    <#
    .SYNOPSIS
        Generates a backup file path with timestamp.
    #>
    param([string]$BasePath = "")

    $Date = Get-Date
    $Timestamp = $Date.ToString("yyyy-MM-dd_HHmmss")

    if ([string]::IsNullOrWhiteSpace($BasePath)) {
        $RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
        $BasePath = Join-Path $RepoRoot "backups"
    }

    if (-not (Test-Path $BasePath)) {
        New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
    }

    return Join-Path $BasePath "customfields_$Timestamp.json"
}

function Get-LatestBackup {
    <#
    .SYNOPSIS
        Gets the most recent backup file.
    #>
    param([string]$BasePath = "")

    if ([string]::IsNullOrWhiteSpace($BasePath)) {
        $RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
        $BasePath = Join-Path $RepoRoot "backups"
    }

    if (-not (Test-Path $BasePath)) {
        return $null
    }

    $Latest = Get-ChildItem -Path $BasePath -Filter "customfields_*.zip" |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if ($Latest) {
        return $Latest.FullName
    }
    return $null
}

function Compare-BackupWithCurrent {
    <#
    .SYNOPSIS
        Compares a backup with current custom field values.
    #>
    param(
        [PSObject]$Backup,
        [switch]$IncludeDevices = $false
    )

    $Differences = @()
    Write-LevelInfo "Comparing backup with current state..."

    foreach ($OrgBackup in $Backup.Organizations) {
        $CurrentOrgFields = Get-LevelEntityCustomFields -ApiKey $Script:LevelApiKey -EntityType "organization" -EntityId $OrgBackup.Id

        foreach ($Field in $OrgBackup.CustomFields.PSObject.Properties) {
            $BackupValue = $Field.Value
            $CurrentValue = $CurrentOrgFields.$($Field.Name)

            if ($BackupValue -ne $CurrentValue) {
                $Differences += @{
                    EntityType   = "Organization"
                    EntityName   = $OrgBackup.Name
                    EntityId     = $OrgBackup.Id
                    FieldName    = $Field.Name
                    BackupValue  = if ([string]::IsNullOrWhiteSpace($BackupValue)) { "(empty)" } else { $BackupValue }
                    CurrentValue = if ([string]::IsNullOrWhiteSpace($CurrentValue)) { "(empty)" } else { $CurrentValue }
                }
            }
        }

        foreach ($FolderBackup in $OrgBackup.Folders) {
            $CurrentFolderFields = Get-LevelEntityCustomFields -ApiKey $Script:LevelApiKey -EntityType "folder" -EntityId $FolderBackup.Id

            foreach ($Field in $FolderBackup.CustomFields.PSObject.Properties) {
                $BackupValue = $Field.Value
                $CurrentValue = $CurrentFolderFields.$($Field.Name)

                if ($BackupValue -ne $CurrentValue) {
                    $Differences += @{
                        EntityType   = "Folder"
                        EntityName   = $FolderBackup.Name
                        EntityId     = $FolderBackup.Id
                        FieldName    = $Field.Name
                        BackupValue  = if ([string]::IsNullOrWhiteSpace($BackupValue)) { "(empty)" } else { $BackupValue }
                        CurrentValue = if ([string]::IsNullOrWhiteSpace($CurrentValue)) { "(empty)" } else { $CurrentValue }
                    }
                }
            }

            if ($IncludeDevices) {
                foreach ($DeviceBackup in $FolderBackup.Devices) {
                    $CurrentDeviceFields = Get-LevelEntityCustomFields -ApiKey $Script:LevelApiKey -EntityType "device" -EntityId $DeviceBackup.Id

                    foreach ($Field in $DeviceBackup.CustomFields.PSObject.Properties) {
                        $BackupValue = $Field.Value
                        $CurrentValue = $CurrentDeviceFields.$($Field.Name)

                        if ($BackupValue -ne $CurrentValue) {
                            $Differences += @{
                                EntityType   = "Device"
                                EntityName   = $DeviceBackup.Name
                                EntityId     = $DeviceBackup.Id
                                FieldName    = $Field.Name
                                BackupValue  = if ([string]::IsNullOrWhiteSpace($BackupValue)) { "(empty)" } else { $BackupValue }
                                CurrentValue = if ([string]::IsNullOrWhiteSpace($CurrentValue)) { "(empty)" } else { $CurrentValue }
                            }
                        }
                    }
                }
            }
        }
    }

    return $Differences
}

function Show-BackupDifferences {
    <#
    .SYNOPSIS
        Displays differences between backup and current state.
    #>
    param([array]$Differences)

    if ($Differences.Count -eq 0) {
        Write-LevelSuccess "No differences found - backup matches current state."
        return
    }

    Write-Host ""
    Write-Host "Found $($Differences.Count) difference(s):" -ForegroundColor Yellow
    Write-Host ""

    $Grouped = $Differences | Group-Object EntityType

    foreach ($Group in $Grouped) {
        Write-Host "  $($Group.Name)s:" -ForegroundColor Cyan

        foreach ($Diff in $Group.Group) {
            Write-Host "    $($Diff.EntityName) - $($Diff.FieldName)" -ForegroundColor White
            Write-Host "      Backup:  $($Diff.BackupValue)" -ForegroundColor Green
            Write-Host "      Current: $($Diff.CurrentValue)" -ForegroundColor Red
        }
        Write-Host ""
    }
}

# ============================================================
# GITHUB FUNCTIONS (Admin Tools)
# ============================================================

# Script-level variable for GitHub repo
$Script:GitHubRepo = "coolnetworks/COOLForge"

function Get-GitHubReleases {
    <#
    .SYNOPSIS
        Fetches the latest releases from GitHub.
    #>
    param([int]$Count = 5)

    $Uri = "https://api.github.com/repos/$Script:GitHubRepo/releases"
    $Headers = @{
        "Accept"     = "application/vnd.github.v3+json"
        "User-Agent" = "COOLForge_Lib-Setup"
    }

    try {
        $Response = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method Get -ErrorAction Stop
        $Releases = @()

        foreach ($Release in ($Response | Select-Object -First $Count)) {
            $Releases += @{
                TagName     = $Release.tag_name
                Name        = $Release.name
                Body        = $Release.body
                PublishedAt = $Release.published_at
                HtmlUrl     = $Release.html_url
                Prerelease  = $Release.prerelease
            }
        }

        return $Releases
    }
    catch {
        Write-LevelWarning "Could not fetch GitHub releases: $($_.Exception.Message)"
        return @()
    }
}

function Show-ReleaseNotes {
    <#
    .SYNOPSIS
        Displays release notes for a version.
    #>
    param([hashtable]$Release)

    Write-Host ""
    Write-Host "Release: $($Release.Name)" -ForegroundColor Cyan
    Write-Host "Tag: $($Release.TagName)" -ForegroundColor DarkGray
    Write-Host "Published: $($Release.PublishedAt)" -ForegroundColor DarkGray
    if ($Release.Prerelease) {
        Write-Host "  [PRE-RELEASE]" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "Release Notes:" -ForegroundColor White
    Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray

    if (-not [string]::IsNullOrWhiteSpace($Release.Body)) {
        $Body = $Release.Body
        $Body = $Body -replace '#+\s*', ''
        $Body = $Body -replace '\*\*([^*]+)\*\*', '$1'
        $Body = $Body -replace '\*([^*]+)\*', '$1'
        Write-Host $Body
    }
    else {
        Write-Host "(No release notes available)"
    }
    Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
}

function Select-Version {
    <#
    .SYNOPSIS
        Interactive version selector with GitHub releases.
    #>
    param([string]$CurrentVersion = "")

    Write-LevelInfo "Fetching available releases from GitHub..."
    $Releases = Get-GitHubReleases -Count 5

    if ($Releases.Count -eq 0) {
        Write-LevelWarning "Could not fetch releases. Enter version manually."
        return Read-UserInput -Prompt "Version tag (e.g., v2025.12.29)" -Default $CurrentVersion
    }

    Write-Host ""
    Write-Host "Available versions:" -ForegroundColor Cyan
    Write-Host ""

    $Index = 1
    foreach ($Release in $Releases) {
        $PreReleaseTag = if ($Release.Prerelease) { " [PRE-RELEASE]" } else { "" }
        $CurrentTag = if ($Release.TagName -eq $CurrentVersion) { " (current)" } else { "" }
        Write-Host "  [$Index] $($Release.TagName)$PreReleaseTag$CurrentTag" -ForegroundColor White
        Write-Host "      $($Release.Name)" -ForegroundColor DarkGray
        $Index++
    }

    Write-Host ""
    Write-Host "  [0] Don't pin (use latest from main branch)" -ForegroundColor Yellow
    Write-Host "  [M] Enter version manually" -ForegroundColor Yellow
    Write-Host ""

    $Choice = Read-UserInput -Prompt "Select version" -Default "1"

    if ($Choice -eq "0") {
        return ""
    }
    elseif ($Choice.ToUpper() -eq "M") {
        return Read-UserInput -Prompt "Version tag (e.g., v2025.12.29)" -Default $CurrentVersion
    }
    elseif ($Choice -match '^\d+$') {
        $ChoiceInt = [int]$Choice
        if ($ChoiceInt -ge 1 -and $ChoiceInt -le $Releases.Count) {
            $SelectedRelease = $Releases[$ChoiceInt - 1]
            Show-ReleaseNotes -Release $SelectedRelease

            if (Read-YesNo -Prompt "Pin to $($SelectedRelease.TagName)" -Default $true) {
                return $SelectedRelease.TagName
            }
            else {
                return Select-Version -CurrentVersion $CurrentVersion
            }
        }
    }

    Write-LevelWarning "Invalid selection. Please try again."
    return Select-Version -CurrentVersion $CurrentVersion
}

# ============================================================
# ADMIN INITIALIZATION
# ============================================================

# Script-level API key for admin functions
$Script:LevelApiKey = $null

function Initialize-LevelApi {
    <#
    .SYNOPSIS
        Initializes the Level.io API for admin tools.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey
    )

    $Script:LevelApiKey = $ApiKey
    return @{ Success = $true }
}

# Alias for backward compatibility
Set-Alias -Name Initialize-COOLForgeCustomFields -Value Initialize-LevelApi -Scope Script

# ============================================================
# LAUNCHER HELPERS
# ============================================================
# Functions to support slim launchers - script download/execution

function Get-ContentMD5 {
    <#
    .SYNOPSIS
        Computes MD5 hash of string content.
    #>
    param([string]$Content)
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Content)
    $hash = $md5.ComputeHash($bytes)
    return ([BitConverter]::ToString($hash) -replace '-', '').ToLower()
}

function Get-ExpectedMD5 {
    <#
    .SYNOPSIS
        Looks up expected MD5 hash from MD5SUMS content.
    #>
    param([string]$FileName, [string]$MD5Content)
    $SearchName = Split-Path $FileName -Leaf
    foreach ($line in $MD5Content -split "`n") {
        $line = $line.Trim()
        if ($line -match '^#' -or [string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -match '^([a-f0-9]{32})\s+(.+)$') {
            $FilePath = $Matches[2].Trim()
            $FileLeaf = Split-Path $FilePath -Leaf
            if ($FilePath -eq $FileName -or $FileLeaf -eq $SearchName -or $FileLeaf -like "*$SearchName") {
                return $Matches[1].ToLower()
            }
        }
    }
    return $null
}

function Get-ScriptPathFromMD5 {
    <#
    .SYNOPSIS
        Resolves full script path from MD5SUMS content.
    #>
    param([string]$ScriptName, [string]$MD5Content)
    if ([string]::IsNullOrWhiteSpace($MD5Content)) { return $null }
    foreach ($line in $MD5Content -split "`n") {
        $line = $line.Trim()
        if ($line -match '^#' -or [string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -match '^([a-f0-9]{32})\s+(.+)$') {
            $FilePath = $Matches[2].Trim()
            $FileName = Split-Path $FilePath -Leaf
            if ($FileName -eq $ScriptName -or $FileName -like "*$ScriptName") {
                return $FilePath
            }
        }
    }
    return $null
}

function Get-ScriptVersion {
    <#
    .SYNOPSIS
        Extracts version number from script content.
    #>
    param([string]$Content, [string]$Source = "unknown")
    if ($Content -match 'Version:\s*([\d\.]+)') {
        return $Matches[1]
    }
    return $null
}

function Invoke-ScriptLauncher {
    <#
    .SYNOPSIS
        Downloads and executes a script from GitHub with caching and verification.
    .DESCRIPTION
        This function handles script download, MD5 verification, caching, and execution.
        It's designed to be called from slim launchers after the library is loaded.
    .PARAMETER ScriptName
        Name of the script to run (e.g., "chrome.ps1")
    .PARAMETER RepoBaseUrl
        Base URL of the GitHub repo (e.g., "https://raw.githubusercontent.com/.../main")
    .PARAMETER MD5SumsContent
        Content of the MD5SUMS file for checksum verification
    .PARAMETER MspScratchFolder
        Path to MSP scratch folder for caching
    .PARAMETER LauncherVariables
        Hashtable of variables to pass to the executed script
    .PARAMETER DebugMode
        Enable debug output
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptName,

        [Parameter(Mandatory = $true)]
        [string]$RepoBaseUrl,

        [string]$MD5SumsContent,

        [Parameter(Mandatory = $true)]
        [string]$MspScratchFolder,

        [hashtable]$LauncherVariables = @{},

        [bool]$DebugMode = $false
    )

    # Fix emoji encoding
    $ScriptName = Repair-LevelEmoji -Text $ScriptName

    # Resolve script path from MD5SUMS
    $ScriptRelativePath = $null
    if ($MD5SumsContent) {
        $ScriptRelativePath = Get-ScriptPathFromMD5 -ScriptName $ScriptName -MD5Content $MD5SumsContent
        if ($ScriptRelativePath) {
            Write-Host "[*] Resolved script path: $ScriptRelativePath"
        }
    }

    Write-Host "[*] Preparing to run: $ScriptName"

    # Define script storage location
    $ScriptsFolder = Join-Path -Path $MspScratchFolder -ChildPath "Scripts"
    if (!(Test-Path $ScriptsFolder)) {
        New-Item -Path $ScriptsFolder -ItemType Directory -Force | Out-Null
    }

    # Sanitize script name for filesystem
    $SafeScriptName = $ScriptName -replace '[<>:"/\\|?*]', '_'
    $ScriptPath = Join-Path -Path $ScriptsFolder -ChildPath $SafeScriptName

    # Build script URL
    $ScriptRepoBaseUrl = "$RepoBaseUrl/scripts"
    if ($ScriptRelativePath) {
        $ScriptUrl = "$RepoBaseUrl/$(Get-LevelUrlEncoded $ScriptRelativePath)"
    } else {
        Write-Host "[!] Script not found in MD5SUMS - trying flat path"
        $ScriptUrl = "$ScriptRepoBaseUrl/$(Get-LevelUrlEncoded $ScriptName)"
    }

    # Debug mode: cache-busting
    if ($DebugMode) {
        $CacheBuster = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $ScriptUrl = "$ScriptUrl`?t=$CacheBuster"
        Write-Host "[DEBUG] Cache-busting URL: $ScriptUrl"
    }

    # Check for local version
    $ScriptNeedsUpdate = $false
    $LocalScriptVersion = $null
    $LocalScriptContent = $null
    $ScriptBackupPath = "$ScriptPath.backup"

    # Debug mode: force fresh download
    if ($DebugMode -and (Test-Path $ScriptPath)) {
        Write-Host "[DEBUG] Deleting cached script to force fresh download..."
        Remove-Item -Path $ScriptPath -Force -ErrorAction SilentlyContinue
    }

    if (Test-Path $ScriptPath) {
        try {
            $LocalScriptContent = Get-Content -Path $ScriptPath -Raw -ErrorAction Stop
            $LocalScriptVersion = Get-ScriptVersion -Content $LocalScriptContent -Source "local script"
        }
        catch {
            Write-Host "[!] Local script corrupt or no version - will redownload"
            $ScriptNeedsUpdate = $true
        }
    }
    else {
        $ScriptNeedsUpdate = $true
        Write-Host "[*] Script not cached - downloading..."
    }

    # Download script from GitHub
    try {
        $RemoteScriptContent = (Invoke-WebRequest -Uri $ScriptUrl -UseBasicParsing -TimeoutSec 15).Content
        $RemoteScriptVersion = Get-ScriptVersion -Content $RemoteScriptContent -Source "remote script"

        if ($RemoteScriptVersion) {
            if ($null -eq $LocalScriptVersion -or [version]$RemoteScriptVersion -gt [version]$LocalScriptVersion) {
                $ScriptNeedsUpdate = $true
                if ($LocalScriptVersion) {
                    Write-Host "[*] Script update available: $LocalScriptVersion -> $RemoteScriptVersion"
                }
            }
        } else {
            # No version - always update
            $ScriptNeedsUpdate = $true
        }

        if ($ScriptNeedsUpdate) {
            # Backup working local copy
            if ($LocalScriptVersion -and $LocalScriptContent) {
                Set-Content -Path $ScriptBackupPath -Value $LocalScriptContent -Force -ErrorAction Stop
            }

            # Write new version
            Set-Content -Path $ScriptPath -Value $RemoteScriptContent -Force -ErrorAction Stop

            # Verify
            try {
                $VerifyScriptContent = Get-Content -Path $ScriptPath -Raw -ErrorAction Stop
                if ($VerifyScriptContent.Length -lt 50) {
                    throw "Downloaded script appears to be empty or truncated"
                }

                # MD5 verification (skip in debug mode)
                if ($MD5SumsContent -and -not $DebugMode) {
                    $ScriptMD5Key = if ($ScriptRelativePath) { $ScriptRelativePath } else { "scripts/$ScriptName" }
                    $ExpectedScriptMD5 = Get-ExpectedMD5 -FileName $ScriptMD5Key -MD5Content $MD5SumsContent
                    if ($ExpectedScriptMD5) {
                        $ActualScriptMD5 = Get-ContentMD5 -Content $RemoteScriptContent
                        if ($ActualScriptMD5 -ne $ExpectedScriptMD5) {
                            throw "MD5 checksum mismatch: expected $ExpectedScriptMD5, got $ActualScriptMD5"
                        }
                        Write-Host "[+] Script checksum verified"
                    }
                }
                elseif ($DebugMode) {
                    Write-Host "[*] Debug mode - skipping script checksum verification"
                }

                # Success - remove backup
                if (Test-Path $ScriptBackupPath) {
                    Remove-Item -Path $ScriptBackupPath -Force -ErrorAction SilentlyContinue
                }
                if ($RemoteScriptVersion) {
                    Write-Host "[+] Script updated to v$RemoteScriptVersion"
                } else {
                    Write-Host "[+] Script downloaded successfully"
                }
            }
            catch {
                # Restore backup on failure
                if (Test-Path $ScriptBackupPath) {
                    Write-Host "[!] Downloaded script corrupt or checksum failed - restoring backup"
                    Move-Item -Path $ScriptBackupPath -Destination $ScriptPath -Force
                }
                throw "Downloaded script failed verification: $($_.Exception.Message)"
            }
        }
    }
    catch {
        # GitHub unreachable - try cached version
        if (Test-Path $ScriptBackupPath) {
            Move-Item -Path $ScriptBackupPath -Destination $ScriptPath -Force -ErrorAction SilentlyContinue
        }

        if (!(Test-Path $ScriptPath)) {
            Write-Host "[X] FATAL: Cannot download script and no local copy exists"
            Write-Host "[X] URL: $ScriptUrl"
            Write-Host "[X] Error: $($_.Exception.Message)"
            return 1
        }
        Write-Host "[!] Could not check for script updates (using cached version)"
    }

    # Execute the downloaded script
    Write-Host "[*] Executing: $ScriptName"
    Write-Host "============================================================"

    $ScriptContent = Get-Content -Path $ScriptPath -Raw

    # Build variable injection block
    $VarsBlock = ""
    foreach ($key in $LauncherVariables.Keys) {
        $value = $LauncherVariables[$key]
        if ($null -eq $value) {
            $VarsBlock += "`n`$$key = `$null"
        } elseif ($value -is [bool]) {
            $VarsBlock += "`n`$$key = `$$value"
        } else {
            $EscapedValue = $value -replace "'", "''" -replace '\$', '`$'
            $VarsBlock += "`n`$$key = '$EscapedValue'"
        }
    }

    $ExecutionBlock = @"
# Variables passed from launcher
$VarsBlock

# Script content:
$ScriptContent
"@

    try {
        $ScriptBlock = [scriptblock]::Create($ExecutionBlock)
        & $ScriptBlock
        $ScriptExitCode = $LASTEXITCODE
        if ($null -eq $ScriptExitCode) { $ScriptExitCode = 0 }
        return $ScriptExitCode
    }
    catch {
        Write-Host "[X] Script execution failed: $($_.Exception.Message)"
        return 1
    }
}

# ============================================================
# MODULE LOAD MESSAGE
# ============================================================
# Extract version from header comment (single source of truth)
# This ensures the displayed version always matches the header
# Handles both Import-Module and New-Module loading methods
$script:ModuleVersion = "2026.01.13.13"
Write-Host "[*] COOLForge-Common v$script:ModuleVersion loaded"

# ============================================================
# EXPORT MODULE MEMBERS
# ============================================================
Export-ModuleMember -Function @(
    # Initialization & Execution
    'Initialize-LevelScript',
    'Invoke-LevelScript',
    'Complete-LevelScript',
    'Remove-LevelLockFile',

    # Logging
    'Write-LevelLog',

    # Device & System Info
    'Test-LevelAdmin',
    'Get-LevelDeviceInfo',

    # Software Detection Utilities
    'Test-SoftwareInstalled',
    'Stop-SoftwareProcesses',
    'Stop-SoftwareServices',
    'Get-SoftwareUninstallString',
    'Test-ServiceExists',
    'Test-ServiceRunning',

    # Software Policy & Emoji Handling
    'Get-EmojiMap',
    'Get-EmojiLiterals',
    'Get-SoftwarePolicy',
    'Invoke-SoftwarePolicyCheck',

    # Launcher Helpers
    'Get-ContentMD5',
    'Get-ExpectedMD5',
    'Get-ScriptPathFromMD5',
    'Get-ScriptVersion',
    'Invoke-ScriptLauncher',

    # API Helpers
    'Invoke-LevelApiCall',
    'Get-LevelGroups',
    'Get-LevelDevices',
    'Find-LevelDevice',
    'Get-LevelDeviceById',
    'Get-LevelDeviceTagNames',

    # Tag Management
    'Get-LevelTags',
    'Find-LevelTag',
    'Add-LevelTagToDevice',
    'Remove-LevelTagFromDevice',
    'Add-LevelPolicyTag',
    'Remove-LevelPolicyTag',

    # Custom Field Management
    'Get-LevelCustomFields',
    'Find-LevelCustomField',
    'New-LevelCustomField',
    'Set-LevelCustomFieldValue',
    'Set-LevelCustomFieldDefaultValue',
    'Initialize-LevelSoftwarePolicy',
    'Initialize-SoftwarePolicyInfrastructure',
    'Get-LevelCustomFieldById',
    'Remove-LevelCustomField',

    # Hierarchy Navigation
    'Get-LevelOrganizations',
    'Get-LevelOrganizationFolders',
    'Get-LevelFolderDevices',
    'Get-LevelEntityCustomFields',

    # Wake-on-LAN
    'Send-LevelWakeOnLan',

    # Text Processing
    'Repair-LevelEmoji',
    'Get-LevelUrlEncoded',

    # Technician Alerts
    'Test-TechnicianWorkstation',
    'Get-TechnicianName',
    'Add-TechnicianAlert',
    'Send-TechnicianAlert',
    'Send-TechnicianAlertQueue',

    # UI Helpers (Admin Tools)
    'Write-Header',
    'Write-LevelSuccess',
    'Write-LevelInfo',
    'Write-LevelWarning',
    'Write-LevelError',
    'Read-UserInput',
    'Read-YesNo',

    # Debug Output Helpers (Policy Scripts)
    'Write-DebugSection',
    'Write-DebugTags',
    'Write-DebugPolicy',
    'Write-DebugTagManagement',

    'Get-CompanyNameFromPath',

    # Config/Security (Admin Tools)
    'Get-SavedConfig',
    'Save-Config',
    'Protect-ApiKey',
    'Unprotect-ApiKey',

    # Backup/Restore (Admin Tools)
    'Backup-AllCustomFields',
    'Save-Backup',
    'Import-Backup',
    'Restore-CustomFields',
    'Get-BackupPath',
    'Get-LatestBackup',
    'Compare-BackupWithCurrent',
    'Show-BackupDifferences',

    # GitHub (Admin Tools)
    'Get-GitHubReleases',
    'Show-ReleaseNotes',
    'Select-Version',

    # Admin Initialization
    'Initialize-LevelApi',
    'Initialize-COOLForgeCustomFields'
)
