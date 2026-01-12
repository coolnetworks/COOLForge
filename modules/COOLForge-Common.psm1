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
    Version:    2026.01.12.04
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
            Write-LevelLog "Script completed with exit code: $FinalExitCode" -Level "WARNING"
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

    # Observed corruption patterns from Level.io:
    # U+2705 -> CE 93 C2 A3 C3 A0 (displays as: checkmark corrupted)
    # U+1F4CC -> E2 89 A1 C6 92 C3 B4 C3 AE (displays as: pushpin corrupted)
    # U+1F64F -> E2 89 A1 C6 92 C3 96 C3 85 (displays as: pray corrupted)
    # U+1F6AB -> E2 89 A1 C6 92 C2 A2 C3 A6 (displays as: prohibit corrupted)
    # U+1F504 -> E2 89 A1 C6 92 C3 94 C3 84 (displays as: arrows corrupted) - TBD

    # Build corrupted string patterns from observed byte sequences
    $CorruptedCheckmark = [System.Text.Encoding]::UTF8.GetString([byte[]](0xCE, 0x93, 0xC2, 0xA3, 0xC3, 0xA0))  # U+2705
    $CorruptedPin = [System.Text.Encoding]::UTF8.GetString([byte[]](0xE2, 0x89, 0xA1, 0xC6, 0x92, 0xC3, 0xB4, 0xC3, 0xAE))  # U+1F4CC
    $CorruptedPray = [System.Text.Encoding]::UTF8.GetString([byte[]](0xE2, 0x89, 0xA1, 0xC6, 0x92, 0xC3, 0x96, 0xC3, 0x85))  # U+1F64F
    $CorruptedProhibit = [System.Text.Encoding]::UTF8.GetString([byte[]](0xE2, 0x89, 0xA1, 0xC6, 0x92, 0xC2, 0xA2, 0xC3, 0xA6))  # U+1F6AB
    # U+1F504 corruption pattern TBD - will be logged to EmojiTags.log when encountered
    $CorruptedWindow = [System.Text.Encoding]::UTF8.GetString([byte[]](0xE2, 0x89, 0xA1, 0xC6, 0x92, 0xC2, 0xAC, 0xC6, 0x92))  # U+1FA9F
    $CorruptedAlert = [System.Text.Encoding]::UTF8.GetString([byte[]](0xE2, 0x89, 0xA1, 0xC6, 0x92, 0xC3, 0x9C, 0xC2, 0xBF))  # U+1F6A8
    $CorruptedPenguin = [System.Text.Encoding]::UTF8.GetString([byte[]](0xE2, 0x89, 0xA1, 0xC6, 0x92, 0xC3, 0x89, 0xC2, 0xBA))  # U+1F427
    $CorruptedCyclone = [System.Text.Encoding]::UTF8.GetString([byte[]](0xE2, 0x89, 0xA1, 0xC6, 0x92, 0xC3, 0xAE, 0xC3, 0x87))  # U+1F300
    $CorruptedSatellite = [System.Text.Encoding]::UTF8.GetString([byte[]](0xE2, 0x89, 0xA1, 0xC6, 0x92, 0xC2, 0xA2, 0xE2, 0x96, 0x91, 0xE2, 0x88, 0xA9, 0xE2, 0x95, 0x95, 0xC3, 0x85))  # U+1F6F0
    $CorruptedCross = [System.Text.Encoding]::UTF8.GetString([byte[]](0xCE, 0x93, 0xC2, 0xA5, 0xC3, 0xAE))  # U+274C - observed
    $CorruptedNoEntry = [System.Text.Encoding]::UTF8.GetString([byte[]](0xCE, 0x93, 0xC2, 0xA2, 0xC3, 0xB6))  # U+26D4 Stop/NoEntry - observed

    # Build clean emoji strings programmatically to avoid encoding issues
    # when module is loaded via scriptblock::Create()
    $EmojiPray = [char]::ConvertFromUtf32(0x1F64F)       # U+1F64F Pray - Install
    $EmojiProhibit = [char]::ConvertFromUtf32(0x1F6AB)   # U+1F6AB Prohibited - Remove
    $EmojiArrows = [char]::ConvertFromUtf32(0x1F504)     # U+1F504 Arrows - Reinstall
    $EmojiPin = [char]::ConvertFromUtf32(0x1F4CC)        # U+1F4CC Pushpin - Pin
    $EmojiCheck = [char]0x2705                            # U+2705 Checkmark - Installed
    $EmojiCross = [char]0x274C                            # U+274C Cross - Excluded
    $EmojiWindow = [char]::ConvertFromUtf32(0x1FA9F)     # U+1FA9F Window - Windows
    $EmojiAlert = [char]::ConvertFromUtf32(0x1F6A8)      # U+1F6A8 Police light - Alert
    $EmojiPenguin = [char]::ConvertFromUtf32(0x1F427)    # U+1F427 Penguin - Linux
    $EmojiCyclone = [char]::ConvertFromUtf32(0x1F300)    # U+1F300 Cyclone - AdelaideMRI
    $EmojiSatellite = [char]::ConvertFromUtf32(0x1F6F0)  # U+1F6F0 Satellite
    $EmojiWrench = [char]::ConvertFromUtf32(0x1F527)     # U+1F527 Wrench - Fix
    $EmojiEyes = [char]::ConvertFromUtf32(0x1F440)       # U+1F440 Eyes - Check
    $EmojiNoEntry = [char]::ConvertFromUtf32(0x26D4)     # U+26D4 No Entry - Remove/Block

    return @{
        # ============================================================
        # SOFTWARE POLICY TAGS (5-tag model per POLICY-TAGS.md)
        # ============================================================
        # Override tags (transient - removed after action)
        $EmojiPray = "Install"
        $EmojiProhibit = "Remove"
        $EmojiNoEntry = "Remove"
        $EmojiArrows = "Reinstall"
        # Override tag (persistent - admin intent)
        $EmojiPin = "Pin"
        # Status tag (set by script)
        $EmojiCheck = "Installed"

        # ============================================================
        # GLOBAL CONTROL TAGS (standalone, no software suffix)
        # ============================================================
        $EmojiCross = "Excluded"

        # ============================================================
        # PLATFORM/CATEGORY TAGS (informational)
        # ============================================================
        $EmojiWindow = "Windows"
        $EmojiAlert = "Alert"
        $EmojiPenguin = "Linux"
        $EmojiCyclone = "AdelaideMRI"
        $EmojiSatellite = "Satellite"
        $EmojiWrench = "Fix"
        $EmojiEyes = "Check"

        # ============================================================
        # LEVEL.IO CORRUPTED PATTERNS
        # ============================================================
        $CorruptedCheckmark = "Installed"
        $CorruptedPin = "Pin"
        $CorruptedPray = "Install"
        $CorruptedProhibit = "Remove"
        $CorruptedNoEntry = "Remove"
        $CorruptedCross = "Excluded"
        $CorruptedWindow = "Windows"
        $CorruptedAlert = "Alert"
        $CorruptedPenguin = "Linux"
        $CorruptedCyclone = "AdelaideMRI"
        $CorruptedSatellite = "Satellite"
    }
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

    # Get centralized emoji map (single source of truth)
    $EmojiMap = Get-EmojiMap

    # Define global control emojis (clean and corrupted)
    $CheckmarkEmoji = [char]0x2705  # U+2705 checkmark
    $CrossEmoji = [char]0x274C      # U+274C cross
    $CorruptedCheckmark = [System.Text.Encoding]::UTF8.GetString([byte[]](0xCE, 0x93, 0xC2, 0xA3, 0xC3, 0xA0))
    $CorruptedCross = [System.Text.Encoding]::UTF8.GetString([byte[]](0xCE, 0x93, 0xC2, 0xA3, 0xC3, 0x8C))  # TBD

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

    # ============================================================
    # STEP 3: RESOLVE ACTION (Priority order per POLICY-TAGS.md)
    # ============================================================
    # Priority: Pin/Excluded > Reinstall > Remove > Install
    # Note: "Excluded" with software suffix means "pin this software" (don't touch)
    $IsPinned = "Pin" -in $UniqueActions -or "Excluded" -in $UniqueActions
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
        Write-LevelLog "$($Policy.SkipReason)" -Level "WARNING"
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
        "Content-Type"  = "application/json"
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

    # Add body for non-GET requests
    if ($Body -and $Method -ne "GET") {
        $Params.Body = ($Body | ConvertTo-Json -Depth 10)
    }

    try {
        $Response = Invoke-RestMethod @Params
        return @{ Success = $true; Data = $Response }
    }
    catch {
        Write-LevelLog "API call failed: $($_.Exception.Message)" -Level "ERROR"
        return @{ Success = $false; Error = $_.Exception.Message }
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
    $Body = @{ device_id = $DeviceId }

    $Result = Invoke-LevelApiCall -Uri $Uri -ApiKey $ApiKey -Method "POST" -Body $Body

    if (-not $Result.Success) {
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
    $Body = @{ device_id = $DeviceId }

    $Result = Invoke-LevelApiCall -Uri $Uri -ApiKey $ApiKey -Method "DELETE" -Body $Body

    if (-not $Result.Success) {
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
        [ValidateSet("Install", "Remove", "Has", "Pin", "Block", "Skip", "Verify")]
        [string]$EmojiPrefix,

        [Parameter(Mandatory = $true)]
        [string]$DeviceHostname,

        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://api.level.io/v2"
    )

    # Map action names to emoji characters
    $EmojiChar = switch ($EmojiPrefix) {
        "Install" { [char]::ConvertFromUtf32(0x1F64F) }  # U+1F64F Pray
        "Remove"  { [char]0x26D4 }                       # U+26D4 No entry
        "Has"     { [char]0x2705 }                       # U+2705 Check mark
        "Pin"     { [char]::ConvertFromUtf32(0x1F4CC) }  # U+1F4CC Pushpin
        "Block"   { [char]::ConvertFromUtf32(0x1F6AB) }  # U+1F6AB No entry sign
        "Skip"    { [char]0x274C }                       # U+274C Cross mark
        "Verify"  { [char]::ConvertFromUtf32(0x1F440) }  # U+1F440 Eyes
    }

    $FullTagName = "$EmojiChar$TagName"
    Write-LevelLog "Adding tag '$FullTagName' to device..." -Level "DEBUG"

    # Find the device
    $Device = Find-LevelDevice -ApiKey $ApiKey -Hostname $DeviceHostname -BaseUrl $BaseUrl
    if (-not $Device) {
        Write-LevelLog "Could not find device '$DeviceHostname' in Level.io" -Level "WARN"
        return $false
    }

    # Find the tag
    $Tag = Find-LevelTag -ApiKey $ApiKey -TagName $FullTagName -BaseUrl $BaseUrl
    if (-not $Tag) {
        Write-LevelLog "Tag '$FullTagName' not found in Level.io - cannot add" -Level "WARN"
        return $false
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
        [ValidateSet("Install", "Remove", "Has", "Pin", "Block", "Skip", "Verify")]
        [string]$EmojiPrefix,

        [Parameter(Mandatory = $true)]
        [string]$DeviceHostname,

        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://api.level.io/v2"
    )

    # Map action names to emoji characters
    $EmojiChar = switch ($EmojiPrefix) {
        "Install" { [char]::ConvertFromUtf32(0x1F64F) }  # U+1F64F Pray
        "Remove"  { [char]0x26D4 }                       # U+26D4 No entry
        "Has"     { [char]0x2705 }                       # U+2705 Check mark
        "Pin"     { [char]::ConvertFromUtf32(0x1F4CC) }  # U+1F4CC Pushpin
        "Block"   { [char]::ConvertFromUtf32(0x1F6AB) }  # U+1F6AB No entry sign
        "Skip"    { [char]0x274C }                       # U+274C Cross mark
        "Verify"  { [char]::ConvertFromUtf32(0x1F440) }  # U+1F440 Eyes
    }

    $FullTagName = "$EmojiChar$TagName"
    Write-LevelLog "Removing tag '$FullTagName' from device..." -Level "DEBUG"

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

    # Remove the tag
    $Success = Remove-LevelTagFromDevice -ApiKey $ApiKey -TagId $Tag.id -DeviceId $Device.id -BaseUrl $BaseUrl
    if ($Success) {
        Write-LevelLog "Removed tag '$FullTagName' from device" -Level "SUCCESS"
    }

    return $Success
}

# ============================================================
# WAKE-ON-LAN
# ============================================================

<#
.SYNOPSIS
    Sends a Wake-on-LAN magic packet to wake a device.

.DESCRIPTION
    Constructs and broadcasts a WOL magic packet to wake a device from sleep
    or powered-off state. The magic packet consists of 6 bytes of 0xFF followed
    by the target MAC address repeated 16 times (102 bytes total).

    Packets are sent via UDP broadcast on port 9.

.PARAMETER MacAddress
    The MAC address of the target device. Accepts formats:
    - Colon-separated: XX:XX:XX:XX:XX:XX
    - Dash-separated: XX-XX-XX-XX-XX-XX
    - No delimiter: XXXXXXXXXXXX

.PARAMETER Attempts
    Number of magic packets to send. Default: 10
    Multiple attempts increase reliability on congested networks.

.PARAMETER DelayMs
    Milliseconds to wait between packet sends. Default: 500

.OUTPUTS
    [bool] $true if packets were sent successfully, $false on error.

.EXAMPLE
    $Success = Send-LevelWakeOnLan -MacAddress "AA:BB:CC:DD:EE:FF"
    if ($Success) {
        Write-LevelLog "WOL packet sent"
    }

.EXAMPLE
    # Send with more attempts for unreliable network
    Send-LevelWakeOnLan -MacAddress $Mac -Attempts 20 -DelayMs 250

.NOTES
    - Device must have WOL enabled in BIOS/UEFI
    - Device must be on the same broadcast domain (subnet)
    - Some NICs require WOL to be enabled in device properties
#>
function Send-LevelWakeOnLan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MacAddress,

        [Parameter(Mandatory = $false)]
        [int]$Attempts = 10,

        [Parameter(Mandatory = $false)]
        [int]$DelayMs = 500
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

        # Build magic packet: 6 bytes of 0xFF + MAC repeated 16 times = 102 bytes
        $MagicPacket = [byte[]]::new(102)

        # First 6 bytes are 0xFF
        for ($i = 0; $i -lt 6; $i++) {
            $MagicPacket[$i] = 0xFF
        }

        # Repeat MAC address 16 times
        for ($i = 0; $i -lt 16; $i++) {
            [Array]::Copy($MacBytes, 0, $MagicPacket, 6 + ($i * 6), 6)
        }

        # Broadcast via UDP port 9
        $UdpClient = New-Object System.Net.Sockets.UdpClient
        $UdpClient.Connect([System.Net.IPAddress]::Broadcast, 9)

        for ($i = 1; $i -le $Attempts; $i++) {
            $UdpClient.Send($MagicPacket, $MagicPacket.Length) | Out-Null
            if ($i -lt $Attempts) {
                Start-Sleep -Milliseconds $DelayMs
            }
        }

        $UdpClient.Close()
        return $true
    }
    catch {
        Write-LevelLog "Failed to send WOL packet: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

# ============================================================
# MODULE LOAD MESSAGE
# ============================================================
# Extract version from header comment (single source of truth)
# This ensures the displayed version always matches the header
# Handles both Import-Module and New-Module loading methods
$script:ModuleVersion = "2026.01.08.01"
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

    # Software Policy & Emoji Handling
    'Get-EmojiMap',
    'Get-SoftwarePolicy',
    'Invoke-SoftwarePolicyCheck',

    # API Helpers
    'Invoke-LevelApiCall',
    'Get-LevelGroups',
    'Get-LevelDevices',
    'Find-LevelDevice',

    # Tag Management
    'Get-LevelTags',
    'Find-LevelTag',
    'Add-LevelTagToDevice',
    'Remove-LevelTagFromDevice',
    'Add-LevelPolicyTag',
    'Remove-LevelPolicyTag',

    # Wake-on-LAN
    'Send-LevelWakeOnLan',

    # Text Processing
    'Repair-LevelEmoji',
    'Get-LevelUrlEncoded'
)
