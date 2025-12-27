<#
.SYNOPSIS
    LevelIO-Common - Shared PowerShell module for Level.io automation scripts.

.DESCRIPTION
    This module provides a standardized set of functions for Level.io RMM automation scripts:
    - Tag gate system for device filtering
    - Lockfile management to prevent concurrent execution
    - Standardized logging with severity levels
    - Automatic error handling and cleanup
    - REST API helper with bearer token authentication
    - Device information utilities

.NOTES
    Version:    2025.12.27.11
    Target:     Level.io RMM
    Location:   {{cf_msp_scratch_folder}}\Libraries\LevelIO-Common.psm1

    Required Level.io Custom Fields:
    - {{cf_msp_scratch_folder}}       : Persistent storage folder (e.g., C:\ProgramData\MSP)
    - {{cf_ps_module_library_source}} : URL to download this module from GitHub or custom host

    Copyright (c) COOLNETWORKS
    https://coolnetworks.au
    https://github.com/coolnetworks/LevelLib

.LINK
    https://github.com/coolnetworks/LevelLib

.EXAMPLE
    # Import and use the module
    Import-Module "C:\ProgramData\MSP\Libraries\LevelIO-Common.psm1" -Force

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
    Base path for MSP files. Typically "{{cf_msp_scratch_folder}}".
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
                                   -MspScratchFolder "{{cf_msp_scratch_folder}}" `
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

    Write-Host "$Timestamp $Prefix $Message"
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
    - Exits with appropriate code (0 = success, 1 = failure)

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
        [switch]$NoCleanup
    )

    # Ensure initialization was called
    if (-not $script:Initialized) {
        Write-LevelLog "ERROR: Initialize-LevelScript must be called first!" -Level "ERROR"
        exit 1
    }

    try {
        # Execute the main script logic
        & $ScriptBlock

        Write-LevelLog "Script completed successfully" -Level "SUCCESS"

        if (-not $NoCleanup) {
            Remove-LevelLockFile
        }
        exit 0
    }
    catch {
        Write-LevelLog "FATAL: $($_.Exception.Message)" -Level "ERROR"
        Write-LevelLog "Stack: $($_.ScriptStackTrace)" -Level "DEBUG"

        if (-not $NoCleanup) {
            Remove-LevelLockFile
        }
        exit 1
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

<#
.SYNOPSIS
    Makes authenticated REST API calls with standardized error handling.

.DESCRIPTION
    Wrapper for Invoke-RestMethod with:
    - Bearer token authentication
    - JSON content type headers
    - Automatic body serialization
    - Standardized success/failure response format

.PARAMETER Uri
    Full API endpoint URL.

.PARAMETER ApiKey
    Bearer token for authentication. Sent as "Authorization: Bearer $ApiKey".

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

    # Set up headers with bearer token authentication
    $Headers = @{
        "Authorization" = "Bearer $ApiKey"
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
# EXPORT MODULE MEMBERS
# ============================================================
Export-ModuleMember -Function @(
    'Initialize-LevelScript',
    'Write-LevelLog',
    'Invoke-LevelScript',
    'Remove-LevelLockFile',
    'Complete-LevelScript',
    'Test-LevelAdmin',
    'Get-LevelDeviceInfo',
    'Invoke-LevelApiCall'
)
