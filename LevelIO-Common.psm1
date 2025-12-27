# LevelIO-Common.psm1
# Version: 2025.12.27.2
# Target: Level.io
# Shared library for all Level.io automation scripts
# Location: {{cf_msp_scratch_folder}}\Libraries\LevelIO-Common.psm1
#
# Copyright (c) COOLNETWORKS
# https://coolnetworks.au
# https://github.com/coolnetworks/LevelLib

# ============================================================
# MODULE VARIABLES (set via Initialize-LevelScript)
# ============================================================
$script:ScriptName = $null
$script:LockFilePath = $null
$script:LockFile = $null
$script:DeviceHostname = $null
$script:Initialized = $false

# ============================================================
# INITIALIZATION
# ============================================================
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
        [string[]]$BlockingTags = @("❌"),
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipTagCheck,
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipLockFile
    )
    
    $script:ScriptName = $ScriptName
    $script:DeviceHostname = $DeviceHostname
    $script:LockFilePath = Join-Path -Path $MspScratchFolder -ChildPath "lockfiles"
    $script:LockFile = Join-Path -Path $script:LockFilePath -ChildPath "$ScriptName.lock"
    
    Write-LevelLog "Initializing: $ScriptName on $DeviceHostname"
    
    # --- Tag Gate Check ---
    if (-not $SkipTagCheck -and $DeviceTags) {
        $TagArray = $DeviceTags -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        foreach ($BlockTag in $BlockingTags) {
            if ($TagArray -contains $BlockTag) {
                Write-LevelLog "Tag '$BlockTag' is SET - script blocked" -Level "SKIP"
                return @{ Success = $false; Reason = "TagBlocked"; Tag = $BlockTag }
            }
        }
    }
    
    # --- Lockfile Setup ---
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
                $ExistingProcess = Get-Process -Id $LockContent.PID -ErrorAction SilentlyContinue
                if ($ExistingProcess) {
                    Write-LevelLog "Already running (PID: $($LockContent.PID))" -Level "SKIP"
                    return @{ Success = $false; Reason = "AlreadyRunning"; PID = $LockContent.PID }
                }
            }
            # Stale lockfile - remove it
            Remove-Item -Path $script:LockFile -Force -ErrorAction SilentlyContinue
        }
        
        # Create new lockfile
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
        "SUCCESS" { "[✓]" }
        "SKIP"    { "[-]" }
        "DEBUG"   { "[D]" }
    }
    
    Write-Host "$Timestamp $Prefix $Message"
}

# ============================================================
# SCRIPT EXECUTION WRAPPER
# ============================================================
function Invoke-LevelScript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        
        [Parameter(Mandatory = $false)]
        [switch]$NoCleanup
    )
    
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
function Remove-LevelLockFile {
    if ($script:LockFile -and (Test-Path $script:LockFile)) {
        Remove-Item -Path $script:LockFile -Force -ErrorAction SilentlyContinue
        Write-LevelLog "Lockfile removed" -Level "DEBUG"
    }
}

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
function Test-LevelAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-LevelDeviceInfo {
    return @{
        Hostname      = $env:COMPUTERNAME
        Username      = $env:USERNAME
        Domain        = $env:USERDOMAIN
        OS            = (Get-CimInstance Win32_OperatingSystem).Caption
        OSVersion     = (Get-CimInstance Win32_OperatingSystem).Version
        IsAdmin       = Test-LevelAdmin
        PowerShell    = $PSVersionTable.PSVersion.ToString()
        ScriptPID     = $PID
    }
}

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
    
    $Headers = @{
        "Authorization" = "Bearer $ApiKey"
        "Content-Type"  = "application/json"
        "Accept"        = "application/json"
    }
    
    $Params = @{
        Uri             = $Uri
        Method          = $Method
        Headers         = $Headers
        TimeoutSec      = $TimeoutSec
        UseBasicParsing = $true
    }
    
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