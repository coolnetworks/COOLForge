<#
.SYNOPSIS
    Template script for creating new Level.io automation scripts.

.DESCRIPTION
    This template provides a standardized structure for creating PowerShell scripts
    that run on Level.io managed endpoints. It includes:

    - Automatic library download and update from GitHub
    - Version comparison to ensure latest library is always used
    - Graceful fallback to local copy if GitHub is unreachable
    - Script initialization with tag gating and lockfile management
    - Structured error handling via Invoke-LevelScript wrapper

    USAGE:
    1. Copy this template to create a new script
    2. Replace [SCRIPT NAME HERE] with your script name
    3. Update the ScriptName parameter in Initialize-LevelScript
    4. Add your code inside the Invoke-LevelScript block
    5. Optionally configure BlockingTags for tag-based exclusions

.NOTES
    Template Version: 2025.12.27.11
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

.EXAMPLE
    # Basic usage - just add your code inside the Invoke-LevelScript block:

    Invoke-LevelScript -ScriptBlock {
        Write-LevelLog "Starting my task..."
        # Your code here
        Write-LevelLog "Task completed" -Level SUCCESS
    }

.EXAMPLE
    # Using tag blocking to exclude specific devices:

    $Init = Initialize-LevelScript -ScriptName "MyScript" `
                                   -MspScratchFolder $MspScratchFolder `
                                   -DeviceHostname "{{level_device_hostname}}" `
                                   -DeviceTags "{{level_tag_names}}" `
                                   -BlockingTags @("NoUpdates", "MaintenanceMode")
#>

# [SCRIPT NAME HERE]
# Template Version: 2025.12.27.11
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
# This section handles automatic downloading and updating of the
# LevelIO-Common library from GitHub. It ensures scripts always
# use the latest version while gracefully handling offline scenarios.

# Level.io custom fields
# $MspScratchFolder: Persistent storage folder on the endpoint
# $LibraryUrl: URL to download the LevelIO-Common library (allows private repos/forks)
$MspScratchFolder = "{{cf_msp_scratch_folder}}"
$LibraryUrl = "{{cf_ps_module_library_source}}"

# Define library storage location within the scratch folder
$LibraryFolder = Join-Path -Path $MspScratchFolder -ChildPath "Libraries"
$LibraryPath = Join-Path -Path $LibraryFolder -ChildPath "LevelIO-Common.psm1"

# Create Libraries folder if it doesn't exist
# This is where we'll store the downloaded library
if (!(Test-Path $LibraryFolder)) {
    New-Item -Path $LibraryFolder -ItemType Directory -Force | Out-Null
}

# Function to extract version number from module content
# Matches "Version:" followed by version number (handles both .NOTES and comment styles)
function Get-ModuleVersion {
    param([string]$Content)
    if ($Content -match 'Version:\s*([\d\.]+)') {
        return $Matches[1]
    }
    return "0.0.0"
}

# Version tracking variables
$NeedsUpdate = $false
$LocalVersion = "0.0.0"
$RemoteVersion = "0.0.0"

# Check if library already exists locally and get its version
if (Test-Path $LibraryPath) {
    $LocalContent = Get-Content -Path $LibraryPath -Raw -ErrorAction SilentlyContinue
    $LocalVersion = Get-ModuleVersion -Content $LocalContent
}
else {
    # No local copy exists - must download
    $NeedsUpdate = $true
    Write-Host "[*] Library not found - downloading..."
}

# Attempt to fetch the latest version from GitHub
# Compare versions and update if a newer version is available
try {
    $RemoteContent = (Invoke-WebRequest -Uri $LibraryUrl -UseBasicParsing -TimeoutSec 10).Content
    $RemoteVersion = Get-ModuleVersion -Content $RemoteContent

    # Compare versions using PowerShell's [version] type for proper semantic comparison
    if ([version]$RemoteVersion -gt [version]$LocalVersion) {
        $NeedsUpdate = $true
        Write-Host "[*] Update available: $LocalVersion -> $RemoteVersion"
    }

    # Download and save the new version if needed
    if ($NeedsUpdate) {
        Set-Content -Path $LibraryPath -Value $RemoteContent -Force -ErrorAction Stop
        Write-Host "[+] Library updated to v$RemoteVersion"
    }
}
catch {
    # GitHub unreachable - check if we have a local fallback
    if (!(Test-Path $LibraryPath)) {
        # No local copy and can't download - fatal error
        Write-Host "[X] FATAL: Cannot download library and no local copy exists"
        Write-Host "[X] Error: $($_.Exception.Message)"
        exit 1
    }
    # Local copy exists - continue with potentially outdated version
    Write-Host "[!] Could not check for updates (using local v$LocalVersion)"
}

# Import the library module, making all functions available
# Use New-Module with ScriptBlock to bypass execution policy while maintaining module context
$ModuleContent = Get-Content -Path $LibraryPath -Raw
New-Module -Name "LevelIO-Common" -ScriptBlock ([scriptblock]::Create($ModuleContent)) | Import-Module -Force

# ============================================================
# INITIALIZE
# ============================================================
# Initialize the script with tag checking and lockfile management
#
# Parameters:
#   -ScriptName       : Unique identifier for this script (used for lockfiles)
#   -MspScratchFolder : Path to persistent storage folder
#   -DeviceHostname   : Current device hostname (for logging)
#   -DeviceTags       : Comma-separated device tags (for tag gating)
#   -BlockingTags     : Array of tags that should prevent execution (optional)
#   -SkipTagCheck     : Skip tag validation (optional)
#   -SkipLockFile     : Skip lockfile creation (optional)

$Init = Initialize-LevelScript -ScriptName "YourScriptName" `
                               -MspScratchFolder $MspScratchFolder `
                               -DeviceHostname "{{level_device_hostname}}" `
                               -DeviceTags "{{level_tag_names}}" `
                               -BlockingTags @("❌")

# Check initialization result
# If tag blocked or already running, exit gracefully (exit 0)
# This prevents the script from showing as "failed" in Level.io
if (-not $Init.Success) {
    exit 0  # Tag blocked or already running - graceful exit
}

# ============================================================
# MAIN SCRIPT LOGIC
# ============================================================
# Wrap your main code in Invoke-LevelScript for:
# - Automatic error handling and logging
# - Proper exit code management
# - Lockfile cleanup on completion
#
# Your code goes inside the ScriptBlock parameter.
# Use Write-LevelLog for consistent logging throughout.

Invoke-LevelScript -ScriptBlock {

    # --------------------------------------------------------
    # YOUR CODE HERE
    # --------------------------------------------------------

    Write-LevelLog "Doing the thing..."

    # Example: Get device info
    # Returns hashtable with: Hostname, Username, Domain, OS, OSVersion, IsAdmin, PowerShell, ScriptPID
    $DeviceInfo = Get-LevelDeviceInfo
    Write-LevelLog "Running on: $($DeviceInfo.OS)"

    # Example: API call with Bearer token authentication
    # $Result = Invoke-LevelApiCall -Uri "https://api.example.com/endpoint" -ApiKey "{{cf_apikey}}"

}
