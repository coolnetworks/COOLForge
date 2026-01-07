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
    Template Version: 2025.12.27.14
    Target Platform:  Level.io RMM
    Exit Codes:       0 = Success | 1 = Alert (Failure)

    Level.io Variables Used:
    - {{cf_coolforge_msp_scratch_folder}}      : MSP-defined scratch folder for persistent storage
    - {{cf_coolforge_ps_module_library_source}}: URL to download COOLForge-Common.psm1 library
    - {{level_device_hostname}}      : Device hostname from Level.io
    - {{level_tag_names}}            : Comma-separated list of device tags

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge

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
# Template Version: 2025.12.27.14
# Target: Level.io
# Exit 0 = Success | Exit 1 = Alert (Failure)
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge
$ErrorActionPreference = "SilentlyContinue"

# ============================================================
# LIBRARY AUTO-UPDATE & IMPORT
# ============================================================
# This section handles automatic downloading and updating of the
# COOLForge-Common library from GitHub. It ensures scripts always
# use the latest version while gracefully handling offline scenarios.

# Level.io custom fields
# Supports both new (CoolForge_*) and legacy field names for backward compatibility
# $MspScratchFolder: Persistent storage folder on the endpoint
# $LibraryUrl: URL to download the COOLForge-Common library (allows private repos/forks)
$MspScratchFolder = "{{cf_coolforge_msp_scratch_folder}}"
if ([string]::IsNullOrWhiteSpace($MspScratchFolder) -or $MspScratchFolder -eq "{{cf_coolforge_msp_scratch_folder}}") {
    $MspScratchFolder = "{{cf_msp_scratch_folder}}"  # Fallback to legacy field name
}
$LibraryUrl = "{{cf_coolforge_ps_module_library_source}}"
if ([string]::IsNullOrWhiteSpace($LibraryUrl) -or $LibraryUrl -eq "{{cf_coolforge_ps_module_library_source}}") {
    $LibraryUrl = "{{cf_ps_module_library_source}}"  # Fallback to legacy field name
}

# Default to official repo if custom field not set
if ([string]::IsNullOrWhiteSpace($LibraryUrl) -or $LibraryUrl -eq "{{cf_coolforge_ps_module_library_source}}" -or $LibraryUrl -eq "{{cf_ps_module_library_source}}") {
    $LibraryUrl = "https://raw.githubusercontent.com/coolnetworks/COOLForge/main/modules/COOLForge-Common.psm1"
}

# Define library storage location within the scratch folder
$LibraryFolder = Join-Path -Path $MspScratchFolder -ChildPath "Libraries"
$LibraryPath = Join-Path -Path $LibraryFolder -ChildPath "COOLForge-Common.psm1"

# Create Libraries folder if it doesn't exist
# This is where we'll store the downloaded library
if (!(Test-Path $LibraryFolder)) {
    New-Item -Path $LibraryFolder -ItemType Directory -Force | Out-Null
}

# Function to extract version number from module content
# Matches "Version:" followed by version number (handles both .NOTES and comment styles)
function Get-ModuleVersion {
    param([string]$Content, [string]$Source = "unknown")
    if ($Content -match 'Version:\s*([\d\.]+)') {
        return $Matches[1]
    }
    throw "Could not parse version from $Source - invalid or corrupt library content"
}

# Check if library already exists locally and get its version
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
        # Local file exists but is corrupt - force redownload
        Write-Host "[!] Local library corrupt - will redownload"
        $NeedsUpdate = $true
    }
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
    $RemoteVersion = Get-ModuleVersion -Content $RemoteContent -Source "remote URL"

    # Compare versions using PowerShell's [version] type for proper semantic comparison
    if ($null -eq $LocalVersion -or [version]$RemoteVersion -gt [version]$LocalVersion) {
        $NeedsUpdate = $true
        if ($LocalVersion) {
            Write-Host "[*] Update available: $LocalVersion -> $RemoteVersion"
        }
    }

    # Download and save the new version if needed
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
        # No valid local copy and can't download - fatal error
        Write-Host "[X] FATAL: Cannot download library and no valid local copy exists"
        Write-Host "[X] Error: $($_.Exception.Message)"
        exit 1
    }
    # Valid local copy exists - continue with potentially outdated version
    Write-Host "[!] Could not check for updates (using local v$LocalVersion)"
}

# Import the library module, making all functions available
# Use New-Module with ScriptBlock to bypass execution policy while maintaining module context
$ModuleContent = Get-Content -Path $LibraryPath -Raw
New-Module -Name "COOLForge-Common" -ScriptBlock ([scriptblock]::Create($ModuleContent)) | Import-Module -Force

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
