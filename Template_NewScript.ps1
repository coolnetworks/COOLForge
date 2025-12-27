# [SCRIPT NAME HERE]
# Template Version: 2025.12.27.2
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
$LibraryFolder = Join-Path -Path $MspScratchFolder -ChildPath "Libraries"
$LibraryPath = Join-Path -Path $LibraryFolder -ChildPath "LevelIO-Common.psm1"
$LibraryUrl = "https://raw.githubusercontent.com/coolnetworks/LevelLib/main/LevelIO-Common.psm1"

# Create Libraries folder if needed
if (!(Test-Path $LibraryFolder)) {
    New-Item -Path $LibraryFolder -ItemType Directory -Force | Out-Null
}

# Function to get version from module content
function Get-ModuleVersion {
    param([string]$Content)
    if ($Content -match '# Version:\s*([\d\.]+)') {
        return $Matches[1]
    }
    return "0.0.0"
}

# Check for updates or install
$NeedsUpdate = $false
$LocalVersion = "0.0.0"
$RemoteVersion = "0.0.0"

if (Test-Path $LibraryPath) {
    $LocalContent = Get-Content -Path $LibraryPath -Raw -ErrorAction SilentlyContinue
    $LocalVersion = Get-ModuleVersion -Content $LocalContent
}
else {
    $NeedsUpdate = $true
    Write-Host "[*] Library not found - downloading..."
}

# Try to fetch latest version from GitHub
try {
    $RemoteContent = (Invoke-WebRequest -Uri $LibraryUrl -UseBasicParsing -TimeoutSec 10).Content
    $RemoteVersion = Get-ModuleVersion -Content $RemoteContent

    if ([version]$RemoteVersion -gt [version]$LocalVersion) {
        $NeedsUpdate = $true
        Write-Host "[*] Update available: $LocalVersion -> $RemoteVersion"
    }

    if ($NeedsUpdate) {
        Set-Content -Path $LibraryPath -Value $RemoteContent -Force -ErrorAction Stop
        Write-Host "[+] Library updated to v$RemoteVersion"
    }
}
catch {
    if (!(Test-Path $LibraryPath)) {
        Write-Host "[X] FATAL: Cannot download library and no local copy exists"
        Write-Host "[X] Error: $($_.Exception.Message)"
        exit 1
    }
    Write-Host "[!] Could not check for updates (using local v$LocalVersion)"
}

Import-Module $LibraryPath -Force

# ============================================================
# INITIALIZE
# ============================================================
$Init = Initialize-LevelScript -ScriptName "YourScriptName" `
                               -MspScratchFolder $MspScratchFolder `
                               -DeviceHostname "{{level_device_hostname}}" `
                               -DeviceTags "{{level_tag_names}}"

if (-not $Init.Success) {
    exit 0  # Tag blocked or already running - graceful exit
}

# ============================================================
# MAIN SCRIPT LOGIC
# ============================================================
Invoke-LevelScript -ScriptBlock {

    # --------------------------------------------------------
    # YOUR CODE HERE
    # --------------------------------------------------------

    Write-LevelLog "Doing the thing..."

    # Example: Get device info
    $DeviceInfo = Get-LevelDeviceInfo
    Write-LevelLog "Running on: $($DeviceInfo.OS)"

    # Example: API call
    # $Result = Invoke-LevelApiCall -Uri "https://api.example.com/endpoint" -ApiKey "{{cf_apikey}}"

}
