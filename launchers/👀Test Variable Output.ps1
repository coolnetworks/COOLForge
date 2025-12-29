# ============================================================
# SCRIPT TO RUN - PRE-CONFIGURED
# ============================================================
$ScriptToRun = "👀Test Variable Output.ps1"
# ============================================================

<#
.SYNOPSIS
    Level.io Script Launcher - Downloads and executes scripts from GitHub with auto-update.

.DESCRIPTION
    This launcher script provides a single deployment point for running scripts from your
    GitHub repository. Instead of deploying individual scripts via Level.io, you deploy
    this launcher once and it handles:

    - Downloading the requested script from GitHub
    - Version checking and automatic updates
    - Backup/restore safety for corrupted downloads
    - Passing all Level.io variables to the downloaded script
    - Library auto-update (same as template scripts)

    USAGE:
    1. Copy this launcher code into a new Level.io script
    2. Change $ScriptToRun at the TOP of this script to your script name
    3. Run the script - it will download and execute the matching GitHub script

    BENEFITS:
    - Scripts update automatically from GitHub
    - No need to redeploy when scripts change
    - Centralized script management in your repository

.NOTES
    Launcher Version: 2025.12.29.01
    Target Platform:  Level.io RMM
    Exit Codes:       0 = Success | 1 = Alert (Failure)

    Level.io Variables Used:
    - {{cf_CoolForge_msp_scratch_folder}}      : MSP-defined scratch folder for persistent storage
    - {{cf_CoolForge_ps_module_library_source}}: URL to download COOLForge-Common.psm1 library
                                       (scripts URL is derived from this automatically)
    - {{cf_CoolForge_pin_psmodule_to_version}} : (Optional) Pin to specific version tag (e.g., "v2025.12.29")
                                       If not set, uses latest from main branch
    - {{level_device_hostname}}      : Device hostname from Level.io
    - {{level_tag_names}}            : Comma-separated list of device tags

    Copyright (c) COOLNETWORKS
    https://coolnetworks.au
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge

.EXAMPLE
    # Change the script name at the top of the launcher:
    $ScriptToRun = "👀Test Show Versions.ps1"
    # ... rest of launcher code ...

.EXAMPLE
    # Or use a custom field to control which script runs:
    $ScriptToRun = "{{cf_script_to_run}}"
    # ... rest of launcher code ...
#>

# Script Launcher
# Launcher Version: 2025.12.29.01
# Target: Level.io
# Exit 0 = Success | Exit 1 = Alert (Failure)
#
# Copyright (c) COOLNETWORKS
# https://coolnetworks.au
# https://github.com/coolnetworks/COOLForge
$ErrorActionPreference = "SilentlyContinue"

# ============================================================
# LEVEL.IO VARIABLES - PASSED TO DOWNLOADED SCRIPT
# ============================================================
# These variables will be passed to the downloaded script
$MspScratchFolder = "{{cf_CoolForge_msp_scratch_folder}}"
if ([string]::IsNullOrWhiteSpace($MspScratchFolder) -or $MspScratchFolder -eq "{{cf_CoolForge_msp_scratch_folder}}") {
    $MspScratchFolder = "{{cf_msp_scratch_folder}}"  # Fallback to legacy field name
}
$DeviceHostname = "{{level_device_hostname}}"
$DeviceTags = "{{level_tag_names}}"

# Version pinning - if set, use specific version tag instead of main branch
$PinnedVersion = "{{cf_CoolForge_pin_psmodule_to_version}}"
if ([string]::IsNullOrWhiteSpace($PinnedVersion) -or $PinnedVersion -eq "{{cf_CoolForge_pin_psmodule_to_version}}") {
    $PinnedVersion = "{{cf_pin_psmodule_to_version}}"  # Fallback to legacy
}
$UsePinnedVersion = $false
if (-not [string]::IsNullOrWhiteSpace($PinnedVersion) -and $PinnedVersion -ne "{{cf_CoolForge_pin_psmodule_to_version}}" -and $PinnedVersion -ne "{{cf_pin_psmodule_to_version}}") {
    $UsePinnedVersion = $true
    Write-Host "[*] Version pinned to: $PinnedVersion"
}

# Library URL - uses custom field if set, otherwise defaults to official repo
$LibraryUrl = "{{cf_CoolForge_ps_module_library_source}}"
if ([string]::IsNullOrWhiteSpace($LibraryUrl) -or $LibraryUrl -eq "{{cf_CoolForge_ps_module_library_source}}") {
    $LibraryUrl = "{{cf_ps_module_library_source}}"  # Fallback to legacy
}
if ([string]::IsNullOrWhiteSpace($LibraryUrl) -or $LibraryUrl -eq "{{cf_CoolForge_ps_module_library_source}}" -or $LibraryUrl -eq "{{cf_ps_module_library_source}}") {
    # Default to official repo - use pinned version or main branch
    $Branch = if ($UsePinnedVersion) { $PinnedVersion } else { "main" }
    $LibraryUrl = "https://raw.githubusercontent.com/coolnetworks/COOLForge/$Branch/modules/COOLForge-Common.psm1"
} elseif ($UsePinnedVersion) {
    # Custom URL provided but version pinning requested - replace branch in URL
    # Pattern: .../coolnetworks/COOLForge/main/... -> .../coolnetworks/COOLForge/$PinnedVersion/...
    $LibraryUrl = $LibraryUrl -replace '/COOLForge/[^/]+/', "/COOLForge/$PinnedVersion/"
}

# Additional custom fields can be added here and they will be available
# in the downloaded script's scope
# $ApiKey = "{{cf_apikey}}"
# $CustomField1 = "{{cf_custom_field_1}}"

# Derive base URL and scripts URL from library URL
# Example: https://raw.githubusercontent.com/.../main/COOLForge-Common.psm1
#       -> https://raw.githubusercontent.com/.../main/scripts
$RepoBaseUrl = $LibraryUrl -replace '/[^/]+$', ''
$ScriptRepoBaseUrl = "$RepoBaseUrl/scripts"
$MD5SumsUrl = "$RepoBaseUrl/MD5SUMS"

# ============================================================
# LIBRARY AUTO-UPDATE & IMPORT
# ============================================================
# This section handles automatic downloading and updating of the
# COOLForge-Common library from GitHub. It ensures scripts always
# use the latest version while gracefully handling offline scenarios.

# Define library storage location within the scratch folder
$LibraryFolder = Join-Path -Path $MspScratchFolder -ChildPath "Libraries"
$LibraryPath = Join-Path -Path $LibraryFolder -ChildPath "COOLForge-Common.psm1"

# Create Libraries folder if it doesn't exist
if (!(Test-Path $LibraryFolder)) {
    New-Item -Path $LibraryFolder -ItemType Directory -Force | Out-Null
}

# Function to extract version number from content
function Get-ModuleVersion {
    param([string]$Content, [string]$Source = "unknown")
    if ($Content -match 'Version:\s*([\d\.]+)') {
        return $Matches[1]
    }
    throw "Could not parse version from $Source - invalid or corrupt content"
}

# Function to compute MD5 hash of content
function Get-ContentMD5 {
    param([string]$Content)
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Content)
    $hash = $md5.ComputeHash($bytes)
    return ([BitConverter]::ToString($hash) -replace '-', '').ToLower()
}

# Function to get expected MD5 from MD5SUMS file
function Get-ExpectedMD5 {
    param([string]$FileName, [string]$MD5Content)
    foreach ($line in $MD5Content -split "`n") {
        $line = $line.Trim()
        if ($line -match '^#' -or [string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -match '^([a-f0-9]{32})\s+(.+)$') {
            if ($Matches[2].Trim() -eq $FileName) {
                return $Matches[1].ToLower()
            }
        }
    }
    return $null
}

# Load MD5SUMS file from repository
$MD5SumsContent = $null
try {
    $MD5SumsContent = (Invoke-WebRequest -Uri $MD5SumsUrl -UseBasicParsing -TimeoutSec 5).Content
}
catch {
    Write-Host "[!] Could not download MD5SUMS - checksum verification disabled"
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
        Write-Host "[!] Local library corrupt - will redownload"
        $NeedsUpdate = $true
    }
}
else {
    $NeedsUpdate = $true
    Write-Host "[*] Library not found - downloading..."
}

# Attempt to fetch the latest version from GitHub
try {
    $RemoteContent = (Invoke-WebRequest -Uri $LibraryUrl -UseBasicParsing -TimeoutSec 10).Content
    $RemoteVersion = Get-ModuleVersion -Content $RemoteContent -Source "remote URL"

    if ($null -eq $LocalVersion -or [version]$RemoteVersion -gt [version]$LocalVersion) {
        $NeedsUpdate = $true
        if ($LocalVersion) {
            Write-Host "[*] Library update available: $LocalVersion -> $RemoteVersion"
        }
    }

    if ($NeedsUpdate) {
        if ($LocalVersion -and $LocalContent) {
            Set-Content -Path $BackupPath -Value $LocalContent -Force -ErrorAction Stop
        }

        Set-Content -Path $LibraryPath -Value $RemoteContent -Force -ErrorAction Stop

        try {
            $VerifyContent = Get-Content -Path $LibraryPath -Raw -ErrorAction Stop
            $null = Get-ModuleVersion -Content $VerifyContent -Source "downloaded file"

            # Verify MD5 checksum if available
            if ($MD5SumsContent) {
                $ExpectedMD5 = Get-ExpectedMD5 -FileName "COOLForge-Common.psm1" -MD5Content $MD5SumsContent
                if ($ExpectedMD5) {
                    $ActualMD5 = Get-ContentMD5 -Content $RemoteContent
                    if ($ActualMD5 -ne $ExpectedMD5) {
                        throw "MD5 checksum mismatch: expected $ExpectedMD5, got $ActualMD5"
                    }
                    Write-Host "[+] Library checksum verified"
                }
            }

            if (Test-Path $BackupPath) {
                Remove-Item -Path $BackupPath -Force -ErrorAction SilentlyContinue
            }
            Write-Host "[+] Library updated to v$RemoteVersion"
        }
        catch {
            if (Test-Path $BackupPath) {
                Write-Host "[!] Downloaded library corrupt or checksum failed - restoring backup"
                Move-Item -Path $BackupPath -Destination $LibraryPath -Force
            }
            throw "Downloaded library failed verification: $($_.Exception.Message)"
        }
    }
}
catch {
    if (Test-Path $BackupPath) {
        Move-Item -Path $BackupPath -Destination $LibraryPath -Force -ErrorAction SilentlyContinue
    }

    if (!(Test-Path $LibraryPath) -or $null -eq $LocalVersion) {
        Write-Host "[X] FATAL: Cannot download library and no valid local copy exists"
        Write-Host "[X] Error: $($_.Exception.Message)"
        exit 1
    }
    Write-Host "[!] Could not check for library updates (using local v$LocalVersion)"
}

# Import the library module
$ModuleContent = Get-Content -Path $LibraryPath -Raw
New-Module -Name "COOLForge-Common" -ScriptBlock ([scriptblock]::Create($ModuleContent)) | Import-Module -Force

# Verify critical functions are available - if not, force redownload
if (-not (Get-Command -Name "Repair-LevelEmoji" -ErrorAction SilentlyContinue)) {
    Write-Host "[!] Library missing critical functions - forcing redownload"
    Remove-Item -Path $LibraryPath -Force -ErrorAction SilentlyContinue
    try {
        $RemoteContent = (Invoke-WebRequest -Uri $LibraryUrl -UseBasicParsing -TimeoutSec 10).Content
        Set-Content -Path $LibraryPath -Value $RemoteContent -Force -ErrorAction Stop
        $ModuleContent = Get-Content -Path $LibraryPath -Raw
        Remove-Module -Name "COOLForge-Common" -Force -ErrorAction SilentlyContinue
        New-Module -Name "COOLForge-Common" -ScriptBlock ([scriptblock]::Create($ModuleContent)) | Import-Module -Force
        Write-Host "[+] Library redownloaded successfully"
    }
    catch {
        Write-Host "[X] FATAL: Failed to redownload library: $($_.Exception.Message)"
        exit 1
    }
}

# ============================================================
# VALIDATE CONFIGURATION
# ============================================================
if ([string]::IsNullOrWhiteSpace($ScriptToRun)) {
    Write-Host "[X] FATAL: No script specified. Set `$ScriptToRun at the top of this script."
    exit 1
}

# ============================================================
# FIX EMOJI ENCODING
# ============================================================
# Level.io may corrupt UTF-8 emojis when deploying scripts.
# Use library function to repair corrupted emojis.
$ScriptToRun = Repair-LevelEmoji -Text $ScriptToRun

# ============================================================
# SCRIPT DOWNLOAD & EXECUTION
# ============================================================
# Download the requested script from GitHub and execute it

Write-Host "[*] Script Launcher v2025.12.29.01"
Write-Host "[*] Preparing to run: $ScriptToRun"

# Define script storage location
$ScriptsFolder = Join-Path -Path $MspScratchFolder -ChildPath "Scripts"
if (!(Test-Path $ScriptsFolder)) {
    New-Item -Path $ScriptsFolder -ItemType Directory -Force | Out-Null
}

# Sanitize script name for filesystem (replace problematic characters)
$SafeScriptName = $ScriptToRun -replace '[<>:"/\\|?*]', '_'
$ScriptPath = Join-Path -Path $ScriptsFolder -ChildPath $SafeScriptName

# URL-encode the script name for the download URL
# Use library function for proper UTF-8 emoji handling
$ScriptUrl = "$ScriptRepoBaseUrl/$(Get-LevelUrlEncoded $ScriptToRun)"

# Check for local version
$ScriptNeedsUpdate = $false
$LocalScriptVersion = $null
$LocalScriptContent = $null
$ScriptBackupPath = "$ScriptPath.backup"

if (Test-Path $ScriptPath) {
    try {
        $LocalScriptContent = Get-Content -Path $ScriptPath -Raw -ErrorAction Stop
        $LocalScriptVersion = Get-ModuleVersion -Content $LocalScriptContent -Source "local script"
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

    # Try to get version, but don't require it for scripts
    try {
        $RemoteScriptVersion = Get-ModuleVersion -Content $RemoteScriptContent -Source "remote script"

        if ($null -eq $LocalScriptVersion -or [version]$RemoteScriptVersion -gt [version]$LocalScriptVersion) {
            $ScriptNeedsUpdate = $true
            if ($LocalScriptVersion) {
                Write-Host "[*] Script update available: $LocalScriptVersion -> $RemoteScriptVersion"
            }
        }
    }
    catch {
        # Script doesn't have a version number - always update if we downloaded successfully
        $ScriptNeedsUpdate = $true
    }

    if ($ScriptNeedsUpdate) {
        # Backup working local copy before updating
        if ($LocalScriptVersion -and $LocalScriptContent) {
            Set-Content -Path $ScriptBackupPath -Value $LocalScriptContent -Force -ErrorAction Stop
        }

        # Write new version
        Set-Content -Path $ScriptPath -Value $RemoteScriptContent -Force -ErrorAction Stop

        # Verify the file was written correctly
        try {
            $VerifyScriptContent = Get-Content -Path $ScriptPath -Raw -ErrorAction Stop
            if ($VerifyScriptContent.Length -lt 50) {
                throw "Downloaded script appears to be empty or truncated"
            }

            # Verify MD5 checksum if available
            if ($MD5SumsContent) {
                $ScriptMD5Key = "scripts/$ScriptToRun"
                $ExpectedScriptMD5 = Get-ExpectedMD5 -FileName $ScriptMD5Key -MD5Content $MD5SumsContent
                if ($ExpectedScriptMD5) {
                    $ActualScriptMD5 = Get-ContentMD5 -Content $RemoteScriptContent
                    if ($ActualScriptMD5 -ne $ExpectedScriptMD5) {
                        throw "MD5 checksum mismatch: expected $ExpectedScriptMD5, got $ActualScriptMD5"
                    }
                    Write-Host "[+] Script checksum verified"
                }
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
            # New file is corrupt or checksum failed - restore backup
            if (Test-Path $ScriptBackupPath) {
                Write-Host "[!] Downloaded script corrupt or checksum failed - restoring backup"
                Move-Item -Path $ScriptBackupPath -Destination $ScriptPath -Force
            }
            throw "Downloaded script failed verification: $($_.Exception.Message)"
        }
    }
}
catch {
    # GitHub unreachable or download failed
    if (Test-Path $ScriptBackupPath) {
        Move-Item -Path $ScriptBackupPath -Destination $ScriptPath -Force -ErrorAction SilentlyContinue
    }

    if (!(Test-Path $ScriptPath)) {
        Write-Host "[X] FATAL: Cannot download script and no local copy exists"
        Write-Host "[X] URL: $ScriptUrl"
        Write-Host "[X] Error: $($_.Exception.Message)"
        exit 1
    }
    Write-Host "[!] Could not check for script updates (using cached version)"
}

# ============================================================
# EXECUTE THE DOWNLOADED SCRIPT
# ============================================================
# The script is executed in a child scope with all Level.io variables available

Write-Host "[*] Executing: $ScriptToRun"
Write-Host "============================================================"

# Read the script content
$ScriptContent = Get-Content -Path $ScriptPath -Raw

# Create a scriptblock that:
# 1. Defines all Level.io variables in the script's scope
# 2. Executes the downloaded script content
$ExecutionBlock = @"
# Level.io variables passed from launcher
`$MspScratchFolder = '$($MspScratchFolder -replace "'", "''")'
`$LibraryUrl = '$($LibraryUrl -replace "'", "''")'
`$DeviceHostname = '$($DeviceHostname -replace "'", "''")'
`$DeviceTags = '$($DeviceTags -replace "'", "''")'

# Additional custom fields can be added here
# `$ApiKey = '$($ApiKey -replace "'", "''")'

# The downloaded script content follows:
$ScriptContent
"@

# Execute the script
try {
    $ScriptBlock = [scriptblock]::Create($ExecutionBlock)
    & $ScriptBlock
    $ScriptExitCode = $LASTEXITCODE
    if ($null -eq $ScriptExitCode) { $ScriptExitCode = 0 }
}
catch {
    Write-Host "[X] Script execution failed: $($_.Exception.Message)"
    exit 1
}

# Pass through the script's exit code
exit $ScriptExitCode
