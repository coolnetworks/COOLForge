# ============================================================
# SCRIPT TO RUN - PRE-CONFIGURED
# ============================================================
# Use plain text identifier to avoid emoji corruption by Level.io
$ScriptToRun = "unchecky.ps1"
$ScriptCategory = "Check"  # Check, Fix, Remove, or Maintain
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
    Launcher Version: 2025.12.31.01
    Target Platform:  Level.io RMM
    Exit Codes:       0 = Success | 1 = Alert (Failure)

    Level.io Variables Used:
    - {{cf_coolforge_msp_scratch_folder}}      : MSP-defined scratch folder for persistent storage
    - {{cf_coolforge_ps_module_library_source}}: URL to download COOLForge-Common.psm1 library
                                                  (scripts URL is derived from this automatically)
    - {{cf_coolforge_pin_psmodule_to_version}} : (Optional) Pin to specific version tag (e.g., "v2025.12.29")
                                                  If not set, uses latest from main branch
    - {{cf_coolforge_pat}}                     : (Optional) GitHub Personal Access Token for private repos
                                                  Admin-only custom field - token is never logged or visible
    - {{level_device_hostname}}                : Device hostname from Level.io
    - {{level_tag_names}}                      : Comma-separated list of device tags

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge

.EXAMPLE
    # Change the script name at the top of the launcher:
    $ScriptToRun = "unchecky.ps1"
    # ... rest of launcher code ...

#>

# Script Launcher
# Launcher Version: 2025.12.31.01
# Target: Level.io
# Exit 0 = Success | Exit 1 = Alert (Failure)
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge5
$ErrorActionPreference = "SilentlyContinue"

# ============================================================
# LEVEL.IO VARIABLES - PASSED TO DOWNLOADED SCRIPT
# ============================================================
# These variables will be passed to the downloaded script
# Supports both new (CoolForge_*) and legacy field names for backward compatibility
$MspScratchFolder = "{{cf_coolforge_msp_scratch_folder}}"
Write-Host "[DEBUG] cf_coolforge_msp_scratch_folder = '$MspScratchFolder'"
# Check if the field was substituted (not a template literal)
if ([string]::IsNullOrWhiteSpace($MspScratchFolder) -or $MspScratchFolder.StartsWith("{{")) {
    Write-Host "[DEBUG] Primary field empty/unset - trying legacy field"
    $MspScratchFolder = "{{cf_msp_scratch_folder}}"  # Fallback to legacy field name
    Write-Host "[DEBUG] cf_msp_scratch_folder = '$MspScratchFolder'"
}
# Final validation
if ([string]::IsNullOrWhiteSpace($MspScratchFolder) -or $MspScratchFolder.StartsWith("{{")) {
    Write-Host "[X] FATAL: cf_coolforge_msp_scratch_folder custom field is not set in Level.io"
    Write-Host "[X] Please set this field to your scratch folder path (e.g., C:\ProgramData\MSP)"
    exit 1
}
Write-Host "[DEBUG] Final MspScratchFolder = '$MspScratchFolder'"
$DeviceHostname = "{{level_device_hostname}}"
$DeviceTags = "{{level_tag_names}}"

# GitHub Personal Access Token for private repositories (admin-only custom field)
$GitHubPAT = "{{cf_coolforge_pat}}"
if ([string]::IsNullOrWhiteSpace($GitHubPAT) -or $GitHubPAT -eq "{{cf_coolforge_pat}}") {
    $GitHubPAT = $null
}

# Version pinning - if set, use specific version tag instead of main branch
# Check new field name first, then legacy
$PinnedVersion = "{{cf_coolforge_pin_psmodule_to_version}}"
Write-Host "[DEBUG] cf_coolforge_pin_psmodule_to_version = '$PinnedVersion'"
if ([string]::IsNullOrWhiteSpace($PinnedVersion) -or $PinnedVersion -eq "{{cf_coolforge_pin_psmodule_to_version}}" -or $PinnedVersion -like "{{*}}") {
    $PinnedVersion = "{{cf_pin_psmodule_to_version}}"  # Fallback to legacy
    Write-Host "[DEBUG] cf_pin_psmodule_to_version = '$PinnedVersion'"
}
$UsePinnedVersion = $false
# Check if we have a valid pin (not empty and not a template string)
if (-not [string]::IsNullOrWhiteSpace($PinnedVersion) -and $PinnedVersion -notlike "{{*}}") {
    $UsePinnedVersion = $true
    Write-Host "[*] Version pinned to: $PinnedVersion"
} else {
    Write-Host "[DEBUG] No version pin detected - using main branch"
    Write-Host "[DEBUG] PinnedVersion final value: '$PinnedVersion'"
}

# Library URL - uses custom field if set, otherwise defaults to official repo
# Check new field name first, then legacy
$LibraryUrl = "{{cf_coolforge_ps_module_library_source}}"
if ([string]::IsNullOrWhiteSpace($LibraryUrl) -or $LibraryUrl -eq "{{cf_coolforge_ps_module_library_source}}") {
    $LibraryUrl = "{{cf_ps_module_library_source}}"  # Fallback to legacy
}
if ([string]::IsNullOrWhiteSpace($LibraryUrl) -or $LibraryUrl -eq "{{cf_ps_module_library_source}}" -or $LibraryUrl -eq "{{cf_coolforge_ps_module_library_source}}") {
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

# ============================================================
# GITHUB PAT INJECTION HELPER
# ============================================================
# Function to inject GitHub PAT into URL if needed
function Add-GitHubToken {
    param([string]$Url, [string]$Token)

    # Only inject if:
    # 1. Token is provided
    # 2. URL is a GitHub raw content URL
    # 3. URL doesn't already contain a token
    if ([string]::IsNullOrWhiteSpace($Token)) { return $Url }
    if ($Url -notmatch 'raw\.githubusercontent\.com') { return $Url }
    if ($Url -match '@raw\.githubusercontent\.com') { return $Url }

    # Inject token: https://raw.githubusercontent.com -> https://TOKEN@raw.githubusercontent.com
    return $Url -replace '(https://)raw\.githubusercontent\.com', "`$1$Token@raw.githubusercontent.com"
}

# Derive base URL and scripts URL from library URL
# Example: https://raw.githubusercontent.com/.../dev/modules/COOLForge-Common.psm1
#       -> https://raw.githubusercontent.com/.../dev/scripts
# Strip /modules/COOLForge-Common.psm1 to get branch root
$RepoBaseUrl = $LibraryUrl -replace '/modules/[^/]+$', ''
$ScriptRepoBaseUrl = "$RepoBaseUrl/scripts"
$MD5SumsUrl = "$RepoBaseUrl/MD5SUMS"

Write-Host "[DEBUG] LibraryUrl = $LibraryUrl"
Write-Host "[DEBUG] RepoBaseUrl = $RepoBaseUrl"
Write-Host "[DEBUG] MD5SumsUrl = $MD5SumsUrl"

# Inject PAT if provided (for private repositories)
if ($GitHubPAT) {
    $LibraryUrl = Add-GitHubToken -Url $LibraryUrl -Token $GitHubPAT
    $MD5SumsUrl = Add-GitHubToken -Url $MD5SumsUrl -Token $GitHubPAT
    $ScriptRepoBaseUrl = Add-GitHubToken -Url $ScriptRepoBaseUrl -Token $GitHubPAT
}

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

# Function to find script path from MD5SUMS file
function Find-ScriptPath {
    param([string]$ScriptName, [string]$MD5Content)

    # Search for script in MD5SUMS entries
    foreach ($line in $MD5Content -split "`n") {
        $line = $line.Trim()
        if ($line -match '^#' -or [string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -match '^([a-f0-9]{32})\s+(.+)$') {
            $fullPath = $Matches[2].Trim()
            # Extract just the filename from the path
            $fileName = Split-Path -Path $fullPath -Leaf
            if ($fileName -eq $ScriptName) {
                return $fullPath
            }
        }
    }

    # Fallback: try flat structure (backward compatibility)
    return "scripts/$ScriptName"
}

# Load MD5SUMS file from repository (download as binary to preserve UTF-8 emoji encoding)
$MD5SumsContent = $null
try {
    $TempMD5Path = Join-Path -Path $env:TEMP -ChildPath "MD5SUMS.tmp"
    $WebClient = New-Object System.Net.WebClient
    $WebClient.DownloadFile($MD5SumsUrl, $TempMD5Path)
    $WebClient.Dispose()

    # Read as bytes and convert to UTF-8 string
    $MD5Bytes = [System.IO.File]::ReadAllBytes($TempMD5Path)
    $MD5SumsContent = [System.Text.Encoding]::UTF8.GetString($MD5Bytes)
    Remove-Item -Path $TempMD5Path -Force -ErrorAction SilentlyContinue
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
    # Download to temp file as binary to prevent encoding corruption
    $TempLibPath = "$LibraryPath.download"
    $WebClient = New-Object System.Net.WebClient
    $WebClient.DownloadFile($LibraryUrl, $TempLibPath)
    $WebClient.Dispose()

    # Read as bytes and convert to UTF-8 string
    $RemoteBytes = [System.IO.File]::ReadAllBytes($TempLibPath)
    $RemoteContent = [System.Text.Encoding]::UTF8.GetString($RemoteBytes)
    $RemoteVersion = Get-ModuleVersion -Content $RemoteContent -Source "remote URL"

    if ($null -eq $LocalVersion -or [version]$RemoteVersion -gt [version]$LocalVersion) {
        $NeedsUpdate = $true
        if ($LocalVersion) {
            Write-Host "[*] Library update available: $LocalVersion -> $RemoteVersion"
        }
    }

    if ($NeedsUpdate) {
        if ($LocalVersion -and $LocalContent) {
            $BackupBytes = [System.Text.Encoding]::UTF8.GetBytes($LocalContent)
            [System.IO.File]::WriteAllBytes($BackupPath, $BackupBytes)
        }

        # Move the temp download to final location
        Move-Item -Path $TempLibPath -Destination $LibraryPath -Force -ErrorAction Stop

        try {
            # Verify by reading as bytes
            $VerifyBytes = [System.IO.File]::ReadAllBytes($LibraryPath)
            $VerifyContent = [System.Text.Encoding]::UTF8.GetString($VerifyBytes)
            $null = Get-ModuleVersion -Content $VerifyContent -Source "downloaded file"

            # Skip MD5 verification for library - version check is sufficient

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
    # Clean up temp download file
    if (Test-Path "$LibraryPath.download") {
        Remove-Item -Path "$LibraryPath.download" -Force -ErrorAction SilentlyContinue
    }

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
finally {
    # Always clean up temp download file
    if (Test-Path "$LibraryPath.download") {
        Remove-Item -Path "$LibraryPath.download" -Force -ErrorAction SilentlyContinue
    }
}

# Import the library module
try {
    # Read file as binary and create module from scriptblock (bypasses execution policy on downloaded files)
    $ModuleBytes = [System.IO.File]::ReadAllBytes($LibraryPath)
    $ModuleContent = [System.Text.Encoding]::UTF8.GetString($ModuleBytes)
    $null = New-Module -Name "COOLForge-Common" -ScriptBlock ([scriptblock]::Create($ModuleContent)) | Import-Module -Force
    Write-Host "[+] Library imported successfully"
}
catch {
    Write-Host "[!] Library import failed - forcing redownload"
    Write-Host "[!] Error: $($_.Exception.Message)"
    Remove-Item -Path $LibraryPath -Force -ErrorAction SilentlyContinue
    try {
        # Redownload the library as binary
        $WebClient = New-Object System.Net.WebClient
        $WebClient.DownloadFile($LibraryUrl, $LibraryPath)
        $WebClient.Dispose()
        Write-Host "[+] Library redownloaded"

        # Read file as binary and create module from scriptblock
        $ModuleBytes = [System.IO.File]::ReadAllBytes($LibraryPath)
        $ModuleContent = [System.Text.Encoding]::UTF8.GetString($ModuleBytes)
        $null = New-Module -Name "COOLForge-Common" -ScriptBlock ([scriptblock]::Create($ModuleContent)) | Import-Module -Force
        Write-Host "[+] Library imported successfully after redownload"
    }
    catch {
        Write-Host "[X] FATAL: Failed to redownload library: $($_.Exception.Message)"
        exit 1
    }
}

# Verify critical functions are available
if (-not (Get-Command -Name "Repair-LevelEmoji" -ErrorAction SilentlyContinue)) {
    Write-Host "[X] FATAL: Library missing critical functions after import"
    exit 1
}

# ============================================================
# COPY DOCUMENTATION TO SCRATCH FOLDER
# ============================================================
# Copy "What is this folder.md" to scratch folder if it changed
$ReadmeUrl = "$RepoBaseUrl/templates/What is this folder.md"
$ReadmeDestPath = Join-Path -Path $MspScratchFolder -ChildPath "What is this folder.md"

try {
    $ReadmeRemoteContent = (Invoke-WebRequest -Uri $ReadmeUrl -UseBasicParsing -TimeoutSec 5).Content
    $NeedsReadmeUpdate = $false

    if (Test-Path $ReadmeDestPath) {
        $ReadmeLocalContent = Get-Content -Path $ReadmeDestPath -Raw -ErrorAction SilentlyContinue
        if ($ReadmeLocalContent -ne $ReadmeRemoteContent) {
            $NeedsReadmeUpdate = $true
        }
    }
    else {
        $NeedsReadmeUpdate = $true
    }

    if ($NeedsReadmeUpdate) {
        Set-Content -Path $ReadmeDestPath -Value $ReadmeRemoteContent -Force -ErrorAction Stop

        # Verify checksum if MD5SUMS available
        if ($MD5SumsContent) {
            $ExpectedReadmeMD5 = Get-ExpectedMD5 -FileName "templates/What is this folder.md" -MD5Content $MD5SumsContent
            if ($ExpectedReadmeMD5) {
                $ActualReadmeMD5 = Get-ContentMD5 -Content $ReadmeRemoteContent
                if ($ActualReadmeMD5 -eq $ExpectedReadmeMD5) {
                    Write-Host "[+] Documentation updated and verified"
                }
            }
        }
    }
}
catch {
    # Non-critical - don't fail if readme can't be downloaded
    Write-Host "[!] Could not update scratch folder documentation"
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
# Note: Repair-LevelEmoji not called because $ScriptToRun is hardcoded
# and the library itself may have emoji corruption during download.
# $ScriptToRun = Repair-LevelEmoji -Text $ScriptToRun

# ============================================================
# SCRIPT DOWNLOAD & EXECUTION
# ============================================================
# Download the requested script from GitHub and execute it

Write-Host "[*] Script Launcher v2025.12.31.01"
Write-Host "[*] Preparing to run: $ScriptToRun"

# Define script storage location
$ScriptsFolder = Join-Path -Path $MspScratchFolder -ChildPath "Scripts"
if (!(Test-Path $ScriptsFolder)) {
    New-Item -Path $ScriptsFolder -ItemType Directory -Force | Out-Null
}

# Sanitize script name for filesystem (replace problematic characters)
$SafeScriptName = $ScriptToRun -replace '[<>:"/\\|?*]', '_'
$ScriptPath = Join-Path -Path $ScriptsFolder -ChildPath $SafeScriptName

# Script category was set at the top of the file alongside $ScriptToRun
# Validate it's one of the allowed values
if ($ScriptCategory -notin @("Check", "Fix", "Remove", "Maintain")) {
    Write-Host "[!] Invalid script category '$ScriptCategory' - defaulting to 'Check'"
    $ScriptCategory = "Check"
}

# Determine emoji prefix for the actual script filename on GitHub
$EmojiPrefix = switch ($ScriptCategory) {
    "Check"    { [char]::ConvertFromUtf32(0x1F440) }  #  Eyes
    "Fix"      { [char]::ConvertFromUtf32(0x1F527) }  #  Wrench
    "Remove"   { [char]0x26D4 }                       #  Stop sign
    "Maintain" { [char]::ConvertFromUtf32(0x1F504) }  #  Counterclockwise arrows
}

# Full script name with emoji for GitHub
$FullScriptName = "$EmojiPrefix$ScriptToRun"

$ScriptRelativePath = "scripts/$ScriptCategory/$FullScriptName"
Write-Host "[*] Script category: $ScriptCategory"
Write-Host "[*] Script name: $FullScriptName"
Write-Host "[*] Script path: $ScriptRelativePath"

# Build download URL - encode only the filename to preserve emoji UTF-8
# Convert filename to UTF-8 bytes and URL-encode them manually
$ScriptNameBytes = [System.Text.Encoding]::UTF8.GetBytes($FullScriptName)
$EncodedScriptName = [System.Text.StringBuilder]::new()
foreach ($byte in $ScriptNameBytes) {
    if (($byte -ge 0x30 -and $byte -le 0x39) -or  # 0-9
        ($byte -ge 0x41 -and $byte -le 0x5A) -or  # A-Z
        ($byte -ge 0x61 -and $byte -le 0x7A) -or  # a-z
        $byte -eq 0x2D -or $byte -eq 0x2E -or $byte -eq 0x5F) {  # - . _
        [void]$EncodedScriptName.Append([char]$byte)
    } else {
        [void]$EncodedScriptName.Append(('%{0:X2}' -f $byte))
    }
}
$ScriptUrl = "$RepoBaseUrl/scripts/$ScriptCategory/$($EncodedScriptName.ToString())"

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

# Library is already loaded by launcher - skip library import in script
`$UseLibrary = `$true

# Tell scripts not to exit - launcher will handle exit after showing log
`$RunningFromLauncher = `$true

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

# ============================================================
# SHOW LOG FILE
# ============================================================
Write-Host ""
Write-Host "============================================================"
Write-Host "SHOWING LOG FILE"
Write-Host "============================================================"
$LogDate = Get-Date -Format "yyyy-MM-dd"
$LogFile = Join-Path (Join-Path $MspScratchFolder "Logs") "COOLForge_$LogDate.log"
if (Test-Path $LogFile) {
    Get-Content $LogFile -Encoding UTF8
} else {
    Write-Host "[!] Log file not found: $LogFile"
}
Write-Host "============================================================"

# Pass through the script's exit code
exit $ScriptExitCode
