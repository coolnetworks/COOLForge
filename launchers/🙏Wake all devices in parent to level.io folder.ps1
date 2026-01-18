# ============================================================
# DEPRECATED - USE Slim-Launcher.ps1 INSTEAD
# ============================================================
# This full launcher template (~660 lines) has been replaced by the
# slim launcher model (~200 lines). The slim launcher uses
# Invoke-ScriptLauncher from the library to handle script download/execution.
#
# For new scripts, use: templates/Slim-Launcher.ps1
# Or run: tools/New-PolicyScript.ps1 -Name <software>
# ============================================================

# ============================================================
# SCRIPT TO RUN - PRE-CONFIGURED
# ============================================================
# Use plain text identifier to avoid emoji corruption by Level.io
$ScriptToRun = "??Wake all devices in parent to level.io folder.ps1"
$ScriptCategory = "Check"  # Check, Fix, Remove, Configure, or Utility
# $policy_SCRIPTNAME = "{{cf_policy_SCRIPTNAME}}"
<#
.SYNOPSIS
    [DEPRECATED] Level.io Script Launcher - Downloads and executes scripts from GitHub with auto-update.

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
    Launcher Version: 2026.01.12.06
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
    $ScriptToRun = "??Wake all devices in parent to level.io folder.ps1"
    # The launcher will find the full path (scripts/Check/unchecky.ps1) from MD5SUMS
#>

# Script Launcher
# Launcher Version: 2026.01.12.06
# Target: Level.io
# Exit 0 = Success | Exit 1 = Alert (Failure)
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge
$ErrorActionPreference = "SilentlyContinue"

# ============================================================
# LEVEL.IO VARIABLES - PASSED TO DOWNLOADED SCRIPT
# ============================================================
# These variables will be passed to the downloaded script
$MspScratchFolder = "{{cf_coolforge_msp_scratch_folder}}"
$DeviceHostname = "{{level_device_hostname}}"
$DeviceTags = "{{level_tag_names}}"

# GitHub Personal Access Token for private repositories (admin-only custom field)
# IMPORTANT: Use here-string to prevent PowerShell expanding $ characters in tokens
$GitHubPAT = @'
{{cf_coolforge_pat}}
'@
$GitHubPAT = $GitHubPAT.Trim()
if ([string]::IsNullOrWhiteSpace($GitHubPAT) -or $GitHubPAT -like "{{*}}") {
    $GitHubPAT = $null
}

# Version pinning - if set, use specific version tag or branch name instead of main branch
$PinnedVersion = "{{cf_coolforge_pin_psmodule_to_version}}"
$UsePinnedVersion = $false
# Check if we have a valid pin (not empty and not a template placeholder)
if (-not [string]::IsNullOrWhiteSpace($PinnedVersion) -and $PinnedVersion -notlike "{{*}}") {
    $UsePinnedVersion = $true
    Write-Host "[*] Version pinned to: $PinnedVersion"
}

# Library URL - uses custom field if set, otherwise defaults to official repo
$LibraryUrl = "{{cf_coolforge_ps_module_library_source}}"
if ([string]::IsNullOrWhiteSpace($LibraryUrl) -or $LibraryUrl -like "{{*}}") {
    # Default to official repo - use pinned version or main branch
    $Branch = if ($UsePinnedVersion) { $PinnedVersion } else { "main" }
    $LibraryUrl = "https://raw.githubusercontent.com/coolnetworks/COOLForge/$Branch/modules/COOLForge-Common.psm1"
} elseif ($UsePinnedVersion) {
    # Custom URL provided but version pinning requested - replace branch in URL
    # Pattern: .../coolnetworks/COOLForge/main/... -> .../coolnetworks/COOLForge/$PinnedVersion/...
    $LibraryUrl = $LibraryUrl -replace '/COOLForge/[^/]+/', "/COOLForge/$PinnedVersion/"
}

# Debug mode - enables verbose output for troubleshooting (define early so we can use it)
$DebugScripts = "{{cf_debug_scripts}}"
if ([string]::IsNullOrWhiteSpace($DebugScripts) -or $DebugScripts -like "{{*}}") {
    $DebugScripts = $false
} else {
    $DebugScripts = $DebugScripts -eq "true"
}

# Level.io API key for tag management (optional - enables automatic tag updates)
# IMPORTANT: Use here-string to prevent PowerShell expanding $ characters in the key
$LevelApiKey_Raw = @'
{{cf_apikey}}
'@
$LevelApiKey = $LevelApiKey_Raw.Trim()

# API key debug output is handled by the script itself - no need to duplicate here

# ScreenConnect whitelisting - for RAT detection script
$ScreenConnectInstanceId = "{{cf_coolforge_screenconnect_instance_id}}"
if ([string]::IsNullOrWhiteSpace($ScreenConnectInstanceId) -or $ScreenConnectInstanceId -like "{{*}}") {
    $ScreenConnectInstanceId = ""
}

$IsScreenConnectServer = "{{cf_coolforge_is_screenconnect_server}}"
if ([string]::IsNullOrWhiteSpace($IsScreenConnectServer) -or $IsScreenConnectServer -like "{{*}}") {
    $IsScreenConnectServer = ""
}

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
# Example: https://raw.githubusercontent.com/.../dev2/modules/COOLForge-Common.psm1
#       -> https://raw.githubusercontent.com/.../dev2 (repo root)
#       -> https://raw.githubusercontent.com/.../dev2/scripts
$RepoBaseUrl = $LibraryUrl -replace '/modules/[^/]+$', ''
$ScriptRepoBaseUrl = "$RepoBaseUrl/scripts"
$MD5SumsUrl = "$RepoBaseUrl/MD5SUMS"

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

# In debug mode, delete cached library to force fresh download
if ($DebugScripts -and (Test-Path $LibraryPath)) {
    Write-Host "[DEBUG] Deleting cached library to force fresh download..."
    Remove-Item -Path $LibraryPath -Force -ErrorAction SilentlyContinue
}

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
    # Extract just the filename for wildcard matching (handles emoji corruption)
    $SearchName = Split-Path $FileName -Leaf
    foreach ($line in $MD5Content -split "`n") {
        $line = $line.Trim()
        if ($line -match '^#' -or [string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -match '^([a-f0-9]{32})\s+(.+)$') {
            $FilePath = $Matches[2].Trim()
            $FileLeaf = Split-Path $FilePath -Leaf
            # Match by exact path, or by filename ending (for emoji-prefixed scripts)
            if ($FilePath -eq $FileName -or $FileLeaf -eq $SearchName -or $FileLeaf -like "*$SearchName") {
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

            # Verify MD5 checksum if available (skip in debug mode)
            if ($MD5SumsContent -and -not $DebugScripts) {
                $ExpectedMD5 = Get-ExpectedMD5 -FileName "COOLForge-Common.psm1" -MD5Content $MD5SumsContent
                if ($ExpectedMD5) {
                    $ActualMD5 = Get-ContentMD5 -Content $RemoteContent
                    if ($ActualMD5 -ne $ExpectedMD5) {
                        throw "MD5 checksum mismatch: expected $ExpectedMD5, got $ActualMD5"
                    }
                    Write-Host "[+] Library checksum verified"
                }
            }
            elseif ($DebugScripts) {
                Write-Host "[*] Debug mode - skipping checksum verification"
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

# Copy LICENSE to scratch folder if it changed
$LicenseUrl = "$RepoBaseUrl/LICENSE"
$LicenseDestPath = Join-Path -Path $MspScratchFolder -ChildPath "LICENSE"

try {
    $LicenseRemoteContent = (Invoke-WebRequest -Uri $LicenseUrl -UseBasicParsing -TimeoutSec 5).Content
    $NeedsLicenseUpdate = $false

    if (Test-Path $LicenseDestPath) {
        $LicenseLocalContent = Get-Content -Path $LicenseDestPath -Raw -ErrorAction SilentlyContinue
        if ($LicenseLocalContent -ne $LicenseRemoteContent) {
            $NeedsLicenseUpdate = $true
        }
    }
    else {
        $NeedsLicenseUpdate = $true
    }

    if ($NeedsLicenseUpdate) {
        Set-Content -Path $LicenseDestPath -Value $LicenseRemoteContent -Force -ErrorAction Stop
        Write-Host "[+] LICENSE file updated"
    }
}
catch {
    # Non-critical - don't fail if license can't be downloaded
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
# RESOLVE SCRIPT PATH FROM MD5SUMS
# ============================================================
# Scripts are organized in subfolders (Check/, Fix/, Remove/, etc.)
# Parse MD5SUMS to find the actual path for the script name.

function Get-ScriptPathFromMD5 {
    param([string]$ScriptName, [string]$MD5Content)

    if ([string]::IsNullOrWhiteSpace($MD5Content)) { return $null }

    foreach ($line in $MD5Content -split "`n") {
        $line = $line.Trim()
        if ($line -match '^#' -or [string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -match '^([a-f0-9]{32})\s+(.+)$') {
            $FilePath = $Matches[2].Trim()
            # Check if filename matches (case-insensitive)
            # Use wildcard to match emoji-prefixed scripts (e.g., "unchecky.ps1" matches "scripts/Check/unchecky.ps1")
            $FileName = Split-Path $FilePath -Leaf
            if ($FileName -eq $ScriptName -or $FileName -like "*$ScriptName") {
                return $FilePath
            }
        }
    }
    return $null
}

# Try to resolve the full path from MD5SUMS
$ScriptRelativePath = $null
if ($MD5SumsContent) {
    $ScriptRelativePath = Get-ScriptPathFromMD5 -ScriptName $ScriptToRun -MD5Content $MD5SumsContent
    if ($ScriptRelativePath) {
        Write-Host "[*] Resolved script path: $ScriptRelativePath"
    }
}

# ============================================================
# SCRIPT DOWNLOAD & EXECUTION
# ============================================================
# Download the requested script from GitHub and execute it

Write-Host "[*] Script Launcher v2026.01.12.06"
Write-Host "[*] Preparing to run: $ScriptToRun"

# Define script storage location
$ScriptsFolder = Join-Path -Path $MspScratchFolder -ChildPath "Scripts"
if (!(Test-Path $ScriptsFolder)) {
    New-Item -Path $ScriptsFolder -ItemType Directory -Force | Out-Null
}

# Sanitize script name for filesystem (replace problematic characters)
$SafeScriptName = $ScriptToRun -replace '[<>:"/\\|?*]', '_'
$ScriptPath = Join-Path -Path $ScriptsFolder -ChildPath $SafeScriptName

# Build script URL - use resolved path from MD5SUMS if available, otherwise fallback to flat structure
if ($ScriptRelativePath) {
    # Use the full path from MD5SUMS (e.g., "scripts/Check/ScriptName.ps1")
    $ScriptUrl = "$RepoBaseUrl/$(Get-LevelUrlEncoded $ScriptRelativePath)"
} else {
    # Fallback: assume script is directly in /scripts/ folder
    Write-Host "[!] Script not found in MD5SUMS - trying flat path"
    $ScriptUrl = "$ScriptRepoBaseUrl/$(Get-LevelUrlEncoded $ScriptToRun)"
}

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

            # Verify MD5 checksum if available (skip in debug mode)
            if ($MD5SumsContent -and -not $DebugScripts) {
                # Use resolved path if available, otherwise construct from script name
                $ScriptMD5Key = if ($ScriptRelativePath) { $ScriptRelativePath } else { "scripts/$ScriptToRun" }
                $ExpectedScriptMD5 = Get-ExpectedMD5 -FileName $ScriptMD5Key -MD5Content $MD5SumsContent
                if ($ExpectedScriptMD5) {
                    $ActualScriptMD5 = Get-ContentMD5 -Content $RemoteScriptContent
                    if ($ActualScriptMD5 -ne $ExpectedScriptMD5) {
                        throw "MD5 checksum mismatch: expected $ExpectedScriptMD5, got $ActualScriptMD5"
                    }
                    Write-Host "[+] Script checksum verified"
                }
            }
            elseif ($DebugScripts) {
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

# Build list of policy variables to pass through
# These are defined in the launcher header as $policy_* = "{{cf_policy_*}}"
$PolicyVarsBlock = ""
Get-Variable -Name "policy_*" -ErrorAction SilentlyContinue | ForEach-Object {
    $VarName = $_.Name
    $VarValue = $_.Value
    # Only pass if it has a value and isn't an unresolved template placeholder
    if (-not [string]::IsNullOrWhiteSpace($VarValue) -and $VarValue -notlike "{{*}}") {
        $EscapedValue = $VarValue -replace "'", "''"
        $PolicyVarsBlock += "`n`$$VarName = '$EscapedValue'"
    }
}

# Create a scriptblock that:
# 1. Defines all Level.io variables in the script's scope
# 2. Executes the downloaded script content
$ExecutionBlock = @"
# Level.io variables passed from launcher
`$MspScratchFolder = '$($MspScratchFolder -replace "'", "''")'
`$LibraryUrl = '$($LibraryUrl -replace "'", "''")'
`$DeviceHostname = '$($DeviceHostname -replace "'", "''")'
`$DeviceTags = '$($DeviceTags -replace "'", "''")'
`$LevelApiKey = $(if ($LevelApiKey) { "'$($LevelApiKey -replace "'", "''" -replace '\$', '`$')'" } else { '$null' })
`$DebugScripts = `$$DebugScripts

# Policy custom fields (defined in launcher header)
$PolicyVarsBlock

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

