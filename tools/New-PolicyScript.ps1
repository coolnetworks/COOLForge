<#
.SYNOPSIS
    Scaffolds a new software policy script, launcher, and documentation.

.DESCRIPTION
    Creates all the files needed for a new COOLForge policy:
    - scripts/Policy/👀<name>.ps1
    - launchers/Policy/👀<name>.ps1
    - docs/policy/<Name>.md

.PARAMETER Name
    The software name (lowercase). Example: chrome, slack, zoom

.PARAMETER DisplayName
    The display name for documentation. Example: "Google Chrome", "Slack", "Zoom"

.PARAMETER ServiceName
    Optional Windows service name to check. Example: "gupdate" for Chrome

.PARAMETER DetectionPath
    Optional file path to detect installation. Example: "C:\Program Files\Google\Chrome\Application\chrome.exe"

.EXAMPLE
    .\New-PolicyScript.ps1 -Name chrome -DisplayName "Google Chrome"

.EXAMPLE
    .\New-PolicyScript.ps1 -Name chrome -DisplayName "Google Chrome" -DetectionPath "C:\Program Files\Google\Chrome\Application\chrome.exe"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$Name,

    [Parameter(Mandatory=$true)]
    [string]$DisplayName,

    [string]$ServiceName = "",

    [string]$DetectionPath = ""
)

$Name = $Name.ToLower()
$NameUpper = $Name.ToUpper()
$NamePascal = (Get-Culture).TextInfo.ToTitleCase($Name)

$RepoRoot = Split-Path -Parent $PSScriptRoot
$ScriptPath = Join-Path $RepoRoot "scripts\Policy\👀$Name.ps1"
$LauncherPath = Join-Path $RepoRoot "launchers\Policy\👀$Name.ps1"
$DocPath = Join-Path $RepoRoot "docs\policy\$NamePascal.md"

$Today = Get-Date -Format "yyyy.MM.dd"
$Version = "$Today.01"

# Check if files already exist
$existingFiles = @()
if (Test-Path $ScriptPath) { $existingFiles += $ScriptPath }
if (Test-Path $LauncherPath) { $existingFiles += $LauncherPath }
if (Test-Path $DocPath) { $existingFiles += $DocPath }

if ($existingFiles.Count -gt 0) {
    Write-Host "ERROR: The following files already exist:" -ForegroundColor Red
    $existingFiles | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    Write-Host ""
    Write-Host "Delete them first or choose a different name." -ForegroundColor Red
    exit 1
}

# ============================================================
# Generate Policy Script
# ============================================================

$detectionCode = if ($DetectionPath) {
@"
    # Check for installation file
    if (Test-Path "$DetectionPath") {
        return `$true
    }
"@
} else {
@"
    # TODO: Add file path detection
    # Example: if (Test-Path "C:\Program Files\$DisplayName\app.exe") { return `$true }
"@
}

$serviceCode = if ($ServiceName) {
@"
    # Check for service
    `$service = Get-Service -Name "$ServiceName" -ErrorAction SilentlyContinue
    if (`$service) {
        return `$true
    }
"@
} else {
@"
    # TODO: Add service detection if applicable
    # Example: `$service = Get-Service -Name "ServiceName" -ErrorAction SilentlyContinue
"@
}

$scriptContent = @"
<#
.SYNOPSIS
    Software policy enforcement for $DisplayName.

.DESCRIPTION
    Implements the COOLForge 5-tag policy model for $DisplayName management.
    See docs/policy/TAGS.md for the complete policy specification.

    POLICY FLOW:
    1. Check global control tags (device must have checkmark to be managed)
    2. Check software-specific override tags (highest priority)
    3. Fall back to custom field policy (policy_$Name)
    4. Execute resolved action (install/remove/reinstall)

    SOFTWARE-SPECIFIC OVERRIDE TAGS (with "$Name" suffix):
    - U+1F64F $Name = Install if missing (transient)
    - U+1F6AB $Name = Remove if present (transient)
    - U+1F4CC $Name = Pin - no changes allowed (persistent)
    - U+1F504 $Name = Reinstall - remove + install (transient)
    - U+2705 $Name  = Status: software is installed (set by script)

    CUSTOM FIELD POLICY (inherited Group->Folder->Device):
    - policy_$Name = "install" | "remove" | "pin" | ""

.NOTES
    Version:          $Version
    Target Platform:  Level.io RMM (via Script Launcher)
    Exit Codes:       0 = Success | 1 = Alert (Failure)

    Level.io Variables Used (passed from Script Launcher):
    - `$MspScratchFolder   : MSP-defined scratch folder for persistent storage
    - `$DeviceHostname     : Device hostname from Level.io
    - `$DeviceTags         : Comma-separated list of device tags
    - `$policy_$Name       : Custom field policy value (inherited)

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# Software Policy - $DisplayName
# Version: $Version
# Target: Level.io (via Script Launcher)
# Exit 0 = Success | Exit 1 = Alert (Failure)

# ============================================================
# CONFIGURATION
# ============================================================

`$SoftwareName = "$Name"
`$SoftwareDisplayName = "$DisplayName"

# Custom field names (create these in Level.io)
`$PolicyFieldName = "policy_$Name"
# `$InstallerUrlField = "policy_${Name}_url"  # Uncomment if using hosted installer

# ============================================================
# SOFTWARE-SPECIFIC FUNCTIONS
# ============================================================

function Test-SoftwareInstalled {
    <#
    .SYNOPSIS
        Check if $DisplayName is installed
    #>
$serviceCode

$detectionCode

    # Check registry for uninstall entry
    `$uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    `$found = `$uninstallPaths | ForEach-Object {
        Get-ItemProperty `$_ -ErrorAction SilentlyContinue
    } | Where-Object { `$_.DisplayName -like "*$DisplayName*" }

    return (`$null -ne `$found)
}

function Install-Software {
    <#
    .SYNOPSIS
        Install $DisplayName
    #>
    param([string]`$InstallerUrl)

    Write-LevelLog "Installing $DisplayName..."

    # TODO: Implement installation logic
    # Options:
    # 1. Download from URL: Invoke-WebRequest -Uri `$InstallerUrl -OutFile `$installerPath
    # 2. Use winget: winget install --id Google.Chrome --silent --accept-package-agreements
    # 3. Use chocolatey: choco install googlechrome -y

    # Example using winget:
    # `$result = Start-Process -FilePath "winget" -ArgumentList "install --id Google.Chrome --silent --accept-package-agreements" -Wait -PassThru
    # return `$result.ExitCode -eq 0

    Write-LevelLog "TODO: Implement Install-Software function" -Level "WARN"
    return `$false
}

function Remove-Software {
    <#
    .SYNOPSIS
        Remove $DisplayName
    #>
    Write-LevelLog "Removing $DisplayName..."

    # TODO: Implement uninstall logic
    # Options:
    # 1. Use registry UninstallString
    # 2. Use winget: winget uninstall --id Google.Chrome --silent
    # 3. Use chocolatey: choco uninstall googlechrome -y

    # Example using winget:
    # `$result = Start-Process -FilePath "winget" -ArgumentList "uninstall --id Google.Chrome --silent" -Wait -PassThru
    # return `$result.ExitCode -eq 0

    Write-LevelLog "TODO: Implement Remove-Software function" -Level "WARN"
    return `$false
}

function Test-SoftwareHealthy {
    <#
    .SYNOPSIS
        Check if $DisplayName is healthy (running correctly)
    #>
    # TODO: Add health checks if applicable
    # Examples: check if service is running, check if process exists

    return (Test-SoftwareInstalled)
}

# ============================================================
# MAIN EXECUTION
# ============================================================

# Initialize script (creates lockfile, sets up logging)
`$Init = Initialize-LevelScript -ScriptName "Policy-$Name" ``
                               -MspScratchFolder `$MspScratchFolder ``
                               -DeviceHostname `$DeviceHostname ``
                               -DeviceTags `$DeviceTags

if (-not `$Init.Success) {
    exit 0
}

`$ScriptVersion = "$Version"
`$InvokeParams = @{ ScriptBlock = {

    Write-LevelLog "$DisplayName Policy (v`$ScriptVersion)"
    Write-Host ""

    # Run policy check
    `$Policy = Invoke-SoftwarePolicyCheck -SoftwareName `$SoftwareName -DeviceTags `$DeviceTags

    # Check current installation state
    `$IsInstalled = Test-SoftwareInstalled
    Write-LevelLog "Current state: `$(if (`$IsInstalled) { 'Installed' } else { 'Not installed' })"

    # Execute based on resolved action
    switch (`$Policy.ResolvedAction) {
        "Install" {
            if (-not `$IsInstalled) {
                # `$url = [Environment]::GetEnvironmentVariable("policy_${Name}_url", "Process")
                `$success = Install-Software # -InstallerUrl `$url
                if (`$success) {
                    Write-LevelLog "$DisplayName installed successfully" -Level "SUCCESS"
                } else {
                    Write-Host "Alert: $DisplayName installation failed"
                    exit 1
                }
            } else {
                Write-LevelLog "$DisplayName already installed" -Level "SUCCESS"
            }
        }
        "Remove" {
            if (`$IsInstalled) {
                `$success = Remove-Software
                if (`$success) {
                    Write-LevelLog "$DisplayName removed successfully" -Level "SUCCESS"
                } else {
                    Write-Host "Alert: $DisplayName removal failed"
                    exit 1
                }
            } else {
                Write-LevelLog "$DisplayName not installed - nothing to remove" -Level "SUCCESS"
            }
        }
        "Reinstall" {
            if (`$IsInstalled) {
                Remove-Software | Out-Null
            }
            `$success = Install-Software
            if (`$success) {
                Write-LevelLog "$DisplayName reinstalled successfully" -Level "SUCCESS"
            } else {
                Write-Host "Alert: $DisplayName reinstall failed"
                exit 1
            }
        }
        default {
            if (`$Policy.IsPinned) {
                Write-LevelLog "PINNED: No changes allowed" -Level "INFO"
            } elseif (`$Policy.IsSkipped) {
                Write-LevelLog "SKIPPED: Hands off" -Level "INFO"
            } else {
                Write-LevelLog "No policy action required" -Level "INFO"
            }
        }
    }

    # Verify and report health if applicable
    if (`$Policy.ShouldVerify -and (Test-SoftwareInstalled)) {
        if (Test-SoftwareHealthy) {
            Write-LevelLog "$DisplayName is healthy" -Level "SUCCESS"
        } else {
            Write-LevelLog "$DisplayName health check failed" -Level "WARN"
        }
    }

    Write-LevelLog "Policy check completed" -Level "SUCCESS"
}}

if (`$RunningFromLauncher) { `$InvokeParams.NoExit = `$true }
Invoke-LevelScript @InvokeParams
"@

# ============================================================
# Generate Launcher
# ============================================================

$launcherContent = @"
# ============================================================
# SCRIPT TO RUN - PRE-CONFIGURED
# ============================================================
`$ScriptToRun = "👀$Name.ps1"
`$policy_$Name = "{{cf_policy_$Name}}"
<#
.SYNOPSIS
    Slim Level.io Launcher for $DisplayName Policy Script

.DESCRIPTION
    Downloads library, then uses Invoke-ScriptLauncher for script handling.
    ~200 lines vs ~660 lines in full launchers.

.NOTES
    Version: $Version
    See docs/policy/$NamePascal.md for documentation
#>

`$ErrorActionPreference = "SilentlyContinue"

# ============================================================
# LEVEL.IO VARIABLES
# ============================================================
`$MspScratchFolder = "{{cf_coolforge_msp_scratch_folder}}"
`$DeviceHostname = "{{level_device_hostname}}"
`$DeviceTags = "{{level_tag_names}}"

`$GitHubPAT = @'
{{cf_coolforge_pat}}
'@
`$GitHubPAT = `$GitHubPAT.Trim()
if ([string]::IsNullOrWhiteSpace(`$GitHubPAT) -or `$GitHubPAT -like "{{*}}") { `$GitHubPAT = `$null }

`$PinnedVersion = "{{cf_coolforge_pin_psmodule_to_version}}"
`$UsePinnedVersion = (-not [string]::IsNullOrWhiteSpace(`$PinnedVersion) -and `$PinnedVersion -notlike "{{*}}")
Write-Host "[DEBUG] PinnedVersion='`$PinnedVersion' UsePinnedVersion=`$UsePinnedVersion"

`$LibraryUrl = "{{cf_coolforge_ps_module_library_source}}"
if ([string]::IsNullOrWhiteSpace(`$LibraryUrl) -or `$LibraryUrl -like "{{*}}") {
    `$Branch = if (`$UsePinnedVersion) { `$PinnedVersion } else { "main" }
    `$LibraryUrl = "https://raw.githubusercontent.com/coolnetworks/COOLForge/`$Branch/modules/COOLForge-Common.psm1"
} elseif (`$UsePinnedVersion) {
    `$LibraryUrl = `$LibraryUrl -replace '/COOLForge/[^/]+/', "/COOLForge/`$PinnedVersion/"
}
Write-Host "[DEBUG] LibraryUrl=`$LibraryUrl"

`$DebugScripts = "{{cf_debug_scripts}}"
if ([string]::IsNullOrWhiteSpace(`$DebugScripts) -or `$DebugScripts -like "{{*}}") {
    `$DebugScripts = `$false
} else {
    `$DebugScripts = `$DebugScripts -eq "true"
}

`$LevelApiKey_Raw = @'
{{cf_apikey}}
'@
`$LevelApiKey = `$LevelApiKey_Raw.Trim()

# ============================================================
# GITHUB PAT INJECTION
# ============================================================
function Add-GitHubToken {
    param([string]`$Url, [string]`$Token)
    if ([string]::IsNullOrWhiteSpace(`$Token)) { return `$Url }
    if (`$Url -notmatch 'raw\.githubusercontent\.com') { return `$Url }
    if (`$Url -match '@raw\.githubusercontent\.com') { return `$Url }
    return `$Url -replace '(https://)raw\.githubusercontent\.com', "`$1`$Token@raw.githubusercontent.com"
}

`$RepoBaseUrl = `$LibraryUrl -replace '/modules/[^/]+`$', ''
`$MD5SumsUrl = "`$RepoBaseUrl/MD5SUMS"

if (`$GitHubPAT) {
    `$LibraryUrl = Add-GitHubToken -Url `$LibraryUrl -Token `$GitHubPAT
    `$MD5SumsUrl = Add-GitHubToken -Url `$MD5SumsUrl -Token `$GitHubPAT
    `$RepoBaseUrl = Add-GitHubToken -Url `$RepoBaseUrl -Token `$GitHubPAT
}

# ============================================================
# LIBRARY BOOTSTRAP
# ============================================================
`$LibraryFolder = Join-Path -Path `$MspScratchFolder -ChildPath "Libraries"
`$LibraryPath = Join-Path -Path `$LibraryFolder -ChildPath "COOLForge-Common.psm1"

if (`$DebugScripts -and (Test-Path `$LibraryPath)) {
    Remove-Item -Path `$LibraryPath -Force -ErrorAction SilentlyContinue
}

if (!(Test-Path `$LibraryFolder)) {
    New-Item -Path `$LibraryFolder -ItemType Directory -Force | Out-Null
}

function Get-ModuleVersion {
    param([string]`$Content)
    if (`$Content -match 'Version:\s*([\d\.]+)') { return `$Matches[1] }
    throw "Could not parse version"
}

`$NeedsUpdate = `$false
`$LocalVersion = `$null
`$LocalContent = `$null

if (Test-Path `$LibraryPath) {
    try {
        `$LocalContent = Get-Content -Path `$LibraryPath -Raw -ErrorAction Stop
        `$LocalVersion = Get-ModuleVersion -Content `$LocalContent
    } catch {
        `$NeedsUpdate = `$true
    }
} else {
    `$NeedsUpdate = `$true
    Write-Host "[*] Library not found - downloading..."
}

try {
    `$RemoteContent = (Invoke-WebRequest -Uri `$LibraryUrl -UseBasicParsing -TimeoutSec 10).Content
    `$RemoteVersion = Get-ModuleVersion -Content `$RemoteContent

    if (`$null -eq `$LocalVersion -or [version]`$RemoteVersion -gt [version]`$LocalVersion) {
        `$NeedsUpdate = `$true
        if (`$LocalVersion) { Write-Host "[*] Library update: `$LocalVersion -> `$RemoteVersion" }
    }

    if (`$NeedsUpdate) {
        Set-Content -Path `$LibraryPath -Value `$RemoteContent -Force -ErrorAction Stop
        Write-Host "[+] Library updated to v`$RemoteVersion"
    }
} catch {
    if (!(Test-Path `$LibraryPath)) {
        Write-Host "[X] FATAL: Cannot download library"
        exit 1
    }
    Write-Host "[!] Using cached library v`$LocalVersion"
}

`$ModuleContent = Get-Content -Path `$LibraryPath -Raw
New-Module -Name "COOLForge-Common" -ScriptBlock ([scriptblock]::Create(`$ModuleContent)) | Import-Module -Force

# Load MD5SUMS (with cache-busting in debug mode)
`$MD5SumsContent = `$null
`$MD5FetchUrl = `$MD5SumsUrl
if (`$DebugScripts) {
    `$CacheBuster = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    `$MD5FetchUrl = "`$MD5SumsUrl``?t=`$CacheBuster"
    Write-Host "[DEBUG] MD5SUMS URL: `$MD5FetchUrl"
}
try {
    `$MD5SumsContent = (Invoke-WebRequest -Uri `$MD5FetchUrl -UseBasicParsing -TimeoutSec 5).Content
    if (`$DebugScripts) { Write-Host "[DEBUG] MD5SUMS loaded, length: `$(`$MD5SumsContent.Length)" }
} catch {
    if (`$DebugScripts) { Write-Host "[DEBUG] Failed to load MD5SUMS: `$_" }
}

# ============================================================
# COLLECT POLICY VARIABLES & EXECUTE
# ============================================================
`$PolicyVars = @{}
Get-Variable -Name "policy_*" -ErrorAction SilentlyContinue | ForEach-Object {
    if (-not [string]::IsNullOrWhiteSpace(`$_.Value) -and `$_.Value -notlike "{{*}}") {
        `$PolicyVars[`$_.Name] = `$_.Value
    }
}

Write-Host "[*] Slim Launcher v$Version"

`$LauncherVars = @{
    MspScratchFolder = `$MspScratchFolder
    DeviceHostname   = `$DeviceHostname
    DeviceTags       = `$DeviceTags
    LevelApiKey      = `$LevelApiKey
    DebugScripts     = `$DebugScripts
    LibraryUrl       = `$LibraryUrl
}
foreach (`$key in `$PolicyVars.Keys) { `$LauncherVars[`$key] = `$PolicyVars[`$key] }

`$ExitCode = Invoke-ScriptLauncher -ScriptName `$ScriptToRun ``
                                   -RepoBaseUrl `$RepoBaseUrl ``
                                   -MD5SumsContent `$MD5SumsContent ``
                                   -MspScratchFolder `$MspScratchFolder ``
                                   -LauncherVariables `$LauncherVars ``
                                   -DebugMode `$DebugScripts

exit `$ExitCode
"@

# ============================================================
# Generate Documentation
# ============================================================

$docContent = @"
# $DisplayName Policy Script

**Script:** ``scripts/Policy/👀$Name.ps1``
**Launcher:** ``launchers/Policy/👀$Name.ps1``
**Version:** $Version
**Category:** Policy

## Purpose

Tag-based policy enforcement script for $DisplayName management. Handles installation, removal, and verification based on Level.io device tags.

## Features

- **Policy-based management** via device tags
- **Tag auto-management** - Updates tags based on action results (requires API key)
- **Health monitoring** - Verifies software is functioning correctly

## Policy Tags

| Tag | Action |
|-----|--------|
| 🙏$Name | Install $DisplayName |
| 🚫$Name | Remove $DisplayName |
| 📌$Name | Pin state - no changes allowed |
| 🔄$Name | Reinstall $DisplayName |
| ✅$Name | Verify $DisplayName is installed and healthy |

> **Note:** ``⛔$Name`` also works for Remove but is **deprecated**. Use ``🚫$Name`` instead.

## Exit Codes

| Code | Status | Description |
|------|--------|-------------|
| 0 | Success | Policy action completed successfully |
| 1 | Alert | Action failed or configuration missing |

## Custom Fields

| Level.io Field | Script Variable | Required | Description |
|----------------|-----------------|----------|-------------|
| ``policy_$Name`` | ``{{cf_policy_$Name}}`` | No | Policy action: ``install`` / ``remove`` / ``pin`` |
| ``apikey`` | ``{{cf_apikey}}`` | No | Level.io API key for tag auto-management |

> **Note:** Level.io adds ``cf_`` prefix automatically when referencing in scripts.

## Files

| File | Path | Purpose |
|------|------|---------|
| Launcher | ``launchers/Policy/👀$Name.ps1`` | Deploy to Level.io |
| Script | ``scripts/Policy/👀$Name.ps1`` | Policy enforcement logic |
| Module | ``modules/COOLForge-Common.psm1`` | Shared library |

## Implementation Notes

This script was scaffolded and requires implementation of:

1. **Test-SoftwareInstalled** - Detection logic for $DisplayName
2. **Install-Software** - Installation method (winget, chocolatey, direct download, etc.)
3. **Remove-Software** - Uninstallation method

## Troubleshooting

### Debug Mode

Set ``debug_scripts = true`` on the device for verbose output.

### Common Issues

| Issue | Solution |
|-------|----------|
| Install fails | Check Install-Software implementation |
| Detection wrong | Verify Test-SoftwareInstalled checks correct paths/registry |
| Tags not updating | Set ``apikey`` custom field |
"@

# ============================================================
# Write Files
# ============================================================

Write-Host ""
Write-Host "Creating policy files for: $DisplayName" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# Create directories if needed
$ScriptDir = Split-Path $ScriptPath -Parent
$LauncherDir = Split-Path $LauncherPath -Parent
$DocDir = Split-Path $DocPath -Parent

@($ScriptDir, $LauncherDir, $DocDir) | ForEach-Object {
    if (-not (Test-Path $_)) {
        New-Item -ItemType Directory -Path $_ -Force | Out-Null
    }
}

# Write files
Set-Content -Path $ScriptPath -Value $scriptContent -Encoding UTF8
Write-Host "[OK] Script:   $ScriptPath" -ForegroundColor Green

Set-Content -Path $LauncherPath -Value $launcherContent -Encoding UTF8
Write-Host "[OK] Launcher: $LauncherPath" -ForegroundColor Green

Set-Content -Path $DocPath -Value $docContent -Encoding UTF8
Write-Host "[OK] Docs:     $DocPath" -ForegroundColor Green

Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Edit scripts/Policy/👀$Name.ps1 to implement:" -ForegroundColor White
Write-Host "     - Test-SoftwareInstalled (detection)" -ForegroundColor Gray
Write-Host "     - Install-Software (installation)" -ForegroundColor Gray
Write-Host "     - Remove-Software (uninstallation)" -ForegroundColor Gray
Write-Host "  2. Create custom field in Level.io: policy_$Name" -ForegroundColor White
Write-Host "  3. Upload launcher to Level.io" -ForegroundColor White
Write-Host "  4. Add to docs/scripts/README.md Policy Scripts table" -ForegroundColor White
Write-Host ""
