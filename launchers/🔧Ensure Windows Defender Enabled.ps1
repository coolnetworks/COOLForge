# ============================================================
# SCRIPT TO RUN - PRE-CONFIGURED
# ============================================================
$ScriptToRun = "🔧Ensure Windows Defender Enabled.ps1"
$PolicyDefender = "{{policy_defender}}"
<#
.SYNOPSIS
    Slim Level.io Launcher for Windows Defender Enforcement

.DESCRIPTION
    Ensures Windows Defender is enabled and running on all Windows variants.
    Includes self-healing capabilities to repair corrupted Defender installations.

    POLICY FIELD (inherited Group->Folder->Device):
    - policy_defender = "enforce" (default) | "skip" | ""

    Default behavior is ENFORCE - Defender will be enabled unless explicitly skipped.

.NOTES
    Launcher Version: 2026.01.18.01
    Target Platform:  Level.io RMM

    Level.io Variables Used:
    - {{cf_coolforge_msp_scratch_folder}}      : MSP-defined scratch folder
    - {{cf_coolforge_ps_module_library_source}}: URL to download COOLForge-Common.psm1
    - {{cf_coolforge_pin_psmodule_to_version}} : (Optional) Pin to specific version tag
    - {{cf_coolforge_pat}}                     : (Optional) GitHub PAT for private repos
    - {{level_device_hostname}}                : Device hostname from Level.io
    - {{level_tag_names}}                      : Comma-separated list of device tags
    - {{policy_defender}}                      : Policy setting (default: enforce)

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge
#>

$ErrorActionPreference = "SilentlyContinue"

# ============================================================
# LEVEL.IO VARIABLES
# ============================================================
$MspScratchFolder = "{{cf_coolforge_msp_scratch_folder}}"
$DeviceHostname = "{{level_device_hostname}}"
$DeviceTags = "{{level_tag_names}}"

$GitHubPAT = @'
{{cf_coolforge_pat}}
'@
$GitHubPAT = $GitHubPAT.Trim()
if ([string]::IsNullOrWhiteSpace($GitHubPAT) -or $GitHubPAT -like "{{*}}") { $GitHubPAT = $null }

$PinnedVersion = "{{cf_coolforge_pin_psmodule_to_version}}"
$UsePinnedVersion = (-not [string]::IsNullOrWhiteSpace($PinnedVersion) -and $PinnedVersion -notlike "{{*}}")

$LibraryUrl = "{{cf_coolforge_ps_module_library_source}}"
if ([string]::IsNullOrWhiteSpace($LibraryUrl) -or $LibraryUrl -like "{{*}}") {
    $Branch = if ($UsePinnedVersion) { $PinnedVersion } else { "main" }
    $LibraryUrl = "https://raw.githubusercontent.com/coolnetworks/COOLForge/$Branch/modules/COOLForge-Common.psm1"
} elseif ($UsePinnedVersion) {
    $LibraryUrl = $LibraryUrl -replace '/COOLForge/[^/]+/', "/COOLForge/$PinnedVersion/"
}

$DebugScripts = "{{cf_debug_scripts}}"
if ([string]::IsNullOrWhiteSpace($DebugScripts) -or $DebugScripts -like "{{*}}") {
    $DebugScripts = $false
} else {
    $DebugScripts = $DebugScripts -eq "true"
}

$LevelApiKey_Raw = @'
{{cf_apikey}}
'@
$LevelApiKey = $LevelApiKey_Raw.Trim()

# ============================================================
# GITHUB PAT INJECTION
# ============================================================
function Add-GitHubToken {
    param([string]$Url, [string]$Token)
    if ([string]::IsNullOrWhiteSpace($Token)) { return $Url }
    if ($Url -notmatch 'raw\.githubusercontent\.com') { return $Url }
    if ($Url -match '@raw\.githubusercontent\.com') { return $Url }
    return $Url -replace '(https://)raw\.githubusercontent\.com', "`$1$Token@raw.githubusercontent.com"
}

$RepoBaseUrl = $LibraryUrl -replace '/modules/[^/]+$', ''
$MD5SumsUrl = "$RepoBaseUrl/MD5SUMS"

if ($GitHubPAT) {
    $LibraryUrl = Add-GitHubToken -Url $LibraryUrl -Token $GitHubPAT
    $MD5SumsUrl = Add-GitHubToken -Url $MD5SumsUrl -Token $GitHubPAT
    $RepoBaseUrl = Add-GitHubToken -Url $RepoBaseUrl -Token $GitHubPAT
}

# ============================================================
# LIBRARY BOOTSTRAP
# ============================================================
$LibraryFolder = Join-Path -Path $MspScratchFolder -ChildPath "Libraries"
$LibraryPath = Join-Path -Path $LibraryFolder -ChildPath "COOLForge-Common.psm1"

if ($DebugScripts -and (Test-Path $LibraryPath)) {
    Remove-Item -Path $LibraryPath -Force -ErrorAction SilentlyContinue
}

if (!(Test-Path $LibraryFolder)) {
    New-Item -Path $LibraryFolder -ItemType Directory -Force | Out-Null
}

function Get-ModuleVersion {
    param([string]$Content)
    if ($Content -match 'Version:\s*([\d\.]+)') { return $Matches[1] }
    throw "Could not parse version"
}

$NeedsUpdate = $false
$LocalVersion = $null
$LocalContent = $null

if (Test-Path $LibraryPath) {
    try {
        $LocalContent = Get-Content -Path $LibraryPath -Raw -ErrorAction Stop
        $LocalVersion = Get-ModuleVersion -Content $LocalContent
    } catch {
        $NeedsUpdate = $true
    }
} else {
    $NeedsUpdate = $true
    Write-Host "[*] Library not found - downloading..."
}

try {
    $RemoteContent = (Invoke-WebRequest -Uri $LibraryUrl -UseBasicParsing -TimeoutSec 10).Content
    $RemoteVersion = Get-ModuleVersion -Content $RemoteContent

    if ($null -eq $LocalVersion -or [version]$RemoteVersion -gt [version]$LocalVersion) {
        $NeedsUpdate = $true
        if ($LocalVersion) { Write-Host "[*] Library update: $LocalVersion -> $RemoteVersion" }
    }

    if ($NeedsUpdate) {
        Set-Content -Path $LibraryPath -Value $RemoteContent -Force -ErrorAction Stop
        Write-Host "[+] Library updated to v$RemoteVersion"
    }
} catch {
    if (!(Test-Path $LibraryPath)) {
        Write-Host "[X] FATAL: Cannot download library"
        exit 1
    }
    Write-Host "[!] Using cached library v$LocalVersion"
}

# Import library
$ModuleContent = Get-Content -Path $LibraryPath -Raw
New-Module -Name "COOLForge-Common" -ScriptBlock ([scriptblock]::Create($ModuleContent)) | Import-Module -Force

# Load MD5SUMS
$MD5SumsContent = $null
$MD5FetchUrl = $MD5SumsUrl
if ($DebugScripts) {
    $CacheBuster = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $MD5FetchUrl = "$MD5SumsUrl`?t=$CacheBuster"
}
try {
    $MD5SumsContent = (Invoke-WebRequest -Uri $MD5FetchUrl -UseBasicParsing -TimeoutSec 5).Content
} catch { }

# ============================================================
# COLLECT LAUNCHER VARIABLES
# ============================================================
# Clean up policy variable
if ([string]::IsNullOrWhiteSpace($PolicyDefender) -or $PolicyDefender -like "{{*}}") {
    $PolicyDefender = "enforce"
}

$LauncherVars = @{
    MspScratchFolder = $MspScratchFolder
    DeviceHostname   = $DeviceHostname
    DeviceTags       = $DeviceTags
    LevelApiKey      = $LevelApiKey
    DebugScripts     = $DebugScripts
    LibraryUrl       = $LibraryUrl
    PolicyDefender   = $PolicyDefender
}

# ============================================================
# EXECUTE SCRIPT
# ============================================================
Write-Host "[*] Slim Launcher v2026.01.18.01"

$ExitCode = Invoke-ScriptLauncher -ScriptName $ScriptToRun `
                                   -RepoBaseUrl $RepoBaseUrl `
                                   -MD5SumsContent $MD5SumsContent `
                                   -MspScratchFolder $MspScratchFolder `
                                   -LauncherVariables $LauncherVars `
                                   -DebugMode $DebugScripts

exit $ExitCode
