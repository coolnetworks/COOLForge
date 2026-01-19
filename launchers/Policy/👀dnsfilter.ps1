# ============================================================
# SCRIPT TO RUN - PRE-CONFIGURED
# ============================================================
$ScriptToRun = "Policy/👀dnsfilter.ps1"
$policy_dnsfilter = "{{cf_policy_dnsfilter}}"
$policy_dnsfilter_sitekey = "{{cf_policy_dnsfilter_sitekey}}"
<#
.SYNOPSIS
    Slim Level.io Launcher for DNSFilter Policy Script

.NOTES
    Launcher Version: 2026.01.16.01
    Target Platform:  Level.io RMM

    This slim launcher (~200 lines) replaces the full launcher (~660 lines).
    Script download/execution is handled by Invoke-ScriptLauncher in the library.

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge
#>

$LauncherVersion = "2026.01.16.01"
$LauncherName = "Policy/👀dnsfilter.ps1"

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
Write-Host "[DEBUG] PinnedVersion='$PinnedVersion' UsePinnedVersion=$UsePinnedVersion"

$LibraryUrl = "{{cf_coolforge_ps_module_library_source}}"
if ([string]::IsNullOrWhiteSpace($LibraryUrl) -or $LibraryUrl -like "{{*}}") {
    $Branch = if ($UsePinnedVersion) { $PinnedVersion } else { "main" }
    $LibraryUrl = "https://raw.githubusercontent.com/coolnetworks/COOLForge/$Branch/modules/COOLForge-Common.psm1"
} elseif ($UsePinnedVersion) {
    $LibraryUrl = $LibraryUrl -replace '/COOLForge/[^/]+/', "/COOLForge/$PinnedVersion/"
}
Write-Host "[DEBUG] LibraryUrl=$LibraryUrl"

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
# LIBRARY BOOTSTRAP (required - can't use library to download itself)
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
        Write-Host "[Alert] Cannot download library"
        exit 1
    }
    Write-Host "[!] Using cached library v$LocalVersion"
}

# Import library
$ModuleContent = Get-Content -Path $LibraryPath -Raw
New-Module -Name "COOLForge-Common" -ScriptBlock ([scriptblock]::Create($ModuleContent)) | Import-Module -Force

# Load MD5SUMS (with cache-busting in debug mode)
$MD5SumsContent = $null
$MD5FetchUrl = $MD5SumsUrl
if ($DebugScripts) {
    $CacheBuster = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $MD5FetchUrl = "$MD5SumsUrl`?t=$CacheBuster"
    Write-Host "[DEBUG] MD5SUMS URL: $MD5FetchUrl"
}
try {
    $MD5SumsContent = (Invoke-WebRequest -Uri $MD5FetchUrl -UseBasicParsing -TimeoutSec 5).Content
    if ($DebugScripts) { Write-Host "[DEBUG] MD5SUMS loaded, length: $($MD5SumsContent.Length)" }
} catch {
    if ($DebugScripts) { Write-Host "[DEBUG] Failed to load MD5SUMS: $_" }
}

# Check launcher version
try {
    $VersionsUrl = "$RepoBaseUrl/LAUNCHER-VERSIONS.json"
    if ($GitHubPAT) { $VersionsUrl = Add-GitHubToken -Url $VersionsUrl -Token $GitHubPAT }
    $VersionsJson = (Invoke-WebRequest -Uri $VersionsUrl -UseBasicParsing -TimeoutSec 3).Content | ConvertFrom-Json
    $RepoVersion = $VersionsJson.launchers.$LauncherName
    if ($RepoVersion -and ([version]$RepoVersion -gt [version]$LauncherVersion)) {
        Write-Host ""
        Write-Host "[Alert] LAUNCHER OUTDATED: v$LauncherVersion -> v$RepoVersion"
        Write-Host "[Alert] Update this script in Level.io from: launchers/$LauncherName"
        Write-Host ""
    }
} catch {
    if ($DebugScripts) { Write-Host "[DEBUG] Version check failed: $_" }
}

# ============================================================
# COLLECT POLICY VARIABLES
# ============================================================
$PolicyVars = @{}
Get-Variable -Name "policy_*" -ErrorAction SilentlyContinue | ForEach-Object {
    if (-not [string]::IsNullOrWhiteSpace($_.Value) -and $_.Value -notlike "{{*}}") {
        $PolicyVars[$_.Name] = $_.Value
    }
}

# ============================================================
# EXECUTE SCRIPT
# ============================================================
Write-Host "[*] Slim Launcher v$LauncherVersion"

$LauncherVars = @{
    MspScratchFolder = $MspScratchFolder
    DeviceHostname   = $DeviceHostname
    DeviceTags       = $DeviceTags
    LevelApiKey      = $LevelApiKey
    DebugScripts     = $DebugScripts
    LibraryUrl       = $LibraryUrl
}

# Add policy variables
foreach ($key in $PolicyVars.Keys) {
    $LauncherVars[$key] = $PolicyVars[$key]
}

$ExitCode = Invoke-ScriptLauncher -ScriptName $ScriptToRun `
                                   -RepoBaseUrl $RepoBaseUrl `
                                   -MD5SumsContent $MD5SumsContent `
                                   -MspScratchFolder $MspScratchFolder `
                                   -LauncherVariables $LauncherVars `
                                   -DebugMode $DebugScripts

exit $ExitCode
