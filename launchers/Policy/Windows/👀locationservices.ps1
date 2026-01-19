# ============================================================
# SCRIPT TO RUN - PRE-CONFIGURED
# ============================================================
$ScriptToRun = "Windows/👀locationservices.ps1"
$policy_device_locationservices = "{{cf_policy_device_locationservices}}"
<#
.SYNOPSIS
    Slim Level.io Launcher for Windows Location Services Configuration Policy

.NOTES
    Launcher Version: 2026.01.19.01
    Target Platform:  Level.io RMM

    This slim launcher (~200 lines) replaces the full launcher (~660 lines).
    Script download/execution is handled by Invoke-ScriptLauncher in the library.

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge
#>

$LauncherVersion = "2026.01.20.02"
$LauncherName = "Policy/Windows/👀locationservices.ps1"

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

if (!(Test-Path $LibraryFolder)) {
    New-Item -Path $LibraryFolder -ItemType Directory -Force | Out-Null
}

# Helper to parse version from content
function Get-ModuleVersion {
    param([string]$Content)
    if ($Content -match 'Version:\s*([\d\.]+)') { return $Matches[1] }
    return "unknown"
}

# Helper to compute MD5 hash of string content
function Get-StringMD5 {
    param([string]$Content)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Content)
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $hash = $md5.ComputeHash($bytes)
    return [BitConverter]::ToString($hash).Replace("-", "").ToLower()
}

# STEP 1: Download MD5SUMS first (with cache-busting)
$MD5SumsContent = $null
$CacheBuster = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$MD5FetchUrl = "$MD5SumsUrl`?t=$CacheBuster"
if ($DebugScripts) { Write-Host "[DEBUG] MD5SUMS URL: $MD5FetchUrl" }

try {
    $MD5SumsContent = (Invoke-WebRequest -Uri $MD5FetchUrl -UseBasicParsing -TimeoutSec 5).Content
    if ($DebugScripts) { Write-Host "[DEBUG] MD5SUMS loaded, length: $($MD5SumsContent.Length)" }
} catch {
    if ($DebugScripts) { Write-Host "[DEBUG] Failed to load MD5SUMS: $_" }
}

# STEP 2: Parse expected library hash from MD5SUMS
$ExpectedLibraryHash = $null
if ($MD5SumsContent) {
    $MD5SumsContent -split "`n" | ForEach-Object {
        if ($_ -match '^([a-f0-9]{32})\s+modules/COOLForge-Common\.psm1') {
            $ExpectedLibraryHash = $Matches[1]
        }
    }
    if ($DebugScripts) { Write-Host "[DEBUG] Expected library hash: $ExpectedLibraryHash" }
}

# STEP 3: Check local library hash
$NeedsUpdate = $false
$LocalHash = $null
$LocalVersion = $null

if ($DebugScripts -and (Test-Path $LibraryPath)) {
    # In debug mode, always re-download
    Remove-Item -Path $LibraryPath -Force -ErrorAction SilentlyContinue
    $NeedsUpdate = $true
    Write-Host "[DEBUG] Forcing library re-download"
} elseif (Test-Path $LibraryPath) {
    try {
        $LocalContent = Get-Content -Path $LibraryPath -Raw -ErrorAction Stop
        $LocalVersion = Get-ModuleVersion -Content $LocalContent
        $LocalHash = Get-StringMD5 -Content $LocalContent
        if ($DebugScripts) { Write-Host "[DEBUG] Local library hash: $LocalHash" }

        if ($ExpectedLibraryHash -and $LocalHash -ne $ExpectedLibraryHash) {
            $NeedsUpdate = $true
            Write-Host "[*] Library hash mismatch - updating..."
        }
    } catch {
        $NeedsUpdate = $true
    }
} else {
    $NeedsUpdate = $true
    Write-Host "[*] Library not found - downloading..."
}

# STEP 4: Download library if needed (always use cache-busting)
if ($NeedsUpdate) {
    $LibFetchUrl = "$LibraryUrl`?t=$CacheBuster"
    if ($DebugScripts) { Write-Host "[DEBUG] Library URL: $LibFetchUrl" }

    try {
        $RemoteContent = (Invoke-WebRequest -Uri $LibFetchUrl -UseBasicParsing -TimeoutSec 10).Content
        $RemoteVersion = Get-ModuleVersion -Content $RemoteContent
        $RemoteHash = Get-StringMD5 -Content $RemoteContent

        if ($DebugScripts) { Write-Host "[DEBUG] Remote library hash: $RemoteHash" }

        # Verify downloaded content matches expected hash
        if ($ExpectedLibraryHash -and $RemoteHash -ne $ExpectedLibraryHash) {
            Write-Host "[!] WARNING: Downloaded library hash doesn't match MD5SUMS!"
            Write-Host "[!] Expected: $ExpectedLibraryHash"
            Write-Host "[!] Got: $RemoteHash"
        }

        Set-Content -Path $LibraryPath -Value $RemoteContent -Force -ErrorAction Stop
        Write-Host "[+] Library updated to v$RemoteVersion"
    } catch {
        if (!(Test-Path $LibraryPath)) {
            Write-Host "[Alert] Cannot download library: $_"
            exit 1
        }
        Write-Host "[!] Using cached library v$LocalVersion"
    }
}

# Import library
$ModuleContent = Get-Content -Path $LibraryPath -Raw
New-Module -Name "COOLForge-Common" -ScriptBlock ([scriptblock]::Create($ModuleContent)) | Import-Module -Force

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
