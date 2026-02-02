# COOLForge Bootstrap - Downloaded and executed by micro-launcher
# This script reads variables from the parent (micro-launcher) scope
# and handles library download, verification, import, and script execution.
#
# Version: 2026.02.03.01
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge
#
# IMPORTANT: This script must NOT use 'exit' - it returns the exit code as a value.
# The micro-launcher handles 'exit'.

$ErrorActionPreference = "SilentlyContinue"

# ============================================================
# PARSE DEBUG LEVEL
# ============================================================
if ([string]::IsNullOrWhiteSpace($DebugScriptsRaw) -or $DebugScriptsRaw -like "{{*}}" -or $DebugScriptsRaw -eq "false" -or $DebugScriptsRaw -eq "normal") {
    $DebugLevel = "normal"
} elseif ($DebugScriptsRaw -eq "true" -or $DebugScriptsRaw -eq "1" -or $DebugScriptsRaw -eq "verbose") {
    $DebugLevel = "verbose"
} elseif ($DebugScriptsRaw -eq "2" -or $DebugScriptsRaw -eq "veryverbose") {
    $DebugLevel = "veryverbose"
} else {
    $DebugLevel = "normal"
}
# Keep $DebugScripts boolean for backwards compatibility
$DebugScripts = ($DebugLevel -ne "normal")

# ============================================================
# RESOLVE LIBRARY URL
# ============================================================
$UsePinnedVersion = (-not [string]::IsNullOrWhiteSpace($PinnedVersion) -and $PinnedVersion -notlike "{{*}}")
if ($DebugScripts) { Write-Host "[DEBUG] PinnedVersion='$PinnedVersion' UsePinnedVersion=$UsePinnedVersion" }

if ([string]::IsNullOrWhiteSpace($LibraryUrl) -or $LibraryUrl -like "{{*}}") {
    $Branch = if ($UsePinnedVersion) { $PinnedVersion } else { "main" }
    $LibraryUrl = "https://raw.githubusercontent.com/coolnetworks/COOLForge/$Branch/modules/COOLForge-Common.psm1"
} elseif ($UsePinnedVersion) {
    $LibraryUrl = $LibraryUrl -replace '/COOLForge/[^/]+/', "/COOLForge/$PinnedVersion/"
}
if ($DebugScripts) { Write-Host "[DEBUG] LibraryUrl=$LibraryUrl" }

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

if (!(Test-Path $LibraryFolder)) {
    New-Item -Path $LibraryFolder -ItemType Directory -Force | Out-Null
}

function Get-ModuleVersion {
    param([string]$Content)
    if ($Content -match 'Version:\s*([\d\.]+)') { return $Matches[1] }
    return "unknown"
}

function Get-StringMD5 {
    param([string]$Content)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Content)
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $hash = $md5.ComputeHash($bytes)
    return [BitConverter]::ToString($hash).Replace("-", "").ToLower()
}

# STEP 1: Download MD5SUMS (with cache-busting)
$MD5SumsContent = $null
$CacheBuster = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$MD5FetchUrl = "$MD5SumsUrl`?t=$CacheBuster"
$NoCacheHeaders = @{ 'Cache-Control' = 'no-cache, no-store'; 'Pragma' = 'no-cache' }
if ($DebugScripts) { Write-Host "[DEBUG] MD5SUMS URL: $MD5FetchUrl" }

try {
    $MD5SumsContent = (Invoke-WebRequest -Uri $MD5FetchUrl -UseBasicParsing -TimeoutSec 5 -Headers $NoCacheHeaders).Content
    if ($DebugScripts) { Write-Host "[DEBUG] MD5SUMS loaded, length: $($MD5SumsContent.Length)" }
} catch {
    if ($DebugScripts) { Write-Host "[DEBUG] Failed to load MD5SUMS: $_" }
}

# STEP 2: Parse expected library hash
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
    Remove-Item -Path $LibraryPath -Force -ErrorAction SilentlyContinue
    $NeedsUpdate = $true
    Write-Host "[DEBUG] Forcing library re-download"
} elseif (Test-Path $LibraryPath) {
    try {
        $LocalContent = Get-Content -Path $LibraryPath -Raw -ErrorAction Stop
        if ($LocalContent.StartsWith([char]0xFEFF)) {
            $LocalContent = $LocalContent.Substring(1)
        }
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

# STEP 4: Download library if needed
if ($NeedsUpdate) {
    $LibFetchUrl = if ($DebugScripts) { "$LibraryUrl`?t=$CacheBuster" } else { $LibraryUrl }
    if ($DebugScripts) { Write-Host "[DEBUG] Library URL: $LibFetchUrl" }

    try {
        $RemoteContent = (Invoke-WebRequest -Uri $LibFetchUrl -UseBasicParsing -TimeoutSec 10 -Headers $NoCacheHeaders).Content
        if ($RemoteContent.StartsWith([char]0xFEFF) -or $RemoteContent.StartsWith('?')) {
            $RemoteContent = $RemoteContent.Substring(1)
        }
        $RemoteVersion = Get-ModuleVersion -Content $RemoteContent
        $RemoteHash = Get-StringMD5 -Content $RemoteContent

        if ($DebugScripts) { Write-Host "[DEBUG] Remote library hash: $RemoteHash" }

        if ($ExpectedLibraryHash -and $RemoteHash -ne $ExpectedLibraryHash -and -not $DebugScripts) {
            Write-Host "[*] Hash mismatch - retrying with cache-bust..."
            $LibFetchUrl = "$LibraryUrl`?t=$CacheBuster"
            $RemoteContent = (Invoke-WebRequest -Uri $LibFetchUrl -UseBasicParsing -TimeoutSec 10 -Headers $NoCacheHeaders).Content
            if ($RemoteContent.StartsWith([char]0xFEFF) -or $RemoteContent.StartsWith('?')) {
                $RemoteContent = $RemoteContent.Substring(1)
            }
            $RemoteVersion = Get-ModuleVersion -Content $RemoteContent
            $RemoteHash = Get-StringMD5 -Content $RemoteContent
        }

        if ($ExpectedLibraryHash -and $RemoteHash -ne $ExpectedLibraryHash) {
            Write-Host "[!] WARNING: Library hash still doesn't match after cache-bust"
            Write-Host "[!] Expected: $ExpectedLibraryHash"
            Write-Host "[!] Got: $RemoteHash"
        }

        [System.IO.File]::WriteAllText($LibraryPath, $RemoteContent, [System.Text.UTF8Encoding]::new($true))
        Write-Host "[+] Library updated to v$RemoteVersion"
    } catch {
        if (!(Test-Path $LibraryPath)) {
            Write-Host "[Alert] Cannot download library: $_"
            return 1
        }
        Write-Host "[!] Using cached library v$LocalVersion"
    }
}

# Import library
$ModuleContent = Get-Content -Path $LibraryPath -Raw
New-Module -Name "COOLForge-Common" -ScriptBlock ([scriptblock]::Create($ModuleContent)) | Import-Module -Force

# Check launcher version (display at end of script)
$LauncherOutdatedMsg = $null
try {
    $VersionsUrl = "$RepoBaseUrl/LAUNCHER-VERSIONS.json?t=$CacheBuster"
    if ($GitHubPAT) { $VersionsUrl = Add-GitHubToken -Url $VersionsUrl -Token $GitHubPAT }
    $VersionsJson = (Invoke-WebRequest -Uri $VersionsUrl -UseBasicParsing -TimeoutSec 3 -Headers $NoCacheHeaders).Content | ConvertFrom-Json
    $RepoVersion = $VersionsJson.launchers.$LauncherName
    if ($RepoVersion -and ([version]$RepoVersion -gt [version]$LauncherVersion)) {
        $LauncherOutdatedMsg = "[Alert] LAUNCHER OUTDATED: v$LauncherVersion -> v$RepoVersion - Update this script in Level.io from: launchers/$LauncherName"
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
Write-Host "[*] Micro Launcher v$LauncherVersion"

$LauncherVars = @{
    MspScratchFolder = $MspScratchFolder
    DeviceHostname   = $DeviceHostname
    DeviceTags       = $DeviceTags
    LevelApiKey      = $LevelApiKey
    DebugScripts     = $DebugScripts
    DebugLevel       = $DebugLevel
    LibraryUrl       = $LibraryUrl
}

foreach ($key in $PolicyVars.Keys) {
    $LauncherVars[$key] = $PolicyVars[$key]
}

$ExitCode = Invoke-ScriptLauncher -ScriptName $ScriptToRun `
                                   -RepoBaseUrl $RepoBaseUrl `
                                   -MD5SumsContent $MD5SumsContent `
                                   -MspScratchFolder $MspScratchFolder `
                                   -LauncherVariables $LauncherVars `
                                   -DebugMode $DebugScripts

if ($LauncherOutdatedMsg) { Write-Host $LauncherOutdatedMsg }
$ExitCode
