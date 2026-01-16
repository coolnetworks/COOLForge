# ============================================================
# SCRIPT TO RUN - PRE-CONFIGURED
# ============================================================
$ScriptToRun = "👀Check DNS Server Compliance.ps1"
$ScriptCategory = "Check"
$AllowedDnsServers = "{{cf_dns}}"
<#
.SYNOPSIS
    Level.io Script Launcher - Downloads and executes scripts from GitHub with auto-update.

.DESCRIPTION
    This launcher checks that network adapters are using approved DNS servers.
    Virtual adapters (Hyper-V, TAP, VPN) are automatically ignored.

    Configure the cf_dns custom field with allowed DNS server IPs:
    Example: 1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4

.NOTES
    Launcher Version: 2026.01.17.01
    Target Platform:  Level.io RMM
    Exit Codes:       0 = Success (Compliant) | 1 = Alert (Non-compliant)

    Level.io Variables Used:
    - {{cf_coolforge_msp_scratch_folder}}      : MSP-defined scratch folder for persistent storage
    - {{cf_coolforge_ps_module_library_source}}: URL to download COOLForge-Common.psm1 library
    - {{cf_coolforge_pin_psmodule_to_version}} : (Optional) Pin to specific version tag
    - {{cf_coolforge_pat}}                     : (Optional) GitHub Personal Access Token for private repos
    - {{level_device_hostname}}                : Device hostname from Level.io
    - {{level_tag_names}}                      : Comma-separated list of device tags
    - {{cf_dns}}                               : Comma-separated list of allowed DNS servers

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# Script Launcher
# Launcher Version: 2026.01.17.01
# Target: Level.io
# Exit 0 = Success | Exit 1 = Alert (Failure)
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge
$ErrorActionPreference = "SilentlyContinue"

# ============================================================
# LEVEL.IO VARIABLES - PASSED TO DOWNLOADED SCRIPT
# ============================================================
$MspScratchFolder = "{{cf_coolforge_msp_scratch_folder}}"
$DeviceHostname = "{{level_device_hostname}}"
$DeviceTags = "{{level_tag_names}}"

$GitHubPAT = @'
{{cf_coolforge_pat}}
'@
$GitHubPAT = $GitHubPAT.Trim()
if ([string]::IsNullOrWhiteSpace($GitHubPAT) -or $GitHubPAT -like "{{*}}") {
    $GitHubPAT = $null
}

$PinnedVersion = "{{cf_coolforge_pin_psmodule_to_version}}"
$UsePinnedVersion = $false
if (-not [string]::IsNullOrWhiteSpace($PinnedVersion) -and $PinnedVersion -notlike "{{*}}") {
    $UsePinnedVersion = $true
    Write-Host "[*] Version pinned to: $PinnedVersion"
}

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
if ([string]::IsNullOrWhiteSpace($LevelApiKey) -or $LevelApiKey -like "{{*}}") {
    $LevelApiKey = $null
}

# ============================================================
# GITHUB PAT INJECTION HELPER
# ============================================================
function Add-GitHubToken {
    param([string]$Url, [string]$Token)
    if ([string]::IsNullOrWhiteSpace($Token)) { return $Url }
    if ($Url -notmatch 'raw\.githubusercontent\.com') { return $Url }
    if ($Url -match '@raw\.githubusercontent\.com') { return $Url }
    return $Url -replace '(https://)raw\.githubusercontent\.com', "`$1$Token@raw.githubusercontent.com"
}

$RepoBaseUrl = $LibraryUrl -replace '/modules/[^/]+$', ''
$ScriptRepoBaseUrl = "$RepoBaseUrl/scripts"
$MD5SumsUrl = "$RepoBaseUrl/MD5SUMS"

if ($GitHubPAT) {
    $LibraryUrl = Add-GitHubToken -Url $LibraryUrl -Token $GitHubPAT
    $MD5SumsUrl = Add-GitHubToken -Url $MD5SumsUrl -Token $GitHubPAT
    $ScriptRepoBaseUrl = Add-GitHubToken -Url $ScriptRepoBaseUrl -Token $GitHubPAT
}

# ============================================================
# LIBRARY AUTO-UPDATE & IMPORT
# ============================================================
$LibraryFolder = Join-Path -Path $MspScratchFolder -ChildPath "Libraries"
$LibraryPath = Join-Path -Path $LibraryFolder -ChildPath "COOLForge-Common.psm1"

if ($DebugScripts -and (Test-Path $LibraryPath)) {
    Write-Host "[DEBUG] Deleting cached library to force fresh download..."
    Remove-Item -Path $LibraryPath -Force -ErrorAction SilentlyContinue
}

if (!(Test-Path $LibraryFolder)) {
    New-Item -Path $LibraryFolder -ItemType Directory -Force | Out-Null
}

function Get-ModuleVersion {
    param([string]$Content, [string]$Source = "unknown")
    if ($Content -match 'Version:\s*([\d\.]+)') {
        return $Matches[1]
    }
    throw "Could not parse version from $Source - invalid or corrupt content"
}

function Get-ContentMD5 {
    param([string]$Content)
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Content)
    $hash = $md5.ComputeHash($bytes)
    return ([BitConverter]::ToString($hash) -replace '-', '').ToLower()
}

function Get-ExpectedMD5 {
    param([string]$FileName, [string]$MD5Content)
    $SearchName = Split-Path $FileName -Leaf
    foreach ($line in $MD5Content -split "`n") {
        $line = $line.Trim()
        if ($line -match '^#' -or [string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -match '^([a-f0-9]{32})\s+(.+)$') {
            $FilePath = $Matches[2].Trim()
            $FileLeaf = Split-Path $FilePath -Leaf
            if ($FilePath -eq $FileName -or $FileLeaf -eq $SearchName -or $FileLeaf -like "*$SearchName") {
                return $Matches[1].ToLower()
            }
        }
    }
    return $null
}

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
}
catch {
    Write-Host "[!] Could not download MD5SUMS - checksum verification disabled"
    if ($DebugScripts) { Write-Host "[DEBUG] MD5SUMS error: $_" }
}

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

$ModuleContent = Get-Content -Path $LibraryPath -Raw
New-Module -Name "COOLForge-Common" -ScriptBlock ([scriptblock]::Create($ModuleContent)) | Import-Module -Force

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
$ScriptToRun = Repair-LevelEmoji -Text $ScriptToRun

# ============================================================
# RESOLVE SCRIPT PATH FROM MD5SUMS
# ============================================================
function Get-ScriptPathFromMD5 {
    param([string]$ScriptName, [string]$MD5Content)

    if ([string]::IsNullOrWhiteSpace($MD5Content)) { return $null }

    foreach ($line in $MD5Content -split "`n") {
        $line = $line.Trim()
        if ($line -match '^#' -or [string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -match '^([a-f0-9]{32})\s+(.+)$') {
            $FilePath = $Matches[2].Trim()
            $FileName = Split-Path $FilePath -Leaf
            if ($FileName -eq $ScriptName -or $FileName -like "*$ScriptName") {
                return $FilePath
            }
        }
    }
    return $null
}

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
Write-Host "[*] Script Launcher v2026.01.17.01"
Write-Host "[*] Preparing to run: $ScriptToRun"

$ScriptsFolder = Join-Path -Path $MspScratchFolder -ChildPath "Scripts"
if (!(Test-Path $ScriptsFolder)) {
    New-Item -Path $ScriptsFolder -ItemType Directory -Force | Out-Null
}

$SafeScriptName = $ScriptToRun -replace '[<>:"/\\|?*]', '_'
$ScriptPath = Join-Path -Path $ScriptsFolder -ChildPath $SafeScriptName

if ($ScriptRelativePath) {
    $ScriptUrl = "$RepoBaseUrl/$(Get-LevelUrlEncoded $ScriptRelativePath)"
} else {
    Write-Host "[!] Script not found in MD5SUMS - trying flat path"
    $ScriptUrl = "$ScriptRepoBaseUrl/$(Get-LevelUrlEncoded $ScriptToRun)"
}

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

try {
    $RemoteScriptContent = (Invoke-WebRequest -Uri $ScriptUrl -UseBasicParsing -TimeoutSec 15).Content

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
        $ScriptNeedsUpdate = $true
    }

    if ($ScriptNeedsUpdate) {
        if ($LocalScriptVersion -and $LocalScriptContent) {
            Set-Content -Path $ScriptBackupPath -Value $LocalScriptContent -Force -ErrorAction Stop
        }

        Set-Content -Path $ScriptPath -Value $RemoteScriptContent -Force -ErrorAction Stop

        try {
            $VerifyScriptContent = Get-Content -Path $ScriptPath -Raw -ErrorAction Stop
            if ($VerifyScriptContent.Length -lt 50) {
                throw "Downloaded script appears to be empty or truncated"
            }

            if ($MD5SumsContent -and -not $DebugScripts) {
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
            if (Test-Path $ScriptBackupPath) {
                Write-Host "[!] Downloaded script corrupt or checksum failed - restoring backup"
                Move-Item -Path $ScriptBackupPath -Destination $ScriptPath -Force
            }
            throw "Downloaded script failed verification: $($_.Exception.Message)"
        }
    }
}
catch {
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
Write-Host "[*] Executing: $ScriptToRun"
Write-Host "============================================================"

$ScriptContent = Get-Content -Path $ScriptPath -Raw

$PolicyVarsBlock = ""
Get-Variable -Name "policy_*" -ErrorAction SilentlyContinue | ForEach-Object {
    $VarName = $_.Name
    $VarValue = $_.Value
    if (-not [string]::IsNullOrWhiteSpace($VarValue) -and $VarValue -notlike "{{*}}") {
        $EscapedValue = $VarValue -replace "'", "''"
        $PolicyVarsBlock += "`n`$$VarName = '$EscapedValue'"
    }
}

$ExecutionBlock = @"
# Level.io variables passed from launcher
`$MspScratchFolder = '$($MspScratchFolder -replace "'", "''")'
`$LibraryUrl = '$($LibraryUrl -replace "'", "''")'
`$DeviceHostname = '$($DeviceHostname -replace "'", "''")'
`$DeviceTags = '$($DeviceTags -replace "'", "''")'
`$LevelApiKey = $(if ($LevelApiKey) { "'$($LevelApiKey -replace "'", "''" -replace '\$', '`$')'" } else { '$null' })
`$DebugScripts = `$$DebugScripts
`$AllowedDnsServers = '$($AllowedDnsServers -replace "'", "''")'

# Policy custom fields (defined in launcher header)
$PolicyVarsBlock

# The downloaded script content follows:
$ScriptContent
"@

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

exit $ScriptExitCode
