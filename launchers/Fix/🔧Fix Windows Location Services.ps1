# ============================================================
# SCRIPT TO RUN - PRE-CONFIGURED
# ============================================================
$ScriptToRun = "🔧Fix Windows Location Services.ps1"
$policy_SCRIPTNAME = "{{cf_policy_SCRIPTNAME}}"
<#
.SYNOPSIS
    Micro Level.io Script Launcher - Downloads bootstrap from GitHub, which handles everything else.

.NOTES
    Launcher Version: 2026.02.03.01
    Target Platform:  Level.io RMM

    This micro-launcher (~50 lines) downloads and executes the bootstrap script.
    All launcher logic is in the bootstrap and library (updatable via GitHub).

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge
#>

$LauncherVersion = "2026.02.03.01"
$LauncherName = "Fix/🔧Fix Windows Location Services.ps1"

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
$LibraryUrl = "{{cf_coolforge_ps_module_library_source}}"
$DebugScriptsRaw = "{{cf_debug_coolforge}}"

$LevelApiKey_Raw = @'
{{cf_apikey}}
'@
$LevelApiKey = $LevelApiKey_Raw.Trim()

# ============================================================
# BOOTSTRAP DOWNLOAD + EXECUTE
# ============================================================
$Branch = if (-not [string]::IsNullOrWhiteSpace($PinnedVersion) -and $PinnedVersion -notlike "{{*}}") { $PinnedVersion } else { "main" }
$BootstrapUrl = "https://raw.githubusercontent.com/coolnetworks/COOLForge/$Branch/bootstrap/COOLForge-Bootstrap.ps1"
if ($GitHubPAT) { $BootstrapUrl = $BootstrapUrl -replace '(https://)raw\.githubusercontent\.com', "`$1$GitHubPAT@raw.githubusercontent.com" }

$BootstrapCachePath = Join-Path -Path $MspScratchFolder -ChildPath "Libraries\COOLForge-Bootstrap.ps1"
$Content = $null

try {
    $CacheBuster = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $Content = (Invoke-WebRequest -Uri "$BootstrapUrl`?t=$CacheBuster" -UseBasicParsing -TimeoutSec 10 -Headers @{ 'Cache-Control' = 'no-cache, no-store'; 'Pragma' = 'no-cache' }).Content
    $CacheDir = Split-Path $BootstrapCachePath -Parent
    if (!(Test-Path $CacheDir)) { New-Item -Path $CacheDir -ItemType Directory -Force | Out-Null }
    [System.IO.File]::WriteAllText($BootstrapCachePath, $Content, [System.Text.UTF8Encoding]::new($true))
} catch {
    if (Test-Path $BootstrapCachePath) {
        Write-Host "[!] Bootstrap download failed - using cached version"
        $Content = Get-Content -Path $BootstrapCachePath -Raw
    } else {
        Write-Host "[Alert] Cannot download bootstrap: $_"
        exit 1
    }
}

$BootstrapResult = & ([scriptblock]::Create($Content))
$ExitCode = if ($BootstrapResult -is [int]) { $BootstrapResult } elseif ($BootstrapResult -is [array]) { $BootstrapResult[-1] } else { 0 }
exit $ExitCode
