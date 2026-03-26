<#
.SYNOPSIS
    Software policy enforcement for Adobe Acrobat Pro.

.DESCRIPTION
    Implements the COOLForge 5-tag policy model for Adobe Acrobat Pro software management.
    See docs/POLICY-TAGS.md for the complete policy specification.

    POLICY FLOW (per POLICY-TAGS.md):
    1. Check global control tags (device must have checkmark to be managed)
    2. Check software-specific override tags (highest priority)
    3. Fall back to custom field policy (policy_acrobat_pro)
    4. Execute resolved action (install/remove/reinstall)

    GLOBAL CONTROL TAGS (standalone):
    - U+2705 = Device is managed (required to process)
    - U+274C = Device is excluded from management
    - Both = Device is globally pinned (no changes)

    SOFTWARE-SPECIFIC OVERRIDE TAGS (with "acrobat-pro" suffix):
    - U+1F64F acrobat-pro = Install if missing (transient)
    - U+1F6AB acrobat-pro = Remove if present (transient)
    - U+1F4CC acrobat-pro = Pin - no changes allowed (persistent)
    - U+1F504 acrobat-pro = Reinstall - remove + install (transient)
    - U+2705 acrobat-pro  = Status: software is installed (set by script)

    CUSTOM FIELD POLICY (inherited Group->Folder->Device):
    - policy_acrobat_pro = "install" | "remove" | "pin" | ""

    INSTALLATION METHOD:
    Uses Office Deployment Tool (ODT) to install/remove Acrobat Pro.
    Falls back to winget if ODT is not available.

.NOTES
    Version:          2026.03.26.04
    Target Platform:  Level.io RMM (via Script Launcher)
    Exit Codes:       0 = Success | 1 = Alert (Failure)

    Level.io Variables Used (passed from Script Launcher):
    - $MspScratchFolder   : MSP-defined scratch folder for persistent storage
    - $DeviceHostname     : Device hostname from Level.io
    - $DeviceTags         : Comma-separated list of device tags
    - $policy_acrobat_pro : Custom field policy value (inherited)

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# Software Policy - Adobe Acrobat Pro
# Version: 2026.03.26.04
# Target: Level.io (via Script Launcher)
# Exit 0 = Success | Exit 1 = Alert (Failure)
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge

# ============================================================
# DEBUG OUTPUT HELPER (Software-specific)
# ============================================================
function Write-DebugInstallCheck {
    param([bool]$IsInstalled)
    if (-not $DebugScripts) { return }

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " DEBUG: Installation Check" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    $RegPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    Write-Host "  --- Registry Search ---"
    foreach ($Path in $RegPaths) {
        $Found = Get-ItemProperty $Path -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*Acrobat*Pro*" }
        if ($Found) {
            foreach ($item in $Found) {
                Write-Host "  [FOUND] $($item.DisplayName) v$($item.DisplayVersion)" -ForegroundColor Green
            }
        } else {
            Write-Host "  [    ] $Path" -ForegroundColor DarkGray
        }
    }

    Write-Host ""
    Write-Host "  SOFTWARE INSTALLED: $(if ($IsInstalled) { 'YES' } else { 'NO' })" -ForegroundColor $(if ($IsInstalled) { 'Green' } else { 'Yellow' })
}

# ============================================================
# CONFIGURATION
# ============================================================
$SoftwareName = "acrobat-pro"

# ============================================================
# INITIALIZE
# ============================================================
$Init = Initialize-LevelScript -ScriptName "Policy-$SoftwareName" `
                               -MspScratchFolder $MspScratchFolder `
                               -DeviceHostname $DeviceHostname `
                               -DeviceTags $DeviceTags

if (-not $Init.Success) {
    exit 0
}

# Sync script-level debug variables if a debug tag overrode the custom field
if ($Init.DebugTagDetected) {
    $DebugLevel = $Init.DebugLevel
    $DebugScripts = $Init.DebugMode
}

# ============================================================
# SOFTWARE DETECTION
# ============================================================
function Test-AcrobatProInstalled {
    # Check registry for Acrobat Pro
    $RegPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    foreach ($Path in $RegPaths) {
        $Found = Get-ItemProperty $Path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like "*Acrobat*Pro*" -and $_.DisplayName -notlike "*Reader*" }
        if ($Found) {
            if ($DebugScripts) {
                Write-Host "  [DEBUG] Acrobat Pro detected: $($Found[0].DisplayName)" -ForegroundColor Green
            }
            return $true
        }
    }

    # Check common install paths
    $InstallPaths = @(
        "$env:ProgramFiles\Adobe\Acrobat DC\Acrobat\Acrobat.exe",
        "${env:ProgramFiles(x86)}\Adobe\Acrobat DC\Acrobat\Acrobat.exe",
        "$env:ProgramFiles\Adobe\Acrobat 2020\Acrobat\Acrobat.exe"
    )
    foreach ($Path in $InstallPaths) {
        if (Test-Path $Path) {
            if ($DebugScripts) {
                Write-Host "  [DEBUG] Acrobat Pro detected at: $Path" -ForegroundColor Green
            }
            return $true
        }
    }

    return $false
}

function Remove-ConflictingAdobeProducts {
    # Remove O365HomePremRetail and OneNoteFreeRetail if present (block Acrobat Pro install)
    # Also remove Acrobat Reader (conflicts with Pro)
    $Removed = @()

    # Check for Office Home products via ODT
    $OdtSetup = Join-Path $env:TEMP "odt_setup.exe"
    $HasOdt = Test-Path $OdtSetup

    # Remove Acrobat Reader via winget or uninstaller
    $ReaderInstalled = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like "*Acrobat*Reader*" }

    if ($ReaderInstalled) {
        Write-LevelLog "Removing Acrobat Reader (conflicts with Pro)..." -Level "INFO"
        foreach ($reader in $ReaderInstalled) {
            if ($reader.UninstallString) {
                $uninstCmd = $reader.UninstallString -replace '/I', '/X'
                if ($uninstCmd -like "MsiExec*") {
                    $uninstCmd = "$uninstCmd /qn /norestart"
                    Write-LevelLog "Running: $uninstCmd" -Level "DEBUG"
                    cmd /c $uninstCmd 2>&1 | Out-Null
                    $Removed += "Acrobat Reader"
                }
            }
        }
    }

    return $Removed
}

function Install-AcrobatPro {
    param([string]$ScratchFolder)

    # Validate scratch folder path
    if ([string]::IsNullOrWhiteSpace($ScratchFolder) -or $ScratchFolder -like "*{{*") {
        Write-Host "Alert: Invalid scratch folder path"
        Write-Host "  ScratchFolder: $ScratchFolder"
        Write-LevelLog "Invalid scratch folder - template variable not resolved" -Level "ERROR"
        return $false
    }

    $InstallersFolder = Join-Path $ScratchFolder "Installers"
    if (-not (Test-Path $InstallersFolder)) {
        New-Item -ItemType Directory -Path $InstallersFolder -Force | Out-Null
    }

    # Remove conflicting products first
    $RemovedProducts = Remove-ConflictingAdobeProducts
    if ($RemovedProducts.Count -gt 0) {
        Write-LevelLog "Removed conflicting products: $($RemovedProducts -join ', ')" -Level "INFO"
        Start-Sleep -Seconds 5
    }

    # Strategy: Try winget first (handles download + hash verification), fall back to ODT
    $WingetInstalled = $false

    # --- Method 1: winget ---
    $WingetPath = Get-Command winget -ErrorAction SilentlyContinue
    if ($WingetPath) {
        Write-LevelLog "Attempting install via winget..." -Level "INFO"
        try {
            $WingetResult = & winget install --id "Adobe.Acrobat.Pro" --accept-source-agreements --accept-package-agreements --silent 2>&1
            $WingetExitCode = $LASTEXITCODE
            $WingetOutput = $WingetResult -join "`n"

            if ($DebugScripts) {
                Write-Host "[DEBUG] winget exit code: $WingetExitCode"
                Write-Host "[DEBUG] winget output: $WingetOutput"
            }

            if ($WingetExitCode -eq 0) {
                Write-LevelLog "Acrobat Pro installed via winget" -Level "SUCCESS"
                $WingetInstalled = $true
            } elseif ($WingetOutput -match "hash does not match|installer hash") {
                Write-LevelLog "winget hash mismatch - falling back to direct download" -Level "WARN"
            } else {
                Write-LevelLog "winget failed (exit $WingetExitCode) - falling back to direct download" -Level "WARN"
            }
        } catch {
            Write-LevelLog "winget exception: $($_.Exception.Message)" -Level "WARN"
        }
    }

    if ($WingetInstalled) {
        return $true
    }

    # --- Method 2: Direct download via Adobe CDN ---
    Write-LevelLog "Attempting direct download from Adobe CDN..." -Level "INFO"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Browser-like headers to avoid Adobe CDN blocking automated requests
    $DownloadHeaders = @{
        'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36'
        'Accept' = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        'Accept-Language' = 'en-US,en;q=0.5'
        'Referer' = 'https://www.adobe.com/'
    }

    # Try multiple download URLs - full installer (zip) first, MSP patch only for updates
    $DownloadUrls = @(
        @{ Url = "https://trials.adobe.com/AdobeProducts/APRO/Acrobat_HelpX/win32/Acrobat_DC_Web_x64_WWMUI.zip"; Type = "zip" },
        @{ Url = "https://ardownload2.adobe.com/pub/adobe/acrobat/win/AcrobatDC/2500121223/AcrobatDCx64Upd2500121223.msp"; Type = "msp" }
    )

    $ZipPath = Join-Path $InstallersFolder "Acrobat_DC_Web_x64_WWMUI.zip"
    $MspPath = Join-Path $InstallersFolder "AcrobatDCx64Upd.msp"
    $DownloadSuccess = $false
    $DownloadType = $null

    foreach ($UrlEntry in $DownloadUrls) {
        $CurrentUrl = $UrlEntry.Url
        $CurrentType = $UrlEntry.Type
        $TargetPath = if ($CurrentType -eq "msp") { $MspPath } else { $ZipPath }

        Write-LevelLog "Trying: $CurrentUrl" -Level "INFO"

        for ($attempt = 1; $attempt -le 2; $attempt++) {
            try {
                # Streaming download with progress output
                $WebRequest = [System.Net.HttpWebRequest]::Create($CurrentUrl)
                $WebRequest.UserAgent = $DownloadHeaders['User-Agent']
                $WebRequest.Referer = $DownloadHeaders['Referer']
                $WebRequest.Accept = $DownloadHeaders['Accept']
                $WebRequest.Timeout = 300000  # 5 min timeout

                $Response = $WebRequest.GetResponse()
                $TotalBytes = $Response.ContentLength
                $TotalMB = if ($TotalBytes -gt 0) { [math]::Round($TotalBytes / 1MB, 1) } else { "?" }
                Write-Host "[*] Downloading: $TotalMB MB"

                $ResponseStream = $Response.GetResponseStream()
                $FileStream = [System.IO.File]::Create($TargetPath)
                $Buffer = New-Object byte[] 65536
                $BytesRead = 0
                $LastProgress = 0

                while (($Read = $ResponseStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {
                    $FileStream.Write($Buffer, 0, $Read)
                    $BytesRead += $Read
                    $CurrentMB = [math]::Round($BytesRead / 1MB, 1)

                    # Report progress every 10%
                    if ($TotalBytes -gt 0) {
                        $Pct = [math]::Floor(($BytesRead / $TotalBytes) * 100)
                        if ($Pct -ge ($LastProgress + 10)) {
                            $LastProgress = $Pct - ($Pct % 10)
                            Write-Host "[*] Progress: $CurrentMB / $TotalMB MB ($LastProgress%)"
                        }
                    } elseif ($CurrentMB -ge ($LastProgress + 10)) {
                        $LastProgress = [math]::Floor($CurrentMB / 10) * 10
                        Write-Host "[*] Downloaded: $CurrentMB MB..."
                    }
                }

                $FileStream.Close()
                $ResponseStream.Close()
                $Response.Close()

                if ((Test-Path $TargetPath) -and (Get-Item $TargetPath).Length -gt 1MB) {
                    $FinalMB = [math]::Round((Get-Item $TargetPath).Length / 1MB, 2)
                    $DownloadSuccess = $true
                    $DownloadType = $CurrentType
                    Write-LevelLog "Download complete: $FinalMB MB ($CurrentType)" -Level "SUCCESS"
                    break
                }
                Write-LevelLog "Download too small, retrying..." -Level "WARN"
            } catch {
                # Clean up partial file
                if ($FileStream) { try { $FileStream.Close() } catch {} }
                if ($ResponseStream) { try { $ResponseStream.Close() } catch {} }
                if ($Response) { try { $Response.Close() } catch {} }
                Write-LevelLog "Download attempt $attempt failed: $($_.Exception.Message)" -Level "WARN"
            }
            if ($attempt -lt 2) { Start-Sleep -Seconds 3 }
        }
        if ($DownloadSuccess) { break }
    }

    if (-not $DownloadSuccess) {
        Write-Host "Alert: Failed to download Acrobat Pro installer from all sources"
        Write-LevelLog "All download URLs failed" -Level "ERROR"
        return $false
    }

    # Install based on download type
    $maxAttempts = 2
    $installSuccess = $false
    $InstallerFile = $null
    $InstallArgs = $null
    $ExtractPath = $null

    if ($DownloadType -eq "msp") {
        # MSP is a patch - requires base Acrobat to already be installed
        if (-not (Test-AcrobatProInstalled)) {
            Write-Host "Alert: MSP patch downloaded but Acrobat Pro is not installed (required for patching)"
            Write-Host "  The full installer (zip) was unavailable. MSP patches cannot do fresh installs."
            Write-LevelLog "MSP requires base Acrobat - cannot fresh install with patch" -Level "ERROR"
            Remove-Item $MspPath -Force -ErrorAction SilentlyContinue
            return $false
        }
        Write-LevelLog "Applying MSP update patch..." -Level "INFO"
        $InstallerFile = $MspPath
        $InstallArgs = "/p `"$MspPath`" /qn /norestart EULA_ACCEPT=YES"
        $UseMsiexec = $true
    } else {
        # ZIP file - extract and find setup.exe
        Write-LevelLog "Extracting installer..." -Level "INFO"
        $ExtractPath = Join-Path $InstallersFolder "AcrobatProSetup"
        if (Test-Path $ExtractPath) {
            Remove-Item $ExtractPath -Recurse -Force -ErrorAction SilentlyContinue
        }
        try {
            Expand-Archive -Path $ZipPath -DestinationPath $ExtractPath -Force -ErrorAction Stop
        } catch {
            Write-Host "Alert: Failed to extract Acrobat Pro installer"
            Write-Host "  Error: $($_.Exception.Message)"
            Write-LevelLog "Extraction failed: $($_.Exception.Message)" -Level "ERROR"
            return $false
        }

        # Find setup.exe in extracted folder
        $SetupExe = Get-ChildItem -Path $ExtractPath -Filter "setup.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $SetupExe) {
            $SetupExe = Get-ChildItem -Path $ExtractPath -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match "Acro|Setup" } | Select-Object -First 1
        }

        if (-not $SetupExe) {
            Write-Host "Alert: setup.exe not found in extracted installer"
            Write-LevelLog "No setup.exe found in: $ExtractPath" -Level "ERROR"
            return $false
        }

        $InstallerFile = $SetupExe.FullName
        $InstallArgs = "/sAll /msi EULA_ACCEPT=YES"
        $UseMsiexec = $false
    }

    Write-LevelLog "Installing Acrobat Pro silently..." -Level "INFO"

    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            if ($UseMsiexec) {
                $Process = Start-Process "msiexec.exe" -ArgumentList $InstallArgs -Wait -PassThru -ErrorAction Stop
            } else {
                $Process = Start-Process -FilePath $InstallerFile -ArgumentList $InstallArgs -Wait -PassThru -ErrorAction Stop
            }

            if ($Process.ExitCode -eq 0 -or $Process.ExitCode -eq 3010) {
                $installSuccess = $true
                if ($Process.ExitCode -eq 3010) {
                    Write-LevelLog "Install succeeded - reboot required" -Level "WARN"
                }
                break
            }

            if ($attempt -lt $maxAttempts) {
                Write-LevelLog "Install failed (exit code: $($Process.ExitCode)) - retrying..." -Level "WARN"
                Start-Sleep -Seconds 5
                continue
            }

            Write-Host "Alert: Acrobat Pro installer failed after $maxAttempts attempts"
            Write-Host "  Installer: $InstallerFile"
            Write-Host "  Arguments: $InstallArgs"
            Write-Host "  Exit code: $($Process.ExitCode)"
            Write-LevelLog "Installer exited with code: $($Process.ExitCode)" -Level "ERROR"
        } catch {
            if ($attempt -lt $maxAttempts) {
                Write-LevelLog "Install error: $($_.Exception.Message) - retrying..." -Level "WARN"
                Start-Sleep -Seconds 3
                continue
            }
            Write-Host "Alert: Acrobat Pro installation exception"
            Write-Host "  Error: $($_.Exception.Message)"
            Write-LevelLog "Installation failed: $($_.Exception.Message)" -Level "ERROR"
        }
    }

    # Cleanup installer files
    Remove-Item $ZipPath -Force -ErrorAction SilentlyContinue
    Remove-Item $MspPath -Force -ErrorAction SilentlyContinue
    if ($ExtractPath) { Remove-Item $ExtractPath -Recurse -Force -ErrorAction SilentlyContinue }

    if ($installSuccess) {
        Write-LevelLog "Adobe Acrobat Pro installed successfully" -Level "SUCCESS"
        return $true
    }

    return $false
}

function Remove-AcrobatPro {
    # Find Acrobat Pro uninstall info from registry
    $RegPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $AcrobatPro = $null
    foreach ($Path in $RegPaths) {
        $AcrobatPro = Get-ItemProperty $Path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like "*Acrobat*Pro*" -and $_.DisplayName -notlike "*Reader*" } |
            Select-Object -First 1
        if ($AcrobatPro) { break }
    }

    if (-not $AcrobatPro) {
        Write-LevelLog "Acrobat Pro not found in registry" -Level "WARN"
        return $true  # Not installed = success
    }

    Write-LevelLog "Uninstalling: $($AcrobatPro.DisplayName)..." -Level "INFO"

    # Try MSI uninstall first
    if ($AcrobatPro.UninstallString -and $AcrobatPro.UninstallString -like "*MsiExec*") {
        $ProductCode = $null
        if ($AcrobatPro.UninstallString -match '\{[A-F0-9-]+\}') {
            $ProductCode = $Matches[0]
        }

        if ($ProductCode) {
            Write-LevelLog "Removing via MSI: $ProductCode" -Level "INFO"
            try {
                $Process = Start-Process "msiexec.exe" -ArgumentList "/X$ProductCode /qn /norestart" -Wait -PassThru -ErrorAction Stop
                if ($Process.ExitCode -eq 0 -or $Process.ExitCode -eq 3010) {
                    Write-LevelLog "Acrobat Pro uninstalled via MSI" -Level "SUCCESS"
                    return $true
                }
                Write-LevelLog "MSI uninstall exit code: $($Process.ExitCode)" -Level "WARN"
            } catch {
                Write-LevelLog "MSI uninstall error: $($_.Exception.Message)" -Level "WARN"
            }
        }
    }

    # Try winget remove as fallback
    $WingetPath = Get-Command winget -ErrorAction SilentlyContinue
    if ($WingetPath) {
        Write-LevelLog "Attempting removal via winget..." -Level "INFO"
        try {
            & winget uninstall --id "Adobe.Acrobat.Pro" --silent 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-LevelLog "Acrobat Pro removed via winget" -Level "SUCCESS"
                return $true
            }
        } catch {
            Write-LevelLog "winget removal failed: $($_.Exception.Message)" -Level "WARN"
        }
    }

    # Try direct uninstall string
    if ($AcrobatPro.UninstallString) {
        Write-LevelLog "Attempting direct uninstall..." -Level "INFO"
        try {
            $UninstallCmd = $AcrobatPro.UninstallString
            if ($UninstallCmd -notmatch '/qn|/quiet|/silent') {
                $UninstallCmd = "$UninstallCmd /qn /norestart"
            }
            cmd /c $UninstallCmd 2>&1 | Out-Null
            Start-Sleep -Seconds 5
            if (-not (Test-AcrobatProInstalled)) {
                Write-LevelLog "Acrobat Pro uninstalled" -Level "SUCCESS"
                return $true
            }
        } catch {
            Write-LevelLog "Direct uninstall failed: $($_.Exception.Message)" -Level "WARN"
        }
    }

    Write-Host "Alert: Failed to remove Adobe Acrobat Pro"
    Write-Host "  Product: $($AcrobatPro.DisplayName)"
    Write-LevelLog "All removal methods failed" -Level "ERROR"
    return $false
}

# ============================================================
# MAIN SCRIPT LOGIC
# ============================================================
$ScriptVersion = "2026.03.26.04"
$ExitCode = 0

$InvokeParams = @{ ScriptBlock = {

    Write-LevelLog "Policy Enforcement: $SoftwareName (v$ScriptVersion)"

    # Debug header
    if ($DebugScripts) {
        Write-Host ""
        Write-Host "============================================================" -ForegroundColor Magenta
        Write-Host " DEBUG MODE ENABLED (debug_coolforge = verbose)" -ForegroundColor Magenta
        Write-Host " Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Magenta
        Write-Host " Computer:  $env:COMPUTERNAME" -ForegroundColor Magenta
        Write-Host "============================================================" -ForegroundColor Magenta
    }

    # Debug: Show all launcher variables
    Write-DebugSection -Title "Launcher Variables" -Data @{
        'MspScratchFolder' = $MspScratchFolder
        'DeviceHostname' = $DeviceHostname
        'DeviceTags' = $DeviceTags
        'LevelApiKey' = $LevelApiKey
    } -MaskApiKey

    Write-Host ""

    # Get custom field policy if available (passed from launcher)
    $CustomFieldPolicyVar = "policy_$SoftwareName"
    $CustomFieldPolicy = Get-Variable -Name $CustomFieldPolicyVar -ValueOnly -ErrorAction SilentlyContinue
    if ($CustomFieldPolicy) {
        Write-LevelLog "Custom field policy: $CustomFieldPolicy"
    }

    # Debug: Show custom field policy
    Write-DebugSection -Title "Custom Field Policy" -Data @{
        "policy_$SoftwareName" = $CustomFieldPolicy
    }

    # Debug: Analyze device tags
    Write-DebugTags -TagString $DeviceTags -SoftwareName $SoftwareName

    # ============================================================
    # AUTO-BOOTSTRAP: Ensure policy infrastructure exists
    # ============================================================
    if ($LevelApiKey) {
        $KeyLength = $LevelApiKey.Length
        $KeyPreview = if ($KeyLength -gt 4) { $LevelApiKey.Substring(0, 4) + "****" } else { "(invalid)" }
        Write-LevelLog "API key: $KeyPreview (length: $KeyLength)" -Level "DEBUG"

        $PolicyFieldValue = Get-Variable -Name "policy_$SoftwareName" -ValueOnly -ErrorAction SilentlyContinue

        $InfraResult = Initialize-SoftwarePolicyInfrastructure -ApiKey $LevelApiKey `
            -SoftwareName $SoftwareName `
            -RequireUrl $false `
            -PolicyFieldValue $PolicyFieldValue

        if ($InfraResult.Success) {
            if ($InfraResult.TagsCreated -gt 0 -or $InfraResult.FieldsCreated -gt 0) {
                Write-LevelLog "Created $($InfraResult.TagsCreated) tags, $($InfraResult.FieldsCreated) fields" -Level "SUCCESS"
                Write-Host ""
                Write-Host "Alert: Policy infrastructure created - please configure custom fields"
                Write-Host "  Set the following custom fields in Level.io:"
                Write-Host "  - policy_acrobat_pro: Set to 'install', 'remove', or 'pin' at Group/Folder/Device level"
                Write-Host ""
                Write-LevelLog "Infrastructure created - exiting for configuration" -Level "INFO"
                $script:ExitCode = 1
                return 1
            }
        }
        else {
            Write-LevelLog "Infrastructure setup warning: $($InfraResult.Error)" -Level "WARN"
        }
    }

    # Check current installation state
    $IsInstalled = Test-AcrobatProInstalled
    Write-LevelLog "Current state: $(if ($IsInstalled) { 'Installed' } else { 'Not installed' })"

    # Debug: Show installation check details
    Write-DebugInstallCheck -IsInstalled $IsInstalled

    Write-Host ""

    # Run the policy check with the 5-tag model
    if ($DebugScripts) {
        Write-Host ""
        Write-Host "============================================================" -ForegroundColor Cyan
        Write-Host " DEBUG: Get-SoftwarePolicy Internal Trace" -ForegroundColor Cyan
        Write-Host "============================================================" -ForegroundColor Cyan
        $null = Get-SoftwarePolicy -SoftwareName $SoftwareName -DeviceTags $DeviceTags -CustomFieldPolicy $CustomFieldPolicy -ShowDebug
    }
    $Policy = Invoke-SoftwarePolicyCheck -SoftwareName $SoftwareName `
                                         -DeviceTags $DeviceTags `
                                         -CustomFieldPolicy $CustomFieldPolicy

    # Debug: Show policy resolution details
    Write-DebugPolicy -Policy $Policy

    # Debug: Show tag management readiness
    Write-DebugTagManagement -HasApiKey ([bool]$LevelApiKey) -DeviceHostname $DeviceHostname -ApiKeyValue $LevelApiKey

    Write-Host ""

    # Take action based on resolved policy
    $ActionSuccess = $false
    if ($Policy.ShouldProcess) {
        switch ($Policy.ResolvedAction) {
            "Install" {
                # If triggered by tag, set device custom field to "install" so intent persists
                if ($Policy.ActionSource -eq "Tag" -and $LevelApiKey) {
                    $Device = Find-LevelDevice -ApiKey $LevelApiKey -Hostname $DeviceHostname
                    if ($Device) {
                        $FieldRef = "policy_$SoftwareName"
                        $SetResult = Set-LevelCustomFieldValue -ApiKey $LevelApiKey -EntityType "device" -EntityId $Device.id -FieldReference $FieldRef -Value "install"
                        if ($SetResult) {
                            Write-LevelLog "Set device custom field '$FieldRef' = 'install'" -Level "SUCCESS"
                        }
                    }
                }
                if ($IsInstalled) {
                    Write-LevelLog "Already installed - no action needed" -Level "SUCCESS"
                    $ActionSuccess = $true
                }
                else {
                    Write-LevelLog "ACTION: Installing $SoftwareName" -Level "INFO"
                    $ActionSuccess = Install-AcrobatPro -ScratchFolder $MspScratchFolder
                    if (-not $ActionSuccess) {
                        Write-LevelLog "FAILED: Installation unsuccessful" -Level "ERROR"
                        $script:ExitCode = 1
                    }
                }
            }
            "Remove" {
                if ($Policy.ActionSource -eq "Tag" -and $LevelApiKey) {
                    $Device = Find-LevelDevice -ApiKey $LevelApiKey -Hostname $DeviceHostname
                    if ($Device) {
                        $FieldRef = "policy_$SoftwareName"
                        $SetResult = Set-LevelCustomFieldValue -ApiKey $LevelApiKey -EntityType "device" -EntityId $Device.id -FieldReference $FieldRef -Value "remove"
                        if ($SetResult) {
                            Write-LevelLog "Set device custom field '$FieldRef' = 'remove'" -Level "SUCCESS"
                        }
                    }
                }

                if (-not $IsInstalled) {
                    Write-LevelLog "Not installed - no action needed" -Level "SUCCESS"
                    $ActionSuccess = $true
                }
                else {
                    Write-LevelLog "ACTION: Removing $SoftwareName" -Level "INFO"
                    $ActionSuccess = Remove-AcrobatPro
                    if (-not $ActionSuccess) {
                        Write-LevelLog "FAILED: Removal unsuccessful" -Level "ERROR"
                        $script:ExitCode = 1
                    }
                }
            }
            "Reinstall" {
                Write-LevelLog "ACTION: Reinstalling $SoftwareName" -Level "INFO"
                if ($IsInstalled) {
                    $RemoveSuccess = Remove-AcrobatPro
                    if (-not $RemoveSuccess) {
                        Write-LevelLog "FAILED: Could not remove for reinstall" -Level "ERROR"
                        $script:ExitCode = 1
                        break
                    }
                    Start-Sleep -Seconds 5
                }
                $ActionSuccess = Install-AcrobatPro -ScratchFolder $MspScratchFolder
                if (-not $ActionSuccess) {
                    Write-LevelLog "FAILED: Reinstallation unsuccessful" -Level "ERROR"
                    $script:ExitCode = 1
                }
            }
            "Pin" {
                Write-LevelLog "Pinned - no changes allowed" -Level "INFO"
                if ($LevelApiKey) {
                    $Device = Find-LevelDevice -ApiKey $LevelApiKey -Hostname $DeviceHostname
                    if ($Device) {
                        $FieldRef = "policy_$SoftwareName"
                        $FieldValue = if ("Remove" -in $Policy.PolicyActions) { "remove" } else { "pin" }
                        $SetResult = Set-LevelCustomFieldValue -ApiKey $LevelApiKey -EntityType "device" -EntityId $Device.id -FieldReference $FieldRef -Value $FieldValue
                        if ($SetResult) {
                            Write-LevelLog "Set device custom field '$FieldRef' = '$FieldValue'" -Level "SUCCESS"
                        }
                    }
                }
                $ActionSuccess = $true
            }
            "None" {
                if ($Policy.HasInstalled -and -not $IsInstalled) {
                    Write-LevelLog "WARNING: Status tag says installed but software not found" -Level "WARN"
                }
                elseif (-not $Policy.HasInstalled -and $IsInstalled) {
                    Write-LevelLog "INFO: Software is installed (no policy action)" -Level "INFO"
                }
                else {
                    Write-LevelLog "No action required" -Level "INFO"
                }
                $ActionSuccess = $true
            }
        }
    }

    # ============================================================
    # TAG MANAGEMENT (per POLICY-TAGS.md Tag Cleanup Rules)
    # ============================================================
    if ($LevelApiKey) {
        Write-Host ""
        Write-LevelLog "Updating tags..." -Level "INFO"

        $DeviceForTags = $null
        $TagsBefore = @()
        if ($DebugScripts) {
            $DeviceForTags = Find-LevelDevice -ApiKey $LevelApiKey -Hostname $DeviceHostname
            if ($DeviceForTags) {
                Write-LevelLog "Device ID: $($DeviceForTags.id)" -Level "DEBUG"
                $TagsBefore = Get-LevelDeviceTagNames -ApiKey $LevelApiKey -DeviceId $DeviceForTags.id
                Write-LevelLog "Tags BEFORE: $($TagsBefore -join ', ')" -Level "DEBUG"
            } else {
                Write-LevelLog "Could not find device for tag verification" -Level "WARN"
            }
        }

        $FinalInstallState = Test-AcrobatProInstalled

        if ($ActionSuccess -and $Policy.ShouldProcess) {
            $SoftwareNameUpper = $SoftwareName.ToUpper()

            switch ($Policy.ResolvedAction) {
                "Install" {
                    Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Install" -DeviceHostname $DeviceHostname
                    if ($FinalInstallState) {
                        Add-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Has" -DeviceHostname $DeviceHostname
                    }
                }
                "Remove" {
                    Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Remove" -DeviceHostname $DeviceHostname
                    Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Has" -DeviceHostname $DeviceHostname
                }
                "Reinstall" {
                    Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Reinstall" -DeviceHostname $DeviceHostname
                    if ($FinalInstallState) {
                        Add-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Has" -DeviceHostname $DeviceHostname
                    }
                }
                "Pin" {
                    Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Pin" -DeviceHostname $DeviceHostname
                    if ("Remove" -in $Policy.PolicyActions) {
                        Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Remove" -DeviceHostname $DeviceHostname
                    }
                    if ($FinalInstallState -and -not $Policy.HasInstalled) {
                        Add-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Has" -DeviceHostname $DeviceHostname
                    }
                    elseif (-not $FinalInstallState -and $Policy.HasInstalled) {
                        Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Has" -DeviceHostname $DeviceHostname
                    }
                }
                "None" {
                    if ($FinalInstallState -and -not $Policy.HasInstalled) {
                        Add-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Has" -DeviceHostname $DeviceHostname
                    }
                    elseif (-not $FinalInstallState -and $Policy.HasInstalled) {
                        Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Has" -DeviceHostname $DeviceHostname
                    }
                }
            }
        }
        elseif (-not $Policy.ShouldProcess) {
            Write-LevelLog "Skipped - no tag updates needed" -Level "INFO"
        }
        else {
            Write-LevelLog "Action failed - tags not updated" -Level "WARN"
        }

        # Debug: Get tags AFTER changes
        if ($DebugScripts -and $DeviceForTags) {
            $TagsAfter = Get-LevelDeviceTagNames -ApiKey $LevelApiKey -DeviceId $DeviceForTags.id
            Write-LevelLog "Tags AFTER: $($TagsAfter -join ', ')" -Level "DEBUG"

            $Added = $TagsAfter | Where-Object { $_ -notin $TagsBefore }
            $Removed = $TagsBefore | Where-Object { $_ -notin $TagsAfter }
            if ($Added.Count -gt 0) {
                Write-LevelLog "Tags ADDED: $($Added -join ', ')" -Level "DEBUG"
            }
            if ($Removed.Count -gt 0) {
                Write-LevelLog "Tags REMOVED: $($Removed -join ', ')" -Level "DEBUG"
            }
            if ($Added.Count -eq 0 -and $Removed.Count -eq 0) {
                Write-LevelLog "No tag changes detected" -Level "DEBUG"
            }
        }
    }
    else {
        Write-LevelLog "No API key - tag updates skipped" -Level "DEBUG"
    }

    Write-Host ""

    if ($ActionSuccess) {
        Write-LevelLog "Policy enforcement completed successfully" -Level "SUCCESS"
    }
    else {
        Write-Host ""
        Write-Host "Alert: Policy enforcement failed for $SoftwareName"
        Write-Host "  Device: $DeviceHostname"
        Write-Host "  Action: $($Policy.ResolvedAction)"
        Write-Host "  See details above for specific error"
        Write-LevelLog "Policy enforcement completed with errors" -Level "ERROR"
    }

    # Debug footer
    if ($DebugScripts) {
        Write-Host ""
        Write-Host "============================================================" -ForegroundColor Magenta
        Write-Host " END OF DEBUG OUTPUT" -ForegroundColor Magenta
        Write-Host "============================================================" -ForegroundColor Magenta
    }

    return $(if ($ActionSuccess) { 0 } else { 1 })
}}
if ($RunningFromLauncher) { $InvokeParams.NoExit = $true }
Invoke-LevelScript @InvokeParams

exit $ExitCode
