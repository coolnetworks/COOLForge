<#
.SYNOPSIS
    Debug version of Unchecky policy script - shows all variables and diagnostics.

.DESCRIPTION
    This script displays all custom fields, tags, and policy resolution details
    to help debug why tags aren't being set or policies aren't working.

.NOTES
    Version:          2026.01.12.01
    Target Platform:  Level.io RMM (via Script Launcher)

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge
#>

# Debug Script - Unchecky Policy
# Version: 2026.01.12.01
# Target: Level.io (via Script Launcher)
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge

$SoftwareName = "unchecky"

# ============================================================
# HELPER FUNCTION - Mask sensitive values
# ============================================================
function Get-MaskedValue {
    param([string]$Value, [int]$ShowLast = 3)
    if ([string]::IsNullOrWhiteSpace($Value)) { return "(empty)" }
    if ($Value -like "{{*}}") { return "(unresolved template: $Value)" }
    if ($Value.Length -le $ShowLast) { return "***" }
    return ("*" * ($Value.Length - $ShowLast)) + $Value.Substring($Value.Length - $ShowLast)
}

# ============================================================
# DISPLAY HEADER
# ============================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " UNCHECKY POLICY DEBUG SCRIPT" -ForegroundColor Cyan
Write-Host " Version: 2026.01.12.01" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "Computer:  $env:COMPUTERNAME"
Write-Host ""

# ============================================================
# SECTION 1: RAW VARIABLES FROM LAUNCHER
# ============================================================
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host " 1. RAW VARIABLES (from launcher)" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host ""

# Check each variable and show its state
$Variables = @(
    @{ Name = '$MspScratchFolder'; Value = $MspScratchFolder },
    @{ Name = '$DeviceHostname'; Value = $DeviceHostname },
    @{ Name = '$DeviceTags'; Value = $DeviceTags },
    @{ Name = '$LevelApiKey'; Value = $LevelApiKey; Sensitive = $true },
    @{ Name = '$policy_unchecky'; Value = (Get-Variable -Name 'policy_unchecky' -ValueOnly -ErrorAction SilentlyContinue) }
)

foreach ($Var in $Variables) {
    $DisplayValue = if ($Var.Sensitive) {
        Get-MaskedValue -Value $Var.Value -ShowLast 3
    } else {
        if ([string]::IsNullOrWhiteSpace($Var.Value)) { "(empty)" }
        elseif ($Var.Value -like "{{*}}") { "(unresolved: $($Var.Value))" }
        else { $Var.Value }
    }

    $Status = if ([string]::IsNullOrWhiteSpace($Var.Value) -or $Var.Value -like "{{*}}") {
        "[MISSING]"
    } else {
        "[OK]"
    }

    $Color = if ($Status -eq "[OK]") { "Green" } else { "Red" }
    Write-Host "  $($Var.Name): " -NoNewline
    Write-Host "$Status " -ForegroundColor $Color -NoNewline
    Write-Host "$DisplayValue"
}

Write-Host ""

# ============================================================
# SECTION 2: DEVICE TAGS ANALYSIS
# ============================================================
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host " 2. DEVICE TAGS ANALYSIS" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host ""

if ([string]::IsNullOrWhiteSpace($DeviceTags) -or $DeviceTags -like "{{*}}") {
    Write-Host "  [WARNING] No device tags available" -ForegroundColor Red
} else {
    $TagArray = $DeviceTags -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    Write-Host "  Total tags: $($TagArray.Count)"
    Write-Host ""

    # Define emojis to look for
    $CheckmarkEmoji = [char]0x2705
    $CrossEmoji = [char]0x274C
    $PrayEmoji = [char]::ConvertFromUtf32(0x1F64F)
    $ProhibitEmoji = [char]::ConvertFromUtf32(0x1F6AB)
    $PinEmoji = [char]::ConvertFromUtf32(0x1F4CC)
    $RefreshEmoji = [char]::ConvertFromUtf32(0x1F504)

    $HasGlobalCheckmark = $false
    $HasGlobalCross = $false
    $SoftwareSpecificTags = @()

    foreach ($Tag in $TagArray) {
        $TagBytes = [System.Text.Encoding]::UTF8.GetBytes($Tag)
        $HexBytes = ($TagBytes | ForEach-Object { "{0:X2}" -f $_ }) -join " "

        # Check for global tags
        if ($Tag -eq "$CheckmarkEmoji") { $HasGlobalCheckmark = $true }
        if ($Tag -eq "$CrossEmoji") { $HasGlobalCross = $true }

        # Check for software-specific tags
        $TagUpper = $Tag.ToUpper()
        if ($TagUpper -match "UNCHECKY") {
            $SoftwareSpecificTags += $Tag
        }

        Write-Host "  Tag: '$Tag'"
        Write-Host "       Bytes: $HexBytes" -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "  --- Global Control Tags ---"
    Write-Host "  Global Checkmark ($CheckmarkEmoji): $(if ($HasGlobalCheckmark) { '[FOUND]' } else { '[NOT FOUND]' })" -ForegroundColor $(if ($HasGlobalCheckmark) { 'Green' } else { 'Yellow' })
    Write-Host "  Global Cross ($CrossEmoji): $(if ($HasGlobalCross) { '[FOUND]' } else { '[NOT FOUND]' })" -ForegroundColor $(if ($HasGlobalCross) { 'Green' } else { 'DarkGray' })

    Write-Host ""
    Write-Host "  --- Software-Specific Tags (unchecky) ---"
    if ($SoftwareSpecificTags.Count -eq 0) {
        Write-Host "  (none found)" -ForegroundColor DarkGray
    } else {
        foreach ($Tag in $SoftwareSpecificTags) {
            Write-Host "  - $Tag"
        }
    }
}

Write-Host ""

# ============================================================
# SECTION 3: INITIALIZE AND CHECK POLICY
# ============================================================
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host " 3. POLICY CHECK (via COOLForge-Common)" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host ""

# Try to initialize
$InitSuccess = $false
try {
    $Init = Initialize-LevelScript -ScriptName "Debug-$SoftwareName" `
                                   -MspScratchFolder $MspScratchFolder `
                                   -DeviceHostname $DeviceHostname `
                                   -DeviceTags $DeviceTags `
                                   -SkipLockFile

    if ($Init.Success) {
        Write-Host "  [OK] Initialize-LevelScript succeeded" -ForegroundColor Green
        $InitSuccess = $true
    } else {
        Write-Host "  [SKIP] Initialize-LevelScript: $($Init.Reason)" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "  [ERROR] Initialize-LevelScript failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""

# Get custom field policy
$CustomFieldPolicy = Get-Variable -Name 'policy_unchecky' -ValueOnly -ErrorAction SilentlyContinue
Write-Host "  Custom field policy (policy_unchecky): $(if ($CustomFieldPolicy) { $CustomFieldPolicy } else { '(empty)' })"
Write-Host ""

# Run policy check
if ($InitSuccess -or $true) {  # Run anyway to show diagnostics
    Write-Host "  Running Get-SoftwarePolicy..."
    Write-Host ""

    try {
        $Policy = Get-SoftwarePolicy -SoftwareName $SoftwareName -DeviceTags $DeviceTags -CustomFieldPolicy $CustomFieldPolicy -ShowDebug

        Write-Host ""
        Write-Host "  --- Policy Result ---"
        Write-Host "  GlobalStatus:    $($Policy.GlobalStatus)" -ForegroundColor $(if ($Policy.GlobalStatus -eq 'Managed') { 'Green' } else { 'Yellow' })
        Write-Host "  ShouldProcess:   $($Policy.ShouldProcess)" -ForegroundColor $(if ($Policy.ShouldProcess) { 'Green' } else { 'Yellow' })
        Write-Host "  ResolvedAction:  $($Policy.ResolvedAction)"
        Write-Host "  ActionSource:    $($Policy.ActionSource)"
        Write-Host "  HasInstalled:    $($Policy.HasInstalled)"
        Write-Host "  IsPinned:        $($Policy.IsPinned)"

        if ($Policy.SkipReason) {
            Write-Host "  SkipReason:      $($Policy.SkipReason)" -ForegroundColor Yellow
        }

        if ($Policy.MatchedTags.Count -gt 0) {
            Write-Host "  MatchedTags:     $($Policy.MatchedTags -join ', ')"
        }
    }
    catch {
        Write-Host "  [ERROR] Get-SoftwarePolicy failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host ""

# ============================================================
# SECTION 4: INSTALLATION CHECK
# ============================================================
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host " 4. UNCHECKY INSTALLATION CHECK" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host ""

$FilePaths = @(
    "$env:ProgramFiles\Unchecky\unchecky.exe",
    "${env:ProgramFiles(x86)}\Unchecky\unchecky.exe"
)
$RegPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Unchecky",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Unchecky"
)

Write-Host "  --- File Paths ---"
$FileFound = $false
foreach ($Path in $FilePaths) {
    $Exists = Test-Path $Path
    if ($Exists) { $FileFound = $true }
    Write-Host "  $(if ($Exists) { '[FOUND]' } else { '[    ]' }) $Path" -ForegroundColor $(if ($Exists) { 'Green' } else { 'DarkGray' })
}

Write-Host ""
Write-Host "  --- Registry Keys ---"
$RegFound = $false
foreach ($Path in $RegPaths) {
    $Exists = Test-Path $Path
    if ($Exists) { $RegFound = $true }
    Write-Host "  $(if ($Exists) { '[FOUND]' } else { '[    ]' }) $Path" -ForegroundColor $(if ($Exists) { 'Green' } else { 'DarkGray' })
}

Write-Host ""
$IsInstalled = $FileFound -or $RegFound
Write-Host "  UNCHECKY INSTALLED: $(if ($IsInstalled) { 'YES' } else { 'NO' })" -ForegroundColor $(if ($IsInstalled) { 'Green' } else { 'Yellow' })

Write-Host ""

# ============================================================
# SECTION 5: TAG MANAGEMENT READINESS
# ============================================================
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host " 5. TAG MANAGEMENT READINESS" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host ""

$ApiKeyReady = -not [string]::IsNullOrWhiteSpace($LevelApiKey) -and $LevelApiKey -notlike "{{*}}"
Write-Host "  API Key Present:     $(if ($ApiKeyReady) { '[YES] ' + (Get-MaskedValue $LevelApiKey 3) } else { '[NO] - Tag updates will be skipped!' })" -ForegroundColor $(if ($ApiKeyReady) { 'Green' } else { 'Red' })

$DeviceHostnameReady = -not [string]::IsNullOrWhiteSpace($DeviceHostname) -and $DeviceHostname -notlike "{{*}}"
Write-Host "  Device Hostname:     $(if ($DeviceHostnameReady) { '[YES] ' + $DeviceHostname } else { '[NO]' })" -ForegroundColor $(if ($DeviceHostnameReady) { 'Green' } else { 'Red' })

Write-Host ""

if ($ApiKeyReady -and $DeviceHostnameReady) {
    Write-Host "  [OK] Tag management is READY" -ForegroundColor Green
    Write-Host ""
    Write-Host "  If policy runs with ResolvedAction=Install and software is installed:"
    Write-Host "  -> Should call: Add-LevelPolicyTag -TagName 'UNCHECKY' -EmojiPrefix 'Has'"
} else {
    Write-Host "  [WARNING] Tag management will be SKIPPED" -ForegroundColor Red
    Write-Host ""
    Write-Host "  To enable tag management:"
    if (-not $ApiKeyReady) {
        Write-Host "  1. Create 'apikey' custom field in Level.io (admin-only)" -ForegroundColor Yellow
        Write-Host "     Set value to your Level.io API key" -ForegroundColor Yellow
    }
}

Write-Host ""

# ============================================================
# SECTION 6: WHAT WOULD HAPPEN
# ============================================================
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host " 6. SIMULATION - WHAT WOULD HAPPEN" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host ""

if ($Policy) {
    if (-not $Policy.ShouldProcess) {
        Write-Host "  RESULT: Script would EXIT early" -ForegroundColor Yellow
        Write-Host "  Reason: $($Policy.SkipReason)"
    } else {
        Write-Host "  Policy Action: $($Policy.ResolvedAction)" -ForegroundColor Cyan

        switch ($Policy.ResolvedAction) {
            "Install" {
                if ($IsInstalled) {
                    Write-Host "  -> Software already installed"
                    Write-Host "  -> Would set ActionSuccess = TRUE"
                    if ($ApiKeyReady) {
                        Write-Host "  -> Would call: Remove-LevelPolicyTag 'Install'" -ForegroundColor Green
                        Write-Host "  -> Would call: Add-LevelPolicyTag 'Has'" -ForegroundColor Green
                    } else {
                        Write-Host "  -> Tag updates SKIPPED (no API key)" -ForegroundColor Red
                    }
                } else {
                    Write-Host "  -> Would attempt to install Unchecky"
                    Write-Host "  -> If successful, would set ✅UNCHECKY tag"
                }
            }
            "Remove" {
                if (-not $IsInstalled) {
                    Write-Host "  -> Software not installed, nothing to remove"
                } else {
                    Write-Host "  -> Would attempt to uninstall Unchecky"
                    Write-Host "  -> If successful, would remove ✅UNCHECKY tag"
                }
            }
            "Pin" {
                Write-Host "  -> No changes (pinned)"
            }
            "None" {
                Write-Host "  -> No action required"
                if ($ApiKeyReady -and $IsInstalled -and -not $Policy.HasInstalled) {
                    Write-Host "  -> Would reconcile: Add ✅UNCHECKY tag (installed but no tag)" -ForegroundColor Green
                }
            }
        }
    }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " END OF DEBUG OUTPUT" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Don't actually do anything - this is just for diagnosis
exit 0
