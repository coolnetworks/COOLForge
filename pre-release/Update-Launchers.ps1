<#
.SYNOPSIS
    Synchronizes all launcher files with the micro-launcher template.

.DESCRIPTION
    Updates all launcher files in the launchers/ folder to match the current
    Micro-Launcher template while preserving each launcher's header block
    ($ScriptToRun and $policy_* declarations).

    The header block is everything from the start of the file up to (but not
    including) the <# comment block. The template body is everything from the
    <# comment block onward. This ensures per-launcher policy declarations
    (e.g. screenconnect's 3 custom fields) are preserved while the template
    body stays in sync.

    Can use the script inventory cache to verify all scripts have launchers.

.PARAMETER CheckCompleteness
    Use inventory cache to verify every script in scripts/ has a matching launcher.

.NOTES
    Version: 2026.02.03.01
    Copyright (c) COOLNETWORKS

.EXAMPLE
    .\pre-release\Update-Launchers.ps1
    # Updates all launchers from template

.EXAMPLE
    .\pre-release\Update-Launchers.ps1 -CheckCompleteness
    # Updates launchers and checks for missing launchers
#>

param(
    [switch]$CheckCompleteness
)

$ErrorActionPreference = "Stop"

# Get repository root
$RepoRoot = Split-Path -Parent $PSScriptRoot

$TemplateFile = Join-Path $RepoRoot "templates\Micro-Launcher.ps1"
$LaunchersDir = Join-Path $RepoRoot "launchers"

if (!(Test-Path $TemplateFile)) {
    Write-Error "Template file not found: $TemplateFile"
    exit 1
}

if (!(Test-Path $LaunchersDir)) {
    Write-Error "Launchers directory not found: $LaunchersDir"
    exit 1
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Launcher Synchronization (Micro-Launcher)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Read template content as lines
$TemplateLines = Get-Content -Path $TemplateFile

# Split template into header and body at the <# comment block
$TemplateBodyStartIndex = -1
for ($i = 0; $i -lt $TemplateLines.Count; $i++) {
    if ($TemplateLines[$i] -match '^\s*<#') {
        $TemplateBodyStartIndex = $i
        break
    }
}

if ($TemplateBodyStartIndex -lt 0) {
    Write-Error "Template has no <# comment block - cannot split header/body"
    exit 1
}

$TemplateBody = $TemplateLines[$TemplateBodyStartIndex..($TemplateLines.Count - 1)]
Write-Host "[*] Template body: $($TemplateBody.Count) lines (from line $($TemplateBodyStartIndex + 1))" -ForegroundColor Gray

# Get all launcher files (including subdirectories)
$LauncherFiles = Get-ChildItem -Path $LaunchersDir -Filter "*.ps1" -File -Recurse

Write-Host "[*] Found $($LauncherFiles.Count) launcher files to update" -ForegroundColor Gray
Write-Host ""

foreach ($LauncherFile in $LauncherFiles) {
    Write-Host "Processing: $($LauncherFile.Name)" -ForegroundColor Yellow

    # Read current launcher as lines
    $CurrentLines = Get-Content -Path $LauncherFile.FullName

    # Find the header/body split point in the current launcher
    $HeaderEndIndex = -1
    for ($i = 0; $i -lt $CurrentLines.Count; $i++) {
        if ($CurrentLines[$i] -match '^\s*<#') {
            $HeaderEndIndex = $i
            break
        }
    }

    if ($HeaderEndIndex -lt 0) {
        Write-Host "  [!] No <# comment block found - skipping" -ForegroundColor Yellow
        Write-Host ""
        continue
    }

    # Extract the header (everything before <#)
    $LauncherHeader = $CurrentLines[0..($HeaderEndIndex - 1)]

    # Verify we have a $ScriptToRun in the header
    $HasScriptToRun = $false
    foreach ($line in $LauncherHeader) {
        if ($line -match '\$ScriptToRun\s*=\s*"([^"]+)"') {
            $HasScriptToRun = $true
            $ScriptName = $Matches[1]
            break
        }
    }

    if (-not $HasScriptToRun) {
        Write-Host "  [!] No `$ScriptToRun found in header - skipping" -ForegroundColor Yellow
        Write-Host ""
        continue
    }

    Write-Host "  Script: $ScriptName" -ForegroundColor Gray

    # Count policy variables in header
    $PolicyCount = ($LauncherHeader | Where-Object { $_ -match '^\$policy_' }).Count
    if ($PolicyCount -gt 0) {
        Write-Host "  Policy vars: $PolicyCount" -ForegroundColor Gray
    }

    # Change "CHANGE THIS VALUE" to "PRE-CONFIGURED" in header if present
    $LauncherHeader = $LauncherHeader | ForEach-Object {
        $_ -replace '# SCRIPT TO RUN - CHANGE THIS VALUE', '# SCRIPT TO RUN - PRE-CONFIGURED'
    }

    # Compute the launcher's relative path from launchers/ directory
    $RelativePath = $LauncherFile.FullName.Substring($LaunchersDir.Length + 1).Replace('\', '/')

    # Update $LauncherName in the template body
    $UpdatedBody = $TemplateBody | ForEach-Object {
        $_ -replace 'LAUNCHERNAME\.ps1', $RelativePath
    }

    # Combine header + body
    $NewContent = ($LauncherHeader + $UpdatedBody) -join "`r`n"

    # Write with UTF-8 BOM (critical for emoji filenames)
    [System.IO.File]::WriteAllText($LauncherFile.FullName, $NewContent, [System.Text.UTF8Encoding]::new($true))
    Write-Host "  [+] Updated successfully" -ForegroundColor Green
    Write-Host ""
}

Write-Host "[+] All launchers updated!" -ForegroundColor Cyan
Write-Host ""

# Check completeness if requested
if ($CheckCompleteness) {
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "Launcher Completeness Check" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""

    $InventoryPath = Join-Path $RepoRoot ".cache\script-inventory.json"

    if (!(Test-Path $InventoryPath)) {
        Write-Host "[*] Inventory cache not found, generating..." -ForegroundColor Yellow
        & "$PSScriptRoot\Update-ScriptInventory.ps1"
    }

    if (Test-Path $InventoryPath) {
        $Inventory = Get-Content -Path $InventoryPath -Raw | ConvertFrom-Json

        # Get all script names from inventory
        $AllScripts = @()
        foreach ($Script in $Inventory.Categories.Scripts) {
            $AllScripts += $Script.Name
        }

        # Get all launcher names
        $AllLaunchers = @()
        foreach ($Launcher in $Inventory.Categories.Launchers) {
            $AllLaunchers += $Launcher.Name
        }

        # Find scripts without launchers
        $MissingLaunchers = @()
        foreach ($ScriptName in $AllScripts) {
            if ($ScriptName -notin $AllLaunchers) {
                $MissingLaunchers += $ScriptName
            }
        }

        # Find launchers without scripts
        $OrphanedLaunchers = @()
        foreach ($LauncherName in $AllLaunchers) {
            if ($LauncherName -notin $AllScripts) {
                $OrphanedLaunchers += $LauncherName
            }
        }

        if ($MissingLaunchers.Count -eq 0 -and $OrphanedLaunchers.Count -eq 0) {
            Write-Host "[+] All scripts have matching launchers" -ForegroundColor Green
            Write-Host "[+] Scripts: $($AllScripts.Count) | Launchers: $($AllLaunchers.Count)" -ForegroundColor Green
        }
        else {
            if ($MissingLaunchers.Count -gt 0) {
                Write-Host "[!] Scripts without launchers:" -ForegroundColor Yellow
                foreach ($Missing in $MissingLaunchers) {
                    Write-Host "  - $Missing" -ForegroundColor Yellow
                }
                Write-Host ""
            }

            if ($OrphanedLaunchers.Count -gt 0) {
                Write-Host "[!] Launchers without matching scripts:" -ForegroundColor Yellow
                foreach ($Orphan in $OrphanedLaunchers) {
                    Write-Host "  - $Orphan" -ForegroundColor Yellow
                }
                Write-Host ""
            }
        }
    }
    else {
        Write-Host "[!] Could not load inventory cache" -ForegroundColor Yellow
    }
}
