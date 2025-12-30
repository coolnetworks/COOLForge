<#
.SYNOPSIS
    Synchronizes all launcher files with the template.

.DESCRIPTION
    Updates all launcher files in the launchers/ folder to match the current
    template while preserving individual $ScriptToRun values.

    Can use the script inventory cache to verify all scripts have launchers.

.PARAMETER CheckCompleteness
    Use inventory cache to verify every script in scripts/ has a matching launcher.

.NOTES
    Version: 2025.12.31.01
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

$TemplateFile = Join-Path $RepoRoot "templates\Launcher_Template.ps1"
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
Write-Host "Launcher Synchronization" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Read template
$TemplateContent = Get-Content -Path $TemplateFile -Raw

# Get all launcher files
$LauncherFiles = Get-ChildItem -Path $LaunchersDir -Filter "*.ps1" -File

Write-Host "[*] Found $($LauncherFiles.Count) launcher files to update" -ForegroundColor Gray
Write-Host ""

foreach ($LauncherFile in $LauncherFiles) {
    Write-Host "Processing: $($LauncherFile.Name)" -ForegroundColor Yellow

    # Read current launcher to extract $ScriptToRun value
    $CurrentContent = Get-Content -Path $LauncherFile.FullName -Raw

    # Extract the script name from the current file
    if ($CurrentContent -match '\$ScriptToRun\s*=\s*"([^"]+)"') {
        $ScriptName = $Matches[1]
        Write-Host "  Script: $ScriptName" -ForegroundColor Gray

        # Replace the template's $ScriptToRun value with this script's name
        $NewContent = $TemplateContent -replace '\$ScriptToRun\s*=\s*"[^"]+"', "`$ScriptToRun = `"$ScriptName`""

        # Change "CHANGE THIS VALUE" to "PRE-CONFIGURED" in the comment
        $NewContent = $NewContent -replace '# SCRIPT TO RUN - CHANGE THIS VALUE', '# SCRIPT TO RUN - PRE-CONFIGURED'

        # Write updated launcher
        Set-Content -Path $LauncherFile.FullName -Value $NewContent -Force
        Write-Host "  [+] Updated successfully" -ForegroundColor Green
    }
    else {
        Write-Host "  [!] Could not extract ScriptToRun value - skipping" -ForegroundColor Yellow
    }

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
