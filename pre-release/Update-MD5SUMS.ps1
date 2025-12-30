<#
.SYNOPSIS
    Regenerates the MD5SUMS file for COOLForge_Lib.

.DESCRIPTION
    This script scans all downloadable files (library, scripts, templates) and generates
    MD5 checksums for each. The output is written to the MD5SUMS file in the
    repository root.

    Uses the script inventory cache (.cache/script-inventory.json) if available,
    otherwise falls back to direct file scanning.

    Run this script whenever you update any of the following:
    - modules/COOLForge-Common.psm1
    - Any script in the scripts/ folder (recursive)
    - templates/What is this folder.md

.PARAMETER UseCache
    Use the script inventory cache if available. Runs Update-ScriptInventory.ps1 first if cache is missing.

.NOTES
    Version: 2025.12.31.01
    Copyright (c) COOLNETWORKS

.EXAMPLE
    .\pre-release\Update-MD5SUMS.ps1
    # Generates MD5SUMS using direct file scanning

.EXAMPLE
    .\pre-release\Update-MD5SUMS.ps1 -UseCache
    # Generates MD5SUMS using inventory cache (updates inventory first)
#>

param(
    [switch]$UseCache
)

$ErrorActionPreference = "Stop"

# Get repository root
$RepoRoot = Split-Path -Parent $PSScriptRoot

Write-Host "[*] Generating MD5SUMS for COOLForge_Lib" -ForegroundColor Cyan
Write-Host "[*] Repository: $RepoRoot" -ForegroundColor Gray

# Files to checksum (relative to repo root)
$FilesToHash = @()

if ($UseCache) {
    # Check if inventory cache exists
    $InventoryPath = Join-Path $RepoRoot ".cache\script-inventory.json"

    if (!(Test-Path $InventoryPath)) {
        Write-Host "[*] Inventory cache not found, generating..." -ForegroundColor Yellow
        & "$PSScriptRoot\Update-ScriptInventory.ps1"
    }

    if (Test-Path $InventoryPath) {
        Write-Host "[*] Using inventory cache" -ForegroundColor Gray
        $Inventory = Get-Content -Path $InventoryPath -Raw | ConvertFrom-Json

        # Add library module (only COOLForge-Common.psm1 - the one downloaded by launchers)
        $CommonModule = $Inventory.Categories.Modules | Where-Object { $_.Name -eq "COOLForge-Common.psm1" }
        if ($CommonModule) {
            $FilesToHash += $CommonModule.Path
        }

        # Add templates
        $TemplateReadme = $Inventory.Categories.Templates | Where-Object { $_.Name -eq "What is this folder.md" }
        if ($TemplateReadme) {
            $FilesToHash += $TemplateReadme.Path -replace '\\', '/'
        }

        # Add all scripts
        foreach ($Script in $Inventory.Categories.Scripts) {
            $FilesToHash += $Script.Path
        }

        Write-Host "[*] Loaded $($FilesToHash.Count) files from inventory cache" -ForegroundColor Gray
    }
    else {
        Write-Host "[!] Failed to generate inventory, falling back to direct scan" -ForegroundColor Yellow
        $UseCache = $false
    }
}

if (!$UseCache) {
    # Direct file scanning (original method)
    Write-Host "[*] Using direct file scan" -ForegroundColor Gray

    # Add library module
    $FilesToHash += "modules/COOLForge-Common.psm1"

    # Add templates
    $FilesToHash += "templates/What is this folder.md"

    # Add all scripts from scripts folder (recursive - includes category subfolders)
    $ScriptsFolder = Join-Path $RepoRoot "scripts"
    if (Test-Path $ScriptsFolder) {
        Get-ChildItem -Path $ScriptsFolder -Filter "*.ps1" -Recurse -File | ForEach-Object {
            $RelativePath = $_.FullName.Substring($RepoRoot.Length + 1) -replace '\\', '/'
            $FilesToHash += $RelativePath
        }
    }
}

# Sort files for consistent output
$FilesToHash = $FilesToHash | Sort-Object

# Generate checksums
$Checksums = @()
$Checksums += "# MD5SUMS - Checksums for COOLForge_Lib files"
$Checksums += "# Format: MD5_HASH  FILENAME"
$Checksums += "# Generated: $(Get-Date -Format 'yyyy-MM-dd')"
$Checksums += "#"
$Checksums += "# Verify with PowerShell:"
$Checksums += "#   `$expected = (Invoke-WebRequest -Uri `"`$BaseUrl/MD5SUMS`").Content"
$Checksums += "#   `$hash = (Get-FileHash -Path `$file -Algorithm MD5).Hash.ToLower()"
$Checksums += "#"
$Checksums += "# Note: The launcher uses this file to locate scripts in subfolders."
$Checksums += "# Script paths are relative to repo root (e.g., scripts/Fix/ScriptName.ps1)"
$Checksums += "#"

$MissingCount = 0
foreach ($RelativePath in $FilesToHash) {
    $FullPath = Join-Path $RepoRoot $RelativePath
    if (Test-Path $FullPath) {
        $Hash = (Get-FileHash -Path $FullPath -Algorithm MD5).Hash.ToLower()
        $Checksums += "$Hash  $RelativePath"
        Write-Host "[+] $RelativePath" -ForegroundColor Green
    }
    else {
        Write-Host "[!] File not found: $RelativePath" -ForegroundColor Yellow
        $MissingCount++
    }
}

# Write MD5SUMS file
$MD5SumsPath = Join-Path $RepoRoot "MD5SUMS"
$Checksums -join "`n" | Out-File -FilePath $MD5SumsPath -Encoding UTF8 -NoNewline
Write-Host ""
Write-Host "[+] MD5SUMS file updated: $MD5SumsPath" -ForegroundColor Cyan
Write-Host "[+] Total files: $($FilesToHash.Count)" -ForegroundColor Cyan

if ($MissingCount -gt 0) {
    Write-Host "[!] Warning: $MissingCount file(s) not found" -ForegroundColor Yellow
}
