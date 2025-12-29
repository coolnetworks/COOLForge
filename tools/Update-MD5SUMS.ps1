<#
.SYNOPSIS
    Regenerates the MD5SUMS file for COOLForge_Lib.

.DESCRIPTION
    This script scans all downloadable files (library and scripts) and generates
    MD5 checksums for each. The output is written to the MD5SUMS file in the
    repository root.

    Run this script whenever you update any of the following:
    - modules/COOLForge-Common.psm1
    - Any script in the scripts/ folder

.NOTES
    Version: 2025.12.27.01
    Copyright (c) COOLNETWORKS

.EXAMPLE
    .\tools\Update-MD5SUMS.ps1
#>

$ErrorActionPreference = "Stop"

# Get repository root (parent of tools folder)
$RepoRoot = Split-Path -Parent $PSScriptRoot

Write-Host "[*] Generating MD5SUMS for COOLForge_Lib" -ForegroundColor Cyan
Write-Host "[*] Repository: $RepoRoot" -ForegroundColor Gray

# Files to checksum (relative to repo root)
$FilesToHash = @(
    "modules/COOLForge-Common.psm1"
)

# Add all scripts from scripts folder
$ScriptsFolder = Join-Path $RepoRoot "scripts"
if (Test-Path $ScriptsFolder) {
    Get-ChildItem -Path $ScriptsFolder -Filter "*.ps1" | ForEach-Object {
        $FilesToHash += "scripts/$($_.Name)"
    }
}

# Generate checksums
$Checksums = @()
$Checksums += "# MD5SUMS - Checksums for COOLForge_Lib files"
$Checksums += "# Format: MD5_HASH  FILENAME"
$Checksums += "# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$Checksums += "#"
$Checksums += "# Verify with PowerShell:"
$Checksums += "#   `$expected = (Invoke-WebRequest -Uri `"`$BaseUrl/MD5SUMS`").Content"
$Checksums += "#   `$hash = (Get-FileHash -Path `$file -Algorithm MD5).Hash.ToLower()"
$Checksums += "#"

foreach ($RelativePath in $FilesToHash) {
    $FullPath = Join-Path $RepoRoot $RelativePath
    if (Test-Path $FullPath) {
        $Hash = (Get-FileHash -Path $FullPath -Algorithm MD5).Hash.ToLower()
        $Checksums += "$Hash  $RelativePath"
        Write-Host "[+] $RelativePath : $Hash" -ForegroundColor Green
    }
    else {
        Write-Host "[!] File not found: $RelativePath" -ForegroundColor Yellow
    }
}

# Write MD5SUMS file
$MD5SumsPath = Join-Path $RepoRoot "MD5SUMS"
$Checksums | Out-File -FilePath $MD5SumsPath -Encoding UTF8
Write-Host ""
Write-Host "[+] MD5SUMS file updated: $MD5SumsPath" -ForegroundColor Cyan
Write-Host "[*] Don't forget to commit and push the changes!" -ForegroundColor Yellow
