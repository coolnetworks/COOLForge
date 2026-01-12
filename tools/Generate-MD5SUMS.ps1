<#
.SYNOPSIS
    Generates MD5SUMS file for COOLForge repository.
    Automatically discovers all .ps1 and .psm1 files in modules/ and scripts/.
#>

$RepoRoot = "$PSScriptRoot\.."
Set-Location $RepoRoot

# Auto-discover files (excluding debug/unchecky and test files we do not want)
$moduleFiles = Get-ChildItem -Path "$RepoRoot\modules\*.psm1" -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notlike "*CustomFields*" }

$scriptFiles = Get-ChildItem -Path "$RepoRoot\scripts" -Recurse -Filter "*.ps1" -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notlike "*debug*" }

$allFiles = @()
$allFiles += $moduleFiles
$allFiles += $scriptFiles

$output = @()
$output += "# MD5SUMS - Checksums for COOLForge files"
$output += "# Format: MD5_HASH  FILENAME"
$output += "# Generated: $(Get-Date -Format 'yyyy-MM-dd')"
$output += "#"
$output += "# Verify with PowerShell:"
$output += '#   $expected = (Invoke-WebRequest -Uri "$BaseUrl/MD5SUMS").Content'
$output += '#   $hash = (Get-FileHash -Path $file -Algorithm MD5).Hash.ToLower()'
$output += "#"
$output += "# Note: The launcher uses this file to locate scripts in subfolders."
$output += "# Script paths are relative to repo root (e.g., scripts/Fix/ScriptName.ps1)"
$output += "#"

$count = 0
$RepoRootResolved = (Resolve-Path $RepoRoot).Path
foreach ($file in $allFiles) {
    $relativePath = $file.FullName.Replace($RepoRootResolved + "\", "").Replace("\", "/")
    $hash = (Get-FileHash -Path $file.FullName -Algorithm MD5).Hash.ToLower()
    $output += "$hash  $relativePath"
    Write-Host "  $hash  $relativePath" -ForegroundColor Gray
    $count++
}

$md5Path = Join-Path $RepoRoot "MD5SUMS"
$output -join "`n" | Out-File -FilePath $md5Path -Encoding UTF8 -NoNewline

Write-Host ""
Write-Host "Generated MD5SUMS with $count entries" -ForegroundColor Green
