<#
.SYNOPSIS
    Validates PowerShell syntax for all scripts in the repository.

.DESCRIPTION
    Scans all .ps1 and .psm1 files in the repository and validates their syntax
    using the PowerShell parser. Reports any syntax errors found.

    This is useful for catching syntax issues before committing or releasing code.

.NOTES
    Version: 2025.12.31.01
    Copyright (c) COOLNETWORKS

.EXAMPLE
    .\pre-release\Test-Syntax.ps1
    # Validates all PowerShell files in the repository
#>

$ErrorActionPreference = "Stop"

# Get repository root
$RepoRoot = Split-Path -Parent $PSScriptRoot

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "PowerShell Syntax Validation" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$PSFiles = Get-ChildItem -Path $RepoRoot -Include "*.ps1", "*.psm1" -Recurse -File |
    Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' }

Write-Host "[*] Checking $($PSFiles.Count) PowerShell files..." -ForegroundColor Yellow
Write-Host ""

$ErrorCount = 0
$FileErrors = @()

foreach ($File in $PSFiles) {
    $RelPath = $File.FullName.Substring($RepoRoot.Length + 1)

    try {
        $Content = Get-Content -Path $File.FullName -Raw -Encoding UTF8
        $ParseErrors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseInput($Content, [ref]$null, [ref]$ParseErrors)

        if ($ParseErrors) {
            $ErrorCount++
            $FileErrors += [PSCustomObject]@{
                File = $RelPath
                Errors = $ParseErrors
            }
            Write-Host "[X] $RelPath" -ForegroundColor Red
            foreach ($ParseError in $ParseErrors) {
                Write-Host "    Line $($ParseError.Extent.StartLineNumber): $($ParseError.Message)" -ForegroundColor Red
            }
        }
    }
    catch {
        $ErrorCount++
        Write-Host "[X] $RelPath - Failed to parse: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Syntax Validation Summary" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

if ($ErrorCount -eq 0) {
    Write-Host "[+] All PowerShell files have valid syntax ($($PSFiles.Count) files)" -ForegroundColor Green
    exit 0
}
else {
    Write-Host "[X] VALIDATION FAILED - $ErrorCount file(s) with syntax errors" -ForegroundColor Red
    Write-Host ""
    Write-Host "Fix the above syntax errors before committing." -ForegroundColor Yellow
    exit 1
}
