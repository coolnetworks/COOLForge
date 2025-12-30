<#
.SYNOPSIS
    Generates a comprehensive inventory of all scripts in the repository.

.DESCRIPTION
    Scans the repository for all PowerShell scripts and generates a JSON inventory file
    that can be used by other pre-release tools to ensure nothing is missed.

    The inventory includes:
    - All scripts in scripts/ folder (recursive, all categories)
    - All launcher files in launchers/ folder
    - All modules in modules/ folder
    - All templates in templates/ folder
    - All pre-release tools in pre-release/ folder

    Output is written to: .cache/script-inventory.json

.NOTES
    Version: 2025.12.31.01
    Copyright (c) COOLNETWORKS

.EXAMPLE
    .\pre-release\Update-ScriptInventory.ps1
    # Generates script inventory cache file
#>

$ErrorActionPreference = "Stop"

# Get repository root
$RepoRoot = Split-Path -Parent $PSScriptRoot

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Script Inventory Generator" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Create .cache folder if it doesn't exist
$CacheFolder = Join-Path $RepoRoot ".cache"
if (!(Test-Path $CacheFolder)) {
    New-Item -Path $CacheFolder -ItemType Directory -Force | Out-Null
    Write-Host "[*] Created cache folder: .cache/" -ForegroundColor Gray
}

# Initialize inventory
$Inventory = @{
    Generated = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    RepositoryRoot = $RepoRoot
    Categories = @{}
    Summary = @{
        TotalFiles = 0
        ByCategory = @{}
    }
}

# Function to add files to inventory
function Add-FilesToInventory {
    param(
        [string]$Category,
        [string]$FolderPath,
        [string]$Pattern = "*.ps1",
        [switch]$Recursive
    )

    if (!(Test-Path $FolderPath)) {
        Write-Host "[!] Folder not found: $FolderPath" -ForegroundColor Yellow
        return
    }

    $Files = Get-ChildItem -Path $FolderPath -Filter $Pattern -File -Recurse:$Recursive |
        Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' }

    $FileList = @()
    foreach ($File in $Files) {
        $RelativePath = $File.FullName.Substring($RepoRoot.Length + 1) -replace '\\', '/'

        $FileInfo = @{
            Path = $RelativePath
            Name = $File.Name
            SizeBytes = $File.Length
            LastModified = $File.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
        }

        # Add category info for scripts
        if ($Category -eq "Scripts" -and $RelativePath -match '^scripts/([^/]+)/') {
            $FileInfo.Subcategory = $Matches[1]
        }

        $FileList += $FileInfo
        Write-Host "  [+] $RelativePath" -ForegroundColor Green
    }

    $Inventory.Categories[$Category] = $FileList
    $Inventory.Summary.ByCategory[$Category] = $FileList.Count
    $Inventory.Summary.TotalFiles += $FileList.Count

    Write-Host "[*] $Category`: $($FileList.Count) file(s)" -ForegroundColor Cyan
    Write-Host ""
}

# Scan all categories
Write-Host "[1/6] Scanning scripts..." -ForegroundColor Yellow
Add-FilesToInventory -Category "Scripts" -FolderPath (Join-Path $RepoRoot "scripts") -Pattern "*.ps1" -Recursive

Write-Host "[2/6] Scanning launchers..." -ForegroundColor Yellow
Add-FilesToInventory -Category "Launchers" -FolderPath (Join-Path $RepoRoot "launchers") -Pattern "*.ps1"

Write-Host "[3/6] Scanning modules..." -ForegroundColor Yellow
Add-FilesToInventory -Category "Modules" -FolderPath (Join-Path $RepoRoot "modules") -Pattern "*.psm1"

Write-Host "[4/6] Scanning templates..." -ForegroundColor Yellow
Add-FilesToInventory -Category "Templates" -FolderPath (Join-Path $RepoRoot "templates") -Pattern "*.ps1"

Write-Host "[5/6] Scanning pre-release tools..." -ForegroundColor Yellow
Add-FilesToInventory -Category "PreRelease" -FolderPath (Join-Path $RepoRoot "pre-release") -Pattern "*.ps1"

Write-Host "[6/6] Scanning tools..." -ForegroundColor Yellow
Add-FilesToInventory -Category "Tools" -FolderPath (Join-Path $RepoRoot "tools") -Pattern "*.ps1"

# Add scripts by subcategory breakdown
Write-Host "[*] Analyzing script categories..." -ForegroundColor Yellow
$ScriptsByCategory = @{}
foreach ($Script in $Inventory.Categories.Scripts) {
    if ($Script.Subcategory) {
        if (!$ScriptsByCategory.ContainsKey($Script.Subcategory)) {
            $ScriptsByCategory[$Script.Subcategory] = @()
        }
        $ScriptsByCategory[$Script.Subcategory] += $Script
    }
}

$Inventory.ScriptsBySubcategory = $ScriptsByCategory
Write-Host ""

# Write inventory to JSON file
$InventoryPath = Join-Path $CacheFolder "script-inventory.json"
$Inventory | ConvertTo-Json -Depth 10 | Out-File -FilePath $InventoryPath -Encoding UTF8

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Inventory Summary" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Total files tracked: $($Inventory.Summary.TotalFiles)" -ForegroundColor Green
Write-Host ""
Write-Host "Breakdown by category:" -ForegroundColor Gray
foreach ($Category in $Inventory.Summary.ByCategory.Keys | Sort-Object) {
    $Count = $Inventory.Summary.ByCategory[$Category]
    Write-Host "  $Category`: $Count" -ForegroundColor Gray
}

if ($ScriptsByCategory.Count -gt 0) {
    Write-Host ""
    Write-Host "Scripts by subcategory:" -ForegroundColor Gray
    foreach ($Subcat in $ScriptsByCategory.Keys | Sort-Object) {
        $Count = $ScriptsByCategory[$Subcat].Count
        Write-Host "  scripts/$Subcat`: $Count" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "[+] Inventory saved to: .cache/script-inventory.json" -ForegroundColor Cyan
Write-Host ""
