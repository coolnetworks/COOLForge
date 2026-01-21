<#
COOLNETWORKS - Cleanup VoyagerPACS Studies
Purpose:
  - Removes old study files from VoyagerPACS imaging folders
  - Cleans up files older than 2 days
  - Reports total space freed
  - Searches all fixed drives for ProgramData\Voy* folders
#>

$ErrorActionPreference = 'SilentlyContinue'

# Configuration
$DaysOld = 2

Write-Host ""
Write-Host "=== VoyagerPACS Studies Cleanup ===" -ForegroundColor Cyan
Write-Host ""

# Search all fixed drives for Voyager folders
$searchPaths = @()
$drives = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3" | Select-Object -ExpandProperty DeviceID
foreach ($drive in $drives) {
    $searchPaths += "$drive\ProgramData\Voy*"
}
Write-Host "Searching drives: $($drives -join ', ')"

Write-Host "Settings:"
Write-Host "  Search paths: $($searchPaths -join ', ')"
Write-Host "  Delete older: $DaysOld days"
Write-Host ""

# Initialize counters
$totalFreedSpace = 0
$filesRemoved = 0
$foldersProcessed = 0

# Get folders starting with 'Voy' from all search paths
$voyFolders = @()
foreach ($searchPath in $searchPaths) {
    $found = Get-ChildItem -Path $searchPath -Directory -ErrorAction SilentlyContinue
    if ($found) {
        $voyFolders += $found
    }
}

if ($voyFolders.Count -eq 0) {
    Write-Host "[!] No VoyagerPACS folders found" -ForegroundColor Yellow
    Write-Host "Searched: $($searchPaths -join ', ')"
    exit 0
}

Write-Host "Found $($voyFolders.Count) VoyagerPACS folder(s):" -ForegroundColor Green
foreach ($folder in $voyFolders) {
    Write-Host "  - $($folder.FullName)"
}
Write-Host ""

$cutoffDate = (Get-Date).AddDays(-$DaysOld)
Write-Host "Removing items last modified before: $($cutoffDate.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Host ""

# Find all "Studies" folders within Voyager directories (can be nested)
$allStudiesFolders = @()
foreach ($folder in $voyFolders) {
    Write-Host "Scanning: $($folder.FullName)" -ForegroundColor Gray

    # Find all folders named "Studies" at any depth
    $studiesFolders = Get-ChildItem -Path $folder.FullName -Directory -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq "Studies" }

    if ($studiesFolders) {
        $allStudiesFolders += $studiesFolders
    }

    # Also check if Studies is directly under the Voyager folder
    $directStudies = Join-Path -Path $folder.FullName -ChildPath "Studies"
    if ((Test-Path $directStudies) -and ($allStudiesFolders.FullName -notcontains $directStudies)) {
        $allStudiesFolders += Get-Item $directStudies
    }
}

if ($allStudiesFolders.Count -eq 0) {
    Write-Host "[!] No 'Studies' folders found within VoyagerPACS directories" -ForegroundColor Yellow
    exit 0
}

Write-Host ""
Write-Host "Found $($allStudiesFolders.Count) Studies folder(s):" -ForegroundColor Green
foreach ($sf in $allStudiesFolders) {
    Write-Host "  - $($sf.FullName)"
}
Write-Host ""

foreach ($studiesFolder in $allStudiesFolders) {
    $foldersProcessed++
    Write-Host "Processing: $($studiesFolder.FullName)" -ForegroundColor Cyan

    $oldItems = Get-ChildItem -Path $studiesFolder.FullName -Recurse -ErrorAction SilentlyContinue | Where-Object {
        $_.LastWriteTime -lt $cutoffDate
    }

    $itemCount = 0
    foreach ($item in $oldItems) {
        # Safely calculate size
        $size = if ($item.PSIsContainer) {
            (Get-ChildItem -Path $item.FullName -Recurse -File -ErrorAction SilentlyContinue |
                Measure-Object -Property Length -Sum).Sum
        } else {
            $item.Length
        }

        if ($null -eq $size) { $size = 0 }

        $totalFreedSpace += $size
        $filesRemoved++
        $itemCount++

        Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction SilentlyContinue

        # Progress indicator
        if ($itemCount % 10 -eq 0) {
            Write-Host "." -NoNewline
        }
    }

    if ($itemCount -gt 0) {
        Write-Host ""
        Write-Host "  Removed $itemCount items" -ForegroundColor Green
    } else {
        Write-Host "  No old items found" -ForegroundColor Gray
    }
}

# Final summary
Write-Host ""
Write-Host "=== SUMMARY ===" -ForegroundColor Cyan
Write-Host ""

$totalFreedSpaceMB = [math]::Round($totalFreedSpace / 1MB, 2)
$totalFreedSpaceGB = [math]::Round($totalFreedSpace / 1GB, 2)

Write-Host "  Folders processed: $foldersProcessed"
Write-Host "  Items removed:     $filesRemoved"

if ($totalFreedSpaceGB -ge 1) {
    Write-Host "  Space freed:       $totalFreedSpaceGB GB" -ForegroundColor Green
} else {
    Write-Host "  Space freed:       $totalFreedSpaceMB MB" -ForegroundColor Green
}

Write-Host ""
exit 0
