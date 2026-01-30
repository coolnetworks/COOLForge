<#
COOLNETWORKS - Universal Disk Cleaner
Purpose:
  - Aggressively cleans temp files, caches, and junk from all user profiles
  - Cleans system-wide temp locations
  - Includes VoyagerPACS Studies cleanup
  - Runs DISM and SFC for system repair
  - Reports total space freed per category

.NOTES
    Version:          2026.01.20.01
    Recommended Timeout: 5400 seconds (90 minutes)
#>

$ErrorActionPreference = 'SilentlyContinue'

# ============================================================
# LOCKFILE CHECK - Prevent concurrent runs
# ============================================================
# Uses the COOLForge library lockfile system if available
if ($MspScratchFolder -and (Get-Command Initialize-LevelScript -ErrorAction SilentlyContinue)) {
    $Init = Initialize-LevelScript -ScriptName "Utility-UniversalDiskCleaner" `
                                   -MspScratchFolder $MspScratchFolder `
                                   -DeviceHostname $DeviceHostname `
                                   -SkipTagCheck

    if (-not $Init.Success) {
        if ($Init.Reason -eq "AlreadyRunning") {
            Write-Host "[!] Universal Disk Cleaner is already running (PID: $($Init.PID))" -ForegroundColor Yellow
            Write-Host "[!] Exiting to prevent concurrent execution."
            exit 0
        }
        Write-Host "[!] Initialization failed: $($Init.Reason)" -ForegroundColor Yellow
    }
}

# Run as admin check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] WARNING: Not running as Administrator - some cleanup may fail" -ForegroundColor Yellow
    Write-Host ""
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "     UNIVERSAL DISK CLEANER" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Track totals
$script:totalFreed = 0
$script:totalFiles = 0

function Get-FolderSize {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return 0 }
    $size = (Get-ChildItem -Path $Path -Recurse -File -Force -ErrorAction SilentlyContinue |
        Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
    if ($null -eq $size) { return 0 }
    return $size
}

function Format-Size {
    param([long]$Bytes)
    if ($Bytes -ge 1GB) { return "{0:N2} GB" -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return "{0:N2} MB" -f ($Bytes / 1MB) }
    if ($Bytes -ge 1KB) { return "{0:N2} KB" -f ($Bytes / 1KB) }
    return "$Bytes bytes"
}

function Clear-FolderContents {
    param(
        [string]$Path,
        [string]$Label,
        [switch]$FilesOnly
    )

    if (-not (Test-Path $Path)) { return }

    $sizeBefore = Get-FolderSize -Path $Path
    if ($sizeBefore -eq 0) { return }

    $items = Get-ChildItem -Path $Path -Force -ErrorAction SilentlyContinue
    $count = 0

    foreach ($item in $items) {
        try {
            if ($FilesOnly -and $item.PSIsContainer) { continue }
            Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction Stop
            $count++
        } catch {
            # Skip locked files
        }
    }

    $sizeAfter = Get-FolderSize -Path $Path
    $freed = $sizeBefore - $sizeAfter

    if ($freed -gt 0) {
        $script:totalFreed += $freed
        $script:totalFiles += $count
        Write-Host "    $Label : $(Format-Size $freed) ($count items)" -ForegroundColor Green
    }
}

# ============================================
# PER-USER CLEANUP
# ============================================
Write-Host "--- Per-User Cleanup ---" -ForegroundColor Yellow
Write-Host ""

# Get all user profile folders
$userProfiles = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') }

foreach ($userProfile in $userProfiles) {
    $userName = $userProfile.Name
    $userPath = $userProfile.FullName

    Write-Host "  User: $userName" -ForegroundColor Cyan

    # Local Temp
    Clear-FolderContents -Path "$userPath\AppData\Local\Temp" -Label "Temp folder"

    # Thumbnail Cache
    Clear-FolderContents -Path "$userPath\AppData\Local\Microsoft\Windows\Explorer" -Label "Thumbnail cache" -FilesOnly

    # Windows Error Reporting
    Clear-FolderContents -Path "$userPath\AppData\Local\Microsoft\Windows\WER" -Label "Error Reports"

    # Temporary Internet Files (legacy)
    Clear-FolderContents -Path "$userPath\AppData\Local\Microsoft\Windows\INetCache" -Label "INet Cache"

    # Windows Temp (roaming)
    Clear-FolderContents -Path "$userPath\AppData\Local\Microsoft\Windows\Temporary Internet Files" -Label "Temp Internet Files"

    # Font Cache
    Clear-FolderContents -Path "$userPath\AppData\Local\Microsoft\FontCache" -Label "Font Cache"

    # Recent Items (shortcuts only, safe to clear)
    Clear-FolderContents -Path "$userPath\AppData\Roaming\Microsoft\Windows\Recent" -Label "Recent Items"

    # Windows Defender Scans (old scan results)
    Clear-FolderContents -Path "$userPath\AppData\Local\Microsoft\Windows Defender\Scans\History" -Label "Defender Scan History"

    # Crash Dumps
    Clear-FolderContents -Path "$userPath\AppData\Local\CrashDumps" -Label "Crash Dumps"

    # Downloads folder (files >90 days old)
    $downloadsPath = "$userPath\Downloads"
    if (Test-Path $downloadsPath) {
        $cutoff = (Get-Date).AddDays(-90)
        $oldDownloads = Get-ChildItem -Path $downloadsPath -File -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $cutoff }

        $dlFreed = 0
        $dlCount = 0
        foreach ($file in $oldDownloads) {
            $size = $file.Length
            try {
                Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                $dlFreed += $size
                $dlCount++
            } catch { }
        }

        if ($dlFreed -gt 0) {
            $script:totalFreed += $dlFreed
            $script:totalFiles += $dlCount
            Write-Host "    Downloads (>90 days): $(Format-Size $dlFreed) ($dlCount files)" -ForegroundColor Green
        }
    }

    Write-Host ""
}

# ============================================
# SYSTEM-WIDE CLEANUP
# ============================================
Write-Host "--- System-Wide Cleanup ---" -ForegroundColor Yellow
Write-Host ""

# Windows Temp
Clear-FolderContents -Path "C:\Windows\Temp" -Label "Windows Temp"

# Prefetch (speeds up app launches but can be rebuilt)
Clear-FolderContents -Path "C:\Windows\Prefetch" -Label "Prefetch"

# Windows Update Download Cache (stop service first for better cleanup)
$wuStopped = $false
try {
    $wuService = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
    if ($wuService -and $wuService.Status -eq 'Running') {
        Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        $wuStopped = $true
    }
} catch { }

Clear-FolderContents -Path "C:\Windows\SoftwareDistribution\Download" -Label "Windows Update Cache"

if ($wuStopped) {
    try { Start-Service -Name wuauserv -ErrorAction SilentlyContinue } catch { }
}

# Delivery Optimization
Clear-FolderContents -Path "C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache" -Label "Delivery Optimization"

# Service Account Temp folders
Clear-FolderContents -Path "C:\Windows\ServiceProfiles\LocalService\AppData\Local\Temp" -Label "LocalService Temp"
Clear-FolderContents -Path "C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp" -Label "NetworkService Temp"

# System-wide Windows Error Reporting
Clear-FolderContents -Path "C:\ProgramData\Microsoft\Windows\WER" -Label "System WER Reports"

# Windows Installer Patch Cache (orphaned patches)
Clear-FolderContents -Path "C:\Windows\Installer\$PatchCache$" -Label "Installer Patch Cache"

# System Error Memory Dumps
if (Test-Path "C:\Windows\MEMORY.DMP") {
    $dumpSize = (Get-Item "C:\Windows\MEMORY.DMP" -ErrorAction SilentlyContinue).Length
    if ($dumpSize) {
        Remove-Item "C:\Windows\MEMORY.DMP" -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path "C:\Windows\MEMORY.DMP")) {
            $script:totalFreed += $dumpSize
            $script:totalFiles++
            Write-Host "    Memory Dump: $(Format-Size $dumpSize)" -ForegroundColor Green
        }
    }
}

# Minidumps
Clear-FolderContents -Path "C:\Windows\Minidump" -Label "Minidumps"

# System Logs (older than needed)
Clear-FolderContents -Path "C:\Windows\Logs\CBS" -Label "CBS Logs"

Write-Host ""

# ============================================
# HIGH-VALUE CLEANUP (potentially large folders)
# ============================================
Write-Host "--- High-Value Cleanup ---" -ForegroundColor Yellow
Write-Host ""

# Office Installation Cache (can be several GB)
Clear-FolderContents -Path "C:\MSOCache" -Label "Office Cache (MSOCache)"

# Windows Upgrade Temp folders (can be 10+ GB after upgrades)
Clear-FolderContents -Path 'C:\$Windows.~BT' -Label "Windows Upgrade Temp (~BT)"
Clear-FolderContents -Path 'C:\$Windows.~WS' -Label "Windows Upgrade Temp (~WS)"

# Previous Windows Installation (can be 20+ GB)
# Only delete if older than 10 days (rollback window has expired)
if (Test-Path "C:\Windows.old") {
    $windowsOldItem = Get-Item "C:\Windows.old" -ErrorAction SilentlyContinue
    $windowsOldAge = ((Get-Date) - $windowsOldItem.CreationTime).Days

    if ($windowsOldAge -gt 10) {
        $oldWinSize = Get-FolderSize -Path "C:\Windows.old"
        if ($oldWinSize -gt 0) {
            Write-Host "  Found Windows.old ($windowsOldAge days old, $(Format-Size $oldWinSize))" -ForegroundColor Cyan
            # Use DISM to properly remove Windows.old (handles permissions)
            & DISM /Online /Cleanup-Image /StartComponentCleanup /ResetBase 2>&1 | Out-Null
            # Also try direct removal
            Remove-Item -Path "C:\Windows.old" -Recurse -Force -ErrorAction SilentlyContinue
            $newSize = Get-FolderSize -Path "C:\Windows.old"
            $freed = $oldWinSize - $newSize
            if ($freed -gt 0) {
                $script:totalFreed += $freed
                Write-Host "    Windows.old: $(Format-Size $freed)" -ForegroundColor Green
            }
        }
    } else {
        $oldWinSize = Get-FolderSize -Path "C:\Windows.old"
        Write-Host "    Windows.old: Skipped ($windowsOldAge days old, rollback still available)" -ForegroundColor Gray
    }
}

# Driver installer leftovers
Clear-FolderContents -Path "C:\Intel" -Label "Intel Driver Temp"
Clear-FolderContents -Path "C:\AMD" -Label "AMD Driver Temp"
Clear-FolderContents -Path "C:\NVIDIA" -Label "NVIDIA Driver Temp"

Write-Host ""

# ============================================
# VOYAGERPACS CLEANUP (from original script)
# ============================================
Write-Host "--- VoyagerPACS Studies Cleanup ---" -ForegroundColor Yellow
Write-Host ""

$voyagerDaysOld = 2

# Search all fixed drives for Voyager folders
$drives = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3" | Select-Object -ExpandProperty DeviceID
$voyFolders = @()

foreach ($drive in $drives) {
    $found = Get-ChildItem -Path "$drive\ProgramData\Voy*" -Directory -ErrorAction SilentlyContinue
    if ($found) { $voyFolders += $found }
}

if ($voyFolders.Count -gt 0) {
    Write-Host "  Found $($voyFolders.Count) VoyagerPACS installation(s)" -ForegroundColor Cyan

    $cutoffDate = (Get-Date).AddDays(-$voyagerDaysOld)

    # Find all Studies folders
    $allStudiesFolders = @()
    foreach ($folder in $voyFolders) {
        $studiesFolders = Get-ChildItem -Path $folder.FullName -Directory -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq "Studies" }
        if ($studiesFolders) { $allStudiesFolders += $studiesFolders }

        $directStudies = Join-Path -Path $folder.FullName -ChildPath "Studies"
        if ((Test-Path $directStudies) -and ($allStudiesFolders.FullName -notcontains $directStudies)) {
            $allStudiesFolders += Get-Item $directStudies
        }
    }

    $voyagerFreed = 0
    $voyagerFiles = 0

    foreach ($studiesFolder in $allStudiesFolders) {
        $oldItems = Get-ChildItem -Path $studiesFolder.FullName -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $cutoffDate }

        foreach ($item in $oldItems) {
            $size = if ($item.PSIsContainer) {
                (Get-ChildItem -Path $item.FullName -Recurse -File -ErrorAction SilentlyContinue |
                    Measure-Object -Property Length -Sum).Sum
            } else {
                $item.Length
            }
            if ($null -eq $size) { $size = 0 }

            Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction SilentlyContinue
            if (-not (Test-Path $item.FullName)) {
                $voyagerFreed += $size
                $voyagerFiles++
            }
        }
    }

    if ($voyagerFreed -gt 0) {
        $script:totalFreed += $voyagerFreed
        $script:totalFiles += $voyagerFiles
        Write-Host "    VoyagerPACS Studies (>$voyagerDaysOld days): $(Format-Size $voyagerFreed) ($voyagerFiles items)" -ForegroundColor Green
    } else {
        Write-Host "    No old VoyagerPACS studies found" -ForegroundColor Gray
    }
} else {
    Write-Host "  No VoyagerPACS installations found" -ForegroundColor Gray
}

Write-Host ""

# ============================================
# RECYCLE BIN CLEANUP
# ============================================
Write-Host "--- Recycle Bin ---" -ForegroundColor Yellow
Write-Host ""

try {
    # Get recycle bin size before
    $shell = New-Object -ComObject Shell.Application
    $recycleBin = $shell.Namespace(0xA)
    $recycleBinItems = $recycleBin.Items()
    $recycleSize = 0
    $recycleCount = $recycleBinItems.Count

    foreach ($item in $recycleBinItems) {
        $recycleSize += $item.Size
    }

    if ($recycleCount -gt 0) {
        # Clear recycle bin silently
        Clear-RecycleBin -Force -ErrorAction SilentlyContinue
        $script:totalFreed += $recycleSize
        $script:totalFiles += $recycleCount
        Write-Host "    Recycle Bin: $(Format-Size $recycleSize) ($recycleCount items)" -ForegroundColor Green
    } else {
        Write-Host "    Recycle Bin: Empty" -ForegroundColor Gray
    }
} catch {
    Write-Host "    Recycle Bin: Could not access" -ForegroundColor Gray
}

Write-Host ""

# ============================================
# DISM COMPONENT CLEANUP
# ============================================
Write-Host "--- DISM Component Store Cleanup ---" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Running DISM cleanup (this may take several minutes)..." -ForegroundColor Gray

# Get WinSxS size before
$winsxsPath = "C:\Windows\WinSxS"
$sizeBefore = 0
if (Test-Path $winsxsPath) {
    $sizeBefore = (Get-ChildItem -Path $winsxsPath -Recurse -File -Force -ErrorAction SilentlyContinue |
        Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
    if ($null -eq $sizeBefore) { $sizeBefore = 0 }
}

# Run DISM cleanup
& DISM /Online /Cleanup-Image /StartComponentCleanup /Quiet 2>&1 | Out-Null

# Get WinSxS size after
$sizeAfter = 0
if (Test-Path $winsxsPath) {
    $sizeAfter = (Get-ChildItem -Path $winsxsPath -Recurse -File -Force -ErrorAction SilentlyContinue |
        Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
    if ($null -eq $sizeAfter) { $sizeAfter = 0 }
}

$dismFreed = $sizeBefore - $sizeAfter
if ($dismFreed -gt 0) {
    $script:totalFreed += $dismFreed
    Write-Host "    Component Store: $(Format-Size $dismFreed)" -ForegroundColor Green
} else {
    Write-Host "    Component Store: No cleanup needed" -ForegroundColor Gray
}

Write-Host ""

# ============================================
# SYSTEM REPAIR (DISM + SFC)
# ============================================
Write-Host "--- System Repair ---" -ForegroundColor Yellow
Write-Host ""

# DISM RestoreHealth - repairs the component store (source for SFC)
Write-Host "  Running DISM RestoreHealth (this may take 10-20 minutes)..." -ForegroundColor Gray
& DISM /Online /Cleanup-Image /RestoreHealth 2>&1 | Out-Null
$dismRepairExit = $LASTEXITCODE

if ($dismRepairExit -eq 0) {
    Write-Host "    DISM RestoreHealth: Completed successfully" -ForegroundColor Green
} elseif ($dismRepairExit -eq 87) {
    Write-Host "    DISM RestoreHealth: No corruption detected" -ForegroundColor Gray
} else {
    Write-Host "    DISM RestoreHealth: Completed with code $dismRepairExit" -ForegroundColor Yellow
}

# SFC /scannow - repairs system files using component store
Write-Host ""
Write-Host "  Running SFC /scannow (this may take 10-30 minutes)..." -ForegroundColor Gray
$sfcResult = & sfc /scannow 2>&1
$sfcExit = $LASTEXITCODE

# Parse SFC output for status
$sfcOutput = $sfcResult -join "`n"
if ($sfcOutput -match "did not find any integrity violations") {
    Write-Host "    SFC: No integrity violations found" -ForegroundColor Green
} elseif ($sfcOutput -match "successfully repaired") {
    Write-Host "    SFC: Found and repaired corrupted files" -ForegroundColor Green
} elseif ($sfcOutput -match "found corrupt files but was unable to fix") {
    Write-Host "    SFC: Found corrupt files but could not repair (check CBS.log)" -ForegroundColor Yellow
} else {
    Write-Host "    SFC: Completed with exit code $sfcExit" -ForegroundColor Gray
}

Write-Host ""

# ============================================
# FINAL SUMMARY
# ============================================
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "            SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Total items removed: $($script:totalFiles)" -ForegroundColor White
Write-Host "  Total space freed:   $(Format-Size $script:totalFreed)" -ForegroundColor Green
Write-Host ""

# Clean up lockfile
if (Get-Command Remove-LevelLockFile -ErrorAction SilentlyContinue) {
    Remove-LevelLockFile
}

exit 0
