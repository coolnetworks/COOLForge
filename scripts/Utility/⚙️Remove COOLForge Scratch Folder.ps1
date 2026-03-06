<#
.SYNOPSIS
    Removes the COOLForge MSP scratch folder from the device.

.DESCRIPTION
    Deletes the scratch folder configured in coolforge_msp_scratch_folder,
    including all cached scripts, libraries, lock files, and logs stored there.

    After running, the next COOLForge script execution will re-create the folder
    and re-download the library and any required scripts.

    Safety checks are performed to prevent accidentally deleting root drives
    or system folders.

.NOTES
    Version:          2026.03.06.01
    Target Platform:  Level.io RMM (via Script Launcher)
    Exit Codes:       0 = Success | 1 = Alert (Failure)

    Level.io Variables Used (passed from Script Launcher):
    - $MspScratchFolder  : MSP-defined scratch folder path to remove

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# Remove COOLForge Scratch Folder
# Version: 2026.03.06.01
# Target: Level.io (via Script Launcher)
# Exit 0 = Success | Exit 1 = Alert (Failure)
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge

$ErrorActionPreference = 'SilentlyContinue'

Write-Host ""
Write-Host "============================================================"
Write-Host " COOLForge Scratch Folder Removal"
Write-Host "============================================================"
Write-Host ""

# ============================================================
# VALIDATE PATH
# ============================================================
if ([string]::IsNullOrWhiteSpace($MspScratchFolder) -or $MspScratchFolder -like "{{*}}") {
    Write-Host "[X] coolforge_msp_scratch_folder is not configured - nothing to remove"
    exit 0
}

$TargetPath = $MspScratchFolder.TrimEnd('\', '/')

Write-Host "[*] Target path: $TargetPath"

# Safety: reject drive roots and short paths
$PathObj = [System.IO.DirectoryInfo]$TargetPath
if ($null -eq $PathObj.Parent) {
    Write-Host "[X] SAFETY: Refusing to delete a drive root: $TargetPath"
    exit 1
}

# Safety: reject system-critical paths
$BlockedPaths = @(
    $env:SystemRoot,
    $env:SystemDrive + '\',
    $env:ProgramFiles,
    ${env:ProgramFiles(x86)},
    $env:ProgramData,
    $env:USERPROFILE,
    $env:PUBLIC,
    $env:WINDIR
)
foreach ($blocked in $BlockedPaths) {
    if (-not [string]::IsNullOrWhiteSpace($blocked) -and
        $TargetPath -eq $blocked.TrimEnd('\', '/')) {
        Write-Host "[X] SAFETY: Refusing to delete system path: $TargetPath"
        exit 1
    }
}

# ============================================================
# CHECK IF EXISTS
# ============================================================
if (-not (Test-Path $TargetPath)) {
    Write-Host "[*] Path does not exist - nothing to remove"
    exit 0
}

# ============================================================
# REPORT WHAT WILL BE REMOVED
# ============================================================
$Items = Get-ChildItem -Path $TargetPath -Recurse -Force -ErrorAction SilentlyContinue
$FileCount = ($Items | Where-Object { -not $_.PSIsContainer }).Count
$FolderCount = ($Items | Where-Object { $_.PSIsContainer }).Count
$TotalBytes = ($Items | Where-Object { -not $_.PSIsContainer } |
    Measure-Object -Property Length -Sum).Sum

$SizeDisplay = if ($TotalBytes -ge 1GB) { "{0:N2} GB" -f ($TotalBytes / 1GB) }
               elseif ($TotalBytes -ge 1MB) { "{0:N2} MB" -f ($TotalBytes / 1MB) }
               elseif ($TotalBytes -ge 1KB) { "{0:N2} KB" -f ($TotalBytes / 1KB) }
               else { "$TotalBytes bytes" }

Write-Host "[*] Contents: $FileCount files, $FolderCount folders, $SizeDisplay"
Write-Host ""

# ============================================================
# REMOVE
# ============================================================
Write-Host "[*] Removing: $TargetPath"

try {
    Remove-Item -Path $TargetPath -Recurse -Force -ErrorAction Stop
} catch {
    # Retry once - a file may have been briefly locked
    Start-Sleep -Seconds 2
    Remove-Item -Path $TargetPath -Recurse -Force -ErrorAction SilentlyContinue
}

# ============================================================
# VERIFY
# ============================================================
if (Test-Path $TargetPath) {
    # Check if anything remains
    $Remaining = Get-ChildItem -Path $TargetPath -Recurse -Force -ErrorAction SilentlyContinue
    if ($Remaining.Count -gt 0) {
        Write-Host "[X] Removal incomplete - $($Remaining.Count) items remain"
        Write-Host "    These may be locked by running processes"
        exit 1
    }
    # Empty folder remains - remove it
    Remove-Item -Path $TargetPath -Force -ErrorAction SilentlyContinue
}

if (Test-Path $TargetPath) {
    Write-Host "[X] Failed to remove: $TargetPath"
    exit 1
}

Write-Host "[+] Removed successfully: $TargetPath"
Write-Host "[*] $FileCount files, $FolderCount folders, $SizeDisplay freed"
Write-Host ""
exit 0
