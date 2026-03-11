$TargetPath = "{{cf_coolforge_msp_scratch_folder}}"

if ([string]::IsNullOrWhiteSpace($TargetPath) -or $TargetPath -like "{{*}}") {
    Write-Host "coolforge_msp_scratch_folder is not configured - nothing to remove"
    exit 0
}

$TargetPath = $TargetPath.TrimEnd('\', '/')

Write-Host "Target path: $TargetPath"

$PathObj = [System.IO.DirectoryInfo]$TargetPath
if ($null -eq $PathObj.Parent) {
    Write-Host "SAFETY: Refusing to delete a drive root: $TargetPath"
    exit 1
}

$BlockedPaths = @(
    $env:SystemRoot,
    ($env:SystemDrive + '\'),
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
        Write-Host "SAFETY: Refusing to delete system path: $TargetPath"
        exit 1
    }
}

if (-not (Test-Path $TargetPath)) {
    Write-Host "Path does not exist - nothing to remove"
    exit 0
}

$Items = Get-ChildItem -Path $TargetPath -Recurse -Force -ErrorAction SilentlyContinue
$FileCount = ($Items | Where-Object { -not $_.PSIsContainer }).Count
$FolderCount = ($Items | Where-Object { $_.PSIsContainer }).Count
$TotalBytes = ($Items | Where-Object { -not $_.PSIsContainer } | Measure-Object -Property Length -Sum).Sum

if ($TotalBytes -ge 1GB)     { $SizeDisplay = "{0:N2} GB" -f ($TotalBytes / 1GB) }
elseif ($TotalBytes -ge 1MB) { $SizeDisplay = "{0:N2} MB" -f ($TotalBytes / 1MB) }
elseif ($TotalBytes -ge 1KB) { $SizeDisplay = "{0:N2} KB" -f ($TotalBytes / 1KB) }
else                          { $SizeDisplay = "$TotalBytes bytes" }

Write-Host "Contents: $FileCount files, $FolderCount folders, $SizeDisplay"
Write-Host "Removing..."

try {
    Remove-Item -Path $TargetPath -Recurse -Force -ErrorAction Stop
} catch {
    Start-Sleep -Seconds 2
    Remove-Item -Path $TargetPath -Recurse -Force -ErrorAction SilentlyContinue
}

if (Test-Path $TargetPath) {
    $Remaining = Get-ChildItem -Path $TargetPath -Recurse -Force -ErrorAction SilentlyContinue
    if ($Remaining.Count -gt 0) {
        Write-Host "Alert: Removal incomplete - $($Remaining.Count) items remain (may be locked)"
        exit 1
    }
    Remove-Item -Path $TargetPath -Force -ErrorAction SilentlyContinue
}

if (Test-Path $TargetPath) {
    Write-Host "Alert: Failed to remove $TargetPath"
    exit 1
}

Write-Host "Removed successfully - $FileCount files, $FolderCount folders, $SizeDisplay freed"
exit 0
