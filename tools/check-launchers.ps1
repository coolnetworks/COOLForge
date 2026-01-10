[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$scripts = Get-ChildItem "E:\COOLForge\scripts" -Recurse -Filter "*.ps1" | ForEach-Object { $_.Name }
$launchers = Get-ChildItem "E:\COOLForge\launchers" -Filter "*.ps1" | ForEach-Object { $_.Name }

$missing = $scripts | Where-Object { $_ -notin $launchers }

if ($missing) {
    Write-Host "Missing launchers:" -ForegroundColor Red
    $missing
    exit 1
} else {
    Write-Host "All $($scripts.Count) scripts have matching launchers" -ForegroundColor Green
    exit 0
}
