param([string[]]$Files)
foreach ($f in $Files) {
    $c = Get-Content $f -Raw
    [System.IO.File]::WriteAllText($f, $c, (New-Object System.Text.UTF8Encoding($true)))
    Write-Host "Restored BOM: $f"
}
