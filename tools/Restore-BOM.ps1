param([string[]]$Files)
foreach ($f in $Files) {
    $c = Get-Content $f -Raw
    [System.IO.File]::WriteAllText($f, $c, [System.Text.UTF8Encoding]::new($true))
    Write-Host "Restored BOM: $f"
}
