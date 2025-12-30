$errors = @()
Get-ChildItem -Path "E:\COOLForge" -Recurse -Filter "*.ps1" | ForEach-Object {
    $content = Get-Content $_.FullName -Encoding UTF8 -Raw
    $parseErrors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseInput($content, [ref]$null, [ref]$parseErrors)
    if ($parseErrors) {
        $errors += [PSCustomObject]@{ File = $_.Name; Errors = $parseErrors }
    }
}
if ($errors) {
    $errors | ForEach-Object {
        Write-Host "ERROR: $($_.File)" -ForegroundColor Red
        $_.Errors | ForEach-Object { Write-Host "  $($_.Message)" }
    }
    exit 1
} else {
    Write-Host "All scripts pass syntax check" -ForegroundColor Green
}
