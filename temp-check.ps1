$file = Get-ChildItem 'E:\COOLForge\scripts\Remove' -Filter '*Adobe*'
$bytes = [System.IO.File]::ReadAllBytes($file.FullName)
Write-Host "First 10 bytes:"
$bytes[0..9] | ForEach-Object { Write-Host -NoNewline ('{0:X2} ' -f $_) }
Write-Host ""
Write-Host "First 100 chars:"
$content = Get-Content $file.FullName -Raw -Encoding UTF8
Write-Host $content.Substring(0, [Math]::Min(100, $content.Length))
