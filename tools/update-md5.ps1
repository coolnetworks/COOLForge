# Generate MD5SUMS file
Set-Location "e:\COOLForge"
$output = @()
Get-ChildItem -Recurse -File -Include '*.ps1','*.psm1','*.md' | Where-Object { $_.FullName -notmatch '\\\.git\\' } | ForEach-Object {
    $hash = (Get-FileHash $_.FullName -Algorithm MD5).Hash.ToLower()
    $rel = $_.FullName.Replace('e:\COOLForge\', '').Replace('\', '/')
    $output += "$hash  $rel"
}
$output | Sort-Object { ($_ -split '  ')[1] } | Out-File -FilePath "e:\COOLForge\MD5SUMS" -Encoding UTF8
Write-Host "MD5SUMS updated with $($output.Count) entries"
