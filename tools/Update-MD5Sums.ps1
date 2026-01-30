# Update MD5SUMS file for the repository
$RepoRoot = 'e:\COOLForge'
Set-Location $RepoRoot

$files = Get-ChildItem -Path $RepoRoot -Recurse -File -Include '*.ps1','*.psm1','*.md' | Where-Object { $_.FullName -notmatch '\\\.git' }

$output = @()
foreach ($f in $files) {
    try {
        $hash = (Get-FileHash $f.FullName -Algorithm MD5 -ErrorAction Stop).Hash.ToLower()
        $rel = $f.FullName.Substring($RepoRoot.Length + 1).Replace('\', '/')
        $output += "$hash  $rel"
    } catch {
        Write-Host "Skipped: $($f.Name) - $($_.Exception.Message)"
    }
}

$sorted = $output | Sort-Object { ($_ -split '  ')[1] }
$sorted -join "`n" | Out-File "$RepoRoot\MD5SUMS" -Encoding UTF8 -NoNewline

Write-Host "MD5SUMS updated with $($output.Count) files"
