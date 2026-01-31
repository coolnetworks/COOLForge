# Update MD5SUMS file for the repository
# Hashes are computed on BOM-stripped content to match the launcher's
# Get-ContentMD5 verification method (which strips BOM before hashing).
$RepoRoot = 'e:\COOLForge'
Set-Location $RepoRoot

$files = Get-ChildItem -Path $RepoRoot -Recurse -File -Include '*.ps1','*.psm1' | Where-Object { $_.FullName -notmatch '\\\.git' }

$output = @()
foreach ($f in $files) {
    try {
        $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
        # Strip UTF-8 BOM (EF BB BF) to match launcher's Get-ContentMD5
        if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
            $bytes = $bytes[3..($bytes.Length - 1)]
        }
        $md5 = [System.Security.Cryptography.MD5]::Create()
        $hash = [BitConverter]::ToString($md5.ComputeHash($bytes)).Replace("-", "").ToLower()
        $rel = $f.FullName.Substring($RepoRoot.Length + 1).Replace('\', '/')
        $output += "$hash  $rel"
    } catch {
        Write-Host "Skipped: $($f.Name) - $($_.Exception.Message)"
    }
}

$sorted = $output | Sort-Object { ($_ -split '  ')[1] }
$sorted -join "`n" | Out-File "$RepoRoot\MD5SUMS" -Encoding UTF8 -NoNewline

Write-Host "MD5SUMS updated with $($output.Count) files"
