# Fix file encoding by re-reading and re-writing with proper UTF-8
param(
    [string]$Path
)

if (-not (Test-Path $Path)) {
    Write-Host "File not found: $Path"
    exit 1
}

$tempPath = "$Path.tmp"

# Read the content
$content = Get-Content -Path $Path -Raw -Encoding UTF8

# Write to temp file with UTF-8 BOM
$content | Out-File -FilePath $tempPath -Encoding utf8 -Force

# Replace original
Remove-Item -Path $Path -Force
Move-Item -Path $tempPath -Destination $Path -Force

Write-Host "Re-encoded: $(Split-Path $Path -Leaf)"
