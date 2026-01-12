# Check the corrupted checkmark encoding - simulating Level.io tag parsing
Write-Host "=== SIMULATING LEVEL.IO TAG PARSING ===" -ForegroundColor Cyan

# Build the raw tags from bytes (same as what Level.io sends)
# Tag 1: Corrupted checkmark + UNCHECKY
$Tag1Bytes = @(0xCE, 0x93, 0xC2, 0xA3, 0xC3, 0xA0) + [System.Text.Encoding]::UTF8.GetBytes("UNCHECKY")
$Tag1 = [System.Text.Encoding]::UTF8.GetString($Tag1Bytes)

# Tag 2: Some other corrupted tag (CE 93 C3 91 C3 AE)
$Tag2Bytes = @(0xCE, 0x93, 0xC3, 0x91, 0xC3, 0xAE)
$Tag2 = [System.Text.Encoding]::UTF8.GetString($Tag2Bytes)

# Tag 3: Standalone corrupted checkmark (CE 93 C2 A3 C3 A0)
$Tag3Bytes = @(0xCE, 0x93, 0xC2, 0xA3, 0xC3, 0xA0)
$Tag3 = [System.Text.Encoding]::UTF8.GetString($Tag3Bytes)

$RawTags = "$Tag1, $Tag2, $Tag3"
Write-Host "Raw tags string: '$RawTags'"

# Parse tags (same as module does)
$TagArray = $RawTags -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }
Write-Host "`nParsed $($TagArray.Count) tags:"
foreach ($t in $TagArray) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($t)
    Write-Host "  '$t' => bytes: $(($bytes | ForEach-Object { '{0:X2}' -f $_ }) -join ' ')"
}

# Define corrupted checkmark (same as module)
$CorruptedCheckmark = [System.Text.Encoding]::UTF8.GetString([byte[]](0xCE, 0x93, 0xC2, 0xA3, 0xC3, 0xA0))
$CorruptedBytes = [System.Text.Encoding]::UTF8.GetBytes($CorruptedCheckmark)
Write-Host "`nExpected corrupted checkmark: '$CorruptedCheckmark'"
Write-Host "Expected bytes: $(($CorruptedBytes | ForEach-Object { '{0:X2}' -f $_ }) -join ' ')"

# Check each tag
Write-Host "`n=== COMPARISON TEST ===" -ForegroundColor Yellow
$Found = $false
foreach ($Tag in $TagArray) {
    $IsMatch = $Tag -eq $CorruptedCheckmark
    Write-Host "Tag '$Tag' == CorruptedCheckmark: $IsMatch"
    if ($IsMatch) { $Found = $true }
}
Write-Host "`nGlobal Checkmark Found: $Found" -ForegroundColor $(if ($Found) { 'Green' } else { 'Red' })
