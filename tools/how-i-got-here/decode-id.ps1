$b64 = 'Z2lkOi8vbGV2ZWwvQWxsb3dlZEltcG9ydC8zNDM'
$mod = $b64.Length % 4
if ($mod -gt 0) {
    $b64 = $b64 + ('=' * (4 - $mod))
}
$decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($b64))
Write-Output "Decoded: $decoded"
