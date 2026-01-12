$scriptPath = Get-ChildItem "E:\COOLForge\scripts\Check\*unchecky.ps1" | Select-Object -First 1
$content = Get-Content $scriptPath.FullName -Raw
$bytes = [System.Text.Encoding]::UTF8.GetBytes($content)
$md5 = [System.Security.Cryptography.MD5]::Create()
$hash = $md5.ComputeHash($bytes)
$computed = ([BitConverter]::ToString($hash) -replace '-', '').ToLower()

$fileHash = (Get-FileHash $scriptPath.FullName -Algorithm MD5).Hash.ToLower()

$rawBytes = [System.IO.File]::ReadAllBytes($scriptPath.FullName)
Write-Host "File path: $($scriptPath.FullName)"
Write-Host "First 3 bytes: $($rawBytes[0].ToString('X2')) $($rawBytes[1].ToString('X2')) $($rawBytes[2].ToString('X2'))"
Write-Host "Get-FileHash:     $fileHash"
Write-Host "Content MD5:      $computed"
Write-Host "Match: $($fileHash -eq $computed)"
