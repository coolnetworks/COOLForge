Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) "modules\COOLForge-Common.psm1") -Force -DisableNameChecking

$ConfigPath = Join-Path $PSScriptRoot ".COOLForge_Lib-setup.json"
$Config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
$ApiKey = if ($Config.CoolForge_ApiKeyEncrypted) {
    Unprotect-ApiKey -EncryptedText $Config.CoolForge_ApiKeyEncrypted
} elseif ($Config.ApiKeyEncrypted) {
    Unprotect-ApiKey -EncryptedText $Config.ApiKeyEncrypted
} else { $null }

Initialize-LevelApi -ApiKey $ApiKey | Out-Null

$Result = Get-LevelCustomFields
$Fields = if ($Result -isnot [array] -and $Result.data) { $Result.data } else { $Result }

Write-Host "Total fields: $($Fields.Count)" -ForegroundColor Cyan
Write-Host ""
$Fields | ForEach-Object { Write-Host $_.name }
