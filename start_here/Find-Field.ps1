param([string]$FieldName = "huntress_organization_key")

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

$Found = $Fields | Where-Object { $_.name -eq $FieldName }
if ($Found) {
    Write-Host "Found: $($Found.name) (ID: $($Found.id))" -ForegroundColor Yellow

    # Get value
    $Details = Get-LevelCustomFieldById -FieldId $Found.id
    Write-Host "Value: $($Details.default_value)" -ForegroundColor Cyan

    Write-Host ""
    Write-Host "Delete this field? (y/N): " -NoNewline
    $confirm = Read-Host
    if ($confirm -eq 'y') {
        $del = Remove-LevelCustomField -FieldId $Found.id -FieldName $Found.name
        if ($del) { Write-Host "Deleted!" -ForegroundColor Green }
        else { Write-Host "Failed!" -ForegroundColor Red }
    }
} else {
    Write-Host "Field '$FieldName' not found" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "Available fields:" -ForegroundColor Cyan
    $Fields | ForEach-Object { Write-Host "  $($_.name)" }
}
