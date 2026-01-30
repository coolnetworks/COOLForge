Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) "modules\COOLForge-Common.psm1") -Force -DisableNameChecking

$ConfigPath = Join-Path $PSScriptRoot ".COOLForge_Lib-setup.json"
$Config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
$ApiKey = if ($Config.CoolForge_ApiKeyEncrypted) {
    Unprotect-ApiKey -EncryptedText $Config.CoolForge_ApiKeyEncrypted
} elseif ($Config.ApiKeyEncrypted) {
    Unprotect-ApiKey -EncryptedText $Config.ApiKeyEncrypted
} else { $null }

Initialize-LevelApi -ApiKey $ApiKey | Out-Null

# Get all fields
$Result = Get-LevelCustomFields
$Fields = if ($Result -isnot [array] -and $Result.data) { $Result.data } else { $Result }

# Get all field values in one call
$ValuesResult = Invoke-LevelApiCall -Uri "https://api.level.io/v2/custom_field_values?limit=200" -ApiKey $ApiKey -Method "GET"
$AllValues = if ($ValuesResult.Data.data) { $ValuesResult.Data.data } else { @() }

# Build value lookup (global values only - assigned_to_id is null)
$ValueByFieldId = @{}
foreach ($v in $AllValues) {
    if ([string]::IsNullOrEmpty($v.assigned_to_id)) {
        $ValueByFieldId[$v.custom_field_id] = $v.value
    }
}

Write-Host ""
Write-Host "Fields with DEPRECATED in value:" -ForegroundColor Yellow
$ToDelete = @()
foreach ($f in $Fields) {
    $val = $ValueByFieldId[$f.id]
    if ($val -match "DEPRECATED") {
        Write-Host "  $($f.name) = $val" -ForegroundColor Cyan
        $ToDelete += $f
    }
}

if ($ToDelete.Count -eq 0) {
    Write-Host "  (none found)" -ForegroundColor DarkGray
    exit 0
}

Write-Host ""
Write-Host "Deleting $($ToDelete.Count) field(s)..." -ForegroundColor Yellow
foreach ($f in $ToDelete) {
    Write-Host "  Deleting $($f.name)..." -NoNewline
    $del = Remove-LevelCustomField -FieldId $f.id -FieldName $f.name
    if ($del) { Write-Host " OK" -ForegroundColor Green }
    else { Write-Host " FAILED" -ForegroundColor Red }
    Start-Sleep -Milliseconds 300
}
Write-Host ""
Write-Host "Done!" -ForegroundColor Green
