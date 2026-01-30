Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) "modules\COOLForge-Common.psm1") -Force -DisableNameChecking

# Load saved config for API key
$ConfigPath = Join-Path $PSScriptRoot ".COOLForge_Lib-setup.json"
$Config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
$ApiKey = if ($Config.CoolForge_ApiKeyEncrypted) {
    Unprotect-ApiKey -EncryptedText $Config.CoolForge_ApiKeyEncrypted
} elseif ($Config.ApiKeyEncrypted) {
    Unprotect-ApiKey -EncryptedText $Config.ApiKeyEncrypted
} else { $null }

Initialize-LevelApi -ApiKey $ApiKey | Out-Null

# Load answer file to get extra fields list
$AnswerFile = Join-Path $PSScriptRoot ".COOLForge_Answers.json"
$AnswerData = Get-Content $AnswerFile -Raw | ConvertFrom-Json

# Get Level.io fields
$Result = Get-LevelCustomFields
$FieldList = if ($Result -isnot [array] -and $Result.data) { $Result.data } else { $Result }

# Build lookup
$LevelFieldsByName = @{}
foreach ($f in $FieldList) {
    if ($f.name) {
        $LevelFieldsByName[$f.name] = $f
    }
}

Write-Host "Marking legacy fields for deletion..." -ForegroundColor Cyan
Write-Host ""

$DeprecatedValue = "DEPRECATED - DELETE THIS FIELD"
$Updated = 0

# Process extra fields from answer file
if ($AnswerData.extraFields) {
    foreach ($prop in $AnswerData.extraFields.PSObject.Properties) {
        $FieldName = $prop.Name

        $LevelField = $LevelFieldsByName[$FieldName]
        if (-not $LevelField) {
            Write-Host "  [?] $FieldName - not in Level.io (already deleted?)" -ForegroundColor DarkGray
            continue
        }

        Write-Host "  [>] $FieldName" -ForegroundColor Yellow

        # Check if admin_only and remove it
        if ($LevelField.admin_only -eq $true) {
            Write-Host "      Removing admin_only flag..." -ForegroundColor DarkGray
            $UpdateBody = @{
                admin_only = $false
            }
            $UpdateResult = Invoke-LevelApiCall -Uri "https://api.level.io/v2/custom_fields/$($LevelField.id)" -Method "PATCH" -Body $UpdateBody 2>$null
            if ($UpdateResult.Success) {
                Write-Host "      [OK] admin_only removed" -ForegroundColor Green
            }
            else {
                Write-Host "      [!] Failed to remove admin_only: $($UpdateResult.Error)" -ForegroundColor Red
            }
            Start-Sleep -Milliseconds 300
        }

        # Set value to deprecated message
        Write-Host "      Setting deprecated value..." -ForegroundColor DarkGray
        $ValueResult = Update-CustomFieldValue -FieldId $LevelField.id -Value $DeprecatedValue 2>$null
        if ($ValueResult) {
            Start-Sleep -Milliseconds 300
            $VerifyDetails = Get-LevelCustomFieldById -FieldId $LevelField.id 2>$null
            $VerifyValue = if ($VerifyDetails) { $VerifyDetails.default_value } else { $null }

            if ($VerifyValue -eq $DeprecatedValue) {
                Write-Host "      [OK] Marked as deprecated" -ForegroundColor Green
                $Updated++
            }
            else {
                Write-Host "      [!] Value not set (got: $VerifyValue)" -ForegroundColor Red
            }
        }
        else {
            Write-Host "      [X] Failed to set value" -ForegroundColor Red
        }

        Write-Host ""
    }
}

Write-Host "Summary: $Updated fields marked for deletion" -ForegroundColor Cyan
