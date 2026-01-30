<#
.SYNOPSIS
    Removes deprecated/legacy custom fields from Level.io.

.DESCRIPTION
    This script removes fields listed in the answer file's extraFields section.
    These are legacy fields that have been superseded by new field names.

    Uses efficient API calls - fetches all fields and values in 2 calls total.

.NOTES
    Version: 2026.01.21.02
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$WhatIf,

    [Parameter(Mandatory = $false)]
    [switch]$Force,

    [Parameter(Mandatory = $false)]
    [string]$AnswerFile
)

Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) "modules\COOLForge-Common.psm1") -Force -DisableNameChecking

# Load saved config for API key
$ConfigPath = Join-Path $PSScriptRoot ".COOLForge_Lib-setup.json"
if (-not (Test-Path $ConfigPath)) {
    Write-Host "[X] Config not found: $ConfigPath" -ForegroundColor Red
    exit 1
}

$Config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
$ApiKey = $null

if ($Config.CoolForge_ApiKeyEncrypted) {
    $ApiKey = Unprotect-ApiKey -EncryptedText $Config.CoolForge_ApiKeyEncrypted
}
elseif ($Config.ApiKeyEncrypted) {
    $ApiKey = Unprotect-ApiKey -EncryptedText $Config.ApiKeyEncrypted
}

if ([string]::IsNullOrWhiteSpace($ApiKey)) {
    Write-Host "[X] Could not decrypt API key" -ForegroundColor Red
    exit 1
}

Initialize-LevelApi -ApiKey $ApiKey | Out-Null

# Load answer file
if ([string]::IsNullOrWhiteSpace($AnswerFile)) {
    $AnswerFile = Join-Path $PSScriptRoot ".COOLForge_Answers.json"
}

if (-not (Test-Path $AnswerFile)) {
    Write-Host "[X] Answer file not found: $AnswerFile" -ForegroundColor Red
    Write-Host "    Run Export-AnswerFile.ps1 first." -ForegroundColor Yellow
    exit 1
}

$AnswerData = Get-Content $AnswerFile -Raw | ConvertFrom-Json

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Remove Deprecated Fields" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if ($WhatIf) {
    Write-Host "WHAT-IF MODE - No changes will be made" -ForegroundColor Yellow
    Write-Host ""
}

# Get extra fields from answer file (these are the deprecated ones)
$ExtraFieldNames = @()
if ($AnswerData.extraFields) {
    $ExtraFieldNames = $AnswerData.extraFields.PSObject.Properties.Name
}

if ($ExtraFieldNames.Count -eq 0) {
    Write-Host "No extra/deprecated fields found in answer file." -ForegroundColor Green
    exit 0
}

Write-Host "Found $($ExtraFieldNames.Count) extra field(s) in answer file" -ForegroundColor DarkGray
Write-Host ""

# Get all custom fields from Level.io (single API call)
Write-Host "Fetching custom fields from Level.io..." -ForegroundColor DarkGray
$Result = Get-LevelCustomFields
$Fields = if ($Result -isnot [array] -and $Result.data) { $Result.data } else { $Result }

# Build lookup by name
$LevelFieldsByName = @{}
foreach ($Field in $Fields) {
    if ($Field.name) {
        $LevelFieldsByName[$Field.name] = $Field
    }
}

Write-Host "Found $($Fields.Count) field(s) in Level.io" -ForegroundColor DarkGray
Write-Host ""

# Find which extra fields exist in Level.io
Write-Host "Deprecated fields to remove:" -ForegroundColor Cyan
Write-Host ""

$FieldsToDelete = @()
$NotFoundCount = 0

foreach ($FieldName in $ExtraFieldNames) {
    $LevelField = $LevelFieldsByName[$FieldName]
    if ($LevelField) {
        Write-Host "  [!] $FieldName" -ForegroundColor Yellow
        $FieldsToDelete += [PSCustomObject]@{
            Id = $LevelField.id
            Name = $FieldName
        }
    }
    else {
        Write-Host "  [ ] $FieldName (not in Level.io)" -ForegroundColor DarkGray
        $NotFoundCount++
    }
}

Write-Host ""
Write-Host "Fields to delete: $($FieldsToDelete.Count)" -ForegroundColor Cyan
Write-Host "Already removed:  $NotFoundCount" -ForegroundColor DarkGray
Write-Host ""

if ($FieldsToDelete.Count -eq 0) {
    Write-Host "No deprecated fields to remove." -ForegroundColor Green
    exit 0
}

# Confirm deletion
if (-not $WhatIf -and -not $Force) {
    Write-Host "Delete these $($FieldsToDelete.Count) field(s)? (y/N): " -NoNewline -ForegroundColor Yellow
    $Confirm = Read-Host
    if ($Confirm -ne 'y' -and $Confirm -ne 'Y') {
        Write-Host "Cancelled." -ForegroundColor DarkGray
        exit 0
    }
    Write-Host ""
}

# Delete fields
$DeletedCount = 0
$FailedCount = 0

foreach ($Field in $FieldsToDelete) {
    if ($WhatIf) {
        Write-Host "  [WHATIF] Would delete: $($Field.Name)" -ForegroundColor Cyan
        $DeletedCount++
    }
    else {
        Write-Host "  Deleting $($Field.Name)..." -NoNewline
        $DeleteResult = Remove-LevelCustomField -FieldId $Field.Id -FieldName $Field.Name
        if ($DeleteResult) {
            Write-Host " OK" -ForegroundColor Green
            $DeletedCount++
        }
        else {
            Write-Host " FAILED" -ForegroundColor Red
            $FailedCount++
        }
        Start-Sleep -Milliseconds 300
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Deleted: $DeletedCount" -ForegroundColor Green
if ($FailedCount -gt 0) {
    Write-Host "  Failed:  $FailedCount" -ForegroundColor Red
}
Write-Host ""

# Suggest updating answer file
if ($DeletedCount -gt 0 -and -not $WhatIf) {
    Write-Host "Run Export-AnswerFile.ps1 to update your answer file." -ForegroundColor Yellow
    Write-Host ""
}
