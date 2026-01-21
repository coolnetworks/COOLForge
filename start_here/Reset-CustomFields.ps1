<#
.SYNOPSIS
    Resets all custom fields in Level.io based on definitions.

.DESCRIPTION
    This script deletes all existing custom fields and recreates them from
    definitions/custom-fields.json. Current values are preserved where possible.

    Core fields (core, level_api, debugging groups) are always created.
    Other groups are only recreated if they were previously configured.

.PARAMETER WhatIf
    Preview changes without making them.

.PARAMETER Force
    Skip confirmation prompt.

.NOTES
    Version: 2026.01.21.01
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$WhatIf,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) "modules\COOLForge-Common.psm1") -Force -DisableNameChecking

# Load saved config for API key (pattern from Remove-DeprecatedFields.ps1)
$ConfigPath = Join-Path $PSScriptRoot ".COOLForge_Lib-setup.json"
if (-not (Test-Path $ConfigPath)) {
    Write-Host "[X] Config not found: $ConfigPath" -ForegroundColor Red
    exit 1
}

$Config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
$ApiKey = if ($Config.CoolForge_ApiKeyEncrypted) {
    Unprotect-ApiKey -EncryptedText $Config.CoolForge_ApiKeyEncrypted
} elseif ($Config.ApiKeyEncrypted) {
    Unprotect-ApiKey -EncryptedText $Config.ApiKeyEncrypted
} else { $null }

if ([string]::IsNullOrWhiteSpace($ApiKey)) {
    Write-Host "[X] Could not decrypt API key" -ForegroundColor Red
    exit 1
}

Initialize-LevelApi -ApiKey $ApiKey | Out-Null

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Reset Custom Fields" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if ($WhatIf) {
    Write-Host "WHAT-IF MODE - No changes will be made" -ForegroundColor Yellow
    Write-Host ""
}

# Step 1: Get all existing fields
Write-Host "Fetching current fields from Level.io..." -ForegroundColor DarkGray
$Result = Get-LevelCustomFields
$ExistingFields = if ($Result -isnot [array] -and $Result.data) { $Result.data } else { $Result }
Write-Host "  Found $($ExistingFields.Count) existing field(s)" -ForegroundColor DarkGray

# Step 2: Get all field values (pattern from Remove-DeprecatedByValue.ps1)
Write-Host "Fetching field values..." -ForegroundColor DarkGray
$ValuesResult = Invoke-LevelApiCall -Uri "https://api.level.io/v2/custom_field_values?limit=200" -ApiKey $ApiKey -Method "GET"
$AllValues = if ($ValuesResult.Data.data) { $ValuesResult.Data.data } else { @() }

# Build lookups
$FieldIdToName = @{}
$FieldNameToId = @{}
$PreservedValues = @{}

foreach ($f in $ExistingFields) {
    $FieldIdToName[$f.id] = $f.name
    $FieldNameToId[$f.name] = $f.id
}

foreach ($v in $AllValues) {
    if ([string]::IsNullOrEmpty($v.assigned_to_id)) {
        $fieldName = $FieldIdToName[$v.custom_field_id]
        if ($fieldName) {
            $PreservedValues[$fieldName] = $v.value
        }
    }
}

Write-Host "  Preserved $($PreservedValues.Count) value(s)" -ForegroundColor DarkGray
Write-Host ""

# Step 3: Load definitions
$DefsPath = Join-Path (Split-Path $PSScriptRoot -Parent) "definitions\custom-fields.json"
if (-not (Test-Path $DefsPath)) {
    Write-Host "[X] Definitions not found: $DefsPath" -ForegroundColor Red
    exit 1
}
$Defs = Get-Content $DefsPath -Raw | ConvertFrom-Json

# Build list of existing field names for group detection
$ExistingFieldNames = $ExistingFields | ForEach-Object { $_.name }

# Determine which groups were in use
$CoreGroups = @('core', 'level_api', 'debugging')
$OtherGroups = $Defs.fields.PSObject.Properties.Name | Where-Object { $_ -notin $CoreGroups }

$GroupsToCreate = @{}
$GroupsToSkip = @()

# Core groups always created
foreach ($group in $CoreGroups) {
    $GroupsToCreate[$group] = $true
}

# Other groups only if ANY field from that group existed
foreach ($group in $OtherGroups) {
    $groupFields = $Defs.fields.$group
    $hadAny = $false
    foreach ($field in $groupFields) {
        if ($ExistingFieldNames -contains $field.name) {
            $hadAny = $true
            break
        }
        # Also check legacy names
        if ($field.legacyNames) {
            foreach ($legacy in $field.legacyNames) {
                if ($ExistingFieldNames -contains $legacy) {
                    $hadAny = $true
                    break
                }
            }
        }
        if ($hadAny) { break }
    }

    if ($hadAny) {
        $GroupsToCreate[$group] = $true
    } else {
        $GroupsToSkip += $group
    }
}

# Show what will happen
Write-Host "Groups to create:" -ForegroundColor Cyan
foreach ($group in $GroupsToCreate.Keys | Sort-Object) {
    $fieldCount = ($Defs.fields.$group | Measure-Object).Count
    Write-Host "  [+] $group ($fieldCount fields)" -ForegroundColor Green
}

if ($GroupsToSkip.Count -gt 0) {
    Write-Host ""
    Write-Host "Groups to skip (not previously configured):" -ForegroundColor DarkGray
    foreach ($group in $GroupsToSkip | Sort-Object) {
        Write-Host "  [ ] $group" -ForegroundColor DarkGray
    }
}

Write-Host ""

# Identify deprecated fields (for visibility)
$ValidFieldNames = @()
$LegacyFieldNames = @()
foreach ($group in $Defs.fields.PSObject.Properties.Name) {
    foreach ($f in $Defs.fields.$group) {
        $ValidFieldNames += $f.name
        if ($f.legacyNames) {
            $LegacyFieldNames += $f.legacyNames
        }
    }
}

# Known non-COOLForge fields to ignore in deprecated list
$IgnoreFields = @("Managed", "ssid", "ssid_password", "users_admins", "users_admins_pass",
                  "users", "users_pass", "standards_bypass", "Cipp TenantID", "quiet hours", "AgreedRebootTIme")

$DeprecatedFields = @()
foreach ($f in $ExistingFields) {
    if ($ValidFieldNames -contains $f.name) { continue }
    if ($IgnoreFields -contains $f.name) { continue }
    $DeprecatedFields += $f
}

if ($DeprecatedFields.Count -gt 0) {
    Write-Host "Deprecated fields to remove:" -ForegroundColor Yellow
    foreach ($f in $DeprecatedFields) {
        if ($LegacyFieldNames -contains $f.name) {
            Write-Host "  [!] $($f.name) (legacy - superseded)" -ForegroundColor Yellow
        }
        else {
            Write-Host "  [?] $($f.name) (not in definitions)" -ForegroundColor DarkYellow
        }
    }
    Write-Host ""
}

Write-Host "Fields to delete: $($ExistingFields.Count)" -ForegroundColor Yellow
$totalToCreate = 0
foreach ($group in $GroupsToCreate.Keys) {
    $totalToCreate += ($Defs.fields.$group | Measure-Object).Count
}
Write-Host "Fields to create: $totalToCreate" -ForegroundColor Green
if ($DeprecatedFields.Count -gt 0) {
    Write-Host "Deprecated removed: $($DeprecatedFields.Count)" -ForegroundColor Yellow
}
Write-Host ""

# Confirm
if (-not $WhatIf -and -not $Force) {
    Write-Host "This will DELETE ALL existing fields and recreate them." -ForegroundColor Yellow
    Write-Host "Continue? (y/N): " -NoNewline -ForegroundColor Yellow
    $Confirm = Read-Host
    if ($Confirm -ne 'y' -and $Confirm -ne 'Y') {
        Write-Host "Cancelled." -ForegroundColor DarkGray
        exit 0
    }
    Write-Host ""
}

if ($WhatIf) {
    Write-Host "WHAT-IF: Would delete $($ExistingFields.Count) fields and create $totalToCreate fields" -ForegroundColor Cyan
    Write-Host ""
    exit 0
}

# Step 4: Delete all existing fields
Write-Host "Deleting existing fields..." -ForegroundColor Yellow
$DeletedCount = 0
foreach ($f in $ExistingFields) {
    Write-Host "  Deleting $($f.name)..." -NoNewline
    $del = Remove-LevelCustomField -FieldId $f.id
    if ($del) {
        Write-Host " OK" -ForegroundColor Green
        $DeletedCount++
    } else {
        Write-Host " FAILED" -ForegroundColor Red
    }
    Start-Sleep -Milliseconds 300
}
Write-Host ""

# Step 5: Create fields from definitions
Write-Host "Creating fields..." -ForegroundColor Cyan
$CreatedCount = 0
$FailedCount = 0

foreach ($group in $GroupsToCreate.Keys | Sort-Object) {
    Write-Host ""
    Write-Host "  [$group]" -ForegroundColor Cyan

    foreach ($field in $Defs.fields.$group) {
        $fieldName = $field.name
        $adminOnly = if ($field.adminOnly) { $true } else { $false }

        # Determine value: preserved > default > empty
        $value = ""
        if ($PreservedValues.ContainsKey($fieldName)) {
            $value = $PreservedValues[$fieldName]
        } elseif ($field.default) {
            $value = $field.default
        }

        Write-Host "    Creating $fieldName..." -NoNewline
        $newField = New-LevelCustomField -Name $fieldName -DefaultValue $value -AdminOnly $adminOnly

        if ($newField) {
            # Set org-level default value if we have one
            if (-not [string]::IsNullOrWhiteSpace($value) -and $newField.id) {
                $null = Set-LevelCustomFieldDefaultValue -ApiKey $ApiKey -FieldId $newField.id -Value $value
            }
            Write-Host " OK" -ForegroundColor Green
            $CreatedCount++
        } else {
            Write-Host " FAILED" -ForegroundColor Red
            $FailedCount++
        }
        Start-Sleep -Milliseconds 300
    }
}

# Summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Deleted: $DeletedCount" -ForegroundColor Yellow
Write-Host "  Created: $CreatedCount" -ForegroundColor Green
if ($FailedCount -gt 0) {
    Write-Host "  Failed:  $FailedCount" -ForegroundColor Red
}
Write-Host ""

if ($GroupsToSkip.Count -gt 0) {
    Write-Host "Skipped groups (not previously configured):" -ForegroundColor DarkGray
    foreach ($group in $GroupsToSkip | Sort-Object) {
        Write-Host "  $group" -ForegroundColor DarkGray
    }
    Write-Host ""
}

Write-Host "Run Export-AnswerFile.ps1 to update your answer file." -ForegroundColor Yellow
Write-Host ""
