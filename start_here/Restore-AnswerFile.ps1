<#
.SYNOPSIS
    Restores Level.io custom field values from an answer file backup.

.DESCRIPTION
    This script reads an answer file backup and restores field values to Level.io.

    CORE FIELDS (apikey, coolforge_*):
    - If field exists: Compare values, prompt if different
    - If field doesn't exist: Create it with backup value

    POLICY FIELDS (policy_*):
    - If field exists with empty value: Update from backup (no prompt)
    - If field exists with non-empty value that differs: Prompt before overwriting
    - If field doesn't exist: Skip (policy script will create it later)

    DEPRECATED FIELDS:
    - Fields in Level.io not in definitions: Prompt to delete
    - Legacy field names (superseded): Prompt to delete

    Safe to run multiple times - idempotent operation.

.PARAMETER AnswerFile
    Path to the answer file backup. Defaults to .COOLForge_Answers.json

.PARAMETER WhatIf
    Preview changes without making them.

.PARAMETER Force
    Skip prompts, always use backup values for conflicts.

.NOTES
    Version: 2026.01.21.03
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$AnswerFile,

    [Parameter(Mandatory = $false)]
    [switch]$WhatIf,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) "modules\COOLForge-Common.psm1") -Force -DisableNameChecking

# Load saved config for API key
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

# Load answer file
if ([string]::IsNullOrWhiteSpace($AnswerFile)) {
    $AnswerFile = Join-Path $PSScriptRoot ".COOLForge_Answers.json"
}

if (-not (Test-Path $AnswerFile)) {
    Write-Host "[X] Answer file not found: $AnswerFile" -ForegroundColor Red
    exit 1
}

$AnswerData = Get-Content $AnswerFile -Raw | ConvertFrom-Json

# Load definitions to know which fields are core
$DefsPath = Join-Path (Split-Path $PSScriptRoot -Parent) "definitions\custom-fields.json"
if (-not (Test-Path $DefsPath)) {
    Write-Host "[X] Definitions not found: $DefsPath" -ForegroundColor Red
    exit 1
}
$Defs = Get-Content $DefsPath -Raw | ConvertFrom-Json

# Build list of core field names and their definitions
$CoreFieldNames = @()
$CoreFieldDefs = @{}
foreach ($groupName in @('core', 'level_api', 'debugging')) {
    foreach ($f in $Defs.fields.$groupName) {
        $CoreFieldNames += $f.name
        $CoreFieldDefs[$f.name] = $f
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Restore from Answer File" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if ($WhatIf) {
    Write-Host "WHAT-IF MODE - No changes will be made" -ForegroundColor Yellow
    Write-Host ""
}

Write-Host "Answer file: $AnswerFile" -ForegroundColor DarkGray
Write-Host "Exported at: $($AnswerData.exportedAt)" -ForegroundColor DarkGray
Write-Host ""

# Get current Level.io fields
Write-Host "Fetching current fields from Level.io..." -ForegroundColor DarkGray
$Result = Get-LevelCustomFields
$LevelFields = if ($Result -isnot [array] -and $Result.data) { $Result.data } else { $Result }

# Get current values
$ValuesResult = Invoke-LevelApiCall -Uri "https://api.level.io/v2/custom_field_values?limit=200" -ApiKey $ApiKey -Method "GET"
$AllValues = if ($ValuesResult.Data.data) { $ValuesResult.Data.data } else { @() }

# Build lookups
$LevelFieldsByName = @{}
$FieldIdToName = @{}
$CurrentValues = @{}

foreach ($f in $LevelFields) {
    $LevelFieldsByName[$f.name] = $f
    $FieldIdToName[$f.id] = $f.name
}

foreach ($v in $AllValues) {
    if ([string]::IsNullOrEmpty($v.assigned_to_id)) {
        $fieldName = $FieldIdToName[$v.custom_field_id]
        if ($fieldName) {
            $CurrentValues[$fieldName] = $v.value
        }
    }
}

Write-Host "Found $($LevelFields.Count) field(s) in Level.io" -ForegroundColor DarkGray
Write-Host ""

# Counters
$CreatedCount = 0
$UpdatedCount = 0
$SkippedCount = 0
$ConflictCount = 0

# Process fields from answer file
if (-not $AnswerData.fields) {
    Write-Host "[X] No fields in answer file" -ForegroundColor Red
    exit 1
}

$BackupFields = $AnswerData.fields.PSObject.Properties

Write-Host "Processing $($BackupFields.Count) field(s) from backup..." -ForegroundColor Cyan
Write-Host ""

# ============================================================
# CORE FIELDS
# ============================================================
Write-Host "Core fields:" -ForegroundColor Cyan

foreach ($prop in $BackupFields) {
    $fieldName = $prop.Name
    $backupValue = $prop.Value

    # Only process core fields in this section
    if ($CoreFieldNames -notcontains $fieldName) {
        continue
    }

    # Skip if backup value is null/empty
    if ([string]::IsNullOrWhiteSpace($backupValue)) {
        continue
    }

    $existsInLevel = $LevelFieldsByName.ContainsKey($fieldName)
    $currentValue = $CurrentValues[$fieldName]

    if ($existsInLevel) {
        # Compare values
        if ($currentValue -eq $backupValue) {
            Write-Host "  [=] $fieldName - values match, skipping" -ForegroundColor DarkGray
            $SkippedCount++
        }
        else {
            # Values differ - prompt (core fields always prompt)
            Write-Host ""
            Write-Host "  [!] CONFLICT: $fieldName" -ForegroundColor Yellow
            Write-Host "      Level.io: $currentValue" -ForegroundColor Cyan
            Write-Host "      Backup:   $backupValue" -ForegroundColor Green

            $useBackup = $false
            if ($Force) {
                $useBackup = $true
                Write-Host "      -> Using backup (Force mode)" -ForegroundColor Yellow
            }
            elseif (-not $WhatIf) {
                Write-Host "      Use backup value? (y/N): " -NoNewline -ForegroundColor Yellow
                $confirm = Read-Host
                $useBackup = ($confirm -eq 'y' -or $confirm -eq 'Y')
            }
            else {
                Write-Host "      -> Would prompt (WhatIf)" -ForegroundColor Cyan
            }

            if ($useBackup -and -not $WhatIf) {
                $fieldId = $LevelFieldsByName[$fieldName].id
                $setResult = Set-LevelCustomFieldDefaultValue -ApiKey $ApiKey -FieldId $fieldId -Value $backupValue
                if ($setResult) {
                    Write-Host "      -> Updated" -ForegroundColor Green
                    $UpdatedCount++
                }
                else {
                    Write-Host "      -> FAILED" -ForegroundColor Red
                }
            }
            elseif ($WhatIf -and $Force) {
                Write-Host "      -> Would update (WhatIf+Force)" -ForegroundColor Cyan
                $UpdatedCount++
            }
            elseif (-not $useBackup) {
                Write-Host "      -> Kept Level.io value" -ForegroundColor DarkGray
                $SkippedCount++
            }
            $ConflictCount++
            Write-Host ""
        }
    }
    else {
        # Core field doesn't exist - create it
        Write-Host "  [+] Creating $fieldName = $backupValue" -ForegroundColor Green

        if (-not $WhatIf) {
            # Get adminOnly from definitions
            $adminOnly = $false
            if ($CoreFieldDefs[$fieldName]) {
                $adminOnly = [bool]$CoreFieldDefs[$fieldName].adminOnly
            }

            $newField = New-LevelCustomField -Name $fieldName -DefaultValue $backupValue -AdminOnly $adminOnly
            if ($newField) {
                # Set org-level value
                if ($newField.id) {
                    $null = Set-LevelCustomFieldDefaultValue -ApiKey $ApiKey -FieldId $newField.id -Value $backupValue
                }
                $CreatedCount++
            }
            else {
                Write-Host "      FAILED to create" -ForegroundColor Red
            }
            Start-Sleep -Milliseconds 300
        }
        else {
            Write-Host "      -> Would create (WhatIf)" -ForegroundColor Cyan
            $CreatedCount++
        }
    }
}

Write-Host ""

# ============================================================
# POLICY FIELDS
# ============================================================
Write-Host "Policy fields:" -ForegroundColor Cyan

foreach ($prop in $BackupFields) {
    $fieldName = $prop.Name
    $backupValue = $prop.Value

    # Skip core fields (already handled)
    if ($CoreFieldNames -contains $fieldName) {
        continue
    }

    # Skip if backup value is null/empty
    if ([string]::IsNullOrWhiteSpace($backupValue)) {
        continue
    }

    $existsInLevel = $LevelFieldsByName.ContainsKey($fieldName)
    $currentValue = $CurrentValues[$fieldName]

    if ($existsInLevel) {
        if ($currentValue -eq $backupValue) {
            Write-Host "  [=] $fieldName - values match, skipping" -ForegroundColor DarkGray
            $SkippedCount++
        }
        elseif ([string]::IsNullOrWhiteSpace($currentValue)) {
            # Current value is empty - safe to update without asking
            if (-not $WhatIf) {
                $fieldId = $LevelFieldsByName[$fieldName].id
                $setResult = Set-LevelCustomFieldDefaultValue -ApiKey $ApiKey -FieldId $fieldId -Value $backupValue
                if ($setResult) {
                    Write-Host "  [>] $fieldName - was empty, setting to: $backupValue" -ForegroundColor Cyan
                    $UpdatedCount++
                }
                else {
                    Write-Host "  [X] $fieldName - FAILED" -ForegroundColor Red
                }
            }
            else {
                Write-Host "  [>] $fieldName - was empty, would set to: $backupValue (WhatIf)" -ForegroundColor Cyan
                $UpdatedCount++
            }
        }
        else {
            # Current value is non-empty and differs - prompt before overwriting
            Write-Host ""
            Write-Host "  [!] CONFLICT: $fieldName" -ForegroundColor Yellow
            Write-Host "      Level.io: $currentValue" -ForegroundColor Cyan
            Write-Host "      Backup:   $backupValue" -ForegroundColor Green

            $useBackup = $false
            if ($Force) {
                $useBackup = $true
                Write-Host "      -> Using backup (Force mode)" -ForegroundColor Yellow
            }
            elseif (-not $WhatIf) {
                Write-Host "      Use backup value? (y/N): " -NoNewline -ForegroundColor Yellow
                $confirm = Read-Host
                $useBackup = ($confirm -eq 'y' -or $confirm -eq 'Y')
            }
            else {
                Write-Host "      -> Would prompt (WhatIf)" -ForegroundColor Cyan
            }

            if ($useBackup -and -not $WhatIf) {
                $fieldId = $LevelFieldsByName[$fieldName].id
                $setResult = Set-LevelCustomFieldDefaultValue -ApiKey $ApiKey -FieldId $fieldId -Value $backupValue
                if ($setResult) {
                    Write-Host "      -> Updated" -ForegroundColor Green
                    $UpdatedCount++
                }
                else {
                    Write-Host "      -> FAILED" -ForegroundColor Red
                }
            }
            elseif ($WhatIf -and $Force) {
                Write-Host "      -> Would update (WhatIf+Force)" -ForegroundColor Cyan
                $UpdatedCount++
            }
            elseif (-not $useBackup) {
                Write-Host "      -> Kept Level.io value" -ForegroundColor DarkGray
                $SkippedCount++
            }
            $ConflictCount++
            Write-Host ""
        }
    }
    else {
        # Policy field doesn't exist - skip (policy script will create it)
        Write-Host "  [ ] $fieldName (not in Level.io yet)" -ForegroundColor DarkGray
        $SkippedCount++
    }
}

Write-Host ""

# ============================================================
# DEPRECATED FIELDS
# ============================================================
Write-Host "Deprecated fields:" -ForegroundColor Cyan

# Build list of ALL valid field names from definitions
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

# Known non-COOLForge fields to ignore
$IgnoreFields = @("Managed", "ssid", "ssid_password", "users_admins", "users_admins_pass",
                  "users", "users_pass", "standards_bypass", "Cipp TenantID", "quiet hours", "AgreedRebootTIme")

$DeprecatedCount = 0
$DeletedCount = 0
$DeprecatedFields = @()

foreach ($f in $LevelFields) {
    $name = $f.name

    # Skip if it's a valid current field name
    if ($ValidFieldNames -contains $name) {
        continue
    }

    # Skip if it's a known non-COOLForge field
    if ($IgnoreFields -contains $name) {
        continue
    }

    # This field is either a legacy name or unknown - mark as deprecated
    if ($LegacyFieldNames -contains $name) {
        Write-Host "  [!] $name (legacy - superseded)" -ForegroundColor Yellow
    }
    else {
        Write-Host "  [?] $name (not in definitions)" -ForegroundColor DarkYellow
    }
    $DeprecatedFields += $f
    $DeprecatedCount++
}

if ($DeprecatedCount -eq 0) {
    Write-Host "  No deprecated fields found." -ForegroundColor DarkGray
}
elseif (-not $WhatIf) {
    Write-Host ""
    $deleteConfirmed = $false
    if ($Force) {
        $deleteConfirmed = $true
        Write-Host "  Deleting $DeprecatedCount deprecated field(s) (Force mode)..." -ForegroundColor Yellow
    }
    else {
        Write-Host "  Delete $DeprecatedCount deprecated field(s)? (y/N): " -NoNewline -ForegroundColor Yellow
        $confirm = Read-Host
        $deleteConfirmed = ($confirm -eq 'y' -or $confirm -eq 'Y')
    }

    if ($deleteConfirmed) {
        foreach ($f in $DeprecatedFields) {
            Write-Host "    Deleting $($f.name)..." -NoNewline
            $del = Remove-LevelCustomField -FieldId $f.id -FieldName $f.name
            if ($del) {
                Write-Host " OK" -ForegroundColor Green
                $DeletedCount++
            }
            else {
                Write-Host " FAILED" -ForegroundColor Red
            }
            Start-Sleep -Milliseconds 300
        }
    }
    else {
        Write-Host "  Skipped deletion." -ForegroundColor DarkGray
    }
}
else {
    Write-Host ""
    Write-Host "  Would delete $DeprecatedCount field(s) (WhatIf)" -ForegroundColor Cyan
    $DeletedCount = $DeprecatedCount
}

# Summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Created:    $CreatedCount" -ForegroundColor Green
Write-Host "  Updated:    $UpdatedCount" -ForegroundColor Cyan
Write-Host "  Skipped:    $SkippedCount" -ForegroundColor DarkGray
if ($DeletedCount -gt 0) {
    Write-Host "  Deleted:    $DeletedCount" -ForegroundColor Yellow
}
if ($ConflictCount -gt 0) {
    Write-Host "  Conflicts:  $ConflictCount" -ForegroundColor Yellow
}
Write-Host ""

if ($WhatIf) {
    Write-Host "WHAT-IF: No changes were made." -ForegroundColor Yellow
    Write-Host ""
}
