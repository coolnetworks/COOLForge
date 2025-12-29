<#
.SYNOPSIS
    Removes deprecated legacy custom fields after migration to CoolForge_* naming.

.DESCRIPTION
    This script permanently deletes the old custom field names that have been
    replaced by the new CoolForge_* prefixed fields.

    IMPORTANT: Only run this AFTER you have:
    1. Run Setup-COOLForgeCustomFields.ps1 to create the new fields
    2. Verified all your scripts are updated to use the new field names
    3. Confirmed all endpoints are working correctly with the new fields

    This script requires THREE confirmations before proceeding, as the
    deletion is PERMANENT and cannot be undone.

    LEGACY FIELDS TO BE REMOVED:
    - msp_scratch_folder          (replaced by CoolForge_msp_scratch_folder)
    - ps_module_library_source    (replaced by CoolForge_ps_module_library_source)
    - pin_psmodule_to_version     (replaced by CoolForge_pin_psmodule_to_version)
    - screenconnect_instance_id   (replaced by CoolForge_screenconnect_instance_id)
    - is_screenconnect_server     (replaced by CoolForge_is_screenconnect_server)

.NOTES
    Version:          2025.12.29.01
    Target Platform:  Windows PowerShell 5.1+

    Copyright (c) COOLNETWORKS
    https://coolnetworks.au
    https://github.com/coolnetworks/COOLForge

.EXAMPLE
    .\Remove-LegacyCustomFields.ps1

    Runs the deprecation wizard with triple confirmation.
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$ApiKey
)

$ErrorActionPreference = "Stop"

# Import shared functions
$ModulePath = Join-Path $PSScriptRoot "..\modules\COOLForge-CustomFields.psm1"
if (Test-Path $ModulePath) {
    Import-Module $ModulePath -Force
}
else {
    Write-Host "[X] Could not find COOLForge-CustomFields.psm1" -ForegroundColor Red
    Write-Host "    Expected at: $ModulePath" -ForegroundColor Red
    exit 1
}

# Configuration
$Script:ConfigFileName = ".COOLForgeLib-setup.json"
$Script:ConfigPath = Join-Path $PSScriptRoot $Script:ConfigFileName

# Legacy fields to remove
$Script:LegacyFields = @(
    "msp_scratch_folder",
    "ps_module_library_source",
    "pin_psmodule_to_version",
    "screenconnect_instance_id",
    "is_screenconnect_server"
)

# ============================================================
# MAIN
# ============================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Red
Write-Host " LEGACY CUSTOM FIELD REMOVAL" -ForegroundColor Red
Write-Host "============================================================" -ForegroundColor Red
Write-Host ""
Write-Host "This script will PERMANENTLY DELETE the following legacy fields:" -ForegroundColor Yellow
Write-Host ""
foreach ($Field in $Script:LegacyFields) {
    Write-Host "  - $Field" -ForegroundColor Yellow
}
Write-Host ""
Write-Host "These have been replaced by CoolForge_* prefixed fields." -ForegroundColor DarkGray
Write-Host ""

# Load saved configuration
$Script:SavedConfig = Get-SavedConfig -Path $Script:ConfigPath
$Script:ResolvedApiKey = $null

# Get API Key
if (-not [string]::IsNullOrWhiteSpace($ApiKey)) {
    $Script:ResolvedApiKey = $ApiKey
}
elseif ($Script:SavedConfig -and $Script:SavedConfig.CoolForge_ApiKeyEncrypted) {
    $DecryptedKey = Unprotect-ApiKey -EncryptedText $Script:SavedConfig.CoolForge_ApiKeyEncrypted
    if ($DecryptedKey) {
        Write-LevelInfo "Using saved API key."
        $Script:ResolvedApiKey = $DecryptedKey
    }
}
elseif ($Script:SavedConfig -and $Script:SavedConfig.ApiKeyEncrypted) {
    $DecryptedKey = Unprotect-ApiKey -EncryptedText $Script:SavedConfig.ApiKeyEncrypted
    if ($DecryptedKey) {
        Write-LevelInfo "Using saved API key."
        $Script:ResolvedApiKey = $DecryptedKey
    }
}

if ([string]::IsNullOrWhiteSpace($Script:ResolvedApiKey)) {
    Write-Host "Enter your Level.io API key: " -NoNewline -ForegroundColor Yellow
    $SecureKey = Read-Host -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureKey)
    $Script:ResolvedApiKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
}

# Set the API key for the module
$Script:LevelApiKey = $Script:ResolvedApiKey

# Fetch existing fields
$ExistingFields = Get-ExistingCustomFields
if ($null -eq $ExistingFields) {
    Write-Host "[X] Failed to connect to Level.io API" -ForegroundColor Red
    exit 1
}

Write-LevelSuccess "Connected to Level.io API"
Write-Host ""

# Find which legacy fields exist
$FieldsToDelete = @()
foreach ($LegacyName in $Script:LegacyFields) {
    $Found = Find-CustomField -Name $LegacyName -ExistingFields $ExistingFields
    if ($Found) {
        $FieldsToDelete += @{
            Name = $LegacyName
            Id   = $Found.id
        }
    }
}

if ($FieldsToDelete.Count -eq 0) {
    Write-Host ""
    Write-LevelSuccess "No legacy fields found - nothing to remove!"
    Write-Host ""
    exit 0
}

Write-Host "Found $($FieldsToDelete.Count) legacy field(s) to remove:" -ForegroundColor Yellow
Write-Host ""
foreach ($Field in $FieldsToDelete) {
    Write-Host "  - $($Field.Name) (ID: $($Field.Id))" -ForegroundColor Yellow
}
Write-Host ""

# Verify new fields exist before removing old ones
Write-Host "Checking that replacement fields exist..." -ForegroundColor Cyan
$MissingNewFields = @()
foreach ($Field in $FieldsToDelete) {
    $NewName = "CoolForge_$($Field.Name)"
    $NewField = Find-CustomField -Name $NewName -ExistingFields $ExistingFields
    if (-not $NewField) {
        $MissingNewFields += $NewName
    }
}

if ($MissingNewFields.Count -gt 0) {
    Write-Host ""
    Write-Host "[X] CANNOT PROCEED - The following replacement fields are missing:" -ForegroundColor Red
    foreach ($Missing in $MissingNewFields) {
        Write-Host "    - $Missing" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "Please run Setup-COOLForgeCustomFields.ps1 first to create the new fields." -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

Write-LevelSuccess "All replacement fields exist"
Write-Host ""

# ============================================================
# TRIPLE CONFIRMATION
# ============================================================

Write-Host "============================================================" -ForegroundColor Red
Write-Host " WARNING: THIS ACTION IS PERMANENT AND CANNOT BE UNDONE" -ForegroundColor Red
Write-Host "============================================================" -ForegroundColor Red
Write-Host ""
Write-Host "You are about to permanently delete $($FieldsToDelete.Count) custom field(s)." -ForegroundColor Yellow
Write-Host "Any values stored in these fields will be LOST." -ForegroundColor Yellow
Write-Host ""

# Confirmation 1
Write-Host "CONFIRMATION 1 of 3" -ForegroundColor Magenta
Write-Host "Type 'DELETE' to confirm you want to remove legacy fields: " -NoNewline -ForegroundColor Yellow
$Confirm1 = Read-Host
if ($Confirm1 -ne "DELETE") {
    Write-Host ""
    Write-Host "Aborted - you typed '$Confirm1' instead of 'DELETE'" -ForegroundColor Green
    exit 0
}

Write-Host ""

# Confirmation 2
Write-Host "CONFIRMATION 2 of 3" -ForegroundColor Magenta
Write-Host "Type 'I UNDERSTAND' to confirm this cannot be undone: " -NoNewline -ForegroundColor Yellow
$Confirm2 = Read-Host
if ($Confirm2 -ne "I UNDERSTAND") {
    Write-Host ""
    Write-Host "Aborted - you typed '$Confirm2' instead of 'I UNDERSTAND'" -ForegroundColor Green
    exit 0
}

Write-Host ""

# Confirmation 3
Write-Host "CONFIRMATION 3 of 3" -ForegroundColor Magenta
Write-Host "Type the number of fields to delete ($($FieldsToDelete.Count)) to proceed: " -NoNewline -ForegroundColor Yellow
$Confirm3 = Read-Host
if ($Confirm3 -ne "$($FieldsToDelete.Count)") {
    Write-Host ""
    Write-Host "Aborted - you typed '$Confirm3' instead of '$($FieldsToDelete.Count)'" -ForegroundColor Green
    exit 0
}

Write-Host ""
Write-Host "All confirmations received. Proceeding with deletion..." -ForegroundColor Yellow
Write-Host ""

# ============================================================
# DELETE LEGACY FIELDS
# ============================================================

$DeletedCount = 0
$FailedCount = 0

foreach ($Field in $FieldsToDelete) {
    Write-Host "Deleting $($Field.Name)... " -NoNewline

    $Result = Invoke-LevelApi -Endpoint "/custom_fields/$($Field.Id)" -Method "DELETE"

    if ($Result.Success) {
        Write-Host "OK" -ForegroundColor Green
        $DeletedCount++
    }
    else {
        Write-Host "FAILED" -ForegroundColor Red
        Write-Host "  Error: $($Result.Error)" -ForegroundColor Red
        $FailedCount++
    }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " SUMMARY" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Deleted: $DeletedCount" -ForegroundColor Green
if ($FailedCount -gt 0) {
    Write-Host "  Failed:  $FailedCount" -ForegroundColor Red
}
Write-Host ""

if ($FailedCount -eq 0) {
    Write-LevelSuccess "All legacy fields have been removed!"
    Write-Host ""
    Write-Host "Your Level.io account now uses only the CoolForge_* prefixed fields." -ForegroundColor DarkGray
}
else {
    Write-LevelWarning "Some fields could not be deleted. Check the errors above."
}

Write-Host ""
