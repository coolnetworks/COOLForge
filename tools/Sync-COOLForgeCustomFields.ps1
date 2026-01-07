<#
.SYNOPSIS
    Ensures all COOLForge custom fields exist in Level.io.

.DESCRIPTION
    Reads field definitions from definitions/custom-fields.json and creates any
    missing fields in Level.io. Does not prompt for values - just ensures
    the field definitions exist.

    Use this script to:
    - Quickly sync fields after adding new ones to the config
    - Ensure all required fields exist before deploying scripts
    - Run as part of CI/CD or automated setup

    For interactive setup with value configuration, use Setup-COOLForgeCustomFields.ps1

.PARAMETER FeatureGroups
    Comma-separated list of feature groups to include (e.g., "screenconnect").
    If not specified, only core fields are synced.

.PARAMETER All
    Include all feature groups.

.PARAMETER DryRun
    Show what would be created without making changes.

.NOTES
    Version:          2026.01.07.01
    Target Platform:  Windows PowerShell 5.1+

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge

.EXAMPLE
    .\Sync-COOLForgeCustomFields.ps1
    Syncs only core fields.

.EXAMPLE
    .\Sync-COOLForgeCustomFields.ps1 -All
    Syncs all fields including all feature groups.

.EXAMPLE
    .\Sync-COOLForgeCustomFields.ps1 -FeatureGroups "screenconnect"
    Syncs core fields plus ScreenConnect fields.

.EXAMPLE
    .\Sync-COOLForgeCustomFields.ps1 -All -DryRun
    Shows what would be created without making changes.
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$FeatureGroups = "",

    [Parameter(Mandatory = $false)]
    [switch]$All,

    [Parameter(Mandatory = $false)]
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

# ============================================================
# PATHS
# ============================================================

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptRoot
$ConfigPath = Join-Path $ProjectRoot "definitions\custom-fields.json"
$ModulePath = Join-Path $ProjectRoot "modules\COOLForge-CustomFields.psm1"
$SavedConfigPath = Join-Path $ScriptRoot ".COOLForge_Lib-setup.json"

# ============================================================
# LOAD MODULE
# ============================================================

if (-not (Test-Path $ModulePath)) {
    Write-Host "[X] Module not found: $ModulePath" -ForegroundColor Red
    exit 1
}

Import-Module $ModulePath -Force -DisableNameChecking

# ============================================================
# LOAD CONFIG
# ============================================================

if (-not (Test-Path $ConfigPath)) {
    Write-Host "[X] Config not found: $ConfigPath" -ForegroundColor Red
    exit 1
}

$Config = Get-Content $ConfigPath -Raw | ConvertFrom-Json

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " COOLForge Custom Fields Sync" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Config version: $($Config.version)" -ForegroundColor DarkGray

if ($DryRun) {
    Write-Host "Mode: DRY RUN (no changes will be made)" -ForegroundColor Yellow
}

# ============================================================
# LOAD API KEY
# ============================================================

$ApiKey = $null

if (Test-Path $SavedConfigPath) {
    try {
        $SavedConfig = Get-Content $SavedConfigPath -Raw | ConvertFrom-Json

        # Try new key name first, fall back to legacy
        $EncryptedKey = $SavedConfig.CoolForge_ApiKeyEncrypted
        if (-not $EncryptedKey) {
            $EncryptedKey = $SavedConfig.ApiKeyEncrypted
        }

        if ($EncryptedKey) {
            $ApiKey = Unprotect-ApiKey -Encrypted $EncryptedKey
            Write-Host "[+] Using saved API key" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "[!] Could not load saved API key: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

if (-not $ApiKey) {
    Write-Host "Enter your Level.io API key: " -NoNewline -ForegroundColor Yellow
    $SecureKey = Read-Host -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureKey)
    $ApiKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
}

if ([string]::IsNullOrWhiteSpace($ApiKey)) {
    Write-Host "[X] API key is required" -ForegroundColor Red
    exit 1
}

# Initialize API
Initialize-LevelApi -ApiKey $ApiKey

# ============================================================
# DETERMINE WHICH GROUPS TO SYNC
# ============================================================

$GroupsToSync = @("core")

if ($All) {
    # Get all group names from config
    $Config.fields.PSObject.Properties | ForEach-Object {
        if ($_.Name -notin $GroupsToSync) {
            $GroupsToSync += $_.Name
        }
    }
}
elseif ($FeatureGroups) {
    $FeatureGroups.Split(",") | ForEach-Object {
        $GroupName = $_.Trim().ToLower()
        if ($GroupName -and $GroupName -notin $GroupsToSync) {
            $GroupsToSync += $GroupName
        }
    }
}

Write-Host ""
Write-Host "Groups to sync: $($GroupsToSync -join ', ')" -ForegroundColor Cyan

# ============================================================
# GET EXISTING FIELDS
# ============================================================

Write-Host ""
Write-Host "[*] Fetching existing custom fields..." -ForegroundColor DarkGray

$ExistingFields = Get-ExistingCustomFields
if (-not $ExistingFields) {
    $ExistingFields = @()
}

Write-Host "[+] Found $($ExistingFields.Count) existing field(s)" -ForegroundColor Green

# ============================================================
# SYNC FIELDS
# ============================================================

$Created = 0
$Skipped = 0
$Errors = 0

foreach ($GroupName in $GroupsToSync) {
    $GroupFields = $Config.fields.$GroupName

    if (-not $GroupFields) {
        Write-Host "[!] Unknown group: $GroupName" -ForegroundColor Yellow
        continue
    }

    Write-Host ""
    Write-Host "--- $($GroupName.ToUpper()) ---" -ForegroundColor Cyan

    foreach ($Field in $GroupFields) {
        $FieldName = $Field.name
        $Existing = Find-CustomField -Name $FieldName -ExistingFields $ExistingFields

        if ($Existing) {
            Write-Host "  [OK] $FieldName" -ForegroundColor DarkGray
            $Skipped++
        }
        else {
            if ($DryRun) {
                Write-Host "  [--] $FieldName (would create)" -ForegroundColor Yellow
                $Created++
            }
            else {
                Write-Host "  [+] Creating $FieldName..." -ForegroundColor White
                $NewField = New-CustomField -Name $FieldName -DefaultValue "" -AdminOnly $Field.adminOnly

                if ($NewField) {
                    Write-Host "      Created" -ForegroundColor Green
                    $ExistingFields += $NewField
                    $Created++
                }
                else {
                    Write-Host "      FAILED" -ForegroundColor Red
                    $Errors++
                }
            }
        }
    }
}

# ============================================================
# SUMMARY
# ============================================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " Summary" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

if ($DryRun) {
    Write-Host "  Would create: $Created" -ForegroundColor Yellow
}
else {
    Write-Host "  Created: $Created" -ForegroundColor $(if ($Created -gt 0) { "Green" } else { "DarkGray" })
}

Write-Host "  Already exist: $Skipped" -ForegroundColor DarkGray

if ($Errors -gt 0) {
    Write-Host "  Errors: $Errors" -ForegroundColor Red
}

Write-Host ""

if ($Errors -gt 0) {
    exit 1
}
