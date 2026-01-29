<#
.SYNOPSIS
    Exports current Level.io custom field values to an answer file for Setup-COOLForge.ps1.

.DESCRIPTION
    This standalone script connects to your Level.io instance and exports all
    COOLForge custom field values to a JSON answer file. This file can then be
    used with Setup-COOLForge.ps1 to restore field values after resetting your
    Level instance.

    The script:
    1. Loads field definitions from definitions/custom-fields.json
    2. Connects to Level.io API
    3. Exports all defined field values
    4. Identifies any extra fields not in definitions (potential legacy/deprecated)
    5. Saves to .COOLForge_Answers.json

.NOTES
    Version:          2026.01.21.01
    Target Platform:  Windows PowerShell 5.1+

.EXAMPLE
    .\Export-AnswerFile.ps1

    Exports current Level.io values to .COOLForge_Answers.json

.EXAMPLE
    .\Export-AnswerFile.ps1 -OutputPath "C:\Backups\level-answers.json"

    Exports to a custom location
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ApiKey,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath
)

# ============================================================
# IMPORT SHARED MODULE
# ============================================================

$ModulePath = Join-Path (Split-Path $PSScriptRoot -Parent) "modules\COOLForge-Common.psm1"

if (-not (Test-Path $ModulePath)) {
    Write-Host "[X] Module not found: $ModulePath" -ForegroundColor Red
    Write-Host "    Please ensure COOLForge-Common.psm1 is in the modules/ folder." -ForegroundColor Yellow
    exit 1
}

Import-Module $ModulePath -Force -DisableNameChecking

# ============================================================
# CONFIGURATION
# ============================================================

$Script:ConfigFileName = ".COOLForge_Lib-setup.json"
$Script:ConfigPath = Join-Path $PSScriptRoot $Script:ConfigFileName
$Script:FieldsConfigPath = Join-Path (Split-Path $PSScriptRoot -Parent) "definitions\custom-fields.json"
$Script:DefaultOutputPath = Join-Path $PSScriptRoot ".COOLForge_Answers.json"

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = $Script:DefaultOutputPath
}

# ============================================================
# HELPER FUNCTIONS
# ============================================================

function Get-AllDefinedFieldNames {
    param($FieldsConfig)

    $AllNames = @()
    $LegacyMap = @{}

    foreach ($GroupName in $FieldsConfig.fields.PSObject.Properties.Name) {
        foreach ($Field in $FieldsConfig.fields.$GroupName) {
            $AllNames += $Field.name

            # Track legacy names
            if ($Field.legacyNames) {
                foreach ($LegacyName in $Field.legacyNames) {
                    $LegacyMap[$LegacyName] = $Field.name
                }
            }
        }
    }

    return @{
        Names = $AllNames
        LegacyMap = $LegacyMap
    }
}

function Get-FieldGroup {
    param($FieldsConfig, $FieldName)

    foreach ($GroupName in $FieldsConfig.fields.PSObject.Properties.Name) {
        foreach ($Field in $FieldsConfig.fields.$GroupName) {
            if ($Field.name -eq $FieldName) {
                return $GroupName
            }
        }
    }
    return $null
}

function Get-CompanyNameFromScratchFolder {
    param($ScratchFolderValue)

    if ([string]::IsNullOrWhiteSpace($ScratchFolderValue)) {
        return $null
    }

    # Extract company name from path like "C:\ProgramData\COOLNETWORKS"
    $Parts = $ScratchFolderValue -split '\\'
    if ($Parts.Count -ge 3) {
        return $Parts[-1]
    }
    return $null
}

# ============================================================
# MAIN SCRIPT
# ============================================================

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " COOLForge Answer File Export" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "This script exports your current Level.io custom field values"
Write-Host "to an answer file for use with Setup-COOLForge.ps1"
Write-Host ""

# Load field definitions
if (-not (Test-Path $Script:FieldsConfigPath)) {
    Write-Host "[X] Field definitions not found: $Script:FieldsConfigPath" -ForegroundColor Red
    Write-Host "    Please ensure definitions/custom-fields.json exists." -ForegroundColor Yellow
    exit 1
}

$FieldsConfig = Get-Content $Script:FieldsConfigPath -Raw | ConvertFrom-Json
Write-Host "[+] Loaded field definitions (v$($FieldsConfig.version))" -ForegroundColor DarkGray

$DefinedFields = Get-AllDefinedFieldNames -FieldsConfig $FieldsConfig
Write-Host "    Found $($DefinedFields.Names.Count) defined fields" -ForegroundColor DarkGray
Write-Host ""

# Load saved configuration
$SavedConfig = $null
if (Test-Path $Script:ConfigPath) {
    try {
        $SavedConfig = Get-Content $Script:ConfigPath -Raw | ConvertFrom-Json
        Write-Host "[+] Found saved configuration" -ForegroundColor DarkGray
    } catch {
        Write-Host "[!] Could not load saved configuration" -ForegroundColor Yellow
    }
}

# Get API Key
$ResolvedApiKey = $null

if (-not [string]::IsNullOrWhiteSpace($ApiKey)) {
    $ResolvedApiKey = $ApiKey
}
elseif ($SavedConfig -and $SavedConfig.CoolForge_ApiKeyEncrypted) {
    $DecryptedKey = Unprotect-ApiKey -EncryptedText $SavedConfig.CoolForge_ApiKeyEncrypted
    if ($DecryptedKey) {
        Write-Host "[+] Using saved API key" -ForegroundColor DarkGray
        $ResolvedApiKey = $DecryptedKey
    }
}
elseif ($SavedConfig -and $SavedConfig.ApiKeyEncrypted) {
    # Legacy key name
    $DecryptedKey = Unprotect-ApiKey -EncryptedText $SavedConfig.ApiKeyEncrypted
    if ($DecryptedKey) {
        Write-Host "[+] Using saved API key (legacy format)" -ForegroundColor DarkGray
        $ResolvedApiKey = $DecryptedKey
    }
}

$ApiKeyWasManuallyEntered = $false
if ([string]::IsNullOrWhiteSpace($ResolvedApiKey)) {
    Write-Host "Enter your Level.io API key: " -NoNewline -ForegroundColor Yellow
    $SecureKey = Read-Host -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureKey)
    $ResolvedApiKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    $ApiKeyWasManuallyEntered = $true
}

if ([string]::IsNullOrWhiteSpace($ResolvedApiKey)) {
    Write-Host "[X] API key is required." -ForegroundColor Red
    exit 1
}

# Initialize module API key storage (so subsequent calls don't need -ApiKey parameter)
Initialize-LevelApi -ApiKey $ResolvedApiKey | Out-Null

# Test API connection and get all fields
Write-Host ""
Write-Host "Connecting to Level.io..." -ForegroundColor DarkGray

$AllLevelFields = Get-LevelCustomFields

if ($null -eq $AllLevelFields) {
    Write-Host "[X] Could not connect to Level.io API" -ForegroundColor Red
    exit 1
}

# Handle object with data property
if ($AllLevelFields -isnot [array] -and $AllLevelFields.data) {
    $AllLevelFields = $AllLevelFields.data
}

$FieldCount = if ($AllLevelFields -is [array]) { $AllLevelFields.Count } else { 1 }
Write-Host "[+] Connected! Found $FieldCount custom field(s) in Level.io" -ForegroundColor Green

# Save API key if it was manually entered and connection succeeded
if ($ApiKeyWasManuallyEntered) {
    try {
        $EncryptedKey = Protect-ApiKey -PlainText $ResolvedApiKey
        if ($EncryptedKey) {
            $ConfigToSave = @{
                LastRun = (Get-Date).ToString("o")
                CoolForge_ApiKeyEncrypted = $EncryptedKey
            }

            # Preserve existing config values if present
            if ($SavedConfig) {
                if ($SavedConfig.CompanyName) {
                    $ConfigToSave.CompanyName = $SavedConfig.CompanyName
                }
            }

            $ConfigToSave | ConvertTo-Json | Set-Content -Path $Script:ConfigPath -Encoding UTF8
            Write-Host "[+] API key saved for future use" -ForegroundColor DarkGray
        }
    }
    catch {
        Write-Host "[!] Could not save API key: $_" -ForegroundColor Yellow
    }
}

Write-Host ""

# Build a lookup of Level.io fields by name
$LevelFieldsByName = @{}
foreach ($Field in $AllLevelFields) {
    $LevelFieldsByName[$Field.name] = $Field
}

# ============================================================
# EXPORT FIELDS
# ============================================================

Write-Host "Exporting field values..." -ForegroundColor Cyan
Write-Host ""

$ExportedFields = @{}
$EnabledGroups = @{}
$ExtraFields = @{}
$CompanyName = $null

# Initialize all groups as disabled
foreach ($GroupName in $FieldsConfig.fields.PSObject.Properties.Name) {
    $EnabledGroups[$GroupName] = $false
}

# Process each defined field
foreach ($FieldName in $DefinedFields.Names) {
    $LevelField = $LevelFieldsByName[$FieldName]

    if ($LevelField) {
        # Get full field details including default_value
        $FieldDetails = Get-LevelCustomFieldById -FieldId $LevelField.id
        $FieldValue = if ($FieldDetails) { $FieldDetails.default_value } else { $LevelField.default_value }

        if (-not [string]::IsNullOrWhiteSpace($FieldValue)) {
            $ExportedFields[$FieldName] = $FieldValue

            # Mark the group as enabled
            $GroupName = Get-FieldGroup -FieldsConfig $FieldsConfig -FieldName $FieldName
            if ($GroupName) {
                $EnabledGroups[$GroupName] = $true
            }

            Write-Host "  [+] $FieldName = $FieldValue" -ForegroundColor Green

            # Extract company name from scratch folder
            if ($FieldName -eq "coolforge_msp_scratch_folder") {
                $CompanyName = Get-CompanyNameFromScratchFolder -ScratchFolderValue $FieldValue
            }
        }
        else {
            # Field exists but has no value
            $ExportedFields[$FieldName] = $null
            Write-Host "  [-] $FieldName (exists but empty)" -ForegroundColor DarkGray
        }
    }
    else {
        # Field not found - check legacy names
        $FoundLegacy = $false
        foreach ($LegacyName in $DefinedFields.LegacyMap.Keys) {
            if ($DefinedFields.LegacyMap[$LegacyName] -eq $FieldName) {
                $LegacyField = $LevelFieldsByName[$LegacyName]
                if ($LegacyField) {
                    $FieldDetails = Get-LevelCustomFieldById -FieldId $LegacyField.id
                    $FieldValue = if ($FieldDetails) { $FieldDetails.default_value } else { $LegacyField.default_value }

                    if (-not [string]::IsNullOrWhiteSpace($FieldValue)) {
                        $ExportedFields[$FieldName] = $FieldValue

                        $GroupName = Get-FieldGroup -FieldsConfig $FieldsConfig -FieldName $FieldName
                        if ($GroupName) {
                            $EnabledGroups[$GroupName] = $true
                        }

                        Write-Host "  [+] $FieldName = $FieldValue (from legacy: $LegacyName)" -ForegroundColor Yellow
                        $FoundLegacy = $true

                        if ($FieldName -eq "coolforge_msp_scratch_folder") {
                            $CompanyName = Get-CompanyNameFromScratchFolder -ScratchFolderValue $FieldValue
                        }
                        break
                    }
                }
            }
        }

        if (-not $FoundLegacy) {
            Write-Host "  [ ] $FieldName (not in Level.io)" -ForegroundColor DarkGray
        }
    }
}

Write-Host ""

# Find extra fields (in Level.io but not in definitions)
Write-Host "Checking for extra/legacy fields..." -ForegroundColor Cyan

$AllDefinedNames = $DefinedFields.Names + @($DefinedFields.LegacyMap.Keys)

foreach ($LevelFieldName in $LevelFieldsByName.Keys) {
    if ($LevelFieldName -notin $AllDefinedNames) {
        $LevelField = $LevelFieldsByName[$LevelFieldName]
        $FieldDetails = Get-LevelCustomFieldById -FieldId $LevelField.id
        $FieldValue = if ($FieldDetails) { $FieldDetails.default_value } else { $LevelField.default_value }

        $ExtraFields[$LevelFieldName] = $FieldValue

        if (-not [string]::IsNullOrWhiteSpace($FieldValue)) {
            Write-Host "  [?] $LevelFieldName = $FieldValue" -ForegroundColor Yellow
        }
        else {
            Write-Host "  [?] $LevelFieldName (empty)" -ForegroundColor DarkGray
        }
    }
}

if ($ExtraFields.Count -eq 0) {
    Write-Host "  No extra fields found" -ForegroundColor DarkGray
}

Write-Host ""

# ============================================================
# BUILD AND SAVE ANSWER FILE
# ============================================================

$AnswerFile = [ordered]@{
    version = "2026.01.21"
    exportedAt = (Get-Date).ToString("o")
    companyName = $CompanyName
    enabledGroups = $EnabledGroups
    fields = $ExportedFields
}

if ($ExtraFields.Count -gt 0) {
    $AnswerFile.extraFields = $ExtraFields
}

# Convert to JSON
$JsonContent = $AnswerFile | ConvertTo-Json -Depth 10

# Save to file
try {
    Set-Content -Path $OutputPath -Value $JsonContent -Encoding UTF8
    Write-Host "[+] Answer file saved to:" -ForegroundColor Green
    Write-Host "    $OutputPath" -ForegroundColor Cyan
}
catch {
    Write-Host "[X] Failed to save answer file: $_" -ForegroundColor Red
    exit 1
}

# Summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Export Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$FieldsWithValues = ($ExportedFields.Values | Where-Object { $_ -ne $null }).Count
Write-Host "  Fields with values:  $FieldsWithValues" -ForegroundColor White
Write-Host "  Fields empty/missing: $($ExportedFields.Count - $FieldsWithValues)" -ForegroundColor DarkGray
Write-Host "  Extra/legacy fields: $($ExtraFields.Count)" -ForegroundColor $(if ($ExtraFields.Count -gt 0) { "Yellow" } else { "DarkGray" })

if ($CompanyName) {
    Write-Host "  Company name:        $CompanyName" -ForegroundColor White
}

Write-Host ""
Write-Host "Enabled groups:" -ForegroundColor White
foreach ($Group in $EnabledGroups.Keys | Sort-Object) {
    $Status = if ($EnabledGroups[$Group]) { "[X]" } else { "[ ]" }
    $Color = if ($EnabledGroups[$Group]) { "Green" } else { "DarkGray" }
    Write-Host "  $Status $Group" -ForegroundColor $Color
}

Write-Host ""
Write-Host "Use this answer file with Setup-COOLForge.ps1 to restore values:" -ForegroundColor DarkGray
Write-Host "  .\Setup-COOLForge.ps1 -AnswerFile `"$OutputPath`"" -ForegroundColor Cyan
Write-Host ""
