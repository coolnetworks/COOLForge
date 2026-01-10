<#
.SYNOPSIS
    Interactive setup script for COOLForge custom fields in Level.io.

.DESCRIPTION
    This script helps you configure the required custom fields for COOLForge in your
    Level.io account. It will:

    1. Authenticate with the Level.io API using your API key
    2. Scan for all existing custom fields (new and legacy names)
    3. Show existing values and let you choose which to migrate
    4. Create new lowercase fields (coolforge_*) via Level.io API
    5. Optionally delete legacy fields after migration
    6. Suggest pinning to the current version for stability

    FIELD GROUPS:
    The script reads field definitions from definitions/custom-fields.json and processes
    each group interactively. Groups include:
    - core           : Required COOLForge fields (scratch folder, library source, etc.)
    - level_api      : Level.io API integration fields
    - screenconnect  : ScreenConnect/ConnectWise Control integration
    - huntress       : Huntress agent deployment fields
    - technician_alerts : Technician notification system fields

    LEGACY FIELD MIGRATION:
    The script automatically detects legacy field names (e.g., msp_scratch_folder,
    CoolForge_msp_scratch_folder) and offers to migrate values to new lowercase names.
    After migration, you can optionally delete the legacy fields.

    NOTE: Level.io automatically adds the 'cf_' prefix when referencing fields in scripts.
    So 'coolforge_msp_scratch_folder' becomes '{{cf_coolforge_msp_scratch_folder}}'.

.NOTES
    Version:          2026.01.07.03
    Target Platform:  Windows PowerShell 5.1+

    API Documentation: https://levelapi.readme.io/

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge

.EXAMPLE
    .\Setup-COOLForgeCustomFields.ps1

    Runs the interactive setup wizard.

.EXAMPLE
    .\Setup-COOLForgeCustomFields.ps1 -ApiKey "your-api-key"

    Runs setup with API key provided (skips the prompt).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ApiKey
)

# ============================================================
# IMPORT SHARED MODULE
# ============================================================

$ModulePath = Join-Path (Split-Path $PSScriptRoot -Parent) "modules\COOLForge-CustomFields.psm1"
if (-not (Test-Path $ModulePath)) {
    Write-Host "[X] Module not found: $ModulePath" -ForegroundColor Red
    Write-Host "    Please ensure COOLForge-CustomFields.psm1 is in the modules/ folder." -ForegroundColor Yellow
    exit 1
}
Import-Module $ModulePath -Force

# ============================================================
# CONFIGURATION
# ============================================================

$Script:ConfigFileName = ".COOLForge_Lib-setup.json"
$Script:ConfigPath = Join-Path $PSScriptRoot $Script:ConfigFileName
$Script:FieldsConfigPath = Join-Path (Split-Path $PSScriptRoot -Parent) "definitions\custom-fields.json"

# MSP name (set after prompting user)
$Script:MspName = ""
$Script:SavedConfig = $null
$Script:ResolvedApiKey = $null

# ============================================================
# LOAD FIELD DEFINITIONS FROM CONFIG
# ============================================================

function Convert-JsonFieldToHashtable {
    param($JsonField)

    $Hashtable = @{
        Name        = $JsonField.name
        Description = $JsonField.description
        LegacyNames = @()
        Required    = $false
        Default     = ""
        AdminOnly   = $false
        AutoCreate  = $false
        Prompt      = ""
        Help        = ""
    }

    if ($JsonField.legacyNames) {
        $Hashtable.LegacyNames = @($JsonField.legacyNames)
    }
    if ($null -ne $JsonField.required) {
        $Hashtable.Required = $JsonField.required
    }
    if ($JsonField.default) {
        $Hashtable.Default = $JsonField.default
    }
    if ($null -ne $JsonField.adminOnly) {
        $Hashtable.AdminOnly = $JsonField.adminOnly
    }
    if ($null -ne $JsonField.autoCreate) {
        $Hashtable.AutoCreate = $JsonField.autoCreate
    }
    if ($JsonField.prompt) {
        $Hashtable.Prompt = $JsonField.prompt
    }
    if ($JsonField.help) {
        $Hashtable.Help = $JsonField.help
    }

    return $Hashtable
}

# Load fields from JSON config
if (Test-Path $Script:FieldsConfigPath) {
    $FieldsConfig = Get-Content $Script:FieldsConfigPath -Raw | ConvertFrom-Json

    # Core fields - split into required and optional
    $Script:RequiredFields = @()
    $Script:OptionalFields = @()

    foreach ($Field in $FieldsConfig.fields.core) {
        $Converted = Convert-JsonFieldToHashtable -JsonField $Field
        if ($Field.required -eq $true) {
            $Script:RequiredFields += $Converted
        }
        else {
            $Script:OptionalFields += $Converted
        }
    }

    # Load setup prerequisites from JSON
    $Script:SetupPrerequisites = @()
    $Script:SetupDescription = ""
    $Script:SetupNotes = @()
    if ($FieldsConfig.setup) {
        if ($FieldsConfig.setup.prerequisites) {
            $Script:SetupPrerequisites = @($FieldsConfig.setup.prerequisites)
        }
        if ($FieldsConfig.setup.description) {
            $Script:SetupDescription = $FieldsConfig.setup.description
        }
        if ($FieldsConfig.setup.notes) {
            $Script:SetupNotes = @($FieldsConfig.setup.notes)
        }
    }

    # Load all other field groups dynamically
    $Script:FieldGroups = @{}
    $Script:FieldGroupDisplayNames = @{}
    $Script:FieldGroupDescriptions = @{}
    $Script:FieldGroupPrerequisites = @{}

    # Load field group metadata from JSON if available
    if ($FieldsConfig.fieldGroups) {
        foreach ($GroupName in $FieldsConfig.fieldGroups.PSObject.Properties.Name) {
            $GroupMeta = $FieldsConfig.fieldGroups.$GroupName
            if ($GroupMeta.displayName) {
                $Script:FieldGroupDisplayNames[$GroupName] = $GroupMeta.displayName
            }
            if ($GroupMeta.description) {
                $Script:FieldGroupDescriptions[$GroupName] = $GroupMeta.description
            }
            if ($GroupMeta.prerequisites) {
                $Script:FieldGroupPrerequisites[$GroupName] = @($GroupMeta.prerequisites)
            }
        }
    }

    # Get all group names from the JSON (excluding 'core' which we handle separately)
    $GroupNames = $FieldsConfig.fields.PSObject.Properties.Name | Where-Object { $_ -ne "core" }

    foreach ($GroupName in $GroupNames) {
        $Script:FieldGroups[$GroupName] = @()
        foreach ($Field in $FieldsConfig.fields.$GroupName) {
            $Script:FieldGroups[$GroupName] += (Convert-JsonFieldToHashtable -JsonField $Field)
        }
        # Set defaults for groups without metadata
        if (-not $Script:FieldGroupDisplayNames[$GroupName]) {
            $Script:FieldGroupDisplayNames[$GroupName] = $GroupName
        }
        if (-not $Script:FieldGroupDescriptions[$GroupName]) {
            $Script:FieldGroupDescriptions[$GroupName] = "Configure $GroupName fields."
        }
    }

    Write-Host "[+] Loaded field definitions from config (v$($FieldsConfig.version))" -ForegroundColor DarkGray
    Write-Host "    Groups: core, $($GroupNames -join ', ')" -ForegroundColor DarkGray
}
else {
    Write-Host "[!] Config not found: $Script:FieldsConfigPath" -ForegroundColor Yellow
    Write-Host "    Using built-in defaults..." -ForegroundColor Yellow

    # Fallback to hardcoded defaults if config not found
    $Script:SetupPrerequisites = @(
        "Level.io API key with 'Custom Fields' permission"
    )
    $Script:SetupDescription = ""
    $Script:SetupNotes = @()
    $Script:RequiredFields = @(
        @{
            Name        = "coolforge_msp_scratch_folder"
            LegacyNames = @("msp_scratch_folder")
            Description = "Persistent storage folder for MSP scripts and libraries"
            Required    = $true
            Default     = ""
            AdminOnly   = $false
        }
    )
    $Script:OptionalFields = @()
    $Script:FieldGroups = @{}
    $Script:FieldGroupDisplayNames = @{}
    $Script:FieldGroupDescriptions = @{}
    $Script:FieldGroupPrerequisites = @{}
}

# Track which feature groups are enabled
$Script:EnabledGroups = @{}

# ============================================================
# MAIN SCRIPT
# ============================================================

Write-Header "COOLForge_Lib Custom Fields Setup"

Write-Host "This wizard will help you configure the custom fields required for COOLForge_Lib in Level.io."
Write-Host ""
Write-Host "For new users:      Create and configure the required custom fields."
Write-Host "For existing users: Choose which version to run by default (version pinning)."
Write-Host ""

# Display prerequisites from JSON config
if ($Script:SetupPrerequisites.Count -gt 0) {
    Write-Host "========================================" -ForegroundColor DarkGray
    Write-Host " Before You Begin" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "Please have the following ready:" -ForegroundColor White
    $Index = 1
    foreach ($Prereq in $Script:SetupPrerequisites) {
        Write-Host "  $Index. $Prereq" -ForegroundColor Cyan
        $Index++
    }
    Write-Host ""

    # Show optional integrations and their prerequisites
    if ($Script:FieldGroups.Count -gt 0) {
        Write-Host "Optional integrations (you'll be asked about each):" -ForegroundColor White
        foreach ($GroupName in $Script:FieldGroups.Keys) {
            $DisplayName = $Script:FieldGroupDisplayNames[$GroupName]
            Write-Host "  - $DisplayName" -ForegroundColor DarkCyan
            if ($Script:FieldGroupPrerequisites[$GroupName]) {
                foreach ($Prereq in $Script:FieldGroupPrerequisites[$GroupName]) {
                    Write-Host "      $Prereq" -ForegroundColor DarkGray
                }
            }
        }
        Write-Host ""
    }

    Write-Host "========================================" -ForegroundColor DarkGray
    Write-Host ""
}

Write-Host "Get your API key at: https://app.level.io/api-keys" -ForegroundColor Cyan
Write-Host ""

# Display notes from JSON config (e.g., new account warnings)
if ($Script:SetupNotes.Count -gt 0) {
    foreach ($Note in $Script:SetupNotes) {
        Write-Host "NOTE: $Note" -ForegroundColor DarkYellow
    }
    Write-Host ""
}

# Load saved configuration
$Script:SavedConfig = Get-SavedConfig -Path $Script:ConfigPath
if ($Script:SavedConfig) {
    Write-LevelInfo "Found saved configuration."
}

# Get API Key - check parameter, then saved config (new key name, then legacy), then prompt
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
    # Legacy key name - migrate on next save
    $DecryptedKey = Unprotect-ApiKey -EncryptedText $Script:SavedConfig.ApiKeyEncrypted
    if ($DecryptedKey) {
        Write-LevelInfo "Using saved API key (will migrate to new format on save)."
        $Script:ResolvedApiKey = $DecryptedKey
    }
}

if ([string]::IsNullOrWhiteSpace($Script:ResolvedApiKey)) {
    Write-Host "Enter your Level.io API key: " -NoNewline -ForegroundColor Yellow
    $SecureKey = Read-Host -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureKey)
    $Script:ResolvedApiKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
}

if ([string]::IsNullOrWhiteSpace($Script:ResolvedApiKey)) {
    Write-LevelError "API key is required. Exiting."
    exit 1
}

# Initialize the module with API key
$Script:LevelApiBaseUrl = "https://api.level.io/v2"
Initialize-COOLForgeCustomFields -ApiKey $Script:ResolvedApiKey -LevelApiBase $Script:LevelApiBaseUrl | Out-Null

# Test API connection
Write-Header "Testing API Connection"

Write-Host "API Endpoint: $Script:LevelApiBaseUrl" -ForegroundColor DarkGray
Write-Host "Connecting..." -ForegroundColor DarkGray

$ExistingFields = Get-ExistingCustomFields
if ($null -eq $ExistingFields) {
    Write-LevelError "Could not connect to Level.io API. Please check your API key."
    Write-Host ""
    Write-Host "Troubleshooting:" -ForegroundColor Yellow
    Write-Host "  1. Verify your API key at https://app.level.io/api-keys" -ForegroundColor DarkGray
    Write-Host "  2. Ensure the key has 'Custom Fields' permission enabled" -ForegroundColor DarkGray
    Write-Host "  3. Check your network connection can reach $Script:LevelApiBaseUrl" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  NEW ACCOUNTS: If this is a new Level.io account, API access may not be" -ForegroundColor Yellow
    Write-Host "  enabled yet. Contact Level.io support to request API access be enabled" -ForegroundColor Yellow
    Write-Host "  for your account before using this setup script." -ForegroundColor Yellow
    exit 1
}

# Handle object with data property (not array)
if ($ExistingFields -isnot [array] -and $ExistingFields.data) {
    $ExistingFields = $ExistingFields.data
}

$FieldCount = if ($ExistingFields -is [array]) { $ExistingFields.Count } else { 1 }
Write-LevelSuccess "Connected to Level.io API!"
Write-Host "  Endpoint: $Script:LevelApiBaseUrl/custom_fields" -ForegroundColor DarkGray
Write-Host "  Found $FieldCount existing custom field(s)" -ForegroundColor DarkGray

# API key works - save it immediately for future runs (using new key names)
$ConfigToSave = @{
    CoolForge_ApiKeyEncrypted = Protect-ApiKey -PlainText $Script:ResolvedApiKey
    LastRun                   = (Get-Date).ToString("o")
}
if ($Script:SavedConfig -and $Script:SavedConfig.CompanyName) {
    $ConfigToSave.CompanyName = $Script:SavedConfig.CompanyName
}
if (Save-Config -Config $ConfigToSave -Path $Script:ConfigPath) {
    Write-LevelInfo "API key saved for future runs."
}

# ============================================================
# BACKUP & RESTORE
# ============================================================
Write-Header "Backup & Restore"

# Check for existing backups first
$BackupsFolder = Join-Path (Split-Path $PSScriptRoot -Parent) "backups"
$LatestBackupPath = Get-LatestBackup -BasePath $BackupsFolder
if ($LatestBackupPath) {
    $BackupFileName = Split-Path $LatestBackupPath -Leaf
    Write-LevelInfo "Found existing backup: $BackupFileName"

    if (Read-YesNo -Prompt "Compare backup with current state" -Default $false) {
        $ExistingBackup = Import-Backup -Path $LatestBackupPath

        if ($ExistingBackup) {
            # Check if backup includes devices
            $BackupHasDevices = ($ExistingBackup.Organizations | ForEach-Object { $_.Folders | ForEach-Object { $_.Devices.Count } } | Measure-Object -Sum).Sum -gt 0

            $Differences = Compare-BackupWithCurrent -Backup $ExistingBackup -IncludeDevices:$BackupHasDevices
            Show-BackupDifferences -Differences $Differences

            if ($Differences.Count -gt 0) {
                Write-Host ""
                if (Read-YesNo -Prompt "Restore from this backup" -Default $false) {
                    Write-LevelInfo "Restoring custom field values..."

                    # First do a dry run
                    Write-Host ""
                    Write-Host "Preview of changes:" -ForegroundColor Cyan
                    Restore-CustomFields -Backup $ExistingBackup -DryRun -IncludeDevices:$BackupHasDevices

                    Write-Host ""
                    if (Read-YesNo -Prompt "Apply these changes" -Default $false) {
                        Restore-CustomFields -Backup $ExistingBackup -IncludeDevices:$BackupHasDevices
                        Write-LevelSuccess "Restore complete!"
                        Write-Host ""
                        Write-Host "Exiting setup - no further changes needed." -ForegroundColor Green
                        exit 0
                    }
                    else {
                        Write-LevelInfo "Restore cancelled. Continuing with setup..."
                    }
                }
            }
        }
    }
    Write-Host ""
}

Write-Host "Before making changes, we can backup your current custom field configuration."
Write-Host "This captures field values at all levels (organizations, folders)."
Write-Host ""

if (Read-YesNo -Prompt "Create backup before proceeding" -Default $true) {
    Write-LevelInfo "Creating backup (this may take a moment)..."

    $IncludeDevicesInBackup = Read-YesNo -Prompt "Include device-level values (slower, more complete)" -Default $false

    $Backup = Backup-AllCustomFields -IncludeDevices:$IncludeDevicesInBackup
    $BackupPath = Get-BackupPath -BasePath $BackupsFolder

    if (Save-Backup -Backup $Backup -Path $BackupPath) {
        # Get the actual zip path (Save-Backup updates this)
        $ZipPath = $BackupPath -replace '\.json$', '.zip'
        Write-LevelSuccess "Backup saved to: $ZipPath"

        # Count what was backed up
        $OrgCount = $Backup.Organizations.Count
        $FolderCount = ($Backup.Organizations | ForEach-Object { $_.Folders.Count } | Measure-Object -Sum).Sum
        $DeviceCount = 0
        if ($IncludeDevicesInBackup) {
            $DeviceCount = ($Backup.Organizations | ForEach-Object { $_.Folders | ForEach-Object { $_.Devices.Count } } | Measure-Object -Sum).Sum
        }

        Write-Host "  Backed up: $OrgCount org(s), $FolderCount folder(s)" -NoNewline
        if ($IncludeDevicesInBackup) {
            Write-Host ", $DeviceCount device(s)" -ForegroundColor DarkGray
        }
        else {
            Write-Host "" # newline
        }
    }
    else {
        Write-LevelWarning "Backup failed, but continuing with setup."
    }
}
else {
    Write-LevelInfo "Skipping backup."
}

# ============================================================
# MSP CONFIGURATION - Check existing scratch folder and infer company name
# ============================================================
Write-Header "MSP Configuration"

# Check for all matching fields (new name + all legacy names)
$ScratchFieldDef = $Script:RequiredFields[0]
$AllMatchingFields = @()

# Check new name first
$NewField = Find-CustomField -Name $ScratchFieldDef.Name -ExistingFields $ExistingFields
if ($NewField) {
    $Details = Get-CustomFieldById -FieldId $NewField.id
    $Value = if ($Details) { $Details.default_value } else { $NewField.default_value }
    $AllMatchingFields += @{
        Name   = $ScratchFieldDef.Name
        Id     = $NewField.id
        Value  = $Value
        IsNew  = $true
    }
}

# Check all legacy names
foreach ($LegacyName in $ScratchFieldDef.LegacyNames) {
    $LegacyField = Find-CustomField -Name $LegacyName -ExistingFields $ExistingFields
    if ($LegacyField) {
        $Details = Get-CustomFieldById -FieldId $LegacyField.id
        $Value = if ($Details) { $Details.default_value } else { $LegacyField.default_value }
        $AllMatchingFields += @{
            Name   = $LegacyName
            Id     = $LegacyField.id
            Value  = $Value
            IsNew  = $false
        }
    }
}

$CurrentScratchFolder = ""
$InferredCompanyName = ""
$UsingLegacyField = $false
$LegacyFieldsToDelete = @()

if ($AllMatchingFields.Count -gt 0) {
    Write-LevelInfo "Found $($AllMatchingFields.Count) matching field(s):"
    foreach ($Field in $AllMatchingFields) {
        $FieldType = if ($Field.IsNew) { "(current)" } else { "(legacy)" }
        $DisplayValue = if ([string]::IsNullOrWhiteSpace($Field.Value)) { "(empty)" } else { $Field.Value }
        Write-Host "    $($Field.Name) $FieldType = $DisplayValue" -ForegroundColor $(if ($Field.IsNew) { "Green" } else { "Yellow" })
    }

    # Get all fields with values - ensure it's always an array
    $FieldsWithValues = @($AllMatchingFields | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Value) })

    # Always let user choose which value to use
    Write-Host ""
    Write-Host "Choose which value to use for scratch folder:" -ForegroundColor Cyan

    $Index = 1
    $DefaultChoice = "N"
    foreach ($Field in $FieldsWithValues) {
        $Marker = if ($Field.IsNew) { " (current)" } else { "" }
        Write-Host "  [$Index] $($Field.Value) (from $($Field.Name))$Marker" -ForegroundColor White
        if ($Index -eq 1) { $DefaultChoice = "1" }
        $Index++
    }
    Write-Host "  [N] Enter a new value" -ForegroundColor Yellow
    Write-Host ""

    $Choice = Read-UserInput -Prompt "Select option" -Default $DefaultChoice

    if ($Choice.ToUpper() -eq "N") {
        $CurrentScratchFolder = ""
        $UsingLegacyField = $false
    }
    elseif ($Choice -match '^\d+$') {
        $ChoiceInt = [int]$Choice
        if ($ChoiceInt -ge 1 -and $ChoiceInt -le $FieldsWithValues.Count) {
            $SelectedField = $FieldsWithValues[$ChoiceInt - 1]
            # Validate that we actually got a value before using it
            if ($SelectedField -and -not [string]::IsNullOrWhiteSpace($SelectedField.Value)) {
                $CurrentScratchFolder = $SelectedField.Value
                $UsingLegacyField = -not $SelectedField.IsNew
            }
            else {
                Write-LevelWarning "Selected field has no value. Please enter a new value."
                $CurrentScratchFolder = ""
                $UsingLegacyField = $false
            }
        }
        else {
            Write-LevelWarning "Invalid selection. Please enter a new value."
            $CurrentScratchFolder = ""
            $UsingLegacyField = $false
        }
    }
    else {
        $CurrentScratchFolder = ""
        $UsingLegacyField = $false
    }

    # Track legacy fields for potential deletion
    $LegacyFieldsToDelete = $AllMatchingFields | Where-Object { -not $_.IsNew }
}

if (-not [string]::IsNullOrWhiteSpace($CurrentScratchFolder)) {
    Write-Host "  Found existing scratch folder: $CurrentScratchFolder"
    $InferredCompanyName = Get-CompanyNameFromPath -Path $CurrentScratchFolder
    if (-not [string]::IsNullOrWhiteSpace($InferredCompanyName)) {
        Write-Host "  Inferred company name: $InferredCompanyName"
    }
}

Write-Host ""
Write-Host "Your company name will be used for the scratch folder path."
Write-Host "Example: 'Contoso' -> C:\ProgramData\Contoso"
Write-Host "Example: 'COOLForge' -> C:\ProgramData\COOLForge (default)"
Write-Host ""

# Default to: inferred from scratch folder > saved config > "COOLForge"
$DefaultCompanyName = "COOLForge"
if (-not [string]::IsNullOrWhiteSpace($InferredCompanyName)) {
    $DefaultCompanyName = $InferredCompanyName
}
elseif ($Script:SavedConfig -and $Script:SavedConfig.CompanyName) {
    $DefaultCompanyName = $Script:SavedConfig.CompanyName
    Write-LevelInfo "Using saved company name: $DefaultCompanyName"
}

$Script:MspName = Read-UserInput -Prompt "Enter your company name (or press Enter for COOLForge)" -Default $DefaultCompanyName

# Sanitize MSP name for use in folder path (remove invalid characters, but allow spaces)
$Script:MspName = $Script:MspName -replace '[<>:"/\\|?*]', ''
$Script:MspName = $Script:MspName.Trim()

if ([string]::IsNullOrWhiteSpace($Script:MspName)) {
    $Script:MspName = "COOLForge"
}

# Build the suggested scratch folder path
$SuggestedScratchFolder = "C:\ProgramData\$Script:MspName"

Write-Host ""
Write-Host "Scratch folder path: " -NoNewline
Write-Host $SuggestedScratchFolder -ForegroundColor Cyan

# If different from current, confirm the change
if (-not [string]::IsNullOrWhiteSpace($CurrentScratchFolder) -and $CurrentScratchFolder -ne $SuggestedScratchFolder) {
    Write-Host "  (currently: $CurrentScratchFolder)" -ForegroundColor DarkGray
}

$FinalScratchFolder = Read-UserInput -Prompt "Confirm scratch folder path" -Default $SuggestedScratchFolder

# Update the default value for msp_scratch_folder
$Script:RequiredFields[0].Default = $FinalScratchFolder

Write-LevelSuccess "Company name: $Script:MspName"
Write-LevelSuccess "Scratch folder: $FinalScratchFolder"

# ============================================================
# PROCESS SCRATCH FOLDER FIELD
# ============================================================
Write-Header "Required Custom Fields"

$ScratchFieldName = $ScratchFieldDef.Name

Write-Host ""
Write-Host "Field: $ScratchFieldName" -ForegroundColor Cyan
Write-Host "  Description: Persistent storage folder for MSP scripts and libraries"
Write-Host "  Required: Yes"
Write-Host ""

# Check if the new field already exists
$NewFieldExists = $AllMatchingFields | Where-Object { $_.IsNew } | Select-Object -First 1

if ($NewFieldExists) {
    # New field exists - update if value changed
    if ([string]::IsNullOrWhiteSpace($NewFieldExists.Value)) {
        Write-LevelInfo "Field exists but has no default value set."
        Write-LevelInfo "Setting default value to: $FinalScratchFolder"
        if (Update-CustomFieldValue -FieldId $NewFieldExists.Id -Value $FinalScratchFolder) {
            Write-LevelSuccess "Set default value to: $FinalScratchFolder"
        }
    }
    elseif ($NewFieldExists.Value -ne $FinalScratchFolder) {
        Write-LevelInfo "Updating default value from '$($NewFieldExists.Value)' to '$FinalScratchFolder'"
        if (Update-CustomFieldValue -FieldId $NewFieldExists.Id -Value $FinalScratchFolder) {
            Write-LevelSuccess "Updated default value to: $FinalScratchFolder"
        }
    }
    else {
        Write-LevelSuccess "Field already configured correctly: $FinalScratchFolder"
    }
}
elseif ($UsingLegacyField) {
    # Legacy field exists - create new field with same value
    Write-LevelInfo "Creating new field '$ScratchFieldName' with value from legacy field..."
    $Created = New-CustomField -Name $ScratchFieldName -DefaultValue $FinalScratchFolder -AdminOnly $false

    if ($Created -and -not [string]::IsNullOrWhiteSpace($FinalScratchFolder)) {
        if ([string]::IsNullOrWhiteSpace($Created.default_value)) {
            Write-LevelInfo "Setting default value..."
            if (Update-CustomFieldValue -FieldId $Created.id -Value $FinalScratchFolder) {
                Write-LevelSuccess "Set default value to: $FinalScratchFolder"
            }
        }
    }
    if ($Created) {
        $ExistingFields += $Created
    }
}
else {
    # Field doesn't exist - create it
    Write-LevelWarning "Field does not exist - creating it."
    $Created = New-CustomField -Name $ScratchFieldName -DefaultValue $FinalScratchFolder -AdminOnly $false

    # If API doesn't set default on creation, update it separately
    if ($Created -and -not [string]::IsNullOrWhiteSpace($FinalScratchFolder)) {
        if ([string]::IsNullOrWhiteSpace($Created.default_value)) {
            Write-LevelInfo "Setting default value..."
            if (Update-CustomFieldValue -FieldId $Created.id -Value $FinalScratchFolder) {
                Write-LevelSuccess "Set default value to: $FinalScratchFolder"
            }
        }
    }
    if ($Created) {
        $ExistingFields += $Created
    }
}

# Process Optional Fields
Write-Header "Optional Custom Fields"

Write-Host "These fields are optional but enable additional features."
Write-Host ""

# Track all legacy fields found for potential deletion later
$Script:AllLegacyFieldsFound = @()

# Process optional core fields
foreach ($Field in $Script:OptionalFields) {

    # Find all matching fields (new + legacy)
    $MatchingFields = @()

    $NewField = Find-CustomField -Name $Field.Name -ExistingFields $ExistingFields
    if ($NewField) {
        $Details = Get-CustomFieldById -FieldId $NewField.id
        $Value = if ($Details) { $Details.default_value } else { $NewField.default_value }
        $MatchingFields += @{
            Name   = $Field.Name
            Id     = $NewField.id
            Value  = $Value
            IsNew  = $true
        }
    }

    # Check all legacy names
    foreach ($LegacyName in $Field.LegacyNames) {
        $LegacyField = Find-CustomField -Name $LegacyName -ExistingFields $ExistingFields
        if ($LegacyField) {
            $Details = Get-CustomFieldById -FieldId $LegacyField.id
            $Value = if ($Details) { $Details.default_value } else { $LegacyField.default_value }
            $MatchingFields += @{
                Name   = $LegacyName
                Id     = $LegacyField.id
                Value  = $Value
                IsNew  = $false
            }
            # Track for later deletion
            $Script:AllLegacyFieldsFound += @{
                Name   = $LegacyName
                Id     = $LegacyField.id
                Value  = $Value
                NewFieldName = $Field.Name
            }
        }
    }

    $NewFieldExists = $MatchingFields | Where-Object { $_.IsNew } | Select-Object -First 1
    $LegacyFieldsExist = $MatchingFields | Where-Object { -not $_.IsNew }

    if ($NewFieldExists -or $LegacyFieldsExist.Count -gt 0) {
        # Fields exist - show all matching fields and let user choose
        Write-Host ""
        Write-Host "Field: $($Field.Name)" -ForegroundColor Cyan
        Write-Host "  Description: $($Field.Description)"

        # Show all fields found (new + legacy)
        Write-Host ""
        Write-Host "  Existing fields found:" -ForegroundColor White
        foreach ($Match in $MatchingFields) {
            $FieldType = if ($Match.IsNew) { "(current)" } else { "(legacy)" }
            $DisplayValue = if ([string]::IsNullOrWhiteSpace($Match.Value)) { "(empty)" } else { $Match.Value }
            $Color = if ($Match.IsNew) { "Green" } else { "Yellow" }
            Write-Host "    $($Match.Name) $FieldType = $DisplayValue" -ForegroundColor $Color
        }

        # Get fields with values
        $FieldsWithValues = @($MatchingFields | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Value) })

        Write-Host ""
        Write-Host "  Choose which value to use:" -ForegroundColor Cyan
        $Index = 1
        $DefaultChoice = "N"
        foreach ($Match in $FieldsWithValues) {
            $Marker = if ($Match.IsNew) { " (current)" } else { "" }
            Write-Host "    [$Index] $($Match.Value) (from $($Match.Name))$Marker" -ForegroundColor White
            if ($Index -eq 1) { $DefaultChoice = "1" }
            $Index++
        }
        Write-Host "    [N] Enter a new value" -ForegroundColor Yellow
        if ($NewFieldExists -and -not [string]::IsNullOrWhiteSpace($NewFieldExists.Value)) {
            Write-Host "    [K] Keep current value ($($NewFieldExists.Value))" -ForegroundColor Yellow
            Write-Host "    [D] Delete/clear the global value" -ForegroundColor Red
        }
        Write-Host ""

        $Choice = Read-UserInput -Prompt "  Select option" -Default $DefaultChoice

        if ($Choice.ToUpper() -eq "N") {
            $NewValue = Read-UserInput -Prompt "  Enter value" -Default $Field.Default

            if ($NewFieldExists) {
                # Update existing new field
                if (-not [string]::IsNullOrWhiteSpace($NewValue) -and $NewValue -ne $NewFieldExists.Value) {
                    if (Update-CustomFieldValue -FieldId $NewFieldExists.Id -Value $NewValue) {
                        Write-LevelSuccess "Updated value to: $NewValue"
                    }
                }
            }
            else {
                # Create new field with new value
                Write-LevelInfo "Creating new field '$($Field.Name)'..."
                $Created = New-CustomField -Name $Field.Name -DefaultValue $NewValue -AdminOnly $Field.AdminOnly
                if ($Created -and -not [string]::IsNullOrWhiteSpace($NewValue)) {
                    if ([string]::IsNullOrWhiteSpace($Created.default_value)) {
                        if (Update-CustomFieldValue -FieldId $Created.id -Value $NewValue) {
                            Write-LevelSuccess "Set value: $NewValue"
                        }
                    }
                }
                if ($Created) {
                    $ExistingFields += $Created
                }
            }
        }
        elseif ($Choice.ToUpper() -eq "K" -and $NewFieldExists) {
            Write-LevelInfo "Keeping current value: $($NewFieldExists.Value)"
        }
        elseif ($Choice.ToUpper() -eq "D" -and $NewFieldExists) {
            Write-LevelInfo "Clearing value for field $($NewFieldExists.Name)..."
            $RecreatedField = Remove-CustomFieldValue -FieldId $NewFieldExists.Id -FieldName $Field.Name -AdminOnly $Field.AdminOnly
            if ($RecreatedField) {
                Write-LevelSuccess "Field value cleared"
                # Update ExistingFields with the new field ID
                $ExistingFields = @($ExistingFields | Where-Object { $_.id -ne $NewFieldExists.Id })
                $ExistingFields += $RecreatedField
            }
            else {
                Write-LevelWarning "Could not clear field value"
            }
        }
        elseif ($Choice -match '^\d+$') {
            $ChoiceInt = [int]$Choice
            if ($ChoiceInt -ge 1 -and $ChoiceInt -le $FieldsWithValues.Count) {
                $SelectedField = $FieldsWithValues[$ChoiceInt - 1]
                # Validate that we actually got a value before using it
                if ($SelectedField -and -not [string]::IsNullOrWhiteSpace($SelectedField.Value)) {
                    $SelectedValue = $SelectedField.Value

                    if ($NewFieldExists) {
                        # Update existing new field
                        if ($SelectedValue -ne $NewFieldExists.Value) {
                            if (Update-CustomFieldValue -FieldId $NewFieldExists.Id -Value $SelectedValue) {
                                Write-LevelSuccess "Updated value to: $SelectedValue"
                            }
                        }
                        else {
                            Write-LevelInfo "Value unchanged: $SelectedValue"
                        }
                    }
                    else {
                        # Create new field with selected value
                        Write-LevelInfo "Creating new field '$($Field.Name)'..."
                        $Created = New-CustomField -Name $Field.Name -DefaultValue $SelectedValue -AdminOnly $Field.AdminOnly
                        if ($Created -and -not [string]::IsNullOrWhiteSpace($SelectedValue)) {
                            if ([string]::IsNullOrWhiteSpace($Created.default_value)) {
                                if (Update-CustomFieldValue -FieldId $Created.id -Value $SelectedValue) {
                                    Write-LevelSuccess "Migrated value: $SelectedValue"
                                }
                            }
                        }
                        if ($Created) {
                            $ExistingFields += $Created
                        }
                    }
                }
                else {
                    Write-LevelWarning "Selected field has no value."
                }
            }
            else {
                Write-LevelWarning "Invalid selection."
            }
        }
    }
    else {
        # Field doesn't exist - ask if user wants to create it
        Write-Host ""
        Write-Host "Field: $($Field.Name)" -ForegroundColor Cyan
        Write-Host "  Description: $($Field.Description)"
        if ($Field.Help) {
            Write-Host "  Help: $($Field.Help)" -ForegroundColor DarkGray
        }
        if ($Field.AdminOnly) {
            Write-Host "  Admin Only: Yes (values hidden from non-admins)" -ForegroundColor Yellow
        }
        Write-Host ""

        if (Read-YesNo -Prompt "  Create this field" -Default $false) {
            $DefaultValue = ""

            # Special handling for version pinning
            if ($Field.Name -eq "coolforge_pin_psmodule_to_version") {
                Write-Host ""
                Write-Host "  TIP: Pinning to a version ensures stability across your fleet." -ForegroundColor Cyan
                $DefaultValue = Select-Version -CurrentVersion ""
            }
            else {
                $DefaultValue = Read-UserInput -Prompt "  Default value" -Default $Field.Default
            }

            $Created = New-CustomField -Name $Field.Name -DefaultValue $DefaultValue -AdminOnly $Field.AdminOnly

            # If we have a default value but the field was created without it, update it separately
            if ($Created -and -not [string]::IsNullOrWhiteSpace($DefaultValue)) {
                $CreatedId = $Created.id
                if ($CreatedId -and [string]::IsNullOrWhiteSpace($Created.default_value)) {
                    Write-LevelInfo "Setting default value..."
                    if (Update-CustomFieldValue -FieldId $CreatedId -Value $DefaultValue) {
                        Write-LevelSuccess "Set default value to: $DefaultValue"
                    }
                }
            }
            if ($Created) {
                $ExistingFields += $Created
            }
        }
        else {
            Write-LevelInfo "Skipped: $($Field.Name)"
        }
    }
}

# ============================================================
# ADDITIONAL FIELD GROUPS (Dynamic)
# ============================================================

# Process each field group from the JSON config
foreach ($GroupName in $Script:FieldGroups.Keys) {
    $GroupFields = $Script:FieldGroups[$GroupName]
    if ($GroupFields.Count -eq 0) { continue }

    $DisplayName = if ($Script:FieldGroupDisplayNames[$GroupName]) { $Script:FieldGroupDisplayNames[$GroupName] } else { $GroupName }
    $Description = if ($Script:FieldGroupDescriptions[$GroupName]) { $Script:FieldGroupDescriptions[$GroupName] } else { "Configure $DisplayName fields." }

    Write-Host ""
    Write-Host "========================================" -ForegroundColor DarkGray
    Write-Host " $DisplayName Integration" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host $Description
    Write-Host ""

    # Show prerequisites for this group if available
    if ($Script:FieldGroupPrerequisites[$GroupName] -and $Script:FieldGroupPrerequisites[$GroupName].Count -gt 0) {
        Write-Host "You'll need:" -ForegroundColor Yellow
        foreach ($Prereq in $Script:FieldGroupPrerequisites[$GroupName]) {
            Write-Host "  - $Prereq" -ForegroundColor DarkGray
        }
        Write-Host ""
    }

    $EnableGroup = Read-YesNo -Prompt "Do you use $DisplayName" -Default $false
    $Script:EnabledGroups[$GroupName] = $EnableGroup

    if ($EnableGroup) {
        foreach ($Field in $GroupFields) {
            # Find all matching fields (new + legacy)
            $MatchingFields = @()

            $NewField = Find-CustomField -Name $Field.Name -ExistingFields $ExistingFields
            if ($NewField) {
                $Details = Get-CustomFieldById -FieldId $NewField.id
                $Value = if ($Details) { $Details.default_value } else { $NewField.default_value }
                $MatchingFields += @{
                    Name   = $Field.Name
                    Id     = $NewField.id
                    Value  = $Value
                    IsNew  = $true
                }
            }

            # Check all legacy names
            foreach ($LegacyName in $Field.LegacyNames) {
                $LegacyField = Find-CustomField -Name $LegacyName -ExistingFields $ExistingFields
                if ($LegacyField) {
                    $Details = Get-CustomFieldById -FieldId $LegacyField.id
                    $Value = if ($Details) { $Details.default_value } else { $LegacyField.default_value }
                    $MatchingFields += @{
                        Name   = $LegacyName
                        Id     = $LegacyField.id
                        Value  = $Value
                        IsNew  = $false
                    }
                    # Track for later deletion
                    $Script:AllLegacyFieldsFound += @{
                        Name   = $LegacyName
                        Id     = $LegacyField.id
                        Value  = $Value
                        NewFieldName = $Field.Name
                    }
                }
            }

            $NewFieldExists = $MatchingFields | Where-Object { $_.IsNew } | Select-Object -First 1
            $LegacyFieldsExist = $MatchingFields | Where-Object { -not $_.IsNew }

            if ($NewFieldExists -or $LegacyFieldsExist.Count -gt 0) {
                # AutoCreate fields are handled silently - just ensure field exists
                if ($Field.AutoCreate) {
                    if ($NewFieldExists) {
                        Write-LevelInfo "Field '$($Field.Name)' already exists"
                    }
                    else {
                        # Create the new field silently
                        Write-LevelInfo "Creating field '$($Field.Name)' (auto-created)..."
                        $Created = New-CustomField -Name $Field.Name -DefaultValue "" -AdminOnly $Field.AdminOnly
                        if ($Created) {
                            Write-LevelSuccess "Created: $($Field.Name)"
                            $ExistingFields += $Created
                        }
                    }
                    continue
                }

                # Fields exist - show all matching fields and let user choose
                Write-Host ""
                Write-Host "Field: $($Field.Name)" -ForegroundColor Cyan
                Write-Host "  Description: $($Field.Description)"

                # Show all fields found (new + legacy)
                Write-Host ""
                Write-Host "  Existing fields found:" -ForegroundColor White
                foreach ($Match in $MatchingFields) {
                    $FieldType = if ($Match.IsNew) { "(current)" } else { "(legacy)" }
                    $DisplayValue = if ([string]::IsNullOrWhiteSpace($Match.Value)) { "(empty)" } else { $Match.Value }
                    $Color = if ($Match.IsNew) { "Green" } else { "Yellow" }
                    Write-Host "    $($Match.Name) $FieldType = $DisplayValue" -ForegroundColor $Color
                }

                # Get fields with values
                $FieldsWithValues = @($MatchingFields | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Value) })

                Write-Host ""
                Write-Host "  Choose which value to use:" -ForegroundColor Cyan
                $Index = 1
                $DefaultChoice = "N"
                foreach ($Match in $FieldsWithValues) {
                    $Marker = if ($Match.IsNew) { " (current)" } else { "" }
                    Write-Host "    [$Index] $($Match.Value) (from $($Match.Name))$Marker" -ForegroundColor White
                    if ($Index -eq 1) { $DefaultChoice = "1" }
                    $Index++
                }
                Write-Host "    [N] Enter a new value" -ForegroundColor Yellow
                if ($NewFieldExists -and -not [string]::IsNullOrWhiteSpace($NewFieldExists.Value)) {
                    Write-Host "    [K] Keep current value ($($NewFieldExists.Value))" -ForegroundColor Yellow
                    Write-Host "    [D] Delete/clear the global value" -ForegroundColor Red
                }
                Write-Host ""

                $Choice = Read-UserInput -Prompt "  Select option" -Default $DefaultChoice

                if ($Choice.ToUpper() -eq "N") {
                    $NewValue = Read-UserInput -Prompt "  Enter value" -Default $Field.Default

                    if ($NewFieldExists) {
                        if (-not [string]::IsNullOrWhiteSpace($NewValue) -and $NewValue -ne $NewFieldExists.Value) {
                            if (Update-CustomFieldValue -FieldId $NewFieldExists.Id -Value $NewValue) {
                                Write-LevelSuccess "Updated value to: $NewValue"
                            }
                        }
                    }
                    else {
                        Write-LevelInfo "Creating new field '$($Field.Name)'..."
                        $Created = New-CustomField -Name $Field.Name -DefaultValue $NewValue -AdminOnly $Field.AdminOnly
                        if ($Created -and -not [string]::IsNullOrWhiteSpace($NewValue)) {
                            if ([string]::IsNullOrWhiteSpace($Created.default_value)) {
                                if (Update-CustomFieldValue -FieldId $Created.id -Value $NewValue) {
                                    Write-LevelSuccess "Set value: $NewValue"
                                }
                            }
                        }
                        if ($Created) {
                            $ExistingFields += $Created
                        }
                    }
                }
                elseif ($Choice.ToUpper() -eq "K" -and $NewFieldExists) {
                    Write-LevelInfo "Keeping current value: $($NewFieldExists.Value)"
                }
                elseif ($Choice.ToUpper() -eq "D" -and $NewFieldExists) {
                    Write-LevelInfo "Clearing value for field $($NewFieldExists.Name)..."
                    $RecreatedField = Remove-CustomFieldValue -FieldId $NewFieldExists.Id -FieldName $Field.Name -AdminOnly $Field.AdminOnly
                    if ($RecreatedField) {
                        Write-LevelSuccess "Field value cleared"
                        # Update ExistingFields with the new field ID
                        $ExistingFields = @($ExistingFields | Where-Object { $_.id -ne $NewFieldExists.Id })
                        $ExistingFields += $RecreatedField
                    }
                    else {
                        Write-LevelWarning "Could not clear field value"
                    }
                }
                elseif ($Choice -match '^\d+$') {
                    $ChoiceInt = [int]$Choice
                    if ($ChoiceInt -ge 1 -and $ChoiceInt -le $FieldsWithValues.Count) {
                        $SelectedField = $FieldsWithValues[$ChoiceInt - 1]
                        if ($SelectedField -and -not [string]::IsNullOrWhiteSpace($SelectedField.Value)) {
                            $SelectedValue = $SelectedField.Value

                            if ($NewFieldExists) {
                                if ($SelectedValue -ne $NewFieldExists.Value) {
                                    if (Update-CustomFieldValue -FieldId $NewFieldExists.Id -Value $SelectedValue) {
                                        Write-LevelSuccess "Updated value to: $SelectedValue"
                                    }
                                }
                                else {
                                    Write-LevelInfo "Value unchanged: $SelectedValue"
                                }
                            }
                            else {
                                Write-LevelInfo "Creating new field '$($Field.Name)'..."
                                $Created = New-CustomField -Name $Field.Name -DefaultValue $SelectedValue -AdminOnly $Field.AdminOnly
                                if ($Created -and -not [string]::IsNullOrWhiteSpace($SelectedValue)) {
                                    if ([string]::IsNullOrWhiteSpace($Created.default_value)) {
                                        if (Update-CustomFieldValue -FieldId $Created.id -Value $SelectedValue) {
                                            Write-LevelSuccess "Migrated value: $SelectedValue"
                                        }
                                    }
                                }
                                if ($Created) {
                                    $ExistingFields += $Created
                                }
                            }
                        }
                        else {
                            Write-LevelWarning "Selected field has no value."
                        }
                    }
                    else {
                        Write-LevelWarning "Invalid selection."
                    }
                }
            }
            else {
                # Field doesn't exist
                if ($Field.AutoCreate) {
                    # Auto-create silently without prompting
                    Write-LevelInfo "Creating field '$($Field.Name)' (auto-created)..."
                    $Created = New-CustomField -Name $Field.Name -DefaultValue "" -AdminOnly $Field.AdminOnly
                    if ($Created) {
                        Write-LevelSuccess "Created: $($Field.Name)"
                        $ExistingFields += $Created
                    }
                }
                else {
                    # Ask if user wants to create it
                    Write-Host ""
                    Write-Host "Field: $($Field.Name)" -ForegroundColor Cyan
                    Write-Host "  Description: $($Field.Description)"
                    if ($Field.Help) {
                        Write-Host "  Help: $($Field.Help)" -ForegroundColor DarkGray
                    }
                    if ($Field.AdminOnly) {
                        Write-Host "  Admin Only: Yes (values hidden from non-admins)" -ForegroundColor Yellow
                    }
                    Write-Host ""

                    if (Read-YesNo -Prompt "  Create this field" -Default $true) {
                        $PromptText = if ($Field.Prompt) { "  $($Field.Prompt)" } else { "  Default value" }
                        $DefaultValue = Read-UserInput -Prompt $PromptText -Default $Field.Default

                        $Created = New-CustomField -Name $Field.Name -DefaultValue $DefaultValue -AdminOnly $Field.AdminOnly

                        if ($Created -and -not [string]::IsNullOrWhiteSpace($DefaultValue)) {
                            $CreatedId = $Created.id
                            if ($CreatedId -and [string]::IsNullOrWhiteSpace($Created.default_value)) {
                                Write-LevelInfo "Setting default value..."
                                if (Update-CustomFieldValue -FieldId $CreatedId -Value $DefaultValue) {
                                    Write-LevelSuccess "Set default value to: $DefaultValue"
                                }
                            }
                        }
                        if ($Created) {
                            $ExistingFields += $Created
                        }
                    }
                    else {
                        Write-LevelInfo "Skipped: $($Field.Name)"
                    }
                }
            }
        }
    }
    else {
        Write-LevelInfo "Skipped $DisplayName fields"
    }
}

# ============================================================
# LEGACY FIELD CLEANUP
# ============================================================

# Combine all legacy fields found (from scratch folder + optional fields)
$AllLegacyFields = @()

# Add scratch folder legacy fields
if ($LegacyFieldsToDelete -and $LegacyFieldsToDelete.Count -gt 0) {
    foreach ($LegacyField in $LegacyFieldsToDelete) {
        $AllLegacyFields += @{
            Name         = $LegacyField.Name
            Id           = $LegacyField.Id
            Value        = $LegacyField.Value
            NewFieldName = $ScratchFieldDef.Name
        }
    }
}

# Add optional fields legacy fields
if ($Script:AllLegacyFieldsFound -and $Script:AllLegacyFieldsFound.Count -gt 0) {
    $AllLegacyFields += $Script:AllLegacyFieldsFound
}

if ($AllLegacyFields.Count -gt 0) {
    Write-Header "Legacy Field Cleanup"

    Write-Host "The following legacy custom fields were found:" -ForegroundColor Yellow
    Write-Host ""

    foreach ($LegacyField in $AllLegacyFields) {
        $DisplayValue = if ([string]::IsNullOrWhiteSpace($LegacyField.Value)) { "(empty)" } else { $LegacyField.Value }
        Write-Host "  - $($LegacyField.Name)" -ForegroundColor Yellow
        Write-Host "    Value: $DisplayValue" -ForegroundColor DarkGray
        Write-Host "    Migrated to: $($LegacyField.NewFieldName)" -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "These legacy fields are no longer needed if you've updated your scripts" -ForegroundColor White
    Write-Host "to use the new field names (coolforge_*)." -ForegroundColor White
    Write-Host ""
    Write-LevelWarning "Deleting these fields will permanently remove them and their values."
    Write-Host ""

    if (Read-YesNo -Prompt "Delete legacy fields" -Default $false) {
        Write-Host ""
        Write-Host "Select fields to delete:" -ForegroundColor Cyan
        Write-Host "  [A] Delete ALL legacy fields" -ForegroundColor Yellow
        Write-Host "  [S] Select individually" -ForegroundColor Yellow
        Write-Host "  [N] Cancel - don't delete any" -ForegroundColor Yellow
        Write-Host ""

        $DeleteChoice = Read-UserInput -Prompt "Choice" -Default "N"

        if ($DeleteChoice.ToUpper() -eq "A") {
            # Delete all
            Write-Host ""
            foreach ($LegacyField in $AllLegacyFields) {
                Remove-CustomField -FieldId $LegacyField.Id -FieldName $LegacyField.Name
            }
        }
        elseif ($DeleteChoice.ToUpper() -eq "S") {
            # Select individually
            Write-Host ""
            foreach ($LegacyField in $AllLegacyFields) {
                if (Read-YesNo -Prompt "  Delete '$($LegacyField.Name)'" -Default $false) {
                    Remove-CustomField -FieldId $LegacyField.Id -FieldName $LegacyField.Name
                }
                else {
                    Write-LevelInfo "Keeping: $($LegacyField.Name)"
                }
            }
        }
        else {
            Write-LevelInfo "No legacy fields deleted."
        }
    }
    else {
        Write-LevelInfo "Legacy fields preserved. You can delete them manually later."
    }
}

# Summary
Write-Header "Setup Complete"

Write-Host "Your COOLForge_Lib custom fields are configured!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Deploy a launcher script from the 'launchers/' folder"
Write-Host "  2. Or copy 'templates/Launcher_Template.ps1' and customize it"
Write-Host "  3. Test on a single device first"
Write-Host ""
Write-Host "Documentation: https://github.com/coolnetworks/COOLForge"
Write-Host ""

# Show final field status
Write-Host "Custom Fields Status:" -ForegroundColor Cyan

Write-Host "  Core Fields:" -ForegroundColor White
$AllCoreFields = $Script:RequiredFields + $Script:OptionalFields
foreach ($Field in $AllCoreFields) {
    $Existing = Find-CustomField -Name $Field.Name -ExistingFields $ExistingFields
    $Status = if ($Existing) { "[OK]" } else { "[--]" }
    $Color = if ($Existing) { "Green" } else { "DarkGray" }
    Write-Host "    $Status $($Field.Name)" -ForegroundColor $Color
}

# Show status for each enabled field group
foreach ($GroupName in $Script:EnabledGroups.Keys) {
    if ($Script:EnabledGroups[$GroupName]) {
        $DisplayName = if ($Script:FieldGroupDisplayNames[$GroupName]) { $Script:FieldGroupDisplayNames[$GroupName] } else { $GroupName }
        Write-Host "  $DisplayName Fields:" -ForegroundColor White
        foreach ($Field in $Script:FieldGroups[$GroupName]) {
            $Existing = Find-CustomField -Name $Field.Name -ExistingFields $ExistingFields
            $Status = if ($Existing) { "[OK]" } else { "[--]" }
            $Color = if ($Existing) { "Green" } else { "DarkGray" }
            Write-Host "    $Status $($Field.Name)" -ForegroundColor $Color
        }
    }
}

Write-Host ""

# Save configuration for next time (using new key names)
Write-Host ""
if (Read-YesNo -Prompt "Save settings for next time" -Default $true) {
    $ConfigToSave = @{
        CompanyName               = $Script:MspName
        CoolForge_ApiKeyEncrypted = Protect-ApiKey -PlainText $Script:ResolvedApiKey
        LastRun                   = (Get-Date).ToString("o")
    }

    if (Save-Config -Config $ConfigToSave -Path $Script:ConfigPath) {
        Write-LevelSuccess "Settings saved to $Script:ConfigFileName"
        Write-Host "  Note: API key is encrypted and only works on this computer/user." -ForegroundColor DarkGray
    }
}

Write-Host ""
