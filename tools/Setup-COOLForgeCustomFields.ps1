<#
.SYNOPSIS
    Interactive setup script for COOLForgeLib custom fields in Level.io.

.DESCRIPTION
    This script helps you configure the required custom fields for COOLForgeLib in your
    Level.io account. It will:

    1. Authenticate with the Level.io API using your API key
    2. Check which custom fields already exist
    3. Create any missing required fields
    4. Optionally set default values for fields
    5. Suggest pinning to the current version for stability

    REQUIRED CUSTOM FIELDS:
    - msp_scratch_folder      : Persistent storage folder on endpoints (REQUIRED)

    OPTIONAL CUSTOM FIELDS:
    - ps_module_library_source : Custom library URL (defaults to official repo)
    - pin_psmodule_to_version  : Pin to specific version tag
    - screenconnect_instance_id: Your MSP's ScreenConnect instance ID
    - is_screenconnect_server  : Mark ScreenConnect server devices

.NOTES
    Version:          2025.12.29.02
    Target Platform:  Windows PowerShell 5.1+

    API Documentation: https://levelapi.readme.io/

    Copyright (c) COOLNETWORKS
    https://coolnetworks.au
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

$ModulePath = Join-Path $PSScriptRoot "COOLForge-CustomFields.psm1"
if (-not (Test-Path $ModulePath)) {
    Write-Host "[X] Module not found: $ModulePath" -ForegroundColor Red
    Write-Host "    Please ensure COOLForge-CustomFields.psm1 is in the same folder as this script." -ForegroundColor Yellow
    exit 1
}
Import-Module $ModulePath -Force

# ============================================================
# CONFIGURATION
# ============================================================

$Script:ConfigFileName = ".COOLForgeLib-setup.json"
$Script:ConfigPath = Join-Path $PSScriptRoot $Script:ConfigFileName

# MSP name (set after prompting user)
$Script:MspName = ""
$Script:SavedConfig = $null
$Script:ResolvedApiKey = $null

# Define the custom fields we need (Default for msp_scratch_folder is set dynamically after MSP name prompt)
$Script:RequiredFields = @(
    @{
        Name        = "msp_scratch_folder"
        Description = "Persistent storage folder for MSP scripts and libraries"
        Required    = $true
        Default     = ""  # Set dynamically based on MSP name
        AdminOnly   = $false
    }
)

$Script:OptionalFields = @(
    @{
        Name        = "ps_module_library_source"
        Description = "URL to download COOLForge-Common.psm1 library (leave empty for official repo)"
        Required    = $false
        Default     = ""
        AdminOnly   = $false
    },
    @{
        Name        = "pin_psmodule_to_version"
        Description = "Pin scripts to a specific version tag (e.g., v2025.12.29)"
        Required    = $false
        Default     = ""
        AdminOnly   = $false
    },
    @{
        Name        = "screenconnect_instance_id"
        Description = "Your MSP's ScreenConnect instance ID for whitelisting"
        Required    = $false
        Default     = ""
        AdminOnly   = $true
    },
    @{
        Name        = "is_screenconnect_server"
        Description = "Set to 'true' on devices hosting ScreenConnect server"
        Required    = $false
        Default     = ""
        AdminOnly   = $false
    }
)

# ============================================================
# MAIN SCRIPT
# ============================================================

Write-Header "COOLForgeLib Custom Fields Setup"

Write-Host "This wizard will help you configure the custom fields required for COOLForgeLib."
Write-Host "You'll need a Level.io API key with permission to manage custom fields."
Write-Host ""
Write-Host "Get your API key at: https://app.level.io/security" -ForegroundColor Cyan
Write-Host ""

# Load saved configuration
$Script:SavedConfig = Get-SavedConfig -Path $Script:ConfigPath
if ($Script:SavedConfig) {
    Write-LevelInfo "Found saved configuration."
}

# Get API Key - check parameter, then saved config, then prompt
if (-not [string]::IsNullOrWhiteSpace($ApiKey)) {
    $Script:ResolvedApiKey = $ApiKey
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
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
}

if ([string]::IsNullOrWhiteSpace($Script:ResolvedApiKey)) {
    Write-LevelError "API key is required. Exiting."
    exit 1
}

# Initialize the module with API key
Initialize-COOLForgeCustomFields -ApiKey $Script:ResolvedApiKey | Out-Null

# Test API connection
Write-Header "Testing API Connection"

$ExistingFields = Get-ExistingCustomFields
if ($null -eq $ExistingFields) {
    Write-LevelError "Could not connect to Level.io API. Please check your API key."
    exit 1
}

# Handle both array and object with data property
if ($ExistingFields.data) {
    $ExistingFields = $ExistingFields.data
}

$FieldCount = if ($ExistingFields -is [array]) { $ExistingFields.Count } else { 1 }
Write-LevelSuccess "Connected! Found $FieldCount existing custom field(s)."

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

# Check if scratch folder field exists and get its current value
$ScratchFieldInfo = Find-CustomField -Name "msp_scratch_folder" -ExistingFields $ExistingFields
$CurrentScratchFolder = ""
$InferredCompanyName = ""

if ($ScratchFieldInfo) {
    Write-LevelInfo "Checking existing scratch folder configuration..."
    $ScratchDetails = Get-CustomFieldById -FieldId $ScratchFieldInfo.id
    $CurrentScratchFolder = if ($ScratchDetails) { $ScratchDetails.default_value } else { $ScratchFieldInfo.default_value }

    if (-not [string]::IsNullOrWhiteSpace($CurrentScratchFolder)) {
        Write-Host "  Found existing scratch folder: $CurrentScratchFolder"
        $InferredCompanyName = Get-CompanyNameFromPath -Path $CurrentScratchFolder
        if (-not [string]::IsNullOrWhiteSpace($InferredCompanyName)) {
            Write-Host "  Inferred company name: $InferredCompanyName"
        }
    }
}

Write-Host ""
Write-Host "Your company name will be used for the scratch folder path."
Write-Host "Example: 'Contoso' -> C:\ProgramData\Contoso"
Write-Host ""

# Default to: inferred from scratch folder > saved config > "MSP"
$DefaultCompanyName = "MSP"
if (-not [string]::IsNullOrWhiteSpace($InferredCompanyName)) {
    $DefaultCompanyName = $InferredCompanyName
}
elseif ($Script:SavedConfig -and $Script:SavedConfig.CompanyName) {
    $DefaultCompanyName = $Script:SavedConfig.CompanyName
    Write-LevelInfo "Using saved company name: $DefaultCompanyName"
}

$Script:MspName = Read-UserInput -Prompt "Enter your company name" -Default $DefaultCompanyName

# Sanitize MSP name for use in folder path (remove invalid characters, but allow spaces)
$Script:MspName = $Script:MspName -replace '[<>:"/\\|?*]', ''
$Script:MspName = $Script:MspName.Trim()

if ([string]::IsNullOrWhiteSpace($Script:MspName)) {
    $Script:MspName = "MSP"
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

Write-Host ""
Write-Host "Field: msp_scratch_folder" -ForegroundColor Cyan
Write-Host "  Description: Persistent storage folder for MSP scripts and libraries"
Write-Host "  Required: Yes"
Write-Host ""

if ($ScratchFieldInfo) {
    # Field exists - update if value changed
    if ([string]::IsNullOrWhiteSpace($CurrentScratchFolder)) {
        Write-LevelInfo "Field exists but has no default value set."
        Write-LevelInfo "Setting default value to: $FinalScratchFolder"
        if (Update-CustomFieldValue -FieldId $ScratchFieldInfo.id -Value $FinalScratchFolder) {
            Write-LevelSuccess "Set default value to: $FinalScratchFolder"
        }
    }
    elseif ($CurrentScratchFolder -ne $FinalScratchFolder) {
        Write-LevelInfo "Updating default value from '$CurrentScratchFolder' to '$FinalScratchFolder'"
        if (Update-CustomFieldValue -FieldId $ScratchFieldInfo.id -Value $FinalScratchFolder) {
            Write-LevelSuccess "Updated default value to: $FinalScratchFolder"
        }
    }
    else {
        Write-LevelSuccess "Field already configured correctly: $FinalScratchFolder"
    }
}
else {
    # Field doesn't exist - create it
    Write-LevelWarning "Field does not exist - creating it."
    $Created = New-CustomField -Name "msp_scratch_folder" -DefaultValue $FinalScratchFolder -AdminOnly $false

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

foreach ($Field in $Script:OptionalFields) {
    Write-Host ""
    Write-Host "Field: $($Field.Name)" -ForegroundColor Cyan
    Write-Host "  Description: $($Field.Description)"
    if ($Field.AdminOnly) {
        Write-Host "  Admin Only: Yes (values hidden from non-admins)" -ForegroundColor Yellow
    }
    Write-Host ""

    $Existing = Find-CustomField -Name $Field.Name -ExistingFields $ExistingFields

    if ($Existing) {
        # Query the field individually to get its current value
        Write-LevelInfo "Checking current value..."
        $FieldDetails = Get-CustomFieldById -FieldId $Existing.id
        $CurrentValue = if ($FieldDetails) { $FieldDetails.default_value } else { $Existing.default_value }
        $ActualValue = $CurrentValue  # Keep the actual value for logic checks

        if ([string]::IsNullOrWhiteSpace($CurrentValue)) {
            $CurrentValue = "(not set)"
        }
        Write-LevelSuccess "Field already exists!"
        Write-Host "  Current default value: $CurrentValue"

        # Special handling for version pinning
        if ($Field.Name -eq "pin_psmodule_to_version") {
            Write-Host ""
            if (-not [string]::IsNullOrWhiteSpace($ActualValue)) {
                Write-Host "  Currently pinned to: $ActualValue" -ForegroundColor Cyan
            }

            if (Read-YesNo -Prompt "  Would you like to change the version pin" -Default $false) {
                $SelectedVersion = Select-Version -CurrentVersion $ActualValue

                if ($SelectedVersion -ne $ActualValue) {
                    if ([string]::IsNullOrWhiteSpace($SelectedVersion)) {
                        if (Update-CustomFieldValue -FieldId $Existing.id -Value "") {
                            Write-LevelSuccess "Cleared version pin - will use latest from main"
                        }
                    }
                    else {
                        if (Update-CustomFieldValue -FieldId $Existing.id -Value $SelectedVersion) {
                            Write-LevelSuccess "Pinned to version: $SelectedVersion"
                        }
                    }
                }
                else {
                    Write-LevelInfo "Version unchanged: $ActualValue"
                }
            }
        }
        else {
            $NewValue = Read-UserInput -Prompt "  New value (press Enter to keep current)" -Default ""
            if (-not [string]::IsNullOrWhiteSpace($NewValue)) {
                if (Update-CustomFieldValue -FieldId $Existing.id -Value $NewValue) {
                    Write-LevelSuccess "Updated default value to: $NewValue"
                }
            }
        }
    }
    else {
        if (Read-YesNo -Prompt "  Create this field" -Default $false) {
            $DefaultValue = ""

            # Special handling for version pinning
            if ($Field.Name -eq "pin_psmodule_to_version") {
                Write-Host ""
                Write-Host "  TIP: Pinning to a version ensures stability across your fleet." -ForegroundColor Cyan
                $DefaultValue = Select-Version -CurrentVersion ""
            }
            else {
                $DefaultValue = Read-UserInput -Prompt "  Default value" -Default $Field.Default
            }

            $Created = New-CustomField -Name $Field.Name -DefaultValue $DefaultValue -AdminOnly $Field.AdminOnly

            # If we have a default value but the field was created without it, update it separately
            # (some APIs don't accept default_value on creation)
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

# Summary
Write-Header "Setup Complete"

Write-Host "Your COOLForgeLib custom fields are configured!" -ForegroundColor Green
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
$AllFields = $Script:RequiredFields + $Script:OptionalFields
foreach ($Field in $AllFields) {
    $Existing = Find-CustomField -Name $Field.Name -ExistingFields $ExistingFields
    $Status = if ($Existing) { "[OK]" } else { "[--]" }
    $Color = if ($Existing) { "Green" } else { "DarkGray" }
    Write-Host "  $Status $($Field.Name)" -ForegroundColor $Color
}

Write-Host ""

# Save configuration for next time
Write-Host ""
if (Read-YesNo -Prompt "Save settings for next time" -Default $true) {
    $ConfigToSave = @{
        CompanyName     = $Script:MspName
        ApiKeyEncrypted = Protect-ApiKey -PlainText $Script:ResolvedApiKey
        LastRun         = (Get-Date).ToString("o")
    }

    if (Save-Config -Config $ConfigToSave -Path $Script:ConfigPath) {
        Write-LevelSuccess "Settings saved to $Script:ConfigFileName"
        Write-Host "  Note: API key is encrypted and only works on this computer/user." -ForegroundColor DarkGray
    }
}

Write-Host ""
