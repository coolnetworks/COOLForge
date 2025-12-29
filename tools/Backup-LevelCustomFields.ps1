<#
.SYNOPSIS
    Standalone backup and restore tool for Level.io custom fields.

.DESCRIPTION
    This script provides command-line operations for managing Level.io custom field backups:
    - Backup: Create a backup of all custom field values across organizations, folders, and devices
    - Restore: Restore custom field values from a previous backup
    - Compare: Show differences between a backup and current state
    - List: Show all available backup files

    Backups are stored as compressed zip files in the backups/ folder.

.NOTES
    Version:          2025.12.29.01
    Target Platform:  Windows PowerShell 5.1+

    API Documentation: https://levelapi.readme.io/

    Copyright (c) COOLNETWORKS
    https://coolnetworks.au
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge

.PARAMETER Action
    The operation to perform: Backup, Restore, Compare, or List.

.PARAMETER ApiKey
    Level.io API key. If not provided, uses saved config or prompts.

.PARAMETER BackupPath
    Path to a specific backup file. Required for Restore, optional for Compare.
    If not provided for Compare, uses the most recent backup.

.PARAMETER BackupsFolder
    Base path for the backups folder. Defaults to <repo>/backups/.

.PARAMETER IncludeDevices
    Include device-level custom field values in backup/restore/compare.
    Device-level operations are slower but more complete.

.PARAMETER DryRun
    For Restore action only: Preview changes without applying them.

.EXAMPLE
    .\Backup-LevelCustomFields.ps1 -Action Backup

    Creates a backup of all organization and folder custom fields.

.EXAMPLE
    .\Backup-LevelCustomFields.ps1 -Action Backup -IncludeDevices

    Creates a full backup including device-level custom fields.

.EXAMPLE
    .\Backup-LevelCustomFields.ps1 -Action Restore -BackupPath .\backups\customfields_2025-12-29_120000.zip

    Restores custom field values from the specified backup.

.EXAMPLE
    .\Backup-LevelCustomFields.ps1 -Action Restore -DryRun

    Shows what would be restored from the latest backup without applying changes.

.EXAMPLE
    .\Backup-LevelCustomFields.ps1 -Action Compare

    Compares the latest backup with current custom field values.

.EXAMPLE
    .\Backup-LevelCustomFields.ps1 -Action List

    Lists all available backup files.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("Backup", "Restore", "Compare", "List")]
    [string]$Action,

    [Parameter(Mandatory = $false)]
    [string]$ApiKey,

    [Parameter(Mandatory = $false)]
    [string]$BackupPath,

    [Parameter(Mandatory = $false)]
    [string]$BackupsFolder,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeDevices,

    [Parameter(Mandatory = $false)]
    [switch]$DryRun
)

# ============================================================
# IMPORT SHARED MODULE
# ============================================================

$ModulePath = Join-Path $PSScriptRoot "LevelLib-CustomFields.psm1"
if (-not (Test-Path $ModulePath)) {
    Write-Host "[X] Module not found: $ModulePath" -ForegroundColor Red
    Write-Host "    Please ensure LevelLib-CustomFields.psm1 is in the same folder as this script." -ForegroundColor Yellow
    exit 1
}
Import-Module $ModulePath -Force

# ============================================================
# CONFIGURATION
# ============================================================

$Script:ConfigPath = Join-Path $PSScriptRoot ".levellib-setup.json"
$Script:ResolvedApiKey = $null

# Default backups folder to repo root's backups folder
if ([string]::IsNullOrWhiteSpace($BackupsFolder)) {
    $BackupsFolder = Join-Path (Split-Path $PSScriptRoot -Parent) "backups"
}

# ============================================================
# API KEY RESOLUTION
# ============================================================

function Resolve-ApiKey {
    <#
    .SYNOPSIS
        Resolves the API key from parameter, saved config, or user prompt.
    #>

    # Check parameter first
    if (-not [string]::IsNullOrWhiteSpace($Script:ApiKey)) {
        return $Script:ApiKey
    }

    # Check saved config
    $SavedConfig = Get-SavedConfig -Path $Script:ConfigPath
    if ($SavedConfig -and $SavedConfig.ApiKeyEncrypted) {
        $DecryptedKey = Unprotect-ApiKey -EncryptedText $SavedConfig.ApiKeyEncrypted
        if ($DecryptedKey) {
            Write-LevelInfo "Using saved API key."
            return $DecryptedKey
        }
    }

    # Prompt user
    Write-Host "Enter your Level.io API key: " -NoNewline -ForegroundColor Yellow
    $SecureKey = Read-Host -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureKey)
    $Key = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

    return $Key
}

# ============================================================
# ACTION HANDLERS
# ============================================================

function Invoke-BackupAction {
    <#
    .SYNOPSIS
        Creates a backup of all custom fields.
    #>
    Write-Header "Creating Backup"

    Write-LevelInfo "Backing up custom fields..."
    if ($IncludeDevices) {
        Write-LevelInfo "Including device-level values (this may take a while)..."
    }

    $Backup = Backup-AllCustomFields -IncludeDevices:$IncludeDevices
    $Path = Get-BackupPath -BasePath $BackupsFolder

    if (Save-Backup -Backup $Backup -Path $Path) {
        $ZipPath = $Path -replace '\.json$', '.zip'
        Write-LevelSuccess "Backup saved to: $ZipPath"

        # Count what was backed up
        $OrgCount = $Backup.Organizations.Count
        $FolderCount = ($Backup.Organizations | ForEach-Object { $_.Folders.Count } | Measure-Object -Sum).Sum
        $DeviceCount = 0
        if ($IncludeDevices) {
            $DeviceCount = ($Backup.Organizations | ForEach-Object { $_.Folders | ForEach-Object { $_.Devices.Count } } | Measure-Object -Sum).Sum
        }

        Write-Host ""
        Write-Host "Backup Summary:" -ForegroundColor Cyan
        Write-Host "  Organizations: $OrgCount"
        Write-Host "  Folders: $FolderCount"
        if ($IncludeDevices) {
            Write-Host "  Devices: $DeviceCount"
        }
    }
    else {
        Write-LevelError "Backup failed."
        exit 1
    }
}

function Invoke-RestoreAction {
    <#
    .SYNOPSIS
        Restores custom fields from a backup.
    #>
    Write-Header "Restoring from Backup"

    # Determine which backup to use
    $RestorePath = $BackupPath
    if ([string]::IsNullOrWhiteSpace($RestorePath)) {
        $RestorePath = Get-LatestBackup -BasePath $BackupsFolder
        if (-not $RestorePath) {
            Write-LevelError "No backups found in: $BackupsFolder"
            exit 1
        }
        Write-LevelInfo "Using latest backup: $(Split-Path $RestorePath -Leaf)"
    }

    if (-not (Test-Path $RestorePath)) {
        Write-LevelError "Backup file not found: $RestorePath"
        exit 1
    }

    $Backup = Import-Backup -Path $RestorePath
    if (-not $Backup) {
        Write-LevelError "Failed to load backup."
        exit 1
    }

    # Check if backup includes devices
    $BackupHasDevices = ($Backup.Organizations | ForEach-Object { $_.Folders | ForEach-Object { $_.Devices.Count } } | Measure-Object -Sum).Sum -gt 0
    $RestoreDevices = $IncludeDevices -and $BackupHasDevices

    if ($DryRun) {
        Write-Host ""
        Write-Host "Preview of changes (dry run):" -ForegroundColor Cyan
        Write-Host ""
    }

    Restore-CustomFields -Backup $Backup -DryRun:$DryRun -IncludeDevices:$RestoreDevices

    if (-not $DryRun) {
        Write-Host ""
        Write-LevelSuccess "Restore complete!"
    }
}

function Invoke-CompareAction {
    <#
    .SYNOPSIS
        Compares a backup with current state.
    #>
    Write-Header "Comparing Backup with Current State"

    # Determine which backup to use
    $ComparePath = $BackupPath
    if ([string]::IsNullOrWhiteSpace($ComparePath)) {
        $ComparePath = Get-LatestBackup -BasePath $BackupsFolder
        if (-not $ComparePath) {
            Write-LevelError "No backups found in: $BackupsFolder"
            exit 1
        }
        Write-LevelInfo "Using latest backup: $(Split-Path $ComparePath -Leaf)"
    }

    if (-not (Test-Path $ComparePath)) {
        Write-LevelError "Backup file not found: $ComparePath"
        exit 1
    }

    $Backup = Import-Backup -Path $ComparePath
    if (-not $Backup) {
        Write-LevelError "Failed to load backup."
        exit 1
    }

    # Check if backup includes devices
    $BackupHasDevices = ($Backup.Organizations | ForEach-Object { $_.Folders | ForEach-Object { $_.Devices.Count } } | Measure-Object -Sum).Sum -gt 0
    $CompareDevices = $IncludeDevices -and $BackupHasDevices

    $Differences = Compare-BackupWithCurrent -Backup $Backup -IncludeDevices:$CompareDevices
    Show-BackupDifferences -Differences $Differences

    if ($Differences.Count -gt 0) {
        Write-Host ""
        if (Read-YesNo -Prompt "Would you like to restore from this backup" -Default $false) {
            Write-Host ""
            Write-Host "Preview of changes:" -ForegroundColor Cyan
            Restore-CustomFields -Backup $Backup -DryRun -IncludeDevices:$CompareDevices

            Write-Host ""
            if (Read-YesNo -Prompt "Apply these changes" -Default $false) {
                Restore-CustomFields -Backup $Backup -IncludeDevices:$CompareDevices
                Write-LevelSuccess "Restore complete!"
            }
            else {
                Write-LevelInfo "Restore cancelled."
            }
        }
    }
}

function Invoke-ListAction {
    <#
    .SYNOPSIS
        Lists available backup files.
    #>
    Write-Header "Available Backups"

    if (-not (Test-Path $BackupsFolder)) {
        Write-LevelInfo "No backups folder found: $BackupsFolder"
        return
    }

    $Backups = Get-ChildItem -Path $BackupsFolder -Filter "customfields_*.zip" |
        Sort-Object LastWriteTime -Descending

    if ($Backups.Count -eq 0) {
        Write-LevelInfo "No backup files found."
        return
    }

    Write-Host ""
    Write-Host "Backups folder: $BackupsFolder" -ForegroundColor DarkGray
    Write-Host ""

    $Index = 1
    foreach ($B in $Backups) {
        $SizeKB = [math]::Round($B.Length / 1KB, 1)
        $Age = (Get-Date) - $B.LastWriteTime

        $AgeText = if ($Age.TotalDays -lt 1) {
            "{0:N0} hours ago" -f $Age.TotalHours
        }
        elseif ($Age.TotalDays -lt 7) {
            "{0:N0} days ago" -f $Age.TotalDays
        }
        else {
            $B.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
        }

        $LatestMarker = if ($Index -eq 1) { " (latest)" } else { "" }

        Write-Host "  [$Index] $($B.Name)$LatestMarker" -ForegroundColor White
        Write-Host "      $AgeText, $SizeKB KB" -ForegroundColor DarkGray
        $Index++
    }

    Write-Host ""
    Write-Host "Use -BackupPath to specify a backup for Restore or Compare actions." -ForegroundColor DarkGray
}

# ============================================================
# MAIN SCRIPT
# ============================================================

# List action doesn't need API key
if ($Action -eq "List") {
    Invoke-ListAction
    exit 0
}

# All other actions need API key
$Script:ResolvedApiKey = Resolve-ApiKey

if ([string]::IsNullOrWhiteSpace($Script:ResolvedApiKey)) {
    Write-LevelError "API key is required. Exiting."
    exit 1
}

# Initialize the module
Initialize-LevelLibCustomFields -ApiKey $Script:ResolvedApiKey | Out-Null

# Test API connection
Write-LevelInfo "Testing API connection..."
$TestFields = Get-ExistingCustomFields
if ($null -eq $TestFields) {
    Write-LevelError "Could not connect to Level.io API. Please check your API key."
    exit 1
}
Write-LevelSuccess "Connected to Level.io API."

# Execute the requested action
switch ($Action) {
    "Backup" {
        Invoke-BackupAction
    }
    "Restore" {
        Invoke-RestoreAction
    }
    "Compare" {
        Invoke-CompareAction
    }
}

Write-Host ""
