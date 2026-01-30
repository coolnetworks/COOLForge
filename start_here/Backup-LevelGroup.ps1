<#
.SYNOPSIS
    Backs up a Level.io group hierarchy including subgroups and custom field values.

.DESCRIPTION
    This script creates a complete backup of a specified group and all its subgroups,
    capturing:
    - Group hierarchy structure (parent/child relationships)
    - Custom field values at each group level
    - Group names for reference

    The backup can later be restored using Restore-LevelGroup.ps1 to recreate
    the hierarchy with a new base name.

.NOTES
    Version:          2026.01.13.01
    Target Platform:  Windows PowerShell 5.1+

    API Documentation: https://levelapi.readme.io/

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge

.EXAMPLE
    .\Backup-LevelGroup.ps1 -GroupName "TEMPLATEGROUP"

    Backs up the TEMPLATEGROUP and all subgroups to a timestamped file.

.EXAMPLE
    .\Backup-LevelGroup.ps1 -GroupName "TEMPLATEGROUP" -ApiKey "your-api-key"

    Backs up with API key provided (skips the prompt).

.EXAMPLE
    .\Backup-LevelGroup.ps1 -GroupName "TEMPLATEGROUP" -OutputPath "C:\Backups\template.json"

    Backs up to a specific file path.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$GroupName,

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
$Script:LevelApiBaseUrl = "https://api.level.io/v2"
$Script:ResolvedApiKey = $null

# ============================================================
# HELPER FUNCTIONS
# ============================================================

function Get-GroupHierarchy {
    <#
    .SYNOPSIS
        Recursively builds the group hierarchy starting from a root group.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupId,

        [Parameter(Mandatory = $true)]
        [array]$AllGroups,

        [Parameter(Mandatory = $false)]
        [int]$Depth = 0
    )

    $Group = $AllGroups | Where-Object { $_.id -eq $GroupId }
    if (-not $Group) {
        return $null
    }

    $Indent = "  " * $Depth
    Write-Host "${Indent}Processing: $($Group.name)" -ForegroundColor DarkGray

    # Get custom field values for this group
    $CustomFields = Get-LevelEntityCustomFields -ApiKey $Script:ResolvedApiKey -EntityType "folder" -EntityId $GroupId

    $GroupBackup = @{
        Id           = $Group.id
        Name         = $Group.name
        ParentId     = $Group.parent_id
        CustomFields = $CustomFields
        Children     = @()
        Depth        = $Depth
    }

    # Find and process all child groups
    $ChildGroups = $AllGroups | Where-Object { $_.parent_id -eq $GroupId }
    foreach ($Child in $ChildGroups) {
        $ChildBackup = Get-GroupHierarchy -GroupId $Child.id -AllGroups $AllGroups -Depth ($Depth + 1)
        if ($ChildBackup) {
            $GroupBackup.Children += $ChildBackup
        }
    }

    return $GroupBackup
}

function Get-GroupStats {
    <#
    .SYNOPSIS
        Counts total groups and custom fields in a backup.
    #>
    param([hashtable]$GroupBackup)

    $Stats = @{
        GroupCount       = 1
        CustomFieldCount = 0
    }

    if ($GroupBackup.CustomFields) {
        $Props = $GroupBackup.CustomFields.PSObject.Properties
        if ($Props) {
            $Stats.CustomFieldCount = ($Props | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Value) }).Count
        }
    }

    foreach ($Child in $GroupBackup.Children) {
        $ChildStats = Get-GroupStats -GroupBackup $Child
        $Stats.GroupCount += $ChildStats.GroupCount
        $Stats.CustomFieldCount += $ChildStats.CustomFieldCount
    }

    return $Stats
}

# ============================================================
# MAIN SCRIPT
# ============================================================

Write-Header "Level.io Group Backup"

Write-Host "This tool backs up a group hierarchy including all subgroups and custom field values."
Write-Host "The backup can be restored with a new base name using Restore-LevelGroup.ps1."
Write-Host ""

# Load saved configuration for API key
$SavedConfig = Get-SavedConfig -Path $Script:ConfigPath

# Get API Key - check parameter, then saved config, then prompt
if (-not [string]::IsNullOrWhiteSpace($ApiKey)) {
    $Script:ResolvedApiKey = $ApiKey
}
elseif ($SavedConfig -and $SavedConfig.CoolForge_ApiKeyEncrypted) {
    $DecryptedKey = Unprotect-ApiKey -EncryptedText $SavedConfig.CoolForge_ApiKeyEncrypted
    if ($DecryptedKey) {
        Write-LevelInfo "Using saved API key."
        $Script:ResolvedApiKey = $DecryptedKey
    }
}
elseif ($SavedConfig -and $SavedConfig.ApiKeyEncrypted) {
    $DecryptedKey = Unprotect-ApiKey -EncryptedText $SavedConfig.ApiKeyEncrypted
    if ($DecryptedKey) {
        Write-LevelInfo "Using saved API key."
        $Script:ResolvedApiKey = $DecryptedKey
    }
}

if ([string]::IsNullOrWhiteSpace($Script:ResolvedApiKey)) {
    Write-Host ""
    Write-Host "Get your API key at: https://app.level.io/api-keys" -ForegroundColor Cyan
    Write-Host ""
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

# Test API connection
Write-Header "Testing API Connection"

Write-Host "Connecting to Level.io API..." -ForegroundColor DarkGray
$AllGroups = Get-LevelGroups -ApiKey $Script:ResolvedApiKey -BaseUrl $Script:LevelApiBaseUrl

if ($null -eq $AllGroups) {
    Write-LevelError "Could not connect to Level.io API. Please check your API key."
    exit 1
}

Write-LevelSuccess "Connected! Found $($AllGroups.Count) total groups."

# ============================================================
# SELECT GROUP TO BACKUP
# ============================================================

Write-Header "Select Group to Backup"

if ([string]::IsNullOrWhiteSpace($GroupName)) {
    Write-Host "Available groups:" -ForegroundColor Cyan
    Write-Host ""

    # Show groups organized by hierarchy
    $RootGroups = $AllGroups | Where-Object { $null -eq $_.parent_id -or $_.parent_id -eq "" }

    function Show-GroupTree {
        param(
            [array]$Groups,
            [string]$ParentId = $null,
            [int]$Indent = 0
        )

        $Children = if ($null -eq $ParentId -or $ParentId -eq "") {
            $Groups | Where-Object { $null -eq $_.parent_id -or $_.parent_id -eq "" }
        } else {
            $Groups | Where-Object { $_.parent_id -eq $ParentId }
        }

        foreach ($Group in $Children) {
            $Prefix = "  " * $Indent
            $ChildCount = ($Groups | Where-Object { $_.parent_id -eq $Group.id }).Count
            $ChildInfo = if ($ChildCount -gt 0) { " ($ChildCount subgroups)" } else { "" }
            Write-Host "${Prefix}- $($Group.name)$ChildInfo" -ForegroundColor White
            Show-GroupTree -Groups $Groups -ParentId $Group.id -Indent ($Indent + 1)
        }
    }

    Show-GroupTree -Groups $AllGroups
    Write-Host ""

    $GroupName = Read-UserInput -Prompt "Enter the group name to backup" -Default ""

    if ([string]::IsNullOrWhiteSpace($GroupName)) {
        Write-LevelError "No group name provided. Exiting."
        exit 1
    }
}

# Find the group
$TargetGroup = $AllGroups | Where-Object { $_.name -ieq $GroupName } | Select-Object -First 1

if (-not $TargetGroup) {
    Write-LevelError "Group '$GroupName' not found."
    Write-Host ""
    Write-Host "Did you mean one of these?" -ForegroundColor Yellow
    $Similar = $AllGroups | Where-Object { $_.name -like "*$GroupName*" } | Select-Object -First 5
    foreach ($S in $Similar) {
        Write-Host "  - $($S.name)" -ForegroundColor DarkGray
    }
    exit 1
}

Write-LevelSuccess "Found group: $($TargetGroup.name)"
Write-Host "  ID: $($TargetGroup.id)" -ForegroundColor DarkGray
if ($TargetGroup.parent_id) {
    $ParentGroup = $AllGroups | Where-Object { $_.id -eq $TargetGroup.parent_id }
    if ($ParentGroup) {
        Write-Host "  Parent: $($ParentGroup.name)" -ForegroundColor DarkGray
    }
}

# ============================================================
# CREATE BACKUP
# ============================================================

Write-Header "Creating Backup"

Write-Host "Building group hierarchy..." -ForegroundColor DarkGray

$Backup = @{
    Timestamp    = (Get-Date).ToString("o")
    Version      = "1.0"
    SourceGroup  = $GroupName
    SourceId     = $TargetGroup.id
    CustomFields = @()
    Hierarchy    = $null
}

# Get all custom field definitions
Write-Host "Fetching custom field definitions..." -ForegroundColor DarkGray
$CustomFields = Get-LevelCustomFields -ApiKey $Script:ResolvedApiKey -BaseUrl $Script:LevelApiBaseUrl
$Backup.CustomFields = $CustomFields

# Build the hierarchy recursively
$Backup.Hierarchy = Get-GroupHierarchy -GroupId $TargetGroup.id -AllGroups $AllGroups

# Get stats
$Stats = Get-GroupStats -GroupBackup $Backup.Hierarchy

Write-Host ""
Write-LevelSuccess "Backup created!"
Write-Host "  Groups: $($Stats.GroupCount)" -ForegroundColor DarkGray
Write-Host "  Custom field values: $($Stats.CustomFieldCount)" -ForegroundColor DarkGray

# ============================================================
# SAVE BACKUP
# ============================================================

Write-Header "Save Backup"

# Determine output path
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $BackupsFolder = Join-Path (Split-Path $PSScriptRoot -Parent) "backups"
    if (-not (Test-Path $BackupsFolder)) {
        New-Item -ItemType Directory -Path $BackupsFolder -Force | Out-Null
    }

    $SafeGroupName = $GroupName -replace '[<>:"/\\|?*]', '_'
    $Timestamp = (Get-Date).ToString("yyyy-MM-dd_HHmmss")
    $OutputPath = Join-Path $BackupsFolder "group_${SafeGroupName}_${Timestamp}.json"
}

# Save the backup
try {
    $JsonContent = $Backup | ConvertTo-Json -Depth 20
    $JsonContent | Set-Content -Path $OutputPath -Encoding UTF8 -ErrorAction Stop

    # Compress to zip
    $ZipPath = $OutputPath -replace '\.json$', '.zip'
    Compress-Archive -Path $OutputPath -DestinationPath $ZipPath -Force -ErrorAction Stop
    Remove-Item $OutputPath -Force -ErrorAction SilentlyContinue

    Write-LevelSuccess "Backup saved to: $ZipPath"
}
catch {
    Write-LevelError "Failed to save backup: $($_.Exception.Message)"
    exit 1
}

# ============================================================
# SUMMARY
# ============================================================

Write-Header "Backup Complete"

Write-Host "Group hierarchy backed up successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Backup file: $ZipPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "To restore this backup with a new name, run:" -ForegroundColor White
Write-Host "  .\Restore-LevelGroup.ps1 -BackupPath `"$ZipPath`" -NewGroupName `"NEWNAME`"" -ForegroundColor DarkGray
Write-Host ""
