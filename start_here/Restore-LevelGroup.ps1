<#
.SYNOPSIS
    Restores a Level.io group hierarchy from backup with a new base name.

.DESCRIPTION
    This script restores a group hierarchy from a backup created by Backup-LevelGroup.ps1.
    It will:

    1. Create the group hierarchy with a new base name
    2. For each custom field, prompt how to configure it:
       - Include as default: Set the backed-up value as the default for the new group
       - Inherit from master field: Leave empty to inherit from parent/organization
       - Skip: Don't set any value
    3. Create all subgroups maintaining the original structure

.NOTES
    Version:          2026.01.13.01
    Target Platform:  Windows PowerShell 5.1+

    API Documentation: https://levelapi.readme.io/

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge

.EXAMPLE
    .\Restore-LevelGroup.ps1 -BackupPath ".\backups\group_TEMPLATE_2024-01-01.zip" -NewGroupName "ClientA"

    Restores the backup as a new group hierarchy named "ClientA".

.EXAMPLE
    .\Restore-LevelGroup.ps1 -BackupPath ".\backups\group_TEMPLATE.zip" -NewGroupName "ClientA" -ParentGroupName "Clients"

    Restores under the "Clients" parent group.

.EXAMPLE
    .\Restore-LevelGroup.ps1 -BackupPath ".\backups\group_TEMPLATE.zip" -NewGroupName "ClientA" -NonInteractive

    Restores with all custom fields set to inherit (no prompts).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$BackupPath,

    [Parameter(Mandatory = $false)]
    [string]$NewGroupName,

    [Parameter(Mandatory = $false)]
    [string]$ParentGroupName,

    [Parameter(Mandatory = $false)]
    [string]$ApiKey,

    [Parameter(Mandatory = $false)]
    [switch]$NonInteractive,

    [Parameter(Mandatory = $false)]
    [switch]$DryRun
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

# Track created groups for rollback on error
$Script:CreatedGroups = @()

# Track custom field decisions
$Script:FieldDecisions = @{}

# ============================================================
# HELPER FUNCTIONS
# ============================================================

function New-LevelGroup {
    <#
    .SYNOPSIS
        Creates a new group in Level.io.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [string]$ParentId
    )

    $Body = @{
        name = $Name
    }

    if (-not [string]::IsNullOrWhiteSpace($ParentId)) {
        $Body.parent_id = $ParentId
    }

    $Result = Invoke-LevelApiCall -Uri "$Script:LevelApiBaseUrl/groups" -ApiKey $Script:ResolvedApiKey -Method "POST" -Body $Body

    if ($Result.Success) {
        return $Result.Data
    }
    else {
        Write-LevelError "Failed to create group '$Name': $($Result.Error)"
        return $null
    }
}

function Remove-LevelGroup {
    <#
    .SYNOPSIS
        Deletes a group from Level.io.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupId
    )

    $Result = Invoke-LevelApiCall -Uri "$Script:LevelApiBaseUrl/groups/$GroupId" -ApiKey $Script:ResolvedApiKey -Method "DELETE"
    return $Result.Success
}

function Get-FieldDecision {
    <#
    .SYNOPSIS
        Gets or prompts for a custom field configuration decision.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$FieldName,

        [Parameter(Mandatory = $false)]
        [string]$CurrentValue,

        [Parameter(Mandatory = $false)]
        [string]$GroupName
    )

    # Check if we already have a decision for this field
    if ($Script:FieldDecisions.ContainsKey($FieldName)) {
        return $Script:FieldDecisions[$FieldName]
    }

    if ($NonInteractive) {
        # Default to inherit in non-interactive mode
        $Decision = @{
            Action = "inherit"
            Value  = ""
        }
        $Script:FieldDecisions[$FieldName] = $Decision
        return $Decision
    }

    # Prompt user for decision
    Write-Host ""
    Write-Host "  Custom Field: " -NoNewline -ForegroundColor Cyan
    Write-Host $FieldName -ForegroundColor White

    if (-not [string]::IsNullOrWhiteSpace($CurrentValue)) {
        Write-Host "  Backup value: " -NoNewline -ForegroundColor DarkGray
        Write-Host $CurrentValue -ForegroundColor Yellow
    }
    else {
        Write-Host "  Backup value: (empty)" -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "  How should this field be configured for ALL new groups?" -ForegroundColor White
    Write-Host "    [D] Include as Default - Set the backup value as default" -ForegroundColor Green
    Write-Host "    [I] Inherit - Leave empty to inherit from parent/organization" -ForegroundColor Yellow
    Write-Host "    [C] Custom - Enter a different value" -ForegroundColor Cyan
    Write-Host "    [S] Skip - Don't configure this field" -ForegroundColor DarkGray
    Write-Host ""

    $Choice = Read-UserInput -Prompt "  Choice" -Default "I"

    $Decision = @{
        Action = "inherit"
        Value  = ""
    }

    switch ($Choice.ToUpper()) {
        "D" {
            $Decision.Action = "default"
            $Decision.Value = $CurrentValue
            Write-LevelInfo "  Will set to: $CurrentValue"
        }
        "I" {
            $Decision.Action = "inherit"
            Write-LevelInfo "  Will inherit from parent"
        }
        "C" {
            $CustomValue = Read-UserInput -Prompt "  Enter custom value" -Default ""
            $Decision.Action = "custom"
            $Decision.Value = $CustomValue
            Write-LevelInfo "  Will set to: $CustomValue"
        }
        "S" {
            $Decision.Action = "skip"
            Write-LevelInfo "  Will skip this field"
        }
        default {
            $Decision.Action = "inherit"
            Write-LevelInfo "  Will inherit from parent"
        }
    }

    # Remember this decision for all groups
    $Script:FieldDecisions[$FieldName] = $Decision
    return $Decision
}

function Restore-GroupHierarchy {
    <#
    .SYNOPSIS
        Recursively restores the group hierarchy.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$GroupBackup,

        [Parameter(Mandatory = $false)]
        [string]$ParentId,

        [Parameter(Mandatory = $true)]
        [string]$NewBaseName,

        [Parameter(Mandatory = $true)]
        [string]$OriginalBaseName,

        [Parameter(Mandatory = $false)]
        [int]$Depth = 0
    )

    $Indent = "  " * $Depth

    # Calculate the new name
    # If this is the root group, use NewBaseName directly
    # Otherwise, replace the original base name prefix with the new one
    if ($Depth -eq 0) {
        $NewName = $NewBaseName
    }
    else {
        # For subgroups, keep the relative naming
        $NewName = $GroupBackup.Name
    }

    Write-Host "${Indent}Creating: $NewName" -ForegroundColor DarkGray

    if ($DryRun) {
        Write-Host "${Indent}  [DRY-RUN] Would create group: $NewName" -ForegroundColor Yellow

        # Still process custom fields for decisions
        if ($GroupBackup.CustomFields) {
            $Props = $GroupBackup.CustomFields.PSObject.Properties
            foreach ($Prop in $Props) {
                if (-not [string]::IsNullOrWhiteSpace($Prop.Value)) {
                    $Decision = Get-FieldDecision -FieldName $Prop.Name -CurrentValue $Prop.Value -GroupName $NewName
                    if ($Decision.Action -ne "skip" -and $Decision.Action -ne "inherit") {
                        Write-Host "${Indent}  [DRY-RUN] Would set $($Prop.Name) = $($Decision.Value)" -ForegroundColor Yellow
                    }
                }
            }
        }

        # Process children
        foreach ($Child in $GroupBackup.Children) {
            Restore-GroupHierarchy -GroupBackup $Child -ParentId "dry-run-id" `
                -NewBaseName $NewBaseName -OriginalBaseName $OriginalBaseName -Depth ($Depth + 1)
        }

        return @{ Id = "dry-run-id"; Name = $NewName }
    }

    # Create the group
    $NewGroup = New-LevelGroup -Name $NewName -ParentId $ParentId

    if (-not $NewGroup) {
        Write-LevelError "${Indent}Failed to create group: $NewName"
        return $null
    }

    $Script:CreatedGroups += @{
        Id   = $NewGroup.id
        Name = $NewName
    }

    Write-LevelSuccess "${Indent}Created: $NewName (ID: $($NewGroup.id))"

    # Configure custom fields
    if ($GroupBackup.CustomFields) {
        $Props = $GroupBackup.CustomFields.PSObject.Properties
        foreach ($Prop in $Props) {
            if (-not [string]::IsNullOrWhiteSpace($Prop.Value)) {
                $Decision = Get-FieldDecision -FieldName $Prop.Name -CurrentValue $Prop.Value -GroupName $NewName

                if ($Decision.Action -eq "default" -or $Decision.Action -eq "custom") {
                    $ValueToSet = $Decision.Value
                    if (-not [string]::IsNullOrWhiteSpace($ValueToSet)) {
                        $SetResult = Set-LevelCustomFieldValue -ApiKey $Script:ResolvedApiKey `
                            -EntityType "folder" -EntityId $NewGroup.id `
                            -FieldReference $Prop.Name -Value $ValueToSet

                        if ($SetResult) {
                            Write-Host "${Indent}  Set: $($Prop.Name) = $ValueToSet" -ForegroundColor DarkGray
                        }
                    }
                }
            }
        }
    }

    # Process children recursively
    foreach ($Child in $GroupBackup.Children) {
        $ChildResult = Restore-GroupHierarchy -GroupBackup $Child -ParentId $NewGroup.id `
            -NewBaseName $NewBaseName -OriginalBaseName $OriginalBaseName -Depth ($Depth + 1)

        if (-not $ChildResult) {
            Write-LevelWarning "${Indent}Failed to create child group: $($Child.Name)"
        }
    }

    return @{
        Id   = $NewGroup.id
        Name = $NewName
    }
}

function Rollback-CreatedGroups {
    <#
    .SYNOPSIS
        Removes all groups created during a failed restore.
    #>

    if ($Script:CreatedGroups.Count -eq 0) {
        return
    }

    Write-Host ""
    Write-LevelWarning "Rolling back created groups..."

    # Delete in reverse order (children first)
    $Reversed = $Script:CreatedGroups | Sort-Object -Descending
    foreach ($Group in $Reversed) {
        Write-Host "  Deleting: $($Group.Name)" -ForegroundColor DarkGray
        Remove-LevelGroup -GroupId $Group.Id | Out-Null
    }

    Write-LevelInfo "Rollback complete."
}

# ============================================================
# MAIN SCRIPT
# ============================================================

Write-Header "Level.io Group Restore"

Write-Host "This tool restores a group hierarchy from backup with a new base name."
Write-Host "You'll be prompted to configure each custom field for the new groups."
Write-Host ""

if ($DryRun) {
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host " DRY RUN MODE - No changes will be made" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host ""
}

# Load saved configuration for API key
$SavedConfig = Get-SavedConfig -Path $Script:ConfigPath

# Get API Key
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

Write-LevelSuccess "Connected! Found $($AllGroups.Count) existing groups."

# ============================================================
# SELECT BACKUP FILE
# ============================================================

Write-Header "Select Backup"

if ([string]::IsNullOrWhiteSpace($BackupPath)) {
    $BackupsFolder = Join-Path (Split-Path $PSScriptRoot -Parent) "backups"

    if (Test-Path $BackupsFolder) {
        $Backups = Get-ChildItem -Path $BackupsFolder -Filter "group_*.zip" | Sort-Object LastWriteTime -Descending

        if ($Backups.Count -gt 0) {
            Write-Host "Available backups:" -ForegroundColor Cyan
            Write-Host ""

            $Index = 1
            foreach ($Backup in $Backups | Select-Object -First 10) {
                $Size = [math]::Round($Backup.Length / 1KB, 1)
                $Date = $Backup.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
                Write-Host "  [$Index] $($Backup.Name)" -ForegroundColor White
                Write-Host "      $Date, ${Size}KB" -ForegroundColor DarkGray
                $Index++
            }

            Write-Host ""
            $Choice = Read-UserInput -Prompt "Select backup number (or enter path)" -Default "1"

            if ($Choice -match '^\d+$') {
                $ChoiceInt = [int]$Choice
                if ($ChoiceInt -ge 1 -and $ChoiceInt -le $Backups.Count) {
                    $BackupPath = $Backups[$ChoiceInt - 1].FullName
                }
            }
            else {
                $BackupPath = $Choice
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($BackupPath)) {
        $BackupPath = Read-UserInput -Prompt "Enter backup file path" -Default ""
    }
}

if ([string]::IsNullOrWhiteSpace($BackupPath) -or -not (Test-Path $BackupPath)) {
    Write-LevelError "Backup file not found: $BackupPath"
    exit 1
}

# Load backup
Write-Host "Loading backup: $BackupPath" -ForegroundColor DarkGray

$Backup = Import-Backup -Path $BackupPath

if (-not $Backup) {
    Write-LevelError "Failed to load backup."
    exit 1
}

Write-LevelSuccess "Backup loaded successfully!"
Write-Host "  Source group: $($Backup.SourceGroup)" -ForegroundColor DarkGray
Write-Host "  Created: $($Backup.Timestamp)" -ForegroundColor DarkGray

# Count groups in backup
function Count-Groups {
    param([PSObject]$Node)
    $Count = 1
    foreach ($Child in $Node.Children) {
        $Count += Count-Groups -Node $Child
    }
    return $Count
}

$GroupCount = Count-Groups -Node $Backup.Hierarchy
Write-Host "  Groups in backup: $GroupCount" -ForegroundColor DarkGray

# ============================================================
# CONFIGURE NEW GROUP NAME
# ============================================================

Write-Header "Configure New Group"

if ([string]::IsNullOrWhiteSpace($NewGroupName)) {
    Write-Host "The backup source was: " -NoNewline
    Write-Host $Backup.SourceGroup -ForegroundColor Cyan
    Write-Host ""

    $NewGroupName = Read-UserInput -Prompt "Enter the new base group name" -Default ""

    if ([string]::IsNullOrWhiteSpace($NewGroupName)) {
        Write-LevelError "New group name is required. Exiting."
        exit 1
    }
}

# Check if group already exists
$ExistingGroup = $AllGroups | Where-Object { $_.name -ieq $NewGroupName } | Select-Object -First 1
if ($ExistingGroup) {
    Write-LevelWarning "A group named '$NewGroupName' already exists!"
    if (-not (Read-YesNo -Prompt "Continue anyway" -Default $false)) {
        Write-LevelInfo "Cancelled."
        exit 0
    }
}

# ============================================================
# SELECT PARENT GROUP (OPTIONAL)
# ============================================================

Write-Header "Select Parent Group"

$ParentGroupId = $null

if (-not [string]::IsNullOrWhiteSpace($ParentGroupName)) {
    $ParentGroup = $AllGroups | Where-Object { $_.name -ieq $ParentGroupName } | Select-Object -First 1
    if ($ParentGroup) {
        $ParentGroupId = $ParentGroup.id
        Write-LevelInfo "Will create under: $($ParentGroup.name)"
    }
    else {
        Write-LevelWarning "Parent group '$ParentGroupName' not found. Will create at root level."
    }
}
else {
    Write-Host "Where should the new group be created?" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [R] Root level (no parent)" -ForegroundColor Yellow
    Write-Host "  [S] Select a parent group" -ForegroundColor Yellow
    Write-Host ""

    $ParentChoice = Read-UserInput -Prompt "Choice" -Default "R"

    if ($ParentChoice.ToUpper() -eq "S") {
        Write-Host ""
        Write-Host "Available groups:" -ForegroundColor Cyan

        # Show flat list of groups
        $Index = 1
        $GroupList = @()
        foreach ($G in $AllGroups | Sort-Object name) {
            Write-Host "  [$Index] $($G.name)" -ForegroundColor White
            $GroupList += $G
            $Index++
        }

        Write-Host ""
        $ParentNum = Read-UserInput -Prompt "Select parent group number" -Default ""

        if ($ParentNum -match '^\d+$') {
            $ParentIdx = [int]$ParentNum
            if ($ParentIdx -ge 1 -and $ParentIdx -le $GroupList.Count) {
                $ParentGroupId = $GroupList[$ParentIdx - 1].id
                Write-LevelInfo "Will create under: $($GroupList[$ParentIdx - 1].name)"
            }
        }
    }
    else {
        Write-LevelInfo "Will create at root level."
    }
}

# ============================================================
# PREVIEW & CONFIRM
# ============================================================

Write-Header "Preview"

Write-Host "Restore Summary:" -ForegroundColor Cyan
Write-Host "  Source backup: $($Backup.SourceGroup)" -ForegroundColor White
Write-Host "  New base name: $NewGroupName" -ForegroundColor Green
Write-Host "  Groups to create: $GroupCount" -ForegroundColor White

if ($ParentGroupId) {
    $ParentName = ($AllGroups | Where-Object { $_.id -eq $ParentGroupId }).name
    Write-Host "  Parent group: $ParentName" -ForegroundColor White
}
else {
    Write-Host "  Parent group: (root level)" -ForegroundColor White
}

Write-Host ""

# Show hierarchy preview
Write-Host "Group hierarchy to create:" -ForegroundColor Cyan

function Show-PreviewTree {
    param(
        [PSObject]$Node,
        [string]$NewBaseName,
        [int]$Indent = 0
    )

    $Prefix = "  " * ($Indent + 1)
    $Name = if ($Indent -eq 0) { $NewBaseName } else { $Node.Name }
    Write-Host "${Prefix}- $Name" -ForegroundColor $(if ($Indent -eq 0) { "Green" } else { "White" })

    foreach ($Child in $Node.Children) {
        Show-PreviewTree -Node $Child -NewBaseName $NewBaseName -Indent ($Indent + 1)
    }
}

Show-PreviewTree -Node $Backup.Hierarchy -NewBaseName $NewGroupName

Write-Host ""

if (-not $DryRun) {
    if (-not (Read-YesNo -Prompt "Proceed with restore" -Default $true)) {
        Write-LevelInfo "Cancelled."
        exit 0
    }
}

# ============================================================
# CONFIGURE CUSTOM FIELDS
# ============================================================

Write-Header "Configure Custom Fields"

Write-Host "For each custom field with a value in the backup, choose how to configure it." -ForegroundColor White
Write-Host "Your choice will apply to ALL groups being created." -ForegroundColor DarkGray
Write-Host ""

# Collect all unique custom fields from the hierarchy
function Get-AllCustomFieldsFromHierarchy {
    param([PSObject]$Node)

    $Fields = @{}

    if ($Node.CustomFields) {
        $Props = $Node.CustomFields.PSObject.Properties
        foreach ($Prop in $Props) {
            if (-not [string]::IsNullOrWhiteSpace($Prop.Value)) {
                if (-not $Fields.ContainsKey($Prop.Name)) {
                    $Fields[$Prop.Name] = $Prop.Value
                }
            }
        }
    }

    foreach ($Child in $Node.Children) {
        $ChildFields = Get-AllCustomFieldsFromHierarchy -Node $Child
        foreach ($Key in $ChildFields.Keys) {
            if (-not $Fields.ContainsKey($Key)) {
                $Fields[$Key] = $ChildFields[$Key]
            }
        }
    }

    return $Fields
}

$UniqueFields = Get-AllCustomFieldsFromHierarchy -Node $Backup.Hierarchy

if ($UniqueFields.Count -eq 0) {
    Write-LevelInfo "No custom field values found in backup."
}
else {
    Write-Host "Found $($UniqueFields.Count) custom field(s) with values:" -ForegroundColor Cyan
    Write-Host ""

    # Prompt for each field
    foreach ($FieldName in $UniqueFields.Keys | Sort-Object) {
        $Value = $UniqueFields[$FieldName]
        $null = Get-FieldDecision -FieldName $FieldName -CurrentValue $Value
    }
}

# ============================================================
# RESTORE
# ============================================================

Write-Header "Restoring Groups"

try {
    $Result = Restore-GroupHierarchy -GroupBackup $Backup.Hierarchy `
        -ParentId $ParentGroupId `
        -NewBaseName $NewGroupName `
        -OriginalBaseName $Backup.SourceGroup

    if ($Result) {
        Write-Host ""
        Write-LevelSuccess "Restore completed successfully!"
        Write-Host ""
        Write-Host "Created $($Script:CreatedGroups.Count) group(s):" -ForegroundColor Cyan

        foreach ($Group in $Script:CreatedGroups) {
            Write-Host "  - $($Group.Name)" -ForegroundColor Green
        }
    }
    else {
        throw "Restore failed."
    }
}
catch {
    Write-LevelError "Restore failed: $($_.Exception.Message)"

    if (-not $DryRun -and $Script:CreatedGroups.Count -gt 0) {
        if (Read-YesNo -Prompt "Rollback created groups" -Default $true) {
            Rollback-CreatedGroups
        }
    }

    exit 1
}

# ============================================================
# SUMMARY
# ============================================================

Write-Header "Restore Complete"

if ($DryRun) {
    Write-Host "Dry run complete. No changes were made." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "To perform the actual restore, run without -DryRun:" -ForegroundColor White
    Write-Host "  .\Restore-LevelGroup.ps1 -BackupPath `"$BackupPath`" -NewGroupName `"$NewGroupName`"" -ForegroundColor DarkGray
}
else {
    Write-Host "Group hierarchy restored successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "New group: $NewGroupName" -ForegroundColor Cyan
    if ($Script:CreatedGroups.Count -gt 0) {
        Write-Host "Root ID: $($Script:CreatedGroups[0].Id)" -ForegroundColor DarkGray
    }
    Write-Host ""
    Write-Host "You can now assign devices to the new groups in Level.io." -ForegroundColor White
}

Write-Host ""
