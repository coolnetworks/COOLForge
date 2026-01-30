<#
.SYNOPSIS
    Interactive tool to add new custom fields or groups to the COOLForge config.

.DESCRIPTION
    Questionnaire-style script that guides you through adding:
    - New custom fields to existing groups
    - New feature groups with their fields

    Updates definitions/custom-fields.json and optionally syncs to Level.io.

.PARAMETER AddGroup
    Start by adding a new feature group.

.PARAMETER AddField
    Add a field to an existing group.

.PARAMETER Group
    Specify the target group name (skips group selection prompt).

.NOTES
    Version:          2026.01.07.01
    Target Platform:  Windows PowerShell 5.1+

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge

.EXAMPLE
    .\Add-COOLForgeCustomField.ps1
    Interactive mode - choose to add a group or field.

.EXAMPLE
    .\Add-COOLForgeCustomField.ps1 -AddField -Group "screenconnect"
    Add a new field to the screenconnect group.

.EXAMPLE
    .\Add-COOLForgeCustomField.ps1 -AddGroup
    Create a new feature group.
#>

param(
    [Parameter(Mandatory = $false)]
    [switch]$AddGroup,

    [Parameter(Mandatory = $false)]
    [switch]$AddField,

    [Parameter(Mandatory = $false)]
    [string]$Group = ""
)

$ErrorActionPreference = "Stop"

# ============================================================
# PATHS
# ============================================================

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptRoot
$ConfigPath = Join-Path $ProjectRoot "definitions\custom-fields.json"
$BackupPath = Join-Path $ProjectRoot "definitions\custom-fields.backup.json"

# ============================================================
# HELPER FUNCTIONS
# ============================================================

function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host " $Text" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Prompt {
    param(
        [string]$Question,
        [string]$Default = "",
        [switch]$Required
    )

    $DefaultText = if ($Default) { " [$Default]" } else { "" }
    $RequiredText = if ($Required) { " (required)" } else { "" }

    Write-Host "$Question$RequiredText$DefaultText`: " -NoNewline -ForegroundColor Yellow
    $Response = Read-Host

    if ([string]::IsNullOrWhiteSpace($Response)) {
        if ($Required -and [string]::IsNullOrWhiteSpace($Default)) {
            Write-Host "[!] This field is required." -ForegroundColor Red
            return Write-Prompt -Question $Question -Default $Default -Required:$Required
        }
        return $Default
    }

    return $Response.Trim()
}

function Write-YesNo {
    param(
        [string]$Question,
        [bool]$Default = $false
    )

    $DefaultText = if ($Default) { "[Y/n]" } else { "[y/N]" }
    Write-Host "$Question $DefaultText`: " -NoNewline -ForegroundColor Yellow
    $Response = Read-Host

    if ([string]::IsNullOrWhiteSpace($Response)) {
        return $Default
    }

    return $Response.Trim().ToLower() -in @("y", "yes", "true", "1")
}

function Write-Choice {
    param(
        [string]$Question,
        [string[]]$Options,
        [int]$Default = 0
    )

    Write-Host "$Question" -ForegroundColor Yellow
    for ($i = 0; $i -lt $Options.Count; $i++) {
        $Marker = if ($i -eq $Default) { "*" } else { " " }
        Write-Host "  $Marker [$($i + 1)] $($Options[$i])" -ForegroundColor $(if ($i -eq $Default) { "White" } else { "Gray" })
    }

    Write-Host "Enter choice [1-$($Options.Count)]`: " -NoNewline -ForegroundColor Yellow
    $Response = Read-Host

    if ([string]::IsNullOrWhiteSpace($Response)) {
        return $Default
    }

    $Choice = [int]$Response - 1
    if ($Choice -lt 0 -or $Choice -ge $Options.Count) {
        Write-Host "[!] Invalid choice. Using default." -ForegroundColor Red
        return $Default
    }

    return $Choice
}

function Get-ValidFieldName {
    param([string]$Suggestion = "")

    $Name = Write-Prompt -Question "Field name (coolforge_ prefix added automatically)" -Default $Suggestion -Required

    # Clean up the name
    $Name = $Name.ToLower() -replace "[^a-z0-9_]", "_" -replace "_+", "_" -replace "^_|_$", ""

    # Add prefix if not present
    if (-not $Name.StartsWith("coolforge_")) {
        $Name = "coolforge_$Name"
    }

    return $Name
}

function Get-ValidGroupName {
    $Name = Write-Prompt -Question "Group name (lowercase, no spaces)" -Required

    # Clean up the name
    $Name = $Name.ToLower() -replace "[^a-z0-9_]", "_" -replace "_+", "_" -replace "^_|_$", ""

    return $Name
}

# ============================================================
# LOAD CONFIG
# ============================================================

Write-Header "COOLForge Custom Field Manager"

if (-not (Test-Path $ConfigPath)) {
    Write-Host "[X] Config not found: $ConfigPath" -ForegroundColor Red
    Write-Host "    Run Setup-COOLForge.ps1 first to create the config." -ForegroundColor Gray
    exit 1
}

$ConfigContent = Get-Content $ConfigPath -Raw
$Config = $ConfigContent | ConvertFrom-Json

Write-Host "Config version: $($Config.version)" -ForegroundColor DarkGray

# Get existing groups
$ExistingGroups = @($Config.fields.PSObject.Properties.Name)
Write-Host "Existing groups: $($ExistingGroups -join ', ')" -ForegroundColor DarkGray

# ============================================================
# DETERMINE ACTION
# ============================================================

if (-not $AddGroup -and -not $AddField) {
    Write-Host ""
    $ActionChoice = Write-Choice -Question "What would you like to do?" -Options @(
        "Add a new field to an existing group",
        "Create a new feature group"
    ) -Default 0

    if ($ActionChoice -eq 0) {
        $AddField = $true
    }
    else {
        $AddGroup = $true
    }
}

# ============================================================
# ADD NEW GROUP
# ============================================================

if ($AddGroup) {
    Write-Header "Create New Feature Group"

    $GroupName = Get-ValidGroupName

    if ($GroupName -in $ExistingGroups) {
        Write-Host "[!] Group '$GroupName' already exists." -ForegroundColor Yellow
        $AddToExisting = Write-YesNo -Question "Add a field to this group instead?" -Default $true
        if ($AddToExisting) {
            $AddField = $true
            $Group = $GroupName
            $AddGroup = $false
        }
        else {
            exit 0
        }
    }

    if ($AddGroup) {
        Write-Host ""
        Write-Host "Creating group: $GroupName" -ForegroundColor Green
        Write-Host ""
        Write-Host "Now let's add the first field to this group." -ForegroundColor Cyan

        # Add empty group and switch to field mode
        $Config.fields | Add-Member -NotePropertyName $GroupName -NotePropertyValue @() -Force
        $ExistingGroups += $GroupName
        $AddField = $true
        $Group = $GroupName
    }
}

# ============================================================
# ADD NEW FIELD
# ============================================================

if ($AddField) {
    # Select group if not specified
    if ([string]::IsNullOrWhiteSpace($Group)) {
        Write-Header "Select Target Group"

        $GroupChoice = Write-Choice -Question "Which group should this field belong to?" -Options $ExistingGroups -Default 0
        $Group = $ExistingGroups[$GroupChoice]
    }

    if ($Group -notin $ExistingGroups) {
        Write-Host "[X] Unknown group: $Group" -ForegroundColor Red
        Write-Host "    Available groups: $($ExistingGroups -join ', ')" -ForegroundColor Gray
        exit 1
    }

    Write-Header "Add Field to '$Group'"

    # Get existing field names in this group
    $GroupFields = @($Config.fields.$Group)
    $ExistingFieldNames = @($GroupFields | ForEach-Object { $_.name })

    if ($ExistingFieldNames.Count -gt 0) {
        Write-Host "Existing fields in $Group`:" -ForegroundColor DarkGray
        $ExistingFieldNames | ForEach-Object { Write-Host "  - $_" -ForegroundColor DarkGray }
        Write-Host ""
    }

    # Collect field information
    $FieldName = Get-ValidFieldName

    if ($FieldName -in $ExistingFieldNames) {
        Write-Host "[X] Field '$FieldName' already exists in $Group." -ForegroundColor Red
        exit 1
    }

    Write-Host ""
    $Description = Write-Prompt -Question "Description (shown during setup)" -Required

    Write-Host ""
    $DefaultValue = Write-Prompt -Question "Default value" -Default ""

    Write-Host ""
    $AdminOnly = Write-YesNo -Question "Admin only (hidden from non-admin users)?" -Default $false

    Write-Host ""
    $Required = Write-YesNo -Question "Required field (must have a value)?" -Default $false

    Write-Host ""
    $AutoCreate = Write-YesNo -Question "Auto-create (create silently without prompting)?" -Default $false

    Write-Host ""
    $LegacyNamesInput = Write-Prompt -Question "Legacy field names to migrate from (comma-separated)" -Default ""
    $LegacyNames = @()
    if (-not [string]::IsNullOrWhiteSpace($LegacyNamesInput)) {
        $LegacyNames = @($LegacyNamesInput.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }

    # Build the field object
    $NewField = [ordered]@{
        name        = $FieldName
        description = $Description
        legacyNames = $LegacyNames
        adminOnly   = $AdminOnly
        required    = $Required
    }

    if (-not [string]::IsNullOrWhiteSpace($DefaultValue)) {
        $NewField["default"] = $DefaultValue
    }

    if ($AutoCreate) {
        $NewField["autoCreate"] = $true
    }

    # ============================================================
    # CONFIRM AND SAVE
    # ============================================================

    Write-Header "Review New Field"

    Write-Host "  Name:        $FieldName" -ForegroundColor White
    Write-Host "  Group:       $Group" -ForegroundColor White
    Write-Host "  Description: $Description" -ForegroundColor Gray
    Write-Host "  Default:     $(if ($DefaultValue) { $DefaultValue } else { '(empty)' })" -ForegroundColor Gray
    Write-Host "  Admin Only:  $AdminOnly" -ForegroundColor Gray
    Write-Host "  Required:    $Required" -ForegroundColor Gray
    Write-Host "  Auto-Create: $AutoCreate" -ForegroundColor Gray
    Write-Host "  Legacy Names: $(if ($LegacyNames.Count -gt 0) { $LegacyNames -join ', ' } else { '(none)' })" -ForegroundColor Gray
    Write-Host ""

    $Confirm = Write-YesNo -Question "Add this field to the config?" -Default $true

    if (-not $Confirm) {
        Write-Host "[!] Cancelled." -ForegroundColor Yellow
        exit 0
    }

    # Create backup
    Copy-Item -Path $ConfigPath -Destination $BackupPath -Force
    Write-Host "[+] Backup created: $BackupPath" -ForegroundColor DarkGray

    # Add field to config
    $GroupFields = @($Config.fields.$Group)
    $GroupFields += [PSCustomObject]$NewField
    $Config.fields.$Group = $GroupFields

    # Update version
    $Config.version = (Get-Date).ToString("yyyy.MM.dd")

    # Save config
    $Config | ConvertTo-Json -Depth 10 | Set-Content $ConfigPath -Encoding UTF8

    Write-Host ""
    Write-Host "[+] Field added successfully!" -ForegroundColor Green
    Write-Host ""

    # Offer to sync
    $SyncNow = Write-YesNo -Question "Sync this field to Level.io now?" -Default $false

    if ($SyncNow) {
        $SyncScript = Join-Path $ScriptRoot "Sync-COOLForgeCustomFields.ps1"
        if (Test-Path $SyncScript) {
            Write-Host ""
            & $SyncScript -FeatureGroups $Group
        }
        else {
            Write-Host "[!] Sync script not found: $SyncScript" -ForegroundColor Yellow
        }
    }
}

Write-Host ""
Write-Host "Done!" -ForegroundColor Green
Write-Host ""
