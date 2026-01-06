<#
.SYNOPSIS
    COOLForge-CustomFields - Module for managing Level.io custom fields.

.DESCRIPTION
    This module provides functions for managing Level.io custom fields via the API:
    - Custom field CRUD operations (create, read, update, delete)
    - Hierarchy navigation (organizations, folders, devices)
    - Backup and restore of custom field values across all levels
    - Configuration management with encrypted API key storage
    - GitHub release integration for version management

    This module is used by:
    - Setup-COOLForgeCustomFields.ps1 (interactive setup wizard)
    - Backup-COOLForgeCustomFields.ps1 (standalone backup/restore CLI)

.NOTES
    Version:    2025.12.29.01
    Target:     Windows PowerShell 5.1+

    API Documentation: https://levelapi.readme.io/

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge

.EXAMPLE
    # Import and initialize the module
    Import-Module ".\modules\COOLForge-CustomFields.psm1" -Force
    Initialize-COOLForgeCustomFields -ApiKey "your-api-key"

    # List existing custom fields
    $Fields = Get-ExistingCustomFields
    Write-Host "Found $($Fields.Count) custom fields"

.EXAMPLE
    # Create a backup
    $Backup = Backup-AllCustomFields -IncludeDevices
    $Path = Get-BackupPath -BasePath ".\backups"
    Save-Backup -Backup $Backup -Path $Path
#>

# ============================================================
# MODULE VARIABLES
# ============================================================
$Script:ApiKey = $null
$Script:LevelApiBase = "https://api.level.io/v2"
$Script:GitHubRepo = "coolnetworks/COOLForge"
$Script:Initialized = $false
$Script:ModuleVersion = "2025.12.29.01"

# ============================================================
# INITIALIZATION
# ============================================================

function Initialize-COOLForgeCustomFields {
    <#
    .SYNOPSIS
        Initializes the module with API credentials.
    .DESCRIPTION
        Must be called before using API functions. Sets up the module state
        with the Level.io API key and optional configuration.
    .PARAMETER ApiKey
        Level.io API key (Bearer token format).
    .PARAMETER LevelApiBase
        Base URL for Level.io API. Defaults to "https://api.level.io/v2".
    .PARAMETER GitHubRepo
        GitHub repository for release checks. Defaults to "coolnetworks/COOLForge".
    .EXAMPLE
        Initialize-COOLForgeCustomFields -ApiKey "your-api-key"
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $false)]
        [string]$LevelApiBase = "https://api.level.io/v2",

        [Parameter(Mandatory = $false)]
        [string]$GitHubRepo = "coolnetworks/COOLForge"
    )

    $Script:ApiKey = $ApiKey
    $Script:LevelApiBase = $LevelApiBase
    $Script:GitHubRepo = $GitHubRepo
    $Script:Initialized = $true

    return @{ Success = $true }
}

# ============================================================
# UI HELPER FUNCTIONS
# ============================================================

function Write-Header {
    <#
    .SYNOPSIS
        Displays a section header.
    #>
    param([string]$Text)
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " $Text" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-LevelSuccess {
    <#
    .SYNOPSIS
        Displays a success message.
    #>
    param([string]$Text)
    Write-Host "[+] $Text" -ForegroundColor Green
}

function Write-LevelInfo {
    <#
    .SYNOPSIS
        Displays an info message.
    #>
    param([string]$Text)
    Write-Host "[*] $Text" -ForegroundColor White
}

function Write-LevelWarning {
    <#
    .SYNOPSIS
        Displays a warning message.
    #>
    param([string]$Text)
    Write-Host "[!] $Text" -ForegroundColor Yellow
}

function Write-LevelError {
    <#
    .SYNOPSIS
        Displays an error message.
    #>
    param([string]$Text)
    Write-Host "[X] $Text" -ForegroundColor Red
}

function Read-UserInput {
    <#
    .SYNOPSIS
        Prompts for user input with optional default value.
    #>
    param(
        [string]$Prompt,
        [string]$Default = ""
    )

    if ([string]::IsNullOrWhiteSpace($Default)) {
        $FullPrompt = "$Prompt`: "
    }
    else {
        $FullPrompt = "$Prompt [$Default]: "
    }

    Write-Host $FullPrompt -NoNewline -ForegroundColor Yellow
    $Input = Read-Host

    if ([string]::IsNullOrWhiteSpace($Input)) {
        return $Default
    }
    return $Input
}

function Read-YesNo {
    <#
    .SYNOPSIS
        Prompts for a yes/no answer.
    #>
    param(
        [string]$Prompt,
        [bool]$Default = $true
    )

    $DefaultText = if ($Default) { "Y/n" } else { "y/N" }
    Write-Host "$Prompt [$DefaultText]: " -NoNewline -ForegroundColor Yellow
    $Input = Read-Host

    if ([string]::IsNullOrWhiteSpace($Input)) {
        return $Default
    }

    return $Input.ToLower() -eq "y" -or $Input.ToLower() -eq "yes"
}

function Get-CompanyNameFromPath {
    <#
    .SYNOPSIS
        Extracts the company name from a scratch folder path.
    .DESCRIPTION
        Given a path like "C:\ProgramData\COOLNETWORKS" or "C:\ProgramData\My Company",
        extracts and returns "COOLNETWORKS" or "My Company".
    #>
    param(
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ""
    }

    # Normalize path separators and trim
    $Path = $Path.Trim().TrimEnd('\', '/')

    # Check if it matches the expected pattern C:\ProgramData\<CompanyName>
    if ($Path -match '^[A-Za-z]:\\ProgramData\\(.+)$') {
        return $Matches[1]
    }

    # Also handle forward slashes
    if ($Path -match '^[A-Za-z]:/ProgramData/(.+)$') {
        return $Matches[1]
    }

    # If the path doesn't match expected pattern, try to get the last folder name
    $LastFolder = Split-Path -Leaf $Path
    if (-not [string]::IsNullOrWhiteSpace($LastFolder) -and $LastFolder -ne $Path) {
        return $LastFolder
    }

    return ""
}

# ============================================================
# API CORE FUNCTIONS
# ============================================================

function Invoke-LevelApi {
    <#
    .SYNOPSIS
        Makes an authenticated API call to Level.io.
    .DESCRIPTION
        Wrapper for Invoke-RestMethod with Level.io authentication.
        Returns a hashtable with Success (bool), Data (response), and Error (message).
    #>
    param(
        [string]$Endpoint,
        [string]$Method = "GET",
        [hashtable]$Body = $null
    )

    $Uri = "$Script:LevelApiBase$Endpoint"
    $Headers = @{
        "Authorization" = $Script:ApiKey
        "Content-Type"  = "application/json"
    }

    $Params = @{
        Uri         = $Uri
        Method      = $Method
        Headers     = $Headers
        ErrorAction = "Stop"
    }

    if ($Body -and $Method -ne "GET") {
        $Params.Body = ($Body | ConvertTo-Json -Depth 10)
    }

    try {
        $Response = Invoke-RestMethod @Params
        return @{ Success = $true; Data = $Response }
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        if ($_.Exception.Response) {
            try {
                $Reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $ErrorBody = $Reader.ReadToEnd()
                $Reader.Close()
                if ($ErrorBody) {
                    $ErrorMessage = $ErrorBody
                }
            }
            catch { }
        }
        return @{ Success = $false; Error = $ErrorMessage }
    }
}

function Get-ExistingCustomFields {
    <#
    .SYNOPSIS
        Fetches all existing custom field definitions (with pagination).
    #>
    Write-LevelInfo "Fetching existing custom fields..."

    $AllFields = [System.Collections.Generic.List[object]]::new()
    $Cursor = $null

    do {
        $Endpoint = "/custom_fields"
        if ($Cursor) {
            $Endpoint += "?starting_after=$Cursor"
        }

        $Result = Invoke-LevelApi -Endpoint $Endpoint

        if (-not $Result.Success) {
            Write-LevelError "Failed to fetch custom fields: $($Result.Error)"
            return $null
        }

        $Data = $Result.Data
        $Fields = if ($Data.data) { $Data.data } else { $Data }

        if ($Fields -and $Fields.Count -gt 0) {
            foreach ($Field in $Fields) {
                $AllFields.Add($Field)
            }

            # Check for more pages
            $HasMore = $Data.has_more -eq $true
            if ($HasMore) {
                $Cursor = $Fields[-1].id
            } else {
                break
            }
        } else {
            break
        }
    } while ($true)

    return @($AllFields)
}

function Find-CustomField {
    <#
    .SYNOPSIS
        Finds a custom field by name or reference in a list of fields.
    #>
    param(
        [string]$Name,
        [array]$ExistingFields
    )

    foreach ($Field in $ExistingFields) {
        # Check 'name' and 'reference' properties (API uses 'reference' for script usage)
        if ($Field.name -eq $Name -or $Field.reference -eq $Name) {
            return $Field
        }
    }
    return $null
}

function New-CustomField {
    <#
    .SYNOPSIS
        Creates a new custom field.
    #>
    param(
        [string]$Name,
        [string]$DefaultValue = "",
        [bool]$AdminOnly = $false
    )

    $Body = @{
        name       = $Name
        admin_only = $AdminOnly
    }

    if (-not [string]::IsNullOrWhiteSpace($DefaultValue)) {
        $Body.default_value = $DefaultValue
    }

    Write-LevelInfo "Creating custom field: $Name"
    $Result = Invoke-LevelApi -Endpoint "/custom_fields" -Method "POST" -Body $Body

    if ($Result.Success) {
        Write-LevelSuccess "Created custom field: $Name"
        return $Result.Data
    }
    else {
        Write-LevelError "Failed to create custom field '$Name': $($Result.Error)"
        return $null
    }
}

function Update-CustomFieldValue {
    <#
    .SYNOPSIS
        Updates a custom field's default value.
    #>
    param(
        [string]$FieldId,
        [string]$Value
    )

    $Body = @{
        default_value = $Value
    }

    $Result = Invoke-LevelApi -Endpoint "/custom_fields/$FieldId" -Method "PATCH" -Body $Body
    return $Result.Success
}

function Get-CustomFieldById {
    <#
    .SYNOPSIS
        Gets a single custom field by ID, including its account-level value.
    #>
    param(
        [string]$FieldId
    )

    $Result = Invoke-LevelApi -Endpoint "/custom_fields/$FieldId"
    if ($Result.Success) {
        $Field = $Result.Data

        # Get the account-level value from custom_field_values (use limit=100 to get all)
        $ValueResult = Invoke-LevelApi -Endpoint "/custom_field_values?limit=100"
        if ($ValueResult.Success) {
            $Values = if ($ValueResult.Data.data) { $ValueResult.Data.data } else { $ValueResult.Data }

            # Find the value that matches this field ID
            foreach ($Val in $Values) {
                if ($Val.custom_field_id -eq $FieldId) {
                    $Field | Add-Member -NotePropertyName "default_value" -NotePropertyValue $Val.value -Force
                    break
                }
            }
        }

        return $Field
    }
    return $null
}

# ============================================================
# HIERARCHY NAVIGATION FUNCTIONS
# ============================================================

function Get-AllOrganizations {
    <#
    .SYNOPSIS
        Gets all organizations accessible via the API.
    #>
    $Result = Invoke-LevelApi -Endpoint "/organizations"
    if ($Result.Success) {
        $Data = $Result.Data
        if ($Data.data) { $Data = $Data.data }
        return $Data
    }
    return @()
}

function Get-OrganizationFolders {
    <#
    .SYNOPSIS
        Gets all folders for an organization.
    #>
    param([string]$OrgId)

    $Result = Invoke-LevelApi -Endpoint "/organizations/$OrgId/folders"
    if ($Result.Success) {
        $Data = $Result.Data
        if ($Data.data) { $Data = $Data.data }
        return $Data
    }
    return @()
}

function Get-FolderDevices {
    <#
    .SYNOPSIS
        Gets all devices in a folder.
    #>
    param(
        [string]$OrgId,
        [string]$FolderId
    )

    $Result = Invoke-LevelApi -Endpoint "/organizations/$OrgId/folders/$FolderId/devices"
    if ($Result.Success) {
        $Data = $Result.Data
        if ($Data.data) { $Data = $Data.data }
        return $Data
    }
    return @()
}

function Get-EntityCustomFields {
    <#
    .SYNOPSIS
        Gets custom field values for an entity (org, folder, or device).
    #>
    param(
        [string]$EntityType,  # "organization", "folder", "device"
        [string]$EntityId
    )

    $Endpoint = switch ($EntityType) {
        "organization" { "/organizations/$EntityId" }
        "folder" { "/folders/$EntityId" }
        "device" { "/devices/$EntityId" }
    }

    $Result = Invoke-LevelApi -Endpoint $Endpoint
    if ($Result.Success -and $Result.Data.custom_fields) {
        return $Result.Data.custom_fields
    }
    return @{}
}

function Set-EntityCustomField {
    <#
    .SYNOPSIS
        Sets a custom field value on an entity.
    #>
    param(
        [string]$EntityType,
        [string]$EntityId,
        [string]$FieldKey,
        [string]$Value
    )

    $Endpoint = switch ($EntityType) {
        "organization" { "/organizations/$EntityId" }
        "folder" { "/folders/$EntityId" }
        "device" { "/devices/$EntityId" }
    }

    $Body = @{
        custom_fields = @{
            $FieldKey = $Value
        }
    }

    $Result = Invoke-LevelApi -Endpoint $Endpoint -Method "PATCH" -Body $Body
    return $Result.Success
}

# ============================================================
# BACKUP/RESTORE FUNCTIONS
# ============================================================

function Backup-AllCustomFields {
    <#
    .SYNOPSIS
        Creates a complete backup of all custom field values across the hierarchy.
    .DESCRIPTION
        Iterates through organizations, folders, and devices to capture all
        custom field values. Returns a structured backup object that can be
        used for restoration.
    #>
    param(
        [switch]$IncludeDevices = $false  # Devices can be many, optional
    )

    $Backup = @{
        Timestamp     = (Get-Date).ToString("o")
        Version       = "1.0"
        CustomFields  = @()  # Field definitions
        Organizations = @()
    }

    # Get custom field definitions
    Write-LevelInfo "Backing up custom field definitions..."
    $Fields = Get-ExistingCustomFields
    if ($Fields.data) { $Fields = $Fields.data }
    $Backup.CustomFields = $Fields

    # Get organizations
    Write-LevelInfo "Fetching organizations..."
    $Orgs = Get-AllOrganizations

    if (-not $Orgs -or $Orgs.Count -eq 0) {
        Write-LevelWarning "No organizations found or API doesn't support organization listing."
        return $Backup
    }

    $OrgCount = if ($Orgs -is [array]) { $Orgs.Count } else { 1 }
    Write-LevelInfo "Found $OrgCount organization(s)."

    foreach ($Org in $Orgs) {
        Write-Host "  Processing: $($Org.name)" -ForegroundColor DarkGray

        $OrgBackup = @{
            Id           = $Org.id
            Name         = $Org.name
            CustomFields = Get-EntityCustomFields -EntityType "organization" -EntityId $Org.id
            Folders      = @()
        }

        # Get folders for this org
        $Folders = Get-OrganizationFolders -OrgId $Org.id
        $FolderCount = if ($Folders -is [array]) { $Folders.Count } else { if ($Folders) { 1 } else { 0 } }

        if ($FolderCount -gt 0) {
            Write-Host "    Found $FolderCount folder(s)" -ForegroundColor DarkGray
        }

        foreach ($Folder in $Folders) {
            $FolderBackup = @{
                Id           = $Folder.id
                Name         = $Folder.name
                ParentId     = $Folder.parent_id
                CustomFields = Get-EntityCustomFields -EntityType "folder" -EntityId $Folder.id
                Devices      = @()
            }

            # Optionally get devices
            if ($IncludeDevices) {
                $Devices = Get-FolderDevices -OrgId $Org.id -FolderId $Folder.id
                foreach ($Device in $Devices) {
                    $DeviceBackup = @{
                        Id           = $Device.id
                        Name         = $Device.name
                        CustomFields = Get-EntityCustomFields -EntityType "device" -EntityId $Device.id
                    }
                    $FolderBackup.Devices += $DeviceBackup
                }
            }

            $OrgBackup.Folders += $FolderBackup
        }

        $Backup.Organizations += $OrgBackup
    }

    return $Backup
}

function Save-Backup {
    <#
    .SYNOPSIS
        Saves a backup to a compressed zip file.
    .DESCRIPTION
        Creates a JSON file, compresses it to zip, then removes the JSON.
        Returns $true on success, $false on failure.
    #>
    param(
        [hashtable]$Backup,
        [string]$Path
    )

    try {
        # Write JSON first
        $Backup | ConvertTo-Json -Depth 20 | Set-Content $Path -Encoding UTF8 -ErrorAction Stop

        # Compress to zip
        $ZipPath = $Path -replace '\.json$', '.zip'
        Compress-Archive -Path $Path -DestinationPath $ZipPath -Force -ErrorAction Stop

        # Remove the JSON file, keep only the zip
        Remove-Item $Path -Force -ErrorAction SilentlyContinue

        return $true
    }
    catch {
        Write-LevelError "Failed to save backup: $($_.Exception.Message)"
        return $false
    }
}

function Import-Backup {
    <#
    .SYNOPSIS
        Imports a backup from a zip or JSON file.
    #>
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        Write-LevelError "Backup file not found: $Path"
        return $null
    }

    try {
        $JsonContent = $null

        if ($Path -match '\.zip$') {
            # Extract from zip to temp, read, then cleanup
            $TempDir = Join-Path $env:TEMP "coolforge_lib_backup_$(Get-Random)"
            New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

            Expand-Archive -Path $Path -DestinationPath $TempDir -Force -ErrorAction Stop

            # Find the JSON file inside
            $JsonFile = Get-ChildItem -Path $TempDir -Filter "*.json" | Select-Object -First 1
            if ($JsonFile) {
                $JsonContent = Get-Content $JsonFile.FullName -Raw -ErrorAction Stop
            }

            # Cleanup temp
            Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        else {
            # Direct JSON file
            $JsonContent = Get-Content $Path -Raw -ErrorAction Stop
        }

        if ($JsonContent) {
            return $JsonContent | ConvertFrom-Json
        }
        else {
            Write-LevelError "No JSON content found in backup."
            return $null
        }
    }
    catch {
        Write-LevelError "Failed to load backup: $($_.Exception.Message)"
        return $null
    }
}

function Restore-CustomFields {
    <#
    .SYNOPSIS
        Restores custom field values from a backup.
    #>
    param(
        [PSObject]$Backup,
        [switch]$DryRun = $false,
        [switch]$IncludeDevices = $false
    )

    if (-not $Backup) {
        Write-LevelError "No backup provided."
        return $false
    }

    Write-LevelInfo "Restoring from backup created: $($Backup.Timestamp)"

    $Changes = 0

    foreach ($Org in $Backup.Organizations) {
        Write-Host "  Restoring: $($Org.Name)" -ForegroundColor DarkGray

        # Restore org-level custom fields
        foreach ($Field in $Org.CustomFields.PSObject.Properties) {
            if (-not [string]::IsNullOrWhiteSpace($Field.Value)) {
                if ($DryRun) {
                    Write-Host "    [DRY-RUN] Would set $($Field.Name) = $($Field.Value) on org" -ForegroundColor Yellow
                }
                else {
                    if (Set-EntityCustomField -EntityType "organization" -EntityId $Org.Id -FieldKey $Field.Name -Value $Field.Value) {
                        $Changes++
                    }
                }
            }
        }

        # Restore folder-level custom fields
        foreach ($Folder in $Org.Folders) {
            foreach ($Field in $Folder.CustomFields.PSObject.Properties) {
                if (-not [string]::IsNullOrWhiteSpace($Field.Value)) {
                    if ($DryRun) {
                        Write-Host "    [DRY-RUN] Would set $($Field.Name) = $($Field.Value) on folder $($Folder.Name)" -ForegroundColor Yellow
                    }
                    else {
                        if (Set-EntityCustomField -EntityType "folder" -EntityId $Folder.Id -FieldKey $Field.Name -Value $Field.Value) {
                            $Changes++
                        }
                    }
                }
            }

            # Restore device-level custom fields
            if ($IncludeDevices) {
                foreach ($Device in $Folder.Devices) {
                    foreach ($Field in $Device.CustomFields.PSObject.Properties) {
                        if (-not [string]::IsNullOrWhiteSpace($Field.Value)) {
                            if ($DryRun) {
                                Write-Host "    [DRY-RUN] Would set $($Field.Name) = $($Field.Value) on device $($Device.Name)" -ForegroundColor Yellow
                            }
                            else {
                                if (Set-EntityCustomField -EntityType "device" -EntityId $Device.Id -FieldKey $Field.Name -Value $Field.Value) {
                                    $Changes++
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if ($DryRun) {
        Write-LevelInfo "Dry run complete. No changes made."
    }
    else {
        Write-LevelSuccess "Restored $Changes custom field value(s)."
    }

    return $true
}

function Get-BackupPath {
    <#
    .SYNOPSIS
        Generates a backup file path with timestamp.
    .DESCRIPTION
        Creates backups in: <BasePath>/customfields_<YYYY-MM-DD_HHMMSS>.json
        (Will be zipped by Save-Backup)
    .PARAMETER BasePath
        Base path for backups folder. Defaults to repo root's backups folder.
    #>
    param(
        [string]$BasePath = ""
    )

    $Date = Get-Date
    $Timestamp = $Date.ToString("yyyy-MM-dd_HHmmss")

    # Default to repo root's backups folder (two levels up from tools/)
    if ([string]::IsNullOrWhiteSpace($BasePath)) {
        $RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
        $BasePath = Join-Path $RepoRoot "backups"
    }

    # Create folder if it doesn't exist
    if (-not (Test-Path $BasePath)) {
        New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
    }

    return Join-Path $BasePath "customfields_$Timestamp.json"
}

function Get-LatestBackup {
    <#
    .SYNOPSIS
        Gets the most recent backup file.
    .PARAMETER BasePath
        Base path for backups folder. Defaults to repo root's backups folder.
    #>
    param(
        [string]$BasePath = ""
    )

    # Default to repo root's backups folder (two levels up from tools/)
    if ([string]::IsNullOrWhiteSpace($BasePath)) {
        $RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
        $BasePath = Join-Path $RepoRoot "backups"
    }

    if (-not (Test-Path $BasePath)) {
        return $null
    }

    $Latest = Get-ChildItem -Path $BasePath -Filter "customfields_*.zip" |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if ($Latest) {
        return $Latest.FullName
    }
    return $null
}

function Compare-BackupWithCurrent {
    <#
    .SYNOPSIS
        Compares a backup with current custom field values.
    .DESCRIPTION
        Returns a list of differences between backup and current state.
    #>
    param(
        [PSObject]$Backup,
        [switch]$IncludeDevices = $false
    )

    $Differences = @()

    Write-LevelInfo "Comparing backup with current state..."

    foreach ($OrgBackup in $Backup.Organizations) {
        # Get current org custom fields
        $CurrentOrgFields = Get-EntityCustomFields -EntityType "organization" -EntityId $OrgBackup.Id

        # Compare org-level fields
        foreach ($Field in $OrgBackup.CustomFields.PSObject.Properties) {
            $BackupValue = $Field.Value
            $CurrentValue = $CurrentOrgFields.$($Field.Name)

            if ($BackupValue -ne $CurrentValue) {
                $Differences += @{
                    EntityType  = "Organization"
                    EntityName  = $OrgBackup.Name
                    EntityId    = $OrgBackup.Id
                    FieldName   = $Field.Name
                    BackupValue = if ([string]::IsNullOrWhiteSpace($BackupValue)) { "(empty)" } else { $BackupValue }
                    CurrentValue = if ([string]::IsNullOrWhiteSpace($CurrentValue)) { "(empty)" } else { $CurrentValue }
                }
            }
        }

        # Compare folder-level fields
        foreach ($FolderBackup in $OrgBackup.Folders) {
            $CurrentFolderFields = Get-EntityCustomFields -EntityType "folder" -EntityId $FolderBackup.Id

            foreach ($Field in $FolderBackup.CustomFields.PSObject.Properties) {
                $BackupValue = $Field.Value
                $CurrentValue = $CurrentFolderFields.$($Field.Name)

                if ($BackupValue -ne $CurrentValue) {
                    $Differences += @{
                        EntityType  = "Folder"
                        EntityName  = $FolderBackup.Name
                        EntityId    = $FolderBackup.Id
                        FieldName   = $Field.Name
                        BackupValue = if ([string]::IsNullOrWhiteSpace($BackupValue)) { "(empty)" } else { $BackupValue }
                        CurrentValue = if ([string]::IsNullOrWhiteSpace($CurrentValue)) { "(empty)" } else { $CurrentValue }
                    }
                }
            }

            # Compare device-level fields
            if ($IncludeDevices) {
                foreach ($DeviceBackup in $FolderBackup.Devices) {
                    $CurrentDeviceFields = Get-EntityCustomFields -EntityType "device" -EntityId $DeviceBackup.Id

                    foreach ($Field in $DeviceBackup.CustomFields.PSObject.Properties) {
                        $BackupValue = $Field.Value
                        $CurrentValue = $CurrentDeviceFields.$($Field.Name)

                        if ($BackupValue -ne $CurrentValue) {
                            $Differences += @{
                                EntityType  = "Device"
                                EntityName  = $DeviceBackup.Name
                                EntityId    = $DeviceBackup.Id
                                FieldName   = $Field.Name
                                BackupValue = if ([string]::IsNullOrWhiteSpace($BackupValue)) { "(empty)" } else { $BackupValue }
                                CurrentValue = if ([string]::IsNullOrWhiteSpace($CurrentValue)) { "(empty)" } else { $CurrentValue }
                            }
                        }
                    }
                }
            }
        }
    }

    return $Differences
}

function Show-BackupDifferences {
    <#
    .SYNOPSIS
        Displays differences between backup and current state.
    #>
    param(
        [array]$Differences
    )

    if ($Differences.Count -eq 0) {
        Write-LevelSuccess "No differences found - backup matches current state."
        return
    }

    Write-Host ""
    Write-Host "Found $($Differences.Count) difference(s):" -ForegroundColor Yellow
    Write-Host ""

    # Group by entity type for cleaner display
    $Grouped = $Differences | Group-Object EntityType

    foreach ($Group in $Grouped) {
        Write-Host "  $($Group.Name)s:" -ForegroundColor Cyan

        foreach ($Diff in $Group.Group) {
            Write-Host "    $($Diff.EntityName) - $($Diff.FieldName)" -ForegroundColor White
            Write-Host "      Backup:  $($Diff.BackupValue)" -ForegroundColor Green
            Write-Host "      Current: $($Diff.CurrentValue)" -ForegroundColor Red
        }
        Write-Host ""
    }
}

# ============================================================
# CONFIG/SECURITY FUNCTIONS
# ============================================================

function Get-SavedConfig {
    <#
    .SYNOPSIS
        Loads saved configuration from a config file.
    .PARAMETER Path
        Path to the config file. If not specified, uses default path.
    #>
    param(
        [string]$Path = ""
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        $Path = Join-Path $PSScriptRoot ".COOLForge_Lib-setup.json"
    }

    if (Test-Path $Path) {
        try {
            $Content = Get-Content $Path -Raw -ErrorAction Stop
            return $Content | ConvertFrom-Json
        }
        catch {
            Write-LevelWarning "Could not load saved config: $($_.Exception.Message)"
            return $null
        }
    }
    return $null
}

function Save-Config {
    <#
    .SYNOPSIS
        Saves configuration to a config file.
    .PARAMETER Config
        Hashtable of configuration values to save.
    .PARAMETER Path
        Path to the config file. If not specified, uses default path.
    #>
    param(
        [hashtable]$Config,
        [string]$Path = ""
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        $Path = Join-Path $PSScriptRoot ".COOLForge_Lib-setup.json"
    }

    try {
        $Config | ConvertTo-Json -Depth 5 | Set-Content $Path -Encoding UTF8 -ErrorAction Stop
        return $true
    }
    catch {
        Write-LevelWarning "Could not save config: $($_.Exception.Message)"
        return $false
    }
}

function Protect-ApiKey {
    <#
    .SYNOPSIS
        Encrypts API key for storage (Windows DPAPI - user-specific).
    #>
    param([string]$PlainText)

    try {
        $SecureString = ConvertTo-SecureString $PlainText -AsPlainText -Force
        return ConvertFrom-SecureString $SecureString
    }
    catch {
        return $null
    }
}

function Unprotect-ApiKey {
    <#
    .SYNOPSIS
        Decrypts API key from storage.
    #>
    param([string]$EncryptedText)

    try {
        $SecureString = ConvertTo-SecureString $EncryptedText -ErrorAction Stop
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
        return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    }
    catch {
        return $null
    }
}

# ============================================================
# GITHUB FUNCTIONS
# ============================================================

function Get-GitHubReleases {
    <#
    .SYNOPSIS
        Fetches the latest releases from GitHub.
    #>
    param(
        [int]$Count = 5
    )

    $Uri = "https://api.github.com/repos/$Script:GitHubRepo/releases"
    $Headers = @{
        "Accept"     = "application/vnd.github.v3+json"
        "User-Agent" = "COOLForge_Lib-Setup"
    }

    try {
        $Response = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method Get -ErrorAction Stop
        $Releases = @()

        foreach ($Release in ($Response | Select-Object -First $Count)) {
            $Releases += @{
                TagName     = $Release.tag_name
                Name        = $Release.name
                Body        = $Release.body
                PublishedAt = $Release.published_at
                HtmlUrl     = $Release.html_url
                Prerelease  = $Release.prerelease
            }
        }

        return $Releases
    }
    catch {
        Write-LevelWarning "Could not fetch GitHub releases: $($_.Exception.Message)"
        return @()
    }
}

function Show-ReleaseNotes {
    <#
    .SYNOPSIS
        Displays release notes for a version.
    #>
    param(
        [hashtable]$Release
    )

    Write-Host ""
    Write-Host "Release: $($Release.Name)" -ForegroundColor Cyan
    Write-Host "Tag: $($Release.TagName)" -ForegroundColor DarkGray
    Write-Host "Published: $($Release.PublishedAt)" -ForegroundColor DarkGray
    if ($Release.Prerelease) {
        Write-Host "  [PRE-RELEASE]" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "Release Notes:" -ForegroundColor White
    Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray

    # Format and display the body (markdown)
    if (-not [string]::IsNullOrWhiteSpace($Release.Body)) {
        # Simple markdown cleanup for console display
        $Body = $Release.Body
        $Body = $Body -replace '#+\s*', ''  # Remove markdown headers
        $Body = $Body -replace '\*\*([^*]+)\*\*', '$1'  # Remove bold
        $Body = $Body -replace '\*([^*]+)\*', '$1'  # Remove italic
        Write-Host $Body
    }
    else {
        Write-Host "(No release notes available)"
    }
    Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
}

function Select-Version {
    <#
    .SYNOPSIS
        Interactive version selector with GitHub releases.
    #>
    param(
        [string]$CurrentVersion = ""
    )

    Write-LevelInfo "Fetching available releases from GitHub..."
    $Releases = Get-GitHubReleases -Count 5

    if ($Releases.Count -eq 0) {
        Write-LevelWarning "Could not fetch releases. Enter version manually."
        return Read-UserInput -Prompt "Version tag (e.g., v2025.12.29)" -Default $CurrentVersion
    }

    Write-Host ""
    Write-Host "Available versions:" -ForegroundColor Cyan
    Write-Host ""

    $Index = 1
    foreach ($Release in $Releases) {
        $PreReleaseTag = if ($Release.Prerelease) { " [PRE-RELEASE]" } else { "" }
        $CurrentTag = if ($Release.TagName -eq $CurrentVersion) { " (current)" } else { "" }
        Write-Host "  [$Index] $($Release.TagName)$PreReleaseTag$CurrentTag" -ForegroundColor White
        Write-Host "      $($Release.Name)" -ForegroundColor DarkGray
        $Index++
    }

    Write-Host ""
    Write-Host "  [0] Don't pin (use latest from main branch)" -ForegroundColor Yellow
    Write-Host "  [M] Enter version manually" -ForegroundColor Yellow
    Write-Host ""

    $Choice = Read-UserInput -Prompt "Select version" -Default "1"

    if ($Choice -eq "0") {
        return ""
    }
    elseif ($Choice.ToUpper() -eq "M") {
        return Read-UserInput -Prompt "Version tag (e.g., v2025.12.29)" -Default $CurrentVersion
    }
    elseif ($Choice -match '^\d+$') {
        $ChoiceInt = [int]$Choice
        if ($ChoiceInt -ge 1 -and $ChoiceInt -le $Releases.Count) {
            $SelectedRelease = $Releases[$ChoiceInt - 1]

            # Show release notes
            Show-ReleaseNotes -Release $SelectedRelease

            # Confirm selection
            if (Read-YesNo -Prompt "Pin to $($SelectedRelease.TagName)" -Default $true) {
                return $SelectedRelease.TagName
            }
            else {
                # Recurse to allow another selection
                return Select-Version -CurrentVersion $CurrentVersion
            }
        }
    }

    Write-LevelWarning "Invalid selection. Please try again."
    return Select-Version -CurrentVersion $CurrentVersion
}

# ============================================================
# MODULE EXPORTS
# ============================================================

Write-Host "[*] COOLForge-CustomFields v$Script:ModuleVersion loaded" -ForegroundColor DarkGray

Export-ModuleMember -Function @(
    # Initialization
    'Initialize-COOLForgeCustomFields',

    # UI Helpers
    'Write-Header',
    'Write-LevelSuccess',
    'Write-LevelInfo',
    'Write-LevelWarning',
    'Write-LevelError',
    'Read-UserInput',
    'Read-YesNo',
    'Get-CompanyNameFromPath',

    # API Core
    'Invoke-LevelApi',
    'Get-ExistingCustomFields',
    'Find-CustomField',
    'New-CustomField',
    'Update-CustomFieldValue',
    'Get-CustomFieldById',

    # Hierarchy Navigation
    'Get-AllOrganizations',
    'Get-OrganizationFolders',
    'Get-FolderDevices',
    'Get-EntityCustomFields',
    'Set-EntityCustomField',

    # Backup/Restore
    'Backup-AllCustomFields',
    'Save-Backup',
    'Import-Backup',
    'Restore-CustomFields',
    'Get-BackupPath',
    'Get-LatestBackup',
    'Compare-BackupWithCurrent',
    'Show-BackupDifferences',

    # Config/Security
    'Get-SavedConfig',
    'Save-Config',
    'Protect-ApiKey',
    'Unprotect-ApiKey',

    # GitHub
    'Get-GitHubReleases',
    'Show-ReleaseNotes',
    'Select-Version'
)
