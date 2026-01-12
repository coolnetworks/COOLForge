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
    Version:    2026.01.07.01
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
    $UserInput = Read-Host

    if ([string]::IsNullOrWhiteSpace($UserInput)) {
        return $Default
    }
    return $UserInput
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
    $UserInput = Read-Host

    if ([string]::IsNullOrWhiteSpace($UserInput)) {
        return $Default
    }

    return $UserInput.ToLower() -eq "y" -or $UserInput.ToLower() -eq "yes"
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
        Write-Host "    DEBUG: Calling $Method $Uri" -ForegroundColor DarkGray
        $Response = Invoke-RestMethod @Params
        Write-Host "    DEBUG: Success" -ForegroundColor DarkGray
        return @{ Success = $true; Data = $Response }
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Host "    DEBUG: Exception - $ErrorMessage" -ForegroundColor Red
        if ($_.Exception.Response) {
            try {
                $StatusCode = [int]$_.Exception.Response.StatusCode
                Write-Host "    DEBUG: HTTP Status Code - $StatusCode" -ForegroundColor Red
                $Reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $ErrorBody = $Reader.ReadToEnd()
                $Reader.Close()
                if ($ErrorBody) {
                    Write-Host "    DEBUG: Response Body - $ErrorBody" -ForegroundColor Red
                    $ErrorMessage = $ErrorBody
                }
            }
            catch {
                Write-Host "    DEBUG: Could not read response body" -ForegroundColor Red
            }
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
            Write-Host "    API Error Details: $($Result.Error)" -ForegroundColor Red
            return $null
        }

        $Data = $Result.Data

        # Check for .data property explicitly (don't rely on truthy/falsy since empty array is falsy)
        $Fields = if ($null -ne $Data.data) { $Data.data } else { $Data }

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

    # Use Write-Output with -NoEnumerate to prevent PowerShell from unrolling empty arrays to $null
    Write-Output -NoEnumerate @($AllFields)
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
        Updates a custom field's global/account-level value.
    .DESCRIPTION
        Uses PATCH /custom_field_values with assigned_to_id=null to set the
        global organization-level value for a custom field.
    .PARAMETER FieldId
        The ID of the custom field to update.
    .PARAMETER Value
        The value to set.
    .PARAMETER AllowEmpty
        If set to $true, allows setting an empty value. Default is $false.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$FieldId,

        [Parameter(Mandatory = $true)]
        [string]$Value,

        [Parameter(Mandatory = $false)]
        [bool]$AllowEmpty = $false
    )

    # Safety check - don't accidentally clear values
    if (-not $AllowEmpty -and [string]::IsNullOrWhiteSpace($Value)) {
        Write-LevelWarning "Skipping update - value is empty (use -AllowEmpty to override)"
        Write-LevelWarning "  FieldId: $FieldId"
        Write-LevelWarning "  Value: '$Value'"
        return $false
    }

    Write-LevelInfo "Setting global value for field $FieldId to '$Value'..."

    # PATCH /custom_field_values with assigned_to_id=null sets global value
    $Body = @{
        custom_field_id = $FieldId
        assigned_to_id  = $null
        value           = $Value
    }

    $Result = Invoke-LevelApi -Endpoint "/custom_field_values" -Method "PATCH" -Body $Body

    if ($Result.Success) {
        Write-LevelSuccess "Set global value: '$Value'"

        # Verify by reading back
        Write-LevelInfo "Verifying..."
        $VerifyResult = Invoke-LevelApi -Endpoint "/custom_field_values?limit=100" -Method "GET"
        if ($VerifyResult.Success) {
            $Values = if ($VerifyResult.Data.data) { $VerifyResult.Data.data } else { @($VerifyResult.Data) }
            $GlobalValue = $Values | Where-Object { $_.custom_field_id -eq $FieldId -and [string]::IsNullOrEmpty($_.assigned_to_id) } | Select-Object -First 1
            if ($GlobalValue -and $GlobalValue.value -eq $Value) {
                Write-LevelSuccess "VERIFIED: Global value = '$($GlobalValue.value)'"
            }
            elseif ($GlobalValue) {
                Write-LevelWarning "MISMATCH: Expected '$Value' but got '$($GlobalValue.value)'"
            }
            else {
                Write-LevelWarning "Could not find global value in verification"
            }
        }
        return $true
    }
    else {
        Write-LevelError "Failed to set global value: $($Result.Error)"
        return $false
    }
}

function Remove-CustomFieldValue {
    <#
    .SYNOPSIS
        Clears a custom field's global/account-level value by deleting and recreating the field.
    .DESCRIPTION
        The Level.io API doesn't support clearing values directly. This function
        deletes the custom field and recreates it with an empty value.
    .PARAMETER FieldId
        The ID of the custom field whose global value should be cleared.
    .PARAMETER FieldName
        The name of the custom field (required to recreate it).
    .PARAMETER AdminOnly
        Whether the field should be admin-only when recreated.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$FieldId,

        [Parameter(Mandatory = $true)]
        [string]$FieldName,

        [Parameter(Mandatory = $false)]
        [bool]$AdminOnly = $false
    )

    Write-LevelInfo "Clearing value by deleting and recreating field '$FieldName'..."

    # Delete the field
    $DeleteResult = Invoke-LevelApi -Endpoint "/custom_fields/$FieldId" -Method "DELETE"

    if (-not $DeleteResult.Success) {
        Write-LevelError "Failed to delete field: $($DeleteResult.Error)"
        return $null
    }

    Write-LevelSuccess "Deleted field"

    # Recreate it with empty value
    Start-Sleep -Milliseconds 500  # Brief pause to let API settle

    $Created = New-CustomField -Name $FieldName -DefaultValue "" -AdminOnly $AdminOnly

    if ($Created) {
        Write-LevelSuccess "Recreated field with empty value"
        return $Created
    }
    else {
        Write-LevelError "Failed to recreate field"
        return $null
    }
}

function Remove-CustomField {
    <#
    .SYNOPSIS
        Deletes a custom field by ID.
    .DESCRIPTION
        Permanently removes a custom field definition from Level.io.
        WARNING: This will also remove all values associated with this field.
    .PARAMETER FieldId
        The ID of the custom field to delete.
    .PARAMETER FieldName
        Optional name of the field (for display purposes only).
    .EXAMPLE
        Remove-CustomField -FieldId "cf_abc123" -FieldName "old_field_name"
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$FieldId,

        [Parameter(Mandatory = $false)]
        [string]$FieldName = ""
    )

    $DisplayName = if ($FieldName) { "'$FieldName'" } else { $FieldId }

    $Result = Invoke-LevelApi -Endpoint "/custom_fields/$FieldId" -Method "DELETE"

    if ($Result.Success) {
        Write-LevelSuccess "Deleted custom field: $DisplayName"
        return $true
    }
    else {
        Write-LevelError "Failed to delete custom field $DisplayName`: $($Result.Error)"
        return $false
    }
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
# TAG MANAGEMENT FUNCTIONS
# ============================================================

function Get-LevelTags {
    <#
    .SYNOPSIS
        Gets all tags from Level.io.
    .DESCRIPTION
        Retrieves all tags defined in the Level.io account.
        Handles pagination automatically.
    .PARAMETER ApiKey
        Level.io API key for authentication.
    .OUTPUTS
        Array of tag objects, or empty array on error.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey
    )

    $AllTags = @()
    $StartingAfter = $null

    do {
        $Endpoint = "/tags?limit=100"
        if ($StartingAfter) {
            $Endpoint += "&starting_after=$StartingAfter"
        }

        # Use direct API call since we need the ApiKey parameter
        # Note: Level.io API does NOT use "Bearer " prefix - just the API key directly
        $Uri = "$Script:LevelApiBase$Endpoint"
        $Headers = @{
            "Authorization" = $ApiKey
            "Content-Type"  = "application/json"
        }

        Write-Host "    DEBUG: LevelApiBase = '$Script:LevelApiBase'" -ForegroundColor DarkGray
        Write-Host "    DEBUG: Calling GET $Uri" -ForegroundColor DarkGray
        Write-Host "    DEBUG: ApiKey length = $($ApiKey.Length)" -ForegroundColor DarkGray

        try {
            $Response = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method Get -ErrorAction Stop
            $AllTags += $Response.data

            # Handle pagination
            $StartingAfter = if ($Response.has_more -and $Response.data.Count -gt 0) {
                $Response.data[-1].id
            } else {
                $null
            }
        }
        catch {
            Write-LevelError "Failed to fetch tags: $($_.Exception.Message)"
            return @()
        }
    } while ($StartingAfter)

    return $AllTags
}

function New-LevelTag {
    <#
    .SYNOPSIS
        Creates a new tag in Level.io.
    .DESCRIPTION
        Creates a tag with the specified name in Level.io.
    .PARAMETER ApiKey
        Level.io API key for authentication.
    .PARAMETER TagName
        The name of the tag to create (can include emoji).
    .OUTPUTS
        Tag object on success, $null on failure.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $true)]
        [string]$TagName
    )

    # Note: Level.io API does NOT use "Bearer " prefix - just the API key directly
    $Uri = "$Script:LevelApiBase/tags"
    $Headers = @{
        "Authorization" = $ApiKey
        "Content-Type"  = "application/json; charset=utf-8"
    }
    # Ensure proper UTF-8 encoding for emoji characters
    $JsonBody = @{ name = $TagName } | ConvertTo-Json
    $Body = [System.Text.Encoding]::UTF8.GetBytes($JsonBody)

    Write-Host "    DEBUG: Calling POST $Uri" -ForegroundColor DarkGray
    Write-Host "    DEBUG: Tag name = '$TagName'" -ForegroundColor DarkGray

    try {
        $Response = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method Post -Body $Body -ErrorAction Stop
        return $Response
    }
    catch {
        # 422 typically means tag already exists - treat as success
        if ($_.Exception.Response.StatusCode.value__ -eq 422) {
            Write-Host "    Tag '$TagName' already exists" -ForegroundColor DarkGray
            return @{ name = $TagName; already_exists = $true }
        }
        Write-LevelError "Failed to create tag '$TagName': $($_.Exception.Message)"
        return $null
    }
}

function Remove-LevelTag {
    <#
    .SYNOPSIS
        Deletes a tag from Level.io.
    .DESCRIPTION
        Permanently removes a tag from Level.io by its ID.
    .PARAMETER ApiKey
        Level.io API key for authentication.
    .PARAMETER TagId
        The ID of the tag to delete.
    .PARAMETER TagName
        Optional name of the tag (for display purposes only).
    .OUTPUTS
        $true on success, $false on failure.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $true)]
        [string]$TagId,

        [Parameter(Mandatory = $false)]
        [string]$TagName = ""
    )

    # Note: Level.io API does NOT use "Bearer " prefix - just the API key directly
    $Uri = "$Script:LevelApiBase/tags/$TagId"
    $Headers = @{
        "Authorization" = $ApiKey
        "Content-Type"  = "application/json"
    }

    $DisplayName = if ($TagName) { "'$TagName'" } else { $TagId }

    try {
        Invoke-RestMethod -Uri $Uri -Headers $Headers -Method Delete -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 404) {
            Write-Host "    Tag $DisplayName not found (already deleted?)" -ForegroundColor DarkGray
            return $true
        }
        Write-LevelError "Failed to delete tag $DisplayName`: $($_.Exception.Message)"
        return $false
    }
}

# ============================================================
# HIERARCHY NAVIGATION FUNCTIONS
# ============================================================

function Get-AllGroups {
    <#
    .SYNOPSIS
        Gets all groups accessible via the API.
    #>
    $Result = Invoke-LevelApi -Endpoint "/groups"
    if ($Result.Success) {
        $Data = $Result.Data
        if ($Data.data) { $Data = $Data.data }
        return $Data
    }
    return @()
}

# Alias for backwards compatibility
function Get-AllOrganizations {
    Write-LevelWarning "Get-AllOrganizations is deprecated, use Get-AllGroups"
    return Get-AllGroups
}

function Get-GroupFolders {
    <#
    .SYNOPSIS
        Gets all folders for a group.
    #>
    param([string]$GroupId)

    # Validate GroupId - return empty array if missing
    if ([string]::IsNullOrWhiteSpace($GroupId)) {
        return @()
    }

    $Result = Invoke-LevelApi -Endpoint "/groups/$GroupId/folders"
    if ($Result.Success) {
        $Data = $Result.Data
        if ($Data.data) { $Data = $Data.data }
        return $Data
    }
    return @()
}

# Alias for backwards compatibility
function Get-OrganizationFolders {
    param([string]$OrgId)
    Write-LevelWarning "Get-OrganizationFolders is deprecated, use Get-GroupFolders"
    return Get-GroupFolders -GroupId $OrgId
}

function Get-FolderDevices {
    <#
    .SYNOPSIS
        Gets all devices in a folder.
    #>
    param(
        [string]$GroupId,
        [string]$FolderId
    )

    # Validate IDs - return empty array if missing
    if ([string]::IsNullOrWhiteSpace($GroupId) -or [string]::IsNullOrWhiteSpace($FolderId)) {
        return @()
    }

    $Result = Invoke-LevelApi -Endpoint "/groups/$GroupId/folders/$FolderId/devices"
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
        Gets custom field values for an entity (group, folder, or device).
    #>
    param(
        [string]$EntityType,  # "group", "organization" (legacy), "folder", "device"
        [string]$EntityId
    )

    # Validate EntityId - return empty hashtable if missing
    if ([string]::IsNullOrWhiteSpace($EntityId)) {
        return @{}
    }

    $Endpoint = switch ($EntityType) {
        "group" { "/groups/$EntityId" }
        "organization" { "/groups/$EntityId" }  # Legacy alias
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
        [string]$EntityType,  # "group", "organization" (legacy), "folder", "device"
        [string]$EntityId,
        [string]$FieldKey,
        [string]$Value
    )

    $Endpoint = switch ($EntityType) {
        "group" { "/groups/$EntityId" }
        "organization" { "/groups/$EntityId" }  # Legacy alias
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
        Groups        = @()
    }

    # Get custom field definitions
    Write-LevelInfo "Backing up custom field definitions..."
    $Fields = Get-ExistingCustomFields
    if ($Fields.data) { $Fields = $Fields.data }
    $Backup.CustomFields = $Fields

    # Get groups
    Write-LevelInfo "Fetching groups..."
    $Groups = Get-AllGroups

    if (-not $Groups -or $Groups.Count -eq 0) {
        Write-LevelWarning "No groups found or API doesn't support group listing."
        return $Backup
    }

    $GroupCount = if ($Groups -is [array]) { $Groups.Count } else { 1 }
    Write-LevelInfo "Found $GroupCount group(s)."

    foreach ($Group in $Groups) {
        # Skip groups with missing/empty IDs
        if ([string]::IsNullOrWhiteSpace($Group.id)) {
            Write-Host "  Skipping group with empty ID: $($Group.name)" -ForegroundColor Yellow
            continue
        }

        Write-Host "  Processing: $($Group.name)" -ForegroundColor DarkGray

        $GroupBackup = @{
            Id           = $Group.id
            Name         = $Group.name
            CustomFields = Get-EntityCustomFields -EntityType "group" -EntityId $Group.id
            Folders      = @()
        }

        # Get folders for this group
        $Folders = Get-GroupFolders -GroupId $Group.id
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
                $Devices = Get-FolderDevices -GroupId $Group.id -FolderId $Folder.id
                foreach ($Device in $Devices) {
                    $DeviceBackup = @{
                        Id           = $Device.id
                        Name         = $Device.name
                        CustomFields = Get-EntityCustomFields -EntityType "device" -EntityId $Device.id
                    }
                    $FolderBackup.Devices += $DeviceBackup
                }
            }

            $GroupBackup.Folders += $FolderBackup
        }

        $Backup.Groups += $GroupBackup
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

    # Support both old format (Organizations) and new format (Groups)
    $GroupList = if ($Backup.Groups) { $Backup.Groups } elseif ($Backup.Organizations) { $Backup.Organizations } else { @() }

    foreach ($Group in $GroupList) {
        Write-Host "  Restoring: $($Group.Name)" -ForegroundColor DarkGray

        # Restore group-level custom fields
        foreach ($Field in $Group.CustomFields.PSObject.Properties) {
            if (-not [string]::IsNullOrWhiteSpace($Field.Value)) {
                if ($DryRun) {
                    Write-Host "    [DRY-RUN] Would set $($Field.Name) = $($Field.Value) on group" -ForegroundColor Yellow
                }
                else {
                    if (Set-EntityCustomField -EntityType "group" -EntityId $Group.Id -FieldKey $Field.Name -Value $Field.Value) {
                        $Changes++
                    }
                }
            }
        }

        # Restore folder-level custom fields
        foreach ($Folder in $Group.Folders) {
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

    # Support both old format (Organizations) and new format (Groups)
    $GroupList = if ($Backup.Groups) { $Backup.Groups } elseif ($Backup.Organizations) { $Backup.Organizations } else { @() }

    foreach ($GroupBackup in $GroupList) {
        # Get current group custom fields
        $CurrentGroupFields = Get-EntityCustomFields -EntityType "group" -EntityId $GroupBackup.Id

        # Compare group-level fields
        foreach ($Field in $GroupBackup.CustomFields.PSObject.Properties) {
            $BackupValue = $Field.Value
            $CurrentValue = $CurrentGroupFields.$($Field.Name)

            if ($BackupValue -ne $CurrentValue) {
                $Differences += @{
                    EntityType  = "Group"
                    EntityName  = $GroupBackup.Name
                    EntityId    = $GroupBackup.Id
                    FieldName   = $Field.Name
                    BackupValue = if ([string]::IsNullOrWhiteSpace($BackupValue)) { "(empty)" } else { $BackupValue }
                    CurrentValue = if ([string]::IsNullOrWhiteSpace($CurrentValue)) { "(empty)" } else { $CurrentValue }
                }
            }
        }

        # Compare folder-level fields
        foreach ($FolderBackup in $GroupBackup.Folders) {
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
    'Remove-CustomFieldValue',
    'Remove-CustomField',
    'Get-CustomFieldById',

    # Tag Management
    'Get-LevelTags',
    'New-LevelTag',
    'Remove-LevelTag',

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
