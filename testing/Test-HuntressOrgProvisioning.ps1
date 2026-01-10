<#
.SYNOPSIS
    Standalone test script for Huntress organization auto-provisioning.

.DESCRIPTION
    Deploy this script via Level.io to test the Huntress org provisioning flow:
    1. Gets the device's Level group path
    2. Extracts the top-level folder as the Huntress org name
    3. Checks if the Huntress org exists via API
    4. Creates the org if it doesn't exist
    5. Writes the org key back to Level custom field on the group

    NO DEPENDENCIES on COOLForge library - fully standalone.

.NOTES
    Version: 2026.01.08.01

    Level.io Custom Fields Required:
    - cf_huntress_api_key           : Huntress API public key
    - cf_huntress_api_secret        : Huntress API secret key
    - cf_apikey                     : Level.io API key (for writing org key back)
    - cf_huntress_organization_key  : Will be populated with the org key

    Level.io Variables Used:
    - level_group_path              : Full group path (e.g., "COOLNETWORKS / testing")
    - level_device_hostname         : Device hostname
#>

# ============================================================
# LEVEL.IO VARIABLES
# ============================================================
$HuntressApiKey = "{{cf_huntress_api_key}}"
$HuntressApiSecret = "{{cf_huntress_api_secret}}"
$LevelApiKey = "{{cf_apikey}}"
$LevelGroupPath = "{{level_group_path}}"
$DeviceHostname = "{{level_device_hostname}}"

# Set to $false to make actual changes (default is dry-run for safety)
$WhatIf = $true

# ============================================================
# CONFIGURATION
# ============================================================
$HuntressApiBaseUrl = "https://api.huntress.io/v1"
$LevelApiBaseUrl = "https://api.level.io/v2"

# ============================================================
# LOGGING FUNCTIONS
# ============================================================
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "SUCCESS", "WARN", "ERROR", "DEBUG")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $prefix = switch ($Level) {
        "INFO"    { "[*]" }
        "SUCCESS" { "[+]" }
        "WARN"    { "[!]" }
        "ERROR"   { "[X]" }
        "DEBUG"   { "[D]" }
    }

    $color = switch ($Level) {
        "INFO"    { "White" }
        "SUCCESS" { "Green" }
        "WARN"    { "Yellow" }
        "ERROR"   { "Red" }
        "DEBUG"   { "DarkGray" }
    }

    Write-Host "$timestamp $prefix $Message" -ForegroundColor $color
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
}

# ============================================================
# HUNTRESS API FUNCTIONS
# ============================================================
function Invoke-HuntressApiCall {
    param(
        [Parameter(Mandatory)]
        [string]$Endpoint,

        [ValidateSet("GET", "POST", "PATCH", "DELETE")]
        [string]$Method = "GET",

        [hashtable]$Body = $null
    )

    $uri = "$HuntressApiBaseUrl$Endpoint"

    # Build Basic Auth header
    $authString = "${HuntressApiKey}:${HuntressApiSecret}"
    $authBytes = [System.Text.Encoding]::UTF8.GetBytes($authString)
    $authBase64 = [Convert]::ToBase64String($authBytes)

    $headers = @{
        "Authorization" = "Basic $authBase64"
        "Content-Type" = "application/json"
        "Accept" = "application/json"
    }

    Write-Log "API Call: $Method $uri" -Level "DEBUG"

    try {
        $params = @{
            Uri = $uri
            Method = $Method
            Headers = $headers
            UseBasicParsing = $true
        }

        if ($Body -and $Method -ne "GET") {
            $jsonBody = $Body | ConvertTo-Json -Depth 10
            $params.Body = $jsonBody
            Write-Log "Request Body: $jsonBody" -Level "DEBUG"
        }

        $response = Invoke-RestMethod @params

        return @{
            Success = $true
            Data = $response
            Error = $null
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
        if ($_.Exception.Response) {
            try {
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $errorBody = $reader.ReadToEnd()
                $reader.Close()
                $errorMessage = "$errorMessage - $errorBody"
            }
            catch {}
        }

        Write-Log "API Error: $errorMessage" -Level "ERROR"

        return @{
            Success = $false
            Data = $null
            Error = $errorMessage
        }
    }
}

function Get-HuntressOrganizations {
    Write-Log "Fetching all Huntress organizations..."

    $allOrgs = @()
    $page = 1
    $hasMore = $true

    while ($hasMore) {
        $result = Invoke-HuntressApiCall -Endpoint "/organizations?page=$page&limit=100"

        if (-not $result.Success) {
            return $null
        }

        if ($result.Data.organizations) {
            $allOrgs += $result.Data.organizations
            Write-Log "Page $page: Found $($result.Data.organizations.Count) organizations" -Level "DEBUG"
        }

        # Check pagination
        if ($result.Data.organizations.Count -lt 100) {
            $hasMore = $false
        }
        else {
            $page++
        }
    }

    Write-Log "Total organizations found: $($allOrgs.Count)" -Level "SUCCESS"
    return $allOrgs
}

function Find-HuntressOrganization {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [array]$Organizations = $null
    )

    if (-not $Organizations) {
        $Organizations = Get-HuntressOrganizations
        if (-not $Organizations) {
            return $null
        }
    }

    # Case-insensitive search
    $found = $Organizations | Where-Object { $_.name -eq $Name }

    if ($found) {
        Write-Log "Found organization: $Name (ID: $($found.id))" -Level "SUCCESS"
        return $found
    }

    Write-Log "Organization not found: $Name" -Level "WARN"
    return $null
}

function New-HuntressOrganization {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [string]$Key = $null
    )

    # If no key provided, generate one from the name
    if (-not $Key) {
        # Create key from name: lowercase, replace spaces with underscores, remove special chars
        $Key = $Name.ToLower() -replace '\s+', '_' -replace '[^a-z0-9_]', ''
        Write-Log "Generated organization key: $Key" -Level "DEBUG"
    }

    $body = @{
        name = $Name
        key = $Key
    }

    Write-Log "Creating new Huntress organization: $Name (key: $Key)"

    $result = Invoke-HuntressApiCall -Endpoint "/organizations" -Method "POST" -Body $body

    if ($result.Success) {
        Write-Log "Organization created successfully!" -Level "SUCCESS"
        Write-Log "  Name: $($result.Data.name)" -Level "INFO"
        Write-Log "  ID: $($result.Data.id)" -Level "INFO"
        Write-Log "  Key: $($result.Data.key)" -Level "INFO"
        return $result.Data
    }

    return $null
}

# ============================================================
# LEVEL.IO API FUNCTIONS
# ============================================================
function Invoke-LevelApiCall {
    param(
        [Parameter(Mandatory)]
        [string]$Endpoint,

        [ValidateSet("GET", "POST", "PATCH", "DELETE")]
        [string]$Method = "GET",

        [hashtable]$Body = $null
    )

    $uri = "$LevelApiBaseUrl$Endpoint"

    $headers = @{
        "Authorization" = "Bearer $LevelApiKey"
        "Content-Type" = "application/json"
        "Accept" = "application/json"
    }

    Write-Log "Level API Call: $Method $uri" -Level "DEBUG"

    try {
        $params = @{
            Uri = $uri
            Method = $Method
            Headers = $headers
            UseBasicParsing = $true
        }

        if ($Body -and $Method -ne "GET") {
            $jsonBody = $Body | ConvertTo-Json -Depth 10
            $params.Body = $jsonBody
            Write-Log "Request Body: $jsonBody" -Level "DEBUG"
        }

        $response = Invoke-RestMethod @params

        return @{
            Success = $true
            Data = $response
            Error = $null
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-Log "Level API Error: $errorMessage" -Level "ERROR"

        return @{
            Success = $false
            Data = $null
            Error = $errorMessage
        }
    }
}

function Get-TopLevelGroupName {
    param(
        [Parameter(Mandatory)]
        [string]$GroupPath
    )

    Write-Log "Parsing group path: $GroupPath" -Level "DEBUG"

    # Split by " / " (Level.io format)
    $parts = $GroupPath -split '\s*/\s*'

    # Get first non-empty part
    $topLevel = ($parts | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1).Trim()

    Write-Log "Top-level group name: $topLevel" -Level "DEBUG"

    return $topLevel
}

function Find-LevelDevice {
    param(
        [Parameter(Mandatory)]
        [string]$Hostname
    )

    Write-Log "Finding device in Level.io: $Hostname"

    $startingAfter = $null

    do {
        $uri = "/devices?limit=100"
        if ($startingAfter) {
            $uri += "&starting_after=$startingAfter"
        }

        $result = Invoke-LevelApiCall -Endpoint $uri

        if (-not $result.Success) {
            return $null
        }

        $device = $result.Data.data | Where-Object { $_.hostname -eq $Hostname } | Select-Object -First 1

        if ($device) {
            Write-Log "Found device: $Hostname (ID: $($device.id), Group: $($device.group_id))" -Level "SUCCESS"
            return $device
        }

        # Pagination
        $startingAfter = if ($result.Data.has_more -and $result.Data.data.Count -gt 0) {
            $result.Data.data[-1].id
        } else {
            $null
        }
    } while ($startingAfter)

    Write-Log "Device not found: $Hostname" -Level "WARN"
    return $null
}

function Get-LevelCustomFieldDefinition {
    param(
        [Parameter(Mandatory)]
        [string]$FieldName
    )

    Write-Log "Finding custom field definition: $FieldName" -Level "DEBUG"

    $result = Invoke-LevelApiCall -Endpoint "/custom_fields"

    if (-not $result.Success) {
        return $null
    }

    $field = $result.Data.data | Where-Object { $_.name -eq $FieldName } | Select-Object -First 1

    if ($field) {
        Write-Log "Found custom field: $FieldName (ID: $($field.id))" -Level "DEBUG"
        return $field
    }

    Write-Log "Custom field not found: $FieldName" -Level "WARN"
    return $null
}

function Set-LevelGroupCustomFieldValue {
    param(
        [Parameter(Mandatory)]
        [string]$GroupId,

        [Parameter(Mandatory)]
        [string]$FieldId,

        [Parameter(Mandatory)]
        [string]$Value
    )

    Write-Log "Setting custom field value on group $GroupId"
    Write-Log "  Field ID: $FieldId" -Level "DEBUG"
    Write-Log "  Value: $Value" -Level "DEBUG"

    $body = @{
        value = $Value
    }

    $result = Invoke-LevelApiCall -Endpoint "/groups/$GroupId/custom_field_values/$FieldId" -Method "PATCH" -Body $body

    if ($result.Success) {
        Write-Log "Custom field value set successfully!" -Level "SUCCESS"
        return $true
    }

    return $false
}

function New-LevelCustomField {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [string]$Description = "",

        [bool]$AdminOnly = $false
    )

    Write-Log "Creating custom field: $Name"

    $body = @{
        name = $Name
    }

    if ($Description) {
        $body.description = $Description
    }

    if ($AdminOnly) {
        $body.admin_only = $true
    }

    $result = Invoke-LevelApiCall -Endpoint "/custom_fields" -Method "POST" -Body $body

    if ($result.Success) {
        Write-Log "Custom field created successfully!" -Level "SUCCESS"
        Write-Log "  ID: $($result.Data.id)" -Level "DEBUG"
        return $result.Data
    }

    Write-Log "Failed to create custom field: $($result.Error)" -Level "ERROR"
    return $null
}

function Get-OrCreateLevelCustomField {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [string]$Description = "",

        [bool]$AdminOnly = $false
    )

    # First try to find existing
    $existing = Get-LevelCustomFieldDefinition -FieldName $Name

    if ($existing) {
        return $existing
    }

    # Create if not found
    Write-Log "Custom field '$Name' not found - creating it" -Level "WARN"
    return New-LevelCustomField -Name $Name -Description $Description -AdminOnly $AdminOnly
}

# ============================================================
# MAIN SCRIPT
# ============================================================

Write-Section "HUNTRESS ORG PROVISIONING TEST"
Write-Log "Script Version: 2026.01.08.01"
Write-Log "WhatIf Mode: $WhatIf"
Write-Host ""

# ============================================================
# STEP 1: Validate Inputs
# ============================================================
Write-Section "STEP 1: Validate Configuration"

$validationErrors = @()
$skipLevelIntegration = $false

# Helper to check if a Level.io variable was populated
function Test-LevelVariable {
    param([string]$Value, [string]$VariableName)
    # Check for empty, whitespace, or unpopulated template literal
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -match '^\{\{.*\}\}$') {
        return $false
    }
    return $true
}

# Check Huntress API credentials
if (-not (Test-LevelVariable $HuntressApiKey "cf_huntress_api_key")) {
    $validationErrors += "Huntress API Key not configured (cf_huntress_api_key)"
}
else {
    $maskedKey = $HuntressApiKey.Substring(0, [Math]::Min(4, $HuntressApiKey.Length)) + "****"
    Write-Log "Huntress API Key: $maskedKey" -Level "SUCCESS"
}

if (-not (Test-LevelVariable $HuntressApiSecret "cf_huntress_api_secret")) {
    $validationErrors += "Huntress API Secret not configured (cf_huntress_api_secret)"
}
else {
    Write-Log "Huntress API Secret: ****" -Level "SUCCESS"
}

# Check Group Path
if (-not (Test-LevelVariable $LevelGroupPath "level_group_path")) {
    $validationErrors += "Level Group Path not available (level_group_path)"
}
else {
    Write-Log "Level Group Path: $LevelGroupPath" -Level "SUCCESS"
}

# Check Level API key (optional but needed for writing back)
if (-not (Test-LevelVariable $LevelApiKey "cf_apikey")) {
    Write-Log "Level API Key: NOT CONFIGURED (will skip custom field update)" -Level "WARN"
    $skipLevelIntegration = $true
}
else {
    $maskedKey = $LevelApiKey.Substring(0, [Math]::Min(4, $LevelApiKey.Length)) + "****"
    Write-Log "Level API Key: $maskedKey" -Level "SUCCESS"
}

# Check Device Hostname
if (-not (Test-LevelVariable $DeviceHostname "level_device_hostname")) {
    $DeviceHostname = $env:COMPUTERNAME
    Write-Log "Device Hostname: $DeviceHostname (from env)" -Level "INFO"
}
else {
    Write-Log "Device Hostname: $DeviceHostname" -Level "SUCCESS"
}

# ============================================================
# CHECK/CREATE MISSING CUSTOM FIELDS
# ============================================================
$missingFields = @()
$createdFields = @()

if ($validationErrors.Count -gt 0 -and -not $skipLevelIntegration) {
    Write-Host ""
    Write-Log "Some required custom fields are not configured" -Level "WARN"
    Write-Log "Checking if they exist in Level.io..." -Level "INFO"

    # Define required fields with descriptions
    $requiredFields = @{
        "cf_huntress_api_key" = @{
            Description = "Huntress API public key for organization management"
            AdminOnly = $true
        }
        "cf_huntress_api_secret" = @{
            Description = "Huntress API secret key for organization management"
            AdminOnly = $true
        }
        "cf_huntress_organization_key" = @{
            Description = "Auto-populated Huntress organization install key"
            AdminOnly = $false
        }
    }

    foreach ($fieldName in $requiredFields.Keys) {
        $fieldConfig = $requiredFields[$fieldName]
        $existingField = Get-LevelCustomFieldDefinition -FieldName $fieldName

        if (-not $existingField) {
            Write-Log "Custom field '$fieldName' does not exist - CREATING" -Level "WARN"

            $newField = New-LevelCustomField -Name $fieldName -Description $fieldConfig.Description -AdminOnly $fieldConfig.AdminOnly

            if ($newField) {
                $createdFields += $fieldName
            }
            else {
                $missingFields += $fieldName
            }
        }
        else {
            Write-Log "Custom field '$fieldName' exists (ID: $($existingField.id))" -Level "DEBUG"
        }
    }
}

# Show big alert if fields were created
if ($createdFields.Count -gt 0) {
    Write-Host ""
    Write-Host ("!" * 60) -ForegroundColor Red
    Write-Host "!" -ForegroundColor Red -NoNewline
    Write-Host "  ACTION REQUIRED: NEW CUSTOM FIELDS CREATED  ".PadRight(57) -ForegroundColor Yellow -NoNewline
    Write-Host "!" -ForegroundColor Red
    Write-Host ("!" * 60) -ForegroundColor Red
    Write-Host ""
    Write-Log "The following custom fields were created in Level.io:" -Level "WARN"
    foreach ($field in $createdFields) {
        Write-Log "  - $field" -Level "WARN"
    }
    Write-Host ""
    Write-Host ("!" * 60) -ForegroundColor Red
    Write-Log "GO TO LEVEL.IO AND FILL IN THESE VALUES:" -Level "ERROR"
    Write-Host ("!" * 60) -ForegroundColor Red
    Write-Host ""
    Write-Log "1. Log into Level.io" -Level "INFO"
    Write-Log "2. Go to Settings > Custom Fields" -Level "INFO"
    Write-Log "3. Find and set values for:" -Level "INFO"
    Write-Log "   - cf_huntress_api_key    : Your Huntress API public key" -Level "INFO"
    Write-Log "   - cf_huntress_api_secret : Your Huntress API secret key" -Level "INFO"
    Write-Host ""
    Write-Log "Get your Huntress API credentials from:" -Level "INFO"
    Write-Log "   https://huntress.io/account/api" -Level "INFO"
    Write-Host ""
    Write-Host ("!" * 60) -ForegroundColor Red
    Write-Log "RE-RUN THIS SCRIPT AFTER SETTING THE VALUES" -Level "ERROR"
    Write-Host ("!" * 60) -ForegroundColor Red
    Write-Host ""
    exit 2
}

if ($validationErrors.Count -gt 0) {
    Write-Host ""
    Write-Log "VALIDATION FAILED" -Level "ERROR"
    foreach ($err in $validationErrors) {
        Write-Log "  - $err" -Level "ERROR"
    }
    Write-Host ""
    Write-Log "Please configure the missing custom fields in Level.io and re-run" -Level "INFO"
    exit 1
}

Write-Log "All configuration validated!" -Level "SUCCESS"

# ============================================================
# STEP 2: Extract Huntress Org Name from Group Path
# ============================================================
Write-Section "STEP 2: Determine Huntress Organization Name"

$huntressOrgName = Get-TopLevelGroupName -GroupPath $LevelGroupPath

Write-Log "Level Group Path: $LevelGroupPath"
Write-Log "Huntress Org Name (top-level): $huntressOrgName" -Level "SUCCESS"

# Generate org key (lowercase, underscores)
$huntressOrgKey = $huntressOrgName.ToLower() -replace '\s+', '_' -replace '[^a-z0-9_]', ''
Write-Log "Huntress Org Key: $huntressOrgKey"

# ============================================================
# STEP 3: Check if Huntress Org Exists
# ============================================================
Write-Section "STEP 3: Check Huntress Organization"

Write-Log "Connecting to Huntress API..."

$existingOrgs = Get-HuntressOrganizations
if (-not $existingOrgs) {
    Write-Log "Failed to retrieve Huntress organizations" -Level "ERROR"
    exit 1
}

$existingOrg = Find-HuntressOrganization -Name $huntressOrgName -Organizations $existingOrgs

if ($existingOrg) {
    Write-Host ""
    Write-Log "ORGANIZATION EXISTS" -Level "SUCCESS"
    Write-Log "  Name: $($existingOrg.name)"
    Write-Log "  ID: $($existingOrg.id)"
    Write-Log "  Key: $($existingOrg.key)"

    $huntressOrgKey = $existingOrg.key
}
else {
    Write-Host ""
    Write-Log "ORGANIZATION DOES NOT EXIST" -Level "WARN"
    Write-Log "Will create new organization: $huntressOrgName"

    if ($WhatIf) {
        Write-Log "[WHATIF] Would create organization: $huntressOrgName (key: $huntressOrgKey)" -Level "WARN"
    }
    else {
        $newOrg = New-HuntressOrganization -Name $huntressOrgName -Key $huntressOrgKey

        if (-not $newOrg) {
            Write-Log "Failed to create organization" -Level "ERROR"
            exit 1
        }

        $huntressOrgKey = $newOrg.key
        Write-Log "Organization created with key: $huntressOrgKey" -Level "SUCCESS"
    }
}

# ============================================================
# STEP 4: Find Device and Group in Level.io (Optional)
# ============================================================
Write-Section "STEP 4: Level.io Integration"

$device = $null

if ($skipLevelIntegration) {
    Write-Log "SKIPPING Level.io integration (no API key configured)" -Level "WARN"
    Write-Log "To enable: set cf_apikey custom field in Level.io" -Level "INFO"
}
else {
    Write-Log "Looking up device: $DeviceHostname"

    $device = Find-LevelDevice -Hostname $DeviceHostname

    if (-not $device) {
        Write-Log "Could not find device in Level.io" -Level "WARN"
        Write-Log "Cannot update custom field without device/group context" -Level "WARN"
    }
    else {
        Write-Log "Device found!" -Level "SUCCESS"
        Write-Log "  Hostname: $($device.hostname)"
        Write-Log "  Device ID: $($device.id)"
        Write-Log "  Group ID: $($device.group_id)"
    }
}

# ============================================================
# STEP 5: Update Level Custom Field with Org Key (Optional)
# ============================================================
Write-Section "STEP 5: Update Level Custom Field"

$orgKeyFieldName = "cf_huntress_organization_key"

if ($skipLevelIntegration) {
    Write-Log "SKIPPING custom field update (no Level API key)" -Level "WARN"
    Write-Log "In production, org key '$huntressOrgKey' would be written to $orgKeyFieldName" -Level "INFO"
}
elseif (-not $device) {
    Write-Log "SKIPPING custom field update (device not found)" -Level "WARN"
}
else {
    Write-Log "Looking for custom field: $orgKeyFieldName"

    $orgKeyField = Get-LevelCustomFieldDefinition -FieldName $orgKeyFieldName

    if (-not $orgKeyField) {
        Write-Log "Custom field '$orgKeyFieldName' not found in Level.io" -Level "ERROR"
        Write-Log "Please create this custom field in Level.io first" -Level "WARN"
    }
    else {
        Write-Log "Custom field found: $($orgKeyField.id)"
        Write-Log "Will set value: $huntressOrgKey"

        if ($WhatIf) {
            Write-Log "[WHATIF] Would set $orgKeyFieldName = $huntressOrgKey on group $($device.group_id)" -Level "WARN"
        }
        else {
            $success = Set-LevelGroupCustomFieldValue -GroupId $device.group_id -FieldId $orgKeyField.id -Value $huntressOrgKey

            if ($success) {
                Write-Log "Custom field updated successfully!" -Level "SUCCESS"
            }
            else {
                Write-Log "Failed to update custom field" -Level "ERROR"
            }
        }
    }
}

# ============================================================
# SUMMARY
# ============================================================
Write-Section "SUMMARY"

Write-Host ""
Write-Host "  INPUT" -ForegroundColor White
Write-Host "  -----" -ForegroundColor White
Write-Log "  Level Group Path:      $LevelGroupPath"
Write-Host ""

Write-Host "  HUNTRESS" -ForegroundColor White
Write-Host "  --------" -ForegroundColor White
Write-Log "  Org Name:              $huntressOrgName"
Write-Log "  Org Key:               $huntressOrgKey"

if ($existingOrg) {
    Write-Log "  Status:                EXISTS (no creation needed)" -Level "SUCCESS"
}
else {
    if ($WhatIf) {
        Write-Log "  Status:                WOULD BE CREATED (WhatIf mode)" -Level "WARN"
    }
    else {
        Write-Log "  Status:                CREATED" -Level "SUCCESS"
    }
}

Write-Host ""
Write-Host "  LEVEL.IO" -ForegroundColor White
Write-Host "  --------" -ForegroundColor White
Write-Log "  Custom Field:          $orgKeyFieldName"

if ($skipLevelIntegration) {
    Write-Log "  Status:                SKIPPED (no API key)" -Level "WARN"
}
elseif (-not $device) {
    Write-Log "  Status:                SKIPPED (device not found)" -Level "WARN"
}
else {
    if ($WhatIf) {
        Write-Log "  Status:                WOULD UPDATE group $($device.group_id)" -Level "WARN"
    }
    else {
        Write-Log "  Status:                UPDATED" -Level "SUCCESS"
    }
}

Write-Host ""
Write-Host ("=" * 60) -ForegroundColor Cyan
Write-Host ""
Write-Log "NEXT STEP: Use org key '$huntressOrgKey' for Huntress installation"
Write-Host ""

if ($WhatIf) {
    Write-Log "This was a WhatIf run - no changes were made" -Level "WARN"
}

exit 0
