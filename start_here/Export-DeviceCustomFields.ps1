<#
.SYNOPSIS
    Exports all custom field values for every device to JSON.

.DESCRIPTION
    Extracts custom field values at all levels of the hierarchy:
    - Global/Account level values
    - Group level values
    - Device level values (with inheritance resolved)

    The output JSON includes:
    - All custom field definitions
    - All groups with their custom field values
    - All devices with their effective custom field values

    This is useful for:
    - Auditing custom field configuration across your account
    - Migrating data between Level.io instances
    - Backup and documentation purposes

.PARAMETER OutputFile
    Path to the output JSON file. Defaults to timestamped file in current directory.

.PARAMETER IncludeInherited
    Include inherited values in device output (default: true).
    When false, only shows values explicitly set on the device.

.PARAMETER Filter
    Filter output to specific custom field names (comma-separated).
    Example: -Filter "coolforge_msp_scratch_folder,coolforge_screenconnect_device_url"

.PARAMETER GroupFilter
    Filter to specific group name pattern (supports wildcards).
    Example: -GroupFilter "*Production*"

.PARAMETER Compact
    Output compact JSON (no indentation).

.NOTES
    Version:          2026.01.07.01
    Target Platform:  Windows PowerShell 5.1+

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge

.EXAMPLE
    .\Export-DeviceCustomFields.ps1
    Exports all custom fields for all devices to timestamped JSON file.

.EXAMPLE
    .\Export-DeviceCustomFields.ps1 -OutputFile ".\exports\fields.json"
    Exports to specific file path.

.EXAMPLE
    .\Export-DeviceCustomFields.ps1 -Filter "coolforge_screenconnect_device_url"
    Exports only the screenconnect_device_url field values.

.EXAMPLE
    .\Export-DeviceCustomFields.ps1 -GroupFilter "*ACME*"
    Exports only devices in groups matching "ACME".
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$OutputFile,

    [Parameter(Mandatory = $false)]
    [bool]$IncludeInherited = $true,

    [Parameter(Mandatory = $false)]
    [string]$Filter,

    [Parameter(Mandatory = $false)]
    [string]$GroupFilter,

    [Parameter(Mandatory = $false)]
    [switch]$Compact
)

$ErrorActionPreference = 'Stop'

# ============================================================
# PATHS AND SETUP
# ============================================================

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptRoot
$SavedConfigPath = Join-Path $ScriptRoot ".COOLForge_Lib-setup.json"

# Default output file (in exports folder)
if (-not $OutputFile) {
    $ExportsFolder = Join-Path $ProjectRoot "exports"
    if (-not (Test-Path $ExportsFolder)) {
        New-Item -ItemType Directory -Path $ExportsFolder -Force | Out-Null
    }
    $Timestamp = (Get-Date).ToString("yyyy-MM-dd_HHmmss")
    $OutputFile = Join-Path $ExportsFolder "DeviceCustomFields_$Timestamp.json"
}

# Parse field filter
$FieldFilter = @()
if ($Filter) {
    $FieldFilter = @($Filter.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

# ============================================================
# API FUNCTIONS (standalone - no module dependency)
# ============================================================

$Script:LevelApiBase = "https://api.level.io/v2"
$Script:ApiKey = $null

function Invoke-LevelApi {
    param(
        [string]$Endpoint,
        [string]$Method = "GET",
        [hashtable]$Body = $null
    )

    $Headers = @{
        "Authorization" = $Script:ApiKey
        "Content-Type"  = "application/json"
    }

    $Uri = "$Script:LevelApiBase$Endpoint"

    try {
        $Params = @{
            Uri     = $Uri
            Method  = $Method
            Headers = $Headers
        }
        if ($Body) {
            $Params.Body = ($Body | ConvertTo-Json -Depth 10)
        }

        $Response = Invoke-RestMethod @Params
        return @{ Success = $true; Data = $Response }
    }
    catch {
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Get-AllPaginated {
    param(
        [string]$Endpoint,
        [int]$Limit = 100
    )

    $AllItems = @()
    $Cursor = $null

    do {
        $Url = "$Endpoint"
        $Separator = if ($Url -match '\?') { '&' } else { '?' }
        $Url += "${Separator}limit=$Limit"
        if ($Cursor) {
            $Url += "&starting_after=$Cursor"
        }

        $Result = Invoke-LevelApi -Endpoint $Url
        if (-not $Result.Success) {
            Write-Host "[!] API Error: $($Result.Error)" -ForegroundColor Red
            break
        }

        $Items = if ($Result.Data.data) { $Result.Data.data } else { @($Result.Data) }
        if ($Items.Count -eq 0) { break }

        $AllItems += $Items
        $Cursor = $Items[-1].id

        # Check if we got less than limit (last page)
        if ($Items.Count -lt $Limit) { break }

    } while ($true)

    return $AllItems
}

# ============================================================
# MAIN
# ============================================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " COOLForge Custom Fields Export" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# ============================================================
# LOAD API KEY
# ============================================================

if (Test-Path $SavedConfigPath) {
    try {
        $SavedConfig = Get-Content $SavedConfigPath -Raw | ConvertFrom-Json

        # Try new key name first, fall back to legacy
        $EncryptedKey = $SavedConfig.CoolForge_ApiKeyEncrypted
        if (-not $EncryptedKey) {
            $EncryptedKey = $SavedConfig.ApiKeyEncrypted
        }

        if ($EncryptedKey) {
            $SecureKey = $EncryptedKey | ConvertTo-SecureString
            $Script:ApiKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureKey)
            )
            Write-Host "[+] Using saved API key" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "[!] Could not load saved API key: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

if (-not $Script:ApiKey) {
    Write-Host "Enter your Level.io API key: " -NoNewline -ForegroundColor Yellow
    $SecureKey = Read-Host -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureKey)
    $Script:ApiKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
}

if ([string]::IsNullOrWhiteSpace($Script:ApiKey)) {
    Write-Host "[X] API key is required" -ForegroundColor Red
    exit 1
}

# ============================================================
# COLLECT DATA
# ============================================================

$ExportData = [ordered]@{
    exportInfo = [ordered]@{
        timestamp   = (Get-Date).ToString("o")
        version     = "1.0"
        filters     = [ordered]@{
            fields = if ($FieldFilter.Count -gt 0) { $FieldFilter } else { $null }
            groups = $GroupFilter
        }
    }
    customFields = @()
    globalValues = @()
    groups       = @()
    devices      = @()
}

# --- Custom Field Definitions ---
Write-Host "[*] Fetching custom field definitions..." -ForegroundColor Gray
$AllFields = Get-AllPaginated -Endpoint "/custom_fields"
Write-Host "[+] Found $($AllFields.Count) custom field(s)" -ForegroundColor Green

# Apply field filter if specified
if ($FieldFilter.Count -gt 0) {
    $AllFields = @($AllFields | Where-Object { $_.name -in $FieldFilter })
    Write-Host "    Filtered to $($AllFields.Count) field(s)" -ForegroundColor DarkGray
}

$FieldLookup = @{}
foreach ($Field in $AllFields) {
    $FieldLookup[$Field.id] = $Field.name
    $ExportData.customFields += [ordered]@{
        id          = $Field.id
        name        = $Field.name
        reference   = $Field.reference
        adminOnly   = $Field.admin_only
    }
}

# --- Global/Account Level Values ---
Write-Host "[*] Fetching global custom field values..." -ForegroundColor Gray
$GlobalValues = Get-AllPaginated -Endpoint "/custom_field_values"

# Filter to only global values (no assigned_to_id)
$GlobalOnly = @($GlobalValues | Where-Object { [string]::IsNullOrEmpty($_.assigned_to_id) })

foreach ($Val in $GlobalOnly) {
    $FieldName = $FieldLookup[$Val.custom_field_id]
    if (-not $FieldName) { continue }
    if ($FieldFilter.Count -gt 0 -and $FieldName -notin $FieldFilter) { continue }

    $ExportData.globalValues += [ordered]@{
        fieldId   = $Val.custom_field_id
        fieldName = $FieldName
        value     = $Val.value
    }
}

Write-Host "[+] Found $($ExportData.globalValues.Count) global value(s)" -ForegroundColor Green

# --- Groups ---
Write-Host "[*] Fetching groups..." -ForegroundColor Gray
$AllGroups = Get-AllPaginated -Endpoint "/groups"
Write-Host "[+] Found $($AllGroups.Count) group(s)" -ForegroundColor Green

# Apply group filter if specified
if ($GroupFilter) {
    $AllGroups = @($AllGroups | Where-Object { $_.name -like $GroupFilter })
    Write-Host "    Filtered to $($AllGroups.Count) group(s)" -ForegroundColor DarkGray
}

$GroupLookup = @{}
foreach ($Group in $AllGroups) {
    $GroupLookup[$Group.id] = $Group.name

    $GroupData = [ordered]@{
        id           = $Group.id
        name         = $Group.name
        parentId     = $Group.parent_id
        customFields = [ordered]@{}
    }

    # Get custom field values for this group
    if ($Group.custom_fields) {
        foreach ($Prop in $Group.custom_fields.PSObject.Properties) {
            $FieldName = $Prop.Name -replace "^cf_", ""
            if ($FieldFilter.Count -gt 0 -and $FieldName -notin $FieldFilter) { continue }
            $GroupData.customFields[$FieldName] = $Prop.Value
        }
    }

    $ExportData.groups += $GroupData
}

# --- Devices ---
Write-Host "[*] Fetching devices..." -ForegroundColor Gray
$AllDevices = Get-AllPaginated -Endpoint "/devices"
Write-Host "[+] Found $($AllDevices.Count) device(s)" -ForegroundColor Green

# Filter devices by group if group filter applied
if ($GroupFilter) {
    $FilteredGroupIds = @($ExportData.groups | ForEach-Object { $_.id })
    $AllDevices = @($AllDevices | Where-Object { $_.group_id -in $FilteredGroupIds })
    Write-Host "    Filtered to $($AllDevices.Count) device(s) in matching groups" -ForegroundColor DarkGray
}

$DeviceCount = 0
$TotalDevices = $AllDevices.Count

foreach ($Device in $AllDevices) {
    $DeviceCount++
    if ($DeviceCount % 25 -eq 0 -or $DeviceCount -eq $TotalDevices) {
        Write-Host "    Processing device $DeviceCount / $TotalDevices..." -ForegroundColor DarkGray
    }

    $DeviceData = [ordered]@{
        id           = $Device.id
        hostname     = $Device.hostname
        groupId      = $Device.group_id
        groupName    = $GroupLookup[$Device.group_id]
        online       = $Device.online
        lastSeen     = $Device.last_seen_at
        customFields = [ordered]@{}
    }

    # Get custom field values for this device
    $DeviceValues = Get-AllPaginated -Endpoint "/custom_field_values?assigned_to_id=$($Device.id)"

    foreach ($Val in $DeviceValues) {
        $FieldName = $Val.custom_field_name
        if (-not $FieldName) {
            $FieldName = $FieldLookup[$Val.custom_field_id]
        }
        if (-not $FieldName) { continue }
        if ($FieldFilter.Count -gt 0 -and $FieldName -notin $FieldFilter) { continue }

        $DeviceData.customFields[$FieldName] = $Val.value
    }

    # If including inherited values, also check device's embedded custom_fields
    if ($IncludeInherited -and $Device.custom_fields) {
        foreach ($Prop in $Device.custom_fields.PSObject.Properties) {
            $FieldName = $Prop.Name -replace "^cf_", ""
            if ($FieldFilter.Count -gt 0 -and $FieldName -notin $FieldFilter) { continue }

            # Only add if not already present (device-level takes precedence)
            if (-not $DeviceData.customFields.Contains($FieldName)) {
                $DeviceData.customFields[$FieldName] = $Prop.Value
            }
        }
    }

    $ExportData.devices += $DeviceData
}

# ============================================================
# EXPORT
# ============================================================

Write-Host ""
Write-Host "[*] Writing export file..." -ForegroundColor Gray

# Ensure output directory exists
$OutputDir = Split-Path -Parent $OutputFile
if ($OutputDir -and -not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# Convert to JSON and write
$JsonOutput = $ExportData | ConvertTo-Json -Depth 10
if ($Compact) {
    $JsonOutput = $JsonOutput -replace '\r?\n\s*', ''
}

$JsonOutput | Set-Content -Path $OutputFile -Encoding UTF8

# ============================================================
# SUMMARY
# ============================================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " Export Complete" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Custom Fields: $($ExportData.customFields.Count)" -ForegroundColor White
Write-Host "  Global Values: $($ExportData.globalValues.Count)" -ForegroundColor White
Write-Host "  Groups:        $($ExportData.groups.Count)" -ForegroundColor White
Write-Host "  Devices:       $($ExportData.devices.Count)" -ForegroundColor White
Write-Host ""
Write-Host "[+] Exported to: $OutputFile" -ForegroundColor Green

$FileSizeKB = [math]::Round((Get-Item $OutputFile).Length / 1KB, 1)
Write-Host "    File size: $FileSizeKB KB" -ForegroundColor DarkGray
Write-Host ""
