<#
.SYNOPSIS
    Debug script to check screenconnect_url at all levels for a specific device.
.DESCRIPTION
    Checks device-level, group-level, and org-level custom field values
    for the screenconnect_url field on a specific device.
.NOTES
    Version: 2026.01.06.01
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$DeviceName = "CNMLWS05B",

    [Parameter(Mandatory = $false)]
    [string]$ApiKey
)

$ErrorActionPreference = 'Stop'

# ============================================================
# API FUNCTIONS
# ============================================================

$Script:LevelApiBase = "https://api.level.io/v2"

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

        if ($Items.Count -lt $Limit) { break }

    } while ($true)

    return $AllItems
}

# ============================================================
# MAIN
# ============================================================

Write-Host "=== ScreenConnect URL Debug for: $DeviceName ===" -ForegroundColor Cyan
Write-Host ""

# Get API key from cache
$CachePath = Join-Path $PSScriptRoot ".levelio-apikey.cache"

if (-not $ApiKey) {
    if (Test-Path $CachePath) {
        try {
            $EncryptedKey = (Get-Content $CachePath -Raw).Trim()
            $SecureKey = $EncryptedKey | ConvertTo-SecureString
            $Script:ApiKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureKey)
            )
            Write-Host "[+] Loaded API key from cache" -ForegroundColor Green
        }
        catch {
            Write-Host "[!] Failed to load cached key: $_" -ForegroundColor Yellow
        }
    }

    if (-not $Script:ApiKey) {
        $Script:ApiKey = Read-Host "Enter Level.io API Key"
    }
}
else {
    $Script:ApiKey = $ApiKey
}

# Find screenconnect_device_url custom field
Write-Host "[*] Finding screenconnect_device_url custom field..." -ForegroundColor Gray
$Fields = Get-AllPaginated -Endpoint "/custom_fields"
$ScField = $Fields | Where-Object { $_.name -eq "screenconnect_device_url" } | Select-Object -First 1

if (-not $ScField) {
    Write-Host "[!] Could not find screenconnect_device_url custom field" -ForegroundColor Red
    Write-Host "    Available fields:" -ForegroundColor Yellow
    $Fields | ForEach-Object { Write-Host "      - $($_.name)" -ForegroundColor Gray }
    exit 1
}

Write-Host "[+] Found field: $($ScField.name) (ID: $($ScField.id))" -ForegroundColor Green

# Show full field definition
Write-Host "[DEBUG] Field definition:" -ForegroundColor Magenta
$ScField | Get-Member -MemberType NoteProperty | ForEach-Object {
    $propName = $_.Name
    $propValue = $ScField.$propName
    Write-Host "    $propName : $propValue" -ForegroundColor Magenta
}

# Find the device
Write-Host "[*] Finding device: $DeviceName..." -ForegroundColor Gray
$Devices = Get-AllPaginated -Endpoint "/devices"
$Device = $Devices | Where-Object { $_.hostname -eq $DeviceName } | Select-Object -First 1

if (-not $Device) {
    Write-Host "[!] Device not found: $DeviceName" -ForegroundColor Red
    Write-Host "    Available devices (first 10):" -ForegroundColor Yellow
    $Devices | Select-Object -First 10 | ForEach-Object { Write-Host "      - $($_.hostname)" -ForegroundColor Gray }
    exit 1
}

Write-Host "[+] Found device:" -ForegroundColor Green
Write-Host "    Hostname: $($Device.hostname)" -ForegroundColor White
Write-Host "    ID: $($Device.id)" -ForegroundColor White
Write-Host "    Group ID: $($Device.group_id)" -ForegroundColor White
Write-Host "    Group Name: $($Device.group_name)" -ForegroundColor White

# Get group names
Write-Host ""
Write-Host "[*] Getting group details..." -ForegroundColor Gray
$Groups = Get-AllPaginated -Endpoint "/groups"
$DeviceGroup = $Groups | Where-Object { $_.id -eq $Device.group_id }
if ($DeviceGroup) {
    Write-Host "    Group: $($DeviceGroup.name) (ID: $($Device.group_id))" -ForegroundColor White
    Write-Host "    Parent ID: $($DeviceGroup.parent_id)" -ForegroundColor White
}

# Get ALL custom field values
Write-Host ""
Write-Host "[*] Getting all custom field values..." -ForegroundColor Gray
$AllValuesRaw = Get-AllPaginated -Endpoint "/custom_field_values"
Write-Host "    Total values in system: $($AllValuesRaw.Count)" -ForegroundColor DarkGray

# Filter to just screenconnect_url
$AllValues = $AllValuesRaw | Where-Object { $_.custom_field_id -eq $ScField.id }
Write-Host "    Values for screenconnect_url: $($AllValues.Count)" -ForegroundColor DarkGray

# Debug: Show screenconnect_url values
Write-Host "[DEBUG] screenconnect_url values:" -ForegroundColor Magenta
$AllValues | ForEach-Object {
    Write-Host "    assigned_to_id: $($_.assigned_to_id) | value: $($_.value)" -ForegroundColor Magenta
}

# Try multiple API approaches to find the device-level value
Write-Host ""
Write-Host "[*] Trying different API queries..." -ForegroundColor Gray

# Approach 1: Query by assigned_to_id (device) - with pagination
Write-Host ""
Write-Host "Approach 1: /custom_field_values?assigned_to_id=<device_id> (paginated)" -ForegroundColor Cyan
$DeviceData = Get-AllPaginated -Endpoint "/custom_field_values?assigned_to_id=$($Device.id)"
Write-Host "  Returned $($DeviceData.Count) field(s)" -ForegroundColor Gray
$DeviceScUrl = $DeviceData | Where-Object { $_.custom_field_name -eq "screenconnect_device_url" }
if ($DeviceScUrl) {
    Write-Host "  screenconnect_device_url: $($DeviceScUrl.value)" -ForegroundColor Green
} else {
    Write-Host "  screenconnect_device_url not in response" -ForegroundColor DarkGray
    Write-Host "  Fields returned:" -ForegroundColor Gray
    $DeviceData | ForEach-Object { Write-Host "    - $($_.custom_field_name)" -ForegroundColor DarkGray }
}

# Approach 2: Query by both assigned_to_id AND custom_field_id
Write-Host ""
Write-Host "Approach 2: /custom_field_values?assigned_to_id=<device>&custom_field_id=<field>" -ForegroundColor Cyan
$Combo = Invoke-LevelApi -Endpoint "/custom_field_values?assigned_to_id=$($Device.id)&custom_field_id=$($ScField.id)"
if ($Combo.Success) {
    $ComboData = if ($Combo.Data.data) { $Combo.Data.data } else { @($Combo.Data) }
    Write-Host "  Returned $($ComboData.Count) value(s)" -ForegroundColor Gray
    $ComboData | ForEach-Object {
        Write-Host "  value: $($_.value)" -ForegroundColor Green
    }
} else {
    Write-Host "  Error: $($Combo.Error)" -ForegroundColor Red
}

# Approach 3: Get device details directly
Write-Host ""
Write-Host "Approach 3: /devices/<device_id> (full device details)" -ForegroundColor Cyan
$DeviceDetails = Invoke-LevelApi -Endpoint "/devices/$($Device.id)"
if ($DeviceDetails.Success) {
    Write-Host "  Device details retrieved" -ForegroundColor Gray
    # Check if there's custom_fields property
    if ($DeviceDetails.Data.custom_fields) {
        Write-Host "  custom_fields property exists:" -ForegroundColor Gray
        $DeviceDetails.Data.custom_fields | ForEach-Object {
            Write-Host "    $_" -ForegroundColor Magenta
        }
    }
    if ($DeviceDetails.Data.custom_field_values) {
        Write-Host "  custom_field_values property exists:" -ForegroundColor Gray
        $DeviceDetails.Data.custom_field_values | ForEach-Object {
            Write-Host "    $_" -ForegroundColor Magenta
        }
    }
    # Show all properties
    Write-Host "  All properties:" -ForegroundColor Gray
    $DeviceDetails.Data | Get-Member -MemberType NoteProperty | ForEach-Object {
        $propName = $_.Name
        $propValue = $DeviceDetails.Data.$propName
        if ($propName -like "*custom*" -or $propName -like "*screen*" -or $propName -like "*field*") {
            Write-Host "    $propName : $propValue" -ForegroundColor Magenta
        }
    }
} else {
    Write-Host "  Error: $($DeviceDetails.Error)" -ForegroundColor Red
}

# Check each level
Write-Host ""
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host " CHECKING ALL LEVELS" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan

# 1. Device Level
Write-Host ""
Write-Host "1. DEVICE LEVEL (assigned_to_id = $($Device.id))" -ForegroundColor Yellow
$DeviceValue = $AllValues | Where-Object { $_.assigned_to_id -eq $Device.id }
if ($DeviceValue) {
    Write-Host "   FOUND: $($DeviceValue.value)" -ForegroundColor Green
}
else {
    Write-Host "   NOT SET" -ForegroundColor DarkGray
    # Check if any value looks similar
    Write-Host "   Checking for similar IDs..." -ForegroundColor DarkGray
    $AllValues | ForEach-Object {
        if ($_.assigned_to_id -and $_.assigned_to_id -like "*$($Device.name)*") {
            Write-Host "   Similar: assigned_to_id=$($_.assigned_to_id) value=$($_.value)" -ForegroundColor Magenta
        }
    }
}

# 2. Group Level
Write-Host ""
Write-Host "2. GROUP LEVEL (assigned_to_id = $($Device.group_id))" -ForegroundColor Yellow
if ($Device.group_id) {
    $GroupValue = $AllValues | Where-Object { $_.assigned_to_id -eq $Device.group_id }
    if ($GroupValue) {
        Write-Host "   FOUND in group '$($Device.group_name)': $($GroupValue.value)" -ForegroundColor Green
    }
    else {
        Write-Host "   NOT SET in group '$($Device.group_name)'" -ForegroundColor DarkGray
    }

    # Also check parent groups
    if ($DeviceGroup -and $DeviceGroup.parent_id) {
        Write-Host "   Checking parent group (ID: $($DeviceGroup.parent_id))..." -ForegroundColor Gray
        $ParentValue = $AllValues | Where-Object { $_.assigned_to_id -eq $DeviceGroup.parent_id }
        $ParentGroup = $Groups | Where-Object { $_.id -eq $DeviceGroup.parent_id }
        if ($ParentValue) {
            Write-Host "   FOUND in parent group '$($ParentGroup.name)': $($ParentValue.value)" -ForegroundColor Green
        }
        else {
            Write-Host "   NOT SET in parent group '$($ParentGroup.name)'" -ForegroundColor DarkGray
        }
    }
}
else {
    Write-Host "   Device is not in any group" -ForegroundColor DarkGray
}

# 3. Org Level (null assigned_to_id)
Write-Host ""
Write-Host "3. ORG LEVEL (assigned_to_id = null)" -ForegroundColor Yellow
$OrgValue = $AllValues | Where-Object { -not $_.assigned_to_id -or $_.assigned_to_id -eq "" }
if ($OrgValue) {
    Write-Host "   FOUND: $($OrgValue.value)" -ForegroundColor Green
}
else {
    Write-Host "   NOT SET" -ForegroundColor DarkGray
}

# Show all values for reference
Write-Host ""
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host " ALL VALUES IN SYSTEM (for debugging)" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host ""
$AllValues | ForEach-Object {
    $assignedTo = if ($_.assigned_to_id) { $_.assigned_to_id } else { "(org-level)" }
    Write-Host "assigned_to_id: $assignedTo" -ForegroundColor Gray
    Write-Host "value: $($_.value)" -ForegroundColor White
    Write-Host ""
}
