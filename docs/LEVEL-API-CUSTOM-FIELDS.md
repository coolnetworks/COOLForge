# Level.io API: Custom Fields Guide

This document explains how to correctly retrieve custom field values from the Level.io API, based on real-world debugging and testing.

## API Quirks and Gotchas

### 1. The `/custom_field_values` Endpoint Ignores Query Parameters

**Problem**: When calling `/custom_field_values?custom_field_id=<id>`, the API **ignores** the `custom_field_id` filter and returns ALL custom field values.

```
# This returns ALL custom fields, not just the one specified:
GET /v2/custom_field_values?custom_field_id=Z2lkOi8vbGV2ZWwvQ3VzdG9tRmllbGQvMjI5NA
```

**Solution**: You must filter client-side by the `custom_field_id` property:

```powershell
$AllValues = Get-AllPaginated -Endpoint "/custom_field_values"
$MyFieldValues = $AllValues | Where-Object { $_.custom_field_id -eq $MyFieldId }
```

### 2. Org-Level vs Device-Level Values Use Different Queries

**Problem**: The base `/custom_field_values` endpoint only returns **organization-level** values (where `assigned_to_id` is null). It does NOT return device-specific or group-specific values.

**Solution**: To get a device's custom field values, you MUST query with `assigned_to_id`:

```powershell
# This returns org-level values only:
GET /v2/custom_field_values

# This returns values for a specific device (including inherited values):
GET /v2/custom_field_values?assigned_to_id=<device_id>
```

### 3. Pagination Limits

**Problem**: The API defaults to returning only 20 items per request.

**Solution**: Always use pagination with a higher limit:

```powershell
GET /v2/custom_field_values?assigned_to_id=<device_id>&limit=100
```

And implement cursor-based pagination to get all results:

```powershell
function Get-AllPaginated {
    param([string]$Endpoint, [int]$Limit = 100)

    $AllItems = @()
    $Cursor = $null

    do {
        $Url = "$Endpoint"
        $Separator = if ($Url -match '\?') { '&' } else { '?' }
        $Url += "${Separator}limit=$Limit"
        if ($Cursor) { $Url += "&starting_after=$Cursor" }

        $Result = Invoke-LevelApi -Endpoint $Url
        if (-not $Result.Success) { break }

        $Items = if ($Result.Data.data) { $Result.Data.data } else { @($Result.Data) }
        if ($Items.Count -eq 0) { break }

        $AllItems += $Items
        $Cursor = $Items[-1].id

        if ($Items.Count -lt $Limit) { break }
    } while ($true)

    return $AllItems
}
```

### 4. Device Property Names

**Problem**: Device objects use `hostname`, not `name`:

```powershell
# Wrong:
$Device.name        # Returns nothing

# Correct:
$Device.hostname    # Returns "MYWORKSTATION"
```

### 5. Group Membership

**Problem**: Device objects use `group_id` (singular), not `group_ids` (plural):

```powershell
# Wrong:
$Device.group_ids

# Correct:
$Device.group_id
$Device.group_name
```

## Correct Approach: Getting Custom Field Values

### For a Single Device

```powershell
# 1. Find the custom field definition
$Fields = Get-AllPaginated -Endpoint "/custom_fields"
$MyField = $Fields | Where-Object { $_.name -eq "my_custom_field" }

# 2. Find the device
$Devices = Get-AllPaginated -Endpoint "/devices"
$Device = $Devices | Where-Object { $_.hostname -eq "MYDEVICE" }

# 3. Get ALL custom field values for this device (with pagination!)
$DeviceValues = Get-AllPaginated -Endpoint "/custom_field_values?assigned_to_id=$($Device.id)"

# 4. Filter to the specific field
$MyValue = $DeviceValues | Where-Object { $_.custom_field_name -eq "my_custom_field" }
Write-Host "Value: $($MyValue.value)"
```

### For All Devices

```powershell
# 1. Find the custom field
$Fields = Get-AllPaginated -Endpoint "/custom_fields"
$MyField = $Fields | Where-Object { $_.name -eq "my_custom_field" }

# 2. Get all devices
$Devices = Get-AllPaginated -Endpoint "/devices"

# 3. For each device, get their custom field values
foreach ($Device in $Devices) {
    $DeviceValues = Get-AllPaginated -Endpoint "/custom_field_values?assigned_to_id=$($Device.id)"
    $MyValue = $DeviceValues | Where-Object { $_.custom_field_name -eq "my_custom_field" }

    Write-Host "$($Device.hostname): $($MyValue.value)"
}
```

**Note**: This approach requires one API call per device, which can be slow for large fleets. There is no bulk endpoint to get device-level custom field values for all devices in a single call.

## Custom Field Value Object Structure

When you query `/custom_field_values?assigned_to_id=<device_id>`, each value object contains:

| Property | Description |
|----------|-------------|
| `custom_field_id` | The ID of the custom field definition |
| `custom_field_name` | The name of the custom field (e.g., "screenconnect_url") |
| `assigned_to_id` | The ID of the device/group this value is assigned to (empty for org-level) |
| `value` | The actual value |

## Custom Field Definition Object Structure

When you query `/custom_fields`, each field object contains:

| Property | Description |
|----------|-------------|
| `id` | Unique identifier (e.g., "Z2lkOi8vbGV2ZWwvQ3VzdG9tRmllbGQvMjI5NA") |
| `name` | Field name (e.g., "screenconnect_url") |
| `reference` | Template reference (e.g., "cf_screenconnect_url") |
| `admin_only` | Boolean - whether only admins can view/edit |

## Authentication

The Level.io v2 API uses a simple API key in the Authorization header:

```powershell
$Headers = @{
    "Authorization" = $ApiKey   # Just the key, no "Bearer" prefix
    "Content-Type"  = "application/json"
}
```

**Note**: Unlike many APIs, Level.io v2 does NOT use "Bearer" token format. Just pass the API key directly.

## API Base URL

```
https://api.level.io/v2
```

## Common Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /devices` | List all devices |
| `GET /devices/{id}` | Get single device details |
| `GET /groups` | List all groups |
| `GET /custom_fields` | List all custom field definitions |
| `GET /custom_field_values` | Get org-level values only |
| `GET /custom_field_values?assigned_to_id={id}` | Get values for specific device/group |

## Setting Custom Field Values

### 6. Setting Global/Account-Level Values

Use `PATCH /custom_field_values` with `assigned_to_id` set to `null` to set the global value:

```powershell
PATCH /v2/custom_field_values
Body: {
    "custom_field_id": "Z2lkOi8vbGV2ZWwvQ3VzdG9tRmllbGQvMjMwNA",
    "assigned_to_id": null,
    "value": "C:\ProgramData\MyCompany"
}
```

**Note**: `PATCH /custom_fields/{id}` with `default_value` does NOT work - the API accepts it but silently ignores the value.

### 7. Setting Values on Groups (Alternative)

```powershell
PATCH /v2/groups/{group_id}
Body: {
    "custom_fields": {
        "my_field_name": "my_value"
    }
}
```

Use the field's `name` (e.g., "coolforge_msp_scratch_folder"), NOT the `reference` (e.g., "cf_coolforge_msp_scratch_folder").

### 8. Use /groups NOT /organizations

**Problem**: The Level.io API v2 does NOT have an `/organizations` endpoint. Attempting to call it returns 404.

```powershell
# WRONG - returns 404:
GET /v2/organizations

# CORRECT - use groups:
GET /v2/groups
```

**Groups Hierarchy**: Groups in Level.io represent what other RMMs call "organizations" or "clients". Groups can be nested (parent/child relationship via `parent_id`).

### 9. Values Inherit Down the Hierarchy

Custom field values set at the group level cascade down to:
- Child groups (unless overridden)
- Devices in that group (unless overridden)

To set a "default" for all devices, set the value on the root/top-level groups.

## Example: Complete Script

See `tools/Get-ScreenConnectUrls.ps1` for a working example that:
1. Authenticates with cached API key
2. Finds a specific custom field
3. Iterates through all devices
4. Gets each device's custom field values with proper pagination
5. Outputs a formatted report
