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


---

## Group-Level Custom Field Values — Full Investigation Findings (2026-03-14)

> These findings were established through exhaustive testing against the Level.io primary instance.
> Do not assume group-level PATCH works without re-reading this section.

### What Works vs What Doesn't

| Operation | Endpoint | Works? | Notes |
|-----------|----------|--------|-------|
| Read global (org) default | `GET /v2/custom_field_values` | ✅ | Returns fields where `assigned_to_id` is null |
| Read device-level value | `GET /v2/custom_field_values?assigned_to_id=<device_id>` | ✅ | Returns effective value (inherited or overridden) |
| Read group-level value | `GET /v2/custom_field_values?assigned_to_id=<group_id>` | ⚠️ | Returns INHERITED global value, NOT group-level override |
| Set global default | `PATCH /v2/custom_field_values` with `assigned_to_id=null` | ✅ | Correct way to set org-level defaults |
| Set group-level override | `PATCH /v2/custom_field_values` with `assigned_to_id=<group_id>` | ⚠️ | HTTP 200 returned but value is **silently dropped** |
| Set group-level override | `PATCH /v2/groups/<group_id>` with body `{"custom_fields":{"field_name":"value"}}` | ✅ | **This is the correct method** |
| Read group-level override | `GET /v2/groups/<group_id>` inspect `custom_fields` | ✅ | **This is the correct method** |
| Set device-level override | `PATCH /v2/custom_field_values` with `assigned_to_id=<device_id>` | ✅ | Works correctly for devices |

### The Silent Drop Bug

When you call `PATCH /v2/custom_field_values` with a group ID as `assigned_to_id`:
- The API returns HTTP 200 (success)
- No error message
- The value is **not persisted** — reading back shows the global default, not your value

**This is a known Level.io API behaviour, not a bug in your code.**

### Correct Way to Set a Group-Level Custom Field Override

```powershell
# Use PATCH /v2/groups/<group_id> with field NAME (not reference, not ID)
$Body = @{
    custom_fields = @{
        "policy_meshcentral_meshid" = "abc123meshid..."
    }
} | ConvertTo-Json -Depth 5

$Headers = @{ "Authorization" = $ApiKey; "Content-Type" = "application/json" }
Invoke-RestMethod -Uri "https://api.level.io/v2/groups/$GroupId" -Method Patch -Headers $Headers -Body $Body
```

Key points:
- Use `field_name` (e.g. `policy_meshcentral_meshid`), NOT `cf_policy_meshcentral_meshid` (the template reference)
- Use `PATCH /v2/groups/<id>`, NOT `PATCH /v2/custom_field_values`
- Group ID is the base64 GID (e.g. `Z2lkOi8vbGV2ZWwvRGV2aWNlR3JvdXAvMTM2OTk`)

### Correct Way to Read a Group-Level Custom Field Override

**Critical finding**: `GET /v2/custom_field_values?assigned_to_id=<group_id>` always returns the INHERITED global value, even if a group-level override exists. You cannot detect overrides this way.

The only reliable methods:

**Method 1 — Read the group object directly:**
```powershell
$Group = Invoke-RestMethod -Uri "https://api.level.io/v2/groups/$GroupId" -Headers $Headers
$Value = $Group.custom_fields.policy_meshcentral_meshid
```

**Method 2 — Use the override-specific v2 endpoint (if available):**
```powershell
# Query each field+entity combination individually
# Bulk queries always return inherited globals, never group overrides
GET /v2/custom_field_values?custom_field_id=<field_id>&assigned_to_id=<group_id>
```

The `Get-LevelEntityCustomFieldOverrides` function in `COOLForge-Common.psm1` implements Method 2 with individual per-field queries and 600ms delay between calls.

### Cascade / Inheritance Behaviour

Values cascade DOWN the hierarchy:
```
Org default (global)
  └── Group override (if set) — overrides org default for devices in this group
        └── Child group override (if set) — overrides parent
              └── Device override (if set) — highest priority
```

Cascade is confirmed by the Level v2 OpenAPI spec and verified by direct API testing.

### Entity Type: "group" not "folder"

The Level.io v2 API uses `"group"` as the entity type for device groups everywhere:
- `GET /v2/groups` (not `/v2/folders`, not `/v2/organizations`)
- Entity type string in function calls: `"group"` (not `"folder"`)

**Old code that used `EntityType "folder"` was silently failing.** All COOLForge library functions
that accept `EntityType` now support `"group"` correctly (fixed in commit `55895f3`).

### API Rate Limits

- **Limit**: 100 calls per minute
- **Safe delay**: 600ms between calls (not 6000ms — that was 10x too conservative)
- For bulk operations (e.g. 139 groups × 41 fields = 5,699 calls), use `nohup` or background execution:
  ```bash
  nohup pwsh -File start_here/Backup-COOLForgeCustomFields.ps1 -Action Backup -ApiKey <key> > /tmp/backup.log 2>&1 &
  ```
  ETA for full backup at 100 calls/min: ~57 minutes

### Backup Format v2.0

The `Backup-COOLForgeCustomFields.ps1` script now produces format version `2.0`:

```json
{
  "Timestamp": "2026-03-14T...",
  "Version": "2.0",
  "CustomFields": [ { "Id": "...", "Name": "...", "Reference": "..." } ],
  "GlobalValues": { "field_name": "value" },
  "Groups": [
    { "Id": "Z2lk...", "Name": "COOLNETWORKS", "Values": { "policy_meshcentral_meshid": "abc..." } }
  ],
  "Devices": [
    { "Id": "Z2lk...", "Name": "MYPC", "Values": { "policy_chrome": "pin" } }
  ]
}
```

`Groups` contains ONLY groups that have explicit overrides (not inherited-only values).
`Devices` is optional — only present if device-level values differ from their group.

Legacy v1.0 format (Organizations/Folders) is still supported by `Restore-CustomFields`.

### Authentication (reminder)

```
Authorization: <api_key>    ← Raw key only, NO "Bearer" prefix
```

### Primary vs Secondary Instances

COOLNETWORKS has two Level.io instances:
- **Primary**: API key `GNRdZpcVjyvZbJ6cvVLgU4zf` — 139 groups, field IDs 7806–7829
- **Secondary (test)**: API key `gTcBnH3fxnPWFp4mX17tFE7D` — 6 groups, field IDs 7806–7827

**Always use the primary key** in scripts and tools. Secondary key is for isolated testing only.
The same custom field NAME maps to different numeric IDs on each instance.

### COOLForge Functions for Group Fields

| Function | Purpose |
|----------|---------|
| `Get-LevelGlobalCustomFieldValues` | Get org-level defaults for all fields |
| `Get-LevelEntityCustomFieldOverrides` | Get explicit overrides for a group or device (600ms delay per field) |
| `Set-LevelCustomFieldValueDirect` | PATCH via correct endpoint for groups/devices |
| `Backup-AllCustomFields` | Full backup in v2.0 format |
| `Restore-CustomFields` | Restore from v2.0 or legacy v1.0 backup |
| `Get-LevelEntityCustomFields` | Read fields for entity type "group", "device", etc |
| `Set-LevelCustomFieldValue` | Set field value (supports "group" entity type) |

