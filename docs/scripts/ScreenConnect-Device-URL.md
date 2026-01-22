# Extract and Set ScreenConnect Device URL

**Script:** `scripts/Configure/⚙️Extract and Set ScreenConnect Device URL.ps1`
**Launcher:** `launchers/⚙️Extract and Set ScreenConnect Device URL.ps1`
**Version:** 2026.01.10.01
**Category:** Configure

## Flow

```
+--------------------+
| Launcher Start     |
+--------+-----------+
         |
         v
+--------------------+
| Load Level.io Vars |
| (SC Base URL)      |
+--------+-----------+
         |
         v
+--------------------+
| Download MD5SUMS   |
| & Verify Library   |
+--------+-----------+
         |
         v
+--------------------+
| Import COOLForge   |
| Common Module      |
+--------+-----------+
         |
         v
+--------------------+
| Invoke-Script      |
| Launcher           |
+========+===========+
         |
   SCRIPT: Searches registry
   for SC service, parses
   GUID from ImagePath,
   constructs device URL
         |
         v
+--------------------+
| Search Registry    |
| for SC Services    |
+--------+-----------+
         |
         v
+--------------------+
| Parse ImagePath    |
| for Session GUID   |
+--------+-----------+
         |
    +----+----+
    |         |
    v         v
+------+  +--------+
|Not   |  | Found  |
|Found |  +---+----+
|Exit 1|      |
+------+      v
     +--------------------+
     | Construct URL      |
     | from Base + GUID   |
     +--------+-----------+
              |
              v
     +--------------------+
     | Output CF Format   |
     | {{cf_...=URL}}     |
     +--------+-----------+
              |
              v
     +--------------------+
     |  Exit 0            |
     +--------------------+
```

## Purpose

Extracts the ScreenConnect client GUID from the local Windows registry and constructs the full ScreenConnect connection URL, then automatically populates the device's `cf_screenconnect_device_url` custom field.

## Features

- **Registry extraction** - Parses ScreenConnect service ImagePath for session GUID
- **Auto-populate custom field** - Sets device URL using Level.io variable syntax
- **URL construction** - Builds Host#Access URL format

## Exit Codes

| Code | Status | Description |
|------|--------|-------------|
| 0 | Success | GUID extracted and URL set |
| 1 | Alert | GUID not found |

## Custom Fields

| Field | Type | Description |
|-------|------|-------------|
| `cf_screenconnect_baseurl` | Input | Your ScreenConnect server URL (e.g., `support.example.com`) |
| `cf_screenconnect_device_url` | Output | Per-device ScreenConnect URL (set by script) |

## How It Works

1. Searches `HKLM:\System\ControlSet001\Services` for ScreenConnect Client entries
2. Parses the `ImagePath` registry value for the `&s=` parameter containing the GUID
3. Constructs URL: `https://{baseurl}/Host#Access/All%20Machines//{GUID}/Join`
4. Outputs in Level.io custom field format: `{{cf_screenconnect_device_url=...}}`

## URL Format

```
https://support.example.com/Host#Access/All%20Machines//abc123def456/Join
```

## Configuration

Default base URL in script:
```powershell
$ScreenConnectBaseUrl = "support.cool.net.au"
```

Override via custom field `cf_screenconnect_baseurl`.

## Failure Reasons

If the script exits with code 1:
- ScreenConnect client is not installed
- Service is registered under a different name
- Registry permissions issue

## Use Case

Run this script on endpoints after ScreenConnect installation to automatically populate the device URL custom field, enabling quick access to ScreenConnect sessions from Level.io.
