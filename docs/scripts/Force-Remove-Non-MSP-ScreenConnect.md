# Force Remove Non-MSP ScreenConnect Script

**Script:** `scripts/Remove/⛔Force Remove Non MSP ScreenConnect.ps1`
**Launcher:** `launchers/⛔Force Remove Non MSP ScreenConnect.ps1`
**Version:** 2025.12.27.01
**Category:** Remove

## Flow

```
+--------------------+
| Launcher Start     |
+--------+-----------+
         |
         v
+--------------------+
| Load Level.io Vars |
| (SC Instance ID,   |
|  Server Flag)      |
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
   SCRIPT: Finds SC instances
   filters by whitelist,
   removes unauthorized,
   cleans files/registry
         |
         v
+--------------------+
| Check if SC        |
| Server Device      |
+--------+-----------+
         |
    +----+----+
    |         |
    v         v
+------+  +--------+
| Yes  |  |  No   |
| Exit |  +---+----+
+------+      |
              v
     +--------------------+
     | Find SC Instances  |
     +--------+-----------+
              |
              v
     +--------------------+
     | Filter Non-MSP     |
     | (Check Instance    |
     |  ID Whitelist)     |
     +--------+-----------+
              |
              v
     +--------------------+
     | Remove Each        |
     | Unauthorized       |
     +--------+-----------+
              |
              v
     +--------------------+
     | Cleanup Files      |
     | & Registry         |
     +--------+-----------+
              |
              v
     +--------------------+
     |  Exit 0/1          |
     +--------------------+
```

## Purpose

Removes unauthorized ScreenConnect (ConnectWise Control) installations while preserving your MSP's authorized instance.

## Features

- **Instance ID whitelisting** - Preserves your MSP's ScreenConnect
- **Server device detection** - Skips ScreenConnect server hosts
- **Multi-method removal**:
  - winget uninstall
  - Windows Installer (registry-based)
  - Direct folder-based uninstaller
- **Complete cleanup** - Files, registry, firewall rules, scheduled tasks

## Exit Codes

| Code | Status | Description |
|------|--------|-------------|
| 0 | Success | Unauthorized instances removed or none found |
| 1 | Alert | Removal failed |

## Custom Fields

| Field | Required | Description |
|-------|----------|-------------|
| `cf_policy_screenconnect_instance_id` | Yes | Your MSP's ScreenConnect instance ID to whitelist |
| `cf_policy_screenconnect_machine_hosts_screenconnect_server` | No | Set to `true` on ScreenConnect server devices |

## Tag Support

| Tag | Effect |
|-----|--------|
| `❌` | Blocks script execution on this device |

## How Whitelisting Works

The script:
1. Extracts instance ID from service name (format: `ScreenConnect Client (GUID)`)
2. Compares against `$ScreenConnectInstanceId` custom field
3. Only removes instances that **don't match** the whitelisted ID

## Removal Methods

### Method 1: Stop Services & Processes
- Stops non-whitelisted ScreenConnect services
- Terminates running processes

### Method 2: winget Uninstall
- Attempts uninstall via Windows Package Manager

### Method 3: Windows Installer
- Uses registry uninstall strings
- Executes MSI-based uninstall

### Method 4: Direct Uninstaller
- Runs `Uninstall.exe` from install folder
- Handles portable installations

### Cleanup
- Removes leftover files and folders
- Cleans registry entries
- Removes firewall rules
- Deletes scheduled tasks

## Server Detection

If `$IsScreenConnectServer` is set to `"true"`, the script exits immediately without making changes. This prevents accidentally removing the server-side ScreenConnect installation.

## Instance ID Format

ScreenConnect instance IDs are typically 8+ character hexadecimal strings found in:
- Service names: `ScreenConnect Client (abc12345)`
- Install folders: `C:\Program Files (x86)\ScreenConnect Client (abc12345)`
- Registry uninstall entries

## Use Cases

- Remove unauthorized ScreenConnect from endpoints
- Clean up after clients self-install support tools
- Enforce single-RMM policy
- Remediate after RAT detection

## Related Scripts

- [RAT Detection](RAT-Detection.md) - Detect ScreenConnect and other RATs
- [ScreenConnect Device URL](ScreenConnect-Device-URL.md) - Extract your instance URL
