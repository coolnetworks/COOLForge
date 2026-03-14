# Hostname Mismatch Detection

**Script:** `scripts/Check/👀Hostname Mismatch.ps1`
**Launcher:** `launchers/Policy/👀Hostname Mismatch.ps1`
**Version:** 2026.01.21.15
**Category:** Check

## Flow

```
+--------------------+
| Launcher Start     |
+--------+-----------+
         |
         v
+--------------------+
| Load Level.io Vars |
| (Device Hostname,  |
|  Tags, API Key,    |
|  Policy Field)     |
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
   SCRIPT: Gets actual
   Windows hostname,
   compares to Level.io,
   auto-renames or alerts
         |
         v
+--------------------+
| Level.io Name      |
| Available?         |
+--------+-----------+
         |
    +----+----+
    |         |
    v         v
+------+  +--------+
| No   |  |  Yes   |
| Auto |  +---+----+
| Set  |      |
+--+---+      v
   |   +--------------------+
   |   | Compare Hostnames  |
   |   +--------+-----------+
   |            |
   |       +----+----+
   |       |         |
   |       v         v
   |   +-------+ +--------+
   |   | Match | |Mismatch|
   |   |Exit 0 | +---+----+
   |   +-------+     |
   |                  v
   |       +--------------------+
   |       | Check Policy Mode  |
   |       | & Action Tags      |
   |       +--------+-----------+
   |                |
   |    +-----------+-----------+
   |    |           |           |
   |    v           v           v
   | +-------+  +--------+  +--------+
   | |Monitor|  |Auto-   |  |Auto-   |
   | | Tag & |  |Hostname|  |Level   |
   | | Wait  |  |Rename  |  |Rename  |
   | +-------+  | Level  |  |Windows |
   |             +--------+  +--------+
   |
   +-----> Exit 0
```

## Purpose

Detects hostname mismatches between the Windows hostname and Level.io device name. Supports automatic resolution via policy modes and action tags, including auto-renaming devices via the Level.io API when the device name is blank.

## Features

- **Mismatch detection** — Compares `$env:COMPUTERNAME` to Level.io `$DeviceHostname`
- **Auto-set blank names** — When Level.io has no device name, automatically sets it to the Windows hostname via the API
- **Policy-based resolution** — Three modes: monitor, auto-hostname, auto-level
- **Action tags** — Manual override tags for one-off renames
- **Tag management** — Creates/removes warning and action tags via API
- **Registry cache fallback** — Caches values for when Level.io doesn't provide them

## Policy Modes

Controlled by the `policy_sync_hostnames` custom field:

| Value | Mode | Behavior |
|-------|------|----------|
| `monitor` (default) | Monitor | Tags mismatch, waits for operator action tag |
| `auto-hostname` | Auto-sync to Windows | Renames Level.io device name to match Windows hostname |
| `auto-level` | Auto-sync to Level.io | Renames Windows hostname to match Level.io name (requires reboot) |

## Action Tags

Apply these to a device for one-off rename operations (regardless of policy mode):

| Tag | Action |
|-----|--------|
| (Wrench) Rename Level to Hostname | Updates Level.io device name to match Windows hostname |
| (Wrench) Rename Hostname to Level | Renames Windows computer to match Level.io (requires reboot) |

## Auto-Created Tags

| Tag | Purpose |
|-----|---------|
| (Warning) HOSTNAME MISMATCH | Applied when mismatch detected, removed after resolution |
| (Wrench) Rename Level to Hostname | Action tag for manual rename |
| (Wrench) Rename Hostname to Level | Action tag for manual rename |
| (Pray+Arrows) REBOOT TONIGHT | Applied after Windows rename (reboot required) |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Hostnames match, or rename completed successfully |
| 1 | Mismatch detected (monitor mode), or rename failed |

## Custom Fields

| Field | Required | Description |
|-------|----------|-------------|
| `policy_sync_hostnames` | No | Policy mode: `monitor` / `auto-hostname` / `auto-level` (default: monitor) |
| `apikey` | No | Level.io API key for tag/device operations |

## Usage

Deploy via Level.io automation as a daily check. Uses `{{level_device_hostname}}`, `{{level_device_id}}`, and `{{level_tag_names}}` variables.

## Related

- [Test Variable Output](Test-Variable-Output.md)
