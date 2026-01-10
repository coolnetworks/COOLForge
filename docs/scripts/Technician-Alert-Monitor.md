# Technician Alert Monitor Script

**Script:** `scripts/Utility/🔔Technician Alert Monitor.ps1`
**Launcher:** `launchers/🔔Technician Alert Monitor.ps1`
**Version:** 2026.01.08.02
**Category:** Utility

## Purpose

Monitors for technician alerts and displays Windows toast notifications on technician workstations.

## Features

- **Toast notifications** - Native Windows notifications when alerts arrive
- **Tag-based targeting** - Only runs on devices with technician tag
- **Polling-based** - Checks for new alerts on schedule
- **Alert caching** - Tracks which alerts have been shown

## Prerequisites

- Device must be tagged with technician emoji tag
- Level.io API key configured
- Windows 10/11 for toast notification support

## Custom Fields

| Field | Required | Description |
|-------|----------|-------------|
| `cf_coolforge_technician_alerts` | Yes | JSON array of pending alerts (managed by scripts) |
| `cf_apikey` | Yes | Level.io API key |

## Level.io Variables

| Variable | Description |
|----------|-------------|
| `level_device_hostname` | Device hostname |
| `level_tag_names` | Device tags (to detect technician tag) |

## Configuration

```powershell
$LevelApiBaseUrl = "https://api.level.io/v2"
$AlertCacheFile = "$MspScratchFolder\TechAlerts\seen_alerts.json"
```

## Alert Flow

```
1. Client script detects issue
         ↓
2. Calls Send-TechnicianAlert or Add-TechnicianAlert
         ↓
3. Alert stored in cf_coolforge_technician_alerts
         ↓
4. This monitor polls and detects new alert
         ↓
5. Toast notification displayed on tech workstation
         ↓
6. Alert marked as seen (cached locally)
```

## Technician Tag

Workstations are identified as technician stations by the presence of a tag starting with the technician emoji (U+1F9D1 U+200D U+1F4BB):

Examples:
- `👨‍💻technician`
- `👨‍💻technicianJohn`
- `👨‍💻tech-workstation`

## Alert Format

Alerts in `cf_coolforge_technician_alerts` are JSON arrays:

```json
[
  {
    "id": "unique-id",
    "timestamp": "2026-01-10T12:00:00Z",
    "source_device": "PC-001",
    "title": "Alert Title",
    "message": "Alert details...",
    "severity": "warning"
  }
]
```

## Deployment

Recommended setup:
1. Create Level.io automation to run every 30 seconds
2. Filter to only run on devices with technician tag
3. Script will poll API and show toast notifications

## Alert Caching

Seen alerts are cached in:
```
$MspScratchFolder\TechAlerts\seen_alerts.json
```

This prevents the same alert from being shown multiple times.

## Related Documentation

- [Technician Alerts](../TECHNICIAN-ALERTS.md) - Full alert system documentation
