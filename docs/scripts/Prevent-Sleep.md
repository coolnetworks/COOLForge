# Prevent Sleep Script

**Script:** `scripts/Fix/🔧Prevent Sleep.ps1`
**Launcher:** `launchers/🔧Prevent Sleep.ps1`
**Version:** 2025.12.30.01
**Category:** Fix

## Flow

```
+--------------------+
| Launcher Start     |
+--------+-----------+
         |
         v
+--------------------+
| Load Level.io Vars |
| (Scratch Folder,   |
|  Duration Config)  |
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
   SCRIPT: Backs up power
   settings, disables sleep
   and hibernate, schedules
   auto-restore task
         |
         v
+--------------------+
| Check Existing     |
| Session            |
+--------+-----------+
         |
    +----+----+
    |         |
    v         v
+------+  +--------+
|Active|  |  None  |
|Extend|  +---+----+
+--+---+      |
   |          v
   |   +--------------------+
   |   | Backup Current     |
   |   | Power Settings     |
   |   +--------+-----------+
   |            |
   |            v
   |   +--------------------+
   |   | Disable Sleep &    |
   |   | Hibernate          |
   +-->+--------+-----------+
                |
                v
       +--------------------+
       | Set Expiry Time    |
       +--------+-----------+
                |
                v
       +--------------------+
       | Create Scheduled   |
       | Task for Restore   |
       +--------+-----------+
                |
                v
       +--------------------+
       |  Exit 0/1          |
       +--------------------+
```

## Purpose

Temporarily disables sleep and hibernate modes on a Windows device with automatic restoration after a configurable timeout.

## Features

- **Configurable duration** via custom field
- **Backup before change** - Saves current power settings to registry
- **Verification** - Confirms backup before applying changes
- **Idempotent** - Safe to run multiple times (extends timeout)
- **Auto-restore** - Scheduled task automatically restores settings
- **All Windows versions** - Works on Windows 7/8/8.1/10/11

## Exit Codes

| Code | Status | Description |
|------|--------|-------------|
| 0 | Success | Sleep prevention active |
| 1 | Alert | Failed to disable sleep |

## Custom Fields

| Field | Default | Description |
|-------|---------|-------------|
| `cf_coolforge_nosleep_duration_min` | 60 | Duration in minutes to prevent sleep |
| `cf_coolforge_msp_scratch_folder` | C:\ProgramData\MSP | Storage location |

## How It Works

1. **Check existing session** - If already active, extends or maintains timeout
2. **Backup settings** - Saves current power configuration to registry
3. **Verify backup** - Confirms backup was saved correctly
4. **Disable sleep/hibernate** - Sets timeouts to 0 (never) on AC and DC
5. **Set expiry** - Stores when settings should be restored
6. **Create scheduled task** - Runs every 5 minutes to check if expired

## Settings Modified

| Setting | AC Power | DC Power |
|---------|----------|----------|
| Standby timeout | Disabled | Disabled |
| Hibernate timeout | Disabled | Disabled |
| Monitor timeout | Unchanged | Unchanged |

## Registry Location

```
HKLM:\SOFTWARE\{MSPName}\COOLForge\NoSleep
```

Stores:
- SchemeGuid - Active power scheme
- StandbyTimeoutAC/DC - Original values
- HibernateTimeoutAC/DC - Original values
- MonitorTimeoutAC/DC - Original values
- ExpiryTime - When to restore
- BackupTime - When backup was created

## Scheduled Task

**Name:** `COOLForge_RestoreSleepSettings`

- Runs every 5 minutes as SYSTEM
- Checks if expiry time has passed
- Restores original power settings
- Cleans up registry and removes itself

## Manual Restore

To restore settings before timeout expires:
```powershell
& "$MspScratchFolder\Scripts\🔧Restore Sleep Settings.ps1"
```

## Use Cases

- Keep device awake during long updates
- Prevent sleep during maintenance windows
- Run overnight scripts without interruption
