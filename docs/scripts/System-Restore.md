# Enable System Restore Script

**Script:** `scripts/Fix/🔧Enable System Restore and Create Restore Point.ps1`
**Launcher:** `launchers/🔧Enable System Restore and Create Restore Point.ps1`
**Version:** 2025.12.29.01
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
| (Scratch Folder)   |
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
   SCRIPT: Enables System
   Protection, sets disk
   space, creates restore
   point, schedules daily
         |
         v
+--------------------+
| Enable System      |
| Protection         |
+--------+-----------+
         |
         v
+--------------------+
| Configure Disk     |
| Space (10%)        |
+--------+-----------+
         |
         v
+--------------------+
| Disable 24hr       |
| Frequency Limit    |
+--------+-----------+
         |
         v
+--------------------+
| Create Restore     |
| Point              |
+--------+-----------+
         |
         v
+--------------------+
| Verify Restore     |
| Point Created      |
+--------+-----------+
         |
         v
+--------------------+
| Create Daily       |
| Scheduled Task     |
+--------+-----------+
         |
         v
+--------------------+
| Report Summary     |
+--------+-----------+
         |
         v
+--------------------+
|  Exit 0/1          |
+--------------------+
```

## Purpose

Enables System Protection, creates an immediate restore point, and schedules daily automatic restore points.

## Features

- **Enable System Protection** on system drive
- **Configure disk space** allocation for restore points
- **Create immediate restore point** with timestamp
- **Verify restore point** creation
- **Schedule daily restore points** at 3:00 AM
- **All Windows versions** - Windows 7/8/8.1/10/11

## Exit Codes

| Code | Status | Description |
|------|--------|-------------|
| 0 | Success | System Restore configured |
| 1 | Alert | Configuration failed |

## Configuration

```powershell
$DiskSpacePercent = 10  # Percentage of disk for restore points
$RestorePointDescription = "COOLForge_Lib Automated Restore Point"
$ScheduledTaskName = "COOLForge_Lib Daily System Restore Point"
```

## Operations Performed

### Step 1: Enable System Protection
- Sets `RPSessionInterval` registry value
- Calls `Enable-ComputerRestore` (Windows 8+) or WMI (Windows 7)

### Step 2: Configure Disk Space
- Queries drive size
- Calculates allocation based on percentage
- Uses `vssadmin resize shadowstorage`

### Step 3: Create Restore Point
- Temporarily disables 24-hour creation frequency limit
- Creates restore point with `Checkpoint-Computer`
- Restores original frequency setting

### Step 4: Verify Restore Point
- Queries `Get-ComputerRestorePoint`
- Confirms new restore point exists
- Checks timestamp is within 5 minutes

### Step 5: Create Scheduled Task
- Creates daily task at 3:00 AM
- Runs as SYSTEM with highest privileges
- Uses encoded PowerShell command for reliability

## Output Summary

```
========================================
System Restore Configuration Complete
========================================
  System Protection:  Enabled on C:
  Disk Allocation:    10% (~XX GB)
  Restore Point:      Created & Verified
  Daily Schedule:     3:00 AM
========================================
```

## Windows Version Support

| Version | Method |
|---------|--------|
| Windows 8+ | `Checkpoint-Computer`, `New-ScheduledTask` |
| Windows 7 | WMI SystemRestore, `schtasks.exe` XML |

## Troubleshooting

| Error | Solution |
|-------|----------|
| 0x80070422 | VSS service not running - script attempts to start it |
| Frequency limit | Restore point created recently - waits for scheduled task |
| No restore points | Check System Protection is enabled in Control Panel |
