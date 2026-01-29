# Force Remove Adobe Creative Cloud Script

**Script:** `scripts/Remove/⛔Force Remove Adobe Creative Cloud.ps1`
**Launcher:** `launchers/Remove/⛔Force Remove Adobe Creative Cloud.ps1`
**Version:** 2025.01.27.01
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
| (Scratch Folder,   |
|  Tags)             |
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
   SCRIPT: 6-phase removal
   stop services, cleaner tool,
   remove files, clean registry,
   firewall/tasks, verify gone
         |
         v
+--------------------+
| Check for          |
| Blocking Tags      |
+--------+-----------+
         |
         v
+--------------------+
| Phase 1: Stop ALL  |
| Adobe Services &   |
| Processes (3x)     |
+--------+-----------+
         |
         v
+--------------------+
| Phase 2: Adobe CC  |
| Cleaner Tool       |
+--------+-----------+
         |
    +----+----+
    |         |
    v         v
+------+  +--------+
|Works |  |Fails   |
+--+---+  +---+----+
   |          |
   v          v
+------+  +--------+
|Done? |  |MSI     |
+--+---+  |Fallback|
   |      +---+----+
   |          |
   +----+-----+
        |
        v
+--------------------+
| Phase 3: Remove    |
| Files & Folders    |
+--------+-----------+
         |
         v
+--------------------+
| Phase 4: Clean     |
| Registry           |
+--------+-----------+
         |
         v
+--------------------+
| Phase 5: Clean     |
| Firewall & Tasks   |
+--------+-----------+
         |
         v
+--------------------+
| Phase 6: Final     |
| Verification       |
+--------+-----------+
         |
         v
+--------------------+
|  Exit 0/1          |
+--------------------+
```

## Purpose

Forcefully removes Adobe Creative Cloud and all Adobe products from the system when the standard uninstaller fails due to running Adobe services or applications.

## Features

- **6-phase removal** process with progressively forceful methods
- **Official Adobe tool** - Downloads and runs Adobe CC Cleaner Tool
- **Multi-pass process termination** - 3 passes to catch respawning processes
- **Complete cleanup** - Processes, services, files, registry, firewall rules, scheduled tasks
- **User profile cleanup** - Removes Adobe data from all user profiles
- **Verification** - Confirms Adobe CC is fully removed
- **Tag gating** - Respects blocking tags

## Exit Codes

| Code | Status | Description |
|------|--------|-------------|
| 0 | Success | Adobe CC completely removed (or reboot needed) |
| 1 | Alert | Removal failed or admin privileges required |

## Tag Support

| Tag | Effect |
|-----|--------|
| `SKIP` | Blocks script execution on this device |
| `NoRemoval` | Blocks script execution on this device |

## Removal Phases

### Phase 1: Stop ALL Adobe Services & Processes

This is the critical phase - Creative Cloud refuses to uninstall if ANY Adobe service or process is running.

**3-pass approach:**
1. Stop all Adobe services and disable them
2. Terminate all Adobe processes
3. Repeat up to 3 times to catch respawning processes

**Service patterns detected:**
- `Adobe*`
- `AGS*` (Adobe Genuine Service)
- `AdobeARMservice`
- `AdobeUpdateService`
- `AGMService`
- `CCService`

**Process patterns detected:**
- `Adobe*`
- `Creative Cloud*`
- `CCLibrary*`, `CCXProcess*`
- `Core Sync*`, `CoreSync*`
- `AdobeIPCBroker*`
- `armsvc*`, `AGSService*`
- Node.js processes in Adobe folders

### Phase 2: Adobe Creative Cloud Cleaner Tool

Downloads and runs Adobe's official silent removal utility:
```
https://swupmf.adobe.com/webfeed/CleanerTool/win/AdobeCreativeCloudCleanerTool.exe
```

**Arguments:** `--removeAll=ALL --eulaAccepted=1`

If the CC Cleaner Tool fails or is unavailable, falls back to MSI-based uninstall for products registered via Windows Installer.

### Phase 3: Remove Files & Folders

Forcefully removes Adobe files from:
```
C:\Program Files\Adobe
C:\Program Files (x86)\Adobe
C:\Program Files\Common Files\Adobe
C:\Program Files (x86)\Common Files\Adobe
%LOCALAPPDATA%\Adobe
%APPDATA%\Adobe
%ProgramData%\Adobe
```

Also cleans:
- Desktop shortcuts (Adobe*.lnk)
- Start Menu entries
- Temp files
- All user profiles (AppData\Local, Roaming, LocalLow)

### Phase 4: Clean Registry

Removes Adobe registry entries from:
- HKLM and HKCU uninstall entries
- `HKLM:\SOFTWARE\Adobe` and WOW6432Node equivalent
- `HKCU:\SOFTWARE\Adobe`
- Adobe class registrations
- Service registrations
- Run key entries (startup items)

### Phase 5: Clean Firewall & Scheduled Tasks

- Removes firewall rules with "Adobe" in display name
- Unregisters scheduled tasks with "Adobe" in name or path

### Phase 6: Final Verification

Checks for remaining:
- Adobe installation folders
- Adobe processes
- Adobe services

If traces remain, reports them and suggests reboot may be required.

## Detection Checks

The `Test-AdobeCCInstalled` function checks:
- Installation directories exist
- Adobe services present
- Registry uninstall entries (excluding Adobe Acrobat Reader)

## Common Locations Cleaned

```
C:\Program Files\Adobe
C:\Program Files (x86)\Adobe
C:\Program Files\Common Files\Adobe
C:\Program Files (x86)\Common Files\Adobe
C:\ProgramData\Adobe
C:\Users\*\AppData\Local\Adobe
C:\Users\*\AppData\Roaming\Adobe
C:\Users\*\AppData\LocalLow\Adobe
```

## What Is NOT Removed

- **Adobe Acrobat Reader** - The script explicitly excludes Reader from detection and removal
- This allows the free PDF reader to remain while removing paid Creative Cloud products

## Use Cases

- Remove Adobe Creative Cloud after license expiration
- Clean up abandoned CC installations
- Prepare devices for different Creative Cloud subscription
- Remove unauthorized Adobe software
- Remediate devices after audit findings

## Troubleshooting

### Script exits with "Admin privileges required"
Run the script with administrator rights.

### "Traces still detected" after removal
Some Adobe files are locked until reboot. Restart the device and verify removal.

### CC Cleaner Tool fails
The script falls back to MSI uninstall and force removal. Manual cleanup may still be needed for stubborn installations.

### Adobe Reader gets removed
This should not happen - the script explicitly excludes Reader. Check the logs if Reader is affected.

## Related Scripts

- [RAT Detection](RAT-Detection.md) - Detect remote access tools
- [Force Remove AnyDesk](Force-Remove-AnyDesk.md) - Similar removal pattern
- [Force Remove Non-MSP ScreenConnect](Force-Remove-Non-MSP-ScreenConnect.md) - Similar removal pattern
