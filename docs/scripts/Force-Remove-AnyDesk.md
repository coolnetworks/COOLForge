# Force Remove AnyDesk Script

**Script:** `scripts/Remove/⛔Force Remove Anydesk.ps1`
**Launcher:** `launchers/Remove/⛔Force Remove Anydesk.ps1`
**Version:** 2025.12.27.05
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
   SCRIPT: 5-phase removal
   uninstall, stop services,
   delete files, clean
   registry, verify gone
         |
         v
+--------------------+
| Check for          |
| Blocking Tags      |
+--------+-----------+
         |
         v
+--------------------+
| Phase 1: Standard  |
| Uninstall          |
+--------+-----------+
         |
         v
+--------------------+
| Phase 2: Stop      |
| Services           |
+--------+-----------+
         |
         v
+--------------------+
| Phase 3: Remove    |
| Files              |
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
| Phase 5: Verify    |
| Removal            |
+--------+-----------+
         |
         v
+--------------------+
|  Exit 0/1          |
+--------------------+
```

## Purpose

Removes AnyDesk remote access software from the system using progressively forceful methods.

## Features

- **5-phase removal** process with escalating force
- **Complete removal** - Processes, services, files, and registry
- **Verification** - Confirms AnyDesk is fully removed
- **Tag gating** - Respects blocking tags

## Exit Codes

| Code | Status | Description |
|------|--------|-------------|
| 0 | Success | AnyDesk completely removed |
| 1 | Alert | Removal failed or partially complete |

## Tag Support

| Tag | Effect |
|-----|--------|
| `❌` | Blocks script execution on this device |

## Removal Phases

### Phase 1: Standard Uninstall
- Searches registry for AnyDesk uninstall strings
- Executes standard uninstaller

### Phase 2: Stop Services and Processes
- Stops AnyDesk services
- Terminates running AnyDesk processes

### Phase 3: Remove Files and Folders
- Deletes AnyDesk program folders
- Removes AppData folders
- Clears ProgramData entries

### Phase 4: Clean Registry
- Removes HKLM uninstall entries
- Clears HKCU entries
- Removes service registrations

### Phase 5: Verification
- Checks for remaining processes
- Checks for remaining services
- Checks for remaining files
- Confirms complete removal

## Detection Checks

The `Test-AnyDeskInstalled` function checks:
- Running processes (`AnyDesk*`)
- Installed services (`AnyDesk*`)
- Registry uninstall entries
- Common installation directories

## Common Locations Cleaned

```
C:\Program Files (x86)\AnyDesk
C:\Program Files\AnyDesk
%APPDATA%\AnyDesk
%ProgramData%\AnyDesk
```

## Use Cases

- Remove unauthorized AnyDesk installations
- Clean up after RAT detection alerts
- Enforce remote access tool policies
- Remediate compromised endpoints

## Related Scripts

- [RAT Detection](RAT-Detection.md) - Detect AnyDesk and other RATs
