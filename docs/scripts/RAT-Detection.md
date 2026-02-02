# RAT Detection Script

**Script:** `scripts/Check/👀Check for Unauthorized Remote Access Tools.ps1`
**Launcher:** `launchers/Monitor/👀Check for Unauthorized Remote Access Tools.ps1`
**Version:** 2026.01.10.01
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
| (SC Instance ID,   |
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
   SCRIPT: Loads 60+ RAT
   definitions, checks SC
   whitelist, scans procs
   services, registry, dirs
         |
         v
+--------------------+
| Check Blocking     |
| Tags               |
+--------+-----------+
         |
         v
+--------------------+
| Load RAT           |
| Definitions (60+)  |
+--------+-----------+
         |
         v
+--------------------+
| Check SC           |
| Whitelist          |
+--------+-----------+
         |
         v
+--------------------+
| Scan Processes     |
+--------+-----------+
         |
         v
+--------------------+
| Scan Services      |
+--------+-----------+
         |
         v
+--------------------+
| Scan Registry      |
+--------+-----------+
         |
         v
+--------------------+
| Scan Directories   |
+--------+-----------+
         |
         v
+--------------------+
| Report Findings    |
+--------+-----------+
         |
    +----+----+
    |         |
    v         v
+------+  +-------+
|Found |  | None  |
|Exit 1|  |Exit 0 |
+------+  +-------+
```

## Purpose

Detects unauthorized remote access tools (RATs) that may be installed without authorization on managed endpoints.

## Features

- Scans for **60+ known remote access tools** including:
  - AnyDesk, TeamViewer, RustDesk, ScreenConnect
  - Splashtop, LogMeIn, GoToAssist, RemotePC
  - BeyondTrust, Chrome Remote Desktop, Parsec
  - Various RMM tools (Datto, NinjaRMM, Kaseya, etc.)
- **ScreenConnect whitelisting** - Excludes your MSP's authorized instance
- **Multi-method detection**:
  - Running processes
  - Installed services
  - Registry entries
  - Installation directories

## Exit Codes

| Code | Status | Description |
|------|--------|-------------|
| 0 | Success | No unauthorized RATs detected |
| 1 | Alert | Unauthorized RAT(s) detected |

## Custom Fields

| Field | Required | Description |
|-------|----------|-------------|
| `cf_policy_screenconnect_instance_id` | No | Your MSP's ScreenConnect instance ID for whitelisting |
| `cf_machine_is_screenconnect_server` | No | Set to `true` on ScreenConnect server devices to skip detection |

## Tag Support

| Tag | Effect |
|-----|--------|
| `❌` | Blocks script execution on this device |

## Usage Example

Deploy via launcher to scan endpoints for unauthorized remote access tools. The script will:

1. Load tool definitions (60+ RATs)
2. Check if ScreenConnect matches your whitelisted instance
3. Scan processes, services, registry, and directories
4. Report any unauthorized tools found

## Output

When RATs are detected, the script outputs:
- Tool name
- Detection method (process, service, installed software, directory)

## Related Scripts

- [Force Remove AnyDesk](Force-Remove-AnyDesk.md) - Remove detected AnyDesk
- [Force Remove Non-MSP ScreenConnect](Force-Remove-Non-MSP-ScreenConnect.md) - Remove unauthorized ScreenConnect
