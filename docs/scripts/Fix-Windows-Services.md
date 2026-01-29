# Fix Windows Services Scripts

**Scripts:**
- `scripts/Fix/🔧Fix Windows 11 Services.ps1`
- `scripts/Fix/🔧Fix Windows 10 Services.ps1`
- `scripts/Fix/🔧Fix Windows 8.1 Services.ps1`
- `scripts/Fix/🔧Fix Windows 8 Services.ps1`
- `scripts/Fix/🔧Fix Windows 7 Services.ps1`

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
   SCRIPT: Detects Windows
   version, loads default
   service list, resets
   each to MS defaults
         |
         v
+--------------------+
| Check Admin        |
| Privileges         |
+--------+-----------+
         |
         v
+--------------------+
| Detect Windows     |
| Version            |
+--------+-----------+
         |
    +----+----+
    |         |
    v         v
+------+  +--------+
|Wrong |  |Correct |
|Version|  +---+----+
| Exit |      |
+------+      v
     +--------------------+
     | Load Service       |
     | Defaults List      |
     +--------+-----------+
              |
              v
     +--------------------+
     | Reset Each         |
     | Service Startup    |
     +--------+-----------+
              |
              v
     +--------------------+
     | Report Changes     |
     +--------+-----------+
              |
              v
     +--------------------+
     |  Exit 0/1          |
     +--------------------+
```

## Purpose

Restores Windows services to their Microsoft-recommended default startup configurations.

## Use Cases

- Recovering from malware that modified service settings
- Restoring functionality after aggressive "optimization" tools
- Fixing boot or stability issues caused by disabled services
- Returning a system to a known-good baseline configuration

## Features

- **Version-specific defaults** - Each script contains defaults for its Windows version
- **Comprehensive coverage** - Covers core system, security, networking, and optional services
- **Safe execution** - Uses `SilentlyContinue` to avoid errors on missing services

## Exit Codes

| Code | Status | Description |
|------|--------|-------------|
| 0 | Success | Services reset to defaults |
| 1 | Alert | Script requires admin or wrong Windows version |

## Requirements

- **Administrator privileges** required
- Script validates Windows version before running

## Startup Types

| Type | Description |
|------|-------------|
| Automatic | Service starts at boot |
| Manual | Service starts when needed |
| AutomaticDelayedStart | Starts at boot, after other Automatic services |
| Disabled | Service will not start |

## Service Categories Covered

- **Core System Services** - AppX, Application Management, etc.
- **Security & Firewall** - BitLocker, Windows Firewall, Defender
- **Networking** - DHCP, DNS Client, Network services
- **Audio/Video** - Windows Audio, Multimedia services
- **Storage** - Disk Defragmenter, Volume Shadow Copy
- **Update & Maintenance** - Windows Update, BITS
- **Remote Access** - Remote Desktop, Remote Registry
- **Print Services** - Print Spooler, WSD Print

## Version Detection

Each script checks the Windows build number:

| Script | Build Range |
|--------|-------------|
| Windows 11 | 22000+ |
| Windows 10 | 10240-19045 |
| Windows 8.1 | 9600 |
| Windows 8 | 9200 |
| Windows 7 | 7600-7601 |

## Post-Execution

A system restart is recommended after running this script to ensure all service changes take effect.

## Note

These scripts use `sc.exe config` under the hood to set startup types, ensuring compatibility across all Windows versions.
