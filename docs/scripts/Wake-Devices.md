# Wake All Devices Script

**Script:** `scripts/Utility/🙏Wake all devices in Level group.ps1`
**Launcher:** `launchers/🙏Wake all devices in Level group.ps1`
**Category:** Utility

## Flow

```
+--------------------+
| Launcher Start     |
+--------+-----------+
         |
         v
+--------------------+
| Load Level.io Vars |
| (API Key, Scratch  |
|  Folder, Tags)     |
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
    SCRIPT LOGIC
         |
         v
+--------------------+
| Get Current Device |
| Group/Folder       |
+--------+-----------+
         |
         v
+--------------------+
| Traverse Up by     |
| LevelsUp Count     |
+--------+-----------+
         |
         v
+--------------------+
| Fetch All Devices  |
| in Target Folder   |
+--------+-----------+
         |
         v
+--------------------+
| For Each Device    |
| Send WOL Packets   |
+--------+-----------+
         |
         v
+--------------------+
| Report Results     |
+--------+-----------+
         |
         v
+--------------------+
|  Exit 0            |
+--------------------+
```

## Purpose

Sends Wake-on-LAN (WOL) packets to all devices within a Level.io folder hierarchy.

## Features

- **Folder hierarchy traversal** - Wake devices in parent or ancestor folders
- **Configurable levels** - Specify how many levels up to traverse
- **Multiple WOL attempts** - Sends multiple packets for reliability
- **API-driven** - Uses Level.io API to discover devices

## Prerequisites

- Level.io API key with device read permissions
- Devices must have MAC addresses registered in Level.io
- Network must support WOL (broadcast to port 9)

## Configuration

```powershell
$ApiKey = "{{cf_apikey}}"
$LevelsUp = 1           # 0 = current folder, 1 = parent, 2 = grandparent
$WolAttempts = 10       # Number of WOL packets per device
$WolDelayMs = 500       # Delay between attempts (ms)
```

## How It Works

1. Gets current device's group (folder) from Level.io
2. Traverses up folder hierarchy by `$LevelsUp` levels
3. Fetches all devices in that folder and subfolders
4. Sends WOL magic packets to each device's MAC address

## Level.io API Calls

| Endpoint | Purpose |
|----------|---------|
| `/devices` | List all devices and their MAC addresses |
| `/groups` | Get folder hierarchy for traversal |

## Folder Levels Explained

```
MyMSP (root)
├── Client A
│   ├── Main Office    <- LevelsUp=1 from here...
│   │   └── PC-001     <- ...starts here
│   └── Branch Office
└── Client B
```

- `LevelsUp = 0`: Wake only devices in `Main Office`
- `LevelsUp = 1`: Wake all devices in `Client A` and subfolders
- `LevelsUp = 2`: Wake all devices in `MyMSP` (entire org)

## WOL Magic Packet

The script uses `Send-LevelWakeOnLan` from COOLForge-Common to send UDP magic packets:
- Broadcast to port 9
- Contains target MAC address repeated 16 times
- Multiple attempts for reliability

## Use Cases

- Wake up all devices at a client site before maintenance
- Power on devices remotely for updates/deployments
- Prepare an entire folder of devices for administrative tasks
- Wake devices before running overnight scripts

## Requirements

- Devices must support Wake-on-LAN
- WOL must be enabled in BIOS/UEFI
- Network must allow UDP broadcast to port 9
