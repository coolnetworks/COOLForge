# Configure Wake-on-LAN

Enables Wake-on-LAN (WOL) settings on network adapters.

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
   SCRIPT: Configure
   Wake-on-LAN
         |
         v
+--------------------+
| Find Network       |
| Adapters           |
+--------+-----------+
         |
         v
+--------------------+
| Enable WOL         |
| Power Settings     |
+--------+-----------+
         |
         v
+--------------------+
| Configure NIC      |
| Properties         |
+--------+-----------+
         |
    +----+----+
    |         |
    v         v
+-------+ +--------+
|Success| | Failed |
|Exit 0 | |Exit 1  |
+-------+ +--------+
```

## Purpose

Configures network adapters to respond to WOL magic packets, enabling remote wake functionality.

## Features

- Enables WOL on compatible network adapters
- Configures power management settings
- Works with most Intel and Realtek NICs

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | WOL configured successfully |
| 1 | Configuration failed or not supported |

## Requirements

- Administrator privileges
- Compatible network adapter
- BIOS/UEFI WOL support may also be required

## Usage

Deploy via Level.io automation. No additional configuration required.

## Related

- [Wake-on-LAN Documentation](../WOL.md)
- [Wake Devices Script](Wake-Devices.md)
