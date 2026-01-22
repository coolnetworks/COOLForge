# Wake Tagged Devices

Sends Wake-on-LAN packets to devices with specific tags.

## Flow

```
+------------------+
|  Script Start    |
+--------+---------+
         |
         v
+------------------+
| Query Level.io   |
| for Tagged       |
| Devices          |
+--------+---------+
         |
         v
+------------------+
| Get MAC Addresses|
+--------+---------+
         |
         v
+------------------+
| For Each Device: |
| Send WOL Packet  |
+--------+---------+
         |
         v
+------------------+
| Report Results   |
| Exit 0           |
+------------------+
```

## Purpose

Wakes devices that have been tagged for wake operations, useful for scheduled maintenance windows.

## Features

- Finds devices with specified wake tags
- Sends WOL magic packets
- Supports multiple broadcast methods

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Wake packets sent successfully |
| 1 | Error or no devices found |

## Requirements

- Level.io API key
- Devices must have WOL enabled
- Network must support broadcast packets

## Usage

Deploy via Level.io automation. Tag devices with the appropriate wake tag.

## Related

- [Wake-on-LAN Documentation](../WOL.md)
- [Wake Devices Script](Wake-Devices.md)
