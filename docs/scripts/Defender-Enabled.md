# Ensure Windows Defender Enabled

Ensures Windows Defender antivirus is enabled and running.

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
   SCRIPT: Ensure
   Defender enabled
         |
         v
+--------------------+
| Check Defender     |
| Service Status     |
+--------+-----------+
         |
    +----+----+
    |         |
    v         v
+-------+ +--------+
|Running| |Stopped |
+-------+ +---+----+
    |         |
    |         v
    |    +--------+
    |    | Enable |
    |    | Service|
    |    +---+----+
    |         |
    v         v
+--------------------+
| Verify Real-Time   |
| Protection         |
+--------+-----------+
         |
         v
+--------------------+
|  Exit 0/1          |
+--------------------+
```

## Purpose

Verifies Windows Defender is active and attempts to enable it if disabled.

## Features

- Checks Windows Defender service status
- Enables real-time protection if disabled
- Reports current protection status

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Defender is enabled and running |
| 1 | Failed to enable or error |

## Requirements

- Windows 10/11 or Windows Server with Defender
- Administrator privileges

## Usage

Deploy via Level.io automation. No additional configuration required.

## Notes

Will not interfere with third-party antivirus solutions that have disabled Defender.
