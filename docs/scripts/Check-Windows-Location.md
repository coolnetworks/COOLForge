# Check Windows Location Services

Checks the status of Windows Location Services on the device.

## Flow

```
+------------------+
|  Script Start    |
+--------+---------+
         |
         v
+------------------+
| Query Registry   |
| Location Settings|
+--------+---------+
         |
         v
+------------------+
| Report Status    |
| (Enabled/Disabled)|
+--------+---------+
         |
         v
+------------------+
|  Exit 0          |
+------------------+
```

## Purpose

Audits whether Windows Location Services are enabled or disabled.

## Features

- Checks location service status
- Reports current configuration
- Non-invasive check only

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Check completed successfully |
| 1 | Error during check |

## Usage

Deploy via Level.io automation. No additional configuration required.

## Related

- [Windows Location Services Policy](../policy/Windows.md)
- [Fix Windows Location Services](Fix-Location-Services.md)
