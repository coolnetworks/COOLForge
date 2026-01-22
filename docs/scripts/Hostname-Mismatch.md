# Hostname Mismatch Detection

Detects when a device's actual hostname doesn't match what Level.io expects.

## Flow

```
+------------------+
|  Script Start    |
+--------+---------+
         |
         v
+------------------+
| Get Actual       |
| Hostname         |
+--------+---------+
         |
         v
+------------------+
| Compare to       |
| Level.io Value   |
+--------+---------+
         |
    +----+----+
    |         |
    v         v
+-------+ +--------+
| Match | |Mismatch|
|Exit 0 | |Exit 1  |
+-------+ +--------+
```

## Purpose

Identifies devices where the Windows hostname has changed but Level.io still shows the old name.

## Features

- Compares actual hostname to Level.io recorded hostname
- Reports mismatches for manual review
- Helps maintain accurate device inventory

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Hostnames match or check completed |
| 1 | Mismatch detected or error |

## Usage

Deploy via Level.io automation. Uses `{{level_device_hostname}}` variable.

## Related

- [Test Variable Output](Test-Variable-Output.md)
