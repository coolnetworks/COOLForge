# Cleanup VoyagerPACS Studies

Cleans up old PACS imaging studies from VoyagerPACS installations.

## Flow

```
+--------------------+
| Launcher Start     |
+--------+-----------+
         |
         v
+--------------------+
| Load Level.io Vars |
| (Retention Config) |
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
   SCRIPT: Cleanup
   old PACS studies
         |
         v
+--------------------+
| Find VoyagerPACS   |
| Installation       |
+--------+-----------+
         |
         v
+--------------------+
| Scan for Studies   |
| Older Than         |
| Retention Period   |
+--------+-----------+
         |
         v
+--------------------+
| Delete Expired     |
| Studies            |
+--------+-----------+
         |
         v
+--------------------+
| Report Space       |
| Recovered          |
+--------+-----------+
         |
         v
+--------------------+
|  Exit 0            |
+--------------------+
```

## Purpose

Removes old medical imaging studies that exceed retention policies to free disk space.

## Features

- Identifies old studies based on age
- Removes expired imaging data
- Reports space recovered

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Cleanup completed |
| 1 | Cleanup failed or error |

## Requirements

- VoyagerPACS installation
- Appropriate permissions to delete study data

## Usage

Deploy via Level.io automation. Configure retention period as needed.

## Warning

Ensure compliance with medical record retention requirements before deploying.
