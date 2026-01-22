# Universal Disk Cleaner

Cleans temporary files and frees disk space across common locations.

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
   SCRIPT: Cleans temp
   folders, browser
   caches, Windows Update
   cache to free space
         |
         v
+--------------------+
| Get Initial        |
| Disk Space         |
+--------+-----------+
         |
         v
+--------------------+
| Clean Windows      |
| Temp Folders       |
+--------+-----------+
         |
         v
+--------------------+
| Clean Browser      |
| Caches             |
+--------+-----------+
         |
         v
+--------------------+
| Clean Windows      |
| Update Cache       |
+--------+-----------+
         |
         v
+--------------------+
| Report Space       |
| Recovered          |
+--------+-----------+
         |
         v
+------------------+
|  Exit 0          |
+------------------+
```

## Purpose

Removes temporary files, browser caches, and other cleanable data to free disk space.

## Features

- Cleans Windows temp folders
- Removes browser caches (Chrome, Edge, Firefox)
- Clears Windows Update cache
- Reports space recovered

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Cleanup completed |
| 1 | Cleanup failed or error |

## Requirements

- Administrator privileges for system-level cleanup

## Usage

Deploy via Level.io automation. No additional configuration required.

## Safety

Only removes files from known safe locations. Does not delete user documents or application data.
