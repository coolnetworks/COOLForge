# COOLForge Cache Sync

Synchronizes the local registry cache with Level.io data.

## Flow

```
+------------------+
|  Script Start    |
+--------+---------+
         |
         v
+------------------+
| Query Level.io   |
| API for Device   |
| Data             |
+--------+---------+
         |
         v
+------------------+
| Update Registry  |
| Cache Values     |
+--------+---------+
         |
         v
+------------------+
| Clear Stale      |
| Entries          |
+--------+---------+
         |
         v
+------------------+
|  Exit 0          |
+------------------+
```

## Purpose

Refreshes cached device information, tags, and custom field values stored in the local registry.

## Features

- Updates cached device tags
- Refreshes custom field values
- Clears stale cache entries

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Cache sync completed |
| 1 | Sync failed |

## Requirements

- Level.io API key

## Usage

Deploy via Level.io automation. Run periodically to keep cache fresh.

## Related

- [Codebase - Cache Management](../CODEBASE.md#cache-management)
