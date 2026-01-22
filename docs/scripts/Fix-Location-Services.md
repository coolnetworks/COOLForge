# Fix Windows Location Services

Configures Windows Location Services to the desired state.

## Flow

```
+------------------+
|  Script Start    |
+--------+---------+
         |
         v
+------------------+
| Get Policy       |
| Setting          |
+--------+---------+
         |
    +----+----+
    |         |
    v         v
+-------+ +--------+
|Enable | |Disable |
+---+---+ +---+----+
    |         |
    v         v
+------------------+
| Update Registry  |
| Settings         |
+--------+---------+
         |
         v
+------------------+
|  Exit 0/1        |
+------------------+
```

## Purpose

Enables or disables Windows Location Services based on policy requirements.

## Features

- Enables/disables location services
- Configures registry settings
- Applies to all users

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Location services configured successfully |
| 1 | Configuration failed |

## Requirements

- Administrator privileges

## Usage

Deploy via Level.io automation. Works with the location services policy system.

## Related

- [Check Windows Location Services](Check-Windows-Location.md)
- [Windows Location Services Policy](../policy/Windows.md)
