# Unchecky Policy Script

**Script:** `scripts/Check/👀unchecky.ps1`
**Launcher:** `launchers/👀unchecky.ps1`
**Version:** 2026.01.01.05
**Category:** Check

## Purpose

Tag-based policy enforcement check for Unchecky software. Demonstrates the COOLForge multilaunch pattern for software policy management.

## Features

- **Tag-based policy detection** using emoji prefixes
- **Reusable pattern** - Change `$SoftwareName` to manage any software
- **Library-powered** - Uses `Invoke-SoftwarePolicyCheck` from COOLForge-Common

## Policy Tags

| Tag | Meaning |
|-----|---------|
| 🙏unchecky | Request/Recommend installation |
| ⛔unchecky | Block/Must not be installed |
| 🛑unchecky | Stop/Remove if present |
| 📌unchecky | Pin/Must be installed (enforce presence) |
| ✅unchecky | Installed/Already present |

## Exit Codes

| Code | Status | Description |
|------|--------|-------------|
| 0 | Success | Policy check completed |
| 1 | Alert | Policy violation or failure |

## Multilaunch Pattern

This script demonstrates the COOLForge pattern for software policy management. To use for other software:

1. Copy this script
2. Change `$SoftwareName = "unchecky"` to your software name
3. Update tags in Level.io device configuration
4. Deploy via launcher

The same script pattern handles all software packages through the library's policy resolution logic.

## Usage

The script:
1. Reads device tags from Level.io
2. Calls `Invoke-SoftwarePolicyCheck` to detect policy tags
3. Reports which actions are required based on the emoji prefix

## Related Scripts

- [Debug Policy Script](Debug-Policy.md) - Test policy logic
