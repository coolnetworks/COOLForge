# Unchecky Policy Script

**Script:** `scripts/SoftwarePolicy/👀unchecky.ps1`
**Launcher:** `launchers/👀unchecky.ps1`
**Version:** 2026.01.13
**Category:** SoftwarePolicy

## Purpose

Policy enforcement for Unchecky software. Uses the COOLForge 5-tag model for software management.

## Features

- **Custom field policy** - Set `policy_unchecky` to `install`, `remove`, or `pin`
- **Tag overrides** - Override policy per-device with emoji tags
- **Automatic tag management** - Script updates tags to reflect actual state
- **Library-powered** - Uses `Invoke-SoftwarePolicyCheck` from COOLForge-Common

## Policy Tags

| Tag | Meaning |
|-----|---------|
| 🙏unchecky | Install if missing (override tag) |
| 🚫unchecky | Remove if present (override tag) |
| 📌unchecky | Pin - don't change (override tag) |
| 🔄unchecky | Reinstall (override tag) |
| ✅unchecky | Installed (status tag, set by script) |

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
