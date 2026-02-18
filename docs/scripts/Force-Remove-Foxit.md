# Force Remove Foxit Script

**Script:** `scripts/Remove/⛔Force Remove Foxit.ps1`
**Launcher:** `launchers/Remove/⛔Force Remove Foxit.ps1`
**Version:** 2026.02.01.01
**Category:** Remove

## Purpose

Performs complete removal of Foxit PDF Reader from the system.

## Removal Phases

1. **Stop Foxit processes and services**
2. **Winget and MSI-based uninstall**
3. **Force remove Foxit files and folders** (with takeown/icacls for locked files)
4. **Clean up registry entries, shortcuts, scheduled tasks, and services**
5. **Verify complete removal**

## Exit Codes

| Code | Status | Description |
|------|--------|-------------|
| 0 | Success | Foxit fully removed or was not installed |
| 1 | Alert | Removal failed or incomplete |

## Files

| File | Path | Purpose |
|------|------|---------|
| Launcher | `launchers/Remove/⛔Force Remove Foxit.ps1` | Deploy to Level.io |
| Script | `scripts/Remove/⛔Force Remove Foxit.ps1` | Removal logic |
| Module | `modules/COOLForge-Common.psm1` | Shared library |
