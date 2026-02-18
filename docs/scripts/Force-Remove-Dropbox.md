# Force Remove Dropbox Script

**Script:** `scripts/Remove/⛔Force Remove Dropbox.ps1`
**Launcher:** `launchers/Remove/⛔Force Remove Dropbox.ps1`
**Version:** 2026.02.01.01
**Category:** Remove

## Purpose

Performs complete removal of Dropbox from the system using a 5-phase approach.

## Removal Phases

1. **Stop Dropbox processes**
2. **WMI/CIM uninstall and registry-based uninstall**
3. **Remove Dropbox files and folders** (including all user profiles)
4. **Clean up registry entries, shortcuts, and scheduled tasks**
5. **Verify complete removal**

## Exit Codes

| Code | Status | Description |
|------|--------|-------------|
| 0 | Success | Dropbox fully removed or was not installed |
| 1 | Alert | Removal failed or incomplete |

## Files

| File | Path | Purpose |
|------|------|---------|
| Launcher | `launchers/Remove/⛔Force Remove Dropbox.ps1` | Deploy to Level.io |
| Script | `scripts/Remove/⛔Force Remove Dropbox.ps1` | Removal logic |
| Module | `modules/COOLForge-Common.psm1` | Shared library |
