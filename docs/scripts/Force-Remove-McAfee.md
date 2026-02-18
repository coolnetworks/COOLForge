# Force Remove McAfee Script

**Script:** `scripts/Remove/⛔Force Remove McAfee.ps1`
**Launcher:** `launchers/Remove/⛔Force Remove McAfee.ps1`
**Version:** 2026.02.01.01
**Category:** Remove

## Purpose

Performs complete removal of McAfee security products from the system.

## Removal Phases

1. **Stop McAfee services and processes**
2. **Registry-based uninstall** (MSI and exe uninstallers with silent flags)
3. **MCPR fallback** — Downloads and runs McAfee Consumer Product Removal tool if standard methods fail
4. **Force file removal, registry cleanup, firewall rules, tasks, services**
5. **Verify complete removal**

## Exit Codes

| Code | Status | Description |
|------|--------|-------------|
| 0 | Success | McAfee fully removed or was not installed |
| 1 | Alert | Removal failed or incomplete |

## Files

| File | Path | Purpose |
|------|------|---------|
| Launcher | `launchers/Remove/⛔Force Remove McAfee.ps1` | Deploy to Level.io |
| Script | `scripts/Remove/⛔Force Remove McAfee.ps1` | Removal logic |
| Module | `modules/COOLForge-Common.psm1` | Shared library |
