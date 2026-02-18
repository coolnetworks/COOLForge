# Remove All RATs Script

**Script:** `scripts/Remove/⛔Remove All RATs.ps1`
**Launcher:** `launchers/Remove/⛔Remove All RATs.ps1`
**Version:** 2026.02.06.01
**Category:** Remove

## Purpose

Detects and removes 70+ known remote access tools (RATs) from the system, including commercial tools, VNC variants, RMM tools, and known malicious RATs.

## Detected Software Categories

- **Commercial tools:** AnyDesk, TeamViewer, RustDesk, Splashtop, LogMeIn, etc.
- **VNC variants:** RealVNC, TightVNC, UltraVNC, TigerVNC
- **RMM tools:** Action1, Atera, Datto, NinjaRMM, Kaseya, etc.
- **Known malicious RATs:** Remcos, QuasarRAT, AsyncRAT, njRAT, etc.

## Whitelisted (Never Removed)

- **Level.io** (authorized RMM)
- **ScreenConnect** (use dedicated removal script for non-MSP instances)

## Removal Phases (Per Detected RAT)

1. Stop services and processes
2. Run uninstallers (registry-based, silent)
3. Delete services
4. Remove files and folders
5. Clean registry entries
6. Remove firewall rules and scheduled tasks

## Exit Codes

| Code | Status | Description |
|------|--------|-------------|
| 0 | Success | No RATs detected, or all removed successfully |
| 1 | Alert | RATs detected or removal failed |

## Files

| File | Path | Purpose |
|------|------|---------|
| Launcher | `launchers/Remove/⛔Remove All RATs.ps1` | Deploy to Level.io |
| Script | `scripts/Remove/⛔Remove All RATs.ps1` | Detection and removal logic |
| Module | `modules/COOLForge-Common.psm1` | Shared library |

## Standalone Version

A standalone version for USB-based remediation is available:

- `standalone_scripts/Remove/Remove-AllRATs-Standalone.ps1`

## Related

- [RAT Detection](RAT-Detection.md) — Detection-only script (no removal)
- [Force Remove AnyDesk](Force-Remove-AnyDesk.md) — Deprecated (now handled by this script)
