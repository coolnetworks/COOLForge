# Debug Policy Script

**Script:** `scripts/Check/👀debug.ps1`
**Launcher:** `launchers/👀debug.ps1`
**Version:** 2026.01.01.03
**Category:** Check

## Purpose

Debug script for testing software policy enforcement logic. Demonstrates the COOLForge policy check pattern without actually installing or removing software.

## Features

- **Policy resolution testing** - See what action would be taken
- **Execution plan display** - Shows which routines would run
- **Install mode options** - Reinstall vs Install-only logic
- **Placeholder routines** - Shows where real code would execute

## Policy Tags

| Tag | Action |
|-----|--------|
| 🙏DEBUG | Install/reinstall |
| ⛔DEBUG | Remove if present |
| 🚫DEBUG | Block install |
| 📌DEBUG | Pin (lock state) |
| ✅DEBUG | Has (verify installed) |
| ❌DEBUG | Skip (hands off) |

## Exit Codes

| Code | Status | Description |
|------|--------|-------------|
| 0 | Success | Policy check completed |
| 1 | Alert | Failure detected |

## Configuration

```powershell
$SoftwareName = "DEBUG"
$InstallMode = "Reinstall"  # or "Install"
```

- **Reinstall**: Always uninstall first (for config updates)
- **Install**: Only install if missing

## Placeholder Routines

The script includes placeholder functions that show what real implementations would do:

| Function | Purpose |
|----------|---------|
| `Install-Software` | Download, install, verify |
| `Remove-Software` | Find uninstaller, run, cleanup |
| `Test-SoftwareInstalled` | Check registry and Program Files |
| `Test-SoftwareHealthy` | Check services and config files |

## Use Cases

1. **Test tag parsing** - Verify emoji tags are correctly interpreted
2. **Debug policy logic** - See how `Invoke-SoftwarePolicyCheck` resolves actions
3. **Template for new scripts** - Copy and modify for actual software
4. **Training** - Understand the policy enforcement pattern
