# Debug Policy Script

**Script:** `scripts/Policy/👀debug.ps1`
**Launcher:** `launchers/Policy/👀debug.ps1`
**Version:** 2026.01.01.03
**Category:** Policy

## Flow

```
+--------------------+
| Launcher Start     |
+--------+-----------+
         |
         v
+--------------------+
| Load Level.io Vars |
| (API Key, Tags,    |
|  Policy Fields)    |
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
   SCRIPT: Tests policy
   resolution, displays
   what action would run,
   simulates install/remove
         |
         v
+--------------------+
| Check Tags &       |
| Policy Field       |
+--------+-----------+
         |
    +----+----+----+----+
    |    |    |    |    |
    v    v    v    v    v
+----+ +----+ +---+ +----+ +---+
|Skip| |Pin | |Rem| |Inst| |Has|
+----+ +--+-+ +-+-+ +-+--+ +-+-+
           |    |     |     |
           v    v     v     v
        +------+ +--------+ +--------+
        |No-op | |Simulate| |Simulate|
        +------+ | Remove | | Install|
                 +--------+ +--------+
                    |          |
                    v          v
          +--------------------+
          | Display Results    |
          +--------+-----------+
                   |
                   v
          +--------------------+
          |  Exit 0/1          |
          +--------------------+
```

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
| 🙏DEBUG | Install |
| 🚫DEBUG | Remove if present |
| 📌DEBUG | Pin (lock state) |
| 🔄DEBUG | Reinstall |
| ✅DEBUG | Has (verify installed) |
| ❌DEBUG | Skip (hands off) |

> **Note:** `⛔DEBUG` also works for Remove but is **deprecated** for the software policy context. Use `🚫DEBUG` instead. However, `⛔DEBUG` is also used as a **debug control tag** (force debug off) - see [TAGS.md](TAGS.md#debug-control-tags).
>
> **Naming overlap:** `✅DEBUG` serves double duty: as a software status tag (debug policy script installed) and as a debug control tag (enable verbose debug). The debug control tag check happens first during `Initialize-LevelScript`. This overlap only matters if you use the debug test script on the same device as debug control tags.

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
