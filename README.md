ï»¿# COOLForge — Level.io PowerShell Automation Framework

**Version:** 2026.03.14  
**Copyright:** COOLNETWORKS  
**Repository:** [github.com/coolnetworks/COOLForge](https://github.com/coolnetworks/COOLForge)

A PowerShell automation framework for Level.io RMM. Shared library, standardised scripts, and a launcher system that lets you manage everything from GitHub without touching the RMM.

---

## Terminology

| Term | Description |
|------|-------------|
| **Module** | `modules/COOLForge-Common.psm1` — The shared PowerShell library. Auto-downloaded to endpoints at runtime. |
| **Script** | A `.ps1` file in `scripts/` that performs a specific task (e.g., remove AnyDesk, enforce Chrome policy). |
| **Launcher** | A `.ps1` file in `launchers/` that you deploy to Level.io once. It downloads and runs the real script from GitHub at execution time. |
| **Template** | `launchers/_template.ps1` — The single source for all launcher files. Generate launchers from this via `tools/generate-launchers.py`. |
| **Custom Field** | Level.io variables (e.g., `cf_coolforge_msp_scratch_folder`) that configure script behaviour. |

---

## Overview

COOLForge provides a shared set of functions and a launcher system for Level.io automation scripts, eliminating code duplication and keeping your script portfolio managed from GitHub.

### Key Features

- **Tag Gate System** — Controls whether scripts run on a device at all, and what they do when they run. Devices must be explicitly allowed to run scripts via a tag, and can equally be blocked.

  **Layer 1 — Global device control** (standalone tags, no software name):
  - ✅ alone = device is permitted — scripts will run
  - ❌ alone = device is blocked — all scripts skip it entirely, nothing runs
  - Neither = device is unverified — scripts skip it (safe default, nothing runs until explicitly permitted)
  - ✅ + ❌ together = device is frozen — scripts run but make no changes to anything

  **Layer 2 — Per-software override tags** (emoji + software name, e.g. `🙏HUNTRESS`):
  - 🙏 = install this software if missing
  - 🚫 = remove this software
  - 🔄 = remove and reinstall
  - 📌 = pin — do not touch this software regardless of anything else

  If no override tag is present, the script falls back to the group-level custom field (`policy_huntress = install/remove/pin`), which cascades down from parent groups.

  Priority when multiple tags conflict: **Pin wins → Reinstall → Remove → Install → custom field fallback**.

  Action tags (🙏 🚫 🔄) are transient — removed after the script acts. Status tags (✅HUNTRESS) and intent tags (📌) persist.
- **Concurrent Script Lock** — If Level.io fires the same script twice or a previous run is still going, the second run detects it and exits immediately rather than two copies running at the same time and conflicting.
- **Standardised Logging** — Every script writes output in the same format with timestamps and severity levels (INFO, SUCCESS, ERROR, SKIP). Makes reading Level.io job logs consistent across the whole fleet.
- **Error Handling** — Scripts run inside a wrapper that catches unhandled errors, cleans up lockfiles and temp files, and exits with the right code so Level.io marks the job correctly as passed or failed.
- **API Helper** — Shared functions for calling the Level.io API — handles auth, pagination, retries, and rate limiting so individual scripts don't each need to reinvent that.
- **Device Info** — One-liner functions to get hostname, OS version, group, custom field values, etc. rather than each script doing its own WMI queries and registry reads.
- **Auto-Update** — The shared library and scripts live in GitHub. When a device runs a launcher, it checks if a newer version exists and downloads it automatically. Push a fix once, every device gets it on next run — no re-uploading to Level.io.
- **Script Launcher** — Upload a small launcher to Level.io once and forget it. When a device runs it, the launcher fetches the real script from GitHub and executes it. Fix a bug or add a feature by pushing to the repo — the update reaches every device on its next run without touching the RMM. This makes COOLForge RMM-agnostic at the script level; the same GitHub repo could serve scripts to Level.io, NinjaRMM, or any other platform just by uploading a launcher.
- **Technician Alerts** — Scripts can fire toast notifications to a tech workstation when something needs attention. No need to trawl Level.io job logs to find issues.
- **MeshCentral Integration** — Group-aware MeshCentral agent deployment. Each Level.io group maps to a MeshCentral device group. Devices automatically install into the correct group based on their Level.io group membership.

### Module Functions

The `modules/COOLForge-Common.psm1` module exports functions organised into these categories:

| Category | Description |
|----------|-------------|
| **Initialisation** | Script setup, lockfiles, error handling |
| **Script Logging** | Timestamped output with severity levels (INFO, SUCCESS, ERROR, SKIP) — consistent format across all scripts |
| **System Info** | Admin check, device properties |
| **Software Detection** | Generic install detection, process/service control, MSI/EXE installers |
| **Software Policy** | Tag-based policy enforcement, emoji mapping |
| **Level.io API** | Core API calls, groups, devices, custom fields |
| **Tag Management** | Add/remove tags, policy tags, tag creation |
| **Custom Fields** | CRUD operations, group-level overrides, backup/restore |
| **Technician Alerts** | Toast notifications to tech workstations |
| **Network** | Wake-on-LAN |
| **Cache Management** | Registry cache, protected values, tag/field caching |
| **Script Launcher** | MD5 verification, script downloading, execution |

See [Function Reference](docs/FUNCTIONS.md) for complete documentation.

---

## Documentation

| Document | Description |
|----------|-------------|
| [Why COOLForge?](docs/WHY.md) | Problems COOLForge solves and design philosophy |
| [Codebase Overview](docs/CODEBASE.md) | Complete architecture and module documentation |
| [Function Reference](docs/FUNCTIONS.md) | Complete documentation for all library functions |
| [Script Documentation](docs/scripts/README.md) | Detailed docs for each script |
| [Software Policy Enforcement](docs/policy/README.md) | Complete guide for tag-based software management |
| [Launcher Guide](docs/LAUNCHER.md) | How launchers work and how to use them |
| [Level.io Group Management via API](docs/Level.io%20Group%20Management%20via%20API.md) | How to read/write custom fields at org, group, and device level |
| [Level.io API Reference](docs/LEVEL-API-CUSTOM-FIELDS.md) | Full Level.io v2 API reference including gotchas |
| [Technician Alerts](docs/TECHNICIAN-ALERTS.md) | Real-time toast notifications to tech workstations |
| [Private Fork Guide](docs/PRIVATE-FORK.md) | Using COOLForge with a private GitHub repository |
| [Version Pinning](docs/VERSION-PINNING.md) | Pin devices to specific library versions |
| [Release Workflow](docs/RELEASE-WORKFLOW.md) | Dev vs main releases, testing, and rollback |
| [Variables Reference](docs/VARIABLES.md) | Level.io variables and custom field reference |
| [Folder Structure](docs/FOLDER-STRUCTURE.md) | Script and launcher category organisation |

---

## Repository Structure

```
COOLForge/
├── modules/                          # PowerShell modules
│   └── COOLForge-Common.psm1         # Main shared library (auto-downloaded to endpoints)
├── scripts/                          # Policy and utility scripts
│   ├── Policy/                       # Software policy enforcement (install/remove/pin)
│   ├── Check/                        # Audits and compliance checks
│   ├── Fix/                          # Repair and remediation
│   ├── Remove/                       # Force removal scripts
│   └── Utility/                      # Maintenance and cleanup
├── launchers/                        # Generated launchers — deploy these to Level.io
│   ├── _template.ps1                 # Single source template for all launchers
│   ├── _manifest.json                # Defines variables passed to each script
│   └── Policy/ Fix/ Remove/ ...      # Generated per-script launchers
├── tools/                            # Admin tools (run on admin workstation)
│   ├── generate-launchers.py         # Generates all launchers from _template.ps1
│   ├── provision-mesh-groups.js      # Creates MeshCentral groups and writes meshids to Level.io
│   └── Update-MD5Sums.ps1            # Regenerates MD5SUMS file
├── vendor/                           # Vendored dependencies
│   ├── meshctrl.js                   # MeshCentral CLI (WebSocket API)
│   └── node_modules/                 # Node.js dependencies
├── start_here/                       # Setup and management tools
│   ├── Setup-COOLForge.ps1           # Initial setup wizard
│   ├── New-LevelClient.ps1           # Create a new client with standard group hierarchy
│   ├── Backup-COOLForgeCustomFields.ps1  # Backup all custom field values
│   └── Restore-LevelGroup.ps1        # Restore a backed-up group
├── validation/                       # Pre-commit validation scripts
├── docs/                             # Documentation
└── MD5SUMS                           # Checksums for all files (verified at runtime)
```

---

## Start Here

The `start_here/` folder contains scripts for setting up and managing your Level.io environment. **Run these from your admin workstation**, not on endpoints.

| Tool | Description |
|------|-------------|
| **Setup-COOLForge.ps1** | Initial setup wizard — creates required custom fields, configures API key |
| **New-LevelClient.ps1** | Create a new client with standardised group hierarchy |
| **Backup-COOLForgeCustomFields.ps1** | Backup all custom field values (org, group, and device level) |
| **Restore-LevelGroup.ps1** | Restore a backed-up group hierarchy |

### New-LevelClient.ps1

Creates a new client with a standardised, consistent group structure:

```
🏢1️⃣ClientName           <- Business, Priority 1
├── Main                   <- Site
│   ├── WS                 <- Workstations
│   │   ├── 🪟 WIN
│   │   ├── 🐧 LINUX
│   │   └── 🍎 MAC
│   └── SRV                <- Servers
│       ├── 🪟 WIN
│       └── 🐧 LINUX
└── Branch
    └── ...
```

```powershell
# Interactive mode
.\start_here\New-LevelClient.ps1

# Preview only
.\start_here\New-LevelClient.ps1 -DryRun
```

### Setup-COOLForge.ps1

Run this **first** when setting up COOLForge. Creates required custom fields and saves your API key for other tools.

```powershell
.\start_here\Setup-COOLForge.ps1
```

---

## Using Scripts in Level.io

**Scripts are deployed via launchers, not directly.** The launcher handles downloading and auto-updating the actual script from GitHub.

### Step-by-Step

1. Find the script you want in the [Available Scripts](#available-scripts) table
2. Open the matching launcher from the `launchers/` folder
3. Copy the entire launcher code
4. In Level.io → Automations → Scripts → New Script — paste and save
5. Run it on a device — the launcher downloads and executes the latest version from GitHub automatically

### How It Works

```
Level.io runs launcher → Launcher downloads library + script from GitHub → Script executes
```

- **First run:** Downloads library and script, caches locally
- **Subsequent runs:** Checks for updates, downloads if newer version exists  
- **Offline:** Uses cached local copies
- **Updates:** Push to GitHub — devices pick it up on next run, no Level.io changes needed

---

## Quick Start

> **Required Before First Use:** COOLForge needs one custom field configured:
> - `coolforge_msp_scratch_folder` — A persistent folder path on endpoints (e.g. `C:\ProgramData\YourMSP`)
>
> Without this, scripts have nowhere to store files and will fail.
>
> Run `start_here/Setup-COOLForge.ps1` to create it automatically.

### Prerequisites

- Level.io agent installed on target devices
- PowerShell 5.1 or later on endpoints
- Custom fields configured (see Setup above)

### Key Custom Fields

| Custom Field | Example Value | Required | Description |
|--------------|---------------|----------|-------------|
| `coolforge_msp_scratch_folder` | `C:\ProgramData\YourMSP` | **Yes** | Where COOLForge stores scripts, library, lockfiles, and logs on each endpoint |
| `coolforge_ps_module_library_source` | *(leave empty)* | No | URL to download the library (defaults to official repo) |
| `coolforge_pin_psmodule_to_version` | `v2026.03.14` | No | Pin scripts to a specific version tag |
| `coolforge_pat` | `ghp_abc123...` | No | GitHub PAT for private forks |
| `apikey` | *(your Level.io API key)* | No | Enables Level.io API features (tag management, custom field updates) |

---

## Software Policy Enforcement

COOLForge includes a full software lifecycle management system — install, remove, pin, and reinstall software across your fleet using a combination of Level.io tags and custom fields. Every supported software uses the same model so the behaviour is predictable and consistent.

### How It Works

Each software policy script runs on a schedule via a Level.io monitor. The script checks the device's tags and custom fields to determine what to do, acts on it, then updates the tags to reflect the new state. The monitor only alerts when something goes wrong.

```
Policy runs on schedule
  └── Script checks device tags and custom fields
        └── Resolves action (install / remove / pin / reinstall / nothing)
              └── Acts on it
                    └── Updates tags to reflect outcome
                          └── Alerts only on failure
```

### Policy Resolution — Priority Order

When the script runs, it resolves what to do in this order (first match wins):

| Priority | Source | Example |
|----------|--------|---------|
| 1 (highest) | Device tag — Pin | 📌HUNTRESS — freeze this software on this device |
| 2 | Device tag — Reinstall | 🔄HUNTRESS — force remove and reinstall |
| 3 | Device tag — Remove | 🚫HUNTRESS — remove from this device |
| 4 | Device tag — Install | 🙏HUNTRESS — install on this device |
| 5 | Custom field (device level) | `policy_huntress = install` set directly on device |
| 6 | Custom field (group level) | `policy_huntress = install` inherited from parent group |
| 7 (lowest) | Nothing | No policy set — script does nothing |

Tags always override custom fields. Device-level custom fields always override group-level. Set a default for an entire group and override per-device with tags — nothing else needs to change.

### Tag Lifecycle

Action tags (🙏 🚫 🔄) are transient — the script removes them after acting and sets the ✅ status tag automatically. You add a tag, the script acts and cleans up.

```
Admin adds 🙏HUNTRESS to device
  → Script runs, installs Huntress
    → Removes 🙏HUNTRESS, adds ✅HUNTRESS
      → Sets device custom field to "install" so intent persists
```

### Infrastructure Bootstrap

On first run with `apikey` configured, the script auto-creates all required tags and custom fields in Level.io. No manual setup — run once and it builds its own infrastructure.

### Supported Software

| Software | Notes |
|----------|-------|
| Huntress | Requires account key and org key |
| DNSFilter | Requires site key |
| Chrome | Enterprise MSI only |
| ScreenConnect | MSI with EXE fallback for AppLocker environments |
| MeshCentral | Group-aware — meshid inherited from Level.io group |
| Bitwarden | Browser extension |
| Unchecky | Requires hosted installer URL |

See [Software Policy Guide](docs/policy/README.md) for full setup instructions, flow diagrams, and troubleshooting.

---

## Available Scripts

### Policy Scripts (👀)

| Script | Description |
|--------|-------------|
| [👀chrome](docs/policy/Chrome.md) | Google Chrome Enterprise policy enforcement |
| [👀huntress](docs/policy/Huntress.md) | Huntress agent policy enforcement |
| [👀dnsfilter](docs/policy/DNSFilter.md) | DNSFilter agent policy enforcement |
| [👀meshcentral](docs/policy/MeshCentral.md) | MeshCentral agent policy enforcement (group-aware) |
| [👀screenconnect](docs/policy/ScreenConnect.md) | ScreenConnect/ConnectWise Control policy enforcement |
| [👀bitwarden](docs/policy/Bitwarden.md) | Bitwarden browser extension policy enforcement |
| [👀unchecky](docs/policy/Unchecky.md) | Unchecky policy enforcement |

### Check Scripts (👀)

| Script | Description |
|--------|-------------|
| [👀Hostname Mismatch](docs/scripts/Hostname-Mismatch.md) | Detects Level.io vs actual hostname mismatches, auto-corrects |
| [👀Check for RATs](docs/scripts/RAT-Detection.md) | Detects 60+ remote access tools with whitelisting |
| [👀Test Show Versions](docs/scripts/Test-Show-Versions.md) | Library test suite and version info |

### Fix Scripts (🔧)

| Script | Description |
|--------|-------------|
| [🔧Fix Windows Services](docs/scripts/Fix-Windows-Services.md) | Restores Windows services to defaults |
| [🔧Ensure Windows Defender Enabled](docs/scripts/Defender-Enabled.md) | Ensures Defender is running |
| [🔧Fix Windows Location Services](docs/scripts/Fix-Location-Services.md) | Fixes location services |
| [🔧Prevent Sleep](docs/scripts/Prevent-Sleep.md) | Temporarily prevents sleep with auto-restore |

### Remove Scripts (⛔)

| Script | Description |
|--------|-------------|
| [⛔Force Remove Non MSP ScreenConnect](docs/scripts/Force-Remove-Non-MSP-ScreenConnect.md) | Removes non-whitelisted ScreenConnect instances |
| [⛔Force Remove Adobe CC](docs/scripts/Force-Remove-Adobe-CC.md) | 6-phase Adobe CC removal |
| [⛔Force Remove Dropbox](docs/scripts/Force-Remove-Dropbox.md) | Removes Dropbox with escalating force |
| [⛔Remove All RATs](docs/scripts/Remove-All-RATs.md) | Detects and removes 70+ remote access tools |

### Utility Scripts (⚙️ 🔔)

| Script | Description |
|--------|-------------|
| [🔔Technician Alert Monitor](docs/scripts/Technician-Alert-Monitor.md) | Toast notifications for tech alerts |
| [⚙️Universal Disk Cleaner](docs/scripts/Disk-Cleaner.md) | Cleans temporary files |
| [⚙️COOLForge Cache Sync](docs/scripts/Cache-Sync.md) | Synchronises registry cache |
| [⚙️Cleanup VoyagerPACS Studies](docs/scripts/VoyagerPACS-Cleanup.md) | Cleans up PACS imaging studies |

---

## Versioning

Format: `YYYY.MM.DD.N` (e.g. `2026.03.14.01`)

---

## License

AGPL-3.0 with commercial exception — Free for MSP end-users. Platform vendors require a commercial licence.

See [LICENSE](LICENSE) for details.

---

## Support

**Repository:** [github.com/coolnetworks/COOLForge](https://github.com/coolnetworks/COOLForge)
