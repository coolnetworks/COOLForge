# COOLForge_Lib - Level.io PowerShell Automation Library

**Version:** 2025.12.29.02

A standardized PowerShell module for Level.io RMM automation scripts.

**Copyright:** [COOLNETWORKS](https://coolnetworks.au)
**Repository:** [github.com/coolnetworks/COOLForge](https://github.com/coolnetworks/COOLForge)

---

## Overview

COOLForge_Lib provides a shared set of functions for Level.io automation scripts, eliminating code duplication and ensuring consistent behavior across your script portfolio.

### Key Features

- **Tag Gate System** — Skip execution on devices with blocking tags
- **Lockfile Management** — Prevent concurrent script execution with PID-based lockfiles
- **Standardized Logging** — Timestamped output with severity levels
- **Error Handling** — Wrapped execution with automatic cleanup
- **API Helper** — REST API calls with bearer token authentication
- **Device Info** — Quick access to common system properties
- **Auto-Update** — Scripts automatically download the latest library from GitHub
- **Emoji Encoding Repair** — Fixes UTF-8 emoji corruption from deployment systems
- **Script Launcher** — Run scripts from GitHub without redeploying to Level.io

---

## Documentation

| Document | Description |
|----------|-------------|
| [Function Reference](docs/FUNCTIONS.md) | Complete documentation for all library functions |
| [Script Launcher Guide](docs/LAUNCHER.md) | How to use the launcher to run scripts from GitHub |
| [Version Pinning](docs/VERSION-PINNING.md) | Pin devices to specific library versions |
| [Emoji Handling](docs/EMOJI-HANDLING.md) | UTF-8 emoji corruption repair |
| [Variables Reference](docs/VARIABLES.md) | Level.io variables and setting automation variables |
| [Changelog](CHANGELOG.md) | Version history and changes |
| [Release Process](RELEASING.md) | How to create new releases |

---

## Repository Structure

```
COOLForge/
├── modules/                     # PowerShell modules
│   ├── COOLForge-Common.psm1    # Main library module
│   └── COOLForge-CustomFields.psm1  # Level.io custom fields API module
├── scripts/                     # Ready-to-use automation scripts
├── launchers/                   # Pre-configured launchers (copy-paste to Level.io)
├── templates/                   # Templates for creating new scripts
├── tools/                       # Development and setup tools
├── testing/                     # Test scripts
└── docs/                        # Documentation
```

---

## Using Scripts in Level.io

**Scripts are deployed via launchers, not directly.** The launcher handles downloading and auto-updating the actual script from GitHub.

### Step-by-Step

1. **Find the script** you want in the [Available Scripts](#available-scripts) table below
2. **Open the matching launcher** from the `launchers/` folder (same filename)
3. **Copy the entire launcher code**
4. **Create a new script in Level.io:**
   - Go to Level.io → Automations → Scripts → New Script
   - **Name:** Use the script name **without** `.ps1` (e.g., `👀Test Show Versions`)
   - **Language:** PowerShell
   - **Paste** the launcher code
   - Save
5. **Run the script** on a device — the launcher will download and execute the latest version from GitHub

### How It Works

```
Level.io runs launcher → Launcher downloads script from GitHub → Script executes
```

- **First run:** Downloads the library and script, caches locally
- **Subsequent runs:** Checks for updates, downloads if newer version exists
- **Offline:** Uses cached local copies

### Benefits

- **No redeployment needed** — update scripts in GitHub, devices get updates automatically
- **Version control** — all script changes tracked in Git
- **Rollback capability** — pin devices to specific versions if needed

---

## Quick Start

### Prerequisites

- Level.io agent installed on target devices
- PowerShell 5.1 or later
- Custom fields configured in Level.io (see [Automated Setup](#automated-setup) below)

| Custom Field | Example Value | Required | Description |
|--------------|---------------|----------|-------------|
| `CoolForge_msp_scratch_folder` | `C:\ProgramData\MSP` | **Yes** | Persistent storage folder on endpoints |
| `CoolForge_ps_module_library_source` | *(leave empty)* | No | URL to download the library (defaults to official repo) |
| `CoolForge_pin_psmodule_to_version` | `v2025.12.29` | No | Pin scripts to a specific version tag |

### Automated Setup

Use the setup wizard to automatically create and configure custom fields:

```powershell
# Download and run the setup script
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/coolnetworks/COOLForge/main/tools/Setup-COOLForgeCustomFields.ps1" -OutFile "Setup-COOLForgeCustomFields.ps1"
.\Setup-COOLForgeCustomFields.ps1
```

The wizard will:
1. Connect to Level.io using your API key
2. Check which custom fields already exist
3. Create any missing required fields
4. Optionally configure version pinning

> **Note:** Get your API key from [Level.io Security Settings](https://app.level.io/security)

### Creating a New Script

1. Copy `templates/Script_Template.ps1`
2. Rename to your script name
3. Change `"YourScriptName"` to a unique identifier
4. Add your code in the `Invoke-LevelScript` block

```powershell
$Init = Initialize-LevelScript -ScriptName "MyScript" `
                               -MspScratchFolder $MspScratchFolder `
                               -DeviceHostname "{{level_device_hostname}}" `
                               -DeviceTags "{{level_tag_names}}" `
                               -BlockingTags @("❌")

if (-not $Init.Success) { exit 0 }

Invoke-LevelScript -ScriptBlock {
    Write-LevelLog "Hello from MyScript!"
    # Your code here...
}
```

---

## Available Scripts

| Script | Description |
|--------|-------------|
| `👀Test Show Versions.ps1` | Displays version info for all COOLForge_Lib components |
| `👀Test Variable Output.ps1` | Demonstrates all methods for setting automation variables |
| `👀Check for Unauthorized Remote Access Tools.ps1` | Detects 60+ RATs |
| `⛔Force Remove Anydesk.ps1` | Removes AnyDesk with escalating force (5 phases) |
| `⛔Force Remove Non MSP ScreenConnect.ps1` | Removes non-whitelisted ScreenConnect |
| `🔧Fix Windows 11 Services.ps1` | Restores Windows 11 services to defaults |
| `🔧Fix Windows 10 Services.ps1` | Restores Windows 10 services to defaults |
| `🔧Fix Windows 8.1 Services.ps1` | Restores Windows 8.1 services to defaults |
| `🔧Fix Windows 8 Services.ps1` | Restores Windows 8 services to defaults |
| `🔧Fix Windows 7 Services.ps1` | Restores Windows 7 services to defaults |
| `🔧Enable System Restore and Create Restore Point.ps1` | Enables System Restore |
| `🙏Wake all devices in parent to level.io folder.ps1` | Wakes devices in folder hierarchy |

---

## Library Auto-Update

Scripts using the template automatically download and update the library on each run.

**Default URL:**
```
https://raw.githubusercontent.com/coolnetworks/COOLForge/main/modules/COOLForge-Common.psm1
```

**Behavior:**
- First run: Downloads and installs library
- Subsequent runs: Checks for updates, downloads if newer version available
- Offline: Uses cached local copy

---

## Architecture

```
{{cf_CoolForge_msp_scratch_folder}}\
├── Libraries\
│   └── COOLForge-Common.psm1      # Shared module (auto-downloaded)
├── Scripts\
│   └── *.ps1                      # Cached scripts (auto-downloaded by launcher)
└── lockfiles\
    └── *.lock                     # Active lockfiles
```

---

## Testing

### Test on Level.io Endpoint

Deploy `testing/Test_From_Level.ps1` to a Level.io endpoint to verify the library works correctly.

### Local Development Testing

Run `testing/Test_Local.ps1` locally to test changes before committing.

---

## Versioning

Format: `YYYY.MM.DD.N`

- `YYYY` = Year
- `MM` = Month
- `DD` = Day
- `N` = Release number for that day

---

## License

MIT License with Attribution - Free to use with attribution to COOLNETWORKS.

See [LICENSE](LICENSE) for details.

---

## TODO

Future improvements and feature requests:

- [ ] **Request `level_current_scriptname` variable from Level.io** — Would allow a single universal launcher that auto-detects which script to run based on its name in Level.io, eliminating the need for per-script `$ScriptToRun` configuration

---

## Support

**Website:** [coolnetworks.au](https://coolnetworks.au)
**Repository:** [github.com/coolnetworks/COOLForge](https://github.com/coolnetworks/COOLForge)
