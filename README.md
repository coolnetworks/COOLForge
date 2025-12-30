# COOLForge_Lib - Level.io PowerShell Automation Library

**Version:** 2025.12.30.01

A standardized PowerShell module for Level.io RMM automation scripts.

**Copyright:** [COOLNETWORKS](https://coolnetworks.au)
**Repository:** [github.com/coolnetworks/COOLForge](https://github.com/coolnetworks/COOLForge)

---

## Terminology

| Term | Description |
|------|-------------|
| **Module** | `COOLForge-Common.psm1` — The PowerShell module containing all shared functions. Auto-downloaded to endpoints. |
| **Script** | A `.ps1` file in `scripts/` that performs a specific task (e.g., remove AnyDesk, fix services). |
| **Launcher** | A `.ps1` file in `launchers/` that downloads and runs a script from GitHub. Deploy these to Level.io. |
| **Template** | Starter files in `templates/` for creating new scripts or launchers. |
| **Custom Field** | Level.io variables (e.g., `cf_CoolForge_msp_scratch_folder`) that configure script behavior. |

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
- **Script Launcher** — Manage scripts in Git, deploy once to Level.io, updates happen automatically

### Module Functions (14 total)

The `COOLForge-Common.psm1` module exports these functions:

| Category | Function | Description |
|----------|----------|-------------|
| **Initialization** | `Initialize-LevelScript` | Initialize script, check tags, create lockfile |
| | `Invoke-LevelScript` | Execute script block with error handling |
| | `Complete-LevelScript` | End script with custom exit code/message |
| | `Remove-LevelLockFile` | Manually remove lockfile |
| **Logging** | `Write-LevelLog` | Timestamped log output with severity levels |
| **System** | `Test-LevelAdmin` | Check if running as administrator |
| | `Get-LevelDeviceInfo` | Get device hostname, OS, username, etc. |
| **API** | `Invoke-LevelApiCall` | Make authenticated REST API calls |
| | `Get-LevelGroups` | Retrieve all Level.io groups |
| | `Get-LevelDevices` | Retrieve devices (optionally by group) |
| | `Find-LevelDevice` | Search for device by hostname |
| **Network** | `Send-LevelWakeOnLan` | Send WOL magic packet to MAC address |
| **Text** | `Repair-LevelEmoji` | Fix corrupted UTF-8 emojis |
| | `Get-LevelUrlEncoded` | URL-encode strings with UTF-8 support |

See [Function Reference](docs/FUNCTIONS.md) for detailed documentation.

---

## Documentation

| Document | Description |
|----------|-------------|
| [Why COOLForge?](docs/WHY.md) | **Start here** — Problems COOLForge solves and design philosophy |
| [Function Reference](docs/FUNCTIONS.md) | Complete documentation for all library functions |
| [Script Launcher Guide](docs/LAUNCHER.md) | How to use the launcher to run scripts from GitHub |
| [Private Fork Guide](docs/PRIVATE-FORK.md) | Using COOLForge with a private GitHub repository |
| [Version Pinning](docs/VERSION-PINNING.md) | Pin devices to specific library versions for testing and rollback |
| [Release Workflow](docs/RELEASE-WORKFLOW.md) | Dev vs main releases, testing procedures, and rollback strategies |
| [Emoji Handling](docs/EMOJI-HANDLING.md) | UTF-8 emoji corruption repair |
| [Variables Reference](docs/VARIABLES.md) | Level.io variables and setting automation variables |
| [Folder Structure](docs/FOLDER-STRUCTURE.md) | Script category organization |
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
│   ├── Check/                   # Audits, compliance, health monitoring
│   ├── Configure/               # Settings changes
│   ├── Deploy/                  # Install software, deploy configs
│   ├── Fix/                     # Repair and remediation
│   ├── Maintain/                # Scheduled maintenance
│   ├── Provision/               # New device/user setup
│   ├── Remove/                  # Uninstall, cleanup
│   ├── Report/                  # Generate reports, inventory
│   ├── Secure/                  # Hardening, security policies
│   ├── Update/                  # Patch, upgrade software
│   └── Utility/                 # Miscellaneous tools
├── automations/                 # Multi-step automation workflows (same structure)
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

- **Git-managed scripts** — Edit, review, and track changes using standard Git workflows
- **Deploy once** — Upload the launcher to Level.io once, never touch it again
- **Automatic updates** — Push to GitHub, all devices get the update on next run
- **Rollback capability** — Pin devices to specific versions via custom field
- **Team collaboration** — Multiple admins can contribute via pull requests

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
| `CoolForge_pat` | `ghp_abc123xyz...` | No | GitHub PAT for private repos (admin-only, see [Private Fork Guide](docs/PRIVATE-FORK.md)) |
| `CoolForge_nosleep_duration_min` | `60` | No | Duration in minutes to prevent sleep (default: 60) |

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

Scripts are organized into category folders. See [Folder Structure](docs/FOLDER-STRUCTURE.md) for details.

| Folder | Script | Description |
|--------|--------|-------------|
| Check | `👀Test Show Versions.ps1` | Displays version info for all COOLForge_Lib components |
| Check | `👀Test Variable Output.ps1` | Demonstrates all methods for setting automation variables |
| Check | `👀Check for Unauthorized Remote Access Tools.ps1` | Detects 60+ RATs |
| Remove | `⛔Force Remove Anydesk.ps1` | Removes AnyDesk with escalating force (5 phases) |
| Remove | `⛔Force Remove Non MSP ScreenConnect.ps1` | Removes non-whitelisted ScreenConnect |
| Fix | `🔧Fix Windows 11 Services.ps1` | Restores Windows 11 services to defaults |
| Fix | `🔧Fix Windows 10 Services.ps1` | Restores Windows 10 services to defaults |
| Fix | `🔧Fix Windows 8.1 Services.ps1` | Restores Windows 8.1 services to defaults |
| Fix | `🔧Fix Windows 8 Services.ps1` | Restores Windows 8 services to defaults |
| Fix | `🔧Fix Windows 7 Services.ps1` | Restores Windows 7 services to defaults |
| Fix | `🔧Enable System Restore and Create Restore Point.ps1` | Enables System Restore |
| Fix | `🔧Prevent Sleep.ps1` | Temporarily prevents device from sleeping with auto-restore |
| Utility | `🙏Wake all devices in parent to level.io folder.ps1` | Wakes devices in folder hierarchy |

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

## Using with a Private Fork

You can fork COOLForge to your own repository. For private forks, see [Private Fork Guide](docs/PRIVATE-FORK.md) for authentication options.

**Quick setup:**
1. Fork the repository
2. Keep it public (recommended) or use a GitHub Personal Access Token for private repos
3. Set `CoolForge_ps_module_library_source` to your fork's URL

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
