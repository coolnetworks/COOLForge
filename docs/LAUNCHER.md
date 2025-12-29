# Script Launcher Guide

The Script Launcher lets you run any script from your GitHub repository **without deploying individual scripts to Level.io**. Deploy the launcher once, then run any script by simply changing which launcher you use.

---

## Table of Contents

- [Why Use the Launcher?](#why-use-the-launcher)
- [Benefits](#benefits)
- [Step-by-Step Setup](#step-by-step-setup)
- [Available Scripts](#available-scripts)
- [How It Works](#how-it-works)
- [Variables Passed to Scripts](#variables-passed-to-scripts)
- [Writing Scripts for the Launcher](#writing-scripts-for-the-launcher)
- [Caching and Updates](#caching-and-updates)

---

## Why Use the Launcher?

**Traditional approach:** Deploy each script individually to Level.io. When you update a script, you must redeploy it.

**Launcher approach:** Deploy a launcher once. Your scripts live in GitHub. Update GitHub = all endpoints get the update automatically.

---

## Benefits

- **Single Deployment** — One script in Level.io, unlimited scripts in GitHub
- **Automatic Updates** — Push to GitHub, endpoints get the new version on next run
- **No Redeployment** — Change which script runs by using a different launcher
- **Centralized Management** — All scripts in version control
- **Backup Safety** — Corrupt downloads automatically restore from working backup

---

## Step-by-Step Setup

### Step 1: Create Custom Fields in Level.io

Go to **Settings → Custom Fields** and create these fields:

| Field Name | Type | Value | Required |
|------------|------|-------|----------|
| `CoolForge_msp_scratch_folder` | Text | `C:\ProgramData\MSP` | **Yes** |
| `CoolForge_ps_module_library_source` | Text | `https://raw.githubusercontent.com/...` | No (defaults to official repo) |

> **Note:** The `CoolForge_ps_module_library_source` field is optional - if not set, scripts use the official COOLForge_Lib repository. Set this field only if you're using a fork or private repository.

### Step 2: Create Scripts in Level.io

**Option A: Use a pre-configured launcher**
1. Copy the contents of a file from `launchers/` (e.g., `launchers/👀Test Show Versions.ps1`)
2. Paste into a new Level.io script - it's ready to use!

**Option B: Use the template for a new script**
1. In Level.io, create a new PowerShell script
2. Paste the contents of `templates/Launcher_Template.ps1` into it
3. **Change line 4** at the very top of the script to your script name:

```powershell
# ============================================================
# SCRIPT TO RUN - CHANGE THIS VALUE
# ============================================================
$ScriptToRun = "👀Test Show Versions.ps1"   # <-- Change this to your script
# ============================================================
```

4. Save and deploy

**Example flow:**
```
Level.io runs launcher
         ↓
Launcher sees: $ScriptToRun = "👀Test Show Versions.ps1"
         ↓
Downloads: scripts/👀Test Show Versions.ps1 from GitHub
         ↓
Executes with all Level.io variables
```

### Using Custom Fields Instead

If you want to change scripts without redeploying, use a custom field:

```powershell
$ScriptToRun = "{{cf_script_to_run}}"
```

Then set `script_to_run` custom field on devices/groups to control which script runs.

---

## Available Scripts

Scripts in the `scripts/` folder are ready to use:

| Script | Description |
|--------|-------------|
| `👀Test Show Versions.ps1` | Displays version info for all COOLForge_Lib components |
| `👀Test Variable Output.ps1` | Demonstrates all methods for setting automation variables |
| `⛔Force Remove Anydesk.ps1` | Removes AnyDesk with escalating force (5 phases) |
| `⛔Force Remove Non MSP ScreenConnect.ps1` | Removes ScreenConnect instances not matching your MSP's instance ID |
| `👀Check for Unauthorized Remote Access Tools.ps1` | Detects 60+ RATs (TeamViewer, AnyDesk, etc.) |
| `🔧Fix Windows 11 Services.ps1` | Restores Windows 11 services to default startup types |
| `🔧Fix Windows 10 Services.ps1` | Restores Windows 10 services to default startup types |
| `🔧Fix Windows 8.1 Services.ps1` | Restores Windows 8.1 services to default startup types |
| `🔧Fix Windows 8 Services.ps1` | Restores Windows 8 services to default startup types |
| `🔧Fix Windows 7 Services.ps1` | Restores Windows 7 services to default startup types |
| `🔧Enable System Restore and Create Restore Point.ps1` | Enables System Restore and creates a restore point |
| `🙏Wake all devices in parent to level.io folder.ps1` | Wakes devices in parent folder hierarchy |

---

## How It Works

```
Level.io                          GitHub Repository
    │                                    │
    ▼                                    │
┌─────────────────┐                      │
│ Launcher        │ ◄────────────────────┤ scripts/
│   .ps1          │   downloads          │  ├── 👀Test Show Versions.ps1
└────────┬────────┘                      │  ├── ⛔Force Remove Anydesk.ps1
         │                               │  └── 👀Check for Unauthorized...
         │                               │
         │ passes variables              │
         ▼                               │
┌─────────────────┐                      │
│ Downloaded      │ ◄────────────────────┤ COOLForge-Common.psm1
│ Script          │   library loaded     │
└────────┬────────┘                      │
         │                               │
         ▼                               │
   Executes with full                    │
   library functions                     │
```

1. **Launcher runs** — Downloads/updates the library from GitHub
2. **Script downloaded** — Fetches the script specified in `$ScriptToRun`
3. **Variables passed** — All Level.io variables are injected into the script's scope
4. **Script executes** — Has full access to library functions (`Write-LevelLog`, etc.)
5. **Exit code returned** — Script's exit code is passed back to Level.io

---

## Variables Passed to Scripts

The launcher automatically passes these variables to downloaded scripts:

| Variable | Source | Description |
|----------|--------|-------------|
| `$MspScratchFolder` | `{{cf_CoolForge_msp_scratch_folder}}` | Persistent storage folder |
| `$LibraryUrl` | `{{cf_CoolForge_ps_module_library_source}}` | Library download URL |
| `$DeviceHostname` | `{{level_device_hostname}}` | Device hostname |
| `$DeviceTags` | `{{level_tag_names}}` | Comma-separated device tags |

**Adding more variables:** Edit `templates/Launcher_Template.ps1` to pass additional custom fields to your scripts.

---

## Writing Scripts for the Launcher

Scripts in the `scripts/` folder should follow this pattern:

```powershell
# My Script
# Version: 2025.12.27.01
# Target: Level.io (via Script Launcher)

# Variables are already defined by the launcher:
# - $MspScratchFolder
# - $LibraryUrl
# - $DeviceHostname
# - $DeviceTags

$Init = Initialize-LevelScript -ScriptName "MyScript" `
                               -MspScratchFolder $MspScratchFolder `
                               -DeviceHostname $DeviceHostname `
                               -DeviceTags $DeviceTags `
                               -BlockingTags @("❌")

if (-not $Init.Success) { exit 0 }

Invoke-LevelScript -ScriptBlock {
    Write-LevelLog "Hello from my script!"
    # Your code here...
}
```

**Key differences from standalone scripts:**
- No library download code needed (launcher handles it)
- Use `$DeviceHostname` instead of `"{{level_device_hostname}}"`
- Use `$DeviceTags` instead of `"{{level_tag_names}}"`
- Library functions are already available

---

## Caching and Updates

Scripts are cached locally on endpoints:

```
C:\ProgramData\MSP\
├── Libraries\
│   └── COOLForge-Common.psm1      # Cached library
└── Scripts\
    ├── 👀Test Show Versions.ps1   # Cached scripts
    └── ⛔Force Remove Anydesk.ps1
```

**Update behavior:**
- Launcher checks GitHub for newer versions on each run
- If newer version exists, downloads and replaces cached copy
- If download fails, uses cached version
- Corrupt downloads are detected and rolled back to backup

---

## See Also

- [Main README](../README.md)
- [Function Reference](FUNCTIONS.md)
- [Version Pinning](VERSION-PINNING.md)
