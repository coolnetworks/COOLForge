# COOLForgeLib - Level.io PowerShell Automation Library

**Version:** 2025.12.29.02

A standardized PowerShell module for Level.io RMM automation scripts.

**Copyright:** [COOLNETWORKS](https://coolnetworks.au)
**Repository:** [github.com/coolnetworks/COOLForge](https://github.com/coolnetworks/COOLForge)

---

## Overview

COOLForgeLib provides a shared set of functions for Level.io automation scripts, eliminating code duplication and ensuring consistent behavior across your script portfolio.

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

## Repository Structure

```
COOLForgeLib/
├── modules/                     # PowerShell modulesn�   +-- COOLForge-CustomFields.psm1  # Level.io custom fields API module
├── scripts/                     # Ready-to-use automation scripts
│   ├── ⛔Force Remove Anydesk.ps1
│   ├── ⛔Force Remove Non MSP ScreenConnect.ps1
│   ├── 👀Check for Unauthorized Remote Access Tools.ps1
│   ├── 👀Test Show Versions.ps1
│   ├── 👀Test Variable Output.ps1
│   ├── 🔧Fix Windows 11 Services.ps1
│   ├── 🔧Fix Windows 10 Services.ps1
│   ├── 🔧Fix Windows 8.1 Services.ps1
│   ├── 🔧Fix Windows 8 Services.ps1
│   └── 🔧Fix Windows 7 Services.ps1
├── launchers/                   # Pre-configured launchers (copy-paste to Level.io)
│   ├── ⛔Force Remove Anydesk.ps1
│   ├── ⛔Force Remove Non MSP ScreenConnect.ps1
│   ├── 👀Check for Unauthorized Remote Access Tools.ps1
│   ├── 👀Test Show Versions.ps1
│   └── 👀Test Variable Output.ps1
├── templates/                   # Templates for creating new scripts
│   ├── Script_Template.ps1      # Template for standalone scripts
│   └── Launcher_Template.ps1    # Base launcher template
├── tools/                       # Development and setup tools
│   ├── Setup-COOLForgeCustomFields.ps1  # Interactive setup wizard
│   ├── Backup-COOLForgeCustomFields.ps1 # Backup/restore custom fields
│   └── Update-MD5SUMS.ps1       # Generates MD5SUMS file
└── testing/                     # Test scripts
    ├── Test_Local.ps1           # Local development testing
    └── Test_From_Level.ps1      # Level.io endpoint testing
```

---

## Quick Start

### Prerequisites

- Level.io agent installed on target devices
- PowerShell 5.1 or later
- Custom fields configured in Level.io (see [Automated Setup](#automated-setup) below)

| Custom Field | Example Value | Required | Description |
|--------------|---------------|----------|-------------|
| `msp_scratch_folder` | `C:\ProgramData\MSP` | **Yes** | Persistent storage folder on endpoints |
| `ps_module_library_source` | `https://raw.githubusercontent.com/coolnetworks/COOLForge/main/modules/COOLForge-Common.psm1` | No | URL to download the library (defaults to official repo if not set) |
| `pin_psmodule_to_version` | `v2025.12.29` | No | Pin scripts to a specific version tag (defaults to latest from main branch) |
| `screenconnect_instance_id` | `abc123def456` | No | Your MSP's ScreenConnect instance ID (for ScreenConnect removal script) |
| `is_screenconnect_server` | `true` | No | Set to "true" on devices hosting ScreenConnect server |

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
5. Set up optional fields (ScreenConnect whitelisting, etc.)

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

## Library Auto-Update

Scripts using the template automatically download and update the library on each run.

**Default URL (used if custom field not set):**
```
https://raw.githubusercontent.com/coolnetworks/COOLForge/main/modules/COOLForge-Common.psm1
```

> **Tip:** Setting the `ps_module_library_source` custom field allows you to:
> - Fork the library and use your own repository
> - Use a private GitHub repository with token authentication
> - Host the library on your own infrastructure

**Behavior:**
- First run: Downloads and installs library
- Subsequent runs: Checks for updates, downloads if newer version available
- Offline: Uses cached local copy

**Output Examples:**
```
[*] Library not found - downloading...
[+] Library updated to v2025.12.27.2

[*] Update available: 2025.12.27.1 -> 2025.12.27.2
[+] Library updated to v2025.12.27.2

[!] Could not check for updates (using local v2025.12.27.2)
```

---

## Version Pinning

By default, scripts and the launcher use the latest code from the `main` branch. You can pin devices to a specific release version using the `pin_psmodule_to_version` custom field.

### When to Use Version Pinning

- **Staged Rollouts** — Test new versions on a subset of devices before fleet-wide deployment
- **Stability** — Keep production devices on a known-good version
- **Rollback** — Quickly revert to a previous version if issues arise

### How It Works

1. Create a custom field `pin_psmodule_to_version` in Level.io
2. Set the value to a release tag (e.g., `v2025.12.29`)
3. Scripts will download from that tag instead of `main`

**URL transformation:**
```
Default (no pinning):
https://raw.githubusercontent.com/coolnetworks/COOLForge/main/modules/COOLForge-Common.psm1

With pin_psmodule_to_version = v2025.12.29:
https://raw.githubusercontent.com/coolnetworks/COOLForge/v2025.12.29/modules/COOLForge-Common.psm1
```

### Output Example

When version pinning is active:
```
[*] Version pinned to: v2025.12.29
[*] Library not found - downloading...
[+] Library updated to v2025.12.29.01
```

### Removing the Pin

To return to the latest version:
- Clear the `pin_psmodule_to_version` custom field value, or
- Delete the custom field from the device/group

---

## Script Launcher

The Script Launcher lets you run any script from your GitHub repository **without deploying individual scripts to Level.io**. Deploy the launcher once, then run any script by simply changing a custom field value.

### Why Use the Launcher?

**Traditional approach:** Deploy each script individually to Level.io. When you update a script, you must redeploy it.

**Launcher approach:** Deploy a launcher once. Your scripts live in GitHub. Update GitHub = all endpoints get the update automatically.

### Benefits

- **Single Deployment** — One script in Level.io, unlimited scripts in GitHub
- **Automatic Updates** — Push to GitHub, endpoints get the new version on next run
- **No Redeployment** — Change which script runs by updating a custom field
- **Centralized Management** — All scripts in version control
- **Backup Safety** — Corrupt downloads automatically restore from working backup

### Step-by-Step Setup

#### Step 1: Create Custom Fields in Level.io

Go to **Settings → Custom Fields** and create these fields:

| Field Name | Type | Value | Required |
|------------|------|-------|----------|
| `msp_scratch_folder` | Text | `C:\ProgramData\MSP` | **Yes** |
| `ps_module_library_source` | Text | `https://raw.githubusercontent.com/...` | No (defaults to official repo) |

> **Note:** The `ps_module_library_source` field is optional - if not set, scripts use the official COOLForgeLib repository. Set this field only if you're using a fork or private repository.

#### Step 2: Create Scripts in Level.io

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

#### Using Custom Fields Instead

If you want to change scripts without redeploying, use a custom field:

```powershell
$ScriptToRun = "{{cf_script_to_run}}"
```

Then set `script_to_run` custom field on devices/groups to control which script runs.

### Available Scripts

Scripts in the `scripts/` folder are ready to use:

| Script | Description |
|--------|-------------|
| `👀Test Show Versions.ps1` | Displays version info for all COOLForgeLib components |
| `👀Test Variable Output.ps1` | Demonstrates all methods for setting automation variables |
| `⛔Force Remove Anydesk.ps1` | Removes AnyDesk with escalating force (5 phases) |
| `⛔Force Remove Non MSP ScreenConnect.ps1` | Removes ScreenConnect instances not matching your MSP's instance ID |
| `👀Check for Unauthorized Remote Access Tools.ps1` | Detects 60+ RATs (TeamViewer, AnyDesk, etc.) |
| `🔧Fix Windows 11 Services.ps1` | Restores Windows 11 services to default startup types |
| `🔧Fix Windows 10 Services.ps1` | Restores Windows 10 services to default startup types |
| `🔧Fix Windows 8.1 Services.ps1` | Restores Windows 8.1 services to default startup types |
| `🔧Fix Windows 8 Services.ps1` | Restores Windows 8 services to default startup types |
| `🔧Fix Windows 7 Services.ps1` | Restores Windows 7 services to default startup types |

### How It Works

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

### Variables Passed to Scripts

The launcher automatically passes these variables to downloaded scripts:

| Variable | Source | Description |
|----------|--------|-------------|
| `$MspScratchFolder` | `{{cf_msp_scratch_folder}}` | Persistent storage folder |
| `$LibraryUrl` | `{{cf_ps_module_library_source}}` | Library download URL |
| `$DeviceHostname` | `{{level_device_hostname}}` | Device hostname |
| `$DeviceTags` | `{{level_tag_names}}` | Comma-separated device tags |

**Adding more variables:** Edit `templates/Launcher_Template.ps1` to pass additional custom fields to your scripts.

### Writing Scripts for the Launcher

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

### Caching and Updates

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

## Function Reference

### Initialize-LevelScript

Initializes the script environment, checks blocking tags, and creates a lockfile.

```powershell
$Init = Initialize-LevelScript -ScriptName "MyScript" `
                               -MspScratchFolder "{{cf_msp_scratch_folder}}" `
                               -DeviceHostname "{{level_device_hostname}}" `
                               -DeviceTags "{{level_tag_names}}"
```

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-ScriptName` | String | Yes | — | Unique identifier for the script (used for lockfile) |
| `-MspScratchFolder` | String | Yes | — | Base path for MSP files |
| `-DeviceHostname` | String | No | `$env:COMPUTERNAME` | Device hostname for logging |
| `-DeviceTags` | String | No | `""` | Comma-separated list of device tags |
| `-BlockingTags` | String[] | No | `@("❌")` | Tags that block script execution |
| `-SkipTagCheck` | Switch | No | `$false` | Bypass tag gate check |
| `-SkipLockFile` | Switch | No | `$false` | Don't create a lockfile |

**Return Values:**

```powershell
# Success
@{ Success = $true; Reason = "Initialized" }

# Blocked by tag
@{ Success = $false; Reason = "TagBlocked"; Tag = "BlockedTag" }

# Already running
@{ Success = $false; Reason = "AlreadyRunning"; PID = 1234 }
```

---

### Write-LevelLog

Outputs a timestamped, formatted log message.

```powershell
Write-LevelLog "This is a message"
Write-LevelLog "Something went wrong" -Level "ERROR"
```

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-Message` | String | Yes | — | The message to log |
| `-Level` | String | No | `"INFO"` | Severity level |

**Log Levels:**

| Level | Prefix | Use Case |
|-------|--------|----------|
| `INFO` | `[*]` | General information |
| `WARN` | `[!]` | Warnings (non-fatal issues) |
| `ERROR` | `[X]` | Errors and failures |
| `SUCCESS` | `[+]` | Successful completions |
| `SKIP` | `[-]` | Skipped operations |
| `DEBUG` | `[D]` | Debug/verbose output |

**Output Example:**

```
2025-12-27 14:32:01 [*] Starting cleanup process
2025-12-27 14:32:02 [+] Removed 15 temporary files
2025-12-27 14:32:03 [!] Could not access C:\Locked\File.tmp
2025-12-27 14:32:04 [X] Failed to clear browser cache
```

---

### Invoke-LevelScript

Wraps your main script logic with automatic error handling and cleanup.

```powershell
Invoke-LevelScript -ScriptBlock {
    Write-LevelLog "Doing work..."
    # Your code here
}
```

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-ScriptBlock` | ScriptBlock | Yes | — | The code to execute |
| `-NoCleanup` | Switch | No | `$false` | Don't remove lockfile on completion |

**Behavior:**

- Executes the script block
- On success: logs completion, removes lockfile, exits with code `0`
- On error: logs the exception, removes lockfile, exits with code `1`

---

### Complete-LevelScript

Manually complete the script with a custom exit code and message.

```powershell
Complete-LevelScript -ExitCode 0 -Message "All files processed"
Complete-LevelScript -ExitCode 1 -Message "Database connection failed"
```

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-ExitCode` | Int | No | `0` | Exit code (0 = success, 1 = alert/failure) |
| `-Message` | String | No | `"Script completed"` | Final log message |

---

### Remove-LevelLockFile

Manually remove the current script's lockfile.

```powershell
Remove-LevelLockFile
```

> **Note:** Called automatically by `Invoke-LevelScript` and `Complete-LevelScript`.

---

### Test-LevelAdmin

Checks if the script is running with administrator privileges.

```powershell
if (-not (Test-LevelAdmin)) {
    Write-LevelLog "This script requires admin rights!" -Level "ERROR"
    Complete-LevelScript -ExitCode 1 -Message "Admin required"
}
```

**Returns:** `$true` if running as administrator, `$false` otherwise.

---

### Get-LevelDeviceInfo

Returns a hashtable of common device information.

```powershell
$Info = Get-LevelDeviceInfo
Write-LevelLog "Running on: $($Info.OS) ($($Info.OSVersion))"
```

**Returns:**

```powershell
@{
    Hostname   = "WORKSTATION01"
    Username   = "SYSTEM"
    Domain     = "COOLNETWORKS"
    OS         = "Microsoft Windows 11 Pro"
    OSVersion  = "10.0.22631"
    IsAdmin    = $true
    PowerShell = "5.1.22621.2506"
    ScriptPID  = 4832
}
```

---

### Invoke-LevelApiCall

Makes authenticated REST API calls with standardized error handling.

```powershell
$Result = Invoke-LevelApiCall -Uri "https://api.example.com/endpoint" `
                              -ApiKey "{{cf_apikey}}" `
                              -Method "GET"

if ($Result.Success) {
    $Data = $Result.Data
} else {
    Write-LevelLog "API Error: $($Result.Error)" -Level "ERROR"
}
```

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-Uri` | String | Yes | — | Full API endpoint URL |
| `-ApiKey` | String | Yes | — | Bearer token for authentication |
| `-Method` | String | No | `"GET"` | HTTP method (GET, POST, PUT, DELETE, PATCH) |
| `-Body` | Hashtable | No | — | Request body (converted to JSON) |
| `-TimeoutSec` | Int | No | `30` | Request timeout in seconds |

**Returns:**

```powershell
# Success
@{ Success = $true; Data = <API Response Object> }

# Failure
@{ Success = $false; Error = "Connection timed out" }
```

**POST Example:**

```powershell
$Result = Invoke-LevelApiCall -Uri "https://api.example.com/tickets" `
                              -ApiKey "{{cf_apikey}}" `
                              -Method "POST" `
                              -Body @{
                                  title = "Automated Alert"
                                  description = "Disk space low"
                                  priority = "high"
                              }
```

---

### Repair-LevelEmoji

Repairs corrupted UTF-8 emojis in strings. Level.io and other deployment systems may corrupt UTF-8 emojis when deploying scripts. This function detects common corruption patterns and fixes them.

```powershell
$ScriptName = Repair-LevelEmoji -Text $ScriptName
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Text` | String | Yes | The text string that may contain corrupted emojis |

**Supported Emojis:**

| Emoji | Name | Unicode |
|-------|------|---------|
| ⛔ | Stop sign | U+26D4 |
| 👀 | Eyes | U+1F440 |
| 🙏 | Folded hands | U+1F64F |
| 🚨 | Police light | U+1F6A8 |
| 🛑 | Stop sign octagon | U+1F6D1 |
| ✅ | Check mark | U+2705 |
| 🔚 | End arrow | U+1F51A |
| 🆕 | New button | U+1F195 |
| 🔧 | Wrench | U+1F527 |

**Example:**

```powershell
# The launcher uses this automatically to fix corrupted script names
$ScriptToRun = Repair-LevelEmoji -Text $ScriptToRun
```

> **Note:** This function is called automatically by the Script Launcher after loading the library. You typically don't need to call it directly unless working with emoji-containing strings in your own scripts.

---

### Get-LevelUrlEncoded

URL-encodes a string with proper UTF-8 handling for emojis. Unlike `[System.Uri]::EscapeDataString()`, this function correctly encodes UTF-8 bytes for use in URLs.

```powershell
$EncodedName = Get-LevelUrlEncoded -Text "👀Test Script.ps1"
# Returns: %F0%9F%91%80Test%20Script.ps1
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Text` | String | Yes | The text string to URL-encode |

**Returns:** URL-encoded string safe for use in HTTP requests.

**Example:**

```powershell
# Build a URL with an emoji-containing filename
$ScriptUrl = "$BaseUrl/$(Get-LevelUrlEncoded $ScriptToRun)"
```

> **Note:** This function is called automatically by the Script Launcher when downloading scripts. You typically don't need to call it directly unless building custom URLs.

---

## Setting Automation Variables

Level.io allows scripts to set variables during execution that persist and can be used by subsequent automation steps. This is useful for passing data between scripts in a workflow.

### Syntax

Output variables using this format on their own line:

```
{{variable_name=value}}
```

Use `Write-Output` (not `Write-Host`) to set variables:

```powershell
# Set a simple string variable
$Hostname = $env:COMPUTERNAME
Write-Output "{{device_hostname=$Hostname}}"

# Set a numeric value
$DiskFreeGB = [math]::Round((Get-PSDrive C).Free / 1GB, 2)
Write-Output "{{disk_free_gb=$DiskFreeGB}}"

# Set a boolean
$IsCompliant = "true"
Write-Output "{{is_compliant=$IsCompliant}}"

# Set JSON data
$Info = @{ hostname = $env:COMPUTERNAME; timestamp = (Get-Date).ToString("o") } | ConvertTo-Json -Compress
Write-Output "{{device_info=$Info}}"
```

### Using Variables in Subsequent Steps

After a script sets a variable, it's available in later automation steps as:

```
{{variable_name}}
```

### Test Script

Use `👀Test Variable Output.ps1` to test all variable output methods. It demonstrates:

- Simple strings and numbers
- Boolean values
- Date/time formats (ISO 8601, Unix timestamp)
- System information (IP, OS, disk space, RAM)
- JSON-formatted data
- Special characters and paths
- Empty/null handling
- Status/result patterns

**Documentation:** [Level.io - Set Variables Directly from Scripts](https://docs.level.io/en/articles/11509659-set-variables-directly-from-scripts)

---

## Emoji Handling

### The Problem

When Level.io deploys PowerShell scripts, it may corrupt UTF-8 encoded emojis. For example, the stop sign emoji `⛔` (UTF-8 bytes: `E2 9B 94`) can become corrupted into different character sequences depending on how the script is processed.

### The Solution

COOLForgeLib provides two functions to handle this:

1. **`Repair-LevelEmoji`** — Detects known corruption patterns and repairs them to the correct Unicode characters
2. **`Get-LevelUrlEncoded`** — Properly URL-encodes strings with UTF-8 emojis for GitHub downloads

### How It Works

The Script Launcher automatically:
1. Loads the library from GitHub
2. Calls `Repair-LevelEmoji` on the script name to fix any corruption
3. Uses `Get-LevelUrlEncoded` to build the correct download URL
4. Downloads and executes the script

This means you can use emojis in script names without worrying about encoding issues.

### Adding New Emojis

To add support for additional emojis, update the `$EmojiRepairs` hashtable in the `Repair-LevelEmoji` function in `COOLForge-Common.psm1`:

```powershell
# Get UTF-8 bytes: printf '🔥' | xxd -p  # Returns f09f94a5
# Add to $EmojiRepairs hashtable:
"$([char]0xF0)$([char]0x9F)$([char]0x94)$([char]0xA5)" = [char]::ConvertFromUtf32(0x1F525)
```

---

## Level.io Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `{{cf_msp_scratch_folder}}` | Base path for MSP files | `C:\ProgramData\MSP` |
| `{{cf_ps_module_library_source}}` | URL to download library (scripts URL derived automatically) | `https://raw.githubusercontent.com/.../COOLForge-Common.psm1` |
| `{{cf_apikey}}` | API key custom field | `sk-xxxxx` |
| `{{level_device_hostname}}` | Device hostname | `WORKSTATION01` |
| `{{level_tag_names}}` | Comma-separated device tags | `Production, Windows 11` |

---

## Architecture

```
{{cf_msp_scratch_folder}}\
├── Libraries\
│   └── COOLForge-Common.psm1      # Shared module (auto-downloaded)
├── Scripts\
│   ├── Force Remove Anydesk.ps1 # Cached scripts (auto-downloaded by launcher)
│   └── Other Script.ps1
└── lockfiles\
    ├── ScriptA.lock             # Active lockfiles
    └── ScriptB.lock
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

## Version History

| Version | Date | Component | Changes |
|---------|------|-----------|---------|
| 2025.12.29.02 | 2025-12-29 | All | Add version pinning via `pin_psmodule_to_version` custom field |
| 2025.12.29.01 | 2025-12-29 | All | Add Test Variable Output script, fix launcher script names, add automation variable documentation |
| 2025.12.27.22 | 2025-12-27 | All | Version sync release - Library v20, Launchers v10, README v22 |
| 2025.12.27.20 | 2025-12-27 | Library | Add alternate emoji corruption patterns (👀→≡ƒæÇ, ⛔→Γ¢ö, etc.) for Level.io encoding |
| 2025.12.27.10 | 2025-12-27 | Launcher | Version sync with library emoji fixes |
| 2025.12.27.21 | 2025-12-27 | README | Documentation update - comprehensive function reference, emoji handling guide |
| 2025.12.27.15 | 2025-12-27 | Library | Add more emojis to Repair-LevelEmoji (🙏 🚨 🛑 ✅ 🔚 🆕) |
| 2025.12.27.14 | 2025-12-27 | Library | Add Repair-LevelEmoji and Get-LevelUrlEncoded functions for emoji support |
| 2025.12.27.08 | 2025-12-27 | Launcher | Use library functions for emoji repair and URL encoding |
| 2025.12.27.20 | 2025-12-27 | All | Full release - all scripts use default URL fallback |
| 2025.12.27.13 | 2025-12-27 | Library | Add ScreenConnect removal script with MSP whitelisting |
| 2025.12.27.13 | 2025-12-27 | Library | Output library version to console when module loads |
| 2025.12.27.07 | 2025-12-27 | Launcher | Add Script Launcher for GitHub-based script deployment |
| 2025.12.27.11 | 2025-12-27 | Library | Add informative message when device is blocked by tag |
| 2025.12.27.07 | 2025-12-27 | Library | Use New-Module for proper module context with execution policy bypass |
| 2025.12.27.05 | 2025-12-27 | Library | Fix encoding, use ASCII prefixes, empty default BlockingTags |
| 2025.12.27.04 | 2025-12-27 | Library | Library URL now configurable via custom field |
| 2025.12.27.02 | 2025-12-27 | Library | First public release - GitHub auto-update |

---

## License

MIT License with Attribution - Free to use with attribution to COOLNETWORKS.

See [LICENSE](LICENSE) for details.

---

## Support

**Website:** [coolnetworks.au](https://coolnetworks.au)
**Repository:** [github.com/coolnetworks/COOLForge](https://github.com/coolnetworks/COOLForge)
