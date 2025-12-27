# LevelLib - Level.io PowerShell Automation Library

**Version:** 2025.12.27.14

A standardized PowerShell module for Level.io RMM automation scripts.

**Copyright:** [COOLNETWORKS](https://coolnetworks.au)
**Repository:** [github.com/coolnetworks/LevelLib](https://github.com/coolnetworks/LevelLib)

---

## Overview

LevelLib provides a shared set of functions for Level.io automation scripts, eliminating code duplication and ensuring consistent behavior across your script portfolio.

### Key Features

- **Tag Gate System** — Skip execution on devices with blocking tags
- **Lockfile Management** — Prevent concurrent script execution with PID-based lockfiles
- **Standardized Logging** — Timestamped output with severity levels
- **Error Handling** — Wrapped execution with automatic cleanup
- **API Helper** — REST API calls with bearer token authentication
- **Device Info** — Quick access to common system properties
- **Auto-Update** — Scripts automatically download the latest library from GitHub

---

## Files

| File | Description |
|------|-------------|
| `LevelIO-Common.psm1` | Core PowerShell module with all shared functions |
| `Template_NewScript.ps1` | Template for creating new Level.io scripts |
| `Script_Launcher.ps1` | Universal launcher that downloads and runs scripts from GitHub |
| `Test_From_Level.ps1` | Test script to verify library on Level.io endpoints |
| `Testing_script.ps1` | Local development test script |
| `scripts/` | Folder containing ready-to-use automation scripts |

---

## Quick Start

### Prerequisites

- Level.io agent installed on target devices
- PowerShell 5.1 or later
- Custom fields configured in Level.io:

| Custom Field | Example Value | Description |
|--------------|---------------|-------------|
| `msp_scratch_folder` | `C:\ProgramData\MSP` | Persistent storage folder on endpoints |
| `ps_module_library_source` | `https://raw.githubusercontent.com/coolnetworks/LevelLib/main/LevelIO-Common.psm1` | URL to download the library |
| `script_repo_base_url` | `https://raw.githubusercontent.com/coolnetworks/LevelLib/main/scripts` | Base URL for scripts folder (used by Script Launcher) |
| `script_to_run` | `Force Remove Anydesk.ps1` | Script filename to execute (used by Script Launcher) |

### Creating a New Script

1. Copy `Template_NewScript.ps1`
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

Scripts using the template automatically download and update the library on each run using the URL configured in the `ps_module_library_source` custom field.

**Default URL:**
```
https://raw.githubusercontent.com/coolnetworks/LevelLib/main/LevelIO-Common.psm1
```

> **Tip:** Using a custom field allows you to:
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

## Script Launcher

The Script Launcher lets you run any script from your GitHub repository **without deploying individual scripts to Level.io**. Deploy the launcher once, then run any script by simply changing a custom field value.

### Why Use the Launcher?

**Traditional approach:** Deploy each script individually to Level.io. When you update a script, you must redeploy it.

**Launcher approach:** Deploy `Script_Launcher.ps1` once. Your scripts live in GitHub. Update GitHub = all endpoints get the update automatically.

### Benefits

- **Single Deployment** — One script in Level.io, unlimited scripts in GitHub
- **Automatic Updates** — Push to GitHub, endpoints get the new version on next run
- **No Redeployment** — Change which script runs by updating a custom field
- **Centralized Management** — All scripts in version control
- **Backup Safety** — Corrupt downloads automatically restore from working backup

### Step-by-Step Setup

#### Step 1: Create Custom Fields in Level.io

Go to **Settings → Custom Fields** and create these fields:

| Field Name | Type | Value |
|------------|------|-------|
| `msp_scratch_folder` | Text | `C:\ProgramData\MSP` |
| `ps_module_library_source` | Text | `https://raw.githubusercontent.com/coolnetworks/LevelLib/main/LevelIO-Common.psm1` |
| `script_repo_base_url` | Text | `https://raw.githubusercontent.com/coolnetworks/LevelLib/main/scripts` |
| `script_to_run` | Text | *(leave empty or set default)* |

> **Note:** If using your own fork, replace `coolnetworks/LevelLib` with your repository path.

#### Step 2: Deploy the Launcher

1. In Level.io, create a new PowerShell script
2. Copy the entire contents of `Script_Launcher.ps1` from this repository
3. Save and deploy to your devices

#### Step 3: Run Scripts from GitHub

**Option A: Set script per-job**

When running the launcher, set the `$ScriptToRun` parameter:
```powershell
$ScriptToRun = "Test Show Versions.ps1"
```

**Option B: Use custom field**

Set `script_to_run` custom field on devices/groups, then in the launcher:
```powershell
$ScriptToRun = "{{cf_script_to_run}}"
```

### Available Scripts

Scripts in the `scripts/` folder are ready to use:

| Script | Description |
|--------|-------------|
| `Test Show Versions.ps1` | Displays version info for all LevelLib components |
| `⛔Force Remove Anydesk.ps1` | Removes AnyDesk with escalating force (5 phases) |

### How It Works

```
Level.io                          GitHub Repository
    │                                    │
    ▼                                    │
┌─────────────────┐                      │
│ Script_Launcher │ ◄────────────────────┤ scripts/
│    .ps1         │   downloads          │  ├── Test Show Versions.ps1
└────────┬────────┘                      │  └── ⛔Force Remove Anydesk.ps1
         │                               │
         │ passes variables              │
         ▼                               │
┌─────────────────┐                      │
│ Downloaded      │ ◄────────────────────┤ LevelIO-Common.psm1
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

**Adding more variables:** Edit `Script_Launcher.ps1` to pass additional custom fields to your scripts.

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
│   └── LevelIO-Common.psm1      # Cached library
└── Scripts\
    ├── Test Show Versions.ps1   # Cached scripts
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

## Level.io Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `{{cf_msp_scratch_folder}}` | Base path for MSP files | `C:\ProgramData\MSP` |
| `{{cf_ps_module_library_source}}` | URL to download library | `https://raw.githubusercontent.com/.../LevelIO-Common.psm1` |
| `{{cf_script_repo_base_url}}` | Base URL for scripts folder | `https://raw.githubusercontent.com/.../scripts` |
| `{{cf_script_to_run}}` | Script filename for launcher | `Force Remove Anydesk.ps1` |
| `{{cf_apikey}}` | API key custom field | `sk-xxxxx` |
| `{{level_device_hostname}}` | Device hostname | `WORKSTATION01` |
| `{{level_tag_names}}` | Comma-separated device tags | `Production, Windows 11` |

---

## Architecture

```
{{cf_msp_scratch_folder}}\
├── Libraries\
│   └── LevelIO-Common.psm1      # Shared module (auto-downloaded)
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

Deploy `Test_From_Level.ps1` to a Level.io endpoint to verify the library works correctly.

### Local Development Testing

Run `Testing_script.ps1` locally to test changes before committing.

---

## Versioning

Format: `YYYY.MM.DD.N`

- `YYYY` = Year
- `MM` = Month
- `DD` = Day
- `N` = Release number for that day

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 2025.12.27.14 | 2025-12-27 | Expanded Script Launcher documentation with step-by-step guide |
| 2025.12.27.13 | 2025-12-27 | Add Script Launcher for GitHub-based script deployment |
| 2025.12.27.12 | 2025-12-27 | Output library version to console when module loads |
| 2025.12.27.11 | 2025-12-27 | Add informative message when device is blocked by tag |
| 2025.12.27.10 | 2025-12-27 | Switch to two-digit daily version format |
| 2025.12.27.09 | 2025-12-27 | Add default blocking tag (❌) to template |
| 2025.12.27.08 | 2025-12-27 | Fix version regex to match .NOTES format |
| 2025.12.27.07 | 2025-12-27 | Use New-Module for proper module context with execution policy bypass |
| 2025.12.27.06 | 2025-12-27 | Fix execution policy bypass for module import on endpoints |
| 2025.12.27.05 | 2025-12-27 | Fix encoding, use ASCII prefixes, empty default BlockingTags |
| 2025.12.27.04 | 2025-12-27 | Library URL now configurable via custom field |
| 2025.12.27.03 | 2025-12-27 | Added comprehensive code documentation |
| 2025.12.27.02 | 2025-12-27 | First public release - GitHub auto-update |

---

## License

MIT License with Attribution - Free to use with attribution to COOLNETWORKS.

See [LICENSE](LICENSE) for details.

---

## Support

**Website:** [coolnetworks.au](https://coolnetworks.au)
**Repository:** [github.com/coolnetworks/LevelLib](https://github.com/coolnetworks/LevelLib)
