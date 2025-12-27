# Level.io PowerShell Automation Library

**Version:** 2025.12.27.2

A standardized PowerShell module for COOLNETWORKS Level.io RMM automation scripts.

**Website:** [coolnetworks.au](https://coolnetworks.au)

---

## Overview

This library provides a shared set of functions and routines for all Level.io automation scripts, eliminating code duplication and ensuring consistent behavior across your entire script portfolio.

### Key Features

- **Tag Gate System** — Automatically skip execution on devices with blocking tags (e.g., `❌`)
- **Lockfile Management** — Prevent concurrent script execution with PID-based lockfiles
- **Standardized Logging** — Consistent timestamped output with severity levels
- **Error Handling** — Wrapped execution with automatic cleanup on success or failure
- **API Helper** — Simplified REST API calls with bearer token authentication
- **Device Info** — Quick access to common system properties

---

## Architecture

```
{{cf_msp_scratch_folder}}\
│
├── Libraries\
│   └── LevelIO-Common.psm1      # Shared PowerShell module
│
└── lockfiles\
    ├── ScriptA.lock             # Active lockfiles (auto-managed)
    ├── ScriptB.lock
    └── ...
```

| Component | Purpose |
|-----------|---------|
| `Libraries\` | Contains the shared module imported by all scripts |
| `lockfiles\` | Stores active lockfiles to prevent concurrent runs |
| `LevelIO-Common.psm1` | The core module with all shared functions |

---

## Installation

### Prerequisites

- Level.io agent installed on target devices
- Custom field `msp_scratch_folder` configured (e.g., `C:\ProgramData\MSP`)
- PowerShell 5.1 or later

### Deployment

Deploy the library to all managed endpoints using a Level.io policy:

```powershell
# Deploy-LevelLibrary.ps1
# Run once per device to install the shared library

$MspScratchFolder = "{{cf_msp_scratch_folder}}"
$LibraryFolder = Join-Path -Path $MspScratchFolder -ChildPath "Libraries"
$LibraryFile = Join-Path -Path $LibraryFolder -ChildPath "LevelIO-Common.psm1"

# Create directory structure
if (!(Test-Path $LibraryFolder)) {
    New-Item -Path $LibraryFolder -ItemType Directory -Force | Out-Null
}

# Download from your hosted location
$ModuleUrl = "https://your-storage-location/LevelIO-Common.psm1"
Invoke-WebRequest -Uri $ModuleUrl -OutFile $LibraryFile -UseBasicParsing

Write-Host "[✓] Library deployed successfully"
exit 0
```

> **Tip:** Host the module file on Azure Blob Storage, AWS S3, or a private GitHub repository for easy version control and updates.

---

## Quick Start

### Minimal Script Template

```powershell
# MyScript.ps1
# Target: Level.io
# Exit 0 = Success | Exit 1 = Failure
$ErrorActionPreference = "SilentlyContinue"

# Import library
$LibraryPath = Join-Path -Path "{{cf_msp_scratch_folder}}" -ChildPath "Libraries\LevelIO-Common.psm1"
if (!(Test-Path $LibraryPath)) { Write-Host "[X] Library not found"; exit 1 }
Import-Module $LibraryPath -Force

# Initialize (handles tag gate + lockfile automatically)
$Init = Initialize-LevelScript -ScriptName "MyScript" `
                               -MspScratchFolder "{{cf_msp_scratch_folder}}" `
                               -DeviceHostname "{{level_device_hostname}}" `
                               -DeviceTags "{{level_tag_names}}"

if (-not $Init.Success) { exit 0 }

# Execute with automatic error handling and cleanup
Invoke-LevelScript -ScriptBlock {
    Write-LevelLog "Hello from MyScript!"
    # Your code here...
}
```

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

#### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-ScriptName` | String | Yes | — | Unique identifier for the script (used for lockfile) |
| `-MspScratchFolder` | String | Yes | — | Base path for MSP files |
| `-DeviceHostname` | String | No | `$env:COMPUTERNAME` | Device hostname for logging |
| `-DeviceTags` | String | No | `""` | Comma-separated list of device tags |
| `-BlockingTags` | String[] | No | `@("❌")` | Tags that block script execution |
| `-SkipTagCheck` | Switch | No | `$false` | Bypass tag gate check |
| `-SkipLockFile` | Switch | No | `$false` | Don't create a lockfile |

#### Return Values

```powershell
# Success
@{ Success = $true; Reason = "Initialized" }

# Blocked by tag
@{ Success = $false; Reason = "TagBlocked"; Tag = "❌" }

# Already running
@{ Success = $false; Reason = "AlreadyRunning"; PID = 1234 }
```

#### Examples

```powershell
# Standard initialization
$Init = Initialize-LevelScript -ScriptName "CleanupTemp" `
                               -MspScratchFolder "{{cf_msp_scratch_folder}}" `
                               -DeviceTags "{{level_tag_names}}"

# Multiple blocking tags
$Init = Initialize-LevelScript -ScriptName "Maintenance" `
                               -MspScratchFolder "{{cf_msp_scratch_folder}}" `
                               -DeviceTags "{{level_tag_names}}" `
                               -BlockingTags @("❌", "🚫", "SKIP")

# Skip all checks (use cautiously)
$Init = Initialize-LevelScript -ScriptName "QuickCheck" `
                               -MspScratchFolder "{{cf_msp_scratch_folder}}" `
                               -SkipTagCheck -SkipLockFile
```

---

### Write-LevelLog

Outputs a timestamped, formatted log message.

```powershell
Write-LevelLog "This is a message"
Write-LevelLog "Something went wrong" -Level "ERROR"
```

#### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-Message` | String | Yes | — | The message to log |
| `-Level` | String | No | `"INFO"` | Severity level |

#### Log Levels

| Level | Prefix | Use Case |
|-------|--------|----------|
| `INFO` | `[*]` | General information |
| `WARN` | `[!]` | Warnings (non-fatal issues) |
| `ERROR` | `[X]` | Errors and failures |
| `SUCCESS` | `[✓]` | Successful completions |
| `SKIP` | `[-]` | Skipped operations |
| `DEBUG` | `[D]` | Debug/verbose output |

#### Output Example

```
2025-01-15 14:32:01 [*] Starting cleanup process
2025-01-15 14:32:02 [✓] Removed 15 temporary files
2025-01-15 14:32:03 [!] Could not access C:\Locked\File.tmp
2025-01-15 14:32:04 [X] Failed to clear browser cache
```

---

### Invoke-LevelScript

Wraps your main script logic with automatic error handling and cleanup.

```powershell
Invoke-LevelScript -ScriptBlock {
    # Your code here
    Write-LevelLog "Doing work..."
}
```

#### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-ScriptBlock` | ScriptBlock | Yes | — | The code to execute |
| `-NoCleanup` | Switch | No | `$false` | Don't remove lockfile on completion |

#### Behavior

- Executes the script block
- On success: logs completion, removes lockfile, exits with code `0`
- On error: logs the exception, removes lockfile, exits with code `1`

---

### Complete-LevelScript

Manually complete the script with a custom exit code and message.

```powershell
# Success
Complete-LevelScript -ExitCode 0 -Message "All files processed"

# Failure
Complete-LevelScript -ExitCode 1 -Message "Database connection failed"
```

#### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-ExitCode` | Int | No | `0` | Exit code (0 = success, 1 = failure) |
| `-Message` | String | No | `"Script completed"` | Final log message |

---

### Remove-LevelLockFile

Manually remove the current script's lockfile.

```powershell
Remove-LevelLockFile
```

> **Note:** This is called automatically by `Invoke-LevelScript` and `Complete-LevelScript`. Only use directly if you need manual control.

---

### Test-LevelAdmin

Checks if the script is running with administrator privileges.

```powershell
if (-not (Test-LevelAdmin)) {
    Write-LevelLog "This script requires admin rights!" -Level "ERROR"
    Complete-LevelScript -ExitCode 1 -Message "Admin required"
}
```

#### Returns

`$true` if running as administrator, `$false` otherwise.

---

### Get-LevelDeviceInfo

Returns a hashtable of common device information.

```powershell
$Info = Get-LevelDeviceInfo
Write-LevelLog "Running on: $($Info.OS) ($($Info.OSVersion))"
```

#### Returns

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
$Result = Invoke-LevelApiCall -Uri "https://api.level.io/v1/devices" `
                              -ApiKey "{{cf_apikey}}" `
                              -Method "GET"

if ($Result.Success) {
    $Devices = $Result.Data
} else {
    Write-LevelLog "API Error: $($Result.Error)" -Level "ERROR"
}
```

#### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-Uri` | String | Yes | — | Full API endpoint URL |
| `-ApiKey` | String | Yes | — | Bearer token for authentication |
| `-Method` | String | No | `"GET"` | HTTP method (GET, POST, PUT, DELETE, PATCH) |
| `-Body` | Hashtable | No | — | Request body (automatically converted to JSON) |
| `-TimeoutSec` | Int | No | `30` | Request timeout in seconds |

#### Returns

```powershell
# Success
@{ Success = $true; Data = <API Response Object> }

# Failure
@{ Success = $false; Error = "Connection timed out" }
```

#### POST Example

```powershell
$Result = Invoke-LevelApiCall -Uri "https://api.example.com/tickets" `
                              -ApiKey "{{cf_apikey}}" `
                              -Method "POST" `
                              -Body @{
                                  title = "Automated Alert"
                                  description = "Disk space low on $env:COMPUTERNAME"
                                  priority = "high"
                              }
```

---

## Complete Script Template

```powershell
# ============================================================
# [SCRIPT NAME]
# Description: [What this script does]
# Target: Level.io
# Exit 0 = Success | Exit 1 = Failure
# ============================================================
$ErrorActionPreference = "SilentlyContinue"

# ============================================================
# CONFIGURATION
# ============================================================
$ScriptName = "MyScriptName"  # <-- Change this (used for lockfile)

# ============================================================
# IMPORT SHARED LIBRARY
# ============================================================
$LibraryPath = Join-Path -Path "{{cf_msp_scratch_folder}}" -ChildPath "Libraries\LevelIO-Common.psm1"
if (!(Test-Path $LibraryPath)) {
    Write-Host "[X] FATAL: Shared library not found at $LibraryPath"
    Write-Host "[!] Run the library deployment script first."
    exit 1
}
Import-Module $LibraryPath -Force

# ============================================================
# INITIALIZE
# ============================================================
$Init = Initialize-LevelScript -ScriptName $ScriptName `
                               -MspScratchFolder "{{cf_msp_scratch_folder}}" `
                               -DeviceHostname "{{level_device_hostname}}" `
                               -DeviceTags "{{level_tag_names}}"

if (-not $Init.Success) {
    # Script was blocked (tag gate) or already running (lockfile)
    # Reason is already logged by Initialize-LevelScript
    exit 0
}

# ============================================================
# MAIN SCRIPT LOGIC
# ============================================================
Invoke-LevelScript -ScriptBlock {

    # --- Pre-flight Checks ---
    $DeviceInfo = Get-LevelDeviceInfo
    Write-LevelLog "Device: $($DeviceInfo.Hostname) | OS: $($DeviceInfo.OS)"
    
    if (-not $DeviceInfo.IsAdmin) {
        throw "This script requires administrator privileges"
    }

    # --- Your Code Here ---
    Write-LevelLog "Starting main operation..."
    
    # Example: Do some work
    $TempFiles = Get-ChildItem -Path $env:TEMP -File -ErrorAction SilentlyContinue
    Write-LevelLog "Found $($TempFiles.Count) files in temp folder"
    
    # Example: Conditional logging
    if ($TempFiles.Count -gt 100) {
        Write-LevelLog "Temp folder has excessive files" -Level "WARN"
    }
    
    # Example: API call
    # $ApiResult = Invoke-LevelApiCall -Uri "https://api.example.com/status" -ApiKey "{{cf_apikey}}"
    
    Write-LevelLog "Operation completed"
}
```

---

## Level.io Custom Fields Reference

| Custom Field Variable | Description | Example Value |
|-----------------------|-------------|---------------|
| `{{cf_msp_scratch_folder}}` | Base path for MSP files | `C:\MSP` |
| `{{cf_apikey}}` | API key for external services | `sk-xxxxx` |
| `{{level_device_hostname}}` | Device hostname from Level.io | `WORKSTATION01` |
| `{{level_tag_names}}` | Comma-separated device tags | `Production, Windows 11, ❌` |

---

## Best Practices

### Script Naming

Use descriptive, unique names for `$ScriptName` to avoid lockfile collisions:

```powershell
# Good
$ScriptName = "CleanupTempFiles"
$ScriptName = "WindowsUpdate-Weekly"
$ScriptName = "AnyDesk-Removal"

# Bad (too generic, may collide)
$ScriptName = "Cleanup"
$ScriptName = "Script1"
```

### Error Handling

Use `throw` inside `Invoke-LevelScript` to trigger a failure exit:

```powershell
Invoke-LevelScript -ScriptBlock {
    $Result = Do-Something
    
    if (-not $Result) {
        throw "Operation failed: expected result was null"
    }
}
```

### Logging Verbosity

Be generous with logging — it helps with troubleshooting in Level.io:

```powershell
Write-LevelLog "Starting file cleanup in $TargetPath"
Write-LevelLog "Found $($Files.Count) files to process"

foreach ($File in $Files) {
    Remove-Item $File.FullName -Force
    Write-LevelLog "Removed: $($File.Name)" -Level "DEBUG"
}

Write-LevelLog "Cleanup complete: removed $($Files.Count) files" -Level "SUCCESS"
```

### Using Multiple Blocking Tags

For scripts that should be skipped on various device states:

```powershell
$Init = Initialize-LevelScript -ScriptName "Maintenance" `
                               -MspScratchFolder "{{cf_msp_scratch_folder}}" `
                               -DeviceTags "{{level_tag_names}}" `
                               -BlockingTags @("❌", "🔒", "DO-NOT-TOUCH", "Decommissioned")
```

---

## Troubleshooting

### "Library not found" Error

**Cause:** The shared module hasn't been deployed to this device.

**Solution:** Run the library deployment script on the device first.

### Script Immediately Exits with Code 0

**Possible Causes:**
1. Device has a blocking tag (e.g., `❌`)
2. Script is already running (lockfile exists with active PID)

**Check:** Look at the script output for `[-]` prefixed messages indicating why it was skipped.

### Stale Lockfile Blocking Execution

**Cause:** Previous script run crashed without cleanup (rare).

**Solution:** The library automatically detects stale lockfiles by checking if the PID is still running. If issues persist, manually delete files in `{{cf_msp_scratch_folder}}\lockfiles\`.

### API Calls Failing

**Check:**
- Verify the API key custom field is correctly set
- Ensure the endpoint URL is correct
- Check network/firewall rules on the device
- Review the error message in `$Result.Error`

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 2025.12.27.2 | 2025-12-27 | First public release - GitHub auto-update, removed deploy script |
| 2025.12.27.1 | 2025-12-27 | Initial release |

---

## Support

For issues or feature requests, contact the COOLNETWORKS IT team.

**Website:** [coolnetworks.au](https://coolnetworks.au)  
**Maintained by:** COOLNETWORKS