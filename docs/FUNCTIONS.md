# COOLForge_Lib Function Reference

This document provides detailed documentation for all functions exported by the COOLForge-Common module.

---

## Table of Contents

### Initialization & Execution
- [Initialize-LevelScript](#initialize-levelscript)
- [Write-LevelLog](#write-levellog)
- [Invoke-LevelScript](#invoke-levelscript)
- [Complete-LevelScript](#complete-levelscript)
- [Remove-LevelLockFile](#remove-levellockfile)

### Device & System Info
- [Test-LevelAdmin](#test-leveladmin)
- [Get-LevelDeviceInfo](#get-leveldeviceinfo)

### Software Detection Utilities
- [Test-SoftwareInstalled](#test-softwareinstalled)
- [Stop-SoftwareProcesses](#stop-softwareprocesses)
- [Stop-SoftwareServices](#stop-softwareservices)
- [Get-SoftwareUninstallString](#get-softwareuninstallstring)
- [Test-ServiceExists](#test-serviceexists)
- [Test-ServiceRunning](#test-servicerunning)

### API & Text Processing
- [Invoke-LevelApiCall](#invoke-levelapicall)
- [Repair-LevelEmoji](#repair-levelemoji)
- [Get-LevelUrlEncoded](#get-levelurlencoded)

### Level.io API Functions
- [Get-LevelGroups](#get-levelgroups)
- [Get-LevelDevices](#get-leveldevices)
- [Find-LevelDevice](#find-leveldevice)
- [Send-LevelWakeOnLan](#send-levelwakeonlan)

### Technician Alerts
- [Send-TechnicianAlert](#send-technicianalert)
- [Add-TechnicianAlert](#add-technicianalert)
- [Send-TechnicianAlertQueue](#send-technicianalertqueue)
- [Test-TechnicianWorkstation](#test-technicianworkstation)
- [Get-TechnicianName](#get-technicianname)

---

## Initialize-LevelScript

Initializes the script environment, checks blocking tags, and creates a lockfile.

```powershell
$Init = Initialize-LevelScript -ScriptName "MyScript" `
                               -MspScratchFolder "{{cf_coolforge_msp_scratch_folder}}" `
                               -DeviceHostname "{{level_device_hostname}}" `
                               -DeviceTags "{{level_tag_names}}"
```

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-ScriptName` | String | Yes | — | Unique identifier for the script (used for lockfile) |
| `-MspScratchFolder` | String | Yes | — | Base path for MSP files |
| `-DeviceHostname` | String | No | `$env:COMPUTERNAME` | Device hostname for logging |
| `-DeviceTags` | String | No | `""` | Comma-separated list of device tags |
| `-BlockingTags` | String[] | No | `@("❌")` | Tags that block script execution |
| `-SkipTagCheck` | Switch | No | `$false` | Bypass tag gate check |
| `-SkipLockFile` | Switch | No | `$false` | Don't create a lockfile |
| `-ApiKey` | String | No | `""` | Level.io API key for auto-sending technician alerts |

### Return Values

```powershell
# Success
@{ Success = $true; Reason = "Initialized" }

# Blocked by tag
@{ Success = $false; Reason = "TagBlocked"; Tag = "BlockedTag" }

# Already running
@{ Success = $false; Reason = "AlreadyRunning"; PID = 1234 }
```

---

## Write-LevelLog

Outputs a timestamped, formatted log message.

```powershell
Write-LevelLog "This is a message"
Write-LevelLog "Something went wrong" -Level "ERROR"
```

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-Message` | String | Yes | — | The message to log |
| `-Level` | String | No | `"INFO"` | Severity level |

### Log Levels

| Level | Prefix | Use Case |
|-------|--------|----------|
| `INFO` | `[*]` | General information |
| `WARN` | `[!]` | Warnings (non-fatal issues) |
| `ERROR` | `[X]` | Errors and failures |
| `SUCCESS` | `[+]` | Successful completions |
| `SKIP` | `[-]` | Skipped operations |
| `DEBUG` | `[D]` | Debug/verbose output |

### Output Example

```
2025-12-27 14:32:01 [*] Starting cleanup process
2025-12-27 14:32:02 [+] Removed 15 temporary files
2025-12-27 14:32:03 [!] Could not access C:\Locked\File.tmp
2025-12-27 14:32:04 [X] Failed to clear browser cache
```

---

## Invoke-LevelScript

Wraps your main script logic with automatic error handling and cleanup.

```powershell
Invoke-LevelScript -ScriptBlock {
    Write-LevelLog "Doing work..."
    # Your code here
}
```

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-ScriptBlock` | ScriptBlock | Yes | — | The code to execute |
| `-NoCleanup` | Switch | No | `$false` | Don't remove lockfile on completion |

### Behavior

- Executes the script block
- On completion (success or failure):
  - Sends any queued technician alerts (if ApiKey was provided to `Initialize-LevelScript`)
  - Removes lockfile (unless `-NoCleanup`)
  - Exits with code `0` (success) or `1` (error)

---

## Complete-LevelScript

Manually complete the script with a custom exit code and message.

```powershell
Complete-LevelScript -ExitCode 0 -Message "All files processed"
Complete-LevelScript -ExitCode 1 -Message "Database connection failed"
```

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-ExitCode` | Int | No | `0` | Exit code (0 = success, 1 = alert/failure) |
| `-Message` | String | No | `"Script completed"` | Final log message |

---

## Remove-LevelLockFile

Manually remove the current script's lockfile.

```powershell
Remove-LevelLockFile
```

> **Note:** Called automatically by `Invoke-LevelScript` and `Complete-LevelScript`.

---

## Test-LevelAdmin

Checks if the script is running with administrator privileges.

```powershell
if (-not (Test-LevelAdmin)) {
    Write-LevelLog "This script requires admin rights!" -Level "ERROR"
    Complete-LevelScript -ExitCode 1 -Message "Admin required"
}
```

**Returns:** `$true` if running as administrator, `$false` otherwise.

---

## Get-LevelDeviceInfo

Returns a hashtable of common device information.

```powershell
$Info = Get-LevelDeviceInfo
Write-LevelLog "Running on: $($Info.OS) ($($Info.OSVersion))"
```

### Returns

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

## Test-SoftwareInstalled

Checks if software is installed on the system by examining multiple locations.

```powershell
# Simple check by name
$installed = Test-SoftwareInstalled -SoftwareName "AnyDesk"

# Check with specific paths
$installed = Test-SoftwareInstalled -SoftwareName "Unchecky" -InstallPaths @(
    "$env:ProgramFiles\Unchecky\unchecky.exe",
    "${env:ProgramFiles(x86)}\Unchecky\unchecky.exe"
) -SkipProcessCheck -SkipServiceCheck

# Path-only check (no process/service/registry)
$installed = Test-SoftwareInstalled -SoftwareName "Huntress" -InstallPaths @(
    "$env:ProgramFiles\Huntress\HuntressAgent.exe"
) -SkipProcessCheck -SkipServiceCheck -SkipRegistryCheck
```

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-SoftwareName` | String | Yes | — | Display name pattern for registry search |
| `-ProcessPattern` | String | No | SoftwareName | Pattern to match running processes |
| `-ServicePattern` | String | No | SoftwareName | Pattern to match Windows services |
| `-InstallPaths` | String[] | No | — | Array of file paths to check for existence |
| `-SkipProcessCheck` | Switch | No | `$false` | Skip checking running processes |
| `-SkipServiceCheck` | Switch | No | `$false` | Skip checking Windows services |
| `-SkipRegistryCheck` | Switch | No | `$false` | Skip checking registry uninstall entries |

### Detection Order

1. Running processes (if not skipped)
2. Windows services (if not skipped)
3. File system paths (if provided)
4. Registry uninstall entries (if not skipped)

**Returns:** `$true` if ANY check finds a match, `$false` otherwise.

---

## Stop-SoftwareProcesses

Stops all processes matching a name pattern.

```powershell
# Stop all AnyDesk processes
$count = Stop-SoftwareProcesses -ProcessPattern "AnyDesk"
Write-LevelLog "Stopped $count processes"

# Stop silently (no logging)
$count = Stop-SoftwareProcesses -ProcessPattern "TeamViewer" -Silent
```

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-ProcessPattern` | String | Yes | — | Pattern to match (wildcards appended automatically) |
| `-Silent` | Switch | No | `$false` | Suppress logging output |

**Returns:** Integer count of processes successfully stopped.

---

## Stop-SoftwareServices

Stops and optionally disables Windows services matching a pattern.

```powershell
# Stop services
$count = Stop-SoftwareServices -ServicePattern "AnyDesk"

# Stop and disable services
$count = Stop-SoftwareServices -ServicePattern "AnyDesk" -Disable

# Stop silently
$count = Stop-SoftwareServices -ServicePattern "RemoteApp" -Silent
```

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-ServicePattern` | String | Yes | — | Pattern to match (wildcards appended automatically) |
| `-Disable` | Switch | No | `$false` | Also disable services after stopping |
| `-Silent` | Switch | No | `$false` | Suppress logging output |

**Returns:** Integer count of services successfully stopped.

---

## Get-SoftwareUninstallString

Retrieves the uninstall command from Windows registry.

```powershell
# Get uninstall string
$uninstall = Get-SoftwareUninstallString -SoftwareName "Unchecky"
if ($uninstall) {
    Start-Process cmd -ArgumentList "/c $uninstall" -Wait
}

# Prefer quiet uninstall string if available
$uninstall = Get-SoftwareUninstallString -SoftwareName "AnyDesk" -Quiet
```

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-SoftwareName` | String | Yes | — | Display name pattern to search for |
| `-Quiet` | Switch | No | `$false` | Return QuietUninstallString if available |

### Search Locations

- `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*`
- `HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*`
- `HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*`

**Returns:** Uninstall string if found, `$null` otherwise.

---

## Test-ServiceExists

Checks if a Windows service exists by exact name.

```powershell
if (Test-ServiceExists -ServiceName "HuntressAgent") {
    Write-LevelLog "Huntress agent service is installed"
}
```

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-ServiceName` | String | Yes | Exact service name to check |

**Returns:** `$true` if service exists, `$false` otherwise.

---

## Test-ServiceRunning

Checks if a Windows service is currently running.

```powershell
if (Test-ServiceRunning -ServiceName "HuntressAgent") {
    Write-LevelLog "Huntress agent is running"
} else {
    Write-LevelLog "Huntress agent is not running" -Level "WARN"
}
```

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-ServiceName` | String | Yes | Exact service name to check |

**Returns:** `$true` if service exists AND is running, `$false` otherwise.

---

## Invoke-LevelApiCall

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

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-Uri` | String | Yes | — | Full API endpoint URL |
| `-ApiKey` | String | Yes | — | Bearer token for authentication |
| `-Method` | String | No | `"GET"` | HTTP method (GET, POST, PUT, DELETE, PATCH) |
| `-Body` | Hashtable | No | — | Request body (converted to JSON) |
| `-TimeoutSec` | Int | No | `30` | Request timeout in seconds |

### Returns

```powershell
# Success
@{ Success = $true; Data = <API Response Object> }

# Failure
@{ Success = $false; Error = "Connection timed out" }
```

### POST Example

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

## Repair-LevelEmoji

Repairs corrupted UTF-8 emojis in strings. Level.io and other deployment systems may corrupt UTF-8 emojis when deploying scripts. This function detects common corruption patterns and fixes them.

```powershell
$ScriptName = Repair-LevelEmoji -Text $ScriptName
```

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Text` | String | Yes | The text string that may contain corrupted emojis |

### Supported Emojis

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

### Example

```powershell
# The launcher uses this automatically to fix corrupted script names
$ScriptToRun = Repair-LevelEmoji -Text $ScriptToRun
```

> **Note:** This function is called automatically by the Script Launcher after loading the library. You typically don't need to call it directly unless working with emoji-containing strings in your own scripts.

---

## Get-LevelUrlEncoded

URL-encodes a string with proper UTF-8 handling for emojis. Unlike `[System.Uri]::EscapeDataString()`, this function correctly encodes UTF-8 bytes for use in URLs.

```powershell
$EncodedName = Get-LevelUrlEncoded -Text "👀Test Script.ps1"
# Returns: %F0%9F%91%80Test%20Script.ps1
```

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Text` | String | Yes | The text string to URL-encode |

**Returns:** URL-encoded string safe for use in HTTP requests.

### Example

```powershell
# Build a URL with an emoji-containing filename
$ScriptUrl = "$BaseUrl/$(Get-LevelUrlEncoded $ScriptToRun)"
```

> **Note:** This function is called automatically by the Script Launcher when downloading scripts. You typically don't need to call it directly unless building custom URLs.

---

## Get-LevelGroups

Retrieves all groups (organizations and folders) from the Level.io API with automatic pagination.

```powershell
$Groups = Get-LevelGroups -ApiKey "{{cf_apikey}}"
$RootGroups = $Groups | Where-Object { -not $_.parent_id }
```

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-ApiKey` | String | Yes | — | Level.io API key (Bearer token) |
| `-BaseUrl` | String | No | `https://api.level.io/v2` | API base URL |

### Returns

Array of group objects with properties: `id`, `name`, `parent_id`, `type` (organization/folder), etc.

Returns `$null` on error.

---

## Get-LevelDevices

Retrieves devices from the Level.io API with automatic pagination.

```powershell
# Get all devices
$AllDevices = Get-LevelDevices -ApiKey "{{cf_apikey}}"

# Get devices in a specific group
$GroupDevices = Get-LevelDevices -ApiKey "{{cf_apikey}}" -GroupId "grp_123abc"

# Include network interface details (for MAC addresses)
$DevicesWithNIC = Get-LevelDevices -ApiKey "{{cf_apikey}}" -IncludeNetworkInterfaces
```

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-ApiKey` | String | Yes | — | Level.io API key (Bearer token) |
| `-GroupId` | String | No | — | Filter by group ID |
| `-IncludeNetworkInterfaces` | Switch | No | `$false` | Include NIC details (MAC addresses) |
| `-BaseUrl` | String | No | `https://api.level.io/v2` | API base URL |

### Returns

Array of device objects with properties: `id`, `hostname`, `os_name`, `group_id`, `network_interfaces` (if requested), etc.

Returns `$null` on error.

---

## Find-LevelDevice

Searches for a specific device by hostname.

```powershell
$Device = Find-LevelDevice -ApiKey "{{cf_apikey}}" -Hostname "WORKSTATION01"
if ($Device) {
    Write-LevelLog "Found device: $($Device.id)"
}
```

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-ApiKey` | String | Yes | — | Level.io API key (Bearer token) |
| `-Hostname` | String | Yes | — | Exact hostname to search for |
| `-BaseUrl` | String | No | `https://api.level.io/v2` | API base URL |

### Returns

Device object if found, `$null` otherwise.

---

## Send-LevelWakeOnLan

Sends Wake-on-LAN magic packets to wake a device by MAC address.

```powershell
# Wake a device
$Success = Send-LevelWakeOnLan -MacAddress "AA:BB:CC:DD:EE:FF"

# Multiple attempts with longer delay
$Success = Send-LevelWakeOnLan -MacAddress "AA-BB-CC-DD-EE-FF" -Attempts 15 -DelayMs 1000
```

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-MacAddress` | String | Yes | — | MAC address (accepts `:` or `-` delimiters) |
| `-Attempts` | Int | No | `10` | Number of magic packets to send |
| `-DelayMs` | Int | No | `500` | Delay between packets (milliseconds) |

### Returns

`$true` if packets sent successfully, `$false` on error.

### Requirements

- Target device must have Wake-on-LAN enabled in BIOS/UEFI
- Target NIC must support WOL and have it enabled in device properties
- Sending device must be on the same network segment (or use directed broadcast)

---

## Send-TechnicianAlert

Sends an alert to technician workstations via Level.io custom field. Alerts are displayed as Windows toast notifications on tech workstations running the alert monitor.

```powershell
# Basic alert
$Result = Send-TechnicianAlert -ApiKey "{{cf_apikey}}" `
                               -Title "Install Failed" `
                               -Message "Huntress install failed on this device" `
                               -ClientName "ACME Corp" `
                               -DeviceHostname $env:COMPUTERNAME

# High-priority alert to specific technician
Send-TechnicianAlert -ApiKey "{{cf_apikey}}" `
                     -Title "Security Alert" `
                     -Message "Unauthorized remote access tool detected" `
                     -ClientName "BigClient" `
                     -DeviceHostname "BC-SERVER01" `
                     -Priority "Critical" `
                     -TechnicianName "John"
```

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-ApiKey` | String | Yes | — | Level.io API key |
| `-Title` | String | Yes | — | Short alert title (notification header) |
| `-Message` | String | Yes | — | Detailed message explaining needed action |
| `-ClientName` | String | No | `""` | Client/organization name for routing |
| `-DeviceHostname` | String | No | `$env:COMPUTERNAME` | Hostname of device triggering alert |
| `-Priority` | String | No | `"Normal"` | `Low`, `Normal`, `High`, or `Critical` |
| `-TechnicianName` | String | No | `""` | Route to specific technician (empty = all) |
| `-ExpiresInMinutes` | Int | No | `1440` | Alert expiration time (default: 24 hours) |
| `-BaseUrl` | String | No | `https://api.level.io/v2` | API base URL |

### Returns

```powershell
# Success
@{ Success = $true; AlertId = "a1b2c3d4"; Error = $null }

# Failure
@{ Success = $false; AlertId = $null; Error = "Custom field not found" }
```

### Alert Flow

1. Script calls `Send-TechnicianAlert` with message details
2. Alert is written to `cf_coolforge_technician_alerts` (JSON array on group)
3. Technician workstation polling script detects new alert
4. Toast notification displayed on tech workstation

### Priority Levels

| Priority | Use Case |
|----------|----------|
| `Low` | Informational, can wait |
| `Normal` | Standard priority |
| `High` | Needs attention soon |
| `Critical` | Immediate action required |

### Example: Alert on Script Failure

```powershell
try {
    # Attempt some operation
    Install-Software -Name "Huntress"
}
catch {
    # Send alert to technicians on failure
    Send-TechnicianAlert -ApiKey $LevelApiKey `
        -Title "Manual Install Required" `
        -Message "Huntress install failed: $($_.Exception.Message)" `
        -ClientName $ClientName `
        -DeviceHostname $DeviceHostname `
        -Priority "High"
}
```

### Required Custom Fields

- `cf_coolforge_technician_alerts` — Stores pending alerts (JSON array)

---

## Add-TechnicianAlert

Queues a technician alert to be sent when the script completes. This is the **recommended** way to send alerts - it batches multiple alerts into a single API call and ensures alerts are sent even if the script encounters errors.

```powershell
# Queue an alert (sent automatically when script completes)
Add-TechnicianAlert -Title "Action Required" -Message "Please check the logs"

# Queue a critical alert for a specific technician
Add-TechnicianAlert -Title "Critical Issue" `
                    -Message "Database connection failed" `
                    -Priority "Critical" `
                    -TechnicianName "Allen"
```

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-Title` | String | Yes | — | Short alert title (notification header) |
| `-Message` | String | Yes | — | Detailed message explaining needed action |
| `-ClientName` | String | No | `""` | Client/organization name for context |
| `-Priority` | String | No | `"Normal"` | `Low`, `Normal`, `High`, or `Critical` |
| `-TechnicianName` | String | No | `""` | Route to specific technician (empty = all) |
| `-ExpiresInMinutes` | Int | No | `1440` | Alert expiration time (default: 24 hours) |

### Returns

```powershell
@{ Success = $true; QueueLength = 2; AlertId = "a1b2c3d4" }
```

### Requirements

- Must call `Initialize-LevelScript` with `-ApiKey` before using
- Alerts are automatically sent by `Invoke-LevelScript` on completion

### Example: Queue Alerts During Script Execution

```powershell
$Init = Initialize-LevelScript -ScriptName "InstallSoftware" `
                               -MspScratchFolder $MspFolder `
                               -ApiKey "{{cf_apikey}}"

Invoke-LevelScript -ScriptBlock {
    try {
        Install-Software -Name "Huntress"
    }
    catch {
        # Queue an alert - will be sent when script completes
        Add-TechnicianAlert -Title "Install Failed" `
                            -Message "Huntress: $($_.Exception.Message)" `
                            -Priority "High"
    }

    try {
        Install-Software -Name "Datto AV"
    }
    catch {
        # Queue another alert - both sent in single API call
        Add-TechnicianAlert -Title "Install Failed" `
                            -Message "Datto AV: $($_.Exception.Message)" `
                            -Priority "High"
    }
}
# Alerts automatically sent here
```

---

## Send-TechnicianAlertQueue

Sends all queued technician alerts to Level.io. Called automatically by `Invoke-LevelScript` on completion - you typically don't need to call this directly.

```powershell
# Manual flush (usually not needed)
$Result = Send-TechnicianAlertQueue

# Override API key
$Result = Send-TechnicianAlertQueue -ApiKey "your-api-key" -Force
```

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-ApiKey` | String | No | — | Override API key (uses stored key if not provided) |
| `-Force` | Switch | No | `$false` | Send even if ApiKey wasn't in Initialize-LevelScript |
| `-BaseUrl` | String | No | `https://api.level.io/v2` | API base URL |

### Returns

```powershell
# Success
@{ Success = $true; AlertsSent = 3; Error = $null }

# No ApiKey configured
@{ Success = $false; AlertsSent = 0; Error = "No ApiKey configured" }
```

### Behavior

- Batches all queued alerts into a single API call
- Removes expired alerts from the custom field
- Clears the queue after successful send

---

## Test-TechnicianWorkstation

Checks if the current device is a technician workstation based on device tags.

```powershell
if (Test-TechnicianWorkstation -DeviceTags "{{level_tag_names}}") {
    # This is a tech workstation - start alert monitor
    Start-AlertMonitor
}
```

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-DeviceTags` | String | No | `""` | Comma-separated list of device tags from `{{level_tag_names}}` |

### Returns

`$true` if this device has the technician tag, `$false` otherwise.

### Required Tag

Tag your workstation with: `🧑‍💻technician` or `🧑‍💻YourName`

The emoji is U+1F9D1 U+200D U+1F4BB (technician/person at computer).

---

## Get-TechnicianName

Extracts the technician name from device tags.

```powershell
$TechName = Get-TechnicianName -DeviceTags "{{level_tag_names}}"
if ($TechName) {
    Write-LevelLog "Technician: $TechName"
}
```

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-DeviceTags` | String | No | `""` | Comma-separated list of device tags from `{{level_tag_names}}` |

### Returns

Technician name string extracted from the tag (e.g., "John" from `🧑‍💻John`), or empty string if not found.

### Examples

| Tag | Returns |
|-----|---------|
| `🧑‍💻technician` | `"technician"` |
| `🧑‍💻John` | `"John"` |
| `🧑‍💻Allen B` | `"Allen B"` |
| (no tag) | `""` |

---

## See Also

- [Main README](../README.md)
- [Technician Alerts Guide](TECHNICIAN-ALERTS.md) - Full documentation for the alert system
- [Script Launcher Guide](LAUNCHER.md)
- [Emoji Handling](EMOJI-HANDLING.md)
