# COOLForge Codebase Documentation

Complete technical documentation for the COOLForge PowerShell automation framework for Level.io RMM.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Core Modules](#core-modules)
3. [Launcher System](#launcher-system)
4. [Scripts](#scripts)
5. [Tools](#tools)
6. [Pre-Release Pipeline](#pre-release-pipeline)
7. [Testing](#testing)
8. [Definitions & Configuration](#definitions--configuration)
9. [Custom Fields](#custom-fields)
10. [Emoji Handling](#emoji-handling)

---

## Architecture Overview

COOLForge is a centralized script management framework for Level.io RMM. Instead of deploying individual scripts to Level.io, you deploy lightweight **launchers** that automatically download and execute scripts from GitHub.

```
┌─────────────────────────────────────────────────────────────────┐
│                        LEVEL.IO                                  │
│  ┌─────────────┐                                                │
│  │   Launcher  │ ← Deployed once to Level.io                    │
│  │  (wrapper)  │                                                │
│  └──────┬──────┘                                                │
└─────────┼───────────────────────────────────────────────────────┘
          │
          │ Downloads at runtime
          ▼
┌─────────────────────────────────────────────────────────────────┐
│                      GITHUB REPO                                 │
│                                                                  │
│  ┌──────────────────────┐   ┌─────────────────────────────────┐ │
│  │ COOLForge-Common.psm1│   │        scripts/                 │ │
│  │   (shared library)   │   │   Check/, Fix/, Remove/...      │ │
│  └──────────────────────┘   └─────────────────────────────────┘ │
│                                                                  │
│  ┌──────────────────────┐                                       │
│  │      MD5SUMS         │  ← Checksums + path resolution        │
│  └──────────────────────┘                                       │
└─────────────────────────────────────────────────────────────────┘
```

### Key Benefits

- **Single deployment point**: Launchers auto-update from GitHub
- **Version pinning**: Pin scripts to specific releases via custom fields
- **Centralized management**: Update scripts in GitHub, all devices get updates
- **Integrity verification**: MD5 checksums prevent corrupted downloads

---

## Core Modules

### COOLForge-Common.psm1

**Location**: `modules/COOLForge-Common.psm1`

The main shared library providing standardized functions for all scripts.

#### Initialization & Execution

| Function | Description |
|----------|-------------|
| `Initialize-LevelScript` | Initializes script environment with tag gate and lockfile management |
| `Invoke-LevelScript` | Wraps main script logic with error handling and cleanup |
| `Complete-LevelScript` | Manual completion with custom exit code and message |
| `Remove-LevelLockFile` | Removes current script's lockfile |

**Initialization Example**:
```powershell
$Init = Initialize-LevelScript -ScriptName "MyScript" `
                               -MspScratchFolder $MspScratchFolder `
                               -DeviceHostname $DeviceHostname `
                               -DeviceTags $DeviceTags `
                               -BlockingTags @("NoScript", "Maintenance")

if (-not $Init.Success) { exit 0 }

Invoke-LevelScript -ScriptBlock {
    Write-LevelLog "Doing work..."
    # Your code here
}
```

#### Logging

| Function | Description |
|----------|-------------|
| `Write-LevelLog` | Timestamped logging with severity levels (INFO, WARN, ERROR, SUCCESS, SKIP, DEBUG) |

**Log Prefixes**:
- `[*]` INFO - General information
- `[!]` WARN - Warnings
- `[X]` ERROR - Errors
- `[+]` SUCCESS - Successful completion
- `[-]` SKIP - Skipped operations
- `[D]` DEBUG - Debug output

#### Device & System Info

| Function | Description |
|----------|-------------|
| `Test-LevelAdmin` | Checks if running with administrator privileges |
| `Get-LevelDeviceInfo` | Returns hashtable of device info (Hostname, OS, IsAdmin, etc.) |

#### Software Detection Utilities

Generic functions for detecting and managing software installations. These consolidate common patterns used across removal and policy scripts.

| Function | Description |
|----------|-------------|
| `Test-SoftwareInstalled` | Generic software detection (processes, services, paths, registry) |
| `Stop-SoftwareProcesses` | Stop all processes matching a pattern, returns count |
| `Stop-SoftwareServices` | Stop and optionally disable services matching a pattern |
| `Get-SoftwareUninstallString` | Get uninstall command from registry |
| `Install-MsiWithRetry` | Install MSI packages with configurable retry logic |
| `Install-ExeWithRetry` | Install EXE installers with retry logic |
| `Test-ServiceExists` | Check if a Windows service exists by name |
| `Test-ServiceRunning` | Check if a Windows service is running |

**Usage Example**:
```powershell
# Check if software is installed
$installed = Test-SoftwareInstalled -SoftwareName "AnyDesk" -InstallPaths @(
    "$env:ProgramFiles\AnyDesk",
    "${env:ProgramFiles(x86)}\AnyDesk"
)

# Stop processes and services before removal
$procsStopped = Stop-SoftwareProcesses -ProcessPattern "AnyDesk"
$svcsStopped = Stop-SoftwareServices -ServicePattern "AnyDesk" -Disable

# Get uninstall command
$uninstall = Get-SoftwareUninstallString -SoftwareName "AnyDesk" -Quiet
```

#### Software Policy System

| Function | Description |
|----------|-------------|
| `Get-EmojiBytePatterns` | Get raw emoji byte patterns for tag matching |
| `Get-EmojiMap` | Returns centralized emoji-to-action mapping (single source of truth) |
| `Get-EmojiLiterals` | Get clean emoji literals for display |
| `Get-SoftwarePolicy` | Parses device tags for software policy requirements |
| `Invoke-SoftwarePolicyCheck` | High-level policy check with formatted output |

**Policy Emojis**:
| Emoji | Action | Description |
|-------|--------|-------------|
| `🙏` | Install | Request/recommend installation |
| `🚫` | Remove | Remove if present |
| `📌` | Pin | Lock state (blocks install AND remove) |
| `🔄` | Reinstall | Remove then install |
| `✅` | Has | Installed/verified status |
| `❌` | Skip | Hands off (managed elsewhere) |

> **Note:** `⛔` (U+26D4) also works for Remove but is **deprecated**. Use `🚫` (U+1F6AB) instead.

**Priority Resolution** (highest to lowest):
1. Skip → Exit immediately
2. Pin → Lock state
3. Block → Prevent install only
4. Remove → Uninstall
5. Install → Install/reinstall
6. Has → Verify and remediate

#### Level.io API Functions

| Function | Description |
|----------|-------------|
| `Invoke-LevelApiCall` | Authenticated REST API calls |
| `Get-LevelGroups` | Fetch all groups with pagination |
| `Get-LevelDevices` | Fetch devices with optional group filter |
| `Find-LevelDevice` | Find device by hostname |
| `Get-LevelDeviceById` | Get device by ID |
| `Get-LevelDeviceTagNames` | Get tag names for a device |
| `Set-LevelDeviceName` | Update device hostname |

#### Tag Management

| Function | Description |
|----------|-------------|
| `Get-LevelTags` | Fetch all tags with pagination |
| `Find-LevelTag` | Find tag by name |
| `New-LevelTag` | Create a new tag in Level.io |
| `Add-LevelTagToDevice` | Add tag to device |
| `Remove-LevelTagFromDevice` | Remove tag from device |
| `Add-LevelPolicyTag` | High-level: Add policy tag (e.g., add "Has" after install) |
| `Remove-LevelPolicyTag` | High-level: Remove policy tag |
| `Update-CachedDeviceTags` | Update cached device tags |

#### Wake-on-LAN

| Function | Description |
|----------|-------------|
| `Send-LevelWakeOnLan` | Send WOL magic packet to MAC address |

#### Text Processing

| Function | Description |
|----------|-------------|
| `Repair-LevelEmoji` | Repairs corrupted UTF-8 emojis in strings |
| `Get-LevelUrlEncoded` | URL-encode with proper UTF-8 emoji handling |

#### Custom Field Management

| Function | Description |
|----------|-------------|
| `Get-LevelCustomFields` | Fetch all custom fields with pagination |
| `Find-LevelCustomField` | Find custom field by name |
| `New-LevelCustomField` | Create new custom field |
| `Set-LevelCustomFieldValue` | Set custom field value for device |
| `Initialize-LevelSoftwarePolicy` | Initialize software policy custom field |
| `Initialize-COOLForgeInfrastructure` | Create core COOLForge custom fields |
| `Initialize-SoftwarePolicyInfrastructure` | Create fields and tags for a specific software policy |
| `Get-LevelCustomFieldById` | Get custom field by ID |
| `Set-LevelCustomFieldDefaultValue` | Set account-level default value for custom field |
| `Remove-LevelCustomField` | Delete a custom field |

#### Cache Management

Registry-based caching to reduce API calls and improve performance.

| Function | Description |
|----------|-------------|
| `Initialize-LevelCache` | Initialize registry cache structure |
| `Get-LevelCacheValue` | Retrieve value from registry cache |
| `Set-LevelCacheValue` | Store value in registry cache |
| `Get-LevelCachePath` | Get the registry path for cache |
| `Protect-CacheValue` | Encrypt a cache value (DPAPI) |
| `Unprotect-CacheValue` | Decrypt a protected cache value |
| `Set-ProtectedCacheValue` | Store encrypted value in cache |
| `Get-ProtectedCacheValue` | Retrieve and decrypt cache value |
| `Update-LevelCache` | Refresh cache from API |
| `Get-CachedDeviceTags` | Get cached tags for a device |
| `Update-CachedDeviceTags` | Update device tag cache |
| `Get-CachedTagId` | Get tag ID from cache |
| `Get-CachedCustomFieldId` | Get custom field ID from cache |
| `Clear-LevelCache` | Clear all cached data |
| `Show-DebugCacheInfo` | Display cache contents for debugging |
| `Get-MspNameFromPath` | Extract MSP name from scratch folder path |
| `Get-ApiCallCount` | Get current API call count |
| `Reset-ApiCallCount` | Reset API call counter |

#### Hierarchy Navigation

| Function | Description |
|----------|-------------|
| `Get-LevelOrganizations` | Get all organizations |
| `Get-LevelOrganizationFolders` | Get folders within an organization |
| `Get-LevelFolderDevices` | Get devices in a folder |
| `Get-LevelEntityCustomFields` | Get custom fields for an entity |

#### Technician Alerts

Functions for sending toast notifications to technician workstations. Technicians are identified by the `🧑‍💻` (U+1F9D1 U+200D U+1F4BB) emoji tag.

| Function | Description |
|----------|-------------|
| `Test-TechnicianWorkstation` | Check if device has technician tag |
| `Get-TechnicianName` | Extract technician name from tags (e.g., `🧑‍💻John` → `John`) |
| `Add-TechnicianAlert` | Queue alert for auto-send on script completion |
| `Send-TechnicianAlert` | Send alert immediately to tech workstations |
| `Send-TechnicianAlertQueue` | Manually send all queued alerts |

**Alert Flow**:
1. Scripts call `Add-TechnicianAlert` to queue alerts during execution
2. On script completion, `Invoke-LevelScript` automatically calls `Send-TechnicianAlertQueue`
3. Alerts are written to the `coolforge_technician_alerts` custom field
4. The Technician Alert Monitor script polls this field and displays toast notifications

See [TECHNICIAN-ALERTS.md](TECHNICIAN-ALERTS.md) for detailed usage.

#### Admin Tool Functions (also in COOLForge-Common.psm1)

| Category | Functions |
|----------|-----------|
| **UI Helpers** | `Write-Header`, `Write-LevelSuccess`, `Write-LevelInfo`, `Write-LevelWarning`, `Write-LevelError`, `Read-UserInput`, `Read-YesNo` |
| **Debug Helpers** | `Write-DebugSection`, `Write-DebugTags`, `Write-DebugPolicy`, `Write-DebugTagManagement` |
| **Config/Security** | `Get-SavedConfig`, `Save-Config`, `Protect-ApiKey` (DPAPI), `Unprotect-ApiKey`, `Get-CompanyNameFromPath` |
| **Backup/Restore** | `Backup-AllCustomFields`, `Save-Backup`, `Import-Backup`, `Restore-CustomFields`, `Get-BackupPath`, `Get-LatestBackup`, `Compare-BackupWithCurrent`, `Show-BackupDifferences` |
| **GitHub** | `Get-GitHubReleases`, `Show-ReleaseNotes`, `Select-Version` |
| **Initialization** | `Initialize-LevelApi`, `Initialize-COOLForgeCustomFields` (alias) |
| **Script Launcher** | `Get-ContentMD5`, `Get-ExpectedMD5`, `Get-ScriptPathFromMD5`, `Get-ScriptVersion`, `Invoke-ScriptLauncher` |

---

## Launcher System

### How Launchers Work

Launchers are thin wrappers that:
1. Download the COOLForge-Common library from GitHub
2. Verify MD5 checksums
3. Resolve script paths from MD5SUMS file
4. Download and cache the target script
5. Execute the script with all Level.io variables

### Launcher Template

**Location**: `templates/Launcher_Template.ps1`

The template provides:
- Library auto-update with backup/restore on failure
- MD5 checksum verification
- Version pinning support
- GitHub PAT injection for private repos
- Script caching with update detection

**Key Variables Passed to Scripts**:
- `$MspScratchFolder` - Persistent storage folder
- `$LibraryUrl` - URL to download library
- `$DeviceHostname` - Device hostname
- `$DeviceTags` - Comma-separated device tags

### Creating a Launcher

1. Copy `Launcher_Template.ps1`
2. Change `$ScriptToRun` at the top:
```powershell
$ScriptToRun = "👀Check for Unauthorized Remote Access Tools.ps1"
```
3. Deploy to Level.io

### Version Pinning

Set the custom field `coolforge_pin_psmodule_to_version` to a release tag (e.g., `v2025.12.29`) to pin all devices to a specific version.

---

## Scripts

Scripts are organized by category in `scripts/`:

### Check Scripts (`scripts/Check/`)

Inspection and monitoring scripts prefixed with `👀`:

| Script | Description |
|--------|-------------|
| `👀Check for Unauthorized Remote Access Tools.ps1` | Detects 60+ remote access tools with whitelisting |
| `👀huntress.ps1` | Check Huntress agent installation status |
| `👀unchecky.ps1` | Check Unchecky installation status |
| `👀Test Show Versions.ps1` | Display version information |
| `👀Test Variable Output.ps1` | Test Level.io variable passing |
| `👀debug.ps1` | Debug script for testing and troubleshooting |

### Fix Scripts (`scripts/Fix/`)

Repair and configuration scripts prefixed with `🔧`:

| Script | Description |
|--------|-------------|
| `🔧Prevent Sleep.ps1` | Temporarily disable sleep/hibernate with auto-restore |
| `🔧Enable System Restore and Create Restore Point.ps1` | Enable System Restore and create checkpoint |
| `🔧Fix Windows 11 Services.ps1` | Fix common Windows 11 service issues |
| `🔧Fix Windows 10 Services.ps1` | Fix common Windows 10 service issues |
| `🔧Fix Windows 8.1 Services.ps1` | Fix common Windows 8.1 service issues |
| `🔧Fix Windows 8 Services.ps1` | Fix common Windows 8 service issues |
| `🔧Fix Windows 7 Services.ps1` | Fix common Windows 7 service issues |

### Remove Scripts (`scripts/Remove/`)

Software removal scripts prefixed with `⛔`:

| Script | Description |
|--------|-------------|
| `⛔Force Remove Adobe Creative Cloud.ps1` | Forcefully remove Adobe CC (6-phase removal with official cleaner tool) |
| `⛔Force Remove Anydesk.ps1` | Forcefully remove AnyDesk (5-phase removal) |
| `⛔Force Remove Non MSP ScreenConnect.ps1` | Remove unauthorized ScreenConnect instances |

**Removal Phases**:
1. Standard uninstall via registry
2. Stop services and processes
3. Remove files and folders
4. Clean registry entries
5. Remove firewall rules and scheduled tasks

### Configure Scripts (`scripts/Configure/`)

Configuration scripts prefixed with `⚙️`:

| Script | Description |
|--------|-------------|
| `⚙️Extract and Set ScreenConnect Device URL.ps1` | Extract ScreenConnect GUID and set device URL custom field |

### Utility Scripts (`scripts/Utility/`)

Helper scripts prefixed with `🙏`:

| Script | Description |
|--------|-------------|
| `🙏Wake all devices in parent to level.io folder.ps1` | Send WOL packets to all devices in folder hierarchy |
| `🔔Technician Alert Monitor.ps1` | Monitor and display technician alerts |

---

## Tools

Administrative tools in `tools/`:

### Setup & Configuration

| Tool | Description |
|------|-------------|
| `Setup-COOLForge.ps1` | Interactive setup wizard for custom fields |
| `Generate-CustomFieldsConfig.ps1` | Generate custom field configuration |
| `Add-COOLForgeCustomField.ps1` | Add individual custom field |
| `Sync-COOLForgeCustomFields.ps1` | Sync custom fields from definitions |

### Backup & Export

| Tool | Description |
|------|-------------|
| `Backup-COOLForgeCustomFields.ps1` | Backup/restore custom field values |
| `Backup-LevelAutomationsAndScripts.ps1` | Backup Level.io automations via GraphQL (with token refresh) |
| `Export-DeviceCustomFields.ps1` | Export device custom fields to CSV |
| `Get-FullDeviceLevelCustomFields.ps1` | Get complete custom field data |

### ScreenConnect

| Tool | Description |
|------|-------------|
| `Get-DeviceScreenConnectUrl.ps1` | Get ScreenConnect URL for device |
| `Get-ScreenConnectUrls.ps1` | Batch get ScreenConnect URLs |

### Maintenance

| Tool | Description |
|------|-------------|
| `Update-Launchers.ps1` | Update all launchers from template |
| `Generate-MD5SUMS.ps1` | Regenerate MD5SUMS file |
| `Generate-WorkflowCharts.ps1` | Generate Mermaid workflow diagrams |

### Analysis

| Tool | Description |
|------|-------------|
| `Analyze-LevelBackup.ps1` | Analyze Level.io backup and generate summary |
| `Test-LevelApiCustomFields.ps1` | Test Level.io API custom field operations |
| `Wake-AllDevicesInFolder-Standalone.ps1` | Standalone WOL script |

### Development Tools (`tools/how-i-got-here/`)

Research and development scripts used to understand Level.io's internal APIs:

| Tool | Description |
|------|-------------|
| `Download-LevelScripts.ps1` | Download scripts from Level.io |
| `Extract-LevelAutomationsFromHAR.ps1` | Extract automations from HAR file |
| `Extract-LevelScriptsFromHAR.ps1` | Extract scripts from HAR file |
| `decode-id.ps1` | Decode Level.io IDs |
| `find-automation-queries.ps1` | Find GraphQL automation queries |
| `test-level-api.ps1` | Test Level.io API endpoints |

---

## Pre-Release Pipeline

Scripts in `pre-release/` for release preparation:

| Script | Description |
|--------|-------------|
| `Validate-Release.ps1` | Comprehensive validation before release |
| `Update-MD5SUMS.ps1` | Regenerate MD5SUMS checksums |
| `Update-Launchers.ps1` | Update launchers from template |
| `Update-ScriptInventory.ps1` | Update script inventory cache |
| `Test-Syntax.ps1` | Validate PowerShell syntax |

### Validation Checks

`Validate-Release.ps1` performs:
1. Git status (clean working tree)
2. PowerShell syntax validation
3. MD5SUMS verification
4. Launcher version consistency
5. Launcher completeness (no orphans)
6. Emoji prefix validation
7. TODO comment detection
8. Required files check
9. Release tag suggestion

**Usage**:
```powershell
# Validate only
.\pre-release\Validate-Release.ps1

# Validate and auto-fix
.\pre-release\Validate-Release.ps1 -AutoFix

# Validate, fix, and create tag
.\pre-release\Validate-Release.ps1 -AutoFix -CreateTag
```

---

## Validation (`validation/`)

Tracked validation checks and code generators shared via git.

### Checks

| Script | Description | Critical |
|--------|-------------|----------|
| `check-syntax.ps1` | Parse all PS1 files for syntax errors | Yes |
| `check-bom.ps1` | Verify UTF-8 BOM on PS1/PSM1 files | Yes |
| `check-emoji-corruption.ps1` | Detect `??` and garbled emoji patterns | Yes |
| `check-launcher-fields.ps1` | Verify launchers declare needed policy vars | Yes |
| `check-orphans.ps1` | Find scripts without launchers and vice versa | No |
| `check-definitions.ps1` | Cross-ref `{{cf_*}}` usage against definitions | No |
| `check-psscriptanalyzer.ps1` | Run PSScriptAnalyzer linting | No |
| `check-all.ps1` | Orchestrator that runs all checks | - |

### Code Generators

| Script | Description |
|--------|-------------|
| `Generate-MD5SUMS.ps1` | Generate MD5SUMS file |
| `Update-Launchers.ps1` | Rebuild launchers from template |
| `Generate-CustomFieldsConfig.ps1` | Scan for `{{cf_*}}` usage, build config |
| `Create-New-Script.ps1` | Scaffold new script + launcher |

---

## Testing (`testing/`, gitignored)

Local-only test harnesses (require live API access/secrets):

| Script | Description |
|--------|-------------|
| `Test_Local.ps1` | Local testing without Level.io |
| `Test_From_Level.ps1` | Test as if running from Level.io |
| `Test_AutoUpdate_Dev.ps1` | Test auto-update functionality |
| `Test-ScreenConnectAPI.ps1` | Test ScreenConnect API integration |
| `Test-HuntressOrgProvisioning.ps1` | Test Huntress organization provisioning |

---

## Definitions & Configuration

### custom-fields.json

**Location**: `definitions/custom-fields.json`

Defines all COOLForge custom fields for Level.io:

```json
{
  "fields": {
    "core": [
      { "name": "coolforge_msp_scratch_folder", "required": true },
      { "name": "coolforge_ps_module_library_source", "required": false },
      { "name": "coolforge_pin_psmodule_to_version", "required": false },
      { "name": "coolforge_nosleep_duration_min", "default": "60" }
    ],
    "screenconnect": [
      { "name": "coolforge_screenconnect_instance_id", "adminOnly": true },
      { "name": "coolforge_screenconnect_baseurl" },
      { "name": "coolforge_screenconnect_api_user", "adminOnly": true },
      { "name": "coolforge_screenconnect_api_password", "adminOnly": true },
      { "name": "coolforge_screenconnect_device_url", "autoCreate": true }
    ],
    "technician_alerts": [
      { "name": "coolforge_technician_alerts" }
    ]
  }
}
```

### Legacy Field Support

Scripts support both new (`coolforge_*`) and legacy field names for backward compatibility:
- `coolforge_msp_scratch_folder` ← `msp_scratch_folder`
- `coolforge_ps_module_library_source` ← `ps_module_library_source`
- `coolforge_pin_psmodule_to_version` ← `pin_psmodule_to_version`

---

## Custom Fields

### Required Fields

| Field | Description | Example |
|-------|-------------|---------|
| `coolforge_msp_scratch_folder` | Persistent storage folder | `C:\ProgramData\COOLForge` |

### Optional Fields

| Field | Description | Example |
|-------|-------------|---------|
| `coolforge_ps_module_library_source` | Custom library URL | Leave empty for official |
| `coolforge_pin_psmodule_to_version` | Version pin | `v2025.12.29` |
| `coolforge_nosleep_duration_min` | Prevent sleep duration | `60` |
| `coolforge_screenconnect_baseurl` | ScreenConnect server URL | `support.example.com` |

### Admin-Only Fields

| Field | Description |
|-------|-------------|
| `coolforge_screenconnect_instance_id` | ScreenConnect instance ID for whitelisting |
| `coolforge_screenconnect_api_user` | ScreenConnect API username |
| `coolforge_screenconnect_api_password` | ScreenConnect API password |

### Auto-Created Fields

| Field | Description |
|-------|-------------|
| `coolforge_screenconnect_device_url` | Per-device ScreenConnect URL (populated by scripts) |

---

## Emoji Handling

### The Problem

Level.io corrupts UTF-8 emojis when passing them through its variable system. For example:
- Original: `🙏` (U+1F64F) = bytes `F0 9F 99 8F`
- Corrupted: becomes `≡ƒÖÅ` (bytes `E2 89 A1 C6 92 C3 96 C3 85`)

### The Solution

1. **`Get-EmojiMap`** in `COOLForge-Common.psm1` is the SINGLE SOURCE OF TRUTH
2. Contains both clean emojis and corrupted byte patterns
3. **`Get-SoftwarePolicy`** uses this map to match tags regardless of corruption

### Rules for Working with Emojis

1. **NEVER put emoji literals in comments** - they get corrupted
2. **Use Unicode references**: `# U+1F64F Pray emoji` not `# 🙏`
3. **All emoji matching goes through `Get-EmojiMap`**
4. **New patterns** discovered via `EmojiTags.log` should be added to `Get-EmojiMap`

### Adding New Emojis

1. Add clean emoji to `Get-EmojiMap`: `"🆕" = "NewAction"`
2. Deploy and check `EmojiTags.log` for corrupted pattern
3. Add corrupted pattern with byte array
4. Map both to same action

---

## File Structure

```
COOLForge/
├── modules/
│   └── COOLForge-Common.psm1        # Main shared library (includes admin tools)
├── templates/
│   ├── Launcher_Template.ps1        # Launcher template
│   └── What is this folder.md       # Scratch folder documentation
├── launchers/                        # Pre-configured launchers
│   ├── Alert/                       # 🔔 Notifications, wake devices
│   ├── Config/                      # ⚙️ Configuration, setup
│   ├── Fix/                         # 🔧 Repair, remediation
│   ├── Monitor/                     # 👀 Audits, compliance
│   ├── Policy/                      # 👀 Software policy enforcement
│   ├── Remove/                      # ⛔ Force removal
│   ├── Test/                        # 👀 Testing, debugging
│   └── Utility/                     # ⚙️ Cleanup, maintenance
├── scripts/
│   ├── Check/                        # 👀 Inspection scripts
│   ├── Fix/                          # 🔧 Repair scripts
│   ├── Remove/                       # ⛔ Removal scripts
│   ├── Configure/                    # ⚙️ Configuration scripts
│   └── Utility/                      # 🙏 Helper scripts
├── tools/                            # Administrative tools
│   └── how-i-got-here/              # Development/research tools
├── pre-release/                      # Release preparation scripts
├── validation/                       # Validation checks & code generators
├── testing/                          # Local-only test scripts (gitignored)
├── definitions/
│   └── custom-fields.json           # Custom field definitions
├── docs/                            # Documentation
├── MD5SUMS                          # Checksums and path resolution
└── .gitignore
```

---

## Version Information

- **Module Version**: 2026.01.27 (COOLForge-Common)
- **Launcher Version**: 2026.01.27
- **Last Documentation Update**: 2026-01-27

---

## Related Documentation

- [FUNCTIONS.md](FUNCTIONS.md) - Function reference
- [README.md](../README.md) - Getting started guide
- [TECHNICIAN-ALERTS.md](TECHNICIAN-ALERTS.md) - Technician alerts system
