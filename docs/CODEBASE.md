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

#### Software Policy System

| Function | Description |
|----------|-------------|
| `Get-EmojiMap` | Returns centralized emoji-to-action mapping (single source of truth) |
| `Get-SoftwarePolicy` | Parses device tags for software policy requirements |
| `Invoke-SoftwarePolicyCheck` | High-level policy check with formatted output |

**Policy Emojis**:
| Emoji | Action | Description |
|-------|--------|-------------|
| `🙏` | Install | Request/recommend installation |
| `⛔` | Remove | Remove if present |
| `🚫`/`🛑` | Block | Block install, leave existing |
| `📌` | Pin | Lock state (blocks install AND remove) |
| `✅` | Has | Installed/verified status |
| `❌` | Skip | Hands off (managed elsewhere) |
| `👀` | Verify | Check and report |

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

#### Tag Management

| Function | Description |
|----------|-------------|
| `Get-LevelTags` | Fetch all tags with pagination |
| `Find-LevelTag` | Find tag by name |
| `Add-LevelTagToDevice` | Add tag to device |
| `Remove-LevelTagFromDevice` | Remove tag from device |
| `Add-LevelPolicyTag` | High-level: Add policy tag (e.g., add "Has" after install) |
| `Remove-LevelPolicyTag` | High-level: Remove policy tag |

#### Wake-on-LAN

| Function | Description |
|----------|-------------|
| `Send-LevelWakeOnLan` | Send WOL magic packet to MAC address |

#### Text Processing

| Function | Description |
|----------|-------------|
| `Repair-LevelEmoji` | Repairs corrupted UTF-8 emojis in strings |
| `Get-LevelUrlEncoded` | URL-encode with proper UTF-8 emoji handling |

---

### COOLForge-CustomFields.psm1

**Location**: `modules/COOLForge-CustomFields.psm1`

Module for managing Level.io custom fields via the API. Used by setup and backup tools.

#### Key Functions

| Category | Functions |
|----------|-----------|
| **Initialization** | `Initialize-COOLForgeCustomFields` |
| **UI Helpers** | `Write-Header`, `Write-LevelSuccess`, `Write-LevelInfo`, `Write-LevelWarning`, `Write-LevelError`, `Read-UserInput`, `Read-YesNo` |
| **API Core** | `Invoke-LevelApi`, `Get-ExistingCustomFields`, `Find-CustomField`, `New-CustomField`, `Update-CustomFieldValue`, `Remove-CustomField` |
| **Hierarchy** | `Get-AllOrganizations`, `Get-OrganizationFolders`, `Get-FolderDevices`, `Get-EntityCustomFields`, `Set-EntityCustomField` |
| **Backup/Restore** | `Backup-AllCustomFields`, `Save-Backup`, `Import-Backup`, `Restore-CustomFields`, `Compare-BackupWithCurrent` |
| **Security** | `Protect-ApiKey` (DPAPI), `Unprotect-ApiKey` |
| **GitHub** | `Get-GitHubReleases`, `Show-ReleaseNotes`, `Select-Version` |

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
| `Setup-COOLForgeCustomFields.ps1` | Interactive setup wizard for custom fields |
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
| `Remove-LegacyCustomFields.ps1` | Clean up legacy custom field names |

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

## Testing

Test scripts in `testing/`:

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
│   ├── COOLForge-Common.psm1        # Main shared library
│   └── COOLForge-CustomFields.psm1  # Custom fields API module
├── templates/
│   ├── Launcher_Template.ps1        # Launcher template
│   └── What is this folder.md       # Scratch folder documentation
├── launchers/                        # Pre-configured launchers
├── scripts/
│   ├── Check/                        # 👀 Inspection scripts
│   ├── Fix/                          # 🔧 Repair scripts
│   ├── Remove/                       # ⛔ Removal scripts
│   ├── Configure/                    # ⚙️ Configuration scripts
│   └── Utility/                      # 🙏 Helper scripts
├── tools/                            # Administrative tools
│   └── how-i-got-here/              # Development/research tools
├── pre-release/                      # Release preparation scripts
├── testing/                          # Test scripts
├── definitions/
│   └── custom-fields.json           # Custom field definitions
├── docs/                            # Documentation
├── MD5SUMS                          # Checksums and path resolution
└── .gitignore
```

---

## Version Information

- **Module Version**: 2026.01.08.01
- **Launcher Version**: 2026.01.10.01
- **Custom Fields Version**: 2026.01.10

---

## Related Documentation

- [FUNCTIONS.md](FUNCTIONS.md) - Function reference
- [README.md](../README.md) - Getting started guide
- [TECHNICIAN-ALERTS.md](TECHNICIAN-ALERTS.md) - Technician alerts system
