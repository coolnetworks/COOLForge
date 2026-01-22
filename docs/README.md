# COOLForge Documentation Index

Complete documentation for the COOLForge PowerShell automation framework for Level.io RMM.

**Last Updated:** 2026-01-22

---

## Quick Links

| I want to... | Go to... |
|--------------|----------|
| Understand why COOLForge exists | [WHY.md](WHY.md) |
| Get started quickly | [Main README](../README.md#quick-start) |
| Set up COOLForge | [Main README - Start Here](../README.md#start-here) |
| Find a specific function | [FUNCTIONS.md](FUNCTIONS.md) |
| Understand the architecture | [CODEBASE.md](CODEBASE.md) |
| Learn about software policies | [Policy Documentation](policy/README.md) |
| See all scripts | [Script Documentation](scripts/README.md) |

---

## Getting Started

| Document | Description |
|----------|-------------|
| [WHY.md](WHY.md) | **Start here** - Problems COOLForge solves |
| [WHY-COOLFORGE.md](WHY-COOLFORGE.md) | Design philosophy and architecture decisions |
| [Main README](../README.md) | Quick start guide and overview |

---

## Technical Reference

### Core Documentation

| Document | Description |
|----------|-------------|
| [CODEBASE.md](CODEBASE.md) | Complete architecture and module organization (107 functions) |
| [FUNCTIONS.md](FUNCTIONS.md) | Detailed function reference with parameters and examples |
| [VARIABLES.md](VARIABLES.md) | Level.io variables and automation variables reference |
| [POLICY-FIELDS.md](POLICY-FIELDS.md) | Policy field system explanation |

### Launcher System

| Document | Description |
|----------|-------------|
| [LAUNCHER.md](LAUNCHER.md) | How the script launcher system works |
| [LAUNCHER-FLOWCHART.md](LAUNCHER-FLOWCHART.md) | Visual flowcharts (Mermaid diagrams) |
| [VERSION-PINNING.md](VERSION-PINNING.md) | Pin devices to specific library versions |
| [PRIVATE-FORK.md](PRIVATE-FORK.md) | Using COOLForge with private GitHub repos |

### Emoji & Encoding

| Document | Description |
|----------|-------------|
| [EMOJI-HANDLING.md](EMOJI-HANDLING.md) | UTF-8 emoji handling and corruption patterns |

### Level.io API

| Document | Description |
|----------|-------------|
| [LEVEL-API-CUSTOM-FIELDS.md](LEVEL-API-CUSTOM-FIELDS.md) | Custom field creation via API |

---

## Feature Documentation

| Document | Description |
|----------|-------------|
| [TECHNICIAN-ALERTS.md](TECHNICIAN-ALERTS.md) | Toast notification system for technician workstations |
| [WOL.md](WOL.md) | Wake-on-LAN functionality |

---

## Script Documentation

### By Category

| Category | Index | Description |
|----------|-------|-------------|
| **Policy Scripts** | [policy/README.md](policy/README.md) | Tag-based software policy enforcement |
| **All Scripts** | [scripts/README.md](scripts/README.md) | Complete script index |

### Policy Scripts

| Script | Documentation |
|--------|---------------|
| Unchecky | [policy/Unchecky.md](policy/Unchecky.md) |
| Huntress | [policy/Huntress.md](policy/Huntress.md) |
| DNSFilter | [policy/DNSFilter.md](policy/DNSFilter.md) |
| Chrome | [policy/Chrome.md](policy/Chrome.md) |
| Windows Services | [policy/Windows.md](policy/Windows.md) |
| Debug | [policy/Debug.md](policy/Debug.md) |
| Creating New Scripts | [policy/CREATING-SCRIPTS.md](policy/CREATING-SCRIPTS.md) |
| Tag System | [policy/TAGS.md](policy/TAGS.md) |

### Individual Script Docs

| Script | Documentation |
|--------|---------------|
| RAT Detection | [scripts/RAT-Detection.md](scripts/RAT-Detection.md) |
| Force Remove AnyDesk | [scripts/Force-Remove-AnyDesk.md](scripts/Force-Remove-AnyDesk.md) |
| Force Remove ScreenConnect | [scripts/Force-Remove-Non-MSP-ScreenConnect.md](scripts/Force-Remove-Non-MSP-ScreenConnect.md) |
| Fix Windows Services | [scripts/Fix-Windows-Services.md](scripts/Fix-Windows-Services.md) |
| Prevent Sleep | [scripts/Prevent-Sleep.md](scripts/Prevent-Sleep.md) |
| System Restore | [scripts/System-Restore.md](scripts/System-Restore.md) |
| ScreenConnect Device URL | [scripts/ScreenConnect-Device-URL.md](scripts/ScreenConnect-Device-URL.md) |
| Wake Devices | [scripts/Wake-Devices.md](scripts/Wake-Devices.md) |
| Technician Alert Monitor | [scripts/Technician-Alert-Monitor.md](scripts/Technician-Alert-Monitor.md) |
| Test Show Versions | [scripts/Test-Show-Versions.md](scripts/Test-Show-Versions.md) |
| Test Variable Output | [scripts/Test-Variable-Output.md](scripts/Test-Variable-Output.md) |

---

## Project Documentation

| Document | Description |
|----------|-------------|
| [FOLDER-STRUCTURE.md](FOLDER-STRUCTURE.md) | Script category organization |
| [RELEASE-WORKFLOW.md](RELEASE-WORKFLOW.md) | Dev vs main releases, testing |
| [../RELEASING.md](../RELEASING.md) | Release process guide |
| [../CHANGELOG.md](../CHANGELOG.md) | Version history |
| [../TODO.md](../TODO.md) | Project roadmap |
| [../NEEDS_TESTING.md](../NEEDS_TESTING.md) | Features requiring validation |

---

## Function Categories

The COOLForge-Common module exports **107 functions** organized into these categories:

| Category | Count | Key Functions |
|----------|-------|---------------|
| **Initialization** | 5 | `Initialize-LevelScript`, `Invoke-LevelScript`, `Complete-LevelScript` |
| **Logging** | 1 | `Write-LevelLog` |
| **System Info** | 2 | `Test-LevelAdmin`, `Get-LevelDeviceInfo` |
| **Software Detection** | 8 | `Test-SoftwareInstalled`, `Stop-SoftwareProcesses`, `Install-MsiWithRetry` |
| **Software Policy** | 5 | `Get-SoftwarePolicy`, `Get-EmojiMap`, `Invoke-SoftwarePolicyCheck` |
| **Level.io API** | 10 | `Invoke-LevelApiCall`, `Get-LevelDevices`, `Find-LevelDevice` |
| **Tag Management** | 8 | `Add-LevelTagToDevice`, `Remove-LevelTagFromDevice`, `New-LevelTag` |
| **Custom Fields** | 10 | `Get-LevelCustomFields`, `Set-LevelCustomFieldValue`, `Initialize-COOLForgeInfrastructure` |
| **Cache Management** | 18 | `Get-LevelCacheValue`, `Set-LevelCacheValue`, `Get-CachedDeviceTags` |
| **Hierarchy** | 4 | `Get-LevelOrganizations`, `Get-LevelFolderDevices` |
| **Technician Alerts** | 5 | `Add-TechnicianAlert`, `Send-TechnicianAlert` |
| **Network** | 1 | `Send-LevelWakeOnLan` |
| **Text Processing** | 3 | `Repair-LevelEmoji`, `Get-LevelUrlEncoded` |
| **Config & Backup** | 14 | `Get-SavedConfig`, `Backup-AllCustomFields` |
| **UI Helpers** | 8 | `Write-Header`, `Read-UserInput`, `Write-DebugSection` |
| **Script Launcher** | 5 | `Get-ScriptPathFromMD5`, `Invoke-ScriptLauncher` |

See [FUNCTIONS.md](FUNCTIONS.md) for complete documentation.

---

## Directory Structure

```
docs/
+-- README.md                  # This index file
+-- CODEBASE.md                # Technical architecture
+-- FUNCTIONS.md               # Function reference
+-- VARIABLES.md               # Level.io variables
+-- POLICY-FIELDS.md           # Policy field system
+-- LAUNCHER.md                # Launcher system
+-- LAUNCHER-FLOWCHART.md      # Visual diagrams
+-- EMOJI-HANDLING.md          # UTF-8 emoji handling
+-- TECHNICIAN-ALERTS.md       # Alert system
+-- WOL.md                     # Wake-on-LAN
+-- VERSION-PINNING.md         # Version pinning
+-- PRIVATE-FORK.md            # Private repos
+-- RELEASE-WORKFLOW.md        # Release process
+-- FOLDER-STRUCTURE.md        # Script organization
+-- LEVEL-API-CUSTOM-FIELDS.md # API field creation
+-- WHY.md                     # Why COOLForge
+-- WHY-COOLFORGE.md           # Design philosophy
+-- policy/                    # Policy system docs
|   +-- README.md              # Policy overview
|   +-- CREATING-SCRIPTS.md    # How to create policy scripts
|   +-- TAGS.md                # Tag system
|   +-- Unchecky.md
|   +-- Huntress.md
|   +-- DNSFilter.md
|   +-- Chrome.md
|   +-- Windows.md
|   +-- Debug.md
+-- scripts/                   # Per-script docs
    +-- README.md              # Script index
    +-- RAT-Detection.md
    +-- Force-Remove-AnyDesk.md
    +-- Force-Remove-Non-MSP-ScreenConnect.md
    +-- Fix-Windows-Services.md
    +-- Prevent-Sleep.md
    +-- System-Restore.md
    +-- ScreenConnect-Device-URL.md
    +-- Wake-Devices.md
    +-- Technician-Alert-Monitor.md
    +-- Test-Show-Versions.md
    +-- Test-Variable-Output.md
```
