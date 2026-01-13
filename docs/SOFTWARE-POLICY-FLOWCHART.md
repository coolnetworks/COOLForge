# Software Policy Flowchart

This document explains the COOLForge 5-Tag Policy Model using Unchecky as the example implementation.

---

## Overview

The Software Policy system allows you to manage software installations across your fleet using:
1. **Device Tags** - Quick overrides for individual devices
2. **Custom Field Policies** - Inherited rules from Group/Folder/Device hierarchy
3. **Automatic Tag Management** - Script updates tags to reflect actual state

---

## The 5-Tag Policy Model

Each managed software uses 5 tags with emoji prefixes:

| Tag | Emoji | Action | Persistence |
|-----|-------|--------|-------------|
| Install | `🙏unchecky` | Install if missing | Transient (removed after install) |
| Remove | `🚫unchecky` | Remove if present | Transient (removed after removal) |
| Pin | `📌unchecky` | No changes allowed | Transient (intent saved to custom field) |
| Reinstall | `🔄unchecky` | Remove + Install | Transient (removed after reinstall) |
| Has | `✅unchecky` | Status: installed | Persistent (managed by script) |

**Global Control Tags** (standalone, no software suffix):
- `✅` = Device is managed (required for any action)
- `❌` = Device is excluded from all management
- Both `✅` + `❌` = Device is globally pinned

---

## Complete Execution Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Level.io Scheduler triggers: "Unchecky Policy" script                      │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 1: LAUNCHER EXECUTION                                                 │
│                                                                             │
│  Launcher downloads from GitHub:                                            │
│  - COOLForge-Common.psm1 (library)                                         │
│  - scripts/SoftwarePolicy/unchecky.ps1 (this script)                       │
│                                                                             │
│  Passes variables:                                                          │
│  - $MspScratchFolder = "C:\ProgramData\MSP"                                │
│  - $DeviceHostname = "WORKSTATION01"                                       │
│  - $DeviceTags = "✅, 🙏unchecky, Production"                              │
│  - $policy_unchecky = "install"                                            │
│  - $LevelApiKey = "abc123..."                                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 2: SCRIPT INITIALIZATION                                              │
│                                                                             │
│  Initialize-LevelScript:                                                    │
│  ├─ Check blocking tags (❌, 🚫)                                           │
│  │   └─ If blocked → Exit 0 (skip silently)                                │
│  ├─ Create lockfile (prevent concurrent runs)                              │
│  └─ Setup logging                                                          │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 3: GLOBAL CONTROL CHECK                                               │
│                                                                             │
│  Does device have ✅ (checkmark) tag?                                       │
│  ├─ NO → Exit (device not managed)                                         │
│  └─ YES → Continue                                                         │
│                                                                             │
│  Does device have ❌ (X) tag?                                               │
│  ├─ YES + ✅ → Device is globally pinned (no changes)                       │
│  ├─ YES only → Device excluded from management                             │
│  └─ NO → Continue to policy resolution                                     │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 4: POLICY RESOLUTION (Priority Order)                                 │
│                                                                             │
│  Get-SoftwarePolicy checks in order:                                       │
│                                                                             │
│  1. SOFTWARE-SPECIFIC TAGS (highest priority)                              │
│     ├─ 📌unchecky → Pin (no changes)                                       │
│     ├─ 🔄unchecky → Reinstall                                              │
│     ├─ 🚫unchecky → Remove                                                 │
│     ├─ 🙏unchecky → Install                                                │
│     └─ ✅unchecky → Has (status only)                                      │
│                                                                             │
│  2. CUSTOM FIELD POLICY (if no tag override)                               │
│     └─ policy_unchecky = "install" | "remove" | "pin" | ""                 │
│                                                                             │
│  3. DEFAULT (if neither)                                                   │
│     └─ No action                                                           │
│                                                                             │
│  Output: ResolvedAction = Install | Remove | Reinstall | Pin | None        │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 5: INSTALLATION STATE CHECK                                           │
│                                                                             │
│  Test-UncheckyInstalled checks:                                            │
│  - File paths:                                                             │
│    - C:\Program Files\Unchecky\unchecky.exe                               │
│    - C:\Program Files (x86)\Unchecky\unchecky.exe                         │
│  - Registry keys:                                                          │
│    - HKLM:\SOFTWARE\...\Uninstall\Unchecky                                 │
│                                                                             │
│  Result: IsInstalled = $true | $false                                      │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 6: ACTION EXECUTION                                                   │
│                                                                             │
│  Based on ResolvedAction + IsInstalled:                                    │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  INSTALL action:                                                     │   │
│  │  ├─ Already installed? → Skip (log success)                         │   │
│  │  └─ Not installed? →                                                │   │
│  │      1. Download installer from policy_unchecky_url                 │   │
│  │      2. Validate file size (>1MB)                                   │   │
│  │      3. Run: unchecky_setup.exe -install -no_desktop_icon           │   │
│  │      4. Verify installation succeeded                               │   │
│  │      5. Cleanup installer                                           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  REMOVE action:                                                      │   │
│  │  ├─ Not installed? → Skip (log success)                             │   │
│  │  └─ Installed? →                                                    │   │
│  │      1. Find uninstall.exe in install folder                        │   │
│  │      2. Copy to temp (required for uninstall)                       │   │
│  │      3. Run: uninstall.exe -uninstall -path "..." -delsettings 1    │   │
│  │      4. Verify removal succeeded                                    │   │
│  │      5. Cleanup temp folder                                         │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  REINSTALL action:                                                   │   │
│  │  1. Run REMOVE action                                               │   │
│  │  2. Run INSTALL action                                              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  PIN action:                                                         │   │
│  │  - Log "Pinned - no changes allowed"                                │   │
│  │  - Save intent to device custom field                               │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  Result: ActionSuccess = $true | $false                                    │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 7: TAG MANAGEMENT                                                     │
│                                                                             │
│  After successful action, update tags via Level.io API:                    │
│                                                                             │
│  ┌───────────────┬─────────────────────────────────────────────────────┐   │
│  │ Action        │ Tag Changes                                         │   │
│  ├───────────────┼─────────────────────────────────────────────────────┤   │
│  │ Install       │ Remove 🙏unchecky, Add ✅unchecky                   │   │
│  │ Remove        │ Remove 🚫unchecky, Remove ✅unchecky                │   │
│  │ Reinstall     │ Remove 🔄unchecky, Add ✅unchecky                   │   │
│  │ Pin           │ Remove 📌unchecky (intent saved to custom field)    │   │
│  │ None          │ Reconcile ✅unchecky with actual install state      │   │
│  └───────────────┴─────────────────────────────────────────────────────┘   │
│                                                                             │
│  Note: Transient tags (🙏🚫🔄📌) are removed after action completes.       │
│  The ✅unchecky (Has) tag persists to show current install state.          │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 8: EXIT                                                               │
│                                                                             │
│  ├─ ActionSuccess = $true → Exit 0 (Success - green in Level.io)           │
│  └─ ActionSuccess = $false → Exit 1 (Alert - red in Level.io)              │
│                                                                             │
│  Cleanup: Remove lockfile                                                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Policy Resolution Decision Tree

```
START: Device has tags ["✅", "🙏unchecky", "Production"]
│
├─► Has ✅ (managed)?
│   ├─ NO → EXIT: Device not managed
│   └─ YES ↓
│
├─► Has ❌ (excluded)?
│   ├─ YES + ✅ → EXIT: Globally pinned
│   ├─ YES only → EXIT: Excluded
│   └─ NO ↓
│
├─► Has 📌unchecky (pin)?
│   ├─ YES → ACTION: Pin (no changes)
│   └─ NO ↓
│
├─► Has 🔄unchecky (reinstall)?
│   ├─ YES → ACTION: Reinstall
│   └─ NO ↓
│
├─► Has 🚫unchecky (remove)?
│   ├─ YES → ACTION: Remove
│   └─ NO ↓
│
├─► Has 🙏unchecky (install)?
│   ├─ YES → ACTION: Install         ← This example triggers here
│   └─ NO ↓
│
├─► Has policy_unchecky custom field?
│   ├─ "install" → ACTION: Install
│   ├─ "remove" → ACTION: Remove
│   ├─ "pin" → ACTION: Pin
│   └─ "" or missing ↓
│
└─► ACTION: None (no policy)
```

---

## Tag Lifecycle Example

### Scenario: Install Unchecky on a new device

```
BEFORE: Device tags = ["✅", "Production"]
        policy_unchecky = "install" (inherited from Group)
        Unchecky = Not installed

Script runs:
├─ Global check: Has ✅ → Managed
├─ Tag check: No override tags
├─ Custom field: policy_unchecky = "install"
├─ Install state: Not installed
├─ Action: Download and install Unchecky
└─ Success!

AFTER:  Device tags = ["✅", "Production", "✅unchecky"]
        Unchecky = Installed
```

### Scenario: Override with Install tag

```
BEFORE: Device tags = ["✅", "🙏unchecky"]
        policy_unchecky = "" (no policy)
        Unchecky = Not installed

Script runs:
├─ Global check: Has ✅ → Managed
├─ Tag check: 🙏unchecky → Install action
├─ Action: Download and install Unchecky
├─ Update tags: Remove 🙏unchecky, Add ✅unchecky
└─ Success!

AFTER:  Device tags = ["✅", "✅unchecky"]
        Unchecky = Installed
```

### Scenario: Remove Unchecky

```
BEFORE: Device tags = ["✅", "🚫unchecky", "✅unchecky"]
        Unchecky = Installed

Script runs:
├─ Global check: Has ✅ → Managed
├─ Tag check: 🚫unchecky → Remove action
├─ Action: Uninstall Unchecky
├─ Update tags: Remove 🚫unchecky, Remove ✅unchecky
└─ Success!

AFTER:  Device tags = ["✅"]
        Unchecky = Not installed
```

---

## Custom Field Inheritance

```
Organization Level (Level.io tenant)
│
├── Group: "All Clients"
│   └── policy_unchecky = ""  (no default)
│
├── Group: "Acme Corp"
│   ├── policy_unchecky = "install"  ← All Acme devices get Unchecky by default
│   │
│   ├── Folder: "Workstations"
│   │   └── (inherits "install" from parent)
│   │
│   └── Folder: "Servers"
│       └── policy_unchecky = "remove"  ← Override: No Unchecky on servers
│
└── Group: "Personal Clients"
    └── policy_unchecky = ""  (no action)
```

**Inheritance Priority:**
1. Device custom field (highest)
2. Folder custom field
3. Group custom field
4. Organization default

---

## File System Layout

```
C:\ProgramData\MSP\                    (MspScratchFolder)
├── Libraries\
│   └── COOLForge-Common.psm1          Library module
├── Scripts\
│   └── unchecky.ps1                   Cached script
├── Installers\
│   └── unchecky_setup.exe             Downloaded installer (temp)
└── lockfiles\
    └── Policy-unchecky.lock           Active lockfile
```

---

## Required Custom Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `coolforge_msp_scratch_folder` | Text | Yes | Base folder for library/scripts/installers |
| `policy_unchecky` | Text | No | Policy: "install", "remove", "pin", or "" |
| `policy_unchecky_url` | Text | For Install | URL to hosted installer |
| `coolforge_api_key` | Text | For Tags | Level.io API key for tag management |

---

## Setting Up Unchecky Policy

### 1. Create Custom Fields

```powershell
# Run Setup-COOLForge.ps1 or create manually:
# - policy_unchecky (Text)
# - policy_unchecky_url (Text)
```

### 2. Host the Installer

1. Download from https://www.fosshub.com/Unchecky.html
2. Upload to your own hosting (S3, Azure Blob, web server)
3. Set `policy_unchecky_url` to your hosted URL

### 3. Set Policy at Group/Folder Level

```
Acme Corp (Group)
├── policy_unchecky = "install"
└── Servers (Folder)
    └── policy_unchecky = "remove"
```

### 4. Deploy the Launcher

Copy `launchers/unchecky.ps1` to Level.io with:
- Schedule: Daily or on-demand
- Target: Groups/Folders with policy set

---

## Troubleshooting

### Device not processing?

1. **Check for ✅ tag** - Device must have the checkmark tag to be managed
2. **Check for ❌ tag** - Excluded devices are skipped
3. **Check blocking tags** - 🚫 blocks all scripts

### Tags not updating?

1. **Check API key** - `coolforge_api_key` must be set
2. **Check device hostname** - Must match Level.io device name
3. **Enable debug** - Set `cf_debug_scripts = true` for detailed output

### Install failing?

1. **Check URL** - `policy_unchecky_url` must be set and accessible
2. **Check file size** - Download validates installer is > 1MB
3. **Check exit code** - Installer exit code 0 = success

---

## See Also

- [POLICY-TAGS.md](POLICY-TAGS.md) - Complete policy tag specification
- [LAUNCHER-FLOWCHART.md](LAUNCHER-FLOWCHART.md) - How launchers work
- [WHY.md](WHY.md) - Section 13: Software Policy Chaos
- [unchecky.ps1](../scripts/SoftwarePolicy/👀unchecky.ps1) - Implementation
