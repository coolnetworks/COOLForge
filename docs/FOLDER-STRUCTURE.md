# Folder Structure

COOLForge organizes scripts and launchers into logical categories for easier management and discovery.

---

## Launcher Categories

Launchers are organized into these folders:

| Folder | Emoji | Purpose | Examples |
|--------|-------|---------|----------|
| `Policy/` | 👀 | Software policy enforcement (install/remove/pin) | chrome, huntress, dnsfilter, unchecky |
| `Remove/` | ⛔ | Force removal scripts | Force Remove AnyDesk, Force Remove Adobe CC |
| `Monitor/` | 👀 | Read-only audits, compliance checks | Check DNS Compliance, Check for RATs |
| `Fix/` | 🔧 | Repair broken things, remediation | Fix Windows Services, Ensure Defender Enabled |
| `Alert/` | 🔔 | Notifications, wake devices | Technician Alert Monitor, Wake Devices |
| `Config/` | ⚙️ | Configuration, setup | Configure Wake-on-LAN, Prevent Sleep |
| `Test/` | 👀 | Testing, debugging | Test Show Versions, Test Variable Output |
| `Utility/` | ⚙️ | Cleanup, maintenance | Disk Cleaner, VoyagerPACS Cleanup |

---

## Script Categories

Scripts mirror the launcher structure:

| Folder | Purpose |
|--------|---------|
| `scripts/Policy/` | Software policy enforcement scripts |
| `scripts/Remove/` | Force removal scripts |
| `scripts/Check/` | Audit and compliance scripts |
| `scripts/Fix/` | Repair and remediation scripts |
| `scripts/Configure/` | Configuration scripts |
| `scripts/Utility/` | Utility and maintenance scripts |

---

## Complete Folder Structure

```
COOLForge/
├── launchers/
│   ├── Alert/           # 🔔 Notifications, wake devices
│   │   ├── 🔔Technician Alert Monitor.ps1
│   │   ├── 🔔Wake tagged devices.ps1
│   │   └── 🙏Wake all devices in Level group.ps1
│   ├── Config/          # ⚙️ Configuration, setup
│   │   ├── ⚙️Configure Wake-on-LAN.ps1
│   │   ├── ⚙️COOLForge Cache Sync.ps1
│   │   ├── ⚙️Extract and Set ScreenConnect Device URL.ps1
│   │   └── 🔧Prevent Sleep.ps1
│   ├── Fix/             # 🔧 Repair, remediation
│   │   ├── 🔧Enable System Restore and Create Restore Point.ps1
│   │   ├── 🔧Ensure Windows Defender Enabled.ps1
│   │   ├── 🔧Fix Windows 10 Services.ps1
│   │   ├── 🔧Fix Windows 11 Services.ps1
│   │   ├── 🔧Fix Windows 7 Services.ps1
│   │   ├── 🔧Fix Windows 8 Services.ps1
│   │   ├── 🔧Fix Windows 8.1 Services.ps1
│   │   └── 🔧Fix Windows Location Services.ps1
│   ├── Monitor/         # 👀 Audits, compliance
│   │   ├── 👀Check DNS Server Compliance.ps1
│   │   ├── 👀Check for Unauthorized Remote Access Tools.ps1
│   │   └── 👀Check Windows Location Services.ps1
│   ├── Policy/          # 👀 Software policy enforcement
│   │   ├── 👀chrome.ps1
│   │   ├── 👀debug.ps1
│   │   ├── 👀dnsfilter.ps1
│   │   ├── 👀Hostname Mismatch.ps1
│   │   ├── 👀huntress.ps1
│   │   ├── 👀meshcentral.ps1
│   │   ├── 👀screenconnect.ps1
│   │   ├── 👀unchecky.ps1
│   │   ├── Chrome/
│   │   │   └── 👀Chrome Location Services.ps1
│   │   └── Windows/
│   │       └── 👀Windows Location Services.ps1
│   ├── Remove/          # ⛔ Force removal
│   │   ├── ⛔Force Remove Adobe Creative Cloud.ps1
│   │   ├── ⛔Force Remove Anydesk.ps1
│   │   └── ⛔Force Remove Non MSP ScreenConnect.ps1
│   ├── Test/            # 👀 Testing, debugging
│   │   ├── 👀Test Show Versions.ps1
│   │   └── 👀Test Variable Output.ps1
│   └── Utility/         # ⚙️ Cleanup, maintenance
│       ├── ⚙️Cleanup VoyagerPACS Studies.ps1
│       └── ⚙️Universal Disk Cleaner.ps1
├── scripts/
│   ├── Policy/          # Software policy scripts
│   ├── Remove/          # Force removal scripts
│   ├── Check/           # Audit scripts
│   ├── Fix/             # Repair scripts
│   ├── Configure/       # Configuration scripts
│   └── Utility/         # Utility scripts
├── modules/
│   └── COOLForge-Common.psm1   # Shared library
├── templates/
│   ├── Slim-Launcher.ps1       # Launcher template
│   ├── Script_Template.ps1     # Standalone script template
│   └── SoftwarePolicy-Template.ps1  # Policy script template
├── tools/
│   ├── Update-MD5SUMS.ps1      # Regenerate checksums
│   └── New-PolicyScript.ps1    # Scaffolding tool
├── definitions/
│   ├── custom-fields.json      # Custom field definitions
│   └── tags.json               # Tag definitions
├── docs/
│   ├── scripts/                # Script documentation
│   └── policy/                 # Policy documentation
├── MD5SUMS                     # File checksums
└── LAUNCHER-VERSIONS.json      # Launcher version tracking
```

---

## How the Launcher Finds Scripts

The launcher uses the `MD5SUMS` file to locate scripts in subfolders:

1. Launcher receives script name (e.g., `Remove/⛔Force Remove Adobe Creative Cloud.ps1`)
2. Downloads `MD5SUMS` from the repository
3. Searches for matching path in MD5SUMS entries
4. Extracts the full path (e.g., `scripts/Remove/⛔Force Remove Adobe Creative Cloud.ps1`)
5. Downloads from the correct location

This means:
- Launchers specify the subfolder path in `$ScriptToRun`
- Moving scripts requires updating the launcher's `$ScriptToRun` and `$LauncherName`
- `MD5SUMS` is regenerated automatically by `tools/Update-MD5SUMS.ps1`

---

## Creating a New Script

### Step 1: Choose the Category

Pick the appropriate folder based on what your script does:

| Script Does... | Put In |
|----------------|--------|
| Install/remove/manage software | `scripts/Policy/` + `launchers/Policy/` |
| Force remove stubborn software | `scripts/Remove/` + `launchers/Remove/` |
| Check/audit without changes | `scripts/Check/` + `launchers/Monitor/` |
| Fix/repair something broken | `scripts/Fix/` + `launchers/Fix/` |
| Configure settings | `scripts/Configure/` + `launchers/Config/` |
| Cleanup/maintenance | `scripts/Utility/` + `launchers/Utility/` |
| Alerts/notifications | `scripts/Utility/` + `launchers/Alert/` |

### Step 2: Create the Script

1. Copy `templates/Script_Template.ps1` to the appropriate `scripts/` subfolder
2. Rename with appropriate emoji prefix
3. Implement your logic inside the `Invoke-LevelScript` block

### Step 3: Create the Launcher

1. Copy an existing launcher from the appropriate `launchers/` subfolder
2. Update `$ScriptToRun` to point to your script (include subfolder path)
3. Update `$LauncherName` to match the launcher's location

### Step 4: Update Metadata

```powershell
# Regenerate MD5SUMS
.\tools\Update-MD5SUMS.ps1

# Add to LAUNCHER-VERSIONS.json manually if needed
```

### Step 5: Deploy to Level.io

Copy the launcher content into a new Level.io script and deploy.

---

## Naming Conventions

**Format:** `Emoji` + `Descriptive Name` + `.ps1`

| Category | Emoji | Example |
|----------|-------|---------|
| Policy | 👀 | `👀chrome.ps1` |
| Remove | ⛔ | `⛔Force Remove Adobe Creative Cloud.ps1` |
| Fix | 🔧 | `🔧Fix Windows 11 Services.ps1` |
| Check/Monitor | 👀 | `👀Check DNS Server Compliance.ps1` |
| Alert | 🔔 | `🔔Technician Alert Monitor.ps1` |
| Config | ⚙️ | `⚙️Configure Wake-on-LAN.ps1` |
| Utility | ⚙️ | `⚙️Universal Disk Cleaner.ps1` |
| Wake | 🙏 | `🙏Wake all devices in Level group.ps1` |

---

## See Also

- [Launcher Guide](LAUNCHER.md)
- [Creating Policy Scripts](policy/CREATING-SCRIPTS.md)
- [Variables Reference](VARIABLES.md)
- [Function Reference](FUNCTIONS.md)
