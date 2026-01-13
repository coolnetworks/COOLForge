# Why COOLForge Exists

This document explains the problems COOLForge was built to solve and the philosophy behind its design.

---

## The Core Problems

### 1. **Script Versioning Chaos**

**Problem:** Managing hundreds of PowerShell scripts in Level.io (or any RMM) becomes unmanageable:

- Scripts are copy-pasted into the RMM's web interface
- Bug fixes require manually editing the script in the RMM
- No version control or change tracking - just a text box
- Can't tell what version of the script you deployed last week
- Rollback means manually finding old code (if you saved it)
- Team collaboration is difficult - no proper code review process
- Multiple scripts doing similar things diverge over time
- No way to test changes before deploying to production

**COOLForge Solution:**
- Scripts live in Git repository, managed like proper software
- Deploy a launcher once to Level.io - it never changes
- Launchers automatically download the actual script from GitHub on each run
- Version pinning allows testing on subset of devices before rollout
- Update the script in Git, all executions get the new version
- Standard Git workflow: branches, pull requests, code review
- Instant rollback by changing the version pin or Git tag

**Result:** Manage scripts professionally in Git instead of editing text boxes in a web UI.

---

### 2. **Scripts Running on Wrong Machines**

**Problem:** Some scripts should never run on certain devices (production servers, critical workstations, customer demos):

- No built-in way to prevent execution based on device tags
- Accidental runs cause downtime or data loss
- Manual checking required in every script
- Different RMM systems handle tags differently

**COOLForge Solution:** Tag Gate System
```powershell
$Init = Initialize-LevelScript -ScriptName "MyScript" `
                               -DeviceTags "{{level_tag_names}}" `
                               -BlockingTags @("❌", "🛑")
```

- Scripts automatically skip execution if device has blocking tags
- Standardized across all scripts
- Logged with reason for skipping
- Configurable per-script if needed

**Result:** Never accidentally break a production server again.

---

### 3. **Duplicate Code Everywhere**

**Problem:** Common operations repeated in hundreds of scripts:

- Every script reimplements logging
- Every script reinvents error handling
- Every script has its own lockfile logic
- API calls duplicated across scripts
- Bug fixes need to be applied to hundreds of files

**COOLForge Solution:** Shared Library Module
- 79+ reusable functions in `COOLForge-Common.psm1`
- Auto-downloaded and updated on each script run
- Standardized logging, error handling, lockfile management
- API helpers for Level.io REST API
- Fix once, all scripts benefit

**Result:** Write scripts in 20 lines instead of 200.

---

### 4. **Concurrent Execution Problems**

**Problem:** Multiple instances of the same script running simultaneously:

- Race conditions corrupting files or settings
- Duplicate work wasting resources
- Conflicts causing failures
- Manual PID tracking unreliable

**COOLForge Solution:** Automatic Lockfile Management
```powershell
$Init = Initialize-LevelScript -ScriptName "MyScript" -MspScratchFolder "C:\ProgramData\MSP"
if (-not $Init.Success) {
    Write-Host "Already running (PID: $($Init.PID))"
    exit 0
}
```

- Lockfiles created automatically with PID tracking
- Cleaned up on normal exit or error
- Stale lockfile detection
- Per-script isolation

**Result:** Never worry about concurrent execution again.

---

### 5. **No Protection During Critical Operations**

**Problem:** Long-running scripts interrupted by sleep/hibernate:

- Windows Updates interrupted mid-install
- File transfers aborted
- Database migrations corrupted
- No reliable way to prevent sleep temporarily

**COOLForge Solution:** Prevent Sleep Script with Auto-Restore

Script: `🔧Prevent Sleep.ps1`

```powershell
# Configurable duration via custom field
CoolForge_nosleep_duration_min = 120  # 2 hours

# Script automatically:
# 1. Backs up current power settings to registry
# 2. Disables sleep/hibernate on AC and DC power
# 3. Creates scheduled task to restore settings after timeout
# 4. Verifies backup was successful before proceeding
```

**Features:**
- Timeout-based: automatically reverts after configured duration
- Registry backup: stores original settings with verification
- Scheduled task: ensures restore even if script crashes
- AC/DC power: handles both scenarios
- Configurable: per-device or per-group timeout via custom field

**Result:** Run critical operations without interruption, settings always restored automatically.

---

### 6. **Inconsistent Error Handling**

**Problem:** Scripts fail silently or with cryptic errors:

- No standardized error messages
- Failures don't get logged properly
- No automatic cleanup on errors
- Exit codes inconsistent

**COOLForge Solution:** Wrapped Execution
```powershell
Invoke-LevelScript -ScriptBlock {
    Write-LevelLog "Starting work..."
    # Your code here
    Write-LevelLog "Work completed" -Level "SUCCESS"
}
```

- Automatic try/catch wrapping
- Lockfile cleanup on error
- Standardized error logging
- Consistent exit codes (0 = success, 1 = failure)

**Result:** Scripts fail gracefully with clear error messages.

---

### 7. **No Staged Rollouts**

**Problem:** New script versions deployed to all devices immediately:

- No testing on subset of devices
- Can't roll back if issues found
- Production devices at risk
- All-or-nothing deployment

**COOLForge Solution:** Version Pinning
```powershell
# Custom field per device/group:
CoolForge_pin_psmodule_to_version = v2025.12.29

# Scripts download from that tag instead of main branch
```

**Workflow:**
1. Push new version to GitHub (tag `v2025.12.30`)
2. Pin test group to `v2025.12.30`
3. Verify on test devices
4. Clear pin on production devices to roll out
5. If issues found, set pin to `v2025.12.29` for instant rollback

**Result:** Test safely, deploy confidently, rollback instantly.

---

### 8. **Repetitive Script Setup**

**Problem:** Every new script requires:

- Library download logic
- Custom field variable interpolation
- Error handling boilerplate
- Lockfile management code
- Logging setup
- 100+ lines of setup before actual work begins

**COOLForge Solution:** Script Templates
```powershell
# Copy template, change 3 lines, add your code:
$Init = Initialize-LevelScript -ScriptName "YourScriptName" `
                               -MspScratchFolder $MspScratchFolder `
                               -DeviceHostname "{{level_device_hostname}}" `
                               -DeviceTags "{{level_tag_names}}"

if (-not $Init.Success) { exit 0 }

Invoke-LevelScript -ScriptBlock {
    # Your actual code here (10-20 lines instead of 200)
}
```

**Result:** New scripts in 5 minutes instead of 2 hours.

---

### 9. **No API Abstraction**

**Problem:** Level.io API calls scattered throughout scripts:

- Inconsistent authentication
- No error handling for API failures
- Rate limiting not handled
- Bearer token management duplicated

**COOLForge Solution:** API Helper Functions
```powershell
# Simple API calls with built-in auth and error handling
$Devices = Get-LevelDevices -GroupName "Production Servers"
$Device = Find-LevelDevice -Hostname "SERVER01"
Send-LevelWakeOnLan -MacAddress "00:11:22:33:44:55"
```

**Result:** API operations in one line instead of 20.

---

### 10. **No Built-in Wake-on-LAN for Folders**

**Problem:** Need to wake multiple devices for maintenance windows or urgent tasks:

- Level.io can wake individual devices, but has no built-in capability to wake entire folder hierarchies
- Manually waking 50+ devices one-by-one is impractical
- Scripts running on one device can't wake peer devices
- No way to cascade wake operations through folder structure

**COOLForge Solution:** Hierarchical Wake-on-LAN

Script: `🙏Wake all devices in parent to level.io folder.ps1`

```powershell
# Running on any device in a folder wakes all siblings and descendants
# Uses Level.io API to:
# 1. Find the parent folder of the current device
# 2. Recursively enumerate all devices in folder hierarchy
# 3. Send WOL magic packets to each device
# 4. Reports success/failure for each wake attempt
```

**Use Cases:**
- **Maintenance windows**: Wake all devices in "Servers" folder for patching
- **Emergency response**: Wake all devices in a site for incident investigation
- **Scheduled tasks**: One device wakes peers before running distributed operations
- **Cascading operations**: Wake folder, then run scripts on all newly-woken devices

**Result:** Wake entire folder hierarchies from a single script execution on any device in the folder.

---

### 11. **Client Onboarding Automation**

**Problem:** Setting up new clients in Level.io requires extensive manual work:

- Manually creating folder structure for each new client
- No standardized folder hierarchy across clients
- Custom fields must be configured individually per client/folder
- No backup/restore capability for folder structures
- Inconsistent folder naming and organization
- Hours of repetitive clicking in the web UI

**COOLForge Solution:** Client Provisioning Tools in `start_here/` folder

**Available Scripts:**

1. **New-LevelClient.ps1** - Create standardized client hierarchy
   ```powershell
   .\start_here\New-LevelClient.ps1

   # Creates structure like:
   # 🏢1️⃣ClientName           <- Business, Priority 1
   # ├── Main                   <- Site
   # │   ├── WS                 <- Workstations
   # │   │   ├── 🪟 WIN
   # │   │   ├── 🐧 LINUX
   # │   │   └── 🍎 MAC
   # │   └── SRV                <- Servers
   # │       ├── 🪟 WIN
   # │       └── 🐧 LINUX
   ```

   **Features:**
   - Client type selection (Business/Personal) with visual prefix
   - Priority level (1-5) for sorting and triage
   - Platform selection per company and per site
   - Multi-site support with per-site overrides
   - Custom field configuration during creation
   - Dry-run mode to preview changes

2. **Backup-LevelGroup.ps1** - Backup group hierarchies
   ```powershell
   .\start_here\Backup-LevelGroup.ps1 -GroupName "ClientName"

   # Backs up:
   # - Group hierarchy structure
   # - Custom field values at each level
   # - Parent/child relationships
   ```

3. **Restore-LevelGroup.ps1** - Restore with new name
   ```powershell
   .\start_here\Restore-LevelGroup.ps1 -BackupPath "backup.zip" -NewGroupName "NewClient"

   # Recreates entire hierarchy under new name
   # Restores all custom field values
   ```

4. **Setup-COOLForge.ps1** - Initial tenant setup
   ```powershell
   .\start_here\Setup-COOLForge.ps1

   # Creates required custom fields
   # Configures integrations (Huntress, ScreenConnect, etc.)
   # Saves API key securely for other tools
   ```

**Result:** New client onboarding in minutes instead of hours. Consistent structure across all clients.

---

### 12. **No Real-Time Alerts to Technicians**

**Problem:** Scripts detect issues but technicians don't know until they check:

- Client scripts find problems but can only log to files
- No way to notify the right technician in real-time
- Checking logs across hundreds of devices is impractical
- Critical issues go unnoticed for hours or days

**COOLForge Solution:** Technician Alert System

```powershell
# From any script running on a client device:
Send-TechnicianAlert -Title "Disk Space Critical" `
                     -Message "C: drive below 5% on $DeviceHostname" `
                     -TechnicianName "Allen"

# Or broadcast to all technicians:
Send-TechnicianAlert -Title "Security Alert" `
                     -Message "Unauthorized software detected"
```

**How It Works:**
1. Client scripts call `Send-TechnicianAlert` when issues are detected
2. Alert is stored in Level.io custom field on the target technician's workstation
3. Alert Monitor script (running on tech workstations) polls for new alerts
4. Windows toast notifications appear in real-time
5. Alerts can be targeted to specific technicians or broadcast to all

**Features:**
- Real-time Windows toast notifications
- Technician-specific routing via tags
- Broadcast alerts to all technicians
- Auto-expiring alerts
- Click-to-dismiss functionality

**Result:** Technicians get instant notifications when scripts need attention.

---

### 13. **Software Policy Chaos**

**Problem:** Managing software across hundreds of devices is inconsistent:

- No standardized way to enforce "install on these, remove on those"
- Manual tracking of which devices should have which software
- Different scripts with different approaches to the same problem
- No way to pin software versions or prevent changes on specific devices

**COOLForge Solution:** 5-Tag Policy Model

```powershell
# Tags control software state (override everything):
# U+1F64F unchecky  = Install if missing (transient - removed after install)
# U+1F6AB unchecky  = Remove if present (transient - removed after removal)
# U+1F4CC unchecky  = Pin - no changes allowed (persistent)
# U+1F504 unchecky  = Reinstall (transient)
# U+2705 unchecky   = Status: installed (set automatically by script)

# Custom field policy (inherited from Group -> Folder -> Device):
# policy_unchecky = "install" | "remove" | "pin" | ""
```

**Hierarchy:**
1. Software-specific tags (highest priority)
2. Custom field policy (inherited)
3. Default behavior (do nothing)

**Global Controls:**
- U+2705 = Device is managed (required for any action)
- U+274C = Device is excluded from all management
- Both = Device is globally pinned

**Result:** Consistent software management with clear override hierarchy.

---

### 14. **Wake-on-LAN Configuration Nightmare**

**Problem:** Configuring WOL on Windows is complex and inconsistent:

- Multiple settings across NIC, power options, and BIOS
- Energy Efficient Ethernet (EEE) silently blocks WOL
- Modern Standby vs S3 sleep compatibility varies by hardware
- Wireless WOL (WoWLAN) requires different configuration
- Manual configuration doesn't scale to hundreds of devices

**COOLForge Solution:** Intelligent WOL Configuration Script

Script: `Configure Wake-on-LAN.ps1`

```powershell
# Automatically configures all physical NICs for WOL:
# - Enables WakeOnMagicPacket on wired adapters
# - Enables WoWLAN on wireless adapters
# - Disables Energy Efficient Ethernet (EEE)
# - Configures power management settings
# - Handles Modern Standby vs S3 sleep automatically
```

**Intelligent Handling:**
- Detects adapter capabilities and configures appropriately
- Keeps Modern Standby enabled if WoWLAN-capable adapter present
- Disables Modern Standby only when legacy wired-only setup detected
- Disables hibernation, fast startup (both block WOL)
- Enables wake timers

**Result:** Deploy once, WOL works across your fleet regardless of hardware mix.

---

### 15. **Stale Device Cleanup**

**Problem:** Devices disappear but remain in Level.io:

- Decommissioned machines still showing in inventory
- No easy way to identify offline devices
- Manual cleanup wastes time
- Licenses consumed by ghost devices

**COOLForge Solution:** Stale Device Detection

Script: `Get-StaleDevices.ps1` (in `start_here/`)

```powershell
# Find devices offline for 30+ days
.\start_here\Get-StaleDevices.ps1 -Days 30

# Filter to specific group
.\start_here\Get-StaleDevices.ps1 -GroupFilter "*Production*"

# Export to CSV for review
.\start_here\Get-StaleDevices.ps1 -Days 60 -ExportCsv "stale.csv"

# Show reinstall commands for recovery
.\start_here\Get-StaleDevices.ps1 -ShowReinstallCommands
```

**Result:** Keep your Level.io inventory clean and accurate.

---

## Design Philosophy

### 1. **Convention Over Configuration**

Scripts should "just work" with minimal setup:
- Sensible defaults for everything
- Required fields clearly documented
- Fallbacks for missing configuration

### 2. **Fail Safe, Not Silent**

When something goes wrong:
- Log clearly what happened and why
- Clean up resources (lockfiles, temp files)
- Exit with appropriate code for RMM alerting
- Never leave system in broken state

### 3. **Git as Source of Truth**

Scripts are software, treat them like it:
- Version control everything
- Reviewable changes via pull requests
- Automated testing before deployment
- Rollback capability via tags

### 4. **Deploy Once, Update Forever**

Launchers are static deployment units:
- Never need to update launcher in Level.io
- Scripts self-update from GitHub
- Library auto-updates automatically
- Reduces RMM interface interaction to zero

### 5. **Observable and Debuggable**

Always know what's happening:
- Timestamped logs for everything
- Version information in output
- Reason codes for skipped execution
- Clear error messages

---

## Real-World Impact

### Before COOLForge
- 200 scripts to maintain manually
- Bug fixes = 200 web UI edits
- No way to test safely
- Scripts interfere with each other
- Production incidents from accidental runs
- 2 hours to write a new script

### After COOLForge
- Git push to update 200 devices
- Bug fixes = 1 commit
- Staged rollouts to test devices
- Lockfiles prevent conflicts
- Tag gates prevent accidents
- 5 minutes to write a new script

---

## Who Is This For?

### MSPs (Managed Service Providers)
- Manage hundreds of endpoints across multiple customers
- Need rapid deployment and rollback
- Can't afford production downtime
- Want team collaboration via Git

### IT Teams
- Maintain scripts for corporate fleet
- Need audit trail for changes
- Want testing before production
- Require version control compliance

### Individual Sysadmins
- Tired of copy-paste script management
- Want professional tooling
- Need reliability without complexity
- Value automation

---

## What COOLForge Is NOT

- **Not a replacement for Level.io** - Works with Level.io, extends it
- **Not a programming framework** - Just removes boilerplate
- **Not complex** - Three lines to initialize, then write normal PowerShell
- **Not vendor lock-in** - Scripts are portable, library is MIT licensed

---

## The Bottom Line

COOLForge exists because managing RMM scripts at scale is painful, error-prone, and time-consuming.

It turns script management from a manual, fragile process into a professional software development workflow - while keeping the simplicity PowerShell users expect.

**One-time setup, lifetime of benefits.**

---

## See Also

- [Main README](../README.md) - Getting started guide
- [Function Reference](FUNCTIONS.md) - All available functions
- [Version Pinning](VERSION-PINNING.md) - Staged rollouts and rollback
- [Script Launcher](LAUNCHER.md) - Git-based script deployment
