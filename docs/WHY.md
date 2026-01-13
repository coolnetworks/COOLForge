# Why COOLForge Exists (for Level.io)

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

**Result:** Focus on your actual task logic instead of reinventing logging, lockfiles, and API calls.

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
    # Your actual task logic here - no boilerplate needed
}
```

**Result:** Start with a working template instead of from scratch.

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

### 10. **Scripts Can't Coordinate Across Devices**

**Problem:** Scripts run in isolation on individual devices:

- No way for a script on one device to trigger actions on other devices
- Maintenance windows require waking devices one-by-one manually
- Peer-to-peer coordination requires external orchestration
- Can't cascade operations through device groups

**COOLForge Solution:** Cross-Device Coordination via API

```powershell
# Wake all devices in current folder hierarchy
Send-LevelWakeOnLan -FolderDevices

# Find and interact with peer devices
$Peers = Get-LevelDevices -GroupId $CurrentGroup.id
foreach ($Peer in $Peers) {
    # Tag devices for coordinated actions
    Add-LevelTagToDevice -DeviceId $Peer.id -TagName "WAKEME"
}
```

**Capabilities:**
- **Wake-on-LAN**: Send magic packets to peer devices from any online device
- **Tag coordination**: Tag devices for batch operations
- **Folder awareness**: Scripts know their group context and can find siblings
- **API access**: Full Level.io API available from endpoint scripts

**Result:** Coordinate maintenance windows and batch operations from any device in the fleet.

---

### 11. **Level.io Tenant Setup**

**Problem:** Setting up Level.io for COOLForge requires manual configuration:

- Custom fields must be created one-by-one in the web UI
- No standardized field naming across tenants
- Integration settings (Huntress, ScreenConnect) configured manually
- API key management is ad-hoc
- Easy to miss required fields, causing script failures

**COOLForge Solution:** Setup Wizard

```powershell
.\start_here\Setup-COOLForge.ps1

# Creates required custom fields (coolforge_msp_scratch_folder, etc.)
# Configures integrations (Huntress, ScreenConnect, etc.)
# Saves API key securely for other tools
```

**Result:** One-time setup that ensures all COOLForge scripts will work correctly.

---

### 12. **Client Onboarding Automation**

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

**Result:** New client onboarding in minutes instead of hours. Consistent structure across all clients.

---

### 13. **Software Policy Chaos**

**Problem:** Managing software across hundreds of devices is inconsistent:

- No standardized way to enforce "install on these, remove on those"
- Manual tracking of which devices should have which software
- Different scripts with different approaches to the same problem
- No way to pin software versions or prevent changes on specific devices

**COOLForge Solution:** 5-Tag Policy Model

**Tags control software state (override custom field policy):**

| Tag | Action | Persistence |
|-----|--------|-------------|
| 🙏unchecky | Install if missing | Transient (removed after install) |
| 🚫unchecky | Remove if present | Transient (removed after removal) |
| 📌unchecky | Pin - no changes allowed | Persistent |
| 🔄unchecky | Reinstall | Transient |
| ✅unchecky | Status: installed | Set automatically by script |

**Custom field policy** (inherited from Group → Folder → Device):
- `policy_unchecky` = `"install"` | `"remove"` | `"pin"` | `""`

**Hierarchy:**
1. Software-specific tags (highest priority)
2. Custom field policy (inherited)
3. Default behavior (do nothing)

**Global Controls:**
- ✅ = Device is managed (required for any action)
- ❌ = Device is excluded from all management
- Both = Device is globally pinned

**Result:** Consistent software management with clear override hierarchy.

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
- Start from templates instead of scratch

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
- **Not a programming framework** - A shared library and conventions, not a new language
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
