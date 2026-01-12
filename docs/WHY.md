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
- 14 reusable functions in `COOLForge-Common.psm1`
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

- Level.io can wake individual devices, but not entire folder hierarchies
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

## Planned Features

### Client Onboarding Automation

**Problem:** Setting up new clients in Level.io requires extensive manual work:

- Manually creating folder structure for each new client
- No standardized folder hierarchy across clients
- Custom fields must be configured individually per client/folder
- Site-specific configurations (DNS filter keys, etc.) set one device at a time
- No backup/restore capability for folder structures
- Can't clone a working client setup to a new client
- Inconsistent folder naming and organization
- Hours of repetitive clicking in the web UI

**Planned COOLForge Solution:** Client Provisioning System

**Features in Development:**

1. **Backup Level.io Tenant Configuration**
   ```powershell
   # Export entire tenant configuration to JSON
   Backup-LevelTenantConfiguration -OutputPath "backups/tenant-backup-2025-12-30.json"

   # Backs up:
   # - All organizations and folder hierarchies
   # - Custom field definitions (global)
   # - Custom field values per organization/folder/device
   # - Device group assignments
   # - Folder structures for all clients

   # Or backup specific client:
   Export-LevelFolderStructure -ClientName "ACME Corp" -OutputPath "backups/ACME-structure.json"
   ```

   **Scope:** Level.io tenant configuration only (not endpoint backups)
   - Backs up: RMM folder structure, custom fields, organizational settings
   - Does NOT backup: Endpoint files, registry, applications, user data
   - Restoration limited to what the Level.io API can modify

2. **Restore Tenant Configuration**
   ```powershell
   # Restore from backup (API-controllable items only)
   Restore-LevelTenantConfiguration -BackupPath "backups/tenant-backup-2025-12-30.json" `
                                     -WhatIf  # Preview changes first

   # Can restore:
   # ✓ Folder structures
   # ✓ Custom field definitions
   # ✓ Custom field values
   # ✓ Organization settings

   # Cannot restore (outside API scope):
   # ✗ Endpoint system state
   # ✗ Installed applications
   # ✗ User files or registry
   # ✗ Device-level OS configurations
   ```

3. **Deploy Standardized Folder Structure**
   ```powershell
   # Create new client from template
   New-LevelClientFromTemplate -TemplatePath "templates/standard-client.json" `
                                -ClientName "NewCorp Inc"

   # Automatically creates:
   # ├── NewCorp Inc/
   # │   ├── Servers/
   # │   ├── Workstations/
   # │   ├── Network Devices/
   # │   └── Mobile Devices/
   ```

4. **Bulk Custom Field Configuration**
   ```powershell
   # Set custom fields across folder hierarchy
   Set-LevelFolderCustomFields -FolderPath "NewCorp Inc/Servers" `
                                -CustomFields @{
                                    DNSFilter_SiteKey = "abc123xyz"
                                    Backup_Schedule = "Daily-3AM"
                                    Maintenance_Window = "Sunday-2AM"
                                }

   # Cascades to all devices in folder
   ```

5. **Site-Specific Configuration Templates**
   ```json
   {
     "template_name": "standard-client-v2",
     "folders": [
       {
         "name": "Servers",
         "custom_fields": {
           "DNSFilter_SiteKey": "{{SITE_KEY}}",
           "CoolForge_nosleep_duration_min": "120",
           "Backup_Retention_Days": "90"
         }
       },
       {
         "name": "Workstations",
         "custom_fields": {
           "DNSFilter_SiteKey": "{{SITE_KEY}}",
           "CoolForge_nosleep_duration_min": "60"
         }
       }
     ]
   }
   ```

**Use Cases:**

- **New Client Onboarding**
  - Deploy standardized folder structure in seconds
  - Apply consistent custom fields across all folders
  - Set site-specific keys (DNS Filter, backup credentials, etc.)
  - Ensure compliance with MSP standards

- **DNS Filter Agent Management**
  - Different site keys per folder/location
  - Bulk update all devices in a folder with new key
  - Standardize deployment across all clients

- **Disaster Recovery (Tenant Configuration)**
  - Backup entire Level.io tenant configuration to JSON
  - Restore folder structures if accidentally deleted
  - Restore custom field configurations
  - Clone successful client setup to new client
  - Version control your RMM configuration in Git
  - **Note:** Backs up RMM tenant settings only, not endpoint system state

- **Multi-Site Clients**
  - Create sub-folders per physical location
  - Each location gets unique DNS Filter site key
  - Centralized management, location-specific settings

- **Compliance and Standards**
  - Enforce standardized folder naming
  - Ensure all clients have required custom fields
  - Audit client configurations against template

**Example Workflow:**

```powershell
# 1. Define your standard client template (one time)
$Template = @{
    Name = "Standard SMB Client"
    Folders = @(
        @{ Name = "Servers"; DNSFilter_SiteKey = "{{REPLACE}}" }
        @{ Name = "Workstations"; DNSFilter_SiteKey = "{{REPLACE}}" }
        @{ Name = "Network Devices" }
    )
}
Export-LevelClientTemplate -Template $Template -Path "templates/smb-client.json"

# 2. Onboard new client
New-LevelClient -TemplatePath "templates/smb-client.json" `
                -ClientName "NewCorp Inc" `
                -Variables @{
                    DNSFilter_SiteKey = "newcorp-abc123"
                }

# Result: Folder structure created, custom fields set, ready for devices in minutes
```

**Benefits:**
- **Time Savings**: Hours → minutes for client onboarding
- **Consistency**: Every client follows the same structure
- **Scalability**: Manage hundreds of clients with templates
- **Backup/Restore**: Disaster recovery for configurations
- **Compliance**: Enforce standards automatically
- **Site-Specific Settings**: DNS Filter keys, backup configs per location

**Current Status:** In planning/development phase. Core API functions already exist in `COOLForge-Common.psm1` module.

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
