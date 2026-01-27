# Software Policy Enforcement

> **WARNING: These scripts auto-download and execute code from GitHub.**
> You MUST use your own fork and review all changes before they reach your production systems.
> See [Use Your Own Fork](#important-use-your-own-fork) below.

This guide explains how to deploy and configure COOLForge software policy enforcement in Level.io.

### Minimum Required Setup

Before deploying any launchers, create these custom fields at the **Account** level in Level.io:

| Level.io Field Name | Script Variable | Required | Purpose |
|---------------------|-----------------|----------|---------|
| `apikey` | `{{cf_apikey}}` | **Yes** | Level.io API key - enables auto-bootstrap of tags and custom fields |
| `coolforge_msp_scratch_folder` | `{{cf_coolforge_msp_scratch_folder}}` | **Yes** | Persistent storage path (e.g., `C:\ProgramData\MSP`) |
| `coolforge_ps_module_library_source` | `{{cf_coolforge_ps_module_library_source}}` | **Yes** | URL to YOUR fork's library module |

> **Note:** Level.io adds the `cf_` prefix automatically. Create the field as `apikey`, reference it in scripts as `{{cf_apikey}}`.

Without these fields configured, the scripts will fail or won't be able to auto-create the policy infrastructure.

> **Tip:** Don't want to create these manually? Run the setup script (`start_here/Setup-COOLForge.ps1`) which will ask questions and create/populate these fields for you.

## Overview

The software policy enforcement system works as follows:

```
LEVEL.IO                                         YOUR GITHUB FORK
┌──────────────────────┐  ┌──────────────────┐   ┌─────────────────────────────────┐
│ Policies             │  │ Scripts          │   │ COOLForge Repository            │
│ ┌──────────────────┐ │  │                  │   │                                 │
│ │ Software Policy  │ │  │  👀unchecky ─────┼───┼─► modules/COOLForge-Common.psm1 │
│ │ Enforcement      │ │  │  (launcher)      │   │                                 │
│ │                  │ │  │                  │   │─► scripts/Policy/               │
│ │ Monitor ─────────┼─┼──┼─► runs           │   │   └── 👀unchecky.ps1            │
│ │ (Alert trigger)  │ │  │                  │   │                                 │
│ └──────────────────┘ │  └──────────────────┘   └─────────────────────────────────┘
└──────────────────────┘           │ downloads & executes
                                   ▼
                        ┌─────────────────────────┐
                        │ Policy Script runs      │
                        │ • Checks device tags    │
                        │ • Install/Remove/Pin    │
                        │ • Updates tags          │
                        └─────────────────────────┘
                                   │
                                   │ outputs "Alert" only on failure
                                   ▼
                        ┌─────────────────────────┐
                        │ Monitor detects "Alert" │
                        │ → Sends notification    │
                        └─────────────────────────┘
```

**Key Benefits:**
- Scripts auto-update from GitHub - no redeployment needed
- Single policy with multiple monitors (one per software)
- Only alerts on failures - no notification spam
- Self-healing with auto-resolve when issues are fixed

---

## IMPORTANT: Use Your Own Fork

**DO NOT point your production systems directly at someone else's repository.**

The launcher scripts auto-download and execute code from GitHub. This is powerful but dangerous if you don't control the source. A malicious or buggy commit to the upstream repo would immediately execute across all your managed devices.

### Required Setup

1. **Fork the COOLForge repository** to your own GitHub account/organization
2. **Review all changes** before merging upstream updates into your fork
3. **Configure your launchers** to point to YOUR fork's URL

### How to Configure Your Fork URL

Set the `cf_coolforge_ps_module_library_source` custom field to your fork:

```
https://raw.githubusercontent.com/YOUR-ORG/COOLForge/main/modules/COOLForge-Common.psm1
```

The launcher derives all other URLs from this base path automatically.

### Update Workflow

When upstream COOLForge releases updates:

1. **Review the changes** - check commits, diffs, and release notes
2. **Test in a lab environment** - run against test devices first
3. **Merge to your fork** - only after you've verified the changes are safe
4. **Your devices auto-update** - they pull from your fork on next run

### Version Pinning (Optional)

For extra safety, pin to a specific version tag:

```
cf_coolforge_pin_psmodule_to_version = v2026.01.12
```

This prevents any updates until you explicitly change the pin. Useful for:
- Stable production environments
- Compliance requirements
- Gradual rollouts

### Private Repository Support

If your fork is private, set the GitHub PAT custom field:

```
cf_coolforge_pat = ghp_your_personal_access_token
```

This token is injected into download URLs but never logged.

---

## Quick Start (Using Unchecky as Example)

### Step 1: Upload Launcher to Level.io

1. Copy the entire contents of `launchers/Policy/👀unchecky.ps1`
2. In Level.io: **Scripts** → **Create New Script**
3. Paste the launcher code
4. **Name it: `👀unchecky`** (use emoji prefix to match filename)
5. Save the script

### Step 2: Create Policy

1. Go to **Policies** → **Create Policy**
2. Name: `Software Policy Enforcement`
3. **Targets**: Select "All devices" or specific groups

### Step 3: Add Monitor

1. Click **Add new monitor**
2. Configure:

| Setting | Value |
|---------|-------|
| **Name** | `Enforce Unchecky Policy` |
| **Type** | `Run script` |
| **Severity** | `Information` |
| **Operating system** | `Windows` |
| **Script** | `👀unchecky` |
| **Script output** | `Contains` |
| **Value** | `Alert` |
| **Run frequency** | `1 min` (or your preference) |
| **Trigger count** | `1 time(s)` |
| **Auto-resolve alert** | `ON` |

### Step 4: First Run - Infrastructure Bootstrap

On first run with `cf_apikey` configured, the script auto-creates:

| Created Item | Type | Purpose |
|--------------|------|---------|
| `🙏UNCHECKY` | Tag | Trigger install |
| `🚫UNCHECKY` | Tag | Trigger removal |
| `📌UNCHECKY` | Tag | Pin (lock state) |
| `🔄UNCHECKY` | Tag | Trigger reinstall |
| `✅UNCHECKY` | Tag | Status: installed |
| `policy_unchecky` | Custom Field | Group/Folder/Device policy |
| `policy_unchecky_url` | Custom Field | Installer URL |

**First run outputs Alert** with setup instructions:
```
Alert: Policy infrastructure created - please configure custom fields
  Set the following custom fields in Level.io:
  - policy_unchecky: Set to 'install', 'remove', or 'pin' at Group/Folder/Device level
  - policy_unchecky_url: Set to your hosted Unchecky installer URL
```

### Step 5: Configure Custom Fields

Set these custom fields in Level.io:

| Field | Value | Where to Set |
|-------|-------|--------------|
| `policy_unchecky` | `install` / `remove` / `pin` / (empty) | Group, Folder, or Device |
| `policy_unchecky_url` | Your hosted installer URL | Account or Group level |

---

## Complete Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│ LEVEL.IO POLICY                                                     │
│ "Software Policy Enforcement"                                       │
│   └── Monitor: "Enforce Unchecky Policy"                            │
│       ├── Trigger: Output contains "Alert"                          │
│       ├── Action: Send notification to technician                   │
│       └── Auto-resolve: Clears alert when script succeeds           │
└─────────────────────────┬───────────────────────────────────────────┘
                          │ Runs on schedule
                          ▼
┌─────────────────────────────────────────────────────────────────────┐
│ LAUNCHER (👀unchecky uploaded to Level.io)                          │
│ 1. Receives Level.io variables:                                     │
│    - {{level_device_hostname}} → $DeviceHostname                    │
│    - {{level_tag_names}} → $DeviceTags (may be emoji-corrupted)     │
│    - {{cf_policy_unchecky}} → $policy_unchecky                      │
│    - {{cf_policy_unchecky_url}} → $policy_unchecky_url              │
│ 2. Downloads COOLForge-Common.psm1 from GitHub                      │
│ 3. Does spooky stuff to fix emoji encoding between Level.io ↔ device│
│ 4. Downloads policy script from GitHub                              │
│ 5. Executes policy script with all variables passed through         │
└─────────────────────────┬───────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────────┐
│ POLICY SCRIPT (scripts/Policy/👀unchecky.ps1)                       │
│                                                                     │
│ 1. Initialize-LevelScript (tag gating, lockfile)                    │
│                                                                     │
│ 2. Auto-bootstrap infrastructure (if API key present):              │
│    - Creates missing tags (🙏🚫📌🔄✅ + UNCHECKY)                    │
│    - Creates missing custom fields                                  │
│    - First run: Alert with setup instructions                       │
│                                                                     │
│ 3. Invoke-SoftwarePolicyCheck:                                      │
│    ┌──────────────────────────────────────────┐                     │
│    │ Parse $DeviceTags for policy emojis:     │                     │
│    │  🙏unchecky → Install                    │                     │
│    │  🚫unchecky → Remove                     │                     │
│    │  📌unchecky → Pin                        │                     │
│    │  🔄unchecky → Reinstall                  │                     │
│    │  ✅unchecky → Has (status only)          │                     │
│    │                                          │                     │
│    │ Priority: Pin > Remove > Install > Has   │                     │
│    │                                          │                     │
│    │ Fallback: $policy_unchecky custom field  │                     │
│    │  "install" / "remove" / "pin" / ""       │                     │
│    └──────────────────────────────────────────┘                     │
│                                                                     │
│ 4. Execute resolved action:                                         │
│    Install → Download from URL, run silent install                  │
│    Remove  → Run uninstaller                                        │
│    Pin     → No changes, set custom field                           │
│    None    → Verify state, reconcile tags                           │
│                                                                     │
│ 5. Tag management (if API key present):                             │
│    - Remove trigger tags (🙏🚫🔄) after action                      │
│    - Add/remove status tag (✅) based on final state                │
│                                                                     │
│ 6. Output:                                                          │
│    SUCCESS → exit 0, no "Alert" word                                │
│    FAILURE → exit 1, outputs "Alert: <reason>"                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## The 5-Tag Policy Model

| Emoji | Unicode | Tag Example | Action | Behavior |
|-------|---------|-------------|--------|----------|
| 🙏 | U+1F64F | `🙏UNCHECKY` | Install | Installs if missing, then removes tag and adds ✅ |
| 🚫 | U+1F6AB | `🚫UNCHECKY` | Remove | Uninstalls if present, then removes 🚫 and ✅ |
| 📌 | U+1F4CC | `📌UNCHECKY` | Pin | Locks current state, sets custom field, removes tag |
| 🔄 | U+1F504 | `🔄UNCHECKY` | Reinstall | Removes then installs, auto-manages tags |
| ✅ | U+2705 | `✅UNCHECKY` | Has | Status indicator only (set/removed automatically) |

> **Note:** `⛔` (U+26D4 No Entry) also works for Remove but is **deprecated**. Use `🚫` (U+1F6AB Prohibited) instead.

**Priority Resolution** (when multiple tags present):
```
Pin (highest) > Remove > Reinstall > Install > Has (lowest)
```

---

## Alert Conditions

The scripts only output "Alert" on failure. Level.io monitors this word to trigger notifications.

| Condition | Alert Message |
|-----------|---------------|
| First run (infrastructure created) | `Alert: Policy infrastructure created - please configure custom fields` |
| Missing installer URL | `Alert: <Software> install failed - policy_<software>_url custom field not configured` |
| Download failed | `Alert: Failed to download <Software> installer after X retries` |
| Install failed | `Alert: <Software> installer failed` |
| Uninstall failed | `Alert: <Software> uninstaller failed` |
| General failure | `Alert: Policy enforcement failed for <software>` |

---

## Software-Specific Custom Fields

> **Naming:** Create fields in Level.io without `cf_` prefix. Scripts reference them as `{{cf_fieldname}}`.

### Unchecky (Simple - URL only)

| Level.io Field | Script Variable | Purpose |
|----------------|-----------------|---------|
| `policy_unchecky` | `{{cf_policy_unchecky}}` | Policy action: `install` / `remove` / `pin` |
| `policy_unchecky_url` | `{{cf_policy_unchecky_url}}` | Hosted installer URL |

### DNSFilter (Requires Site Key)

| Level.io Field | Script Variable | Purpose |
|----------------|-----------------|---------|
| `policy_dnsfilter` | `{{cf_policy_dnsfilter}}` | Policy action: `install` / `remove` / `pin` |
| `policy_dnsfilter_sitekey` | `{{cf_policy_dnsfilter_sitekey}}` | DNSFilter NKEY for installation |

### Huntress (Requires Account/Org Keys)

| Level.io Field | Script Variable | Purpose |
|----------------|-----------------|---------|
| `policy_huntress` | `{{cf_policy_huntress}}` | Policy action: `install` / `remove` / `pin` |
| `policy_huntress_account_key` | `{{cf_policy_huntress_account_key}}` | Huntress account key |
| `policy_huntress_org_key` | `{{cf_policy_huntress_org_key}}` | Huntress organization key |
| `policy_huntress_tags` | `{{cf_policy_huntress_tags}}` | Optional Huntress tags |

---

## Required MSP-Level Custom Fields

These must be set at the account level for the system to work:

| Level.io Field | Script Variable | Purpose | Example |
|----------------|-----------------|---------|---------|
| `coolforge_msp_scratch_folder` | `{{cf_coolforge_msp_scratch_folder}}` | Persistent storage path | `C:\ProgramData\MSP` |
| `apikey` | `{{cf_apikey}}` | Level.io API key (enables tag management) | Your API key |
| `debug_scripts` | `{{cf_debug_scripts}}` | Set to `true` for verbose output | `false` |

---

## Adding Multiple Software Policies

To add another software to the same policy:

1. Upload the launcher (e.g., `👀huntress.ps1`) as a new script named `👀huntress`
2. In the existing "Software Policy Enforcement" policy, click **Add new monitor**
3. Configure the monitor with the same pattern:
   - Script output: `Contains`
   - Value: `Alert`
4. Configure the software-specific custom fields

All software enforcement runs under one policy, each with its own monitor:

```
Software Policy Enforcement
├── Enforce DNSFilter Policy  → 👀dnsfilter
├── Enforce Huntress Policy   → 👀huntress
└── Enforce Unchecky Policy   → 👀unchecky
```

---

## Launcher Header Configuration

Each launcher defines its policy variables at the top. When creating a new launcher, configure:

```powershell
# ============================================================
# SCRIPT TO RUN - PRE-CONFIGURED
# ============================================================
$ScriptToRun = "Policy/👀unchecky.ps1"           # Include subfolder path
$policy_unchecky = "{{cf_policy_unchecky}}"
$policy_unchecky_url = "{{cf_policy_unchecky_url}}"

$LauncherName = "Policy/👀unchecky.ps1"          # This launcher's location
```

**Important:** The `$ScriptToRun` must include the subfolder path (e.g., `Policy/👀unchecky.ps1`), not just the filename. The `$LauncherName` should match the launcher's location in the `launchers/` folder for version checking.

The `$policy_*` variables map to Level.io custom fields and are passed to the policy script.

---

## FAQ

### How do I reinstall software after removing it?

When you remove software (via `🚫` tag or custom field), the script sets the **device-level** custom field to `"remove"` so the intent persists. This overrides any group-level `"install"` policy.

To install again:
1. Add the `🙏SOFTWARENAME` tag to the device - this overrides everything and sets the custom field back to `"install"`
2. OR manually change the device custom field from `"remove"` to `"install"` (or clear it)

### How do I block all software installs on a device?

There's no single "block everything" tag. Options:
- **Pin each software individually** with `📌SOFTWARENAME` - locks current state
- **Set device custom field to `"remove"`** - blocks that specific software
- **Don't apply install policies** to that device/group

### What's the priority order?

```
1. Device tags (highest) - 🙏🚫📌🔄 override everything
2. Device custom field   - overrides group/folder
3. Folder custom field   - overrides group
4. Group custom field    - baseline policy
```

Within tags, priority is: `Pin > Remove > Reinstall > Install > Has`

---

## Tag Lifecycle Examples

### Scenario: Install via Group Policy

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

AFTER:  Device tags = ["✅", "Production", "✅UNCHECKY"]
        Unchecky = Installed
```

### Scenario: Override with Tag

```
BEFORE: Device tags = ["✅", "🙏UNCHECKY"]
        policy_unchecky = "" (no policy)
        Unchecky = Not installed

Script runs:
├─ Global check: Has ✅ → Managed
├─ Tag check: 🙏UNCHECKY → Install action
├─ Action: Download and install Unchecky
├─ Update tags: Remove 🙏UNCHECKY, Add ✅UNCHECKY
└─ Success!

AFTER:  Device tags = ["✅", "✅UNCHECKY"]
        policy_unchecky = "install" (set by script)
        Unchecky = Installed
```

### Scenario: Remove Software

```
BEFORE: Device tags = ["✅", "🚫UNCHECKY", "✅UNCHECKY"]
        Unchecky = Installed

Script runs:
├─ Global check: Has ✅ → Managed
├─ Tag check: 🚫UNCHECKY → Remove action
├─ Action: Uninstall Unchecky
├─ Update tags: Remove 🚫UNCHECKY, Remove ✅UNCHECKY
└─ Success!

AFTER:  Device tags = ["✅"]
        policy_unchecky = "remove" (set by script)
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
│   ├── policy_unchecky = "install"  ← All Acme devices get Unchecky
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

---

## Troubleshooting

### Enable Debug Mode

Set `cf_debug_scripts = true` at the device or group level to get verbose output showing:
- All launcher variables received
- Tag parsing details
- Policy resolution steps
- API calls made
- Tag changes before/after

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| "Library not found" | Missing scratch folder | Set `cf_coolforge_msp_scratch_folder` |
| Tags not updating | Missing API key | Set `cf_apikey` custom field |
| Emoji tags not matching | Level.io corruption | Already handled by `Repair-LevelEmoji` |
| "Infrastructure created" alert | First run | Configure the custom fields as instructed |
| Install fails silently | Missing URL custom field | Set `policy_<software>_url` |

---

## Configuration Policies

In addition to software enforcement (install/remove/pin), COOLForge supports **configuration policies** for managing OS and application settings.

Configuration policies use the same 5-tag model as software policies:
- **Use emoji tags** - Same tag system for consistency
- **Are idempotent** - Safe to run repeatedly, only make changes if needed
- **Use install/remove/pin values** - `install` = enable, `remove` = disable

### Available Configuration Policies

| Category | Folder | Policies |
|----------|--------|----------|
| Windows | `scripts/Policy/Windows/` | [Location Services](Windows.md) |
| Chrome | `scripts/Policy/Chrome/` | [Location Services](Chrome.md#chrome-configuration-policies) |

### Naming Convention

Configuration policy custom fields follow this pattern:
```
policy_<category>_<setting> = "install" | "remove" | "pin" | ""
```

Examples:
- `policy_device_locationservices = "install"` (enable Windows location)
- `policy_chrome_locationservices = "install"` (enable Chrome geolocation)
