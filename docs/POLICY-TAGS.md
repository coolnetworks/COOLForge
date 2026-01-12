# COOLForge Policy Tag System

## Overview

COOLForge uses emoji-prefixed tags on Level.io devices to manage software policy enforcement. Tags are device-level only (no inheritance). Custom fields at Group/Folder level provide default policy with inheritance.

## Tag Types

### Global Control Tags (No Software Suffix)

| Tag | Name | Purpose |
|-----|------|---------|
| ✅ | Checkmark | Device is verified/managed by COOLForge |
| ❌ | Cross | Device is excluded from all COOLForge management |

**Tag Combination Logic:**
- **Neither ✅ nor ❌**: Device not yet evaluated - script should skip (no action)
- **✅ only**: Device is managed - run policy checks
- **❌ only**: Device is excluded - skip all policy scripts
- **Both ✅ and ❌**: Device is pinned globally - no changes allowed for any software

### Software-Specific Tags (5 per software)

| Tag | Example | Purpose | Set By | Persists |
|-----|---------|---------|--------|----------|
| 🙏 | 🙏unchecky | Override: Install if missing | Admin | No - removed after action |
| 🚫 | 🚫unchecky | Override: Remove if present | Admin | No - removed after action |
| 📌 | 📌unchecky | Override: Pin (don't touch) | Admin | Yes - admin intent |
| 🔄 | 🔄unchecky | Reinstall (remove + install) | Automation/Admin | No - removed after action |
| ✅ | ✅unchecky | Status: Currently installed | Script | Yes - reflects state |

## Script Execution Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     SCRIPT START                                │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 1: Check Global Tags                                       │
│                                                                 │
│   Has ❌ (global cross)?                                        │
│     YES → EXIT (device excluded from all management)            │
│                                                                 │
│   Has ✅ (global checkmark)?                                    │
│     NO → EXIT (device not yet verified for management)          │
│                                                                 │
│   Has BOTH ✅ AND ❌?                                            │
│     YES → EXIT (device globally pinned - no changes)            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 2: Check Software-Specific Override Tags                   │
│                                                                 │
│   Priority order (first match wins):                            │
│                                                                 │
│   1. 📌software (Pin)                                           │
│      → EXIT (no changes, admin wants state preserved)           │
│                                                                 │
│   2. 🔄software (Reinstall)                                     │
│      → Remove software if present                               │
│      → Install software                                         │
│      → Remove 🔄 tag                                            │
│      → Set ✅software tag                                       │
│      → EXIT                                                     │
│                                                                 │
│   3. 🚫software (Remove)                                        │
│      → Remove software if present                               │
│      → Remove 🚫 tag                                            │
│      → Remove ✅software tag if present                         │
│      → EXIT                                                     │
│                                                                 │
│   4. 🙏software (Install)                                       │
│      → Install software if not present                          │
│      → Remove 🙏 tag                                            │
│      → Set ✅software tag                                       │
│      → EXIT                                                     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 3: Check Custom Field Policy (Inherited)                   │
│                                                                 │
│   Read policy_<software> custom field value                     │
│   (Inherits: Group → Folder → Device)                           │
│                                                                 │
│   Value = "install"                                             │
│      → Install if not present, set ✅software                   │
│                                                                 │
│   Value = "remove"                                              │
│      → Remove if present, remove ✅software                     │
│                                                                 │
│   Value = "pin"                                                 │
│      → No changes                                               │
│                                                                 │
│   Value = "" (empty/not set)                                    │
│      → No policy, skip                                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 4: Verify Current State & Reconcile Tags                   │
│                                                                 │
│   Check actual software state:                                  │
│   - Is it installed?                                            │
│   - Is it running correctly?                                    │
│   - Is configuration correct?                                   │
│                                                                 │
│   If installed and working:                                     │
│      → Ensure ✅software tag is set                             │
│      → Remove any stale action tags (🙏, 🚫, 🔄)                │
│                                                                 │
│   If NOT installed but ✅software present:                      │
│      → Software was removed externally                          │
│      → Remove ✅software tag                                    │
│      → Re-evaluate policy (may trigger reinstall)               │
│                                                                 │
│   If installed but broken:                                      │
│      → Attempt repair                                           │
│      → If repair fails, reinstall                               │
└─────────────────────────────────────────────────────────────────┘
```

## Tag Cleanup Rules

After any action completes successfully:

| Action | Tags to Remove | Tags to Set |
|--------|---------------|-------------|
| Install | 🙏software | ✅software |
| Remove | 🚫software, ✅software | (none) |
| Reinstall | 🔄software | ✅software |
| Pin | (none) | (none) |

**Key Principle:** Action tags (🙏, 🚫, 🔄) are transient - they trigger an action and get cleaned up. Only status tags (✅) and intent tags (📌) persist.

## Custom Field Policy

Custom field `policy_<software>` at Group/Folder level:

| Value | Meaning |
|-------|---------|
| `install` | Software should be installed on all devices in this group/folder |
| `remove` | Software should not be present on devices in this group/folder |
| `pin` | Don't change software state for devices in this group/folder |
| (empty) | No policy - inherit from parent or skip |

**Inheritance:** Device inherits from Folder, Folder inherits from Group.

**Override:** Device-level tags always override custom field policy.

## Automation Integration

Level.io automations can trigger policy changes:

**Example: Device moves to new group**
1. Automation triggers on "device enters group"
2. Automation adds 🔄software tag (for software needing reconfiguration)
3. Next scheduled script run sees 🔄 → reinstalls with new group's config

## Unicode Reference

| Emoji | Unicode | Code Point | PowerShell |
|-------|---------|------------|------------|
| ✅ | U+2705 | 0x2705 | `[char]0x2705` |
| ❌ | U+274C | 0x274C | `[char]0x274C` |
| 🙏 | U+1F64F | 0x1F64F | `[char]::ConvertFromUtf32(0x1F64F)` |
| 🚫 | U+1F6AB | 0x1F6AB | `[char]::ConvertFromUtf32(0x1F6AB)` |
| 📌 | U+1F4CC | 0x1F4CC | `[char]::ConvertFromUtf32(0x1F4CC)` |
| 🔄 | U+1F504 | 0x1F504 | `[char]::ConvertFromUtf32(0x1F504)` |

## Examples

### Example 1: New Device Setup

1. Admin adds device to Level.io
2. Admin adds ✅ tag (device is managed)
3. Group has `policy_unchecky = install`
4. Script runs → installs unchecky → adds ✅unchecky

### Example 2: Exception Override

1. Device has ✅ and ✅unchecky (unchecky installed)
2. Admin adds 🚫unchecky (wants it removed from this device)
3. Script runs → removes unchecky → removes 🚫unchecky → removes ✅unchecky

### Example 3: Global Exclusion

1. Device has ❌ tag (excluded)
2. All COOLForge scripts skip this device entirely

### Example 4: Global Pin

1. Device has both ✅ and ❌ tags
2. Device is verified but pinned - no changes allowed
3. All COOLForge scripts skip actions on this device

### Example 5: Device Moves Groups (DNS Filter scenario)

1. Device has ✅ and ✅dnsfilter
2. Automation fires: "device entered new group"
3. Automation adds 🔄dnsfilter tag
4. Script runs → uninstalls → reinstalls with new group's site key → removes 🔄 → keeps ✅dnsfilter
