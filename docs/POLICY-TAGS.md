# COOLForge Software Policy Tag System

## Overview

COOLForge uses emoji-prefixed tags on Level.io devices to manage software policy enforcement. Tags are device-level only (no inheritance). Custom fields at Group/Folder level provide default policy with inheritance.

## Global Control Tags

Standalone tags (no software suffix) that control device-level management:

| Tag | Name | Purpose |
|-----|------|---------|
| ✅ | Checkmark | Device is verified/managed by COOLForge |
| ❌ | Cross | Device is excluded from all COOLForge management |

### Global Tag Logic

| Device Tags | Result |
|-------------|--------|
| Neither ✅ nor ❌ | Not verified - scripts skip (no action) |
| ✅ only | Managed - run policy checks |
| ❌ only | Excluded - skip all policy scripts |
| Both ✅ and ❌ | Globally pinned - no changes to ANY software |

## Software-Specific Tags

Tags with software suffix (e.g., `HUNTRESS`, `UNCHECKY`) that control individual software:

| Tag | Example | Purpose | Set By | Persists |
|-----|---------|---------|--------|----------|
| 🙏 | 🙏HUNTRESS | Install if missing | Admin | No - removed after action |
| 🚫 | 🚫HUNTRESS | Remove if present | Admin | No - removed after action |
| 📌 | 📌HUNTRESS | Pin (don't touch) | Admin | Yes - admin intent |
| 🔄 | 🔄HUNTRESS | Reinstall (remove + install) | Admin/Automation | No - removed after action |
| ✅ | ✅HUNTRESS | Status: Currently installed | Script | Yes - reflects state |

## Priority Resolution

When multiple tags exist for the same software, highest priority wins:

| Priority | Tag | Action |
|----------|-----|--------|
| 1 (highest) | 📌 Pin | No action - preserve current state |
| 2 | 🔄 Reinstall | Remove then install |
| 3 | 🚫 Remove | Remove software |
| 4 (lowest) | 🙏 Install | Install software |

### Combined Tag Scenarios

| Tags Present | Resolved Action | Reason |
|--------------|-----------------|--------|
| 🙏software | Install | Single action tag |
| 🚫software | Remove | Single action tag |
| 📌software | Pin | Single action tag |
| 🔄software | Reinstall | Single action tag |
| 🙏 + 🚫 | Remove | Remove > Install |
| 🙏 + 📌 | Pin | Pin > Install |
| 🚫 + 📌 | Pin | Pin > Remove |
| 🔄 + 📌 | Pin | Pin > Reinstall |
| 🔄 + 🚫 | Reinstall | Reinstall > Remove |
| 🙏 + 🚫 + 📌 | Pin | Pin wins all |
| ✅software only | No action | Status tag only - no policy change |

## Invalid Tags

These combinations are invalid and will generate warnings:

| Invalid Tag | Reason | Use Instead |
|-------------|--------|-------------|
| ❌software | Cross is global-only (no suffix) | 📌software for software-specific pin |

## Tag Cleanup Rules

After any action completes successfully:

| Action | Tags to Remove | Tags to Set |
|--------|----------------|-------------|
| Install | 🙏software | ✅software |
| Remove | 🚫software, ✅software | (none) |
| Reinstall | 🔄software | ✅software |
| Pin | (none) | (none) |

**Key Principle:** Action tags (🙏, 🚫, 🔄) are transient - they trigger an action and get cleaned up. Only status tags (✅) and intent tags (📌) persist.

## Custom Field Policy (Fallback)

When no software-specific tags exist, check `policy_<software>` custom field:

| Value | Meaning |
|-------|---------|
| `install` | Install on all devices in this group/folder |
| `remove` | Remove from all devices in this group/folder |
| `pin` | Don't change software state |
| (empty) | No policy - inherit from parent or skip |

**Inheritance:** Device inherits from Folder, Folder inherits from Group.

**Override:** Device-level tags always override custom field policy.

## Script Execution Flow

```
1. CHECK GLOBAL TAGS
   - Has ❌ (global cross)? → EXIT (excluded)
   - Has ✅ (global checkmark)? NO → EXIT (not verified)
   - Has BOTH ✅ AND ❌? → EXIT (globally pinned)

2. CHECK SOFTWARE-SPECIFIC TAGS (priority order)
   - 📌software → EXIT (pinned, no changes)
   - 🔄software → Remove + Install → Remove 🔄 → Set ✅software → EXIT
   - 🚫software → Remove → Remove 🚫 → Remove ✅software → EXIT
   - 🙏software → Install → Remove 🙏 → Set ✅software → EXIT

3. CHECK CUSTOM FIELD POLICY
   - policy_<software> = "install" → Install if missing → Set ✅software
   - policy_<software> = "remove" → Remove if present → Remove ✅software
   - policy_<software> = "pin" → No changes
   - policy_<software> = "" → No policy, skip

4. VERIFY STATE & RECONCILE
   - Installed and working → Ensure ✅software is set
   - Not installed but ✅software exists → Remove ✅software tag
```

## Unicode Reference

| Emoji | Name | Unicode | Code Point | PowerShell |
|-------|------|---------|------------|------------|
| ✅ | Checkmark | U+2705 | 0x2705 | `[char]0x2705` |
| ❌ | Cross | U+274C | 0x274C | `[char]0x274C` |
| 🙏 | Pray | U+1F64F | 0x1F64F | `[char]::ConvertFromUtf32(0x1F64F)` |
| 🚫 | Prohibit | U+1F6AB | 0x1F6AB | `[char]::ConvertFromUtf32(0x1F6AB)` |
| 📌 | Pushpin | U+1F4CC | 0x1F4CC | `[char]::ConvertFromUtf32(0x1F4CC)` |
| 🔄 | Arrows | U+1F504 | 0x1F504 | `[char]::ConvertFromUtf32(0x1F504)` |

## Examples

### Example 1: New Device Setup
1. Admin adds device to Level.io
2. Admin adds ✅ tag (device is managed)
3. Group has `policy_huntress = install`
4. Script runs → installs Huntress → adds ✅HUNTRESS

### Example 2: Exception Override
1. Device has ✅ and ✅HUNTRESS (Huntress installed via policy)
2. Admin adds 🚫HUNTRESS (wants it removed from this device only)
3. Script runs → removes Huntress → removes 🚫HUNTRESS → removes ✅HUNTRESS

### Example 3: Temporary Pin
1. Device has ✅ and ✅HUNTRESS
2. Admin adds 📌HUNTRESS (don't touch during maintenance)
3. Script runs → sees 📌 → exits without changes
4. After maintenance, admin removes 📌HUNTRESS

### Example 4: Device Moves Groups
1. Device has ✅ and ✅DNSFILTER (configured for old group)
2. Automation fires: "device entered new group"
3. Automation adds 🔄DNSFILTER tag
4. Script runs → uninstalls → reinstalls with new config → removes 🔄 → keeps ✅DNSFILTER

### Example 5: Global Exclusion
1. Admin adds ❌ tag to device (server that shouldn't be touched)
2. All COOLForge scripts skip this device entirely

### Example 6: Global Pin (Freeze All)
1. Device has both ✅ and ❌ tags
2. Device is verified but pinned globally
3. All COOLForge scripts skip ALL actions on this device
