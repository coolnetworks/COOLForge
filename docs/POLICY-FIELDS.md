# COOLForge Policy Fields

This document explains how `policy_` custom fields work in COOLForge.

## Overview

Policy fields control automated software deployment and configuration management. They use a consistent format across all COOLForge scripts.

## Value Format

All policy fields use this format:

```
value | description
```

**Examples:**
```
pin | uses pin/install/remove (change to activate policy)
install | uses pin/install/remove (change to activate policy)
block | uses block/unblock (change to enable/disable policies)
```

The `|` delimiter separates the actual policy value from helpful documentation. Scripts only read the part before `|`.

## Policy Values

### Software/Config Policies

| Value | Action | Description |
|-------|--------|-------------|
| `pin` | No changes | Freeze current state - don't install or remove |
| `install` | Install if missing | Deploy the software/enable the setting |
| `remove` | Remove if present | Uninstall the software/disable the setting |

**Synonyms accepted:**
- Install: `install`, `enable`, `on`, `yes`, `true`, `allow`
- Remove: `remove`, `disable`, `off`, `no`, `false`, `block`, `deny`, `uninstall`
- Pin: `pin`, `lock`, `freeze`, `hold`

### Device Blocking

| Value | Action |
|-------|--------|
| `block` | Block ALL policy changes on this device |
| `unblock` | Allow policy enforcement |

**Default:** `block` - devices are safe by default until explicitly unblocked.

## Tag Override

Tags (emojis on devices in Level.io) override custom field policies:

| Tag | Meaning | Priority |
|-----|---------|----------|
| `📌SOFTWARE` | Pin - no changes | Highest (1) |
| `🔄SOFTWARE` | Reinstall | 2 |
| `🚫SOFTWARE` | Remove | 3 |
| `🙏SOFTWARE` | Install | 4 (Lowest) |

**Example:** A device with `🙏CHROME` tag will install Chrome even if `policy_chrome = remove`.

## Field List

### Core Policy Fields

| Field | Purpose | Values |
|-------|---------|--------|
| `policy_0_readme` | Documentation (read-only) | - |
| `policy_block_device` | Block all policies | block/unblock |

### Software Policies

| Field | Software | Values |
|-------|----------|--------|
| `policy_chrome` | Google Chrome Enterprise | pin/install/remove |
| `policy_meshcentral` | MeshCentral Agent | pin/install/remove |
| `policy_screenconnect` | ScreenConnect (Control) | pin/install/remove |
| `policy_unchecky` | Unchecky | pin/install/remove |
| `policy_huntress` | Huntress Agent | pin/install/remove |
| `policy_dnsfilter` | DNSFilter | pin/install/remove |

### Configuration Policies

| Field | Setting | Values | Meaning |
|-------|---------|--------|---------|
| `policy_device_locationservices` | Windows Location | pin/install/remove | install=enable, remove=disable |
| `policy_chrome_locationservices` | Chrome Geolocation | pin/install/remove | install=allow prompts, remove=block |

### Supporting Fields

Some policies require additional fields:

| Policy | Additional Fields |
|--------|-------------------|
| `policy_meshcentral` | `policy_meshcentral_server_url`, `policy_meshcentral_download_url` |
| `policy_screenconnect` | `policy_screenconnect_instance_id`, `policy_screenconnect_baseurl`, `policy_screenconnect_api_user`, `policy_screenconnect_api_password`, `policy_screenconnect_device_url` |
| `policy_unchecky` | `policy_unchecky_url` |

## Inheritance

Custom field values inherit down the Level.io hierarchy:

```
Account (Global)
  └── Group (Customer/Site)
        └── Device
```

Values set at higher levels apply to all children unless overridden.

**Recommended pattern:**
1. Set `policy_block_device = block` at Account level (safe default)
2. Set `policy_block_device = unblock` on specific Groups to enable policies
3. Override individual device policies with tags as needed

## Examples

### Safe Rollout of Chrome

1. Set `policy_chrome = pin | uses pin/install/remove` at Account level
2. Set `policy_chrome = install | uses pin/install/remove` on a test Group
3. After testing, change Account level to `install`
4. Use `📌CHROME` tag on any device that shouldn't change

### Emergency Stop

Add `📌SOFTWARE` tag to any device to immediately freeze that software's state, regardless of field values.

### Device Exclusion

Set `policy_block_device = block | uses block/unblock` on a device to exclude it from all policy enforcement.

## Auto-Creation on First Run

When any COOLForge policy script runs for the first time, it automatically creates:

1. **`policy_0_readme`** - Documentation field (always created first)
2. **`policy_block_device`** - Device blocking field (defaults to `block`)
3. **Policy-specific fields** - The field for that software/config

### Default Values Created

Each policy field is created with a self-documenting default value:

| Field Type | Default Value |
|------------|---------------|
| Standard software | `pin \| uses pin/install/remove (change to activate policy)` |
| Windows location | `pin \| uses pin/install/remove (install=enable, remove=disable)` |
| Chrome location | `pin \| uses pin/install/remove (install=allow, remove=block)` |
| Device blocking | `block \| uses block/unblock (change to enable/disable policies)` |
| Readme | `COOLForge Policies \| Format: value \| docs. Values: pin/install/remove...` |

### Tag Name vs Field Name

Most scripts use the same name for both tags and fields (e.g. `huntress` creates `HUNTRESS` tags and `policy_huntress` field). ScreenConnect is an exception — it uses `SC` for tags but `screenconnect` for fields. This is controlled by the `TagName` parameter on `Initialize-SoftwarePolicyInfrastructure`:

```powershell
# Standard (tag name = software name)
Initialize-SoftwarePolicyInfrastructure -SoftwareName "huntress"
# Tags: HUNTRESS  |  Field: policy_huntress

# Split naming (tag name != software name)
Initialize-SoftwarePolicyInfrastructure -SoftwareName "screenconnect" -TagName "sc"
# Tags: SC  |  Field: policy_screenconnect
```

When `TagName` differs from `SoftwareName`, any stale `policy_{TagName}` field (e.g. `policy_sc`) is automatically deleted.

### Why Self-Documenting Values?

The `|` delimiter allows values to include inline documentation:

```
pin | uses pin/install/remove (change to activate policy)
```

- **Scripts read:** `pin` (everything before `|`)
- **Admins see:** The full string with helpful context
- **No separate documentation needed:** Instructions are embedded in the value

When you change a policy, just change the first word:

```
install | uses pin/install/remove (change to activate policy)
```

### Field Definitions

All field definitions are stored in `definitions/custom-fields.json`:

```json
{
  "name": "policy_chrome",
  "default": "pin",
  "valueOptions": ["pin", "install", "remove"],
  "valueFormat": "{value} | uses pin/install/remove (change to activate policy)"
}
```

The setup wizard uses `valueFormat` to construct the full self-documenting value by replacing `{value}` with the selected option.

## See Also

- [policy/TAGS.md](policy/TAGS.md) - Complete tag specification
- [definitions/custom-fields.json](../definitions/custom-fields.json) - Field definitions
- [definitions/tags.json](../definitions/tags.json) - Tag definitions
