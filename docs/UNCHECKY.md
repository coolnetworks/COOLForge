# Unchecky Policy Enforcement

Automated installation and removal of [Unchecky](https://unchecky.com/) across your managed devices using the COOLForge policy tag system.

## Quick Start

### Prerequisites

1. **COOLForge Setup Complete** - Run `Setup-COOLForge.ps1` to create required custom fields
2. **Device Tagged** - Device must have `✅` (checkmark) tag to be managed
3. **API Key Configured** - `cf_apikey` custom field set for tag management

### Deploy to All Devices in a Group

1. Set `policy_unchecky = install` on the Group or Folder
2. Add `✅` tag to devices you want managed
3. Run the `👀unchecky` script via Level.io automation or manually
4. Script installs Unchecky and adds `✅UNCHECKY` status tag

### Deploy to a Single Device

1. Add `✅` tag to device (if not already present)
2. Add `🙏UNCHECKY` tag to device
3. Run the script - it installs Unchecky, removes `🙏UNCHECKY`, adds `✅UNCHECKY`

### Remove from a Single Device

1. Add `🚫UNCHECKY` tag to device
2. Run the script - it removes Unchecky, removes both `🚫UNCHECKY` and `✅UNCHECKY`
3. Device custom field is set to `remove` to prevent reinstallation

### Block Installation Permanently

1. Add both `📌UNCHECKY` and `🚫UNCHECKY` tags to device
2. Run the script - Pin wins (no action), but custom field is set to `remove`
3. Both tags are removed, device is now blocked from future installs via policy

---

## Custom Fields

### Required Custom Fields

| Field Name | Type | Level | Description |
|------------|------|-------|-------------|
| `cf_coolforge_msp_scratch_folder` | Text | Organization | Persistent storage folder (e.g., `C:\ProgramData\YourMSP`) |
| `cf_coolforge_ps_module_library_source` | Text | Organization | URL to COOLForge-Common.psm1 module |
| `cf_apikey` | Text (Admin-only) | Organization | Level.io API key for tag management |

### Policy Custom Fields

| Field Name | Type | Level | Values | Description |
|------------|------|-------|--------|-------------|
| `policy_unchecky` | Text | Group/Folder/Device | `install`, `remove`, `pin`, (empty) | Default policy with inheritance |
| `policy_unchecky_url` | Text | Organization | URL | **Required** - URL to download Unchecky installer |

### Optional Custom Fields

| Field Name | Type | Level | Description |
|------------|------|-------|-------------|
| `cf_debug_scripts` | Text | Device | Set to `true` for verbose debug output |
| `cf_coolforge_pin_psmodule_to_version` | Text | Organization | Pin to specific release (e.g., `v2026.01.13.06`) |

---

## Policy Values

The `policy_unchecky` custom field controls default behavior:

| Value | Behavior |
|-------|----------|
| `install` | Install Unchecky if missing |
| `remove` | Remove Unchecky if present, block future installs |
| `pin` | Preserve current state, no changes |
| (empty) | No policy - inherit from parent or skip |

**Inheritance:** Device inherits from Folder, Folder inherits from Group.

**Override:** Device-level tags always override custom field policy.

---

## Tags Reference

### Global Control Tags (Standalone)

| Tag | Purpose |
|-----|---------|
| `✅` | Device is managed by COOLForge (required) |
| `❌` | Device is excluded from all COOLForge management |
| `✅` + `❌` | Device is globally pinned (no changes to any software) |

### Software-Specific Tags (with UNCHECKY suffix)

| Tag | Purpose | Set By | Persists | Sets Custom Field |
|-----|---------|--------|----------|-------------------|
| `🙏UNCHECKY` | Install if missing | Admin | No | `install` |
| `🚫UNCHECKY` | Remove if present | Admin | No | `remove` |
| `📌UNCHECKY` | Pin - no changes | Admin | No* | `pin` or `remove`** |
| `🔄UNCHECKY` | Reinstall | Admin | No | - |
| `✅UNCHECKY` | Status: installed | Script | Yes | - |

*Pin tag is removed after intent is captured in custom field
**If both Pin and Remove tags present, custom field is set to `remove`

### Tag Priority (Highest to Lowest)

1. `📌` Pin - No action, preserve state
2. `🔄` Reinstall - Remove then install
3. `🚫` Remove - Uninstall software
4. `🙏` Install - Install software

---

## Files

### Launcher

**Path:** `launchers/👀unchecky.ps1`

The launcher is deployed to Level.io and handles:
- Downloading the script from GitHub
- Version checking and auto-updates
- Passing Level.io variables to the script
- Library auto-update

**Key Configuration (top of launcher):**
```powershell
$ScriptToRun = "👀unchecky.ps1"
$ScriptCategory = "Check"
$policy_unchecky = "{{cf_policy_unchecky}}"
```

### Script

**Path:** `scripts/Check/👀unchecky.ps1`

The actual policy enforcement script that:
- Checks global and software-specific tags
- Resolves policy from tags or custom field
- Installs/removes Unchecky as needed
- Updates tags to reflect current state
- Sets custom fields to persist admin intent

### Module

**Path:** `modules/COOLForge-Common.psm1`

Shared library containing:
- Level.io API functions
- Tag management functions
- Policy resolution logic
- Emoji corruption handling

---

## Execution Flow

```
1. LAUNCHER RUNS
   ├── Downloads/updates COOLForge-Common.psm1
   ├── Downloads/updates 👀unchecky.ps1
   └── Executes script with Level.io variables

2. SCRIPT INITIALIZES
   ├── Validates scratch folder
   ├── Checks device hostname
   └── Parses device tags

3. CHECK GLOBAL TAGS
   ├── Has ❌? → EXIT (excluded)
   ├── Has ✅? NO → EXIT (not verified)
   └── Has ✅ AND ❌? → EXIT (globally pinned)

4. CHECK SOFTWARE TAGS (priority order)
   ├── 📌UNCHECKY → Set custom field → Remove tags → EXIT
   ├── 🔄UNCHECKY → Remove + Install → Update tags → EXIT
   ├── 🚫UNCHECKY → Remove → Set custom field → Update tags → EXIT
   └── 🙏UNCHECKY → Install → Set custom field → Update tags → EXIT

5. CHECK CUSTOM FIELD POLICY
   ├── policy_unchecky = "install" → Install if missing
   ├── policy_unchecky = "remove" → Remove if present
   ├── policy_unchecky = "pin" → No changes
   └── policy_unchecky = "" → Skip

6. UPDATE TAGS
   ├── Remove action tags (🙏, 🚫, 🔄, 📌)
   └── Set/remove status tag (✅UNCHECKY) based on install state

7. EXIT
   └── Exit code 0 (success) or 1 (alert/failure)
```

---

## Installation Details

### Detection

Unchecky is detected by checking:
- File: `C:\Program Files\Unchecky\unchecky.exe`
- File: `C:\Program Files (x86)\Unchecky\unchecky.exe`
- Registry: `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Unchecky`
- Registry: `HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Unchecky`

### Install Process

1. Download installer to `<scratch>/Installers/unchecky_setup.exe`
2. Validate file size (minimum 1MB)
3. Run silent install: `unchecky_setup.exe -install -no_desktop_icon`
4. Delete installer after completion

**Installer URL:** You must host the Unchecky installer yourself and set the `policy_unchecky_url` custom field.

**Getting the Installer:**
1. Download from [FossHub - Unchecky](https://www.fosshub.com/Unchecky.html)
2. Host the `unchecky_setup.exe` file on a publicly accessible URL (e.g., S3, Azure Blob, your own web server)
3. Set the `policy_unchecky_url` custom field to your hosted URL

### Uninstall Process

1. Locate install folder (`Program Files` or `Program Files (x86)`)
2. Copy `uninstall.exe` to temp folder
3. Run silent uninstall: `uninstall.exe -uninstall -path "<install_path>" -delsettings 1`
4. Clean up temp folder

---

## Examples

### Example 1: Deploy to New Client

```
1. Create custom fields (run Setup-COOLForge.ps1)
2. Download Unchecky installer from https://www.fosshub.com/Unchecky.html
3. Host the installer on a publicly accessible URL
4. Set Organization custom fields:
   - cf_coolforge_msp_scratch_folder = C:\ProgramData\YourMSP
   - cf_coolforge_ps_module_library_source = (GitHub URL)
   - cf_apikey = (your Level.io API key)
   - policy_unchecky_url = (your hosted installer URL)
5. Set Group policy:
   - policy_unchecky = install
6. Add ✅ tag to devices
5. Create automation to run 👀unchecky launcher
```

### Example 2: Exclude Server from Unchecky

```
1. Server has ✅ tag and Unchecky installed via group policy
2. Add 🚫UNCHECKY and 📌UNCHECKY tags
3. Script runs:
   - Pin wins (no action taken)
   - Custom field set to "remove"
   - Both tags removed
4. Future runs: Custom field "remove" prevents reinstall
```

### Example 3: Reinstall After Issue

```
1. Device has ✅UNCHECKY but Unchecky is broken
2. Add 🔄UNCHECKY tag
3. Script runs:
   - Uninstalls Unchecky
   - Reinstalls fresh
   - Removes 🔄UNCHECKY
   - Keeps ✅UNCHECKY
```

### Example 4: Check Status Without Action

```
1. Device has ✅ tag but no policy set
2. Script runs:
   - Detects current install state
   - Sets/removes ✅UNCHECKY to match reality
   - No install/uninstall performed
```

---

## Troubleshooting

### Enable Debug Mode

Set `cf_debug_scripts = true` on the device to see verbose output including:
- All launcher variables
- Tag byte analysis (for emoji corruption diagnosis)
- Policy resolution details
- API call details

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| Script does nothing | Device missing ✅ tag | Add ✅ tag to device |
| Tags not updating | Missing API key | Set `cf_apikey` custom field |
| Wrong policy resolved | Tag corruption | Check debug output for byte patterns |
| Install fails | URL not configured | Set `policy_unchecky_url` custom field |
| Uninstall fails | Unchecky in use | Reboot and retry |

### Log Files

- **Scratch folder:** `<scratch>/Logs/` contains script execution logs
- **Emoji tag log:** `<scratch>/EmojiTags.log` records tag byte patterns for debugging

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 2026.01.13.07 | 2026-01-13 | Require policy_unchecky_url custom field (no default URL) |
| 2026.01.13.06 | 2026-01-13 | Add policy_unchecky_url custom field support |
| 2026.01.13.05 | 2026-01-13 | Pin+Remove sets custom field to "remove", removes both tags |
| 2026.01.13.04 | 2026-01-13 | Remove tag sets custom field to "remove" |
| 2026.01.13.03 | 2026-01-13 | Move debug functions to module |
| 2026.01.13.02 | 2026-01-13 | Install/Pin tags set custom field |
| 2026.01.13.01 | 2026-01-13 | Initial 5-tag policy implementation |
