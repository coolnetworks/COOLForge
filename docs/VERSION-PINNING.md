# Version Pinning

By default, scripts and the launcher use the latest code from the `main` branch. You can pin devices to a specific release version, development branch, or any Git reference using the `CoolForge_pin_psmodule_to_version` custom field.

---

## When to Use Version Pinning

- **Development Testing** — Test bleeding-edge features from the `dev` branch
- **Staged Rollouts** — Test new versions on a subset of devices before fleet-wide deployment
- **Stability** — Keep production devices on a known-good version
- **Rollback** — Quickly revert to a previous version if issues arise

---

## How It Works

1. Create a custom field `CoolForge_pin_psmodule_to_version` in Level.io
2. Set the value to a branch name, release tag, or Git reference
3. Scripts will download from that reference instead of `main`

**URL transformation:**
```
Default (no pinning):
https://raw.githubusercontent.com/coolnetworks/COOLForge/main/modules/COOLForge-Common.psm1

With CoolForge_pin_psmodule_to_version = dev:
https://raw.githubusercontent.com/coolnetworks/COOLForge/dev/modules/COOLForge-Common.psm1

With CoolForge_pin_psmodule_to_version = v2025.12.29:
https://raw.githubusercontent.com/coolnetworks/COOLForge/v2025.12.29/modules/COOLForge-Common.psm1
```

---

## Pin Options

| Pin Value | Description | Use Case |
|-----------|-------------|----------|
| *(empty)* or `main` | Latest stable release | Production devices |
| `dev` | Latest development version | Testing new features, beta testing |
| `v2025.12.30` | Specific tagged release | Staging, known-good version |
| Any Git ref | Branch, tag, or commit SHA | Advanced use cases |

---

## Output Example

When version pinning is active:
```
[*] Version pinned to: dev
[*] Library not found - downloading...
[+] Library updated to v2025.12.30.01
```

---

## Removing the Pin

To return to the latest stable version:
- Clear the `CoolForge_pin_psmodule_to_version` custom field value, or
- Delete the custom field from the device/group

---

## Common Workflows

### Testing Development Features

Test new features before they reach production:

1. Set `CoolForge_pin_psmodule_to_version = dev` on test devices
2. Run scripts to get latest development code
3. Test functionality, report issues
4. When ready, clear pin to use stable `main` branch

### Staged Rollout of New Release

Deploy new versions safely:

1. Release new version `v2025.12.30` to GitHub
2. Set `CoolForge_pin_psmodule_to_version = v2025.12.30` on a test group
3. Verify everything works on test devices
4. Clear the pin on production devices to roll out automatically

### Rollback to Previous Version

Quickly revert if issues found:

1. Issue discovered in latest release
2. Set `CoolForge_pin_psmodule_to_version = v2025.12.29` on affected devices
3. Scripts revert to known-good version immediately
4. Investigate and fix issue
5. Clear pin when fix is deployed

### Development Workflow

Use dev branch for active development:

```powershell
# Your workstation or dev devices
CoolForge_pin_psmodule_to_version = dev

# Test group devices
CoolForge_pin_psmodule_to_version = v2025.12.30

# Production devices
CoolForge_pin_psmodule_to_version = (empty - uses main)
```

---

## See Also

- [Main README](../README.md)
- [Script Launcher Guide](LAUNCHER.md)
