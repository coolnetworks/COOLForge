# Version Pinning

By default, scripts and the launcher use the latest code from the `main` branch. You can pin devices to a specific release version using the `CoolForge_pin_psmodule_to_version` custom field.

---

## When to Use Version Pinning

- **Staged Rollouts** — Test new versions on a subset of devices before fleet-wide deployment
- **Stability** — Keep production devices on a known-good version
- **Rollback** — Quickly revert to a previous version if issues arise

---

## How It Works

1. Create a custom field `CoolForge_pin_psmodule_to_version` in Level.io
2. Set the value to a release tag (e.g., `v2025.12.29`)
3. Scripts will download from that tag instead of `main`

**URL transformation:**
```
Default (no pinning):
https://raw.githubusercontent.com/coolnetworks/COOLForge/main/modules/COOLForge-Common.psm1

With pin_psmodule_to_version = v2025.12.29:
https://raw.githubusercontent.com/coolnetworks/COOLForge/v2025.12.29/modules/COOLForge-Common.psm1
```

---

## Output Example

When version pinning is active:
```
[*] Version pinned to: v2025.12.29
[*] Library not found - downloading...
[+] Library updated to v2025.12.29.01
```

---

## Removing the Pin

To return to the latest version:
- Clear the `CoolForge_pin_psmodule_to_version` custom field value, or
- Delete the custom field from the device/group

---

## Staged Rollout Example

1. Release new version `v2025.12.30` to GitHub
2. Set `CoolForge_pin_psmodule_to_version = v2025.12.30` on a test group
3. Verify everything works on test devices
4. Clear the pin on production devices to roll out

---

## See Also

- [Main README](../README.md)
- [Script Launcher Guide](LAUNCHER.md)
