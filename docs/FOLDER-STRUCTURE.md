# Folder Structure

COOLForge organizes scripts into logical categories for easier management and discovery.

---

## Script Categories

| Folder | Purpose | Examples |
|--------|---------|----------|
| `Deploy/` | Install software, deploy configurations | Install-Chrome, Deploy-PrinterDriver |
| `Remove/` | Uninstall software, cleanup | Remove-Bloatware, Uninstall-OldSoftware |
| `Update/` | Patch and upgrade existing software | Update-Office, Patch-Windows |
| `Fix/` | Repair broken things, remediation | Fix-WindowsServices, Repair-WMI |
| `Configure/` | Change settings (no new installs) | Set-PowerOptions, Configure-Firewall |
| `Check/` | Read-only audits, compliance, health | Check-Compliance, Test-Connectivity |
| `Secure/` | Hardening, security policies | Enable-BitLocker, Harden-RDP |
| `Maintain/` | Scheduled maintenance, cleanup | Clear-TempFiles, Optimize-Disk |
| `Provision/` | New device/user setup | Setup-NewDevice, Onboard-User |
| `Report/` | Generate reports, inventory | Get-Inventory, Export-LicenseReport |
| `Utility/` | Miscellaneous tools, helpers | Wake-Devices, Test-Variables |

---

## Folder Structure

```
COOLForge/
├── scripts/
│   ├── Deploy/
│   ├── Remove/
│   ├── Update/
│   ├── Fix/
│   ├── Configure/
│   ├── Check/
│   ├── Secure/
│   ├── Maintain/
│   ├── Provision/
│   ├── Report/
│   └── Utility/
├── automations/
│   └── (same structure as scripts/)
├── launchers/
├── modules/
├── tools/
└── docs/
```

---

## How the Launcher Finds Scripts

The launcher uses the `MD5SUMS` file to locate scripts in subfolders:

1. Launcher receives script name (e.g., `🔧Fix Windows 10 Services.ps1`)
2. Downloads `MD5SUMS` from the repository
3. Searches for the script name in MD5SUMS entries
4. Extracts the full path (e.g., `scripts/Fix/🔧Fix Windows 10 Services.ps1`)
5. Downloads from the correct location

This means:
- Script names in Level.io stay simple (no folder paths needed)
- Moving scripts between folders only requires updating `MD5SUMS`
- Backwards compatible with flat structure (fallback if not found in MD5SUMS)

---

## Adding a New Script

1. Create the script in the appropriate category folder
2. Run `tools/Update-MD5SUMS.ps1` to regenerate checksums
3. Create a launcher (copy existing and change `$ScriptToRun`)
4. Deploy the launcher to Level.io

---

## Creating the Folder Structure

Run the setup script to create all folders:

```powershell
.\tools\New-ScriptFolderStructure.ps1
```

This creates both `scripts/` and `automations/` folder hierarchies.

---

## Naming Conventions

**Recommended format:** `Emoji` + `Verb-Noun` + `.ps1`

| Category | Emoji | Example |
|----------|-------|---------|
| Deploy | (none or custom) | `Install-Chrome.ps1` |
| Remove | ⛔ | `⛔Force Remove Anydesk.ps1` |
| Fix | 🔧 | `🔧Fix Windows 10 Services.ps1` |
| Check | 👀 | `👀Check for Unauthorized Remote Access Tools.ps1` |
| Utility | 🙏 or 🔧 | `🙏Wake all devices.ps1` |

The emoji prefix is optional but helps with visual identification in Level.io.

---

## See Also

- [Variables Reference](VARIABLES.md)
- [Function Reference](FUNCTIONS.md)
- [Main README](../README.md)
