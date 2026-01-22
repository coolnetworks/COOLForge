# Unchecky Policy Enforcement

Automated installation and removal of [Unchecky](https://unchecky.com/) across your managed devices.

## Flow

```
+--------------------+
| Launcher Start     |
+--------+-----------+
         |
         v
+--------------------+
| Load Level.io Vars |
| (API Key, Tags,    |
|  Unchecky URL)     |
+--------+-----------+
         |
         v
+--------------------+
| Download MD5SUMS   |
| & Verify Library   |
+--------+-----------+
         |
         v
+--------------------+
| Import COOLForge   |
| Common Module      |
+--------+-----------+
         |
         v
+--------------------+
| Invoke-Script      |
| Launcher           |
+========+===========+
         |
   SCRIPT: Checks tags and
   policy, downloads from
   hosted URL, installs
   or removes Unchecky
         |
         v
+--------------------+
| Check Tags &       |
| Policy Field       |
+--------+-----------+
         |
    +----+----+----+----+
    |    |    |    |    |
    v    v    v    v    v
+----+ +----+ +---+ +----+ +---+
|Skip| |Pin | |Rem| |Inst| |Has|
+----+ +--+-+ +-+-+ +-+--+ +-+-+
           |    |     |     |
           v    v     v     v
        +------+ +------+ +------+
        |No-op | |Remove| |Install|
        +------+ +------+ +------+
                   |        |
                   v        v
          +--------------------+
          | Update Has Tag     |
          +--------+-----------+
                   |
                   v
          +--------------------+
          |  Exit 0/1          |
          +--------------------+
```

## Quick Start

> **IMPORTANT:** Complete ALL steps before running the script. The script will fail if custom fields are not configured.

### 1. Configure Required Custom Fields FIRST

Create these custom fields in Level.io at the **Organization** level:

| Level.io Field | Script Variable | Value |
|----------------|-----------------|-------|
| `coolforge_msp_scratch_folder` | `{{cf_coolforge_msp_scratch_folder}}` | `C:\ProgramData\YourMSP` |
| `policy_unchecky` | `{{cf_policy_unchecky}}` | `install`, `remove`, or `pin` |
| `policy_unchecky_url` | `{{cf_policy_unchecky_url}}` | URL to your hosted installer |

> **Note:** Level.io adds `cf_` prefix automatically when referencing in scripts.

### 2. Host the Unchecky Installer

1. Download `unchecky_setup.exe` from [FossHub](https://www.fosshub.com/Unchecky.html)
2. Upload to a publicly accessible URL (S3, Azure Blob, Wasabi, web server, etc.)
3. Set `policy_unchecky_url` to your hosted URL

### 3. Import the Policy Check

Import the pre-built automation:
**https://app.level.io/import/monitor/Z2lkOi8vbGV2ZWwvQWxsb3dlZEltcG9ydC8zNDY**

### 4. Run the Script

The script will auto-create required tags on first run.

---

## How It Works

### Policy Values

| Value | Behavior |
|-------|----------|
| `install` | Install Unchecky if missing |
| `remove` | Remove Unchecky if present, block future installs |
| `pin` | Preserve current state, no changes |
| (empty) | Inherit from parent or skip |

**Inheritance:** Device < Folder < Group (device-level overrides group-level)

### Override Tags

Tags override custom field policy. Add these to individual devices:

| Tag | Action |
|-----|--------|
| `🙏UNCHECKY` | Force install |
| `🚫UNCHECKY` | Force remove |
| `📌UNCHECKY` | Pin state (no changes) |
| `🔄UNCHECKY` | Reinstall |

### Status Tag

| Tag | Meaning |
|-----|---------|
| `✅UNCHECKY` | Unchecky is installed (set automatically by script) |

---

## Files

| File | Path | Purpose |
|------|------|---------|
| Launcher | `launchers/Policy/👀unchecky.ps1` | Deploy to Level.io |
| Script | `scripts/Policy/👀unchecky.ps1` | Policy enforcement logic |
| Module | `modules/COOLForge-Common.psm1` | Shared library |

---

## Troubleshooting

### Debug Mode

Set `cf_debug_scripts = true` on the device for verbose output.

### Common Issues

| Issue | Solution |
|-------|----------|
| Script does nothing | Add `✅` tag to device |
| Tags not updating | Set `cf_apikey` custom field |
| Install fails | Set `policy_unchecky_url` custom field |

---

## Version History

| Version | Changes |
|---------|---------|
| 2026.01.13.08 | Move to SoftwarePolicy folder, simplify setup |
| 2026.01.13.07 | Require policy_unchecky_url custom field |
| 2026.01.13.06 | Add policy_unchecky_url custom field support |
| 2026.01.13.05 | Pin+Remove sets custom field to "remove" |
