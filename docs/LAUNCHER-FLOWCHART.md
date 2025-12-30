# Launcher Flowchart

Visual representation of how the COOLForge Script Launcher works.

---

## High-Level Flow

```
┌────────────────────────────────────────────────────────────────────┐
│                         Level.io RMM                               │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  Launcher Script (deployed once)                         │    │
│  │  $ScriptToRun = "👀Test Show Versions.ps1"              │    │
│  └───────────────────────┬──────────────────────────────────┘    │
│                          │                                        │
└──────────────────────────┼────────────────────────────────────────┘
                           │
                           ▼
         ┌─────────────────────────────────────┐
         │  1. Download/Update Library         │
         │  COOLForge-Common.psm1              │
         │  from GitHub                        │
         └──────────────┬──────────────────────┘
                        │
                        ▼
         ┌─────────────────────────────────────┐
         │  2. Download Target Script          │
         │  scripts/👀Test Show Versions.ps1   │
         │  from GitHub                        │
         └──────────────┬──────────────────────┘
                        │
                        ▼
         ┌─────────────────────────────────────┐
         │  3. Pass Level.io Variables         │
         │  $MspScratchFolder                  │
         │  $DeviceHostname                    │
         │  $DeviceTags                        │
         └──────────────┬──────────────────────┘
                        │
                        ▼
         ┌─────────────────────────────────────┐
         │  4. Execute Downloaded Script       │
         │  with Library Functions             │
         └──────────────┬──────────────────────┘
                        │
                        ▼
         ┌─────────────────────────────────────┐
         │  5. Return Exit Code to Level.io    │
         │  0 = Success | 1 = Failure          │
         └─────────────────────────────────────┘
```

---

## Detailed Execution Flow

```
START: Level.io triggers launcher
│
├─► Read custom fields
│   ├─ cf_CoolForge_msp_scratch_folder → $MspScratchFolder
│   ├─ cf_CoolForge_ps_module_library_source → $LibraryUrl (optional)
│   ├─ cf_CoolForge_pin_psmodule_to_version → $PinnedVersion (optional)
│   ├─ level_device_hostname → $DeviceHostname
│   └─ level_tag_names → $DeviceTags
│
├─► Determine library URL
│   ├─ If $LibraryUrl is empty → use default GitHub URL
│   ├─ If $PinnedVersion set → use tagged version URL
│   └─ Else → use main branch URL
│
├─► Check library cache
│   ├─ Library path: $MspScratchFolder\Libraries\COOLForge-Common.psm1
│   │
│   ├─ Library exists and is current version?
│   │  ├─ YES → Skip download
│   │  └─ NO ↓
│   │
│   ├─► Download library from GitHub
│   │   ├─ Create backup of existing library (if exists)
│   │   ├─ Download to temp file
│   │   ├─ Verify download succeeded
│   │   ├─ Move temp file to library path
│   │   └─ On error: restore from backup
│   │
│   └─► Import library module
│       └─ Import-Module $LibraryPath -Force
│
├─► Determine script URL
│   ├─ Script name from $ScriptToRun variable
│   ├─ Base URL from library source
│   ├─ If version pinned → use tagged URL
│   └─ Build full URL: {base}/scripts/{category}/{ScriptName}
│
├─► Check script cache
│   ├─ Script path: $MspScratchFolder\Scripts\{ScriptName}
│   │
│   ├─ Script exists and is current version?
│   │  ├─ YES → Skip download
│   │  └─ NO ↓
│   │
│   ├─► Download script from GitHub
│   │   ├─ Emoji repair on script name (fix UTF-8 corruption)
│   │   ├─ Create backup of existing script (if exists)
│   │   ├─ Download to temp file
│   │   ├─ Verify download succeeded
│   │   ├─ Move temp file to script path
│   │   └─ On error: restore from backup
│   │
│   └─► Load script content
│       └─ Read script file into memory
│
├─► Prepare script environment
│   ├─ Create script scope
│   ├─ Inject variables:
│   │  ├─ $MspScratchFolder
│   │  ├─ $LibraryUrl
│   │  ├─ $DeviceHostname
│   │  └─ $DeviceTags
│   │
│   └─ Import library functions into script scope
│
├─► Execute script
│   ├─ Run script content via Invoke-Expression or dot-sourcing
│   ├─ Script uses library functions (Initialize-LevelScript, etc.)
│   ├─ Script performs its task
│   └─ Script calls Complete-LevelScript or exits
│
├─► Capture exit code
│   ├─ 0 = Success (green in Level.io)
│   └─ 1 = Failure/Alert (red in Level.io)
│
└─► END: Return to Level.io
```

---

## Version Pinning Flow

When `cf_CoolForge_pin_psmodule_to_version = v2025.12.29` is set:

```
┌─────────────────────────────────────────────────────┐
│  Without Version Pinning (default)                  │
└─────────────────────────────────────────────────────┘
    │
    ▼
https://raw.githubusercontent.com/coolnetworks/COOLForge/main/modules/COOLForge-Common.psm1
https://raw.githubusercontent.com/coolnetworks/COOLForge/main/scripts/Check/👀Test Show Versions.ps1

┌─────────────────────────────────────────────────────┐
│  With Version Pinning (v2025.12.29)                 │
└─────────────────────────────────────────────────────┘
    │
    ▼
https://raw.githubusercontent.com/coolnetworks/COOLForge/v2025.12.29/modules/COOLForge-Common.psm1
https://raw.githubusercontent.com/coolnetworks/COOLForge/v2025.12.29/scripts/Check/👀Test Show Versions.ps1
```

**Use Cases:**
1. Test new version on subset of devices before fleet-wide rollout
2. Keep production devices on known-good version
3. Instant rollback if new version has issues

---

## Caching and Update Logic

```
┌─────────────────────────────────────────────────────┐
│  First Run (nothing cached)                         │
└─────────────────────────────────────────────────────┘
    │
    ├─► Download library from GitHub
    ├─► Save to: C:\ProgramData\MSP\Libraries\COOLForge-Common.psm1
    ├─► Download script from GitHub
    ├─► Save to: C:\ProgramData\MSP\Scripts\{ScriptName}.ps1
    └─► Execute script

┌─────────────────────────────────────────────────────┐
│  Subsequent Runs (cached)                           │
└─────────────────────────────────────────────────────┘
    │
    ├─► Check library version in cache
    │   ├─ Current version? → Use cached
    │   └─ Old version? → Download new version
    │
    ├─► Check script in cache
    │   ├─ Exists? → Use cached
    │   └─ Missing? → Download
    │
    └─► Execute script

┌─────────────────────────────────────────────────────┐
│  Offline Mode (no GitHub access)                    │
└─────────────────────────────────────────────────────┘
    │
    ├─► Try to download library
    │   └─ Failed → Use cached version if available
    │
    ├─► Try to download script
    │   └─ Failed → Use cached version if available
    │
    └─► Execute from cache (or fail if no cache)
```

---

## Error Handling Flow

```
Library Download Failure:
│
├─ Backup exists?
│  ├─ YES → Restore from backup, continue
│  └─ NO → Check cache
│     ├─ Cached version exists? → Use cache, log warning
│     └─ No cache → ERROR: Cannot proceed

Script Download Failure:
│
├─ Backup exists?
│  ├─ YES → Restore from backup, continue
│  └─ NO → Check cache
│     ├─ Cached version exists? → Use cache, log warning
│     └─ No cache → ERROR: Cannot download script

Script Execution Failure:
│
├─ Exception caught
├─ Log error details
├─ Remove lockfile (if created)
├─ Exit with code 1 (failure/alert)
└─ Level.io shows alert
```

---

## File System Layout

```
{{cf_CoolForge_msp_scratch_folder}}/    (typically C:\ProgramData\MSP)
│
├── Libraries/
│   ├── COOLForge-Common.psm1           ← Main library module
│   └── COOLForge-Common.psm1.bak       ← Backup (created during update)
│
├── Scripts/
│   ├── 👀Test Show Versions.ps1        ← Cached scripts
│   ├── ⛔Force Remove Anydesk.ps1
│   ├── 👀Check for Unauthorized RATs.ps1
│   └── *.ps1.bak                       ← Backups (created during update)
│
└── lockfiles/
    ├── MyScript.lock                   ← Active lockfiles
    └── AnotherScript.lock
```

---

## One Launcher, Many Scripts

```
┌──────────────────────────────────────────────────────────────┐
│  Level.io Scripts (deployed once each)                       │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  Script: "Test Versions"                                     │
│  ┌────────────────────────────────────────────┐              │
│  │ $ScriptToRun = "👀Test Show Versions.ps1" │              │
│  │ {launcher code}                            │              │
│  └────────────────────────────────────────────┘              │
│                                                               │
│  Script: "Remove AnyDesk"                                    │
│  ┌────────────────────────────────────────────┐              │
│  │ $ScriptToRun = "⛔Force Remove Anydesk.ps1"│              │
│  │ {launcher code}                            │              │
│  └────────────────────────────────────────────┘              │
│                                                               │
│  Script: "Check for RATs"                                    │
│  ┌────────────────────────────────────────────────────┐      │
│  │ $ScriptToRun = "👀Check for Unauthorized RATs.ps1"│      │
│  │ {launcher code}                                    │      │
│  └────────────────────────────────────────────────────┘      │
└──────────────────────────────────────────────────────────────┘
                         │
                         │ All launchers download from
                         ▼
┌──────────────────────────────────────────────────────────────┐
│  GitHub Repository: coolnetworks/COOLForge                   │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  scripts/Check/👀Test Show Versions.ps1                      │
│  scripts/Remove/⛔Force Remove Anydesk.ps1                   │
│  scripts/Check/👀Check for Unauthorized RATs.ps1             │
│  scripts/Fix/🔧Fix Windows 11 Services.ps1                   │
│  scripts/Utility/🙏Wake all devices in folder.ps1            │
│  ... (all scripts in Git)                                    │
│                                                               │
│  modules/COOLForge-Common.psm1 (library)                     │
└──────────────────────────────────────────────────────────────┘
```

**Key Point:** Change `$ScriptToRun` = different script runs. Update GitHub = all scripts update automatically.

---

## Benefits Visualized

### Traditional Approach (No Launcher)

```
Update Script → Edit in Level.io web UI → Save → Manually redeploy to devices
   ↑______________________________________________________________|
                  (repeat for each script change)
```

### COOLForge Launcher Approach

```
Update Script → Push to GitHub → Done
                      ↓
           All devices auto-update on next run
```

**Difference:**
- Traditional: Minutes per update, manual process, error-prone
- COOLForge: Seconds per update, automatic, version controlled

---

## See Also

- [Launcher Guide](LAUNCHER.md) - Detailed setup instructions
- [Version Pinning](VERSION-PINNING.md) - Control which version runs
- [Main README](../README.md) - Getting started
