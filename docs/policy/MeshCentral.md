# MeshCentral Policy

Software policy enforcement for MeshCentral remote management agent.

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
|  MeshCentral URLs) |
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
   policy, downloads agent
   from server URL, installs
   or removes MeshCentral
         |
         v
+--------------------+
| Check Tags &       |
| Policy Field       |
+--------+-----------+
         |
         v
+------------------+
| Check Tags &     |
| Policy Field     |
+--------+---------+
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

## Overview

Manages MeshCentral agent installation and removal based on tag and custom field policies.

## Policy Field

`policy_meshcentral` - Set to "install", "remove", or leave empty for tag-based control.

## Additional Fields

| Field | Description |
|-------|-------------|
| `policy_meshcentral_server_url` | MeshCentral server URL |
| `policy_meshcentral_download_url` | Windows agent download URL |
| `policy_meshcentral_linux_install` | Linux installation command |
| `policy_meshcentral_mac_download_url` | macOS agent download URL |

## Tags

| Tag | Action |
|-----|--------|
| Install tag | Install MeshCentral if missing |
| Remove tag | Remove MeshCentral if present |
| Pin tag | Lock current state |
| Has tag | Status indicator (set by script) |

## Platforms

- Windows (PowerShell launcher)
- Linux (Bash launcher)
- macOS (Bash launcher)

## Related

- [Policy System](README.md)
- [Tag System](TAGS.md)
