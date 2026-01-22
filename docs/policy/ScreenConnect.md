# ScreenConnect Policy

Software policy enforcement for ConnectWise ScreenConnect (Control) remote access agent.

## Flow

```
+------------------+
|  Script Start    |
+--------+---------+
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
              +------------------+
              | Update Has Tag   |
              +------------------+
                       |
                       v
              +------------------+
              |  Exit 0/1        |
              +------------------+
```

## Overview

Manages ScreenConnect agent installation and removal based on tag and custom field policies.

## Policy Field

`policy_screenconnect` - Set to "install", "remove", or leave empty for tag-based control.

## Additional Fields

| Field | Description |
|-------|-------------|
| `policy_screenconnect_instance_id` | ScreenConnect instance identifier |
| `policy_screenconnect_api_user` | API username for device URL lookup |
| `policy_screenconnect_api_password` | API password |
| `policy_screenconnect_device_url` | Device-specific ScreenConnect URL (auto-populated) |
| `policy_screenconnect_instance` | Instance name |
| `policy_screenconnect_baseurl` | Base URL for ScreenConnect server |

## Tags

| Tag | Action |
|-----|--------|
| Install tag | Install ScreenConnect if missing |
| Remove tag | Remove ScreenConnect if present |
| Pin tag | Lock current state |
| Has tag | Status indicator (set by script) |

## Related Scripts

- [Extract and Set ScreenConnect Device URL](../scripts/ScreenConnect-Device-URL.md)
- [Force Remove Non-MSP ScreenConnect](../scripts/Force-Remove-Non-MSP-ScreenConnect.md)

## Related

- [Policy System](README.md)
- [Tag System](TAGS.md)
