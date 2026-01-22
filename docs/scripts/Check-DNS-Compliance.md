# Check DNS Server Compliance

Validates that device DNS server settings match expected configuration.

## Flow

```
+--------------------+
| Launcher Start     |
+--------+-----------+
         |
         v
+--------------------+
| Load Level.io Vars |
| (Expected DNS      |
|  Servers)          |
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
   SCRIPT: Checks each
   adapter's DNS against
   expected servers,
   reports compliance
         |
         v
+--------------------+
| Get Network        |
| Adapters           |
+--------+-----------+
         |
         v
+--------------------+
| Check DNS          |
| Settings           |
+--------+-----------+
         |
    +----+----+
    |         |
    v         v
+--------+ +--------+
|Compliant| |Non-   |
|Exit 0  | |Compliant|
+--------+ |Exit 1  |
           +--------+
```

## Purpose

Checks if the device's DNS servers are configured correctly according to organizational policy.

## Features

- Validates primary and secondary DNS servers
- Reports non-compliant configurations
- Supports multiple network adapters

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | DNS configuration compliant |
| 1 | DNS configuration non-compliant or error |

## Usage

Deploy via Level.io automation. No additional configuration required.

## Related

- [DNSFilter Policy](../policy/DNSFilter.md)
