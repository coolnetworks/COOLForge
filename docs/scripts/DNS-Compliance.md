# DNS Server Compliance Policy

**Script:** `scripts/Policy/👀dns.ps1`
**Launcher:** `launchers/Policy/👀dns.ps1`
**Version:** 2026.01.31.01
**Category:** Policy

## Purpose

Checks that all physical network adapters are using approved DNS servers. Ignores virtual adapters (Hyper-V, TAP, VPN, etc.) that typically use internal/localhost DNS.

## Features

- **Physical adapter filtering** — Skips virtual, tunnel, and VPN adapters
- **DNSFilter awareness** — When DNSFilter agent is running, automatically allows 127.0.0.1/127.0.0.2 (local proxy addresses)
- **DNSFilter remediation** — If DNSFilter agent is installed but DNS servers are wrong, applies the reinstall tag to trigger DNSFilter reinstallation
- **Auto-creates policy field** if missing (requires API key)

## Custom Fields

| Level.io Field | Script Variable | Required | Description |
|----------------|-----------------|----------|-------------|
| `policy_allowed_dns_servers` | `{{cf_policy_allowed_dns_servers}}` | Yes | Comma-separated list of approved DNS server IPs |
| `apikey` | `{{cf_apikey}}` | No | Level.io API key for auto-creating fields |

## Flow

1. Read allowed DNS servers from custom field
2. Check if DNSFilter agent is running → auto-add localhost addresses
3. Get physical network adapters (skip virtual/tunnel)
4. Compare each adapter's DNS servers against allowed list
5. Report non-compliant adapters
6. If DNSFilter installed but DNS wrong → apply reinstall tag

## Files

| File | Path | Purpose |
|------|------|---------|
| Launcher | `launchers/Policy/👀dns.ps1` | Deploy to Level.io |
| Script | `scripts/Policy/👀dns.ps1` | DNS compliance logic |
| Module | `modules/COOLForge-Common.psm1` | Shared library |

## Related

- [DNSFilter Policy](../policy/DNSFilter.md) — DNSFilter agent management
- [Policy System](../policy/README.md)
