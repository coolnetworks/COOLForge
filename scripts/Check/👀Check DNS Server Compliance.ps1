<#
.SYNOPSIS
    Monitors DNS server configuration for compliance.

.DESCRIPTION
    Checks that all network adapters are using approved DNS servers.
    Ignores virtual adapters (Hyper-V, TAP, VPN, etc.) that typically
    use internal/localhost DNS.

    This script is designed for environments where DNS filtering is
    required (e.g., DNSFilter, Cisco Umbrella) and you need to ensure
    devices aren't bypassing the filter.

.NOTES
    Version:          2026.01.17.01
    Target Platform:  Level.io RMM (via Script Launcher)
    Exit Codes:       0 = Success (Compliant) | 1 = Alert (Non-compliant)

    Level.io Variables Used (passed from Script Launcher):
    - $MspScratchFolder  : MSP-defined scratch folder for persistent storage
    - $DeviceHostname    : Device hostname from Level.io
    - $DeviceTags        : Comma-separated list of device tags

    Additional Custom Fields (define in launcher):
    - $AllowedDnsServers : Comma-separated list of allowed DNS server IPs

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# Check DNS Server Compliance
# Version: 2026.01.17.01
# Target: Level.io (via Script Launcher)
# Exit 0 = Success (Compliant) | Exit 1 = Alert (Non-compliant)
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge

# ============================================================
# INITIALIZE
# ============================================================
$Init = Initialize-LevelScript -ScriptName "DNSCompliance" `
                               -MspScratchFolder $MspScratchFolder `
                               -DeviceHostname $DeviceHostname `
                               -DeviceTags $DeviceTags

if (-not $Init.Success) {
    exit 0
}

# Sync script-level debug variables if a debug tag overrode the custom field
if ($Init.DebugTagDetected) {
    $DebugLevel = $Init.DebugLevel
    $DebugScripts = $Init.DebugMode
}

# ============================================================
# CONFIGURATION
# ============================================================
# Allowed DNS servers from custom field (passed from launcher)
$AllowedDnsVar = "AllowedDnsServers"
$AllowedDnsRaw = Get-Variable -Name $AllowedDnsVar -ValueOnly -ErrorAction SilentlyContinue
if ([string]::IsNullOrWhiteSpace($AllowedDnsRaw) -or $AllowedDnsRaw -like "{{*}}") {
    $AllowedDnsRaw = $null
}

# Adapter name patterns to ignore (virtual/tunnel adapters)
$IgnoredAdapterPatterns = @(
    "*Hyper-V*"
    "*TAP*"
    "*VPN*"
    "*Virtual*"
    "*Loopback*"
    "*Tunnel*"
    "*WAN Miniport*"
    "*Bluetooth*"
    "*Microsoft Wi-Fi Direct*"
    "*Microsoft Kernel Debug*"
    "*Npcap*"
    "*Teredo*"
    "*isatap*"
    "*6to4*"
)

# ============================================================
# MAIN SCRIPT LOGIC
# ============================================================
Invoke-LevelScript -ScriptBlock {

    Write-LevelLog "Starting DNS Server Compliance Check"

    # Validate configuration
    if (-not $AllowedDnsRaw) {
        Write-Host "Alert: DNS compliance check not configured"
        Write-Host "  Set the 'cf_dns' custom field with allowed DNS servers"
        Write-Host "  Example: 1.1.1.1, 1.0.0.1, 8.8.8.8"
        Write-LevelLog "AllowedDnsServers not configured - cannot check compliance" -Level "ERROR"
        Complete-LevelScript -ExitCode 1 -Message "DNS compliance check not configured"
        return
    }

    # Parse allowed DNS servers
    $AllowedDnsServers = $AllowedDnsRaw -split "\s*,\s*" | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }

    if ($AllowedDnsServers.Count -eq 0) {
        Write-Host "Alert: No valid DNS servers in allowed list"
        Write-Host "  Current value: $AllowedDnsRaw"
        Write-LevelLog "No valid IP addresses in AllowedDnsServers" -Level "ERROR"
        Complete-LevelScript -ExitCode 1 -Message "Invalid DNS server list"
        return
    }

    Write-LevelLog "Allowed DNS servers: $($AllowedDnsServers -join ', ')"

    # Get network adapters with IP enabled
    $NetworkAdapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue |
        Where-Object { $_.IPEnabled -eq $true }

    if (-not $NetworkAdapters) {
        Write-LevelLog "No IP-enabled network adapters found" -Level "WARN"
        Complete-LevelScript -ExitCode 0 -Message "No adapters to check"
        return
    }

    # Track results
    $CheckedAdapters = @()
    $NonCompliantAdapters = @()
    $SkippedAdapters = @()

    foreach ($Adapter in $NetworkAdapters) {
        $AdapterName = $Adapter.Description

        # Check if adapter should be ignored
        $ShouldIgnore = $false
        foreach ($Pattern in $IgnoredAdapterPatterns) {
            if ($AdapterName -like $Pattern) {
                $ShouldIgnore = $true
                break
            }
        }

        if ($ShouldIgnore) {
            $SkippedAdapters += @{
                Name = $AdapterName
                Reason = "Virtual/tunnel adapter"
            }
            continue
        }

        # Get DNS servers for this adapter
        $DnsServers = $Adapter.DNSServerSearchOrder

        $AdapterResult = @{
            Name = $AdapterName
            DnsServers = $DnsServers
            Compliant = $true
            NonCompliantServers = @()
        }

        if ($DnsServers -and $DnsServers.Count -gt 0) {
            # Check each DNS server
            foreach ($DnsServer in $DnsServers) {
                if ($DnsServer -notin $AllowedDnsServers) {
                    $AdapterResult.Compliant = $false
                    $AdapterResult.NonCompliantServers += $DnsServer
                }
            }
        }
        else {
            # No DNS servers configured - using DHCP, considered OK
            $AdapterResult.Compliant = $true
            $AdapterResult.DnsServers = @("(DHCP)")
        }

        $CheckedAdapters += $AdapterResult

        if (-not $AdapterResult.Compliant) {
            $NonCompliantAdapters += $AdapterResult
        }
    }

    # Output results
    Write-Host ""
    Write-LevelLog "========================================" -Level "INFO"
    Write-LevelLog "DNS Server Compliance Results" -Level "INFO"
    Write-LevelLog "========================================" -Level "INFO"
    Write-Host ""

    Write-Host "Allowed DNS Servers: $($AllowedDnsServers -join ', ')"
    Write-Host ""

    # Show skipped adapters in debug mode
    if ($DebugScripts -and $SkippedAdapters.Count -gt 0) {
        Write-Host "Skipped Adapters (virtual/tunnel):" -ForegroundColor DarkGray
        foreach ($Skipped in $SkippedAdapters) {
            Write-Host "  - $($Skipped.Name)" -ForegroundColor DarkGray
        }
        Write-Host ""
    }

    # Show checked adapters
    foreach ($Adapter in $CheckedAdapters) {
        $StatusIcon = if ($Adapter.Compliant) { "[OK]" } else { "[!!]" }
        $StatusColor = if ($Adapter.Compliant) { "Green" } else { "Red" }

        Write-Host "$StatusIcon $($Adapter.Name)" -ForegroundColor $StatusColor
        Write-Host "    DNS: $(if ($Adapter.DnsServers) { $Adapter.DnsServers -join ', ' } else { '(none)' })"

        if (-not $Adapter.Compliant -and $Adapter.NonCompliantServers.Count -gt 0) {
            Write-Host "    Non-compliant: $($Adapter.NonCompliantServers -join ', ')" -ForegroundColor Yellow
        }
        Write-Host ""
    }

    # Final verdict
    if ($NonCompliantAdapters.Count -eq 0) {
        Write-LevelLog "All adapters using approved DNS servers" -Level "SUCCESS"
        Complete-LevelScript -ExitCode 0 -Message "DNS compliant"
    }
    else {
        $AdapterNames = ($NonCompliantAdapters | ForEach-Object { $_.Name }) -join ", "
        Write-Host ""
        Write-Host "Alert: DNS non-compliance detected"
        Write-Host "  Non-compliant adapters: $($NonCompliantAdapters.Count)"
        Write-Host "  Adapters: $AdapterNames"

        # List all non-compliant DNS servers
        $AllNonCompliant = $NonCompliantAdapters | ForEach-Object { $_.NonCompliantServers } | Select-Object -Unique
        Write-Host "  Unauthorized DNS: $($AllNonCompliant -join ', ')"

        Write-LevelLog "DNS non-compliance: $($NonCompliantAdapters.Count) adapter(s) using unauthorized DNS" -Level "ERROR"
        Complete-LevelScript -ExitCode 1 -Message "DNS non-compliant on $($NonCompliantAdapters.Count) adapter(s)"
    }
}
