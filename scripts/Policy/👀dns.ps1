<#
.SYNOPSIS
    DNS server compliance policy enforcement.

.DESCRIPTION
    Checks that all physical network adapters are using approved DNS servers.
    Ignores virtual adapters (Hyper-V, TAP, VPN, etc.) that typically use
    internal/localhost DNS.

    If DNSFilter agent is installed but DNS servers are wrong, applies the
    reinstall tag to trigger DNSFilter reinstallation via existing automation.

    When DNSFilter agent is running, 127.0.0.1 and 127.0.0.2 are automatically
    added to the allowed list (DNSFilter local proxy addresses).

    FLOW:
                         Launcher reads policy_allowed_dns_servers
                                          |
                                  Initialize script
                                          |
                              API key? ---> Auto-create field if missing
                                          |
                              Field configured? ---> No: alert, EXIT 1
                                          |
                         Parse allowed IPs (Google, Cloudflare, OpenDNS, DNSFilter)
                                          |
                         DNSFilter agent running? ---> Yes: auto-add 127.0.0.1/127.0.0.2
                                          |
                         Get physical adapters (skip virtual/tunnel)
                                          |
                      For each adapter: check DNS against allowed list
                      (no DNS / DHCP = non-compliant)
                                          |
                    +---------------------+---------------------+
                    |                                           |
              All compliant                            Non-compliant
              EXIT 0                                          |
                                          DNSFilter running + DNS wrong?
                                          ---> Yes: apply reinstall tag
                                          EXIT 1

.NOTES
    Version:          2026.01.31.01
    Target Platform:  Level.io RMM (via Script Launcher)
    Exit Codes:       0 = Success (Compliant) | 1 = Alert (Non-compliant)

    Level.io Variables Used (passed from Script Launcher):
    - $MspScratchFolder             : MSP-defined scratch folder for persistent storage
    - $DeviceHostname               : Device hostname from Level.io
    - $DeviceTags                   : Comma-separated list of device tags
    - $policy_allowed_dns_servers   : Comma-separated list of allowed DNS server IPs

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# DNS Server Compliance Policy
# Version: 2026.01.31.01
# Target: Level.io (via Script Launcher)
# Exit 0 = Success (Compliant) | Exit 1 = Alert (Non-compliant)
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge

# ============================================================
# CONFIGURATION
# ============================================================
# Allowed DNS servers from custom field (passed from launcher)
$AllowedDnsVar = "policy_allowed_dns_servers"
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
# MAIN SCRIPT LOGIC
# ============================================================
$ScriptVersion = "2026.01.31.01"
$ExitCode = 0

$InvokeParams = @{ ScriptBlock = {

    Write-LevelLog "DNS Server Compliance Check (v$ScriptVersion)"

    # ============================================================
    # AUTO-CREATE CUSTOM FIELD (if API key available)
    # ============================================================
    if ($LevelApiKey) {
        $FieldName = "policy_allowed_dns_servers"
        $ExistingField = Find-LevelCustomField -ApiKey $LevelApiKey -FieldName $FieldName
        if (-not $ExistingField) {
            $NewField = New-LevelCustomField -ApiKey $LevelApiKey -Name $FieldName -DefaultValue ""
            if ($NewField) {
                Write-LevelLog "Created custom field: $FieldName" -Level "SUCCESS"
                Write-Host ""
                Write-Host "Alert: DNS compliance custom field created - please configure it"
                Write-Host "  Set '$FieldName' in Level.io with allowed DNS server IPs"
                Write-Host "  Example: 8.8.8.8, 8.8.4.4, 127.0.0.1, 127.0.0.2"
                Write-Host ""
                Write-LevelLog "Custom field created - exiting for configuration" -Level "INFO"
                Complete-LevelScript -ExitCode 1 -Message "DNS compliance custom field created - configure allowed DNS servers"
                return
            }
        }
    }

    # ============================================================
    # VALIDATE CONFIGURATION
    # ============================================================
    if (-not $AllowedDnsRaw) {
        Write-Host "Alert: DNS compliance check not configured"
        Write-Host "  Set the 'policy_allowed_dns_servers' custom field with allowed DNS server IPs"
        Write-Host "  Example: 8.8.8.8, 8.8.4.4, 127.0.0.1, 127.0.0.2"
        Write-LevelLog "policy_allowed_dns_servers not configured - cannot check compliance" -Level "ERROR"
        Complete-LevelScript -ExitCode 1 -Message "DNS compliance check not configured"
        return
    }

    # Parse allowed DNS servers (validate IP format)
    $AllowedDnsServers = $AllowedDnsRaw -split "\s*,\s*" | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }

    if ($AllowedDnsServers.Count -eq 0) {
        Write-Host "Alert: No valid DNS servers in allowed list"
        Write-Host "  Current value: $AllowedDnsRaw"
        Write-LevelLog "No valid IP addresses in policy_allowed_dns_servers" -Level "ERROR"
        Complete-LevelScript -ExitCode 1 -Message "Invalid DNS server list"
        return
    }

    # If DNSFilter agent is running, auto-allow its local proxy addresses
    $DnsAgentService = Get-Service -Name "DNS Agent" -ErrorAction SilentlyContinue
    $DnsFilterRunning = $DnsAgentService -and $DnsAgentService.Status -eq 'Running'
    if ($DnsFilterRunning) {
        $DnsFilterAddresses = @("127.0.0.1", "127.0.0.2")
        foreach ($Addr in $DnsFilterAddresses) {
            if ($Addr -notin $AllowedDnsServers) {
                $AllowedDnsServers = @($AllowedDnsServers) + $Addr
            }
        }
        Write-LevelLog "DNSFilter running - auto-allowed 127.0.0.1, 127.0.0.2"
    }

    Write-LevelLog "Allowed DNS servers: $($AllowedDnsServers -join ', ')"

    # ============================================================
    # DNS COMPLIANCE CHECK
    # ============================================================
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
            # Check each DNS server against allowed list
            foreach ($DnsServer in $DnsServers) {
                if ($DnsServer -notin $AllowedDnsServers) {
                    $AdapterResult.Compliant = $false
                    $AdapterResult.NonCompliantServers += $DnsServer
                }
            }
        }
        else {
            # No DNS servers returned - non-compliant (DHCP may have assigned unknown DNS)
            $AdapterResult.Compliant = $false
            $AdapterResult.DnsServers = @("(no DNS / DHCP)")
        }

        $CheckedAdapters += $AdapterResult

        if (-not $AdapterResult.Compliant) {
            $NonCompliantAdapters += $AdapterResult
        }
    }

    # ============================================================
    # OUTPUT RESULTS
    # ============================================================
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

    # Summary
    $CompliantCount = ($CheckedAdapters | Where-Object { $_.Compliant }).Count
    Write-Host "Summary: $CompliantCount / $($CheckedAdapters.Count) adapters compliant"
    Write-Host ""

    # ============================================================
    # FINAL VERDICT
    # ============================================================
    if ($NonCompliantAdapters.Count -eq 0) {
        Write-LevelLog "All adapters using approved DNS servers" -Level "SUCCESS"
        Complete-LevelScript -ExitCode 0 -Message "DNS compliant"
    }
    else {
        $AdapterNames = ($NonCompliantAdapters | ForEach-Object { $_.Name }) -join ", "
        $AllNonCompliant = $NonCompliantAdapters | ForEach-Object { $_.NonCompliantServers } | Select-Object -Unique

        # Check if DNSFilter is installed but DNS is wrong
        if ($LevelApiKey) {
            $DnsAgentService = Get-Service -Name "DNS Agent" -ErrorAction SilentlyContinue
            if ($DnsAgentService -and $DnsAgentService.Status -eq 'Running') {
                Write-LevelLog "DNSFilter agent installed but DNS wrong - tagging for reinstall" -Level "WARN"
                Add-LevelPolicyTag -ApiKey $LevelApiKey -TagName "DNSFILTER" -EmojiPrefix "Reinstall" -DeviceHostname $DeviceHostname
            }
        }

        Write-LevelLog "DNS non-compliance: $($NonCompliantAdapters.Count) adapter(s) using unauthorized DNS" -Level "ERROR"
        $script:ExitCode = 1

        Write-Host ""
        Write-Host "Alert: DNS non-compliant - $($NonCompliantAdapters.Count) adapter(s) using unauthorized DNS: $($AllNonCompliant -join ', ')"
    }
}}
if ($RunningFromLauncher) { $InvokeParams.NoExit = $true }
Invoke-LevelScript @InvokeParams

exit $ExitCode
