<#
.SYNOPSIS
    Configures Windows workstations for Wake-on-LAN and disables power-saving features.

.DESCRIPTION
    This script enables Wake-on-LAN (WOL) on all physical network adapters and intelligently
    configures power settings based on adapter capabilities:

    Network Adapter Configuration:
    - Enables WakeOnMagicPacket on wired adapters
    - Enables WoWLAN (Wireless Wake-on-LAN) on wireless adapters
    - Disables Energy Efficient Ethernet (EEE) which can block WOL
    - Configures WMI power management settings
    - Sets registry values for persistent WOL configuration

    Power Settings (Adaptive):
    - Hibernation: Always disabled (blocks WOL)
    - Fast Startup: Always disabled (blocks WOL)
    - Hybrid Sleep: Always disabled
    - Wake Timers: Always enabled

    Modern Standby Handling:
    - If WoWLAN-capable wireless adapter found: Keep Modern Standby ENABLED
      (WoWLAN works with Modern Standby and provides better battery life)
    - If wired adapter supports Modern Standby wake (D0ix/Directed WoL): Keep Modern Standby ENABLED
      (Newer Intel I219/I225 NICs support wake from Modern Standby)
    - If only legacy wired adapters: Disable Modern Standby
      (Traditional WOL requires S3 sleep, not Modern Standby)

.NOTES
    Version:          2026.01.13.03
    Target Platform:  Windows 10, Windows Server 2016+
    Exit Codes:       0 = Success (adapters configured) | 1 = Failure (no adapters found)

    IMPORTANT: WOL must also be enabled in BIOS/UEFI settings for this to work.
    A system restart is required for all changes to take effect.

.EXAMPLE
    .\Configure Wake-on-LAN.ps1
    Configures all network adapters for WOL and adjusts power settings based on capabilities.

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# Configure Wake-on-LAN
# Version: 2026.01.13.03
# Target: Level.io
# Exit 0 = Success | Exit 1 = Alert (Failure)

[CmdletBinding()]
param ()

begin {
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    function Test-WoWLANCapable {
        param([string]$AdapterName)

        # Check if adapter has WoWLAN properties
        $wowlanProps = @('*WoWLAN', 'WoWLANS5Wake', 'Wake on WLAN')
        foreach ($prop in $wowlanProps) {
            $existing = Get-NetAdapterAdvancedProperty -Name $AdapterName -RegistryKeyword $prop -ErrorAction SilentlyContinue
            if ($existing) { return $true }
            $existing = Get-NetAdapterAdvancedProperty -Name $AdapterName -DisplayName $prop -ErrorAction SilentlyContinue
            if ($existing) { return $true }
        }
        return $false
    }

    function Test-ModernStandbyWakeCapable {
        param(
            [string]$AdapterName,
            [string]$AdapterDescription
        )

        # Check for adapters known to support wake from Modern Standby (D0ix/Directed WoL)
        # Intel I219, I225, I226 series support this
        # Some Realtek 2.5G adapters also support it

        $modernStandbyCapablePatterns = @(
            'Intel.*I219',
            'Intel.*I225',
            'Intel.*I226',
            'Intel.*Ethernet Controller I225',
            'Intel.*Ethernet Controller I226',
            'Intel.*Ethernet Connection.*I219',
            'Realtek.*2\.5G',
            'Realtek.*Gaming.*2\.5G',
            'Killer.*E3100',
            'Killer.*E3200'
        )

        foreach ($pattern in $modernStandbyCapablePatterns) {
            if ($AdapterDescription -match $pattern) {
                return $true
            }
        }

        # Also check for specific driver properties that indicate Modern Standby support
        # *DeviceSleepOnDisconnect and *ModernStandbyWoLMagicPacket are indicators
        $modernStandbyProps = @('*ModernStandbyWoLMagicPacket', '*DeviceSleepOnDisconnect', 'Idle Power Saving')
        foreach ($prop in $modernStandbyProps) {
            $existing = Get-NetAdapterAdvancedProperty -Name $AdapterName -RegistryKeyword $prop -ErrorAction SilentlyContinue
            if ($existing) { return $true }
            $existing = Get-NetAdapterAdvancedProperty -Name $AdapterName -DisplayName $prop -ErrorAction SilentlyContinue
            if ($existing) { return $true }
        }

        return $false
    }

    $results = @{
        Adapters = @()
        PowerSettings = @{}
        Errors = @()
        HasWoWLAN = $false
        HasModernStandbyWiredWake = $false
        SupportsModernStandbyWake = $false
    }
}

process {
    if (-not (Test-IsElevated)) {
        Write-Host "[Alert] This script requires Administrator privileges"
        exit 1
    }

    Write-Host "========================================"
    Write-Host "  WOL and Power Configuration"
    Write-Host "========================================"
    Write-Host "  Computer: $env:COMPUTERNAME"
    Write-Host "  Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Host ""

    # ============================================
    # DETECT ADAPTERS FIRST (to determine WoWLAN capability)
    # ============================================

    Write-Host "[DETECTING NETWORK ADAPTERS]"

    # Exclude virtual and non-physical adapters
    $excludePattern = 'Bluetooth|Hyper-V|VMware|VirtualBox|Loopback|WAN Miniport|TAP-Windows|Tunnel|Teredo|ISATAP|6to4|Npcap|Microsoft Wi-Fi Direct|Microsoft Hosted'
    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -notmatch $excludePattern }

    Write-Host "  Found $($adapters.Count) adapter(s)"

    # Check for WoWLAN and Modern Standby wake capability
    $wirelessAdapters = @()
    $wiredAdapters = @()

    foreach ($adapter in $adapters) {
        $isWireless = $adapter.InterfaceDescription -match 'Wireless|Wi-Fi|WiFi|WLAN|802\.11|Qualcomm|MediaTek|Killer|Intel.*Wireless|Realtek.*Wireless|Broadcom.*Wireless'
        if ($isWireless) {
            $wirelessAdapters += $adapter
            if (Test-WoWLANCapable -AdapterName $adapter.Name) {
                $results.HasWoWLAN = $true
                Write-Host "  [INFO] $($adapter.Name): WoWLAN capable (Modern Standby compatible)"
            }
            else {
                Write-Host "  [INFO] $($adapter.Name): Wireless (no WoWLAN)"
            }
        }
        else {
            $wiredAdapters += $adapter
            if (Test-ModernStandbyWakeCapable -AdapterName $adapter.Name -AdapterDescription $adapter.InterfaceDescription) {
                $results.HasModernStandbyWiredWake = $true
                Write-Host "  [INFO] $($adapter.Name): Wired - Modern Standby wake capable (D0ix/Directed WoL)"
            }
            else {
                Write-Host "  [INFO] $($adapter.Name): Wired - Traditional WOL only"
            }
        }
    }

    # Determine if we can keep Modern Standby enabled
    $results.SupportsModernStandbyWake = $results.HasWoWLAN -or $results.HasModernStandbyWiredWake

    if ($results.SupportsModernStandbyWake) {
        if ($results.HasWoWLAN -and $results.HasModernStandbyWiredWake) {
            Write-Host "  [OK] Both WoWLAN and wired Modern Standby wake detected - preserving Modern Standby"
        }
        elseif ($results.HasWoWLAN) {
            Write-Host "  [OK] WoWLAN-capable adapter detected - preserving Modern Standby"
        }
        else {
            Write-Host "  [OK] Modern Standby-compatible wired adapter detected - preserving Modern Standby"
        }
    }
    else {
        Write-Host "  [INFO] No Modern Standby wake capability - will disable for traditional S3 WOL"
    }

    # ============================================
    # POWER SETTINGS (adaptive based on WoWLAN)
    # ============================================

    Write-Host ""
    Write-Host "[POWER SETTINGS]"

    $fastBootPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
    $powerPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Power"

    # Disable Hibernation (always - blocks all WOL types)
    try {
        $null = & powercfg /hibernate off 2>&1
        Write-Host "  [OK] Hibernation disabled"
        $results.PowerSettings['Hibernation'] = 'Disabled'
    }
    catch {
        Write-Host "  [FAIL] Could not disable hibernation"
        $results.Errors += "Hibernation: $_"
    }

    # Disable Fast Startup (always - blocks all WOL types)
    try {
        if (-not (Test-Path $fastBootPath)) {
            New-Item -Path $fastBootPath -Force | Out-Null
        }
        New-ItemProperty -Path $fastBootPath -Name 'HiberbootEnabled' -Value 0 -PropertyType DWord -Force | Out-Null
        Write-Host "  [OK] Fast Startup disabled"
        $results.PowerSettings['FastStartup'] = 'Disabled'
    }
    catch {
        Write-Host "  [FAIL] Failed to disable Fast Startup"
        $results.Errors += "FastStartup: $_"
    }

    # Modern Standby - ONLY disable if no adapter supports Modern Standby wake
    if (-not (Test-Path $powerPath)) {
        New-Item -Path $powerPath -Force | Out-Null
    }

    if ($results.SupportsModernStandbyWake) {
        # Keep Modern Standby enabled - adapter(s) support wake from it
        $wakeType = if ($results.HasWoWLAN -and $results.HasModernStandbyWiredWake) {
            "WoWLAN + Wired D0ix"
        } elseif ($results.HasWoWLAN) {
            "WoWLAN"
        } else {
            "Wired D0ix"
        }

        try {
            # Remove override if it exists (allow Modern Standby)
            Remove-ItemProperty -Path $powerPath -Name 'PlatformAoAcOverride' -ErrorAction SilentlyContinue
            Write-Host "  [OK] Modern Standby preserved ($wakeType compatible)"
            $results.PowerSettings['ModernStandby'] = "Enabled ($wakeType)"
        }
        catch {
            Write-Host "  [INFO] Modern Standby already enabled"
            $results.PowerSettings['ModernStandby'] = "Enabled ($wakeType)"
        }

        # Keep Connected Standby enabled
        try {
            Remove-ItemProperty -Path $powerPath -Name 'CsEnabled' -ErrorAction SilentlyContinue
            Write-Host "  [OK] Connected Standby preserved ($wakeType compatible)"
            $results.PowerSettings['ConnectedStandby'] = "Enabled ($wakeType)"
        }
        catch {
            Write-Host "  [INFO] Connected Standby already enabled"
            $results.PowerSettings['ConnectedStandby'] = "Enabled ($wakeType)"
        }
    }
    else {
        # Disable Modern Standby for traditional WOL (requires S3 sleep)
        try {
            New-ItemProperty -Path $powerPath -Name 'PlatformAoAcOverride' -Value 0 -PropertyType DWord -Force | Out-Null
            Write-Host "  [OK] Modern Standby disabled (for traditional S3 WOL)"
            $results.PowerSettings['ModernStandby'] = 'Disabled'
        }
        catch {
            Write-Host "  [FAIL] Could not disable Modern Standby"
            $results.Errors += "ModernStandby: $_"
        }

        # Disable Connected Standby
        try {
            New-ItemProperty -Path $powerPath -Name 'CsEnabled' -Value 0 -PropertyType DWord -Force | Out-Null
            Write-Host "  [OK] Connected Standby disabled"
            $results.PowerSettings['ConnectedStandby'] = 'Disabled'
        }
        catch {
            Write-Host "  [INFO] Connected Standby not applicable"
        }
    }

    # Disable Hybrid Sleep and Enable Wake Timers in all power plans (always)
    try {
        $schemes = powercfg /list | Select-String -Pattern 'GUID: (\S+)' | ForEach-Object { $_.Matches.Groups[1].Value }
        foreach ($scheme in $schemes) {
            # Hybrid Sleep OFF (Sleep subgroup: 238c9fa8-0aad-41ed-83f4-97be242c8f20)
            $null = powercfg /setacvalueindex $scheme 238c9fa8-0aad-41ed-83f4-97be242c8f20 94ac6d29-73ce-41a6-809f-6363ba21b47e 0 2>&1
            $null = powercfg /setdcvalueindex $scheme 238c9fa8-0aad-41ed-83f4-97be242c8f20 94ac6d29-73ce-41a6-809f-6363ba21b47e 0 2>&1
            # Wake Timers ON
            $null = powercfg /setacvalueindex $scheme 238c9fa8-0aad-41ed-83f4-97be242c8f20 bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d 1 2>&1
            $null = powercfg /setdcvalueindex $scheme 238c9fa8-0aad-41ed-83f4-97be242c8f20 bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d 1 2>&1
        }
        Write-Host "  [OK] Hybrid Sleep disabled"
        Write-Host "  [OK] Wake Timers enabled"
        $results.PowerSettings['HybridSleep'] = 'Disabled'
        $results.PowerSettings['WakeTimers'] = 'Enabled'
    }
    catch {
        Write-Host "  [Alert] Could not configure power plans"
    }

    # ============================================
    # CONFIGURE NETWORK ADAPTERS
    # ============================================

    Write-Host ""
    Write-Host "[CONFIGURING NETWORK ADAPTERS]"

    if (-not $adapters -or $adapters.Count -eq 0) {
        Write-Host "  [Alert] No network adapters found"
        $results.Errors += "No network adapters found"
    }
    else {
        foreach ($adapter in $adapters) {
            $isWireless = $adapter.InterfaceDescription -match 'Wireless|Wi-Fi|WiFi|WLAN|802\.11|Qualcomm|MediaTek|Killer|Intel.*Wireless|Realtek.*Wireless|Broadcom.*Wireless'
            $adapterType = if ($isWireless) { "Wireless" } else { "Wired" }

            Write-Host ""
            Write-Host "  [$adapterType] $($adapter.Name)"
            Write-Host "    $($adapter.InterfaceDescription)"
            Write-Host "    MAC: $($adapter.MacAddress) - Status: $($adapter.Status)"

            $adapterResult = @{
                Name = $adapter.Name
                Description = $adapter.InterfaceDescription
                MACAddress = $adapter.MacAddress
                Type = $adapterType
                Status = [string]$adapter.Status
                Settings = @{}
            }

            # Registry keyword properties for WOL
            $regProps = @(
                @{ Name = '*WakeOnMagicPacket'; Value = '1' },
                @{ Name = '*WakeOnPattern'; Value = '1' },
                @{ Name = 'WakeOnMagicPacket'; Value = '1' },
                @{ Name = 'WakeOnPattern'; Value = '1' },
                @{ Name = '*PMNSOffload'; Value = '1' },
                @{ Name = '*PMARPOffload'; Value = '1' },
                @{ Name = 'EnablePME'; Value = '1' }
            )

            # Additional properties based on adapter type
            if ($isWireless) {
                $regProps += @(
                    @{ Name = '*WoWLAN'; Value = '1' },
                    @{ Name = '*GTKRekeyingOffload'; Value = '1' }
                )
            }
            else {
                # Disable Energy Efficient Ethernet on wired adapters (interferes with WOL)
                $regProps += @(
                    @{ Name = '*EEE'; Value = '0' },
                    @{ Name = 'EEELinkAdvertisement'; Value = '0' }
                )
            }

            foreach ($prop in $regProps) {
                try {
                    $existing = Get-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword $prop.Name -ErrorAction SilentlyContinue
                    if ($existing) {
                        Set-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword $prop.Name -RegistryValue $prop.Value -ErrorAction Stop
                        Write-Host "    [OK] $($prop.Name) = $($prop.Value)"
                        $adapterResult.Settings[$prop.Name] = $prop.Value
                    }
                }
                catch {
                    # Property not available on this adapter - skip silently
                }
            }

            # Display name properties (some adapters use these instead of registry keywords)
            $displayProps = @(
                @{ Display = 'Wake on Magic Packet'; Target = 'Enabled' },
                @{ Display = 'Wake on Pattern Match'; Target = 'Enabled' },
                @{ Display = 'Wake on WLAN'; Target = 'Enabled' },
                @{ Display = 'Energy Efficient Ethernet'; Target = 'Disabled' },
                @{ Display = 'Power Saving Mode'; Target = 'Disabled' },
                @{ Display = 'Green Ethernet'; Target = 'Disabled' }
            )

            foreach ($prop in $displayProps) {
                try {
                    $existing = Get-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName $prop.Display -ErrorAction SilentlyContinue
                    if ($existing) {
                        $validValues = $existing.ValidDisplayValues
                        $targetValue = $validValues | Where-Object { $_ -match $prop.Target } | Select-Object -First 1
                        if ($targetValue) {
                            Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName $prop.Display -DisplayValue $targetValue -ErrorAction Stop
                            Write-Host "    [OK] $($prop.Display) = $targetValue"
                            $adapterResult.Settings[$prop.Display] = $targetValue
                        }
                    }
                }
                catch {
                    # Property not available - skip silently
                }
            }

            # WMI Power Management - Enable device to wake computer
            try {
                $wmiWake = Get-CimInstance -ClassName MSPower_DeviceWakeEnable -Namespace root\wmi -ErrorAction SilentlyContinue | Where-Object { $_.InstanceName -like "*$($adapter.InterfaceGuid)*" }
                if ($wmiWake) {
                    Set-CimInstance -InputObject $wmiWake -Property @{ Enable = $true } -ErrorAction SilentlyContinue
                    Write-Host "    [OK] WMI Wake Enable = True"
                    $adapterResult.Settings['WMI_WakeEnable'] = 'True'
                }
            }
            catch {
                # WMI not available for this adapter
            }

            # WMI Magic Packet setting
            try {
                $wmiMagic = Get-CimInstance -ClassName MSNdis_DeviceWakeOnMagicPacketOnly -Namespace root\wmi -ErrorAction SilentlyContinue | Where-Object { $_.InstanceName -like "*$($adapter.InterfaceGuid)*" }
                if ($wmiMagic) {
                    Set-CimInstance -InputObject $wmiMagic -Property @{ Enable = $true } -ErrorAction SilentlyContinue
                    Write-Host "    [OK] WMI Magic Packet = True"
                    $adapterResult.Settings['WMI_MagicPacket'] = 'True'
                }
            }
            catch {
                # WMI not available for this adapter
            }

            # Direct Registry Configuration for persistence
            try {
                $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}'
                $keys = Get-ChildItem $regPath -ErrorAction SilentlyContinue | Where-Object {
                    (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).DriverDesc -eq $adapter.InterfaceDescription
                }

                foreach ($key in $keys) {
                    # Disable power management (PnPCapabilities = 0 means don't allow power off)
                    New-ItemProperty -Path $key.PSPath -Name 'PnPCapabilities' -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
                    New-ItemProperty -Path $key.PSPath -Name '*WakeOnMagicPacket' -Value '1' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
                    New-ItemProperty -Path $key.PSPath -Name '*WakeOnPattern' -Value '1' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
                    New-ItemProperty -Path $key.PSPath -Name 'EnablePME' -Value '1' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null

                    if ($isWireless) {
                        New-ItemProperty -Path $key.PSPath -Name '*WoWLAN' -Value '1' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
                        New-ItemProperty -Path $key.PSPath -Name 'WoWLANS5Wake' -Value '1' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
                        New-ItemProperty -Path $key.PSPath -Name '*GTKRekeyingOffload' -Value '1' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
                    }

                    Write-Host "    [OK] Registry configured"
                    $adapterResult.Settings['Registry'] = 'Configured'
                }
            }
            catch {
                Write-Host "    [Alert] Registry config failed"
            }

            if ($adapterResult.Settings.Count -eq 0) {
                Write-Host "    [INFO] No WOL properties found for this adapter"
            }

            $results.Adapters += $adapterResult
        }
    }

    # ============================================
    # VERIFICATION
    # ============================================

    Write-Host ""
    Write-Host "[VERIFICATION]"

    $hibStatus = powercfg /availablesleepstates 2>&1
    if ($hibStatus -match 'Hibernation has been disabled') {
        Write-Host "  [VERIFIED] Hibernation disabled"
    }
    elseif ($hibStatus -notmatch 'Hibernate\s') {
        Write-Host "  [VERIFIED] Hibernation not available"
    }

    $fastCheck = Get-ItemProperty -Path $fastBootPath -Name 'HiberbootEnabled' -ErrorAction SilentlyContinue
    if ($fastCheck.HiberbootEnabled -eq 0) {
        Write-Host "  [VERIFIED] Fast Startup disabled"
    }

    $modernCheck = Get-ItemProperty -Path $powerPath -Name 'PlatformAoAcOverride' -ErrorAction SilentlyContinue
    if ($results.SupportsModernStandbyWake) {
        if ($null -eq $modernCheck -or $null -eq $modernCheck.PlatformAoAcOverride) {
            Write-Host "  [VERIFIED] Modern Standby enabled (Modern Standby wake mode)"
        }
    }
    else {
        if ($modernCheck.PlatformAoAcOverride -eq 0) {
            Write-Host "  [VERIFIED] Modern Standby disabled (traditional S3 WOL mode)"
        }
    }

    Write-Host ""
    Write-Host "  Sleep States:"
    $sleepStates = powercfg /availablesleepstates 2>&1
    foreach ($line in $sleepStates) {
        Write-Host "    $line"
    }

    # ============================================
    # SUMMARY
    # ============================================

    Write-Host ""
    Write-Host "========================================"
    Write-Host "  SUMMARY"
    Write-Host "========================================"

    Write-Host ""
    Write-Host "Power Settings:"
    foreach ($setting in $results.PowerSettings.GetEnumerator()) {
        Write-Host "  $($setting.Key): $($setting.Value)"
    }

    $wiredCount = @($results.Adapters | Where-Object { $_.Type -eq 'Wired' }).Count
    $wirelessCount = @($results.Adapters | Where-Object { $_.Type -eq 'Wireless' }).Count

    Write-Host ""
    Write-Host "Adapters Configured: $($results.Adapters.Count) (Wired: $wiredCount, Wireless: $wirelessCount)"

    foreach ($adp in $results.Adapters) {
        $statusText = $adp.Status
        Write-Host "  [$($adp.Type)] $($adp.Name) - $statusText"
        Write-Host "    Settings applied: $($adp.Settings.Count)"
    }

    if ($results.Errors.Count -gt 0) {
        Write-Host ""
        Write-Host "Warnings: $($results.Errors.Count)"
        foreach ($err in $results.Errors) {
            Write-Host "  - $err"
        }
    }

    Write-Host ""
    if ($results.SupportsModernStandbyWake) {
        if ($results.HasWoWLAN -and $results.HasModernStandbyWiredWake) {
            Write-Host "Wake Mode: WoWLAN + Wired D0ix (Modern Standby compatible)"
            Write-Host "  - Device can wake from wireless (WoWLAN) in Modern Standby"
            Write-Host "  - Device can wake from wired (Directed WoL) in Modern Standby"
        }
        elseif ($results.HasWoWLAN) {
            Write-Host "Wake Mode: WoWLAN (Modern Standby compatible)"
            Write-Host "  - Device can wake from wireless while in Modern Standby"
            Write-Host "  - Better battery life preserved"
        }
        else {
            Write-Host "Wake Mode: Wired D0ix/Directed WoL (Modern Standby compatible)"
            Write-Host "  - Device can wake from wired NIC while in Modern Standby"
            Write-Host "  - Intel I219/I225/I226 or compatible NIC detected"
        }
    }
    else {
        Write-Host "Wake Mode: Traditional WOL (S3 Sleep)"
        Write-Host "  - Modern Standby disabled for legacy wired WOL compatibility"
        Write-Host "  - Device uses S3 sleep state for wake capability"
    }

    Write-Host ""
    Write-Host "[NOTE] Restart required for changes to take effect"
    Write-Host "[NOTE] WOL/WoWLAN must be enabled in BIOS/UEFI"
}

end {
    if ($results.Adapters.Count -gt 0) {
        exit 0
    }
    else {
        exit 1
    }
}
