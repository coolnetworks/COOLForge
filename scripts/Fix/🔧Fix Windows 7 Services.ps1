<#
.SYNOPSIS
    Restores Windows 7 services to their default startup types.

.DESCRIPTION
    This script resets all Windows 7 services to their Microsoft-recommended default
    startup configurations. This is useful for:

    - Recovering from malware that modified service settings
    - Restoring functionality after aggressive "optimization" tools
    - Fixing boot or stability issues caused by disabled services
    - Returning a system to a known-good baseline configuration

    The script sets each service's startup type to the Windows 7 default:
    - Auto: Service starts automatically at boot
    - Demand: Service starts manually when needed (Manual)
    - Disabled: Service is disabled and will not start

    IMPORTANT: This script requires Administrator privileges to modify services.
    A system restart is recommended after running this script.

    NOTE: Windows 7 reached end of support on January 14, 2020. Consider upgrading
    to a supported version of Windows for security updates and new features.

.NOTES
    Version:          2025.12.29.01
    Target Platform:  Windows 7
    Exit Codes:       0 = Success | 1 = Alert (Failure)

    Based on Windows 7 default service configuration.
    Original source: Fix Windows Services.cmd

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# Fix Windows 7 Services
# Version: 2025.12.29.01
# Target: Level.io (via Script Launcher) or standalone
# Exit 0 = Success | Exit 1 = Alert (Failure)
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge

$ErrorActionPreference = "SilentlyContinue"

# ============================================================
# VALIDATION
# ============================================================

# Check for Administrator privileges
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Host "[Alert] This script requires Administrator privileges"
    exit 1
}

# Verify Windows 7
$OSInfo = Get-WmiObject -Class Win32_OperatingSystem
$BuildNumber = [int]$OSInfo.BuildNumber
$Caption = $OSInfo.Caption

# Windows 7 is build 7600 (RTM) or 7601 (SP1)
if ($BuildNumber -lt 7600 -or $BuildNumber -ge 9200) {
    Write-Host "[Alert] This script is for Windows 7 only (Build 7600-7601)"
    Write-Host "[*] Current OS: $Caption (Build $BuildNumber)"
    Write-Host "[*] Use the appropriate script for your Windows version"
    exit 1
}

Write-Host "[*] Windows 7 detected (Build $BuildNumber)"
Write-Host "[!] Note: Windows 7 is no longer supported by Microsoft."
Write-Host "[*] Restoring default service startup types..."
Write-Host ""

# ============================================================
# SERVICE CONFIGURATION
# ============================================================
# Format: ServiceName = StartupType
# StartupType values: Automatic, Manual, Disabled

$Services = @{
    # Core System Services
    "AeLookupSvc"                              = "Manual"           # Application Experience
    "ALG"                                      = "Manual"           # Application Layer Gateway Service
    "AppIDSvc"                                 = "Manual"           # Application Identity
    "Appinfo"                                  = "Manual"           # Application Information
    "AppMgmt"                                  = "Manual"           # Application Management
    "AudioEndpointBuilder"                     = "Automatic"        # Windows Audio Endpoint Builder
    "AudioSrv"                                 = "Automatic"        # Windows Audio
    "AxInstSV"                                 = "Manual"           # ActiveX Installer

    # Security & Firewall
    "BDESVC"                                   = "Manual"           # BitLocker Drive Encryption Service
    "BFE"                                      = "Automatic"        # Base Filtering Engine
    "MpsSvc"                                   = "Automatic"        # Windows Firewall
    "WinDefend"                                = "Automatic"        # Windows Defender
    "wscsvc"                                   = "Automatic"        # Security Center

    # Network Services
    "BITS"                                     = "Automatic"        # Background Intelligent Transfer Service
    "Browser"                                  = "Manual"           # Computer Browser
    "bthserv"                                  = "Manual"           # Bluetooth Support Service
    "Dhcp"                                     = "Automatic"        # DHCP Client
    "Dnscache"                                 = "Automatic"        # DNS Client
    "dot3svc"                                  = "Manual"           # Wired AutoConfig
    "iphlpsvc"                                 = "Automatic"        # IP Helper
    "LanmanServer"                             = "Automatic"        # Server
    "LanmanWorkstation"                        = "Automatic"        # Workstation
    "lmhosts"                                  = "Automatic"        # TCP/IP NetBIOS Helper
    "NlaSvc"                                   = "Automatic"        # Network Location Awareness
    "nsi"                                      = "Automatic"        # Network Store Interface Service
    "Netlogon"                                 = "Automatic"        # Netlogon
    "Netman"                                   = "Manual"           # Network Connections
    "netprofm"                                 = "Manual"           # Network List Service
    "NetTcpPortSharing"                        = "Disabled"         # Net.Tcp Port Sharing Service
    "Wlansvc"                                  = "Automatic"        # WLAN AutoConfig
    "WwanSvc"                                  = "Automatic"        # WWAN AutoConfig

    # Remote Access & VPN
    "RasAuto"                                  = "Manual"           # Remote Access Auto Connection Manager
    "RasMan"                                   = "Manual"           # Remote Access Connection Manager
    "RemoteAccess"                             = "Disabled"         # Routing and Remote Access
    "RemoteRegistry"                           = "Manual"           # Remote Registry
    "SstpSvc"                                  = "Manual"           # Secure Socket Tunneling Protocol Service
    "IKEEXT"                                   = "Automatic"        # IKE and AuthIP IPsec Keying Modules
    "PolicyAgent"                              = "Manual"           # IPsec Policy Agent

    # Windows Update & Deployment
    "wuauserv"                                 = "Automatic"        # Windows Update
    "TrustedInstaller"                         = "Manual"           # Windows Modules Installer

    # Cryptographic & Certificate Services
    "CertPropSvc"                              = "Manual"           # Certificate Propagation
    "CryptSvc"                                 = "Automatic"        # Cryptographic Services
    "KeyIso"                                   = "Manual"           # CNG Key Isolation
    "EFS"                                      = "Manual"           # Encrypting File System
    "VaultSvc"                                 = "Manual"           # Credential Manager
    "ProtectedStorage"                         = "Manual"           # Protected Storage

    # User & Session Services
    "ProfSvc"                                  = "Automatic"        # User Profile Service
    "SessionEnv"                               = "Manual"           # Remote Desktop Configuration
    "TermService"                              = "Automatic"        # Remote Desktop Services
    "UmRdpService"                             = "Manual"           # Remote Desktop Services UserMode Port Redirector
    "UxSms"                                    = "Automatic"        # Desktop Window Manager Session Manager

    # Printing
    "Spooler"                                  = "Automatic"        # Print Spooler

    # Audio & Multimedia
    "MMCSS"                                    = "Automatic"        # Multimedia Class Scheduler
    "WMPNetworkSvc"                            = "Automatic"        # Windows Media Player Network Sharing

    # Storage & Backup
    "VSS"                                      = "Manual"           # Volume Shadow Copy
    "swprv"                                    = "Manual"           # Microsoft Software Shadow Copy Provider
    "wbengine"                                 = "Manual"           # Block Level Backup Engine Service
    "SDRSVC"                                   = "Manual"           # Windows Backup
    "defragsvc"                                = "Manual"           # Disk Defragmenter
    "vds"                                      = "Manual"           # Virtual Disk

    # System Core
    "DcomLaunch"                               = "Automatic"        # DCOM Server Process Launcher
    "RpcSs"                                    = "Automatic"        # Remote Procedure Call (RPC)
    "RpcEptMapper"                             = "Automatic"        # RPC Endpoint Mapper
    "RpcLocator"                               = "Manual"           # Remote Procedure Call (RPC) Locator
    "SamSs"                                    = "Automatic"        # Security Accounts Manager
    "gpsvc"                                    = "Automatic"        # Group Policy Client
    "Power"                                    = "Automatic"        # Power
    "Schedule"                                 = "Automatic"        # Task Scheduler
    "PlugPlay"                                 = "Automatic"        # Plug and Play
    "eventlog"                                 = "Automatic"        # Windows Event Log
    "EventSystem"                              = "Automatic"        # COM+ Event System

    # Display & Graphics
    "Themes"                                   = "Automatic"        # Themes
    "FontCache"                                = "Automatic"        # Windows Font Cache Service
    "FontCache3.0.0.0"                         = "Manual"           # Windows Presentation Foundation Font Cache

    # Windows Services Infrastructure
    "ShellHWDetection"                         = "Automatic"        # Shell Hardware Detection
    "stisvc"                                   = "Automatic"        # Windows Image Acquisition (WIA)

    # Diagnostics & Troubleshooting
    "DPS"                                      = "Automatic"        # Diagnostic Policy Service
    "WdiServiceHost"                           = "Manual"           # Diagnostic Service Host
    "WdiSystemHost"                            = "Manual"           # Diagnostic System Host
    "WerSvc"                                   = "Manual"           # Windows Error Reporting Service
    "wercplsupport"                            = "Manual"           # Problem Reports and Solutions Control Panel Support
    "PcaSvc"                                   = "Automatic"        # Program Compatibility Assistant Service

    # Device & Hardware
    "hidserv"                                  = "Manual"           # Human Interface Device Access
    "WPDBusEnum"                               = "Manual"           # Portable Device Enumerator Service
    "SCardSvr"                                 = "Manual"           # Smart Card
    "SCPolicySvc"                              = "Manual"           # Smart Card Removal Policy
    "WbioSrvc"                                 = "Manual"           # Windows Biometric Service
    "IPBusEnum"                                = "Manual"           # PnP-X IP Bus Enumerator
    "TBS"                                      = "Manual"           # TPM Base Services

    # Application Services
    "COMSysApp"                                = "Manual"           # COM+ System Application
    "CscService"                               = "Automatic"        # Offline Files
    "EapHost"                                  = "Manual"           # Extensible Authentication Protocol
    "ehRecvr"                                  = "Automatic"        # Windows Media Center Receiver Service
    "ehSched"                                  = "Automatic"        # Windows Media Center Scheduler Service
    "fdPHost"                                  = "Manual"           # Function Discovery Provider Host
    "FDResPub"                                 = "Automatic"        # Function Discovery Resource Publication
    "hkmsvc"                                   = "Manual"           # Health Key and Certificate Management
    "idsvc"                                    = "Manual"           # Windows CardSpace

    # .NET Framework
    "clr_optimization_v2.0.50727_32"           = "Automatic"        # Microsoft .NET Framework NGEN v2.0.50727_X86
    "clr_optimization_v2.0.50727_64"           = "Automatic"        # Microsoft .NET Framework NGEN v2.0.50727_X64

    # Search & Indexing
    "WSearch"                                  = "Automatic"        # Windows Search

    # Time
    "W32Time"                                  = "Automatic"        # Windows Time

    # Additional Services
    "HomeGroupListener"                        = "Automatic"        # HomeGroup Listener
    "HomeGroupProvider"                        = "Automatic"        # HomeGroup Provider
    "lltdsvc"                                  = "Manual"           # Link-Layer Topology Discovery Mapper
    "Mcx2Svc"                                  = "Disabled"         # Media Center Extender Service
    "MSDTC"                                    = "Manual"           # Distributed Transaction Coordinator
    "MSiSCSI"                                  = "Manual"           # Microsoft iSCSI Initiator Service
    "msiserver"                                = "Manual"           # Windows Installer
    "napagent"                                 = "Manual"           # Network Access Protection Agent
    "p2pimsvc"                                 = "Manual"           # Peer Networking Identity Manager
    "p2psvc"                                   = "Manual"           # Peer Networking Grouping
    "PeerDistSvc"                              = "Manual"           # BranchCache
    "PerfHost"                                 = "Manual"           # Performance Counter DLL Host
    "pla"                                      = "Manual"           # Performance Logs & Alerts
    "PNRPAutoReg"                              = "Manual"           # PNRP Machine Name Publication Service
    "PNRPsvc"                                  = "Manual"           # Peer Name Resolution Protocol
    "QWAVE"                                    = "Manual"           # Quality Windows Audio Video Experience
    "seclogon"                                 = "Manual"           # Secondary Logon
    "SENS"                                     = "Automatic"        # System Event Notification Service
    "SensrSvc"                                 = "Manual"           # Adaptive Brightness
    "SharedAccess"                             = "Disabled"         # Internet Connection Sharing (ICS)
    "SNMPTRAP"                                 = "Manual"           # SNMP Trap
    "sppsvc"                                   = "Automatic"        # Software Protection
    "sppuinotify"                              = "Manual"           # SPP Notification Service
    "SSDPSRV"                                  = "Manual"           # SSDP Discovery
    "SysMain"                                  = "Automatic"        # Superfetch
    "TabletInputService"                       = "Manual"           # Tablet PC Input Service
    "TapiSrv"                                  = "Manual"           # Telephony
    "THREADORDER"                              = "Manual"           # Thread Ordering Server
    "TrkWks"                                   = "Automatic"        # Distributed Link Tracking Client
    "UI0Detect"                                = "Manual"           # Interactive Services Detection
    "upnphost"                                 = "Manual"           # UPnP Device Host
    "WebClient"                                = "Manual"           # WebClient
    "Wecsvc"                                   = "Manual"           # Windows Event Collector
    "WcsPlugInService"                         = "Manual"           # Windows Color System
    "WinHttpAutoProxySvc"                      = "Manual"           # WinHTTP Web Proxy Auto-Discovery Service
    "Winmgmt"                                  = "Automatic"        # Windows Management Instrumentation
    "WinRM"                                    = "Manual"           # Windows Remote Management (WS-Management)
    "wmiApSrv"                                 = "Manual"           # WMI Performance Adapter
    "WPCSvc"                                   = "Manual"           # Parental Controls
    "wudfsvc"                                  = "Manual"           # Windows Driver Foundation - User-mode Driver Framework
    "wcncsvc"                                  = "Manual"           # Windows Connect Now - Config Registrar
    "KtmRm"                                    = "Manual"           # KtmRm for Distributed Transaction Coordinator
}

# ============================================================
# APPLY CONFIGURATION
# ============================================================

$SuccessCount = 0
$FailCount = 0
$SkipCount = 0

foreach ($ServiceName in $Services.Keys) {
    $TargetType = $Services[$ServiceName]

    # Check if service exists
    $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

    if ($null -eq $Service) {
        $SkipCount++
        continue
    }

    try {
        # Map friendly names to sc.exe values
        $ScStartType = switch ($TargetType) {
            "Automatic"            { "auto" }
            "AutomaticDelayedStart" { "delayed-auto" }
            "Manual"               { "demand" }
            "Disabled"             { "disabled" }
        }

        # Use sc.exe for reliability (handles more edge cases than Set-Service)
        $result = & sc.exe config $ServiceName start= $ScStartType 2>&1

        if ($LASTEXITCODE -eq 0) {
            $SuccessCount++
        } else {
            Write-Host "[!] Failed to configure: $ServiceName"
            $FailCount++
        }
    }
    catch {
        Write-Host "[!] Error configuring: $ServiceName - $($_.Exception.Message)"
        $FailCount++
    }
}

# ============================================================
# SUMMARY
# ============================================================
Write-Host ""
Write-Host "========================================"
Write-Host "Service Configuration Complete"
Write-Host "========================================"
Write-Host "  Configured: $SuccessCount services"
Write-Host "  Failed:     $FailCount services"
Write-Host "  Skipped:    $SkipCount services (not installed)"
Write-Host "========================================"
Write-Host ""
Write-Host "[*] A system restart is recommended to apply all changes."
Write-Host ""
Write-Host "[!] IMPORTANT: Windows 7 is no longer supported by Microsoft."
Write-Host "[!] Please consider upgrading to Windows 10 or 11 for security updates."

if ($FailCount -gt 0) {
    Write-Host "[!] Some services could not be configured."
    exit 1
}

exit 0
