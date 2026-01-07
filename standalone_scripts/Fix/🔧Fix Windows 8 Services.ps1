<#
.SYNOPSIS
    Restores Windows 8 services to their default startup types.

.DESCRIPTION
    This script resets all Windows 8 services to their Microsoft-recommended default
    startup configurations. This is useful for:

    - Recovering from malware that modified service settings
    - Restoring functionality after aggressive "optimization" tools
    - Fixing boot or stability issues caused by disabled services
    - Returning a system to a known-good baseline configuration

    The script sets each service's startup type to the Windows 8 default:
    - Auto: Service starts automatically at boot
    - Demand: Service starts manually when needed (Manual)
    - Disabled: Service is disabled and will not start

    IMPORTANT: This script requires Administrator privileges to modify services.
    A system restart is recommended after running this script.

.NOTES
    Version:          2025.12.29.01
    Target Platform:  Windows 8
    Exit Codes:       0 = Success | 1 = Alert (Failure)

    Based on Windows 8 default service configuration.
    Original source: Fix Windows Services.cmd

    License:          MIT License with Attribution
    Copyright (c) 2025 COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# Fix Windows 8 Services
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
    Write-Host "[X] FATAL: This script requires Administrator privileges"
    exit 1
}

# Verify Windows 8
$OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem
$BuildNumber = [int]$OSInfo.BuildNumber
$Caption = $OSInfo.Caption

# Windows 8 is build 9200, Windows 8.1 is 9600
if ($BuildNumber -ne 9200) {
    Write-Host "[X] FATAL: This script is for Windows 8 only (Build 9200)"
    Write-Host "[*] Current OS: $Caption (Build $BuildNumber)"
    Write-Host "[*] Use the appropriate script for your Windows version"
    exit 1
}

Write-Host "[*] Windows 8 detected (Build $BuildNumber)"
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
    "AppHostSvc"                               = "Automatic"        # Application Host Helper Service
    "AppIDSvc"                                 = "Manual"           # Application Identity
    "Appinfo"                                  = "Manual"           # Application Information
    "AppMgmt"                                  = "Manual"           # Application Management
    "AppReadiness"                             = "Manual"           # App Readiness
    "AppXSvc"                                  = "Manual"           # AppX Deployment Service
    "aspnet_state"                             = "Manual"           # ASP.NET State Service
    "AudioEndpointBuilder"                     = "Automatic"        # Windows Audio Endpoint Builder
    "Audiosrv"                                 = "Automatic"        # Windows Audio
    "AxInstSV"                                 = "Manual"           # ActiveX Installer

    # Security & Firewall
    "BDESVC"                                   = "Manual"           # BitLocker Drive Encryption Service
    "BFE"                                      = "Automatic"        # Base Filtering Engine
    "MpsSvc"                                   = "Automatic"        # Windows Defender Firewall
    "WinDefend"                                = "Automatic"        # Windows Defender Antivirus Service
    "WdNisSvc"                                 = "Manual"           # Windows Defender Network Inspection
    "wscsvc"                                   = "Automatic"        # Security Center

    # Network Services
    "BITS"                                     = "Automatic"        # Background Intelligent Transfer Service
    "BrokerInfrastructure"                     = "Automatic"        # Background Tasks Infrastructure
    "Browser"                                  = "Manual"           # Computer Browser
    "BthHFSrv"                                 = "Manual"           # Bluetooth Handsfree Service
    "bthserv"                                  = "Manual"           # Bluetooth Support Service
    "c2wts"                                    = "Manual"           # Claims to Windows Token Service
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
    "NetTcpPortSharing"                        = "Manual"           # Net.Tcp Port Sharing Service
    "WlanSvc"                                  = "Automatic"        # WLAN AutoConfig
    "WwanSvc"                                  = "Automatic"        # WWAN AutoConfig
    "Wcmsvc"                                   = "Automatic"        # Windows Connection Manager
    "wcncsvc"                                  = "Manual"           # Windows Connect Now

    # Remote Access & VPN
    "RasAuto"                                  = "Manual"           # Remote Access Auto Connection Manager
    "RasMan"                                   = "Manual"           # Remote Access Connection Manager
    "RemoteAccess"                             = "Disabled"         # Routing and Remote Access
    "RemoteRegistry"                           = "Disabled"         # Remote Registry
    "SstpSvc"                                  = "Manual"           # Secure Socket Tunneling Protocol Service
    "IKEEXT"                                   = "Manual"           # IKE and AuthIP IPsec Keying Modules
    "PolicyAgent"                              = "Manual"           # IPsec Policy Agent

    # Windows Update & Deployment
    "wuauserv"                                 = "Manual"           # Windows Update
    "TrustedInstaller"                         = "Manual"           # Windows Modules Installer

    # Cryptographic & Certificate Services
    "CertPropSvc"                              = "Manual"           # Certificate Propagation
    "CryptSvc"                                 = "Automatic"        # Cryptographic Services
    "KeyIso"                                   = "Manual"           # CNG Key Isolation
    "EFS"                                      = "Manual"           # Encrypting File System
    "VaultSvc"                                 = "Manual"           # Credential Manager

    # User & Session Services
    "ProfSvc"                                  = "Automatic"        # User Profile Service
    "SessionEnv"                               = "Manual"           # Remote Desktop Configuration
    "TermService"                              = "Manual"           # Remote Desktop Services
    "UmRdpService"                             = "Manual"           # Remote Desktop Services UserMode Port Redirector

    # Printing
    "Spooler"                                  = "Automatic"        # Print Spooler
    "PrintNotify"                              = "Manual"           # Printer Extensions and Notifications

    # Audio & Multimedia
    "MMCSS"                                    = "Automatic"        # Multimedia Class Scheduler
    "WMPNetworkSvc"                            = "Automatic"        # Windows Media Player Network Sharing

    # Storage & Backup
    "StorSvc"                                  = "Manual"           # Storage Service
    "VSS"                                      = "Manual"           # Volume Shadow Copy
    "swprv"                                    = "Manual"           # Microsoft Software Shadow Copy Provider
    "wbengine"                                 = "Manual"           # Block Level Backup Engine Service
    "defragsvc"                                = "Manual"           # Optimize drives
    "vds"                                      = "Manual"           # Virtual Disk

    # System Core
    "DcomLaunch"                               = "Automatic"        # DCOM Server Process Launcher
    "RpcSs"                                    = "Automatic"        # Remote Procedure Call (RPC)
    "RpcEptMapper"                             = "Automatic"        # RPC Endpoint Mapper
    "RpcLocator"                               = "Manual"           # Remote Procedure Call (RPC) Locator
    "SamSs"                                    = "Automatic"        # Security Accounts Manager
    "LSM"                                      = "Automatic"        # Local Session Manager
    "gpsvc"                                    = "Automatic"        # Group Policy Client
    "Power"                                    = "Automatic"        # Power
    "Schedule"                                 = "Automatic"        # Task Scheduler
    "PlugPlay"                                 = "Manual"           # Plug and Play
    "EventLog"                                 = "Automatic"        # Windows Event Log
    "EventSystem"                              = "Automatic"        # COM+ Event System

    # Display & Graphics
    "Themes"                                   = "Automatic"        # Themes
    "FontCache"                                = "Automatic"        # Windows Font Cache Service
    "FontCache3.0.0.0"                         = "Manual"           # Windows Presentation Foundation Font Cache

    # Windows Services Infrastructure
    "SystemEventsBroker"                       = "Automatic"        # System Events Broker
    "TimeBroker"                               = "Manual"           # Time Broker
    "ShellHWDetection"                         = "Automatic"        # Shell Hardware Detection
    "stisvc"                                   = "Manual"           # Windows Image Acquisition
    "WiaRpc"                                   = "Manual"           # Still Image Acquisition Events

    # Diagnostics & Troubleshooting
    "DPS"                                      = "Automatic"        # Diagnostic Policy Service
    "WdiServiceHost"                           = "Manual"           # Diagnostic Service Host
    "WdiSystemHost"                            = "Manual"           # Diagnostic System Host
    "diagtrack"                                = "Automatic"        # Connected User Experiences and Telemetry
    "WerSvc"                                   = "Manual"           # Windows Error Reporting Service
    "wercplsupport"                            = "Manual"           # Problem Reports and Solutions
    "PcaSvc"                                   = "Automatic"        # Program Compatibility Assistant

    # Device & Hardware
    "DeviceAssociationService"                 = "Automatic"        # Device Association Service
    "DeviceInstall"                            = "Manual"           # Device Install Service
    "DsmSvc"                                   = "Manual"           # Device Setup Manager
    "hidserv"                                  = "Manual"           # Human Interface Device Service
    "WPDBusEnum"                               = "Manual"           # Portable Device Enumerator Service
    "SCardSvr"                                 = "Disabled"         # Smart Card
    "ScDeviceEnum"                             = "Manual"           # Smart Card Device Enumeration Service
    "SCPolicySvc"                              = "Manual"           # Smart Card Removal Policy
    "WbioSrvc"                                 = "Manual"           # Windows Biometric Service

    # Application Services
    "COMSysApp"                                = "Manual"           # COM+ System Application
    "CscService"                               = "Manual"           # Offline Files
    "DsRoleSvc"                                = "Manual"           # DS Role Server
    "Eaphost"                                  = "Manual"           # Extensible Authentication Protocol
    "ehRecvr"                                  = "Manual"           # Windows Media Center Receiver Service
    "ehSched"                                  = "Manual"           # Windows Media Center Scheduler Service
    "fdPHost"                                  = "Manual"           # Function Discovery Provider Host
    "FDResPub"                                 = "Manual"           # Function Discovery Resource Publication
    "fhsvc"                                    = "Manual"           # File History Service
    "hkmsvc"                                   = "Manual"           # Health Key and Certificate Management

    # Hyper-V & Virtualization
    "vmicguestinterface"                       = "Manual"           # Hyper-V Guest Service Interface
    "vmicheartbeat"                            = "Manual"           # Hyper-V Heartbeat Service
    "vmickvpexchange"                          = "Manual"           # Hyper-V Data Exchange Service
    "vmicrdv"                                  = "Manual"           # Hyper-V Remote Desktop Virtualization
    "vmicshutdown"                             = "Manual"           # Hyper-V Guest Shutdown Service
    "vmictimesync"                             = "Manual"           # Hyper-V Time Synchronization Service
    "vmicvss"                                  = "Manual"           # Hyper-V Volume Shadow Copy Requestor
    "vmvss"                                    = "Manual"           # Hyper-V VSS Writer

    # Search & Indexing
    "WSearch"                                  = "Automatic"        # Windows Search

    # Time
    "W32Time"                                  = "Automatic"        # Windows Time

    # Additional Services
    "HomeGroupListener"                        = "Automatic"        # HomeGroup Listener
    "HomeGroupProvider"                        = "Automatic"        # HomeGroup Provider
    "IEEtwCollectorService"                    = "Manual"           # Internet Explorer ETW Collector
    "lfsvc"                                    = "Manual"           # Geolocation Service
    "lltdsvc"                                  = "Manual"           # Link-Layer Topology Discovery Mapper
    "Mcx2Svc"                                  = "Disabled"         # Media Center Extender Service
    "MSDTC"                                    = "Manual"           # Distributed Transaction Coordinator
    "MSiSCSI"                                  = "Manual"           # Microsoft iSCSI Initiator Service
    "msiserver"                                = "Manual"           # Windows Installer
    "MsKeyboardFilter"                         = "Disabled"         # Microsoft Keyboard Filter
    "napagent"                                 = "Manual"           # Network Access Protection Agent
    "NcaSvc"                                   = "Manual"           # Network Connectivity Assistant
    "NcbService"                               = "Manual"           # Network Connection Broker
    "NcdAutoSetup"                             = "Manual"           # Network Connected Devices Auto-Setup
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
    "SensrSvc"                                 = "Manual"           # Sensor Monitoring Service
    "SharedAccess"                             = "Disabled"         # Internet Connection Sharing
    "smphost"                                  = "Manual"           # Microsoft Storage Spaces SMP
    "SNMPTRAP"                                 = "Manual"           # SNMP Trap
    "sppsvc"                                   = "Automatic"        # Software Protection
    "SSDPSRV"                                  = "Manual"           # SSDP Discovery
    "svsvc"                                    = "Manual"           # Spot Verifier
    "SysMain"                                  = "Automatic"        # SysMain (Superfetch)
    "TabletInputService"                       = "Automatic"        # Touch Keyboard and Handwriting Panel
    "TapiSrv"                                  = "Manual"           # Telephony
    "THREADORDER"                              = "Manual"           # Thread Ordering Server
    "TlntSvr"                                  = "Disabled"         # Telnet
    "TrkWks"                                   = "Automatic"        # Distributed Link Tracking Client
    "UI0Detect"                                = "Manual"           # Interactive Services Detection
    "upnphost"                                 = "Manual"           # UPnP Device Host
    "WebClient"                                = "Manual"           # WebClient
    "Wecsvc"                                   = "Manual"           # Windows Event Collector
    "WEPHOSTSVC"                               = "Manual"           # Windows Encryption Provider Host Service
    "WcsPlugInService"                         = "Manual"           # Windows Color System
    "WinHttpAutoProxySvc"                      = "Manual"           # WinHTTP Web Proxy Auto-Discovery
    "Winmgmt"                                  = "Automatic"        # Windows Management Instrumentation
    "WinRM"                                    = "Manual"           # Windows Remote Management (WS-Management)
    "wlidsvc"                                  = "Manual"           # Microsoft Account Sign-in Assistant
    "wmiApSrv"                                 = "Manual"           # WMI Performance Adapter
    "workfolderssvc"                           = "Manual"           # Work Folders
    "WPCSvc"                                   = "Manual"           # Parental Controls
    "WSService"                                = "Manual"           # Windows Store Service
    "wudfsvc"                                  = "Manual"           # Windows Driver Foundation

    # IIS & Web Services (if installed)
    "ftpsvc"                                   = "Automatic"        # Microsoft FTP Service
    "IISADMIN"                                 = "Automatic"        # IIS Admin Service
    "iprip"                                    = "Automatic"        # RIP Listener
    "LPDSVC"                                   = "Automatic"        # LPD Service
    "MSMQ"                                     = "Automatic"        # Message Queuing
    "MSMQTriggers"                             = "Automatic"        # Message Queuing Triggers
    "NetMsmqActivator"                         = "Automatic"        # Net.Msmq Listener Adapter
    "NetPipeActivator"                         = "Automatic"        # Net.Pipe Listener Adapter
    "NetTcpActivator"                          = "Automatic"        # Net.Tcp Listener Adapter
    "simptcp"                                  = "Automatic"        # Simple TCP/IP Services
    "SNMP"                                     = "Automatic"        # SNMP Service
    "w3logsvc"                                 = "Manual"           # W3C Logging Service
    "W3SVC"                                    = "Automatic"        # World Wide Web Publishing Service
    "WAS"                                      = "Manual"           # Windows Process Activation Service
    "WMSVC"                                    = "Manual"           # Web Management Service
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

if ($FailCount -gt 0) {
    Write-Host "[!] Some services could not be configured."
    exit 1
}

exit 0
