<#
.SYNOPSIS
    Restores Windows 11 services to their default startup types.

.DESCRIPTION
    This script resets all Windows 11 services to their Microsoft-recommended default
    startup configurations. This is useful for:

    - Recovering from malware that modified service settings
    - Restoring functionality after aggressive "optimization" tools
    - Fixing boot or stability issues caused by disabled services
    - Returning a system to a known-good baseline configuration

    The script sets each service's startup type to the Windows 11 default:
    - Auto: Service starts automatically at boot
    - Demand: Service starts manually when needed (Manual)
    - Delayed-Auto: Service starts automatically, but after other Auto services
    - Disabled: Service is disabled and will not start

    IMPORTANT: This script requires Administrator privileges to modify services.
    A system restart is recommended after running this script.

.NOTES
    Version:          2025.12.29.01
    Target Platform:  Windows 11
    Exit Codes:       0 = Success | 1 = Alert (Failure)

    Based on Windows 11 default service configuration.
    Original source: Fix Windows Services.cmd

    License:          AGPL-3.0 (see LICENSE)
    Copyright (c) 2025-2026 COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# Fix Windows 11 Services
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

# Verify Windows 11
$OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem
$BuildNumber = [int]$OSInfo.BuildNumber

if ($BuildNumber -lt 22000) {
    Write-Host "[Alert] This script is for Windows 11 only (Build 22000+)"
    Write-Host "[*] Current OS: $($OSInfo.Caption) (Build $BuildNumber)"
    Write-Host "[*] Use the appropriate script for your Windows version"
    exit 1
}

Write-Host "[*] Windows 11 detected (Build $BuildNumber)"
Write-Host "[*] Restoring default service startup types..."
Write-Host ""

# ============================================================
# SERVICE CONFIGURATION
# ============================================================
# Format: ServiceName = StartupType
# StartupType values: Automatic, Manual, Disabled, AutomaticDelayedStart

$Services = @{
    # Core System Services
    "AJRouter"                                 = "Manual"           # AllJoyn Router Service
    "ALG"                                      = "Manual"           # Application Layer Gateway Service
    "AppIDSvc"                                 = "Manual"           # Application Identity
    "tzautoupdate"                             = "Manual"           # Auto Time Zone Updater
    "AppMgmt"                                  = "Manual"           # Application Management
    "AppReadiness"                             = "Manual"           # App Readiness
    "AppXSvc"                                  = "Manual"           # AppX Deployment Service
    "AppVClient"                               = "Disabled"         # Microsoft App-V Client
    "AssignedAccessManagerSvc"                 = "Automatic"        # Assigned Access Manager Service
    "autotimesvc"                              = "Manual"           # Cellular Time
    "AxInstSV"                                 = "Manual"           # ActiveX Installer

    # Security & Firewall
    "BDESVC"                                   = "Manual"           # BitLocker Drive Encryption Service
    "BFE"                                      = "Automatic"        # Base Filtering Engine
    "MpsSvc"                                   = "Automatic"        # Windows Defender Firewall
    "WinDefend"                                = "Automatic"        # Windows Defender Antivirus Service
    "WdNisSvc"                                 = "Manual"           # Windows Defender Network Inspection
    "wscsvc"                                   = "AutomaticDelayedStart" # Security Center

    # Network Services
    "BITS"                                     = "Manual"           # Background Intelligent Transfer Service
    "BTAGService"                              = "Manual"           # Bluetooth Audio Gateway Service
    "BrokerInfrastructure"                     = "Automatic"        # Background Tasks Infrastructure
    "BthAvctpSvc"                              = "Manual"           # AVCTP Service
    "bthserv"                                  = "Manual"           # Bluetooth Support Service
    "CDPSvc"                                   = "AutomaticDelayedStart" # Connected Devices Platform Service
    "Dhcp"                                     = "Automatic"        # DHCP Client
    "Dnscache"                                 = "Automatic"        # DNS Client
    "dot3svc"                                  = "Manual"           # Wired AutoConfig
    "iphlpsvc"                                 = "Automatic"        # IP Helper
    "LanmanServer"                             = "Automatic"        # Server
    "LanmanWorkstation"                        = "Automatic"        # Workstation
    "lmhosts"                                  = "Manual"           # TCP/IP NetBIOS Helper
    "NlaSvc"                                   = "Automatic"        # Network Location Awareness
    "nsi"                                      = "Automatic"        # Network Store Interface Service
    "Netlogon"                                 = "Automatic"        # Netlogon
    "Netman"                                   = "Manual"           # Network Connections
    "netprofm"                                 = "Manual"           # Network List Service
    "NetSetupSvc"                              = "Manual"           # Network Setup Service
    "NetTcpPortSharing"                        = "Disabled"         # Net.Tcp Port Sharing Service
    "WlanSvc"                                  = "Automatic"        # WLAN AutoConfig
    "WwanSvc"                                  = "Manual"           # WWAN AutoConfig
    "Wcmsvc"                                   = "Automatic"        # Windows Connection Manager
    "wcncsvc"                                  = "Manual"           # Windows Connect Now

    # Remote Access & VPN
    "RasAuto"                                  = "Manual"           # Remote Access Auto Connection Manager
    "RasMan"                                   = "Automatic"        # Remote Access Connection Manager
    "RemoteAccess"                             = "Disabled"         # Routing and Remote Access
    "RemoteRegistry"                           = "Disabled"         # Remote Registry
    "SstpSvc"                                  = "Manual"           # Secure Socket Tunneling Protocol Service
    "IKEEXT"                                   = "Manual"           # IKE and AuthIP IPsec Keying Modules
    "PolicyAgent"                              = "Manual"           # IPsec Policy Agent

    # Windows Update & Deployment
    "DoSvc"                                    = "Manual"           # Delivery Optimization
    "wuauserv"                                 = "Manual"           # Windows Update
    "UsoSvc"                                   = "AutomaticDelayedStart" # Update Orchestrator Service
    "TrustedInstaller"                         = "Manual"           # Windows Modules Installer
    "InstallService"                           = "Manual"           # Microsoft Store Install Service
    "ClipSVC"                                  = "Manual"           # Client License Service

    # Cryptographic & Certificate Services
    "CertPropSvc"                              = "Manual"           # Certificate Propagation
    "CryptSvc"                                 = "Automatic"        # Cryptographic Services
    "KeyIso"                                   = "Manual"           # CNG Key Isolation
    "EFS"                                      = "Manual"           # Encrypting File System
    "VaultSvc"                                 = "Manual"           # Credential Manager
    "NgcCtnrSvc"                               = "Manual"           # Microsoft Passport Container
    "NgcSvc"                                   = "Manual"           # Microsoft Passport

    # User & Session Services
    "ProfSvc"                                  = "Automatic"        # User Profile Service
    "UserManager"                              = "Automatic"        # User Manager
    "SessionEnv"                               = "Manual"           # Remote Desktop Configuration
    "TermService"                              = "Manual"           # Remote Desktop Services
    "UmRdpService"                             = "Manual"           # Remote Desktop Services UserMode Port Redirector

    # Printing
    "Spooler"                                  = "Automatic"        # Print Spooler
    "PrintNotify"                              = "Manual"           # Printer Extensions and Notifications

    # Audio & Multimedia
    "WMPNetworkSvc"                            = "Automatic"        # Windows Media Player Network Sharing

    # Storage & Backup
    "StorSvc"                                  = "AutomaticDelayedStart" # Storage Service
    "VSS"                                      = "Manual"           # Volume Shadow Copy
    "swprv"                                    = "Manual"           # Microsoft Software Shadow Copy Provider
    "wbengine"                                 = "Manual"           # Block Level Backup Engine Service
    "SDRSVC"                                   = "Manual"           # Windows Backup
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
    "DisplayEnhancementService"                = "Manual"           # Display Enhancement Service
    "DispBrokerDesktopSvc"                     = "Automatic"        # Display Policy Service
    "GraphicsPerfSvc"                          = "Manual"           # GraphicsPerfSvc
    "FontCache"                                = "Automatic"        # Windows Font Cache Service
    "FontCache3.0.0.0"                         = "Manual"           # Windows Presentation Foundation Font Cache

    # Windows Services Infrastructure
    "CoreMessagingRegistrar"                   = "Automatic"        # CoreMessaging
    "StateRepository"                          = "Automatic"        # State Repository Service
    "SystemEventsBroker"                       = "Automatic"        # System Events Broker
    "TimeBrokerSvc"                            = "Manual"           # Time Broker
    "ShellHWDetection"                         = "Automatic"        # Shell Hardware Detection
    "stisvc"                                   = "Automatic"        # Windows Image Acquisition
    "WiaRpc"                                   = "Manual"           # Still Image Acquisition Events

    # Diagnostics & Troubleshooting
    "DPS"                                      = "Automatic"        # Diagnostic Policy Service
    "WdiServiceHost"                           = "Manual"           # Diagnostic Service Host
    "WdiSystemHost"                            = "Manual"           # Diagnostic System Host
    "DiagTrack"                                = "Automatic"        # Connected User Experiences and Telemetry
    "TroubleshootingSvc"                       = "Manual"           # Recommended Troubleshooting Service
    "WerSvc"                                   = "Manual"           # Windows Error Reporting Service
    "wercplsupport"                            = "Manual"           # Problem Reports and Solutions
    "diagnosticshub.standardcollector.service" = "Manual"           # Diagnostics Hub Standard Collector
    "PcaSvc"                                   = "AutomaticDelayedStart" # Program Compatibility Assistant

    # Device & Hardware
    "DeviceAssociationService"                 = "Automatic"        # Device Association Service
    "DeviceInstall"                            = "Manual"           # Device Install Service
    "DevQueryBroker"                           = "Manual"           # DevQuery Background Discovery Broker
    "DsmSvc"                                   = "Manual"           # Device Setup Manager
    "hidserv"                                  = "Manual"           # Human Interface Device Service
    "WPDBusEnum"                               = "Manual"           # Portable Device Enumerator Service
    "SCardSvr"                                 = "Manual"           # Smart Card
    "ScDeviceEnum"                             = "Manual"           # Smart Card Device Enumeration Service
    "SCPolicySvc"                              = "Manual"           # Smart Card Removal Policy
    "WbioSrvc"                                 = "Manual"           # Windows Biometric Service

    # Application Services
    "COMSysApp"                                = "Manual"           # COM+ System Application
    "CscService"                               = "Manual"           # Offline Files
    "DmEnrollmentSvc"                          = "Manual"           # Device Management Enrollment Service
    "dmwappushservice"                         = "Automatic"        # Device Management WAP Push
    "Eaphost"                                  = "Manual"           # Extensible Authentication Protocol
    "EntAppSvc"                                = "Manual"           # Enterprise App Management Service
    "embeddedmode"                             = "Manual"           # Embedded Mode
    "fdPHost"                                  = "Manual"           # Function Discovery Provider Host
    "FDResPub"                                 = "Manual"           # Function Discovery Resource Publication
    "fhsvc"                                    = "Manual"           # File History Service
    "FileSyncHelper"                           = "Manual"           # FileSyncHelper

    # Hyper-V & Virtualization
    "HvHost"                                   = "Manual"           # HV Host Service
    "vmcompute"                                = "Manual"           # Hyper-V Host Compute Service
    "vmicguestinterface"                       = "Manual"           # Hyper-V Guest Service Interface
    "vmicheartbeat"                            = "Manual"           # Hyper-V Heartbeat Service
    "vmicrdv"                                  = "Manual"           # Hyper-V Remote Desktop Virtualization
    "vmicshutdown"                             = "Manual"           # Hyper-V Guest Shutdown Service
    "vmictimesync"                             = "Manual"           # Hyper-V Time Synchronization Service
    "vmicvmsession"                            = "Manual"           # Hyper-V PowerShell Direct Service
    "vmicvss"                                  = "Manual"           # Hyper-V Volume Shadow Copy Requestor
    "HNS"                                      = "Manual"           # Host Network Service

    # Search & Indexing
    "WSearch"                                  = "AutomaticDelayedStart" # Windows Search

    # Time
    "W32Time"                                  = "Manual"           # Windows Time

    # Additional Services
    "Browser"                                  = "Manual"           # Computer Browser
    "cloudidsvc"                               = "Manual"           # Microsoft Cloud Identity Service
    "camsvc"                                   = "Manual"           # Capability Access Manager Service
    "DialogBlockingService"                    = "Disabled"         # Dialog Blocking Service
    "Fax"                                      = "Manual"           # Fax
    "icssvc"                                   = "Manual"           # Windows Mobile Hotspot Service
    "lfsvc"                                    = "Manual"           # Geolocation Service
    "InventorySvc"                             = "Manual"           # Inventory and Compatibility Appraisal
    "lltdsvc"                                  = "Manual"           # Link-Layer Topology Discovery Mapper
    "MapsBroker"                               = "AutomaticDelayedStart" # Downloaded Maps Manager
    "McpManagementService"                     = "Manual"           # McpManagementService
    "MSDTC"                                    = "Manual"           # Distributed Transaction Coordinator
    "MsKeyboardFilter"                         = "Disabled"         # Microsoft Keyboard Filter
    "MSiSCSI"                                  = "Manual"           # Microsoft iSCSI Initiator Service
    "msiserver"                                = "Manual"           # Windows Installer
    "NaturalAuthentication"                    = "Manual"           # Natural Authentication
    "NcaSvc"                                   = "Manual"           # Network Connectivity Assistant
    "NcbService"                               = "Manual"           # Network Connection Broker
    "NcdAutoSetup"                             = "Manual"           # Network Connected Devices Auto-Setup
    "nvagent"                                  = "Manual"           # Network Virtualization Service
    "p2pimsvc"                                 = "Manual"           # Peer Networking Identity Manager
    "p2psvc"                                   = "Manual"           # Peer Networking Grouping
    "PeerDistSvc"                              = "Manual"           # BranchCache
    "PerfHost"                                 = "Manual"           # Performance Counter DLL Host
    "pla"                                      = "Manual"           # Performance Logs & Alerts
    "PNRPAutoReg"                              = "Manual"           # PNRP Machine Name Publication Service
    "PNRPsvc"                                  = "Manual"           # Peer Name Resolution Protocol
    "QWAVE"                                    = "Manual"           # Quality Windows Audio Video Experience
    "RetailDemo"                               = "Manual"           # Retail Demo Service
    "RmSvc"                                    = "Manual"           # Radio Management Service
    "seclogon"                                 = "Manual"           # Secondary Logon
    "SENS"                                     = "Automatic"        # System Event Notification Service
    "SEMgrSvc"                                 = "Manual"           # Payments and NFC/SE Manager
    "SensorDataService"                        = "Manual"           # Sensor Data Service
    "SensorService"                            = "Manual"           # Sensor Service
    "SensrSvc"                                 = "Manual"           # Sensor Monitoring Service
    "SharedAccess"                             = "Manual"           # Internet Connection Sharing
    "ssh-agent"                                = "Disabled"         # OpenSSH Authentication Agent
    "smphost"                                  = "Manual"           # Microsoft Storage Spaces SMP
    "SmsRouter"                                = "Manual"           # Microsoft Windows SMS Router Service
    "SNMPTRAP"                                 = "Manual"           # SNMP Trap
    "sppsvc"                                   = "AutomaticDelayedStart" # Software Protection
    "SSDPSRV"                                  = "Manual"           # SSDP Discovery
    "svsvc"                                    = "Manual"           # Spot Verifier
    "SysMain"                                  = "Automatic"        # SysMain (Superfetch)
    "TabletInputService"                       = "Manual"           # Touch Keyboard and Handwriting Panel
    "TapiSrv"                                  = "Manual"           # Telephony
    "TrkWks"                                   = "Automatic"        # Distributed Link Tracking Client
    "upnphost"                                 = "Manual"           # UPnP Device Host
    "WalletService"                            = "Manual"           # WalletService
    "WebClient"                                = "Manual"           # WebClient
    "Wecsvc"                                   = "Manual"           # Windows Event Collector
    "WEPHOSTSVC"                               = "Manual"           # Windows Encryption Provider Host Service
    "WinHttpAutoProxySvc"                      = "Manual"           # WinHTTP Web Proxy Auto-Discovery
    "Winmgmt"                                  = "Automatic"        # Windows Management Instrumentation
    "WinRM"                                    = "Manual"           # Windows Remote Management (WS-Management)
    "wlidsvc"                                  = "Manual"           # Microsoft Account Sign-in Assistant
    "wlpasvc"                                  = "Manual"           # Local Profile Assistant Service
    "wmiApSrv"                                 = "Manual"           # WMI Performance Adapter
    "workfolderssvc"                           = "Manual"           # Work Folders
    "WpcMonSvc"                                = "Manual"           # Parental Controls
    "WpnService"                               = "Automatic"        # Windows Push Notifications System Service
    "XblAuthManager"                           = "Manual"           # Xbox Live Auth Manager
    "XblGameSave"                              = "Manual"           # Xbox Live Game Save
    "XboxNetApiSvc"                            = "Manual"           # Xbox Live Networking Service

    # IIS & Web Services (if installed)
    "ftpsvc"                                   = "Automatic"        # Microsoft FTP Service
    "IISADMIN"                                 = "Automatic"        # IIS Admin Service
    "iprip"                                    = "Automatic"        # RIP Listener
    "IpxlatCfgSvc"                             = "Manual"           # IP Translation Configuration Service
    "IEEtwCollectorService"                    = "Manual"           # Internet Explorer ETW Collector
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
