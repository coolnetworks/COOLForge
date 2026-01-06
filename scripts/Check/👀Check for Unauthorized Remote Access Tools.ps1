<#
.SYNOPSIS
    Detects unauthorized remote access tools on the system.

.DESCRIPTION
    This script scans for remote access tools (RATs) that may be installed without
    authorization. It checks:

    - Running processes
    - Installed services
    - Registry entries
    - Common installation directories

    The script supports whitelisting for authorized tools like ScreenConnect when
    the instance ID matches the organization's approved installation.

    When run via Script Launcher, this script inherits all Level.io variables
    and the library is already loaded.

.NOTES
    Version:          2025.12.27.02
    Target Platform:  Level.io RMM (via Script Launcher)
    Exit Codes:       0 = Success (No unauthorized RATs) | 1 = Alert (RATs detected)

    Level.io Variables Used (passed from Script Launcher):
    - $MspScratchFolder  : MSP-defined scratch folder for persistent storage
    - $LibraryUrl        : URL to download COOLForge-Common.psm1 library
    - $DeviceHostname    : Device hostname from Level.io
    - $DeviceTags        : Comma-separated list of device tags

    Additional Custom Fields (define in launcher):
    - $ScreenConnectInstanceId : Whitelisted ScreenConnect instance ID
    - $IsScreenConnectServer   : Set to "true" if device is a ScreenConnect server

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# 👀Check for Unauthorized Remote Access Tools
# Version: 2025.12.27.02
# Target: Level.io (via Script Launcher)
# Exit 0 = Success (No unauthorized RATs) | Exit 1 = Alert (RATs detected)
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge

# ============================================================
# INITIALIZE
# ============================================================
# Script Launcher has already loaded the library and passed variables
# We just need to initialize with the passed-through variables

$Init = Initialize-LevelScript -ScriptName "RATDetection" `
                               -MspScratchFolder $MspScratchFolder `
                               -DeviceHostname $DeviceHostname `
                               -DeviceTags $DeviceTags `
                               -BlockingTags @("❌")

if (-not $Init.Success) {
    exit 0
}

# ============================================================
# CONFIGURATION
# ============================================================
# These can be set via custom fields in the launcher
# Add to Script_Launcher.ps1:
#   $ScreenConnectInstanceId = "{{cf_CoolForge_screenconnect_instance_id}}"
#   $IsScreenConnectServer = "{{cf_CoolForge_is_screenconnect_server}}"

# Check if variables exist (passed from launcher), otherwise use empty defaults
if (-not (Get-Variable -Name 'ScreenConnectInstanceId' -ErrorAction SilentlyContinue)) {
    $ScreenConnectInstanceId = ""
}
if (-not (Get-Variable -Name 'IsScreenConnectServer' -ErrorAction SilentlyContinue)) {
    $IsScreenConnectServer = ""
}

# ============================================================
# AUTHORIZED RMM TOOLS (Auto-whitelisted)
# ============================================================
# These RMM tools are automatically excluded from detection because
# this script runs via Level.io, which is an authorized RMM platform.
# Add your organization's authorized RMM tools here.
$AuthorizedRMMTools = @(
    "Level.io"      # The RMM platform running this script
    # Add other authorized RMM tools below:
    # "Datto RMM"
    # "NinjaRMM"
    # "Atera"
)

# ============================================================
# RAT DETECTION FUNCTIONS
# ============================================================

function Get-ScreenConnectInstanceID {
    <#
    .SYNOPSIS
        Extracts the ScreenConnect instance ID from installed services or registry.
    .RETURNS
        The instance ID string, or $null if not found.
    #>

    # Check services for instance ID (format: ScreenConnect Client (GUID))
    $SCServices = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "ScreenConnect*" }
    foreach ($Svc in $SCServices) {
        if ($Svc.Name -match '\(([a-f0-9]{8,})\)') {
            return $Matches[1]
        }
    }

    # Check registry for instance ID
    $RegistryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($Path in $RegistryPaths) {
        $SCInstalls = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like "*ScreenConnect*" -or $_.DisplayName -like "*ConnectWise Control*" }
        foreach ($Install in $SCInstalls) {
            if ($Install.DisplayName -match '\(([a-f0-9]{8,})\)') {
                return $Matches[1]
            }
        }
    }

    # Check install directories
    $SCPaths = @(
        "C:\Program Files (x86)\ScreenConnect Client*"
        "C:\Program Files\ScreenConnect Client*"
    )
    foreach ($Path in $SCPaths) {
        $ParentPath = Split-Path $Path
        $Pattern = Split-Path $Path -Leaf
        if (Test-Path $ParentPath) {
            $Folders = Get-ChildItem -Path $ParentPath -Filter $Pattern -Directory -ErrorAction SilentlyContinue
            foreach ($Folder in $Folders) {
                if ($Folder.Name -match '\(([a-f0-9]{8,})\)') {
                    return $Matches[1]
                }
            }
        }
    }

    return $null
}

function Get-RemoteAccessToolDefinitions {
    <#
    .SYNOPSIS
        Returns the comprehensive list of remote access tools to detect.
    .RETURNS
        Array of hashtables with tool definitions.
    #>

    return @(
        # Tool Name              | Process Names                           | Service Names                              | Registry/Path Indicators
        @{ Name = "AnyDesk";           Processes = @("AnyDesk", "AnyDesk*");           Services = @("AnyDesk", "AnyDesk*");           Paths = @("*\AnyDesk*") }
        @{ Name = "TeamViewer";        Processes = @("TeamViewer", "TeamViewer*");     Services = @("TeamViewer", "TeamViewer*");     Paths = @("*\TeamViewer*") }
        @{ Name = "RustDesk";          Processes = @("rustdesk", "rustdesk*");         Services = @("rustdesk", "RustDesk*");         Paths = @("*\RustDesk*") }
        @{ Name = "ScreenConnect";     Processes = @("ScreenConnect*", "ConnectWiseControl*"); Services = @("ScreenConnect*", "ConnectWise*"); Paths = @("*\ScreenConnect*", "*\ConnectWise*Control*"); Whitelistable = $true }
        @{ Name = "Splashtop";         Processes = @("SplashtopStreamer*", "Splashtop*", "strwinclt*"); Services = @("Splashtop*", "SplashtopRemote*"); Paths = @("*\Splashtop*") }
        @{ Name = "LogMeIn";           Processes = @("LogMeIn*", "LMI*");              Services = @("LogMeIn*", "LMI*");              Paths = @("*\LogMeIn*") }
        @{ Name = "GoToAssist";        Processes = @("GoTo*", "g2a*");                 Services = @("GoTo*", "GoToAssist*");          Paths = @("*\GoTo*", "*\GoToAssist*") }
        @{ Name = "GoToMyPC";          Processes = @("GoToMyPC*", "g2mpc*");           Services = @("GoToMyPC*");                     Paths = @("*\GoToMyPC*") }
        @{ Name = "RemotePC";          Processes = @("RemotePC*", "RPCService*");      Services = @("RemotePC*");                     Paths = @("*\RemotePC*") }
        @{ Name = "BeyondTrust";       Processes = @("bomgar*", "BeyondTrust*");       Services = @("bomgar*", "BeyondTrust*");       Paths = @("*\Bomgar*", "*\BeyondTrust*") }
        @{ Name = "DWService";         Processes = @("dwagent*", "dwagsvc*");          Services = @("dwagent*", "DWAgent*");          Paths = @("*\DWAgent*", "*\DWService*") }
        @{ Name = "RealVNC";           Processes = @("vncserver*", "vncviewer*", "winvnc*"); Services = @("vncserver", "RealVNC*");   Paths = @("*\RealVNC*") }
        @{ Name = "TightVNC";          Processes = @("tvnserver*", "tvnviewer*");      Services = @("tvnserver", "TightVNC*");        Paths = @("*\TightVNC*") }
        @{ Name = "UltraVNC";          Processes = @("winvnc*", "ultravnc*");          Services = @("uvnc*", "UltraVNC*");            Paths = @("*\UltraVNC*", "*\uvnc*") }
        @{ Name = "TigerVNC";          Processes = @("vncserver", "x0vncserver*");     Services = @("TigerVNC*");                     Paths = @("*\TigerVNC*") }
        @{ Name = "Radmin";            Processes = @("radmin*", "rserver*");           Services = @("radmin*", "rserver*");           Paths = @("*\Radmin*") }
        @{ Name = "Chrome Remote Desktop"; Processes = @("remoting_host*", "chromoting*"); Services = @("chromoting*", "Chrome Remote*"); Paths = @("*\Chrome Remote Desktop*", "*\Google\Chrome Remote*") }
        @{ Name = "Ammyy Admin";       Processes = @("AA_v*", "Ammyy*");               Services = @("Ammyy*");                        Paths = @("*\Ammyy*") }
        @{ Name = "SimpleHelp";        Processes = @("SimpleHelp*", "Remote Access*"); Services = @("SimpleHelp*");                   Paths = @("*\SimpleHelp*") }
        @{ Name = "Supremo";           Processes = @("Supremo*", "SupremoService*");   Services = @("Supremo*");                      Paths = @("*\Supremo*") }
        @{ Name = "Zoho Assist";       Processes = @("ZohoMeeting*", "ZohoAssist*", "ZA_Connect*"); Services = @("Zoho*Assist*", "ZohoMeeting*"); Paths = @("*\Zoho*Assist*", "*\ZohoMeeting*") }
        @{ Name = "ISL Online";        Processes = @("ISLLight*", "ISLAlwaysOn*");     Services = @("ISL*");                          Paths = @("*\ISL Online*", "*\ISLLight*") }
        @{ Name = "Parsec";            Processes = @("parsecd*", "pservice*");         Services = @("Parsec*");                       Paths = @("*\Parsec*") }
        @{ Name = "Action1";           Processes = @("action1*", "a1agent*");          Services = @("action1*", "Action1*");          Paths = @("*\Action1*") }
        @{ Name = "Atera";             Processes = @("AteraAgent*", "Atera*");         Services = @("AteraAgent*", "Atera*");         Paths = @("*\Atera*") }
        @{ Name = "N-able Take Control"; Processes = @("BASupSrvc*", "BASupApp*", "TakeControl*"); Services = @("BASupSrvc*", "TakeControl*"); Paths = @("*\BeAnywhere*", "*\Take Control*", "*\N-able*") }
        @{ Name = "Datto RMM";         Processes = @("AEMAgent*", "CagService*");      Services = @("AEM*", "CagService*", "Datto*"); Paths = @("*\CentraStage*", "*\Datto*") }
        @{ Name = "NinjaRMM";          Processes = @("NinjaRMM*", "ninjarmm*");        Services = @("NinjaRMM*");                     Paths = @("*\NinjaRMM*", "*\NinjaMSP*") }
        @{ Name = "NetSupport";        Processes = @("client32*", "pcictlui*");        Services = @("NetSupport*", "client32*");      Paths = @("*\NetSupport*") }
        @{ Name = "Parallels";         Processes = @("prl_*", "Parallels*");           Services = @("Parallels*");                    Paths = @("*\Parallels*") }
        @{ Name = "Remote Utilities";  Processes = @("rutserv*", "rfusclient*");       Services = @("rutserv*", "Remote Utilities*"); Paths = @("*\Remote Utilities*") }
        @{ Name = "Getscreen.me";      Processes = @("getscreen*");                    Services = @("getscreen*");                    Paths = @("*\Getscreen*") }
        @{ Name = "Iperius Remote";    Processes = @("IperiusRemote*");                Services = @("IperiusRemote*");                Paths = @("*\Iperius*") }
        @{ Name = "NoMachine";         Processes = @("nxserver*", "nxnode*", "nxd*");  Services = @("nxserver*", "NoMachine*");       Paths = @("*\NoMachine*") }
        @{ Name = "ZeroTier";          Processes = @("zerotier*");                     Services = @("ZeroTier*");                     Paths = @("*\ZeroTier*") }
        @{ Name = "Tailscale";         Processes = @("tailscale*", "tailscaled*");     Services = @("Tailscale*");                    Paths = @("*\Tailscale*") }
        @{ Name = "Meshcentral";       Processes = @("MeshAgent*", "meshagent*");      Services = @("Mesh Agent*", "MeshAgent*");     Paths = @("*\Mesh Agent*", "*\MeshCentral*") }
        @{ Name = "Fleetdeck";         Processes = @("fleetdeck*");                    Services = @("fleetdeck*");                    Paths = @("*\Fleetdeck*") }
        @{ Name = "Tactical RMM";      Processes = @("tacticalrmm*", "meshagent*");    Services = @("tacticalrmm*");                  Paths = @("*\TacticalAgent*") }
        @{ Name = "mRemoteNG";         Processes = @("mRemoteNG*");                    Services = @();                                Paths = @("*\mRemoteNG*") }
        @{ Name = "Royal TS";          Processes = @("RoyalTS*");                      Services = @();                                Paths = @("*\Royal TS*") }
        @{ Name = "Remote Desktop Plus"; Processes = @("rdp+*", "RemoteDesktopPlus*"); Services = @();                                Paths = @("*\Remote Desktop Plus*") }
        @{ Name = "Proxy Pro";         Processes = @("proxypro*", "pphost*");          Services = @("Proxy Pro*");                    Paths = @("*\Proxy Pro*") }
        @{ Name = "Goverlan";          Processes = @("GovReach*", "Goverlan*");        Services = @("Goverlan*");                     Paths = @("*\Goverlan*") }
        @{ Name = "Instant Housecall"; Processes = @("ihc*");                          Services = @("Instant Housecall*");            Paths = @("*\Instant Housecall*") }
        @{ Name = "FixMe.IT";          Processes = @("FixMe.IT*", "TechInline*");      Services = @("FixMe.IT*", "TechInline*");      Paths = @("*\FixMe.IT*", "*\TechInline*") }
        @{ Name = "Alpemix";           Processes = @("Alpemix*");                      Services = @("Alpemix*");                      Paths = @("*\Alpemix*") }
        @{ Name = "Mikogo";            Processes = @("Mikogo*");                       Services = @("Mikogo*");                       Paths = @("*\Mikogo*") }
        @{ Name = "ShowMyPC";          Processes = @("showmypc*", "smpc*");            Services = @("ShowMyPC*");                     Paths = @("*\ShowMyPC*") }
        @{ Name = "Aeroadmin";         Processes = @("AeroAdmin*");                    Services = @("AeroAdmin*");                    Paths = @("*\AeroAdmin*") }
        @{ Name = "pcAnywhere";        Processes = @("awhost*", "pcAnywhere*");        Services = @("pcAnywhere*");                   Paths = @("*\pcAnywhere*") }
        @{ Name = "LiteManager";       Processes = @("ROMServer*", "ROMViewer*");      Services = @("LiteManager*", "ROMServer*");    Paths = @("*\LiteManager*") }
        @{ Name = "Itarian";           Processes = @("ITSMAgent*", "ItarianAgent*");   Services = @("ITarian*", "ITSM*");             Paths = @("*\ITarian*", "*\ITSM Agent*") }
        @{ Name = "Pulseway";          Processes = @("PCMonitorSrv*", "Pulseway*");    Services = @("Pulseway*", "PCMonitor*");       Paths = @("*\Pulseway*", "*\PCMonitor*") }
        @{ Name = "Syncro";            Processes = @("Syncro*", "Kabuto*");            Services = @("Syncro*", "Kabuto*");            Paths = @("*\Syncro*", "*\Kabuto*") }
        @{ Name = "Naverisk";          Processes = @("Naverisk*", "NACService*");      Services = @("Naverisk*", "NAC*");             Paths = @("*\Naverisk*") }
        @{ Name = "Kaseya";            Processes = @("agentmon*", "KaService*");       Services = @("Kaseya*", "KaService*");         Paths = @("*\Kaseya*") }
        @{ Name = "Continuum";         Processes = @("SAAZ*", "ITSPlatform*");         Services = @("SAAZ*", "ITSPlatform*");         Paths = @("*\SAAZOD*", "*\ITSPlatform*") }
        @{ Name = "Auvik";             Processes = @("AuvikAgent*");                   Services = @("Auvik*");                        Paths = @("*\Auvik*") }
        @{ Name = "Ivanti";            Processes = @("IvantiClient*", "LANDesk*");     Services = @("Ivanti*", "LANDesk*");           Paths = @("*\Ivanti*", "*\LANDesk*") }
        @{ Name = "Tanium";            Processes = @("TaniumClient*");                 Services = @("Tanium*");                       Paths = @("*\Tanium*") }
        @{ Name = "PDQ";               Processes = @("PDQDeploy*", "PDQInventory*");   Services = @("PDQ*");                          Paths = @("*\PDQ*") }
        @{ Name = "ManageEngine";      Processes = @("UEMS*", "DesktopCentral*");      Services = @("ManageEngine*", "DesktopCentral*"); Paths = @("*\ManageEngine*", "*\DesktopCentral*") }
        @{ Name = "Level.io";          Processes = @("level-*", "level_*");            Services = @("level*");                        Paths = @("*\Level\*", "*\Level.io*") }
    )
}

function Test-ToolPresence {
    <#
    .SYNOPSIS
        Checks if a specific remote access tool is present on the system.
    .PARAMETER Tool
        Hashtable containing tool definition (Name, Processes, Services, Paths).
    .PARAMETER RunningProcesses
        Array of running process names.
    .PARAMETER AllServices
        Array of service names.
    .PARAMETER InstalledSoftware
        Array of installed software objects.
    .RETURNS
        Hashtable with detection results, or $null if not found.
    #>
    param(
        [hashtable]$Tool,
        [array]$RunningProcesses,
        [array]$AllServices,
        [array]$InstalledSoftware
    )

    $DetectionMethods = @()

    # Check processes
    foreach ($ProcessPattern in $Tool.Processes) {
        $MatchingProcesses = $RunningProcesses | Where-Object { $_ -like $ProcessPattern }
        if ($MatchingProcesses) {
            $DetectionMethods += "Process: $($MatchingProcesses -join ', ')"
        }
    }

    # Check services
    foreach ($ServicePattern in $Tool.Services) {
        $MatchingServices = $AllServices | Where-Object { $_ -like $ServicePattern }
        if ($MatchingServices) {
            $DetectionMethods += "Service: $($MatchingServices -join ', ')"
        }
    }

    # Check installed software
    foreach ($PathPattern in $Tool.Paths) {
        $MatchingSoftware = $InstalledSoftware | Where-Object {
            $_.DisplayName -like $PathPattern -or $_.InstallLocation -like $PathPattern
        }
        if ($MatchingSoftware) {
            $DetectionMethods += "Installed: $($MatchingSoftware.DisplayName -join ', ')"
        }
    }

    # Check common installation directories
    $CommonPaths = @(
        "C:\Program Files",
        "C:\Program Files (x86)",
        "$env:LOCALAPPDATA",
        "$env:APPDATA",
        "$env:ProgramData"
    )

    foreach ($BasePath in $CommonPaths) {
        foreach ($PathPattern in $Tool.Paths) {
            $SearchPattern = $PathPattern -replace '^\*\\', ''
            $FullPath = Join-Path $BasePath $SearchPattern
            # Handle wildcards in the path
            $ParentPath = Split-Path $FullPath -ErrorAction SilentlyContinue
            $LeafPattern = Split-Path $FullPath -Leaf -ErrorAction SilentlyContinue
            if ($ParentPath -and (Test-Path $ParentPath)) {
                $Matches = Get-ChildItem -Path $ParentPath -Filter $LeafPattern -ErrorAction SilentlyContinue
                if ($Matches) {
                    $DetectionMethods += "Directory: $($Matches.FullName -join ', ')"
                }
            }
        }
    }

    if ($DetectionMethods.Count -gt 0) {
        return @{
            Name = $Tool.Name
            Methods = ($DetectionMethods | Select-Object -Unique)
        }
    }

    return $null
}

# ============================================================
# MAIN SCRIPT LOGIC
# ============================================================
Invoke-LevelScript -ScriptBlock {

    Write-LevelLog "Starting Remote Access Tool detection scan"

    # Log device info
    $DeviceInfo = Get-LevelDeviceInfo
    Write-LevelLog "Device: $($DeviceInfo.Hostname) | OS: $($DeviceInfo.OS) | Admin: $($DeviceInfo.IsAdmin)"

    # Get tool definitions
    $RemoteAccessTools = Get-RemoteAccessToolDefinitions
    Write-LevelLog "Scanning for $($RemoteAccessTools.Count) known remote access tools"

    # Registry paths to check for installed software
    $RegistryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    # Gather system information
    Write-LevelLog "Gathering installed software list..."
    $InstalledSoftware = foreach ($Path in $RegistryPaths) {
        Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } |
            Select-Object DisplayName, InstallLocation, Publisher
    }

    Write-LevelLog "Gathering running processes..."
    $RunningProcesses = Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name -Unique

    Write-LevelLog "Gathering services..."
    $AllServices = Get-Service -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name

    # Track detections
    $DetectedTools = @()

    # Check if this is a ScreenConnect Server
    if ($IsScreenConnectServer -eq "true") {
        Write-LevelLog "This device is marked as a ScreenConnect Server - ScreenConnect excluded" -Level "INFO"
    }

    # Scan for each tool
    foreach ($Tool in $RemoteAccessTools) {

        # Skip authorized RMM tools
        if ($Tool.Name -in $AuthorizedRMMTools) {
            Write-LevelLog "$($Tool.Name) is in authorized list - skipping" -Level "DEBUG"
            continue
        }

        # Handle ScreenConnect whitelisting
        if ($Tool.Name -eq "ScreenConnect") {
            # Skip entirely if this is a ScreenConnect Server
            if ($IsScreenConnectServer -eq "true") {
                continue
            }

            # Check if installed ScreenConnect matches whitelisted instance ID
            if ($ScreenConnectInstanceId -and $ScreenConnectInstanceId -ne "" -and $ScreenConnectInstanceId -notlike "{{*}}") {
                $DetectedInstanceID = Get-ScreenConnectInstanceID
                if ($DetectedInstanceID -and $DetectedInstanceID -eq $ScreenConnectInstanceId) {
                    Write-LevelLog "ScreenConnect instance '$DetectedInstanceID' matches whitelist - skipping" -Level "INFO"
                    continue
                }
                elseif ($DetectedInstanceID) {
                    Write-LevelLog "ScreenConnect instance '$DetectedInstanceID' does NOT match whitelist '$ScreenConnectInstanceId'" -Level "WARN"
                }
            }
        }

        # Check for tool presence
        $Detection = Test-ToolPresence -Tool $Tool `
                                       -RunningProcesses $RunningProcesses `
                                       -AllServices $AllServices `
                                       -InstalledSoftware $InstalledSoftware

        if ($Detection) {
            $DetectedTools += $Detection
        }
    }

    # Output results
    Write-Host ""
    Write-LevelLog "========================================" -Level "INFO"
    Write-LevelLog "Remote Access Tool Detection Results" -Level "INFO"
    Write-LevelLog "========================================" -Level "INFO"
    Write-Host ""

    if ($DetectedTools.Count -eq 0) {
        Write-LevelLog "No unauthorized remote access tools detected" -Level "SUCCESS"
        # Exit via Invoke-LevelScript completion (exit 0)
    }
    else {
        Write-LevelLog "DETECTED REMOTE ACCESS TOOLS: $($DetectedTools.Count)" -Level "ERROR"
        Write-Host ""

        foreach ($Detection in $DetectedTools) {
            Write-LevelLog "ALERT: $($Detection.Name)" -Level "ERROR"
            foreach ($Method in $Detection.Methods) {
                Write-Host "  -> $Method"
            }
            Write-Host ""
        }

        Write-LevelLog "ACTION REQUIRED: Review and remediate detected tools" -Level "WARN"
        Complete-LevelScript -ExitCode 1 -Message "Detected $($DetectedTools.Count) unauthorized remote access tool(s)"
    }
}
