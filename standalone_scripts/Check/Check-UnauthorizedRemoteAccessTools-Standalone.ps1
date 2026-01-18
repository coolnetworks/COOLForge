<#
.SYNOPSIS
    Standalone script to detect unauthorized remote access tools on the system.

.DESCRIPTION
    This script scans for remote access tools (RATs) that may be installed without
    authorization. It checks:
    - Running processes
    - Installed services
    - Registry entries
    - Common installation directories

    STANDALONE VERSION - No COOLForge library required.

.PARAMETER ScreenConnectInstanceId
    Your MSP's whitelisted ScreenConnect instance ID (optional).

.PARAMETER IsScreenConnectServer
    Set to "true" if this device is a ScreenConnect server (optional).

.NOTES
    Version:          2025.01.07.01 (Standalone)
    Exit Codes:       0 = Success (No unauthorized RATs) | 1 = Alert (RATs detected)

    License:          AGPL-3.0 (see LICENSE)
    Copyright (c) 2025-2026 COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge

.EXAMPLE
    .\Check-UnauthorizedRemoteAccessTools-Standalone.ps1
#>

#region Configuration
# ============================================================
# CONFIGURATION
# ============================================================
# These values are populated via Level.io custom field variable substitution.
# Set these custom fields in Level.io:
#   - cf_coolforge_screenconnect_instance_id : Your MSP's ScreenConnect instance ID
#   - cf_coolforge_is_screenconnect_server   : Set to "true" if device hosts ScreenConnect server
$ScreenConnectInstanceId = "{{cf_coolforge_screenconnect_instance_id}}"
$IsScreenConnectServer = "{{cf_coolforge_is_screenconnect_server}}"

# Normalize empty/unsubstituted values
if ($ScreenConnectInstanceId -like "{{*}}") { $ScreenConnectInstanceId = "" }
if ($IsScreenConnectServer -like "{{*}}") { $IsScreenConnectServer = "" }

# Authorized RMM tools (automatically excluded from detection)
$AuthorizedRMMTools = @(
    "Level.io"      # Add your authorized RMM tools here
    # "Datto RMM"
    # "NinjaRMM"
)
#endregion Configuration

#region Embedded Functions
function Write-Log {
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "SKIP", "DEBUG")]
        [string]$Level = "INFO"
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Prefix = switch ($Level) {
        "INFO"    { "[*]" }
        "WARN"    { "[!]" }
        "ERROR"   { "[X]" }
        "SUCCESS" { "[+]" }
        "SKIP"    { "[-]" }
        "DEBUG"   { "[D]" }
    }
    Write-Host "$Timestamp $Prefix $Message"
}

function Get-ScreenConnectInstanceID {
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
    return @(
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
            $ParentPath = Split-Path $FullPath -ErrorAction SilentlyContinue
            $LeafPattern = Split-Path $FullPath -Leaf -ErrorAction SilentlyContinue
            if ($ParentPath -and (Test-Path $ParentPath)) {
                $FoundMatches = Get-ChildItem -Path $ParentPath -Filter $LeafPattern -ErrorAction SilentlyContinue
                if ($FoundMatches) {
                    $DetectionMethods += "Directory: $($FoundMatches.FullName -join ', ')"
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
#endregion Embedded Functions

#region Main Execution
Write-Host ""
Write-Host "============================================================"
Write-Host "  Remote Access Tool Detection (Standalone)"
Write-Host "============================================================"
Write-Host ""

$ErrorActionPreference = "SilentlyContinue"

Write-Log "Starting Remote Access Tool detection scan"
Write-Log "Device: $env:COMPUTERNAME"

# Get tool definitions
$RemoteAccessTools = Get-RemoteAccessToolDefinitions
Write-Log "Scanning for $($RemoteAccessTools.Count) known remote access tools"

# Registry paths to check for installed software
$RegistryPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

# Gather system information
Write-Log "Gathering installed software list..."
$InstalledSoftware = foreach ($Path in $RegistryPaths) {
    Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } |
        Select-Object DisplayName, InstallLocation, Publisher
}

Write-Log "Gathering running processes..."
$RunningProcesses = Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name -Unique

Write-Log "Gathering services..."
$AllServices = Get-Service -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name

# Track detections
$DetectedTools = @()

# Check if this is a ScreenConnect Server
if ($IsScreenConnectServer -eq "true") {
    Write-Log "This device is marked as a ScreenConnect Server - ScreenConnect excluded" -Level "INFO"
}

# Scan for each tool
foreach ($Tool in $RemoteAccessTools) {

    # Skip authorized RMM tools
    if ($Tool.Name -in $AuthorizedRMMTools) {
        continue
    }

    # Handle ScreenConnect whitelisting
    if ($Tool.Name -eq "ScreenConnect") {
        if ($IsScreenConnectServer -eq "true") {
            continue
        }

        if ($ScreenConnectInstanceId -and $ScreenConnectInstanceId -ne "") {
            $DetectedInstanceID = Get-ScreenConnectInstanceID
            if ($DetectedInstanceID -and $DetectedInstanceID -eq $ScreenConnectInstanceId) {
                Write-Log "ScreenConnect instance '$DetectedInstanceID' matches whitelist - skipping" -Level "INFO"
                continue
            }
            elseif ($DetectedInstanceID) {
                Write-Log "ScreenConnect instance '$DetectedInstanceID' does NOT match whitelist '$ScreenConnectInstanceId'" -Level "WARN"
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
Write-Log "========================================"
Write-Log "Remote Access Tool Detection Results"
Write-Log "========================================"
Write-Host ""

if ($DetectedTools.Count -eq 0) {
    Write-Log "No unauthorized remote access tools detected" -Level "SUCCESS"
    exit 0
}
else {
    Write-Log "DETECTED REMOTE ACCESS TOOLS: $($DetectedTools.Count)" -Level "ERROR"
    Write-Host ""

    foreach ($Detection in $DetectedTools) {
        Write-Log "ALERT: $($Detection.Name)" -Level "ERROR"
        foreach ($Method in $Detection.Methods) {
            Write-Host "  -> $Method"
        }
        Write-Host ""
    }

    Write-Log "ACTION REQUIRED: Review and remediate detected tools" -Level "WARN"
    exit 1
}
#endregion Main Execution
