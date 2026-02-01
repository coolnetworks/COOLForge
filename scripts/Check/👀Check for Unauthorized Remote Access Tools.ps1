<#
.SYNOPSIS
    Detects and optionally removes unauthorized remote access tools on the system.

.DESCRIPTION
    This script scans for remote access tools (RATs) that may be installed without
    authorization. It checks:

    - Running processes
    - Installed services
    - Registry entries
    - Common installation directories

    The script supports whitelisting for authorized tools:
    - ScreenConnect: Whitelist by instance ID
    - Meshcentral: Whitelist by server URL (e.g., mc.cool.net.au)
    - Any tool: Whitelist via policy_ok_rats custom field (comma-separated names)

    On first run, if policy_ok_rats is empty, the script populates it with all
    currently detected tools as a baseline whitelist. This prevents unintended
    removal of sanctioned tools when auto-remove is later enabled.

    When auto-remove is enabled, the script will attempt to uninstall detected
    unauthorized RATs using comprehensive removal logic including registry cleanup,
    service removal, firewall rules, scheduled tasks, and file deletion.

    When run via Script Launcher, this script inherits all Level.io variables
    and the library is already loaded.

.NOTES
    Version:          2026.02.01.01
    Target Platform:  Level.io RMM (via Script Launcher)
    Exit Codes:       0 = Success (No unauthorized RATs) | 1 = Alert (RATs detected/removed)

    Level.io Variables Used (passed from Script Launcher):
    - $MspScratchFolder  : MSP-defined scratch folder for persistent storage
    - $LibraryUrl        : URL to download COOLForge-Common.psm1 library
    - $DeviceHostname    : Device hostname from Level.io
    - $DeviceTags        : Comma-separated list of device tags

    Additional Custom Fields (define in launcher):
    - $ScreenConnectInstanceId : Whitelisted ScreenConnect instance ID
    - $IsScreenConnectServer   : Set to "true" if device is a ScreenConnect server
    - $MeshcentralServerUrl    : Whitelisted Meshcentral server URL (e.g., mc.cool.net.au)
    - $AutoRemoveRATs          : Set to "true" to auto-remove detected RATs
    - $PolicyOkRats            : Comma-separated list of whitelisted RAT names

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# Check for Unauthorized Remote Access Tools (U+1F440)
# Version: 2026.02.01.01
# Target: Level.io (via Script Launcher)
# Exit 0 = Success (No unauthorized RATs) | Exit 1 = Alert (RATs detected)
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge

# ============================================================
# LAUNCHER VARIABLE DETECTION
# ============================================================
$RunningFromLauncher = $null -ne (Get-Variable -Name "LauncherVariables" -ValueOnly -ErrorAction SilentlyContinue)

if ($RunningFromLauncher) {
    $MspScratchFolder = $LauncherVariables.MspScratchFolder
    $DeviceHostname = $LauncherVariables.DeviceHostname
    $DeviceTags = $LauncherVariables.DeviceTags
    $DebugScripts = $LauncherVariables.DebugScripts
    $LevelApiKey = $LauncherVariables.LevelApiKey
    $PolicyBlockDevice = $LauncherVariables.PolicyBlockDevice
    $PolicyRatRemoval = $LauncherVariables.PolicyRatRemoval
    $ScreenConnectInstanceId = $LauncherVariables.ScreenConnectInstanceId
    $IsScreenConnectServer = $LauncherVariables.IsScreenConnectServer
    $MeshcentralServerUrl = $LauncherVariables.MeshcentralServerUrl
    $AutoRemoveRATs = $LauncherVariables.AutoRemoveRATs
    $PolicyOkRats = $LauncherVariables.PolicyOkRats
} else {
    # Standalone mode defaults
    $MspScratchFolder = if ($env:CF_SCRATCH) { $env:CF_SCRATCH } else { "C:\ProgramData\MSP" }
    $DeviceHostname = $env:COMPUTERNAME
    $DeviceTags = ""
    $DebugScripts = $false
    $LevelApiKey = $null
    $PolicyBlockDevice = ""
    $PolicyRatRemoval = "detect"
    $ScreenConnectInstanceId = ""
    $IsScreenConnectServer = ""
    $MeshcentralServerUrl = ""
    $AutoRemoveRATs = ""
    $PolicyOkRats = ""
}

# Normalize policy values
if ([string]::IsNullOrWhiteSpace($PolicyRatRemoval) -or $PolicyRatRemoval -like "{{*}}") {
    $PolicyRatRemoval = "detect"
}
$PolicyRatRemoval = $PolicyRatRemoval.ToLower().Trim()

# Normalize auto-remove setting (set by launcher based on policy)
$EnableAutoRemove = ($AutoRemoveRATs -eq "true" -or $PolicyRatRemoval -eq "remove")

# Parse whitelisted RATs from policy field
$WhitelistedRats = @()
if (-not [string]::IsNullOrWhiteSpace($PolicyOkRats) -and $PolicyOkRats -notlike "{{*}}") {
    $WhitelistedRats = $PolicyOkRats -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
}

# ============================================================
# INITIALIZE
# ============================================================
$Init = Initialize-LevelScript -ScriptName "RATDetection" `
                               -MspScratchFolder $MspScratchFolder `
                               -DeviceHostname $DeviceHostname `
                               -DeviceTags $DeviceTags `
                               -BlockingTags @("❌") `
                               -PolicyBlockDevice $PolicyBlockDevice

if (-not $Init.Success) {
    exit 0
}

# Sync script-level debug variables if a debug tag overrode the custom field
if ($Init.DebugTagDetected) {
    $DebugLevel = $Init.DebugLevel
    $DebugScripts = $Init.DebugMode
}

# ============================================================
# AUTO-BOOTSTRAP: Ensure policy_ok_rats field exists
# ============================================================
if ($LevelApiKey) {
    $OkRatsFieldName = "policy_ok_rats"
    $OkRatsFieldExists = -not [string]::IsNullOrWhiteSpace($PolicyOkRats) -and $PolicyOkRats -notlike "{{*}}"
    if (-not $OkRatsFieldExists) {
        $NewField = New-LevelCustomField -ApiKey $LevelApiKey -Name $OkRatsFieldName -DefaultValue ""
        if ($NewField) {
            Write-LevelLog "Created custom field: $OkRatsFieldName" -Level "SUCCESS"
        }
    }
}

# Check if policy says to skip
if ($PolicyRatRemoval -eq "skip") {
    Write-LevelLog "Policy is 'skip' - RAT detection disabled for this device" -Level "INFO"
    Write-Host "OK: RAT detection skipped (policy=skip)"
    exit 0
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

function Get-MeshcentralServerUrl {
    <#
    .SYNOPSIS
        Extracts the Meshcentral server URL from the Mesh Agent configuration.
    .RETURNS
        The server URL string, or $null if not found.
    #>

    # Check common Mesh Agent locations for config
    $MeshAgentPaths = @(
        "$env:ProgramFiles\Mesh Agent",
        "${env:ProgramFiles(x86)}\Mesh Agent",
        "$env:ProgramData\Mesh Agent"
    )

    foreach ($BasePath in $MeshAgentPaths) {
        # Check for MeshAgent.msh config file
        $ConfigFile = Join-Path $BasePath "MeshAgent.msh"
        if (Test-Path $ConfigFile) {
            $Content = Get-Content $ConfigFile -Raw -ErrorAction SilentlyContinue
            # Look for ServerUrl or MeshServer setting
            if ($Content -match 'MeshServer\s*=\s*wss?://([^/\s]+)') {
                return $Matches[1]
            }
            if ($Content -match 'ServerUrl\s*=\s*https?://([^/\s]+)') {
                return $Matches[1]
            }
        }

        # Check MeshAgent.db for server info
        $DbFile = Join-Path $BasePath "MeshAgent.db"
        if (Test-Path $DbFile) {
            $Content = Get-Content $DbFile -Raw -ErrorAction SilentlyContinue
            if ($Content -match 'wss?://([^/\s"]+)') {
                return $Matches[1]
            }
        }
    }

    # Check registry for Mesh Agent server
    $RegPaths = @(
        "HKLM:\SOFTWARE\Mesh Agent",
        "HKLM:\SOFTWARE\WOW6432Node\Mesh Agent"
    )
    foreach ($RegPath in $RegPaths) {
        if (Test-Path $RegPath) {
            $ServerUrl = Get-ItemProperty -Path $RegPath -Name "MeshServer" -ErrorAction SilentlyContinue
            if ($ServerUrl -and $ServerUrl.MeshServer -match 'wss?://([^/\s]+)') {
                return $Matches[1]
            }
        }
    }

    return $null
}

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

        # Additional Legitimate Remote Access Tools
        @{ Name = "UltraViewer";       Processes = @("UltraViewer*");                  Services = @("UltraViewer*");                  Paths = @("*\UltraViewer*") }
        @{ Name = "ToDesk";            Processes = @("ToDesk*", "ToDesk_Service*");    Services = @("ToDesk*");                       Paths = @("*\ToDesk*") }
        @{ Name = "Sunlogin";          Processes = @("SunloginClient*", "slservice*"); Services = @("Sunlogin*", "SunloginService*"); Paths = @("*\Sunlogin*", "*\Oray\SunLogin*") }
        @{ Name = "Oray";              Processes = @("oray*", "PHTunnel*");            Services = @("Oray*", "PHTunnel*");            Paths = @("*\Oray*") }
        @{ Name = "HopToDesk";         Processes = @("HopToDesk*");                    Services = @("HopToDesk*");                    Paths = @("*\HopToDesk*") }
        @{ Name = "AweRay/AweSun";     Processes = @("AweSun*", "AweRay*");            Services = @("AweSun*", "AweRay*");            Paths = @("*\AweSun*", "*\AweRay*") }
        @{ Name = "Dameware";          Processes = @("DVLS*", "dwrcs*", "DameWare*");  Services = @("DameWare*", "DVLS*", "dwmrcs*"); Paths = @("*\DameWare*", "*\SolarWinds\DameWare*") }
        @{ Name = "ConnectWise Automate"; Processes = @("LTService*", "LTSvcMon*", "LabTech*", "LTClient*"); Services = @("LTService*", "LabTech*"); Paths = @("*\LabTech*", "*\ConnectWise\Automate*") }
        @{ Name = "SolarWinds RMM";    Processes = @("SolarWinds*", "Advanced*Monitor*", "Windows Agent*"); Services = @("SolarWinds*", "Advanced Monitoring*"); Paths = @("*\SolarWinds*", "*\Advanced Monitoring*") }
        @{ Name = "Comodo RMM";        Processes = @("ItsmRsp*", "CmdAgent*", "COMODO*"); Services = @("Comodo*", "ItsmRsp*", "CmdAgent*"); Paths = @("*\COMODO\*", "*\Comodo\*") }
        @{ Name = "SuperOps";          Processes = @("SuperOps*");                     Services = @("SuperOps*");                     Paths = @("*\SuperOps*") }
        @{ Name = "Automox";           Processes = @("amagent*", "Automox*");          Services = @("amagent*", "Automox*");          Paths = @("*\Automox*") }
        @{ Name = "JumpCloud";         Processes = @("jumpcloud*", "jcagent*");        Services = @("jumpcloud*", "jcagent*");        Paths = @("*\JumpCloud*") }
        @{ Name = "Screenleap";        Processes = @("Screenleap*");                   Services = @();                                Paths = @("*\Screenleap*") }
        @{ Name = "FastViewer";        Processes = @("FastViewer*");                   Services = @("FastViewer*");                   Paths = @("*\FastViewer*") }
        @{ Name = "CrossLoop";         Processes = @("CrossLoop*");                    Services = @("CrossLoop*");                    Paths = @("*\CrossLoop*") }
        @{ Name = "HiDesk";            Processes = @("HiDesk*");                       Services = @("HiDesk*");                       Paths = @("*\HiDesk*") }
        @{ Name = "RayLink";           Processes = @("RayLink*");                      Services = @("RayLink*");                      Paths = @("*\RayLink*") }
        @{ Name = "RPort";             Processes = @("rport*");                        Services = @("rport*");                        Paths = @("*\rport*") }
        @{ Name = "Tmate";             Processes = @("tmate*");                        Services = @();                                Paths = @("*\tmate*") }
        @{ Name = "Ngrok";             Processes = @("ngrok*");                        Services = @("ngrok*");                        Paths = @("*\ngrok*") }
        @{ Name = "LocalTunnel";       Processes = @("lt*", "localtunnel*");           Services = @();                                Paths = @("*\localtunnel*") }

        # Known Malicious RATs / C2 Frameworks (High Priority Detection)
        @{ Name = "Remcos RAT";        Processes = @("remcos*", "Remcos*");            Services = @("remcos*");                       Paths = @("*\Remcos*"); Malicious = $true }
        @{ Name = "QuasarRAT";         Processes = @("Quasar*", "Client.exe");         Services = @("Quasar*");                       Paths = @("*\Quasar*"); Malicious = $true }
        @{ Name = "AsyncRAT";          Processes = @("AsyncClient*", "Async*");        Services = @("Async*");                        Paths = @("*\Async*"); Malicious = $true }
        @{ Name = "njRAT";             Processes = @("njRAT*", "Bladabindi*", "njw0rm*"); Services = @();                              Paths = @("*\njRAT*"); Malicious = $true }
        @{ Name = "NanoCore";          Processes = @("NanoCore*", "nanocore*");        Services = @();                                Paths = @("*\NanoCore*"); Malicious = $true }
        @{ Name = "DarkComet";         Processes = @("DarkComet*", "frmMain*");        Services = @();                                Paths = @("*\DarkComet*"); Malicious = $true }
        @{ Name = "Orcus RAT";         Processes = @("Orcus*");                        Services = @("Orcus*");                        Paths = @("*\Orcus*"); Malicious = $true }
        @{ Name = "NetWire RAT";       Processes = @("NetWire*", "Netwire*");          Services = @();                                Paths = @("*\NetWire*"); Malicious = $true }
        @{ Name = "Warzone RAT";       Processes = @("Warzone*", "Ave Maria*", "AveMaria*"); Services = @();                          Paths = @("*\Warzone*", "*\AveMaria*"); Malicious = $true }
        @{ Name = "Gh0st RAT";         Processes = @("Gh0st*", "ghost*", "pcshare*");  Services = @("Gh0st*");                        Paths = @("*\Gh0st*"); Malicious = $true }
        @{ Name = "Poison Ivy";        Processes = @("PoisonIvy*", "PIVY*");           Services = @();                                Paths = @("*\PoisonIvy*"); Malicious = $true }
        @{ Name = "BlackShades";       Processes = @("BlackShades*", "bss*");          Services = @();                                Paths = @("*\BlackShades*"); Malicious = $true }
        @{ Name = "Cobalt Strike";     Processes = @("beacon*", "artifact*", "cobaltstrike*"); Services = @();                        Paths = @("*\cobaltstrike*"); Malicious = $true }
        @{ Name = "Meterpreter";       Processes = @("metsrv*", "meterpreter*");       Services = @();                                Paths = @(); Malicious = $true }
        @{ Name = "Havoc C2";          Processes = @("demon*", "havoc*");              Services = @();                                Paths = @("*\havoc*"); Malicious = $true }
        @{ Name = "Sliver C2";         Processes = @("sliver*");                       Services = @();                                Paths = @("*\sliver*"); Malicious = $true }
        @{ Name = "Brute Ratel";       Processes = @("badger*", "bruteratel*");        Services = @();                                Paths = @("*\bruteratel*"); Malicious = $true }
        @{ Name = "Pupy RAT";          Processes = @("pupy*");                         Services = @();                                Paths = @("*\pupy*"); Malicious = $true }
        @{ Name = "Mythic C2";         Processes = @("mythic*", "apollo*", "poseidon*"); Services = @();                              Paths = @("*\mythic*"); Malicious = $true }
        @{ Name = "Covenant C2";       Processes = @("Grunt*", "covenant*");           Services = @();                                Paths = @("*\covenant*"); Malicious = $true }
        @{ Name = "Empire/Starkiller"; Processes = @("empire*", "starkiller*");        Services = @();                                Paths = @("*\empire*", "*\starkiller*"); Malicious = $true }
        @{ Name = "XtremeRAT";         Processes = @("Xtreme*", "XtremeRAT*");         Services = @();                                Paths = @("*\XtremeRAT*"); Malicious = $true }
        @{ Name = "Imminent Monitor";  Processes = @("Imminent*");                     Services = @();                                Paths = @("*\Imminent*"); Malicious = $true }
        @{ Name = "LuminosityLink";    Processes = @("Luminosity*");                   Services = @();                                Paths = @("*\Luminosity*"); Malicious = $true }
        @{ Name = "Adwind/JRat";       Processes = @("java*", "javaw*");               Services = @();                                Paths = @("*\Adwind*", "*\JRat*"); Malicious = $true }
        @{ Name = "SpyNote";           Processes = @("SpyNote*");                      Services = @();                                Paths = @("*\SpyNote*"); Malicious = $true }
        @{ Name = "CrackMapExec";      Processes = @("crackmapexec*", "cme*");         Services = @();                                Paths = @("*\crackmapexec*"); Malicious = $true }
        @{ Name = "Impacket";          Processes = @("impacket*", "smbexec*", "wmiexec*", "psexec*"); Services = @();                 Paths = @("*\impacket*"); Malicious = $true }
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
# RAT REMOVAL FUNCTIONS
# ============================================================

function Remove-RATool {
    param([string]$ToolName)

    $Result = @{ Success = $false; Message = "" }

    Write-LevelLog "Attempting to remove: $ToolName" -Level "INFO"

    switch ($ToolName) {
        "AnyDesk" {
            $Result = Remove-AnyDesk
        }
        "TeamViewer" {
            $Result = Remove-TeamViewer
        }
        "RustDesk" {
            $Result = Remove-RustDesk
        }
        "Meshcentral" {
            $Result = Remove-Meshcentral
        }
        "Splashtop" {
            $Result = Remove-Splashtop
        }
        "Chrome Remote Desktop" {
            $Result = Remove-ChromeRemoteDesktop
        }
        "LogMeIn" {
            $Result = Remove-GenericRAT -Name "LogMeIn" -ProcessPatterns @("LogMeIn*", "LMI*") -ServicePatterns @("LogMeIn*", "LMI*")
        }
        "RealVNC" {
            $Result = Remove-GenericRAT -Name "RealVNC" -ProcessPatterns @("vncserver*", "winvnc*") -ServicePatterns @("vncserver", "RealVNC*")
        }
        "TightVNC" {
            $Result = Remove-GenericRAT -Name "TightVNC" -ProcessPatterns @("tvnserver*") -ServicePatterns @("tvnserver", "TightVNC*")
        }
        "UltraVNC" {
            $Result = Remove-GenericRAT -Name "UltraVNC" -ProcessPatterns @("winvnc*", "ultravnc*") -ServicePatterns @("uvnc*", "UltraVNC*")
        }
        "DWService" {
            $Result = Remove-GenericRAT -Name "DWService" -ProcessPatterns @("dwagent*", "dwagsvc*") -ServicePatterns @("dwagent*", "DWAgent*")
        }
        "Supremo" {
            $Result = Remove-GenericRAT -Name "Supremo" -ProcessPatterns @("Supremo*") -ServicePatterns @("Supremo*")
        }
        "Ammyy Admin" {
            $Result = Remove-GenericRAT -Name "Ammyy" -ProcessPatterns @("AA_v*", "Ammyy*") -ServicePatterns @("Ammyy*")
        }
        "Remote Utilities" {
            $Result = Remove-GenericRAT -Name "Remote Utilities" -ProcessPatterns @("rutserv*", "rfusclient*") -ServicePatterns @("rutserv*")
        }
        "Radmin" {
            $Result = Remove-GenericRAT -Name "Radmin" -ProcessPatterns @("radmin*", "rserver*") -ServicePatterns @("radmin*", "rserver*")
        }
        default {
            $Result = Remove-GenericRAT -Name $ToolName -ProcessPatterns @("$ToolName*") -ServicePatterns @("$ToolName*")
        }
    }

    return $Result
}

function Remove-AnyDesk {
    $Result = @{ Success = $false; Message = "" }

    Write-LevelLog "=== AnyDesk Comprehensive Removal ===" -Level "INFO"

    # Phase 1: Stop processes and services
    Get-Process -Name "AnyDesk*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    Get-Service -Name "AnyDesk*" -ErrorAction SilentlyContinue | ForEach-Object {
        Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue
        Set-Service -Name $_.Name -StartupType Disabled -ErrorAction SilentlyContinue
    }

    # Phase 2: Registry uninstall string parsing
    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($regPath in $regPaths) {
        $entries = Get-ItemProperty $regPath -ErrorAction SilentlyContinue |
                   Where-Object { $_.DisplayName -like "*AnyDesk*" }

        foreach ($entry in $entries) {
            $uninstallString = $entry.UninstallString
            if ($uninstallString) {
                Write-LevelLog "Found uninstaller: $uninstallString"
                if ($uninstallString -match '^"(.+)"(.*)$') {
                    $exe = $Matches[1]
                    $uninstallArgs = $Matches[2].Trim()
                }
                elseif ($uninstallString -match '^(.+\.exe)(.*)$') {
                    $exe = $Matches[1]
                    $uninstallArgs = $Matches[2].Trim()
                }
                else {
                    $exe = $uninstallString
                    $uninstallArgs = ""
                }
                if ($uninstallArgs -notmatch '/S|--silent|--remove') {
                    $uninstallArgs = "$uninstallArgs --remove --silent"
                }
                try {
                    Start-Process -FilePath $exe -ArgumentList $uninstallArgs -Wait -PassThru -ErrorAction Stop | Out-Null
                    Start-Sleep -Seconds 3
                } catch {
                    Write-LevelLog "Uninstall failed: $($_.Exception.Message)" -Level "WARN"
                }
            }
        }
    }

    # Phase 2b: Direct uninstaller
    $anyDeskPaths = @(
        "$env:ProgramFiles\AnyDesk\AnyDesk.exe",
        "${env:ProgramFiles(x86)}\AnyDesk\AnyDesk.exe",
        "$env:LOCALAPPDATA\AnyDesk\AnyDesk.exe"
    )
    foreach ($adPath in $anyDeskPaths) {
        if (Test-Path $adPath) {
            try {
                Start-Process -FilePath $adPath -ArgumentList "--remove --silent" -Wait -PassThru -ErrorAction Stop | Out-Null
                Start-Sleep -Seconds 3
            } catch {
                Write-LevelLog "Direct uninstall failed: $($_.Exception.Message)" -Level "WARN"
            }
        }
    }

    # Phase 3: Force remove files (including all user profiles)
    $paths = @(
        "$env:ProgramFiles\AnyDesk",
        "${env:ProgramFiles(x86)}\AnyDesk",
        "$env:LOCALAPPDATA\AnyDesk",
        "$env:ProgramData\AnyDesk",
        "$env:APPDATA\AnyDesk",
        "$env:TEMP\AnyDesk*",
        "$env:PUBLIC\Desktop\AnyDesk*.lnk",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\AnyDesk*.lnk"
    )
    foreach ($path in $paths) {
        Get-Item -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
            Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # All user profiles
    Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        @(
            "$($_.FullName)\AppData\Local\AnyDesk",
            "$($_.FullName)\AppData\Roaming\AnyDesk",
            "$($_.FullName)\Desktop\AnyDesk*.lnk",
            "$($_.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\AnyDesk*.lnk"
        ) | ForEach-Object {
            Get-Item -Path $_ -ErrorAction SilentlyContinue | ForEach-Object {
                Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # Phase 4: Registry cleanup
    $anyDeskKeys = @(
        "HKLM:\SOFTWARE\AnyDesk",
        "HKLM:\SOFTWARE\WOW6432Node\AnyDesk",
        "HKCU:\SOFTWARE\AnyDesk",
        "HKLM:\SYSTEM\CurrentControlSet\Services\AnyDesk"
    )
    foreach ($key in $anyDeskKeys) {
        if (Test-Path $key) {
            Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # Clean uninstall entries
    foreach ($regPath in @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")) {
        Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue | ForEach-Object {
            $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
            if ($props.DisplayName -like "*AnyDesk*") {
                Remove-Item -Path $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # Clean Run keys
    foreach ($runKey in @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")) {
        $props = Get-ItemProperty -Path $runKey -ErrorAction SilentlyContinue
        if ($props) {
            $props.PSObject.Properties | Where-Object { $_.Value -like "*AnyDesk*" } | ForEach-Object {
                Remove-ItemProperty -Path $runKey -Name $_.Name -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # Delete services
    Get-Service -Name "AnyDesk*" -ErrorAction SilentlyContinue | ForEach-Object {
        & sc.exe delete $_.Name 2>$null
    }

    # Phase 5: Firewall rules and scheduled tasks
    Get-NetFirewallRule -DisplayName "*AnyDesk*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Get-ScheduledTask -TaskName "*AnyDesk*" -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue

    # Verification
    Start-Sleep -Seconds 3
    $StillPresent = (Get-Process -Name "AnyDesk*" -ErrorAction SilentlyContinue) -or (Get-Service -Name "AnyDesk*" -ErrorAction SilentlyContinue)
    if (-not $StillPresent) {
        $Result.Success = $true
        $Result.Message = "AnyDesk removed successfully"
    } else {
        $remaining = @()
        $procs = Get-Process -Name "AnyDesk*" -ErrorAction SilentlyContinue
        if ($procs) { $remaining += "Processes: $($procs.Name -join ', ')" }
        $svcs = Get-Service -Name "AnyDesk*" -ErrorAction SilentlyContinue
        if ($svcs) { $remaining += "Services: $($svcs.Name -join ', ')" }
        $Result.Message = "AnyDesk removal incomplete - $($remaining -join '; ')"
    }

    return $Result
}

function Remove-TeamViewer {
    $Result = @{ Success = $false; Message = "" }

    Write-LevelLog "=== TeamViewer Comprehensive Removal ===" -Level "INFO"

    # Phase 1: Stop services (versioned) and processes
    $tvServices = @("TeamViewer", "TeamViewer7", "TeamViewer8", "TeamViewer9", "TeamViewer10", "TeamViewer11", "TeamViewer12", "TeamViewer13", "TeamViewer14", "TeamViewer15")
    foreach ($svcName in $tvServices) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
            Set-Service -Name $svcName -StartupType Disabled -ErrorAction SilentlyContinue
        }
    }

    $tvProcesses = @("TeamViewer", "TeamViewer_Service", "tv_w32", "tv_x64", "TeamViewer_Desktop", "TeamViewer_Note")
    foreach ($proc in $tvProcesses) {
        Get-Process -Name $proc -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 2

    # Phase 2: Winget uninstall
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        & winget uninstall --id "TeamViewer.TeamViewer" --silent --force 2>$null
        & winget uninstall --id "TeamViewer.TeamViewer.Host" --silent --force 2>$null
        & winget uninstall --name "TeamViewer" --silent --force 2>$null
    }

    # Phase 3: MSI uninstall from registry
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    foreach ($path in $uninstallPaths) {
        if (Test-Path $path) {
            Get-ChildItem -Path $path | ForEach-Object {
                $displayName = (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue).DisplayName
                if ($displayName -like "*TeamViewer*") {
                    $uninstallString = (Get-ItemProperty -Path $_.PSPath).UninstallString
                    $quietUninstall = (Get-ItemProperty -Path $_.PSPath).QuietUninstallString
                    if ($quietUninstall) {
                        cmd /c $quietUninstall 2>$null
                    } elseif ($uninstallString) {
                        if ($uninstallString -match "msiexec") {
                            $uninstallString = $uninstallString -replace "/I", "/X"
                            cmd /c "$uninstallString /qn /norestart" 2>$null
                        } elseif ($uninstallString -match "uninstall.exe") {
                            cmd /c "`"$uninstallString`" /S" 2>$null
                        }
                    }
                }
            }
        }
    }
    Start-Sleep -Seconds 5

    # Phase 4: Direct uninstaller execution
    $tvFolders = @(
        Get-ChildItem "${env:ProgramFiles}" -Filter "TeamViewer*" -Directory -ErrorAction SilentlyContinue
        Get-ChildItem "${env:ProgramFiles(x86)}" -Filter "TeamViewer*" -Directory -ErrorAction SilentlyContinue
    )
    foreach ($folder in $tvFolders) {
        $uninstaller = Join-Path $folder.FullName "uninstall.exe"
        if (Test-Path $uninstaller) {
            Start-Process -FilePath $uninstaller -ArgumentList "/S" -Wait -ErrorAction SilentlyContinue
        }
    }
    Start-Sleep -Seconds 3

    # Phase 5: Cleanup files
    $foldersToRemove = @(
        "${env:ProgramFiles}\TeamViewer",
        "${env:ProgramFiles(x86)}\TeamViewer",
        "${env:ProgramData}\TeamViewer",
        "${env:LOCALAPPDATA}\TeamViewer",
        "${env:APPDATA}\TeamViewer",
        "C:\Users\Public\Desktop\TeamViewer.lnk"
    )
    foreach ($folder in $tvFolders) {
        $foldersToRemove += $folder.FullName
    }

    Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $foldersToRemove += "$($_.FullName)\AppData\Local\TeamViewer"
        $foldersToRemove += "$($_.FullName)\AppData\Roaming\TeamViewer"
        $foldersToRemove += "$($_.FullName)\Desktop\TeamViewer*.lnk"
    }
    foreach ($folder in $foldersToRemove) {
        if (Test-Path $folder) {
            Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # Phase 6: Registry cleanup
    $registryPaths = @(
        "HKLM:\SOFTWARE\TeamViewer",
        "HKLM:\SOFTWARE\WOW6432Node\TeamViewer",
        "HKCU:\SOFTWARE\TeamViewer",
        "HKLM:\SOFTWARE\TeamViewer GmbH",
        "HKLM:\SOFTWARE\WOW6432Node\TeamViewer GmbH"
    )
    foreach ($regPath in $registryPaths) {
        if (Test-Path $regPath) {
            Remove-Item -Path $regPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # Run keys
    foreach ($runKey in @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")) {
        if (Test-Path $runKey) {
            $props = Get-ItemProperty -Path $runKey -ErrorAction SilentlyContinue
            if ($props) {
                $props.PSObject.Properties | Where-Object { $_.Name -like "*TeamViewer*" } | ForEach-Object {
                    Remove-ItemProperty -Path $runKey -Name $_.Name -ErrorAction SilentlyContinue
                }
            }
        }
    }

    # Clean uninstall entries
    foreach ($path in $uninstallPaths) {
        Get-ChildItem -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
            $displayName = (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue).DisplayName
            if ($displayName -like "*TeamViewer*") {
                Remove-Item -Path $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # Delete services, firewall, tasks
    Get-NetFirewallRule -DisplayName "*TeamViewer*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    foreach ($svcName in $tvServices) {
        if (Get-Service -Name $svcName -ErrorAction SilentlyContinue) {
            & sc.exe delete $svcName 2>$null
        }
    }
    Get-ScheduledTask -TaskName "*TeamViewer*" -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue

    # Remove printers and drivers
    Get-Printer -Name "*TeamViewer*" -ErrorAction SilentlyContinue | Remove-Printer -ErrorAction SilentlyContinue
    Get-PrinterDriver -Name "*TeamViewer*" -ErrorAction SilentlyContinue | Remove-PrinterDriver -ErrorAction SilentlyContinue

    # Verification
    $remainingInstalls = @()
    foreach ($path in $uninstallPaths) {
        Get-ChildItem -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
            $displayName = (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue).DisplayName
            if ($displayName -like "*TeamViewer*") {
                $remainingInstalls += $displayName
            }
        }
    }

    if ($remainingInstalls.Count -eq 0) {
        $Result.Success = $true
        $Result.Message = "TeamViewer removed successfully"
    } else {
        $Result.Message = "TeamViewer removal incomplete - remaining: $($remainingInstalls -join ', ')"
    }

    return $Result
}

function Remove-RustDesk {
    $Result = @{ Success = $false; Message = "" }

    Write-LevelLog "=== RustDesk Comprehensive Removal ===" -Level "INFO"

    # Stop services and processes
    @("RustDesk", "rustdesk", "rustdesk_service") | ForEach-Object {
        $svc = Get-Service -Name $_ -ErrorAction SilentlyContinue
        if ($svc) {
            Stop-Service -Name $_ -Force -ErrorAction SilentlyContinue
            Set-Service -Name $_ -StartupType Disabled -ErrorAction SilentlyContinue
        }
    }
    @("rustdesk", "rustdesk_service") | ForEach-Object {
        Get-Process -Name $_ -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 2

    # Registry-based uninstall
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    foreach ($path in $uninstallPaths) {
        if (Test-Path $path) {
            Get-ChildItem -Path $path | ForEach-Object {
                $displayName = (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue).DisplayName
                $uninstallString = (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue).UninstallString
                $quietUninstall = (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue).QuietUninstallString
                if ($displayName -like "*RustDesk*") {
                    if ($quietUninstall) {
                        cmd /c $quietUninstall 2>&1 | Out-Null
                    } elseif ($uninstallString) {
                        if ($uninstallString -match "msiexec") {
                            $uninstallString = $uninstallString -replace "/I", "/X"
                            cmd /c "$uninstallString /qn /norestart" 2>&1 | Out-Null
                        } else {
                            cmd /c "$uninstallString --silent" 2>&1 | Out-Null
                        }
                    }
                }
            }
        }
    }
    Start-Sleep -Seconds 3

    # Direct uninstaller
    @("$env:ProgramFiles\RustDesk\rustdesk.exe", "${env:ProgramFiles(x86)}\RustDesk\rustdesk.exe") | ForEach-Object {
        if (Test-Path $_) {
            Start-Process -FilePath $_ -ArgumentList "--uninstall" -Wait -ErrorAction SilentlyContinue
        }
    }

    # Delete services
    @("RustDesk", "rustdesk", "rustdesk_service") | ForEach-Object {
        if (Get-Service -Name $_ -ErrorAction SilentlyContinue) {
            & sc.exe delete $_ 2>&1 | Out-Null
        }
    }

    # Remove directories (including user profiles and .rustdesk)
    $directories = @(
        "$env:ProgramFiles\RustDesk",
        "${env:ProgramFiles(x86)}\RustDesk",
        "$env:LOCALAPPDATA\RustDesk",
        "$env:APPDATA\RustDesk",
        "$env:ProgramData\RustDesk",
        "$env:PUBLIC\Documents\RustDesk"
    )
    Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $directories += "$($_.FullName)\AppData\Local\RustDesk"
        $directories += "$($_.FullName)\AppData\Roaming\RustDesk"
        $directories += "$($_.FullName)\.rustdesk"
    }
    foreach ($dir in $directories) {
        if (Test-Path $dir) {
            Remove-Item -Path $dir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # Registry cleanup
    @("HKLM:\SOFTWARE\RustDesk", "HKLM:\SOFTWARE\WOW6432Node\RustDesk", "HKCU:\SOFTWARE\RustDesk") | ForEach-Object {
        if (Test-Path $_) { Remove-Item -Path $_ -Recurse -Force -ErrorAction SilentlyContinue }
    }

    # Clean uninstall entries
    foreach ($path in $uninstallPaths) {
        Get-ChildItem -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
            $displayName = (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue).DisplayName
            if ($displayName -like "*RustDesk*") {
                Remove-Item -Path $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # Firewall, tasks, shortcuts
    Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*RustDesk*" } | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like "*RustDesk*" } | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue

    $shortcutLocations = @("$env:PUBLIC\Desktop\RustDesk*.lnk", "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\RustDesk*.lnk")
    Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $shortcutLocations += "$($_.FullName)\Desktop\RustDesk*.lnk"
        $shortcutLocations += "$($_.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\RustDesk*.lnk"
    }
    foreach ($shortcut in $shortcutLocations) {
        Get-Item -Path $shortcut -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    }

    # Verification
    $remainingItems = @()
    @("RustDesk", "rustdesk") | ForEach-Object {
        if (Get-Service -Name $_ -ErrorAction SilentlyContinue) { $remainingItems += "Service: $_" }
    }
    @("rustdesk", "rustdesk_service") | ForEach-Object {
        if (Get-Process -Name $_ -ErrorAction SilentlyContinue) { $remainingItems += "Process: $_" }
    }
    @("$env:ProgramFiles\RustDesk", "${env:ProgramFiles(x86)}\RustDesk") | ForEach-Object {
        if (Test-Path $_) { $remainingItems += "Directory: $_" }
    }

    if ($remainingItems.Count -eq 0) {
        $Result.Success = $true
        $Result.Message = "RustDesk removed successfully"
    } else {
        $Result.Message = "RustDesk removal incomplete - $($remainingItems -join '; ')"
    }

    return $Result
}

function Remove-Meshcentral {
    $Result = @{ Success = $false; Message = "" }

    Get-Process -Name "MeshAgent*", "meshagent*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    $Services = Get-Service -Name "Mesh Agent*", "MeshAgent*" -ErrorAction SilentlyContinue
    foreach ($Service in $Services) {
        Stop-Service -Name $Service.Name -Force -ErrorAction SilentlyContinue
        & sc.exe delete $Service.Name 2>$null
    }

    $UninstallPaths = @(
        "$env:ProgramFiles\Mesh Agent\MeshAgent.exe",
        "${env:ProgramFiles(x86)}\Mesh Agent\MeshAgent.exe"
    )
    foreach ($Path in $UninstallPaths) {
        if (Test-Path $Path) {
            Start-Process $Path -ArgumentList "-uninstall" -Wait -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
        }
    }

    $RemovePaths = @(
        "$env:ProgramFiles\Mesh Agent",
        "${env:ProgramFiles(x86)}\Mesh Agent",
        "$env:ProgramData\Mesh Agent"
    )
    foreach ($Path in $RemovePaths) {
        if (Test-Path $Path) {
            Remove-Item $Path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    $StillPresent = Get-Process -Name "MeshAgent*", "meshagent*" -ErrorAction SilentlyContinue
    if (-not $StillPresent) {
        $Result.Success = $true
        $Result.Message = "Meshcentral agent removed successfully"
    } else {
        $Result.Message = "Meshcentral removal incomplete"
    }

    return $Result
}

function Remove-Splashtop {
    $Result = @{ Success = $false; Message = "" }

    Write-LevelLog "=== Splashtop Comprehensive Removal ===" -Level "INFO"

    # Stop services and processes
    @("SplashtopRemoteService", "SSUService") | ForEach-Object {
        $svc = Get-Service -Name $_ -ErrorAction SilentlyContinue
        if ($svc) {
            Stop-Service -Name $_ -Force -ErrorAction SilentlyContinue
            Set-Service -Name $_ -StartupType Disabled -ErrorAction SilentlyContinue
        }
    }
    @("SRManager", "SRService", "SRFeature", "SRAgent", "strwinclt", "SplashtopStreamer") | ForEach-Object {
        Get-Process -Name $_ -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 2

    # Winget
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        & winget uninstall --id "Splashtop.SplashtopStreamer" --silent --force 2>$null
        & winget uninstall --name "Splashtop Streamer" --silent --force 2>$null
    }

    # MSI uninstall from registry
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    foreach ($path in $uninstallPaths) {
        if (Test-Path $path) {
            Get-ChildItem -Path $path | ForEach-Object {
                $displayName = (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue).DisplayName
                if ($displayName -like "*Splashtop*Streamer*" -or $displayName -like "*Splashtop*Remote*") {
                    $uninstallString = (Get-ItemProperty -Path $_.PSPath).UninstallString
                    $quietUninstall = (Get-ItemProperty -Path $_.PSPath).QuietUninstallString
                    if ($quietUninstall) {
                        cmd /c $quietUninstall 2>$null
                    } elseif ($uninstallString) {
                        if ($uninstallString -match "msiexec") {
                            $uninstallString = $uninstallString -replace "/I", "/X"
                            cmd /c "$uninstallString /qn /norestart" 2>$null
                        } elseif ($uninstallString -notmatch "/S|/silent|/quiet") {
                            cmd /c "`"$uninstallString`" /S" 2>$null
                        } else {
                            cmd /c $uninstallString 2>$null
                        }
                    }
                }
            }
        }
    }
    Start-Sleep -Seconds 5

    # Direct uninstallers
    @(
        "${env:ProgramFiles}\Splashtop\Splashtop Remote\Server\uninst.exe",
        "${env:ProgramFiles(x86)}\Splashtop\Splashtop Remote\Server\uninst.exe",
        "${env:ProgramFiles}\Splashtop\Splashtop Streamer\uninst.exe",
        "${env:ProgramFiles(x86)}\Splashtop\Splashtop Streamer\uninst.exe"
    ) | ForEach-Object {
        if (Test-Path $_) {
            Start-Process -FilePath $_ -ArgumentList "/S" -Wait -ErrorAction SilentlyContinue
        }
    }
    Start-Sleep -Seconds 3

    # Remove directories
    @(
        "${env:ProgramFiles}\Splashtop",
        "${env:ProgramFiles(x86)}\Splashtop",
        "${env:ProgramData}\Splashtop",
        "${env:LOCALAPPDATA}\Splashtop",
        "${env:APPDATA}\Splashtop"
    ) | ForEach-Object {
        if (Test-Path $_) { Remove-Item -Path $_ -Recurse -Force -ErrorAction SilentlyContinue }
    }

    # Registry cleanup
    @("HKLM:\SOFTWARE\Splashtop", "HKLM:\SOFTWARE\WOW6432Node\Splashtop", "HKCU:\SOFTWARE\Splashtop") | ForEach-Object {
        if (Test-Path $_) { Remove-Item -Path $_ -Recurse -Force -ErrorAction SilentlyContinue }
    }

    # Delete services
    @("SplashtopRemoteService", "SSUService") | ForEach-Object {
        if (Get-Service -Name $_ -ErrorAction SilentlyContinue) {
            & sc.exe delete $_ 2>$null
        }
    }

    # Firewall and tasks
    Get-NetFirewallRule -DisplayName "*Splashtop*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Get-ScheduledTask -TaskName "*Splashtop*" -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue

    # Verification
    $remainingInstalls = @()
    foreach ($path in $uninstallPaths) {
        if (Test-Path $path) {
            Get-ChildItem -Path $path | ForEach-Object {
                $displayName = (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue).DisplayName
                if ($displayName -like "*Splashtop*") {
                    $remainingInstalls += $displayName
                }
            }
        }
    }

    if ($remainingInstalls.Count -eq 0) {
        $Result.Success = $true
        $Result.Message = "Splashtop removed successfully"
    } else {
        $Result.Message = "Splashtop removal incomplete - remaining: $($remainingInstalls -join ', ')"
    }

    return $Result
}

function Remove-ChromeRemoteDesktop {
    $Result = @{ Success = $false; Message = "" }

    Write-LevelLog "=== Chrome Remote Desktop Removal ===" -Level "INFO"

    # Stop services
    @("chromoting", "Chrome Remote Desktop*") | ForEach-Object {
        Get-Service -Name $_ -ErrorAction SilentlyContinue | ForEach-Object {
            Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue
            & sc.exe delete $_.Name 2>$null
        }
    }
    Get-Process -Name "remoting_host*", "chromoting*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    # CIM uninstall
    Get-CimInstance -ClassName Win32_Product -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "*Chrome Remote Desktop*" } | ForEach-Object {
        Write-LevelLog "Uninstalling CIM: $($_.Name)"
        $_ | Invoke-CimMethod -MethodName Uninstall -ErrorAction SilentlyContinue | Out-Null
    }

    # Remove directories
    @(
        "$env:ProgramFiles\Google\Chrome Remote Desktop",
        "${env:ProgramFiles(x86)}\Google\Chrome Remote Desktop",
        "$env:LOCALAPPDATA\Google\Chrome Remote Desktop",
        "$env:ProgramData\Google\Chrome Remote Desktop"
    ) | ForEach-Object {
        if (Test-Path $_) { Remove-Item -Path $_ -Recurse -Force -ErrorAction SilentlyContinue }
    }

    # Registry cleanup
    @("HKLM:\SOFTWARE\Google\Chrome Remote Desktop", "HKCU:\SOFTWARE\Google\Chrome Remote Desktop") | ForEach-Object {
        if (Test-Path $_) { Remove-Item -Path $_ -Recurse -Force -ErrorAction SilentlyContinue }
    }

    $StillPresent = Get-Process -Name "remoting_host*", "chromoting*" -ErrorAction SilentlyContinue
    if (-not $StillPresent) {
        $Result.Success = $true
        $Result.Message = "Chrome Remote Desktop removed successfully"
    } else {
        $Result.Message = "Chrome Remote Desktop removal incomplete"
    }

    return $Result
}

function Get-SoftwareUninstallString {
    param(
        [string]$SoftwareName,
        [switch]$Quiet
    )

    $RegistryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($Path in $RegistryPaths) {
        $Software = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like "*$SoftwareName*" }
        if ($Software) {
            if ($Software.UninstallString) {
                return $Software.UninstallString
            }
            if ($Software.QuietUninstallString) {
                return $Software.QuietUninstallString
            }
        }
    }

    if (-not $Quiet) {
        Write-LevelLog "No uninstall string found for $SoftwareName" -Level "DEBUG"
    }
    return $null
}

function Remove-GenericRAT {
    param(
        [string]$Name,
        [string[]]$ProcessPatterns,
        [string[]]$ServicePatterns
    )

    $Result = @{ Success = $false; Message = "" }

    foreach ($Pattern in $ProcessPatterns) {
        Get-Process -Name $Pattern -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 2

    foreach ($Pattern in $ServicePatterns) {
        $Services = Get-Service -Name $Pattern -ErrorAction SilentlyContinue
        foreach ($Service in $Services) {
            Stop-Service -Name $Service.Name -Force -ErrorAction SilentlyContinue
            & sc.exe delete $Service.Name 2>$null
        }
    }

    $UninstallString = Get-SoftwareUninstallString -SoftwareName $Name -Quiet
    if ($UninstallString) {
        Write-LevelLog "Running $Name uninstaller..."
        if ($UninstallString -match 'msiexec') {
            if ($UninstallString -match '\{[A-Fa-f0-9\-]+\}') {
                $ProductCode = $matches[0]
                Start-Process msiexec.exe -ArgumentList "/x $ProductCode /qn /norestart" -Wait -ErrorAction SilentlyContinue
            }
        } else {
            Start-Process cmd.exe -ArgumentList "/c `"$UninstallString`" /S /silent /quiet" -Wait -ErrorAction SilentlyContinue
        }
        Start-Sleep -Seconds 3
    }

    $CommonPaths = @(
        "$env:ProgramFiles\$Name",
        "${env:ProgramFiles(x86)}\$Name",
        "$env:APPDATA\$Name",
        "$env:ProgramData\$Name",
        "$env:LOCALAPPDATA\$Name"
    )
    foreach ($Path in $CommonPaths) {
        if (Test-Path $Path) {
            Remove-Item $Path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    $StillRunning = $false
    foreach ($Pattern in $ProcessPatterns) {
        if (Get-Process -Name $Pattern -ErrorAction SilentlyContinue) {
            $StillRunning = $true
            break
        }
    }

    if (-not $StillRunning) {
        $Result.Success = $true
        $Result.Message = "$Name removed successfully"
    } else {
        $Result.Message = "$Name removal incomplete - some processes still running"
    }

    return $Result
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

    # Log whitelisting settings
    if ($IsScreenConnectServer -eq "true") {
        Write-LevelLog "This device is marked as a ScreenConnect Server - ScreenConnect excluded" -Level "INFO"
    }
    if ($MeshcentralServerUrl -and $MeshcentralServerUrl -ne "" -and $MeshcentralServerUrl -notlike "{{*}}") {
        Write-LevelLog "Meshcentral whitelist URL: $MeshcentralServerUrl" -Level "INFO"
    }
    if ($WhitelistedRats.Count -gt 0) {
        Write-LevelLog "policy_ok_rats whitelist: $($WhitelistedRats -join ', ')" -Level "INFO"
    }
    if ($EnableAutoRemove) {
        Write-LevelLog "Auto-remove mode ENABLED - will attempt to remove detected RATs" -Level "WARN"
    }

    # Scan for each tool
    foreach ($Tool in $RemoteAccessTools) {

        # Skip authorized RMM tools
        if ($Tool.Name -in $AuthorizedRMMTools) {
            Write-LevelLog "$($Tool.Name) is in authorized list - skipping" -Level "DEBUG"
            continue
        }

        # Skip tools whitelisted via policy_ok_rats
        if ($Tool.Name -in $WhitelistedRats) {
            Write-LevelLog "$($Tool.Name) is in policy_ok_rats whitelist - skipping" -Level "INFO"
            continue
        }

        # Handle ScreenConnect whitelisting
        if ($Tool.Name -eq "ScreenConnect") {
            if ($IsScreenConnectServer -eq "true") {
                continue
            }
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

        # Handle Meshcentral whitelisting
        if ($Tool.Name -eq "Meshcentral") {
            if ($MeshcentralServerUrl -and $MeshcentralServerUrl -ne "" -and $MeshcentralServerUrl -notlike "{{*}}") {
                $DetectedMeshUrl = Get-MeshcentralServerUrl
                if ($DetectedMeshUrl) {
                    $WhitelistUrl = $MeshcentralServerUrl -replace '^https?://', '' -replace '/$', ''
                    $DetectedUrl = $DetectedMeshUrl -replace '^https?://', '' -replace '/$', ''
                    if ($DetectedUrl -like "*$WhitelistUrl*" -or $WhitelistUrl -like "*$DetectedUrl*") {
                        Write-LevelLog "Meshcentral server '$DetectedMeshUrl' matches whitelist '$MeshcentralServerUrl' - skipping" -Level "INFO"
                        continue
                    }
                    else {
                        Write-LevelLog "Meshcentral server '$DetectedMeshUrl' does NOT match whitelist '$MeshcentralServerUrl'" -Level "WARN"
                    }
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

    # ============================================================
    # POPULATE policy_ok_rats ON FIRST RUN
    # ============================================================
    # If policy_ok_rats is empty and we detected tools, populate it with the
    # current baseline so sanctioned tools get whitelisted automatically.
    if ($WhitelistedRats.Count -eq 0 -and $DetectedTools.Count -gt 0 -and $LevelApiKey) {
        $BaselineNames = ($DetectedTools | ForEach-Object { $_.Name }) -join ", "
        Write-LevelLog "First run - populating policy_ok_rats baseline: $BaselineNames" -Level "INFO"

        $Device = Find-LevelDevice -ApiKey $LevelApiKey -Hostname $DeviceHostname
        if ($Device) {
            $SetResult = Set-LevelCustomFieldValue -ApiKey $LevelApiKey -EntityType "device" -EntityId $Device.id -FieldReference "policy_ok_rats" -Value $BaselineNames
            if ($SetResult) {
                Write-LevelLog "Set policy_ok_rats = '$BaselineNames'" -Level "SUCCESS"
                Write-Host ""
                Write-Host "BASELINE SET: policy_ok_rats populated with $($DetectedTools.Count) tool(s)"
                Write-Host "  Tools: $BaselineNames"
                Write-Host "  These tools will be whitelisted on future runs."
                Write-Host "  Edit policy_ok_rats in Level.io to adjust the whitelist."
                Write-Host ""
                # All detected tools are now whitelisted - exit clean on this first run
                exit 0
            }
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

        # Auto-removal if enabled
        if ($EnableAutoRemove) {
            Write-Host ""
            Write-LevelLog "========================================" -Level "WARN"
            Write-LevelLog "AUTO-REMOVE MODE - Attempting Removal" -Level "WARN"
            Write-LevelLog "========================================" -Level "WARN"
            Write-Host ""

            $RemovalResults = @()
            foreach ($Detection in $DetectedTools) {
                Write-LevelLog "Removing $($Detection.Name)..." -Level "INFO"
                $RemovalResult = Remove-RATool -ToolName $Detection.Name
                $RemovalResults += @{
                    Name = $Detection.Name
                    Success = $RemovalResult.Success
                    Message = $RemovalResult.Message
                }

                if ($RemovalResult.Success) {
                    Write-LevelLog "  SUCCESS: $($RemovalResult.Message)" -Level "SUCCESS"
                } else {
                    Write-LevelLog "  FAILED: $($RemovalResult.Message)" -Level "ERROR"
                }
            }

            # Summary
            Write-Host ""
            Write-LevelLog "========================================" -Level "INFO"
            Write-LevelLog "REMOVAL SUMMARY" -Level "INFO"
            Write-LevelLog "========================================" -Level "INFO"

            $SuccessCount = ($RemovalResults | Where-Object { $_.Success }).Count
            $FailCount = ($RemovalResults | Where-Object { -not $_.Success }).Count

            Write-LevelLog "Successfully removed: $SuccessCount" -Level $(if ($SuccessCount -gt 0) { "SUCCESS" } else { "INFO" })
            Write-LevelLog "Failed to remove: $FailCount" -Level $(if ($FailCount -gt 0) { "ERROR" } else { "INFO" })

            if ($FailCount -gt 0) {
                Write-Host ""
                Write-LevelLog "Failed removals require manual intervention:" -Level "WARN"
                foreach ($Result in ($RemovalResults | Where-Object { -not $_.Success })) {
                    Write-Host "  - $($Result.Name): $($Result.Message)"
                }
            }

            Complete-LevelScript -ExitCode 1 -Message "Detected $($DetectedTools.Count) RAT(s). Removed: $SuccessCount, Failed: $FailCount"
        }
        else {
            Write-LevelLog "ACTION REQUIRED: Review and remediate detected tools" -Level "WARN"
            Write-LevelLog "TIP: Set AutoRemoveRATs=true to enable automatic removal" -Level "INFO"
            Complete-LevelScript -ExitCode 1 -Message "Detected $($DetectedTools.Count) unauthorized remote access tool(s)"
        }
    }
}
