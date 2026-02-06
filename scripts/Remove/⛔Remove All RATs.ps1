<#
.SYNOPSIS
    Detects and removes unauthorized remote access tools (RATs) from the system.

.DESCRIPTION
    This script scans for and removes 70+ known remote access tools including:
    - Commercial tools: AnyDesk, TeamViewer, RustDesk, Splashtop, LogMeIn, etc.
    - VNC variants: RealVNC, TightVNC, UltraVNC, TigerVNC
    - RMM tools: Action1, Atera, Datto, NinjaRMM, Kaseya, etc.
    - Known malicious RATs: Remcos, QuasarRAT, AsyncRAT, njRAT, etc.

    WHITELISTED (never removed):
    - Level.io (authorized RMM)
    - ScreenConnect (use dedicated removal script)

    Removal phases for each detected RAT:
    1. Stop services and processes
    2. Run uninstallers (registry-based, silent)
    3. Delete services
    4. Remove files and folders
    5. Clean registry entries
    6. Remove firewall rules and scheduled tasks

.NOTES
    Version:          2026.02.06.01
    Target Platform:  Level.io RMM (via Script Launcher)
    Exit Codes:       0 = Success | 1 = Alert (RATs detected or removal failed)

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# U+26D4 No Entry - Remove All RATs
# Version: 2026.02.06.01
# Target: Level.io (via Script Launcher)
# Exit 0 = Success | Exit 1 = Alert
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge

# ============================================================
# INITIALIZE
# ============================================================
$Init = Initialize-LevelScript -ScriptName "RemoveAllRATs" `
                               -MspScratchFolder $MspScratchFolder `
                               -DeviceHostname $DeviceHostname `
                               -DeviceTags $DeviceTags `
                               -BlockingTags @("❌")

if (-not $Init.Success) {
    exit 0
}

# ============================================================
# RAT DEFINITIONS
# ============================================================
$Script:RATDefinitions = @(
    # Common Remote Access Tools
    @{ Name = "AnyDesk"; Processes = @("AnyDesk*"); Services = @("AnyDesk*"); Paths = @("AnyDesk"); Priority = "High" }
    @{ Name = "TeamViewer"; Processes = @("TeamViewer*", "tv_w32*", "tv_x64*"); Services = @("TeamViewer*"); Paths = @("TeamViewer"); Priority = "High" }
    @{ Name = "RustDesk"; Processes = @("rustdesk*"); Services = @("rustdesk*", "RustDesk*"); Paths = @("RustDesk"); Priority = "High" }
    @{ Name = "Splashtop"; Processes = @("SplashtopStreamer*", "Splashtop*", "strwinclt*", "SRManager*", "SRService*"); Services = @("Splashtop*", "SSUService*"); Paths = @("Splashtop"); Priority = "High" }
    @{ Name = "LogMeIn"; Processes = @("LogMeIn*", "LMI*"); Services = @("LogMeIn*", "LMI*"); Paths = @("LogMeIn"); Priority = "High" }
    @{ Name = "GoToAssist"; Processes = @("GoTo*", "g2a*"); Services = @("GoTo*", "GoToAssist*"); Paths = @("GoTo", "GoToAssist"); Priority = "Medium" }
    @{ Name = "GoToMyPC"; Processes = @("GoToMyPC*", "g2mpc*"); Services = @("GoToMyPC*"); Paths = @("GoToMyPC"); Priority = "Medium" }
    @{ Name = "RemotePC"; Processes = @("RemotePC*", "RPCService*"); Services = @("RemotePC*"); Paths = @("RemotePC"); Priority = "Medium" }
    @{ Name = "BeyondTrust"; Processes = @("bomgar*", "BeyondTrust*"); Services = @("bomgar*", "BeyondTrust*"); Paths = @("Bomgar", "BeyondTrust"); Priority = "Medium" }
    @{ Name = "DWService"; Processes = @("dwagent*", "dwagsvc*"); Services = @("dwagent*", "DWAgent*"); Paths = @("DWAgent", "DWService"); Priority = "Medium" }

    # VNC Variants
    @{ Name = "RealVNC"; Processes = @("vncserver*", "vncviewer*", "winvnc*"); Services = @("vncserver", "RealVNC*"); Paths = @("RealVNC"); Priority = "Medium" }
    @{ Name = "TightVNC"; Processes = @("tvnserver*", "tvnviewer*"); Services = @("tvnserver", "TightVNC*"); Paths = @("TightVNC"); Priority = "Medium" }
    @{ Name = "UltraVNC"; Processes = @("winvnc*", "ultravnc*"); Services = @("uvnc*", "UltraVNC*"); Paths = @("UltraVNC", "uvnc"); Priority = "Medium" }
    @{ Name = "TigerVNC"; Processes = @("vncserver", "x0vncserver*"); Services = @("TigerVNC*"); Paths = @("TigerVNC"); Priority = "Medium" }

    # Other Remote Tools
    @{ Name = "Radmin"; Processes = @("radmin*", "rserver*"); Services = @("radmin*", "rserver*"); Paths = @("Radmin"); Priority = "Medium" }
    @{ Name = "Chrome Remote Desktop"; Processes = @("remoting_host*", "chromoting*"); Services = @("chromoting*", "Chrome Remote*"); Paths = @("Chrome Remote Desktop"); Priority = "Medium" }
    @{ Name = "Ammyy Admin"; Processes = @("AA_v*", "Ammyy*"); Services = @("Ammyy*"); Paths = @("Ammyy"); Priority = "Medium" }
    @{ Name = "SimpleHelp"; Processes = @("SimpleHelp*"); Services = @("SimpleHelp*"); Paths = @("SimpleHelp"); Priority = "Medium" }
    @{ Name = "Supremo"; Processes = @("Supremo*", "SupremoService*", "SupremoHelper*"); Services = @("Supremo*"); Paths = @("Supremo", "SupremoRemoteDesktop"); Priority = "Medium" }
    @{ Name = "Zoho Assist"; Processes = @("ZohoMeeting*", "ZohoAssist*", "ZA_Connect*"); Services = @("Zoho*Assist*"); Paths = @("Zoho Assist", "ZohoMeeting"); Priority = "Medium" }
    @{ Name = "ISL Online"; Processes = @("ISLLight*", "ISLAlwaysOn*"); Services = @("ISL*"); Paths = @("ISL Online", "ISLLight"); Priority = "Medium" }
    @{ Name = "Parsec"; Processes = @("parsecd*", "pservice*"); Services = @("Parsec*"); Paths = @("Parsec"); Priority = "Low" }
    @{ Name = "Meshcentral"; Processes = @("MeshAgent*", "meshagent*"); Services = @("Mesh Agent*", "MeshAgent*"); Paths = @("Mesh Agent", "MeshCentral"); Priority = "Medium" }
    @{ Name = "Fleetdeck"; Processes = @("fleetdeck*"); Services = @("fleetdeck*"); Paths = @("Fleetdeck"); Priority = "Low" }
    @{ Name = "Tactical RMM"; Processes = @("tacticalrmm*"); Services = @("tacticalrmm*"); Paths = @("TacticalAgent"); Priority = "Low" }

    # Additional Tools
    @{ Name = "UltraViewer"; Processes = @("UltraViewer*"); Services = @("UltraViewer*"); Paths = @("UltraViewer"); Priority = "Medium" }
    @{ Name = "ToDesk"; Processes = @("ToDesk*"); Services = @("ToDesk*"); Paths = @("ToDesk"); Priority = "Medium" }
    @{ Name = "Sunlogin"; Processes = @("SunloginClient*", "slservice*"); Services = @("Sunlogin*"); Paths = @("Sunlogin", "Oray\SunLogin"); Priority = "Medium" }
    @{ Name = "HopToDesk"; Processes = @("HopToDesk*"); Services = @("HopToDesk*"); Paths = @("HopToDesk"); Priority = "Medium" }
    @{ Name = "AweSun"; Processes = @("AweSun*", "AweRay*"); Services = @("AweSun*"); Paths = @("AweSun", "AweRay"); Priority = "Medium" }
    @{ Name = "Dameware"; Processes = @("DVLS*", "dwrcs*", "DameWare*"); Services = @("DameWare*", "DVLS*"); Paths = @("DameWare"); Priority = "Medium" }
    @{ Name = "NetSupport"; Processes = @("client32*", "pcictlui*"); Services = @("NetSupport*"); Paths = @("NetSupport"); Priority = "Medium" }
    @{ Name = "Remote Utilities"; Processes = @("rutserv*", "rfusclient*"); Services = @("rutserv*"); Paths = @("Remote Utilities"); Priority = "Medium" }
    @{ Name = "Getscreen.me"; Processes = @("getscreen*"); Services = @("getscreen*"); Paths = @("Getscreen"); Priority = "Low" }
    @{ Name = "Iperius Remote"; Processes = @("IperiusRemote*"); Services = @("IperiusRemote*"); Paths = @("Iperius"); Priority = "Low" }
    @{ Name = "NoMachine"; Processes = @("nxserver*", "nxnode*", "nxd*"); Services = @("nxserver*", "NoMachine*"); Paths = @("NoMachine"); Priority = "Medium" }
    @{ Name = "LiteManager"; Processes = @("ROMServer*", "ROMViewer*"); Services = @("LiteManager*", "ROMServer*"); Paths = @("LiteManager"); Priority = "Medium" }
    @{ Name = "Alpemix"; Processes = @("Alpemix*"); Services = @("Alpemix*"); Paths = @("Alpemix"); Priority = "Low" }
    @{ Name = "ShowMyPC"; Processes = @("showmypc*", "smpc*"); Services = @("ShowMyPC*"); Paths = @("ShowMyPC"); Priority = "Low" }
    @{ Name = "Aeroadmin"; Processes = @("AeroAdmin*"); Services = @("AeroAdmin*"); Paths = @("AeroAdmin"); Priority = "Low" }
    @{ Name = "FastViewer"; Processes = @("FastViewer*"); Services = @("FastViewer*"); Paths = @("FastViewer"); Priority = "Low" }
    @{ Name = "RayLink"; Processes = @("RayLink*"); Services = @("RayLink*"); Paths = @("RayLink"); Priority = "Low" }

    # Tunneling Tools
    @{ Name = "ZeroTier"; Processes = @("zerotier*"); Services = @("ZeroTier*"); Paths = @("ZeroTier"); Priority = "Low" }
    @{ Name = "Tailscale"; Processes = @("tailscale*", "tailscaled*"); Services = @("Tailscale*"); Paths = @("Tailscale"); Priority = "Low" }
    @{ Name = "Ngrok"; Processes = @("ngrok*"); Services = @("ngrok*"); Paths = @("ngrok"); Priority = "Medium" }

    # RMM Tools
    @{ Name = "Action1"; Processes = @("action1*", "a1agent*"); Services = @("action1*"); Paths = @("Action1"); Priority = "Low" }
    @{ Name = "Atera"; Processes = @("AteraAgent*"); Services = @("AteraAgent*"); Paths = @("Atera"); Priority = "Low" }
    @{ Name = "N-able Take Control"; Processes = @("BASupSrvc*", "BASupApp*"); Services = @("BASupSrvc*"); Paths = @("BeAnywhere", "Take Control"); Priority = "Low" }
    @{ Name = "Datto RMM"; Processes = @("AEMAgent*", "CagService*"); Services = @("AEM*", "CagService*"); Paths = @("CentraStage", "Datto"); Priority = "Low" }
    @{ Name = "NinjaRMM"; Processes = @("NinjaRMM*", "ninjarmm*"); Services = @("NinjaRMM*"); Paths = @("NinjaRMM", "NinjaMSP"); Priority = "Low" }
    @{ Name = "ConnectWise Automate"; Processes = @("LTService*", "LTSvcMon*", "LabTech*"); Services = @("LTService*", "LabTech*"); Paths = @("LabTech", "ConnectWise\Automate"); Priority = "Low" }
    @{ Name = "Kaseya"; Processes = @("agentmon*", "KaService*"); Services = @("Kaseya*", "KaService*"); Paths = @("Kaseya"); Priority = "Low" }
    @{ Name = "Pulseway"; Processes = @("PCMonitorSrv*", "Pulseway*"); Services = @("Pulseway*", "PCMonitor*"); Paths = @("Pulseway", "PCMonitor"); Priority = "Low" }
    @{ Name = "Syncro"; Processes = @("Syncro*", "Kabuto*"); Services = @("Syncro*", "Kabuto*"); Paths = @("Syncro", "Kabuto"); Priority = "Low" }

    # Known Malicious RATs (Critical Priority)
    @{ Name = "Remcos RAT"; Processes = @("remcos*"); Services = @("remcos*"); Paths = @("Remcos"); Priority = "Critical"; Malicious = $true }
    @{ Name = "QuasarRAT"; Processes = @("Quasar*"); Services = @("Quasar*"); Paths = @("Quasar"); Priority = "Critical"; Malicious = $true }
    @{ Name = "AsyncRAT"; Processes = @("AsyncClient*", "Async*"); Services = @("Async*"); Paths = @("Async"); Priority = "Critical"; Malicious = $true }
    @{ Name = "njRAT"; Processes = @("njRAT*", "Bladabindi*"); Services = @(); Paths = @("njRAT"); Priority = "Critical"; Malicious = $true }
    @{ Name = "NanoCore"; Processes = @("NanoCore*"); Services = @(); Paths = @("NanoCore"); Priority = "Critical"; Malicious = $true }
    @{ Name = "DarkComet"; Processes = @("DarkComet*"); Services = @(); Paths = @("DarkComet"); Priority = "Critical"; Malicious = $true }
    @{ Name = "Orcus RAT"; Processes = @("Orcus*"); Services = @("Orcus*"); Paths = @("Orcus"); Priority = "Critical"; Malicious = $true }
    @{ Name = "NetWire RAT"; Processes = @("NetWire*"); Services = @(); Paths = @("NetWire"); Priority = "Critical"; Malicious = $true }
    @{ Name = "Warzone RAT"; Processes = @("Warzone*", "AveMaria*"); Services = @(); Paths = @("Warzone", "AveMaria"); Priority = "Critical"; Malicious = $true }
    @{ Name = "Gh0st RAT"; Processes = @("Gh0st*", "pcshare*"); Services = @("Gh0st*"); Paths = @("Gh0st"); Priority = "Critical"; Malicious = $true }
    @{ Name = "Cobalt Strike"; Processes = @("beacon*", "artifact*"); Services = @(); Paths = @("cobaltstrike"); Priority = "Critical"; Malicious = $true }

    # Scareware / Fake Security
    @{ Name = "Network Security Premium"; Processes = @("NetworkSecurity*", "NetSecPremium*"); Services = @("NetworkSecurity*"); Paths = @("Network Security Premium", "NetworkSecurityPremium"); Priority = "Critical"; Malicious = $true }
    @{ Name = "PC Protector Plus"; Processes = @("PCProtector*"); Services = @("PCProtector*"); Paths = @("PC Protector", "PCProtector"); Priority = "Critical"; Malicious = $true }

    # WHITELISTED - Never removed
    @{ Name = "Level.io"; Processes = @("level-*", "level_*"); Services = @("level*"); Paths = @("Level"); Priority = "Skip"; Authorized = $true }
    @{ Name = "ScreenConnect"; Processes = @("ScreenConnect*", "ConnectWiseControl*"); Services = @("ScreenConnect*", "ConnectWise*"); Paths = @("ScreenConnect", "ConnectWise Control"); Priority = "Skip"; Authorized = $true }
)

# ============================================================
# DETECTION FUNCTIONS
# ============================================================
function Get-SystemInfo {
    $info = @{
        Processes = @()
        Services = @()
        InstalledSoftware = @()
    }

    $info.Processes = Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name -Unique
    $info.Services = Get-Service -ErrorAction SilentlyContinue | Select-Object Name, DisplayName, Status

    $RegistryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($Path in $RegistryPaths) {
        $info.InstalledSoftware += Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } |
            Select-Object DisplayName, UninstallString, QuietUninstallString, InstallLocation, PSPath
    }

    return $info
}

function Test-RATPresence {
    param([hashtable]$RATDef, [hashtable]$SystemInfo)

    $detection = @{
        Name = $RATDef.Name
        Found = $false
        Processes = @()
        Services = @()
        Software = @()
        Folders = @()
        Priority = $RATDef.Priority
        Malicious = $RATDef.Malicious -eq $true
        Authorized = $RATDef.Authorized -eq $true
    }

    # Check processes
    foreach ($pattern in $RATDef.Processes) {
        $matches = $SystemInfo.Processes | Where-Object { $_ -like $pattern }
        if ($matches) {
            $detection.Processes += $matches
            $detection.Found = $true
        }
    }

    # Check services
    foreach ($pattern in $RATDef.Services) {
        $matches = $SystemInfo.Services | Where-Object { $_.Name -like $pattern -or $_.DisplayName -like $pattern }
        if ($matches) {
            $detection.Services += $matches
            $detection.Found = $true
        }
    }

    # Check installed software
    foreach ($pathPattern in $RATDef.Paths) {
        $matches = $SystemInfo.InstalledSoftware | Where-Object {
            $_.DisplayName -like "*$pathPattern*" -or $_.InstallLocation -like "*$pathPattern*"
        }
        if ($matches) {
            $detection.Software += $matches
            $detection.Found = $true
        }
    }

    # Check common installation directories
    $CommonPaths = @(
        "$env:ProgramFiles",
        "${env:ProgramFiles(x86)}",
        "$env:LOCALAPPDATA",
        "$env:APPDATA",
        "$env:ProgramData"
    )

    foreach ($basePath in $CommonPaths) {
        foreach ($pathPattern in $RATDef.Paths) {
            $fullPath = Join-Path $basePath $pathPattern
            if (Test-Path $fullPath) {
                $detection.Folders += $fullPath
                $detection.Found = $true
            }
        }
    }

    return $detection
}

# ============================================================
# REMOVAL FUNCTIONS
# ============================================================
function Remove-RATProcesses {
    param([string]$Name, [array]$ProcessPatterns)
    $count = 0
    foreach ($pattern in $ProcessPatterns) {
        $procs = Get-Process -Name $pattern -ErrorAction SilentlyContinue
        foreach ($proc in $procs) {
            try {
                Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                Write-LevelLog "  Stopped process: $($proc.Name) (PID: $($proc.Id))"
                $count++
            } catch {
                $null = taskkill /F /PID $proc.Id 2>&1
                Write-LevelLog "  Killed via taskkill: $($proc.Name)"
            }
        }
    }
    return $count
}

function Remove-RATServices {
    param([string]$Name, [array]$ServicePatterns)
    $count = 0
    foreach ($pattern in $ServicePatterns) {
        $services = Get-Service -Name $pattern -ErrorAction SilentlyContinue
        foreach ($svc in $services) {
            try {
                if ($svc.Status -eq 'Running') {
                    Stop-Service -Name $svc.Name -Force -ErrorAction Stop
                }
                Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction SilentlyContinue
                Write-LevelLog "  Stopped service: $($svc.Name)"
                $count++
            } catch {
                $null = sc.exe stop $svc.Name 2>&1
                $null = sc.exe config $svc.Name start= disabled 2>&1
            }
        }
    }
    return $count
}

function Remove-RATUninstall {
    param([string]$Name, [array]$Software)
    $count = 0
    foreach ($sw in $Software) {
        $uninstallString = if ($sw.QuietUninstallString) { $sw.QuietUninstallString } else { $sw.UninstallString }
        if ($uninstallString) {
            Write-LevelLog "  Running uninstaller for: $($sw.DisplayName)"
            try {
                if ($uninstallString -match "msiexec") {
                    $uninstallString = $uninstallString -replace "/I", "/X"
                    if ($uninstallString -notmatch "/qn") {
                        $uninstallString = "$uninstallString /qn /norestart"
                    }
                } elseif ($uninstallString -notmatch "/S|/silent|/quiet|--silent|--remove") {
                    $uninstallString = "$uninstallString /S"
                }
                cmd /c $uninstallString 2>&1 | Out-Null
                $count++
                Start-Sleep -Seconds 3
            } catch {
                Write-LevelLog "  Uninstaller failed: $($_.Exception.Message)" -Level "WARN"
            }
        }
    }
    return $count
}

function Remove-RATFolders {
    param([string]$Name, [array]$Folders)
    $count = 0

    # Add standard paths
    $allFolders = @($Folders)
    $standardPaths = @(
        "$env:ProgramFiles\$Name",
        "${env:ProgramFiles(x86)}\$Name",
        "$env:ProgramData\$Name",
        "$env:LOCALAPPDATA\$Name",
        "$env:APPDATA\$Name"
    )
    foreach ($path in $standardPaths) {
        if ((Test-Path $path) -and ($path -notin $allFolders)) {
            $allFolders += $path
        }
    }

    foreach ($folder in $allFolders) {
        if (Test-Path $folder) {
            try {
                Remove-Item -Path $folder -Recurse -Force -ErrorAction Stop
                Write-LevelLog "  Removed folder: $folder"
                $count++
            } catch {
                # Fallback
                $null = cmd /c rd /s /q "`"$folder`"" 2>&1
                if (-not (Test-Path $folder)) {
                    Write-LevelLog "  Removed via cmd: $folder"
                    $count++
                }
            }
        }
    }

    # Clean shortcuts
    $shortcutPatterns = @(
        "$env:PUBLIC\Desktop\$Name*.lnk",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\$Name*.lnk"
    )
    foreach ($pattern in $shortcutPatterns) {
        Get-Item -Path $pattern -ErrorAction SilentlyContinue | ForEach-Object {
            Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
        }
    }

    return $count
}

function Remove-RATRegistry {
    param([string]$Name)
    $count = 0

    $regPaths = @(
        "HKLM:\SOFTWARE\$Name",
        "HKLM:\SOFTWARE\WOW6432Node\$Name",
        "HKCU:\SOFTWARE\$Name"
    )

    foreach ($regPath in $regPaths) {
        if (Test-Path $regPath) {
            try {
                Remove-Item -Path $regPath -Recurse -Force -ErrorAction Stop
                Write-LevelLog "  Removed registry: $regPath"
                $count++
            } catch { }
        }
    }

    # Clean uninstall entries
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    foreach ($path in $uninstallPaths) {
        if (Test-Path $path) {
            Get-ChildItem -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
                $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                if ($props.DisplayName -like "*$Name*") {
                    Remove-Item -Path $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                    $count++
                }
            }
        }
    }

    return $count
}

function Remove-RATServicesDelete {
    param([array]$ServicePatterns)
    foreach ($pattern in $ServicePatterns) {
        $services = Get-Service -Name $pattern -ErrorAction SilentlyContinue
        foreach ($svc in $services) {
            $null = sc.exe delete $svc.Name 2>&1
            Write-LevelLog "  Deleted service: $($svc.Name)"
        }
    }
}

function Remove-RATFirewallAndTasks {
    param([string]$Name)
    Get-NetFirewallRule -DisplayName "*$Name*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Get-ScheduledTask -TaskName "*$Name*" -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
}

function Remove-RAT {
    param([hashtable]$Detection, [hashtable]$RATDef)

    Write-LevelLog "--- Removing $($Detection.Name) ---" -Level "INFO"

    # Phase 1: Stop services
    if ($RATDef.Services) {
        Remove-RATServices -Name $Detection.Name -ServicePatterns $RATDef.Services | Out-Null
    }

    # Phase 2: Stop processes
    if ($RATDef.Processes) {
        Remove-RATProcesses -Name $Detection.Name -ProcessPatterns $RATDef.Processes | Out-Null
    }

    Start-Sleep -Seconds 2

    # Phase 3: Run uninstallers
    if ($Detection.Software.Count -gt 0) {
        Remove-RATUninstall -Name $Detection.Name -Software $Detection.Software | Out-Null
    }

    Start-Sleep -Seconds 2

    # Phase 4: Delete services
    if ($RATDef.Services) {
        Remove-RATServicesDelete -ServicePatterns $RATDef.Services
    }

    # Phase 5: Remove folders
    Remove-RATFolders -Name $Detection.Name -Folders $Detection.Folders | Out-Null

    # Phase 6: Clean registry
    Remove-RATRegistry -Name $Detection.Name | Out-Null

    # Phase 7: Firewall and scheduled tasks
    Remove-RATFirewallAndTasks -Name $Detection.Name

    # Verify removal
    Start-Sleep -Seconds 2
    $stillRunning = $false
    foreach ($pattern in $RATDef.Processes) {
        if (Get-Process -Name $pattern -ErrorAction SilentlyContinue) {
            $stillRunning = $true
            break
        }
    }

    if ($stillRunning) {
        Write-LevelLog "  WARNING: Some processes still running" -Level "WARN"
        return $false
    } else {
        Write-LevelLog "  Removed successfully" -Level "SUCCESS"
        return $true
    }
}

# ============================================================
# MAIN SCRIPT LOGIC
# ============================================================
Invoke-LevelScript -ScriptBlock {

    Write-LevelLog "Starting RAT scan and removal"

    # Check admin
    if (-not (Test-LevelAdmin)) {
        Write-LevelLog "This script requires administrator privileges" -Level "ERROR"
        Complete-LevelScript -ExitCode 1 -Message "Admin privileges required"
    }

    $DeviceInfo = Get-LevelDeviceInfo
    Write-LevelLog "Device: $($DeviceInfo.Hostname) | OS: $($DeviceInfo.OS)"

    # ============================================================
    # DETECTION PHASE
    # ============================================================
    Write-LevelLog "=== SCANNING FOR REMOTE ACCESS TOOLS ===" -Level "INFO"
    Write-LevelLog "Checking $($Script:RATDefinitions.Count) known tools..."

    $systemInfo = Get-SystemInfo
    Write-LevelLog "Found $($systemInfo.Processes.Count) processes, $($systemInfo.Services.Count) services, $($systemInfo.InstalledSoftware.Count) programs"

    $detections = @()
    foreach ($ratDef in $Script:RATDefinitions) {
        $detection = Test-RATPresence -RATDef $ratDef -SystemInfo $systemInfo

        if ($detection.Found) {
            if ($detection.Authorized) {
                Write-LevelLog "SKIP: $($detection.Name) (Authorized)" -Level "DEBUG"
                continue
            }

            $levelText = if ($detection.Malicious) { "ERROR" } elseif ($detection.Priority -eq "High") { "WARN" } else { "INFO" }
            Write-LevelLog "FOUND: $($detection.Name) (Priority: $($detection.Priority))" -Level $levelText

            $detections += @{
                Detection = $detection
                RATDef = $ratDef
            }
        }
    }

    # ============================================================
    # SUMMARY
    # ============================================================
    Write-LevelLog "=== DETECTION SUMMARY ===" -Level "INFO"

    if ($detections.Count -eq 0) {
        Write-LevelLog "No unauthorized remote access tools detected!" -Level "SUCCESS"
        Complete-LevelScript -ExitCode 0 -Message "No RATs found"
    }

    $criticalCount = ($detections | Where-Object { $_.Detection.Malicious }).Count
    $highCount = ($detections | Where-Object { $_.Detection.Priority -eq "High" -and -not $_.Detection.Malicious }).Count
    $otherCount = $detections.Count - $criticalCount - $highCount

    Write-LevelLog "Total RATs detected: $($detections.Count)"
    if ($criticalCount -gt 0) { Write-LevelLog "  CRITICAL (Malicious): $criticalCount" -Level "ERROR" }
    if ($highCount -gt 0) { Write-LevelLog "  High Priority: $highCount" -Level "WARN" }
    if ($otherCount -gt 0) { Write-LevelLog "  Other: $otherCount" }

    # ============================================================
    # REMOVAL PHASE
    # ============================================================
    Write-LevelLog "=== REMOVAL PHASE ===" -Level "INFO"

    $successCount = 0
    $failCount = 0

    foreach ($item in $detections) {
        $success = Remove-RAT -Detection $item.Detection -RATDef $item.RATDef
        if ($success) { $successCount++ } else { $failCount++ }
    }

    # ============================================================
    # FINAL SUMMARY
    # ============================================================
    Write-LevelLog "=== REMOVAL SUMMARY ===" -Level "INFO"
    Write-LevelLog "Successfully removed: $successCount" -Level $(if ($successCount -gt 0) { "SUCCESS" } else { "INFO" })
    Write-LevelLog "Failed to remove: $failCount" -Level $(if ($failCount -gt 0) { "WARN" } else { "INFO" })

    if ($failCount -gt 0) {
        Write-LevelLog "Some RATs may require a reboot to complete removal" -Level "WARN"
        Complete-LevelScript -ExitCode 1 -Message "RAT removal incomplete - $failCount failed"
    }

    if ($criticalCount -gt 0) {
        Write-Host ""
        Write-Host "Alert: CRITICAL - Malicious RATs were detected and removed from this system"
        Write-Host "  Device: $($DeviceInfo.Hostname)"
        Write-Host "  RATs removed: $($detections | ForEach-Object { $_.Detection.Name } | Join-String -Separator ', ')"
    }
}
