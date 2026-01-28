<#
.SYNOPSIS
    Comprehensive standalone script to detect and remove unauthorized remote access tools.

.DESCRIPTION
    This script scans for and removes remote access tools (RATs) from the system.
    It is designed for offline/manual cleanup scenarios where the COOLForge library
    is not available.

    Key Features:
    - Detects 70+ known remote access tools and malicious RATs
    - Level.io is automatically whitelisted (authorized RMM)
    - ScreenConnect instances are verified - prompts to confirm authorized instance ID
    - Multi-phase removal: processes, services, uninstallers, files, registry, firewall, tasks
    - Comprehensive logging to file and console
    - Interactive mode with confirmation prompts (use -Force to skip)
    - Dry-run mode with -WhatIf

    STANDALONE VERSION - No COOLForge library required.

.PARAMETER Force
    Skip all confirmation prompts and proceed with removal automatically.
    WARNING: This will remove all detected RATs without asking.

.PARAMETER WhatIf
    Dry-run mode - show what would be detected and removed without making changes.

.PARAMETER LogPath
    Optional path for the log file. Defaults to script directory.

.PARAMETER ScreenConnectInstanceId
    Pre-authorize a specific ScreenConnect instance ID. If the detected instance
    matches this ID, it will be skipped. Otherwise, removal will proceed.

.PARAMETER IncludeScreenConnect
    Force removal of ALL ScreenConnect instances regardless of instance ID.

.NOTES
    Version:          2026.01.27.01 (Standalone)
    Exit Codes:       0 = Success (No RATs or all removed) | 1 = Alert (RATs detected/removal failed)
    Requires:         Administrator privileges

    License:          AGPL-3.0 (see LICENSE)
    Copyright (c) 2025-2026 COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge

.EXAMPLE
    .\Remove-AllRATs-Standalone.ps1
    Interactive mode - scans, shows findings, prompts for each RAT.

.EXAMPLE
    .\Remove-AllRATs-Standalone.ps1 -Force
    Automated mode - removes all detected RATs without prompts.

.EXAMPLE
    .\Remove-AllRATs-Standalone.ps1 -WhatIf
    Dry-run mode - shows what would be detected and removed.

.EXAMPLE
    .\Remove-AllRATs-Standalone.ps1 -ScreenConnectInstanceId "abc123def456"
    Pre-authorize a specific ScreenConnect instance.
#>

param(
    [switch]$Force,
    [switch]$WhatIf,
    [string]$LogPath,
    [string]$ScreenConnectInstanceId,
    [switch]$IncludeScreenConnect
)

#region Configuration

# Authorized tools that will NEVER be removed
$Script:AuthorizedTools = @(
    "Level.io"
)

# Tool definitions - comprehensive list of RATs to detect
$Script:RATDefinitions = @(
    # Common Remote Access Tools
    @{ Name = "AnyDesk"; Processes = @("AnyDesk*"); Services = @("AnyDesk*"); Paths = @("AnyDesk"); Priority = "High" }
    @{ Name = "TeamViewer"; Processes = @("TeamViewer*", "tv_w32*", "tv_x64*"); Services = @("TeamViewer*"); Paths = @("TeamViewer"); Priority = "High" }
    @{ Name = "RustDesk"; Processes = @("rustdesk*"); Services = @("rustdesk*", "RustDesk*"); Paths = @("RustDesk"); Priority = "High" }
    @{ Name = "Splashtop"; Processes = @("SplashtopStreamer*", "Splashtop*", "strwinclt*", "SRManager*", "SRService*"); Services = @("Splashtop*", "SSUService*"); Paths = @("Splashtop"); Priority = "High" }
    @{ Name = "ScreenConnect"; Processes = @("ScreenConnect*", "ConnectWiseControl*"); Services = @("ScreenConnect*", "ConnectWise*"); Paths = @("ScreenConnect", "ConnectWise Control"); Priority = "High"; RequiresVerification = $true }
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

    # RMM Tools (usually authorized but detect anyway)
    @{ Name = "Action1"; Processes = @("action1*", "a1agent*"); Services = @("action1*"); Paths = @("Action1"); Priority = "Low" }
    @{ Name = "Atera"; Processes = @("AteraAgent*"); Services = @("AteraAgent*"); Paths = @("Atera"); Priority = "Low" }
    @{ Name = "N-able Take Control"; Processes = @("BASupSrvc*", "BASupApp*"); Services = @("BASupSrvc*"); Paths = @("BeAnywhere", "Take Control"); Priority = "Low" }
    @{ Name = "Datto RMM"; Processes = @("AEMAgent*", "CagService*"); Services = @("AEM*", "CagService*"); Paths = @("CentraStage", "Datto"); Priority = "Low" }
    @{ Name = "NinjaRMM"; Processes = @("NinjaRMM*", "ninjarmm*"); Services = @("NinjaRMM*"); Paths = @("NinjaRMM", "NinjaMSP"); Priority = "Low" }
    @{ Name = "ConnectWise Automate"; Processes = @("LTService*", "LTSvcMon*", "LabTech*"); Services = @("LTService*", "LabTech*"); Paths = @("LabTech", "ConnectWise\Automate"); Priority = "Low" }
    @{ Name = "Kaseya"; Processes = @("agentmon*", "KaService*"); Services = @("Kaseya*", "KaService*"); Paths = @("Kaseya"); Priority = "Low" }
    @{ Name = "Pulseway"; Processes = @("PCMonitorSrv*", "Pulseway*"); Services = @("Pulseway*", "PCMonitor*"); Paths = @("Pulseway", "PCMonitor"); Priority = "Low" }
    @{ Name = "Syncro"; Processes = @("Syncro*", "Kabuto*"); Services = @("Syncro*", "Kabuto*"); Paths = @("Syncro", "Kabuto"); Priority = "Low" }

    # Known Malicious RATs (High Priority)
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

    # Level.io - Authorized (will be skipped)
    @{ Name = "Level.io"; Processes = @("level-*", "level_*"); Services = @("level*"); Paths = @("Level"); Priority = "Skip"; Authorized = $true }
)

#endregion Configuration

#region Logging Functions

$Script:LogFile = $null

function Initialize-Log {
    param([string]$CustomPath)

    $timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
    $logFileName = "Remove-AllRATs-$timestamp.log"

    if ($CustomPath) {
        if (Test-Path $CustomPath -PathType Container) {
            $Script:LogFile = Join-Path $CustomPath $logFileName
        } else {
            $Script:LogFile = $CustomPath
        }
    } else {
        $scriptDir = Split-Path -Parent $MyInvocation.ScriptName
        if ([string]::IsNullOrEmpty($scriptDir)) { $scriptDir = Get-Location }
        $Script:LogFile = Join-Path $scriptDir $logFileName
    }

    $header = @"
================================================================================
Remove All RATs - Standalone Script Log
================================================================================
Started:    $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Computer:   $env:COMPUTERNAME
User:       $env:USERNAME
Mode:       $(if ($WhatIf) { "WhatIf (Dry-Run)" } elseif ($Force) { "Force (Automated)" } else { "Interactive" })
================================================================================

"@
    $header | Out-File -FilePath $Script:LogFile -Encoding UTF8
    return $Script:LogFile
}

function Write-Log {
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "ACTION", "SKIP", "DEBUG", "CRITICAL")]
        [string]$Level = "INFO"
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogLine = "[$Timestamp] [$Level] $Message"

    $Color = switch ($Level) {
        "INFO"     { "White" }
        "WARN"     { "Yellow" }
        "ERROR"    { "Red" }
        "SUCCESS"  { "Green" }
        "ACTION"   { "Cyan" }
        "SKIP"     { "Gray" }
        "DEBUG"    { "DarkGray" }
        "CRITICAL" { "Magenta" }
    }
    Write-Host $LogLine -ForegroundColor $Color

    if ($Script:LogFile) {
        $LogLine | Out-File -FilePath $Script:LogFile -Append -Encoding UTF8
    }
}

#endregion Logging Functions

#region Detection Functions

function Get-ScreenConnectInstanceId {
    <#
    .SYNOPSIS
        Extracts the ScreenConnect instance ID from installed services or registry.
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
    foreach ($PathPattern in $SCPaths) {
        $ParentPath = Split-Path $PathPattern
        if (Test-Path $ParentPath) {
            $Folders = Get-ChildItem -Path $ParentPath -Filter "ScreenConnect*" -Directory -ErrorAction SilentlyContinue
            foreach ($Folder in $Folders) {
                if ($Folder.Name -match '\(([a-f0-9]{8,})\)') {
                    return $Matches[1]
                }
            }
        }
    }

    return $null
}

function Get-SystemInfo {
    <#
    .SYNOPSIS
        Gathers system information for RAT detection.
    #>

    Write-Log "Gathering system information..." -Level "INFO"

    $info = @{
        Processes = @()
        Services = @()
        InstalledSoftware = @()
    }

    # Get running processes
    Write-Log "  Scanning running processes..." -Level "DEBUG"
    $info.Processes = Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name -Unique

    # Get services
    Write-Log "  Scanning services..." -Level "DEBUG"
    $info.Services = Get-Service -ErrorAction SilentlyContinue | Select-Object Name, DisplayName, Status

    # Get installed software from registry
    Write-Log "  Scanning installed software..." -Level "DEBUG"
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

    Write-Log "  Found $($info.Processes.Count) processes, $($info.Services.Count) services, $($info.InstalledSoftware.Count) installed programs" -Level "INFO"

    return $info
}

function Test-RATPresence {
    <#
    .SYNOPSIS
        Checks if a specific RAT is present on the system.
    #>
    param(
        [hashtable]$RATDef,
        [hashtable]$SystemInfo
    )

    $detection = @{
        Name = $RATDef.Name
        Found = $false
        Processes = @()
        Services = @()
        Software = @()
        Folders = @()
        Priority = $RATDef.Priority
        Malicious = $RATDef.Malicious -eq $true
        RequiresVerification = $RATDef.RequiresVerification -eq $true
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

    # Check common installation directories (including temp folders where RATs hide)
    $CommonPaths = @(
        "$env:ProgramFiles",
        "${env:ProgramFiles(x86)}",
        "$env:LOCALAPPDATA",
        "$env:APPDATA",
        "$env:ProgramData",
        "$env:TEMP",
        "$env:windir\Temp"
    )

    foreach ($basePath in $CommonPaths) {
        foreach ($pathPattern in $RATDef.Paths) {
            $fullPath = Join-Path $basePath $pathPattern
            if (Test-Path $fullPath) {
                $detection.Folders += $fullPath
                $detection.Found = $true
            }
            # Also check with wildcards
            $items = Get-ChildItem -Path $basePath -Filter "$pathPattern*" -Directory -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                if ($item.FullName -notin $detection.Folders) {
                    $detection.Folders += $item.FullName
                    $detection.Found = $true
                }
            }
        }
    }

    return $detection
}

function Invoke-RATScan {
    <#
    .SYNOPSIS
        Scans the system for all known RATs.
    #>

    Write-Log "=== SCANNING FOR REMOTE ACCESS TOOLS ===" -Level "INFO"
    Write-Log "Checking $($Script:RATDefinitions.Count) known tools..." -Level "INFO"

    $systemInfo = Get-SystemInfo
    $detections = @()

    foreach ($ratDef in $Script:RATDefinitions) {
        $detection = Test-RATPresence -RATDef $ratDef -SystemInfo $systemInfo

        if ($detection.Found) {
            # Skip authorized tools
            if ($detection.Authorized) {
                Write-Log "SKIP: $($detection.Name) (Authorized RMM)" -Level "SKIP"
                continue
            }

            $levelText = if ($detection.Malicious) { "CRITICAL" } elseif ($detection.Priority -eq "High") { "WARN" } else { "INFO" }
            Write-Log "FOUND: $($detection.Name)" -Level $levelText

            if ($detection.Processes.Count -gt 0) {
                Write-Log "  Processes: $($detection.Processes -join ', ')" -Level "DEBUG"
            }
            if ($detection.Services.Count -gt 0) {
                Write-Log "  Services: $(($detection.Services | Select-Object -ExpandProperty Name) -join ', ')" -Level "DEBUG"
            }
            if ($detection.Folders.Count -gt 0) {
                Write-Log "  Folders: $($detection.Folders -join ', ')" -Level "DEBUG"
            }

            $detections += $detection
        }
    }

    return $detections
}

#endregion Detection Functions

#region Removal Functions

function Remove-RATProcesses {
    param([string]$Name, [array]$ProcessPatterns)

    $count = 0
    $prefix = if ($WhatIf) { "WOULD: " } else { "" }

    foreach ($pattern in $ProcessPatterns) {
        $procs = Get-Process -Name $pattern -ErrorAction SilentlyContinue
        foreach ($proc in $procs) {
            Write-Log "${prefix}Stopping process: $($proc.Name) (PID: $($proc.Id))" -Level "INFO"
            if (-not $WhatIf) {
                try {
                    Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                    $count++
                } catch {
                    Write-Log "Failed to stop process $($proc.Name): $($_.Exception.Message)" -Level "WARN"
                }
            }
        }
    }

    return $count
}

function Remove-RATServices {
    param([string]$Name, [array]$ServicePatterns)

    $count = 0
    $prefix = if ($WhatIf) { "WOULD: " } else { "" }

    foreach ($pattern in $ServicePatterns) {
        $services = Get-Service -Name $pattern -ErrorAction SilentlyContinue
        foreach ($svc in $services) {
            Write-Log "${prefix}Stopping service: $($svc.Name)" -Level "INFO"
            if (-not $WhatIf) {
                try {
                    if ($svc.Status -eq 'Running') {
                        Stop-Service -Name $svc.Name -Force -ErrorAction Stop
                    }
                    Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction SilentlyContinue
                    $count++
                } catch {
                    Write-Log "Failed to stop service $($svc.Name): $($_.Exception.Message)" -Level "WARN"
                }
            }
        }
    }

    return $count
}

function Remove-RATUninstall {
    param([string]$Name, [array]$Software)

    $count = 0
    $prefix = if ($WhatIf) { "WOULD: " } else { "" }

    foreach ($sw in $Software) {
        $uninstallString = if ($sw.QuietUninstallString) { $sw.QuietUninstallString } else { $sw.UninstallString }

        if ($uninstallString) {
            Write-Log "${prefix}Running uninstaller for: $($sw.DisplayName)" -Level "INFO"

            if (-not $WhatIf) {
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
                    Write-Log "Uninstaller failed: $($_.Exception.Message)" -Level "WARN"
                }
            }
        }
    }

    return $count
}

function Remove-RATFolders {
    param([string]$Name, [array]$Folders)

    $count = 0
    $prefix = if ($WhatIf) { "WOULD: " } else { "" }

    foreach ($folder in $Folders) {
        if (Test-Path $folder) {
            Write-Log "${prefix}Removing folder: $folder" -Level "INFO"
            if (-not $WhatIf) {
                try {
                    Remove-Item -Path $folder -Recurse -Force -ErrorAction Stop
                    $count++
                } catch {
                    Write-Log "Failed to remove folder: $($_.Exception.Message)" -Level "WARN"
                }
            }
        }
    }

    # Also remove from user profiles
    $userProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue
    foreach ($profile in $userProfiles) {
        $userPaths = @(
            "$($profile.FullName)\AppData\Local\$Name",
            "$($profile.FullName)\AppData\Roaming\$Name",
            "$($profile.FullName)\Desktop\$Name*.lnk"
        )
        foreach ($path in $userPaths) {
            $items = Get-Item -Path $path -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                Write-Log "${prefix}Removing: $($item.FullName)" -Level "DEBUG"
                if (-not $WhatIf) {
                    try {
                        Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction Stop
                        $count++
                    } catch { }
                }
            }
        }
    }

    return $count
}

function Remove-RATRegistry {
    param([string]$Name)

    $count = 0
    $prefix = if ($WhatIf) { "WOULD: " } else { "" }

    # Common registry locations
    $regPaths = @(
        "HKLM:\SOFTWARE\$Name",
        "HKLM:\SOFTWARE\WOW6432Node\$Name",
        "HKCU:\SOFTWARE\$Name"
    )

    foreach ($regPath in $regPaths) {
        if (Test-Path $regPath) {
            Write-Log "${prefix}Removing registry: $regPath" -Level "INFO"
            if (-not $WhatIf) {
                try {
                    Remove-Item -Path $regPath -Recurse -Force -ErrorAction Stop
                    $count++
                } catch {
                    Write-Log "Failed to remove registry key: $($_.Exception.Message)" -Level "WARN"
                }
            }
        }
    }

    # Clean uninstall entries
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    foreach ($path in $uninstallPaths) {
        if (Test-Path $path) {
            Get-ChildItem -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
                $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                if ($props.DisplayName -like "*$Name*") {
                    Write-Log "${prefix}Removing uninstall entry: $($props.DisplayName)" -Level "DEBUG"
                    if (-not $WhatIf) {
                        try {
                            Remove-Item -Path $_.PSPath -Recurse -Force -ErrorAction Stop
                            $count++
                        } catch { }
                    }
                }
            }
        }
    }

    return $count
}

function Remove-RATServices-Delete {
    param([string]$Name, [array]$ServicePatterns)

    $count = 0
    $prefix = if ($WhatIf) { "WOULD: " } else { "" }

    foreach ($pattern in $ServicePatterns) {
        $services = Get-Service -Name $pattern -ErrorAction SilentlyContinue
        foreach ($svc in $services) {
            Write-Log "${prefix}Deleting service: $($svc.Name)" -Level "INFO"
            if (-not $WhatIf) {
                try {
                    sc.exe delete $svc.Name 2>&1 | Out-Null
                    $count++
                } catch {
                    Write-Log "Failed to delete service: $($_.Exception.Message)" -Level "WARN"
                }
            }
        }
    }

    return $count
}

function Remove-RATFirewallRules {
    param([string]$Name)

    $count = 0
    $prefix = if ($WhatIf) { "WOULD: " } else { "" }

    $rules = Get-NetFirewallRule -DisplayName "*$Name*" -ErrorAction SilentlyContinue
    foreach ($rule in $rules) {
        Write-Log "${prefix}Removing firewall rule: $($rule.DisplayName)" -Level "DEBUG"
        if (-not $WhatIf) {
            try {
                Remove-NetFirewallRule -Name $rule.Name -ErrorAction Stop
                $count++
            } catch { }
        }
    }

    return $count
}

function Remove-RATScheduledTasks {
    param([string]$Name)

    $count = 0
    $prefix = if ($WhatIf) { "WOULD: " } else { "" }

    $tasks = Get-ScheduledTask -TaskName "*$Name*" -ErrorAction SilentlyContinue
    foreach ($task in $tasks) {
        Write-Log "${prefix}Removing scheduled task: $($task.TaskName)" -Level "DEBUG"
        if (-not $WhatIf) {
            try {
                Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction Stop
                $count++
            } catch { }
        }
    }

    return $count
}

#region Tool-Specific Removal Functions

function Remove-AnyDesk-Specific {
    <#
    .SYNOPSIS
        Comprehensive AnyDesk removal with all cleanup phases.
    #>
    $prefix = if ($WhatIf) { "WOULD: " } else { "" }

    Write-Log "--- AnyDesk Comprehensive Removal ---" -Level "ACTION"

    # Phase 1: Stop services
    Write-Log "${prefix}Phase 1: Stopping AnyDesk services..." -Level "INFO"
    Get-Service -Name "AnyDesk*" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Log "${prefix}Stopping service: $($_.Name)" -Level "INFO"
        if (-not $WhatIf) {
            Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue
            Set-Service -Name $_.Name -StartupType Disabled -ErrorAction SilentlyContinue
        }
    }

    # Phase 2: Stop processes
    Write-Log "${prefix}Phase 2: Stopping AnyDesk processes..." -Level "INFO"
    Get-Process -Name "AnyDesk*" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Log "${prefix}Stopping process: $($_.Name) (PID: $($_.Id))" -Level "INFO"
        if (-not $WhatIf) { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
    }

    if (-not $WhatIf) { Start-Sleep -Seconds 2 }

    # Phase 3: Run AnyDesk's own uninstaller
    Write-Log "${prefix}Phase 3: Running AnyDesk uninstaller..." -Level "INFO"
    $anyDeskPaths = @(
        "$env:ProgramFiles\AnyDesk\AnyDesk.exe",
        "${env:ProgramFiles(x86)}\AnyDesk\AnyDesk.exe",
        "$env:LOCALAPPDATA\AnyDesk\AnyDesk.exe"
    )
    foreach ($adPath in $anyDeskPaths) {
        if (Test-Path $adPath) {
            Write-Log "${prefix}Running: $adPath --remove --silent" -Level "INFO"
            if (-not $WhatIf) {
                Start-Process -FilePath $adPath -ArgumentList "--remove --silent" -Wait -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 3
            }
        }
    }

    # Phase 4: Registry-based uninstall
    Write-Log "${prefix}Phase 4: Registry-based uninstall..." -Level "INFO"
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    foreach ($regPath in $uninstallPaths) {
        Get-ItemProperty $regPath -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*AnyDesk*" } | ForEach-Object {
            $uninstallString = $_.UninstallString
            if ($uninstallString) {
                Write-Log "${prefix}Running uninstaller: $uninstallString" -Level "INFO"
                if (-not $WhatIf) {
                    if ($uninstallString -notmatch '--remove|--silent') {
                        $uninstallString = "$uninstallString --remove --silent"
                    }
                    cmd /c $uninstallString 2>&1 | Out-Null
                    Start-Sleep -Seconds 3
                }
            }
        }
    }

    # Phase 5: Delete services
    Write-Log "${prefix}Phase 5: Deleting AnyDesk services..." -Level "INFO"
    if (-not $WhatIf) {
        Get-Service -Name "AnyDesk*" -ErrorAction SilentlyContinue | ForEach-Object {
            sc.exe delete $_.Name 2>&1 | Out-Null
        }
    }

    # Phase 6: Remove files and folders
    Write-Log "${prefix}Phase 6: Removing AnyDesk files..." -Level "INFO"
    $foldersToRemove = @(
        "$env:ProgramFiles\AnyDesk",
        "${env:ProgramFiles(x86)}\AnyDesk",
        "$env:LOCALAPPDATA\AnyDesk",
        "$env:ProgramData\AnyDesk",
        "$env:APPDATA\AnyDesk"
    )

    # Add user profile folders
    Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $foldersToRemove += "$($_.FullName)\AppData\Local\AnyDesk"
        $foldersToRemove += "$($_.FullName)\AppData\Roaming\AnyDesk"
    }

    foreach ($folder in $foldersToRemove) {
        if (Test-Path $folder) {
            Write-Log "${prefix}Removing folder: $folder" -Level "INFO"
            if (-not $WhatIf) { Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    # Remove shortcuts
    $shortcutPatterns = @(
        "$env:PUBLIC\Desktop\AnyDesk*.lnk",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\AnyDesk*.lnk"
    )
    Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $shortcutPatterns += "$($_.FullName)\Desktop\AnyDesk*.lnk"
        $shortcutPatterns += "$($_.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\AnyDesk*.lnk"
    }
    foreach ($pattern in $shortcutPatterns) {
        Get-Item -Path $pattern -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Log "${prefix}Removing shortcut: $($_.FullName)" -Level "DEBUG"
            if (-not $WhatIf) { Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue }
        }
    }

    # Phase 7: Clean registry
    Write-Log "${prefix}Phase 7: Cleaning AnyDesk registry..." -Level "INFO"
    $regKeys = @(
        "HKLM:\SOFTWARE\AnyDesk",
        "HKLM:\SOFTWARE\WOW6432Node\AnyDesk",
        "HKCU:\SOFTWARE\AnyDesk",
        "HKLM:\SYSTEM\CurrentControlSet\Services\AnyDesk"
    )
    foreach ($key in $regKeys) {
        if (Test-Path $key) {
            Write-Log "${prefix}Removing registry: $key" -Level "DEBUG"
            if (-not $WhatIf) { Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    # Clean Run keys
    @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run") | ForEach-Object {
        if (Test-Path $_) {
            Get-ItemProperty -Path $_ -ErrorAction SilentlyContinue | ForEach-Object {
                $_.PSObject.Properties | Where-Object { $_.Value -like "*AnyDesk*" } | ForEach-Object {
                    Write-Log "${prefix}Removing Run entry: $($_.Name)" -Level "DEBUG"
                    if (-not $WhatIf) { Remove-ItemProperty -Path $using:_ -Name $_.Name -Force -ErrorAction SilentlyContinue }
                }
            }
        }
    }

    # Phase 8: Firewall and scheduled tasks
    Write-Log "${prefix}Phase 8: Cleaning firewall and tasks..." -Level "INFO"
    if (-not $WhatIf) {
        Get-NetFirewallRule -DisplayName "*AnyDesk*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        Get-ScheduledTask -TaskName "*AnyDesk*" -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
    }
}

function Remove-TeamViewer-Specific {
    <#
    .SYNOPSIS
        Comprehensive TeamViewer removal with all cleanup phases.
    #>
    $prefix = if ($WhatIf) { "WOULD: " } else { "" }

    Write-Log "--- TeamViewer Comprehensive Removal ---" -Level "ACTION"

    # Phase 1: Stop services (including versioned services)
    Write-Log "${prefix}Phase 1: Stopping TeamViewer services..." -Level "INFO"
    $serviceNames = @("TeamViewer", "TeamViewer7", "TeamViewer8", "TeamViewer9", "TeamViewer10",
                      "TeamViewer11", "TeamViewer12", "TeamViewer13", "TeamViewer14", "TeamViewer15")
    foreach ($svcName in $serviceNames) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            Write-Log "${prefix}Stopping service: $svcName" -Level "INFO"
            if (-not $WhatIf) {
                Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
                Set-Service -Name $svcName -StartupType Disabled -ErrorAction SilentlyContinue
            }
        }
    }

    # Phase 2: Stop processes
    Write-Log "${prefix}Phase 2: Stopping TeamViewer processes..." -Level "INFO"
    $processNames = @("TeamViewer", "TeamViewer_Service", "tv_w32", "tv_x64", "TeamViewer_Desktop", "TeamViewer_Note")
    foreach ($procName in $processNames) {
        Get-Process -Name $procName -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Log "${prefix}Stopping process: $($_.Name) (PID: $($_.Id))" -Level "INFO"
            if (-not $WhatIf) { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
        }
    }

    if (-not $WhatIf) { Start-Sleep -Seconds 2 }

    # Phase 3: Winget uninstall
    Write-Log "${prefix}Phase 3: Attempting winget uninstall..." -Level "INFO"
    if (-not $WhatIf) {
        $winget = Get-Command winget -ErrorAction SilentlyContinue
        if ($winget) {
            @("TeamViewer.TeamViewer", "TeamViewer.TeamViewer.Host") | ForEach-Object {
                Write-Log "Running: winget uninstall --id $_ --silent --force" -Level "DEBUG"
                & winget uninstall --id $_ --silent --force 2>&1 | Out-Null
            }
            & winget uninstall --name "TeamViewer" --silent --force 2>&1 | Out-Null
        } else {
            Write-Log "Winget not available, skipping..." -Level "SKIP"
        }
    }

    if (-not $WhatIf) { Start-Sleep -Seconds 3 }

    # Phase 4: Registry-based uninstall
    Write-Log "${prefix}Phase 4: Registry-based uninstall..." -Level "INFO"
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    foreach ($path in $uninstallPaths) {
        if (Test-Path $path) {
            Get-ChildItem -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
                $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                if ($props.DisplayName -like "*TeamViewer*") {
                    $uninstallString = if ($props.QuietUninstallString) { $props.QuietUninstallString } else { $props.UninstallString }
                    if ($uninstallString) {
                        Write-Log "${prefix}Running uninstaller for: $($props.DisplayName)" -Level "INFO"
                        if (-not $WhatIf) {
                            if ($uninstallString -match "msiexec") {
                                $uninstallString = $uninstallString -replace "/I", "/X"
                                $uninstallString = "$uninstallString /qn /norestart"
                            } elseif ($uninstallString -match "uninstall.exe" -and $uninstallString -notmatch "/S") {
                                $uninstallString = "$uninstallString /S"
                            }
                            cmd /c $uninstallString 2>&1 | Out-Null
                        }
                    }
                }
            }
        }
    }

    if (-not $WhatIf) { Start-Sleep -Seconds 5 }

    # Phase 5: Direct uninstaller execution
    Write-Log "${prefix}Phase 5: Direct uninstaller execution..." -Level "INFO"
    $uninstallerPaths = @(
        "${env:ProgramFiles}\TeamViewer\uninstall.exe",
        "${env:ProgramFiles(x86)}\TeamViewer\uninstall.exe"
    )
    # Add versioned TeamViewer folders
    @(Get-ChildItem "${env:ProgramFiles}" -Filter "TeamViewer*" -Directory -ErrorAction SilentlyContinue) +
    @(Get-ChildItem "${env:ProgramFiles(x86)}" -Filter "TeamViewer*" -Directory -ErrorAction SilentlyContinue) | ForEach-Object {
        $uninstallerPaths += Join-Path $_.FullName "uninstall.exe"
    }

    foreach ($uninstaller in ($uninstallerPaths | Select-Object -Unique)) {
        if (Test-Path $uninstaller) {
            Write-Log "${prefix}Running: $uninstaller /S" -Level "INFO"
            if (-not $WhatIf) {
                Start-Process -FilePath $uninstaller -ArgumentList "/S" -Wait -ErrorAction SilentlyContinue
            }
        }
    }

    if (-not $WhatIf) { Start-Sleep -Seconds 3 }

    # Phase 6: Delete services
    Write-Log "${prefix}Phase 6: Deleting TeamViewer services..." -Level "INFO"
    if (-not $WhatIf) {
        foreach ($svcName in $serviceNames) {
            if (Get-Service -Name $svcName -ErrorAction SilentlyContinue) {
                sc.exe delete $svcName 2>&1 | Out-Null
            }
        }
    }

    # Phase 7: Remove files and folders
    Write-Log "${prefix}Phase 7: Removing TeamViewer files..." -Level "INFO"
    $foldersToRemove = @(
        "${env:ProgramFiles}\TeamViewer",
        "${env:ProgramFiles(x86)}\TeamViewer",
        "${env:ProgramData}\TeamViewer",
        "${env:LOCALAPPDATA}\TeamViewer",
        "${env:APPDATA}\TeamViewer"
    )

    # Add versioned folders
    @(Get-ChildItem "${env:ProgramFiles}" -Filter "TeamViewer*" -Directory -ErrorAction SilentlyContinue) +
    @(Get-ChildItem "${env:ProgramFiles(x86)}" -Filter "TeamViewer*" -Directory -ErrorAction SilentlyContinue) | ForEach-Object {
        $foldersToRemove += $_.FullName
    }

    # Add user profile folders
    Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $foldersToRemove += "$($_.FullName)\AppData\Local\TeamViewer"
        $foldersToRemove += "$($_.FullName)\AppData\Roaming\TeamViewer"
    }

    foreach ($folder in ($foldersToRemove | Select-Object -Unique)) {
        if (Test-Path $folder) {
            Write-Log "${prefix}Removing folder: $folder" -Level "INFO"
            if (-not $WhatIf) { Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    # Remove shortcuts
    $shortcutPatterns = @("$env:PUBLIC\Desktop\TeamViewer*.lnk", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\TeamViewer*.lnk")
    Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $shortcutPatterns += "$($_.FullName)\Desktop\TeamViewer*.lnk"
        $shortcutPatterns += "$($_.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\TeamViewer*.lnk"
    }
    foreach ($pattern in $shortcutPatterns) {
        Get-Item -Path $pattern -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Log "${prefix}Removing shortcut: $($_.FullName)" -Level "DEBUG"
            if (-not $WhatIf) { Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue }
        }
    }

    # Phase 8: Clean registry
    Write-Log "${prefix}Phase 8: Cleaning TeamViewer registry..." -Level "INFO"
    $regKeys = @(
        "HKLM:\SOFTWARE\TeamViewer",
        "HKLM:\SOFTWARE\WOW6432Node\TeamViewer",
        "HKCU:\SOFTWARE\TeamViewer",
        "HKLM:\SOFTWARE\TeamViewer GmbH",
        "HKLM:\SOFTWARE\WOW6432Node\TeamViewer GmbH"
    )
    foreach ($key in $regKeys) {
        if (Test-Path $key) {
            Write-Log "${prefix}Removing registry: $key" -Level "DEBUG"
            if (-not $WhatIf) { Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    # Clean Run keys
    @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run") | ForEach-Object {
        $runKey = $_
        if (Test-Path $runKey) {
            $props = Get-ItemProperty -Path $runKey -ErrorAction SilentlyContinue
            $props.PSObject.Properties | Where-Object { $_.Name -like "*TeamViewer*" } | ForEach-Object {
                Write-Log "${prefix}Removing Run entry: $($_.Name)" -Level "DEBUG"
                if (-not $WhatIf) { Remove-ItemProperty -Path $runKey -Name $_.Name -ErrorAction SilentlyContinue }
            }
        }
    }

    # Phase 9: Firewall, scheduled tasks, printers
    Write-Log "${prefix}Phase 9: Cleaning firewall, tasks, printers..." -Level "INFO"
    if (-not $WhatIf) {
        Get-NetFirewallRule -DisplayName "*TeamViewer*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        Get-ScheduledTask -TaskName "*TeamViewer*" -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
        Get-Printer -Name "*TeamViewer*" -ErrorAction SilentlyContinue | Remove-Printer -ErrorAction SilentlyContinue
        Get-PrinterDriver -Name "*TeamViewer*" -ErrorAction SilentlyContinue | Remove-PrinterDriver -ErrorAction SilentlyContinue
    }
}

function Remove-Splashtop-Specific {
    <#
    .SYNOPSIS
        Comprehensive Splashtop removal with all cleanup phases.
    #>
    $prefix = if ($WhatIf) { "WOULD: " } else { "" }

    Write-Log "--- Splashtop Comprehensive Removal ---" -Level "ACTION"

    # Phase 1: Stop services
    Write-Log "${prefix}Phase 1: Stopping Splashtop services..." -Level "INFO"
    $serviceNames = @("SplashtopRemoteService", "SSUService")
    foreach ($svcName in $serviceNames) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            Write-Log "${prefix}Stopping service: $svcName" -Level "INFO"
            if (-not $WhatIf) {
                Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
                Set-Service -Name $svcName -StartupType Disabled -ErrorAction SilentlyContinue
            }
        }
    }

    # Phase 2: Stop processes
    Write-Log "${prefix}Phase 2: Stopping Splashtop processes..." -Level "INFO"
    $processNames = @("SRManager", "SRService", "SRFeature", "SRAgent", "strwinclt", "SplashtopStreamer", "Splashtop")
    foreach ($procName in $processNames) {
        Get-Process -Name $procName -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Log "${prefix}Stopping process: $($_.Name) (PID: $($_.Id))" -Level "INFO"
            if (-not $WhatIf) { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
        }
    }

    if (-not $WhatIf) { Start-Sleep -Seconds 2 }

    # Phase 3: Winget uninstall
    Write-Log "${prefix}Phase 3: Attempting winget uninstall..." -Level "INFO"
    if (-not $WhatIf) {
        $winget = Get-Command winget -ErrorAction SilentlyContinue
        if ($winget) {
            & winget uninstall --id "Splashtop.SplashtopStreamer" --silent --force 2>&1 | Out-Null
            & winget uninstall --name "Splashtop Streamer" --silent --force 2>&1 | Out-Null
        } else {
            Write-Log "Winget not available, skipping..." -Level "SKIP"
        }
    }

    if (-not $WhatIf) { Start-Sleep -Seconds 3 }

    # Phase 4: Registry-based uninstall
    Write-Log "${prefix}Phase 4: Registry-based uninstall..." -Level "INFO"
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    foreach ($path in $uninstallPaths) {
        if (Test-Path $path) {
            Get-ChildItem -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
                $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                if ($props.DisplayName -like "*Splashtop*Streamer*" -or $props.DisplayName -like "*Splashtop*Remote*") {
                    $uninstallString = if ($props.QuietUninstallString) { $props.QuietUninstallString } else { $props.UninstallString }
                    if ($uninstallString) {
                        Write-Log "${prefix}Running uninstaller for: $($props.DisplayName)" -Level "INFO"
                        if (-not $WhatIf) {
                            if ($uninstallString -match "msiexec") {
                                $uninstallString = $uninstallString -replace "/I", "/X"
                                $uninstallString = "$uninstallString /qn /norestart"
                            } elseif ($uninstallString -notmatch "/S|/silent|/quiet") {
                                $uninstallString = "$uninstallString /S"
                            }
                            cmd /c $uninstallString 2>&1 | Out-Null
                        }
                    }
                }
            }
        }
    }

    if (-not $WhatIf) { Start-Sleep -Seconds 5 }

    # Phase 5: Direct uninstaller execution
    Write-Log "${prefix}Phase 5: Direct uninstaller execution..." -Level "INFO"
    $uninstallerPaths = @(
        "${env:ProgramFiles}\Splashtop\Splashtop Remote\Server\uninst.exe",
        "${env:ProgramFiles(x86)}\Splashtop\Splashtop Remote\Server\uninst.exe",
        "${env:ProgramFiles}\Splashtop\Splashtop Streamer\uninst.exe",
        "${env:ProgramFiles(x86)}\Splashtop\Splashtop Streamer\uninst.exe"
    )

    foreach ($uninstaller in ($uninstallerPaths | Select-Object -Unique)) {
        if (Test-Path $uninstaller) {
            Write-Log "${prefix}Running: $uninstaller /S" -Level "INFO"
            if (-not $WhatIf) {
                Start-Process -FilePath $uninstaller -ArgumentList "/S" -Wait -ErrorAction SilentlyContinue
            }
        }
    }

    if (-not $WhatIf) { Start-Sleep -Seconds 3 }

    # Phase 6: Delete services
    Write-Log "${prefix}Phase 6: Deleting Splashtop services..." -Level "INFO"
    if (-not $WhatIf) {
        foreach ($svcName in $serviceNames) {
            if (Get-Service -Name $svcName -ErrorAction SilentlyContinue) {
                sc.exe delete $svcName 2>&1 | Out-Null
            }
        }
    }

    # Phase 7: Remove files and folders
    Write-Log "${prefix}Phase 7: Removing Splashtop files..." -Level "INFO"
    $foldersToRemove = @(
        "${env:ProgramFiles}\Splashtop",
        "${env:ProgramFiles(x86)}\Splashtop",
        "${env:ProgramData}\Splashtop",
        "${env:LOCALAPPDATA}\Splashtop",
        "${env:APPDATA}\Splashtop"
    )

    # Add user profile folders
    Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $foldersToRemove += "$($_.FullName)\AppData\Local\Splashtop"
        $foldersToRemove += "$($_.FullName)\AppData\Roaming\Splashtop"
    }

    foreach ($folder in ($foldersToRemove | Select-Object -Unique)) {
        if (Test-Path $folder) {
            Write-Log "${prefix}Removing folder: $folder" -Level "INFO"
            if (-not $WhatIf) { Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    # Phase 8: Clean registry
    Write-Log "${prefix}Phase 8: Cleaning Splashtop registry..." -Level "INFO"
    $regKeys = @(
        "HKLM:\SOFTWARE\Splashtop",
        "HKLM:\SOFTWARE\WOW6432Node\Splashtop",
        "HKCU:\SOFTWARE\Splashtop"
    )
    foreach ($key in $regKeys) {
        if (Test-Path $key) {
            Write-Log "${prefix}Removing registry: $key" -Level "DEBUG"
            if (-not $WhatIf) { Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    # Phase 9: Firewall and scheduled tasks
    Write-Log "${prefix}Phase 9: Cleaning firewall and tasks..." -Level "INFO"
    if (-not $WhatIf) {
        Get-NetFirewallRule -DisplayName "*Splashtop*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        Get-ScheduledTask -TaskName "*Splashtop*" -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
    }
}

function Remove-RustDesk-Specific {
    <#
    .SYNOPSIS
        Comprehensive RustDesk removal with all cleanup phases.
    #>
    $prefix = if ($WhatIf) { "WOULD: " } else { "" }

    Write-Log "--- RustDesk Comprehensive Removal ---" -Level "ACTION"

    # Phase 1: Stop services
    Write-Log "${prefix}Phase 1: Stopping RustDesk services..." -Level "INFO"
    $serviceNames = @("RustDesk", "rustdesk")
    foreach ($svcName in $serviceNames) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            Write-Log "${prefix}Stopping service: $svcName" -Level "INFO"
            if (-not $WhatIf) {
                Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
                Set-Service -Name $svcName -StartupType Disabled -ErrorAction SilentlyContinue
            }
        }
    }

    # Phase 2: Stop processes
    Write-Log "${prefix}Phase 2: Stopping RustDesk processes..." -Level "INFO"
    $processNames = @("rustdesk", "rustdesk_service")
    foreach ($procName in $processNames) {
        Get-Process -Name $procName -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Log "${prefix}Stopping process: $($_.Name) (PID: $($_.Id))" -Level "INFO"
            if (-not $WhatIf) { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
        }
    }

    if (-not $WhatIf) { Start-Sleep -Seconds 2 }

    # Phase 3: MSI-based uninstall
    Write-Log "${prefix}Phase 3: MSI-based uninstall..." -Level "INFO"
    if (-not $WhatIf) {
        try {
            $msiProducts = Get-WmiObject -Class Win32_Product -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*RustDesk*" }
            foreach ($product in $msiProducts) {
                Write-Log "Uninstalling MSI: $($product.Name)" -Level "INFO"
                $product.Uninstall() | Out-Null
            }
        } catch {
            Write-Log "MSI uninstall failed or not applicable" -Level "DEBUG"
        }
    }

    # Phase 4: Registry-based uninstall
    Write-Log "${prefix}Phase 4: Registry-based uninstall..." -Level "INFO"
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    foreach ($path in $uninstallPaths) {
        if (Test-Path $path) {
            Get-ChildItem -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
                $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                if ($props.DisplayName -like "*RustDesk*") {
                    $uninstallString = if ($props.QuietUninstallString) { $props.QuietUninstallString } else { $props.UninstallString }
                    if ($uninstallString) {
                        Write-Log "${prefix}Running uninstaller for: $($props.DisplayName)" -Level "INFO"
                        if (-not $WhatIf) {
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
    }

    if (-not $WhatIf) { Start-Sleep -Seconds 3 }

    # Phase 5: Delete services
    Write-Log "${prefix}Phase 5: Deleting RustDesk services..." -Level "INFO"
    if (-not $WhatIf) {
        foreach ($svcName in $serviceNames) {
            if (Get-Service -Name $svcName -ErrorAction SilentlyContinue) {
                sc.exe delete $svcName 2>&1 | Out-Null
            }
        }
    }

    # Phase 6: Remove files and folders (including .rustdesk)
    Write-Log "${prefix}Phase 6: Removing RustDesk files..." -Level "INFO"
    $foldersToRemove = @(
        "$env:ProgramFiles\RustDesk",
        "${env:ProgramFiles(x86)}\RustDesk",
        "$env:ProgramData\RustDesk",
        "$env:LOCALAPPDATA\RustDesk",
        "$env:APPDATA\RustDesk",
        "$env:PUBLIC\Documents\RustDesk"
    )

    # Add user profile folders including .rustdesk
    Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $foldersToRemove += "$($_.FullName)\AppData\Local\RustDesk"
        $foldersToRemove += "$($_.FullName)\AppData\Roaming\RustDesk"
        $foldersToRemove += "$($_.FullName)\.rustdesk"
    }

    foreach ($folder in ($foldersToRemove | Select-Object -Unique)) {
        if (Test-Path $folder) {
            Write-Log "${prefix}Removing folder: $folder" -Level "INFO"
            if (-not $WhatIf) { Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    # Remove shortcuts
    $shortcutPatterns = @(
        "$env:PUBLIC\Desktop\RustDesk*.lnk",
        "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\RustDesk*.lnk",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\RustDesk*.lnk"
    )
    Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $shortcutPatterns += "$($_.FullName)\Desktop\RustDesk*.lnk"
        $shortcutPatterns += "$($_.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\RustDesk*.lnk"
    }
    foreach ($pattern in $shortcutPatterns) {
        Get-Item -Path $pattern -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Log "${prefix}Removing shortcut: $($_.FullName)" -Level "DEBUG"
            if (-not $WhatIf) { Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue }
        }
    }

    # Phase 7: Clean registry
    Write-Log "${prefix}Phase 7: Cleaning RustDesk registry..." -Level "INFO"
    $regKeys = @(
        "HKLM:\SOFTWARE\RustDesk",
        "HKLM:\SOFTWARE\WOW6432Node\RustDesk",
        "HKCU:\SOFTWARE\RustDesk"
    )
    foreach ($key in $regKeys) {
        if (Test-Path $key) {
            Write-Log "${prefix}Removing registry: $key" -Level "DEBUG"
            if (-not $WhatIf) { Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    # Phase 8: Firewall and scheduled tasks
    Write-Log "${prefix}Phase 8: Cleaning firewall and tasks..." -Level "INFO"
    if (-not $WhatIf) {
        Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*RustDesk*" } | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like "*RustDesk*" } | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
    }
}

#endregion Tool-Specific Removal Functions

function Remove-RAT {
    <#
    .SYNOPSIS
        Removes a detected RAT from the system using tool-specific or generic removal.
    #>
    param([hashtable]$Detection)

    $result = @{
        Name = $Detection.Name
        Success = $false
        Message = ""
        ProcessesStopped = 0
        ServicesStopped = 0
        Uninstalled = 0
        FoldersRemoved = 0
        RegistryRemoved = 0
    }

    Write-Log "--- Removing $($Detection.Name) ---" -Level "ACTION"

    # Use tool-specific removal for known tools
    switch ($Detection.Name) {
        "AnyDesk" {
            Remove-AnyDesk-Specific
        }
        "TeamViewer" {
            Remove-TeamViewer-Specific
        }
        "Splashtop" {
            Remove-Splashtop-Specific
        }
        "RustDesk" {
            Remove-RustDesk-Specific
        }
        default {
            # Generic removal for other tools
            Write-Log "Using generic removal for $($Detection.Name)..." -Level "INFO"

            $ratDef = $Script:RATDefinitions | Where-Object { $_.Name -eq $Detection.Name }

            # Phase 1: Stop services
            if ($ratDef.Services) {
                $result.ServicesStopped = Remove-RATServices -Name $Detection.Name -ServicePatterns $ratDef.Services
            }

            # Phase 2: Stop processes
            if ($ratDef.Processes) {
                $result.ProcessesStopped = Remove-RATProcesses -Name $Detection.Name -ProcessPatterns $ratDef.Processes
            }

            if (-not $WhatIf) { Start-Sleep -Seconds 2 }

            # Phase 3: Run uninstallers
            if ($Detection.Software.Count -gt 0) {
                $result.Uninstalled = Remove-RATUninstall -Name $Detection.Name -Software $Detection.Software
            }

            if (-not $WhatIf) { Start-Sleep -Seconds 3 }

            # Phase 4: Delete services
            if ($ratDef.Services) {
                Remove-RATServices-Delete -Name $Detection.Name -ServicePatterns $ratDef.Services | Out-Null
            }

            # Phase 5: Remove folders
            $allFolders = @($Detection.Folders)
            $standardPaths = @(
                "$env:ProgramFiles\$($Detection.Name)",
                "${env:ProgramFiles(x86)}\$($Detection.Name)",
                "$env:ProgramData\$($Detection.Name)",
                "$env:LOCALAPPDATA\$($Detection.Name)",
                "$env:APPDATA\$($Detection.Name)"
            )
            foreach ($path in $standardPaths) {
                if ((Test-Path $path) -and ($path -notin $allFolders)) {
                    $allFolders += $path
                }
            }
            $result.FoldersRemoved = Remove-RATFolders -Name $Detection.Name -Folders $allFolders

            # Phase 6: Clean registry
            $result.RegistryRemoved = Remove-RATRegistry -Name $Detection.Name

            # Phase 7: Firewall and scheduled tasks
            Remove-RATFirewallRules -Name $Detection.Name | Out-Null
            Remove-RATScheduledTasks -Name $Detection.Name | Out-Null
        }
    }

    # Verify removal
    if (-not $WhatIf) {
        Start-Sleep -Seconds 2

        $ratDef = $Script:RATDefinitions | Where-Object { $_.Name -eq $Detection.Name }
        $stillRunning = $false
        foreach ($pattern in $ratDef.Processes) {
            if (Get-Process -Name $pattern -ErrorAction SilentlyContinue) {
                $stillRunning = $true
                break
            }
        }

        if ($stillRunning) {
            $result.Message = "Some processes still running"
            $result.Success = $false
        } else {
            $result.Message = "Removed successfully"
            $result.Success = $true
        }
    } else {
        $result.Success = $true
        $result.Message = "Would be removed (WhatIf)"
    }

    return $result
}

#endregion Removal Functions

#region Main Execution

$ErrorActionPreference = "SilentlyContinue"

Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "  Remove All RATs - Standalone Script" -ForegroundColor Cyan
Write-Host "  Comprehensive Remote Access Tool Removal" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""

# Initialize logging
$logFile = Initialize-Log -CustomPath $LogPath

Write-Log "=== Remove All RATs - Standalone Script ===" -Level "INFO"
Write-Log "Mode: $(if ($WhatIf) { 'WhatIf (Dry-Run)' } elseif ($Force) { 'Force (Automated)' } else { 'Interactive' })" -Level "INFO"
Write-Log "Log file: $logFile" -Level "INFO"

# Check for Administrator privileges
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Log "This script requires Administrator privileges" -Level "ERROR"
    Write-Host ""
    Write-Host "Please run this script as Administrator." -ForegroundColor Red
    exit 1
}

Write-Log "Computer: $env:COMPUTERNAME" -Level "INFO"
Write-Host ""

# === DETECTION PHASE ===
$detections = Invoke-RATScan

Write-Host ""
Write-Log "=== DETECTION SUMMARY ===" -Level "INFO"

if ($detections.Count -eq 0) {
    Write-Log "No unauthorized remote access tools detected!" -Level "SUCCESS"
    Write-Log "Log file: $logFile" -Level "INFO"
    exit 0
}

# Categorize detections
$criticalDetections = $detections | Where-Object { $_.Malicious }
$highDetections = $detections | Where-Object { $_.Priority -eq "High" -and -not $_.Malicious }
$otherDetections = $detections | Where-Object { $_.Priority -notin @("High", "Critical") -and -not $_.Malicious }

Write-Log "Total RATs detected: $($detections.Count)" -Level "WARN"
if ($criticalDetections.Count -gt 0) {
    Write-Log "  CRITICAL (Malicious): $($criticalDetections.Count)" -Level "CRITICAL"
}
if ($highDetections.Count -gt 0) {
    Write-Log "  High Priority: $($highDetections.Count)" -Level "WARN"
}
if ($otherDetections.Count -gt 0) {
    Write-Log "  Other: $($otherDetections.Count)" -Level "INFO"
}

Write-Host ""

# Handle ScreenConnect verification
$screenConnectDetection = $detections | Where-Object { $_.Name -eq "ScreenConnect" }
if ($screenConnectDetection) {
    $detectedInstanceId = Get-ScreenConnectInstanceId

    Write-Log "=== SCREENCONNECT VERIFICATION ===" -Level "ACTION"

    if ($detectedInstanceId) {
        Write-Log "Detected ScreenConnect Instance ID: $detectedInstanceId" -Level "INFO"

        if ($ScreenConnectInstanceId -and $detectedInstanceId -eq $ScreenConnectInstanceId) {
            Write-Log "Instance ID matches pre-authorized ID - SKIPPING removal" -Level "SUCCESS"
            $detections = $detections | Where-Object { $_.Name -ne "ScreenConnect" }
        }
        elseif ($IncludeScreenConnect) {
            Write-Log "IncludeScreenConnect flag set - will remove ALL ScreenConnect instances" -Level "WARN"
        }
        elseif (-not $Force -and -not $WhatIf) {
            Write-Host ""
            Write-Host "  Detected ScreenConnect Instance ID: " -NoNewline -ForegroundColor Yellow
            Write-Host $detectedInstanceId -ForegroundColor White
            Write-Host ""
            Write-Host "  Is this YOUR authorized ScreenConnect instance?" -ForegroundColor Cyan
            Write-Host "  [Y] Yes, KEEP this instance (skip removal)" -ForegroundColor Green
            Write-Host "  [N] No, REMOVE this instance" -ForegroundColor Red
            Write-Host "  [?] I don't know (skip for now)" -ForegroundColor Gray
            Write-Host ""

            $response = Read-Host "  Your choice [Y/N/?]"

            if ($response -eq 'Y' -or $response -eq 'y') {
                Write-Log "User confirmed ScreenConnect instance is authorized - SKIPPING" -Level "SUCCESS"
                $detections = $detections | Where-Object { $_.Name -ne "ScreenConnect" }
            }
            elseif ($response -eq 'N' -or $response -eq 'n') {
                Write-Log "User confirmed ScreenConnect instance is UNAUTHORIZED - will remove" -Level "WARN"
            }
            else {
                Write-Log "User unsure about ScreenConnect - SKIPPING for safety" -Level "INFO"
                $detections = $detections | Where-Object { $_.Name -ne "ScreenConnect" }
            }
        }
    } else {
        Write-Log "Could not determine ScreenConnect instance ID" -Level "WARN"
        if (-not $Force -and -not $WhatIf -and -not $IncludeScreenConnect) {
            Write-Host ""
            $response = Read-Host "  Remove ScreenConnect anyway? [Y/N]"
            if ($response -ne 'Y' -and $response -ne 'y') {
                $detections = $detections | Where-Object { $_.Name -ne "ScreenConnect" }
            }
        }
    }

    Write-Host ""
}

# Check if anything left to remove
if ($detections.Count -eq 0) {
    Write-Log "No RATs to remove after filtering." -Level "SUCCESS"
    Write-Log "Log file: $logFile" -Level "INFO"
    exit 0
}

# Show action plan
Write-Log "=== ACTION PLAN ===" -Level "ACTION"
foreach ($detection in $detections) {
    $level = if ($detection.Malicious) { "CRITICAL" } elseif ($detection.Priority -eq "High") { "WARN" } else { "INFO" }
    Write-Log "  Will remove: $($detection.Name)" -Level $level
}

Write-Host ""

# Confirmation
if (-not $WhatIf -and -not $Force) {
    Write-Host "Proceed with removal of $($detections.Count) RAT(s)? " -NoNewline -ForegroundColor Yellow
    $response = Read-Host "[Y/N]"
    if ($response -ne 'Y' -and $response -ne 'y') {
        Write-Log "Removal cancelled by user" -Level "INFO"
        Write-Log "Log file: $logFile" -Level "INFO"
        exit 0
    }
}

if ($WhatIf) {
    Write-Log "=== WHATIF MODE - No changes will be made ===" -Level "INFO"
}

# === REMOVAL PHASE ===
Write-Host ""
Write-Log "=== REMOVAL PHASE ===" -Level "ACTION"

$results = @()
foreach ($detection in $detections) {
    $result = Remove-RAT -Detection $detection
    $results += $result

    if ($result.Success) {
        Write-Log "$($detection.Name): $($result.Message)" -Level "SUCCESS"
    } else {
        Write-Log "$($detection.Name): $($result.Message)" -Level "ERROR"
    }
}

# === SUMMARY ===
Write-Host ""
Write-Log "=== REMOVAL SUMMARY ===" -Level "INFO"

$successCount = ($results | Where-Object { $_.Success }).Count
$failCount = ($results | Where-Object { -not $_.Success }).Count

Write-Log "Successfully removed: $successCount" -Level $(if ($successCount -gt 0) { "SUCCESS" } else { "INFO" })
Write-Log "Failed to remove: $failCount" -Level $(if ($failCount -gt 0) { "ERROR" } else { "INFO" })

if ($failCount -gt 0) {
    Write-Host ""
    Write-Log "Failed removals may require manual intervention or a reboot:" -Level "WARN"
    foreach ($result in ($results | Where-Object { -not $_.Success })) {
        Write-Host "  - $($result.Name): $($result.Message)" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Log "Log file saved to: $logFile" -Level "INFO"

if ($WhatIf) {
    # WhatIf mode: return 1 if RATs were found (to trigger removal prompt in launcher)
    if ($detections.Count -gt 0) { exit 1 } else { exit 0 }
} elseif ($failCount -gt 0) {
    exit 1
} else {
    exit 0
}

#endregion Main Execution
