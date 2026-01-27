<#
.SYNOPSIS
    Security Baseline Checker - Comprehensive Windows security audit

.DESCRIPTION
    Performs comprehensive offline security checks including:
    - Windows Defender status and exclusions audit
    - Firewall status (all profiles)
    - UAC configuration
    - Suspicious user accounts
    - Keylogger indicators (hooks, processes, drivers)
    - SMBv1, RDP, Secure Boot, BitLocker status
    - DNS hijacking detection
    - Hosts file tampering
    - Proxy settings audit
    - Rogue root certificate detection
    - LSA Protection and Credential Guard status
    - WDigest plaintext password check
    - WMI persistence subscriptions
    - IFEO debugger hijacking
    - AppInit_DLLs injection
    - Volume Shadow Copy status (ransomware indicator)
    - Windows Recovery Environment status
    - Scheduled tasks audit
    - Startup items audit

.PARAMETER OutputPath
    Path for the report file. Defaults to script directory.

.PARAMETER JsonOutput
    Also output results as JSON for programmatic parsing.

.EXAMPLE
    .\Check-SecurityBaseline.ps1
    .\Check-SecurityBaseline.ps1 -OutputPath "C:\Reports"

.NOTES
    Version: 1.0.0
    Requires: Administrator privileges
    Runs offline - no internet required
#>

param(
    [string]$OutputPath = "",
    [switch]$JsonOutput
)

#region Initialization
$ErrorActionPreference = "SilentlyContinue"
$ScriptVersion = "1.0.0"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if ([string]::IsNullOrEmpty($OutputPath)) {
    $OutputPath = $ScriptDir
}

# Generate timestamp
$Timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$ReportFile = Join-Path $OutputPath "SecurityBaseline-$Timestamp.txt"
$JsonFile = Join-Path $OutputPath "SecurityBaseline-$Timestamp.json"

# Results collection
$Results = @{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    ComputerName = $env:COMPUTERNAME
    Checks = @()
    Summary = @{
        Pass = 0
        Warning = 0
        Fail = 0
        Info = 0
    }
}

#endregion

#region Helper Functions

function Write-Report {
    param(
        [string]$Message,
        [string]$Status = "INFO",
        [switch]$NoNewline
    )

    $StatusColors = @{
        "PASS" = "Green"
        "FAIL" = "Red"
        "WARNING" = "Yellow"
        "INFO" = "Cyan"
        "HEADER" = "White"
    }

    $Color = $StatusColors[$Status]
    if (-not $Color) { $Color = "White" }

    if ($Status -eq "HEADER") {
        Write-Host $Message -ForegroundColor $Color
        Add-Content -Path $ReportFile -Value $Message
    } else {
        $Line = "[$Status] $Message"
        Write-Host $Line -ForegroundColor $Color -NoNewline:$NoNewline
        if (-not $NoNewline) {
            Add-Content -Path $ReportFile -Value $Line
        }
    }
}

function Add-CheckResult {
    param(
        [string]$Category,
        [string]$Check,
        [string]$Status,
        [string]$Details,
        [string]$Remediation = ""
    )

    $Results.Checks += @{
        Category = $Category
        Check = $Check
        Status = $Status
        Details = $Details
        Remediation = $Remediation
    }

    switch ($Status) {
        "PASS" { $Results.Summary.Pass++ }
        "WARNING" { $Results.Summary.Warning++ }
        "FAIL" { $Results.Summary.Fail++ }
        default { $Results.Summary.Info++ }
    }

    Write-Report -Message "$Check - $Details" -Status $Status
    if ($Remediation -and $Status -ne "PASS") {
        Write-Report -Message "  Remediation: $Remediation" -Status "INFO"
    }
}

#endregion

#region Admin Check
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Red
    Write-Host "   ADMINISTRATOR PRIVILEGES REQUIRED" -ForegroundColor Red
    Write-Host "  ============================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "   Right-click this script and select 'Run as administrator'" -ForegroundColor Yellow
    Write-Host ""
    exit 1
}
#endregion

#region Main Script

# Initialize report file
@"
================================================================================
SECURITY BASELINE CHECK REPORT
================================================================================
Generated: $($Results.Timestamp)
Computer:  $($Results.ComputerName)
Tool Ver:  $ScriptVersion
================================================================================

"@ | Set-Content -Path $ReportFile

Write-Host ""
Write-Host "  ================================================================================" -ForegroundColor Cyan
Write-Host "                    SECURITY BASELINE CHECK" -ForegroundColor Cyan
Write-Host "  ================================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Report will be saved to: $ReportFile" -ForegroundColor Gray
Write-Host ""

# ============================================================================
# SECTION 1: WINDOWS DEFENDER
# ============================================================================
Write-Report -Message "`n=== WINDOWS DEFENDER ===" -Status "HEADER"

try {
    $DefenderStatus = Get-MpComputerStatus -ErrorAction Stop

    # Real-time protection
    if ($DefenderStatus.RealTimeProtectionEnabled) {
        Add-CheckResult -Category "Defender" -Check "Real-time Protection" -Status "PASS" -Details "Enabled"
    } else {
        Add-CheckResult -Category "Defender" -Check "Real-time Protection" -Status "FAIL" -Details "DISABLED" -Remediation "Set-MpPreference -DisableRealtimeMonitoring `$false"
    }

    # Antivirus enabled
    if ($DefenderStatus.AntivirusEnabled) {
        Add-CheckResult -Category "Defender" -Check "Antivirus" -Status "PASS" -Details "Enabled"
    } else {
        Add-CheckResult -Category "Defender" -Check "Antivirus" -Status "FAIL" -Details "DISABLED" -Remediation "Enable Windows Defender via Windows Security"
    }

    # Signature age
    $SigAge = $DefenderStatus.AntivirusSignatureAge
    if ($SigAge -le 1) {
        Add-CheckResult -Category "Defender" -Check "Signature Age" -Status "PASS" -Details "$SigAge day(s) old"
    } elseif ($SigAge -le 7) {
        Add-CheckResult -Category "Defender" -Check "Signature Age" -Status "WARNING" -Details "$SigAge days old" -Remediation "Update-MpSignature"
    } else {
        Add-CheckResult -Category "Defender" -Check "Signature Age" -Status "FAIL" -Details "$SigAge days old - OUTDATED" -Remediation "Update-MpSignature"
    }

    # Tamper protection
    if ($DefenderStatus.IsTamperProtected) {
        Add-CheckResult -Category "Defender" -Check "Tamper Protection" -Status "PASS" -Details "Enabled"
    } else {
        Add-CheckResult -Category "Defender" -Check "Tamper Protection" -Status "WARNING" -Details "Disabled" -Remediation "Enable via Windows Security > Virus & threat protection settings"
    }

    # Behavior monitoring
    if ($DefenderStatus.BehaviorMonitorEnabled) {
        Add-CheckResult -Category "Defender" -Check "Behavior Monitoring" -Status "PASS" -Details "Enabled"
    } else {
        Add-CheckResult -Category "Defender" -Check "Behavior Monitoring" -Status "WARNING" -Details "Disabled" -Remediation "Set-MpPreference -DisableBehaviorMonitoring `$false"
    }

} catch {
    Add-CheckResult -Category "Defender" -Check "Windows Defender" -Status "FAIL" -Details "Cannot query status - may not be installed or accessible"
}

# ============================================================================
# SECTION 2: DEFENDER EXCLUSIONS AUDIT
# ============================================================================
Write-Report -Message "`n=== DEFENDER EXCLUSIONS AUDIT ===" -Status "HEADER"

try {
    $Prefs = Get-MpPreference -ErrorAction Stop

    # Suspicious exclusion patterns
    $SuspiciousPatterns = @(
        "C:\\$",                    # Entire C: drive
        "C:\\Windows$",            # Windows folder
        "C:\\Users$",              # All users
        "\\AppData\\",             # AppData (common malware location)
        "\\Temp\\",                # Temp folders
        "\\Downloads\\",           # Downloads folder
        "\.exe$",                  # All EXE files
        "\.dll$",                  # All DLL files
        "\.ps1$",                  # All PowerShell scripts
        "\.bat$",                  # All batch files
        "\.cmd$",                  # All cmd files
        "\.vbs$",                  # All VBScript files
        "\.js$"                    # All JavaScript files
    )

    # Path exclusions
    $PathExclusions = $Prefs.ExclusionPath
    if ($PathExclusions -and $PathExclusions.Count -gt 0) {
        Write-Report -Message "  Path Exclusions ($($PathExclusions.Count) found):" -Status "INFO"
        foreach ($Path in $PathExclusions) {
            $IsSuspicious = $false
            foreach ($Pattern in $SuspiciousPatterns) {
                if ($Path -match $Pattern) {
                    $IsSuspicious = $true
                    break
                }
            }

            if ($IsSuspicious) {
                Add-CheckResult -Category "Exclusions" -Check "Path Exclusion" -Status "WARNING" -Details "SUSPICIOUS: $Path" -Remediation "Remove-MpPreference -ExclusionPath '$Path'"
            } else {
                Add-CheckResult -Category "Exclusions" -Check "Path Exclusion" -Status "INFO" -Details $Path
            }
        }
    } else {
        Add-CheckResult -Category "Exclusions" -Check "Path Exclusions" -Status "PASS" -Details "None configured"
    }

    # Process exclusions
    $ProcessExclusions = $Prefs.ExclusionProcess
    if ($ProcessExclusions -and $ProcessExclusions.Count -gt 0) {
        Write-Report -Message "  Process Exclusions ($($ProcessExclusions.Count) found):" -Status "INFO"
        foreach ($Proc in $ProcessExclusions) {
            # Flag any process exclusion as worth reviewing
            Add-CheckResult -Category "Exclusions" -Check "Process Exclusion" -Status "WARNING" -Details "Review: $Proc" -Remediation "Remove-MpPreference -ExclusionProcess '$Proc'"
        }
    } else {
        Add-CheckResult -Category "Exclusions" -Check "Process Exclusions" -Status "PASS" -Details "None configured"
    }

    # Extension exclusions
    $ExtExclusions = $Prefs.ExclusionExtension
    if ($ExtExclusions -and $ExtExclusions.Count -gt 0) {
        Write-Report -Message "  Extension Exclusions ($($ExtExclusions.Count) found):" -Status "INFO"
        $DangerousExts = @("exe", "dll", "ps1", "bat", "cmd", "vbs", "js", "scr", "com", "msi")
        foreach ($Ext in $ExtExclusions) {
            $ExtClean = $Ext.TrimStart(".")
            if ($DangerousExts -contains $ExtClean.ToLower()) {
                Add-CheckResult -Category "Exclusions" -Check "Extension Exclusion" -Status "FAIL" -Details "DANGEROUS: .$ExtClean excluded" -Remediation "Remove-MpPreference -ExclusionExtension '$Ext'"
            } else {
                Add-CheckResult -Category "Exclusions" -Check "Extension Exclusion" -Status "WARNING" -Details ".$ExtClean" -Remediation "Remove-MpPreference -ExclusionExtension '$Ext'"
            }
        }
    } else {
        Add-CheckResult -Category "Exclusions" -Check "Extension Exclusions" -Status "PASS" -Details "None configured"
    }

    # Check for hidden exclusions (attacker technique)
    $HideExclusions = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "HideExclusionsFromLocalAdmins" -ErrorAction SilentlyContinue
    if ($HideExclusions -and $HideExclusions.HideExclusionsFromLocalAdmins -eq 1) {
        Add-CheckResult -Category "Exclusions" -Check "Hidden Exclusions" -Status "FAIL" -Details "ATTACK INDICATOR: Exclusions are hidden from admins!" -Remediation "Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name 'HideExclusionsFromLocalAdmins'"
    }

} catch {
    Add-CheckResult -Category "Exclusions" -Check "Exclusions Audit" -Status "WARNING" -Details "Cannot query exclusions: $_"
}

# ============================================================================
# SECTION 3: FIREWALL STATUS
# ============================================================================
Write-Report -Message "`n=== WINDOWS FIREWALL ===" -Status "HEADER"

$FirewallProfiles = @("Domain", "Private", "Public")
foreach ($Profile in $FirewallProfiles) {
    try {
        $FwProfile = Get-NetFirewallProfile -Name $Profile -ErrorAction Stop
        if ($FwProfile.Enabled) {
            Add-CheckResult -Category "Firewall" -Check "$Profile Profile" -Status "PASS" -Details "Enabled"
        } else {
            Add-CheckResult -Category "Firewall" -Check "$Profile Profile" -Status "FAIL" -Details "DISABLED" -Remediation "Set-NetFirewallProfile -Profile $Profile -Enabled True"
        }
    } catch {
        Add-CheckResult -Category "Firewall" -Check "$Profile Profile" -Status "WARNING" -Details "Cannot query"
    }
}

# ============================================================================
# SECTION 4: UAC CONFIGURATION
# ============================================================================
Write-Report -Message "`n=== USER ACCOUNT CONTROL (UAC) ===" -Status "HEADER"

try {
    $UACKey = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction Stop

    # EnableLUA - UAC enabled
    if ($UACKey.EnableLUA -eq 1) {
        Add-CheckResult -Category "UAC" -Check "UAC Enabled" -Status "PASS" -Details "Yes"
    } else {
        Add-CheckResult -Category "UAC" -Check "UAC Enabled" -Status "FAIL" -Details "DISABLED - Major security risk!" -Remediation "Set EnableLUA to 1 in registry"
    }

    # ConsentPromptBehaviorAdmin - 0=Elevate without prompting, 1=Prompt for creds on secure desktop, 2=Prompt for consent on secure desktop, 3=Prompt for creds, 4=Prompt for consent, 5=Prompt for consent for non-Windows binaries
    $UACLevel = $UACKey.ConsentPromptBehaviorAdmin
    $UACLevelDesc = switch ($UACLevel) {
        0 { "Elevate without prompting (INSECURE)" }
        1 { "Prompt for credentials on secure desktop" }
        2 { "Prompt for consent on secure desktop (Recommended)" }
        3 { "Prompt for credentials" }
        4 { "Prompt for consent" }
        5 { "Prompt for consent for non-Windows binaries (Default)" }
        default { "Unknown ($UACLevel)" }
    }

    if ($UACLevel -eq 0) {
        Add-CheckResult -Category "UAC" -Check "UAC Prompt Level" -Status "FAIL" -Details $UACLevelDesc -Remediation "Set ConsentPromptBehaviorAdmin to 2 or higher"
    } elseif ($UACLevel -ge 2) {
        Add-CheckResult -Category "UAC" -Check "UAC Prompt Level" -Status "PASS" -Details $UACLevelDesc
    } else {
        Add-CheckResult -Category "UAC" -Check "UAC Prompt Level" -Status "WARNING" -Details $UACLevelDesc
    }

} catch {
    Add-CheckResult -Category "UAC" -Check "UAC Status" -Status "WARNING" -Details "Cannot query UAC settings"
}

# ============================================================================
# SECTION 5: USER ACCOUNTS AUDIT
# ============================================================================
Write-Report -Message "`n=== USER ACCOUNTS AUDIT ===" -Status "HEADER"

try {
    # Guest account
    $GuestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($GuestAccount) {
        if ($GuestAccount.Enabled) {
            Add-CheckResult -Category "Accounts" -Check "Guest Account" -Status "WARNING" -Details "ENABLED" -Remediation "Disable-LocalUser -Name 'Guest'"
        } else {
            Add-CheckResult -Category "Accounts" -Check "Guest Account" -Status "PASS" -Details "Disabled"
        }
    }

    # Administrator account
    $AdminAccount = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
    if ($AdminAccount -and $AdminAccount.Enabled) {
        Add-CheckResult -Category "Accounts" -Check "Built-in Administrator" -Status "WARNING" -Details "Enabled - consider disabling if not needed" -Remediation "Disable-LocalUser -Name 'Administrator'"
    } else {
        Add-CheckResult -Category "Accounts" -Check "Built-in Administrator" -Status "PASS" -Details "Disabled or renamed"
    }

    # List all admin users
    $AdminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    if ($AdminGroup) {
        Write-Report -Message "  Administrator Group Members:" -Status "INFO"
        foreach ($Member in $AdminGroup) {
            $MemberInfo = "$($Member.Name) ($($Member.ObjectClass))"
            Add-CheckResult -Category "Accounts" -Check "Admin Member" -Status "INFO" -Details $MemberInfo
        }
    }

    # Check for recently created accounts (last 30 days)
    $RecentAccounts = Get-LocalUser | Where-Object {
        $_.PasswordLastSet -and
        $_.PasswordLastSet -gt (Get-Date).AddDays(-30)
    }
    if ($RecentAccounts) {
        Write-Report -Message "  Recently Modified Accounts (last 30 days):" -Status "INFO"
        foreach ($Account in $RecentAccounts) {
            Add-CheckResult -Category "Accounts" -Check "Recent Account" -Status "WARNING" -Details "$($Account.Name) - Modified: $($Account.PasswordLastSet)"
        }
    }

} catch {
    Add-CheckResult -Category "Accounts" -Check "Account Audit" -Status "WARNING" -Details "Cannot enumerate accounts: $_"
}

# ============================================================================
# SECTION 6: KEYLOGGER INDICATORS
# ============================================================================
Write-Report -Message "`n=== KEYLOGGER INDICATORS ===" -Status "HEADER"

# Known keylogger process names
$KnownKeyloggers = @(
    "keylogger", "klogger", "keygrabber", "keystroke",
    "revealer", "rvlkl", "actualspy", "spyagent",
    "spector", "refog", "ardamax", "kidlogger",
    "bestlogger", "shadowkeylogger", "perfectkeylogger",
    "familykeylogger", "homestealth", "spyrix",
    "iwantsoft", "micro_keylogger", "elite_keylogger",
    "realtime-spy", "webwatcher", "spytech",
    "net_keylogger", "ghost_keylogger"
)

Write-Report -Message "  Checking for known keylogger processes..." -Status "INFO"
$RunningProcesses = Get-Process | Select-Object Name, Id, Path

$KeyloggerFound = $false
foreach ($Proc in $RunningProcesses) {
    $ProcLower = $Proc.Name.ToLower()
    foreach ($KL in $KnownKeyloggers) {
        if ($ProcLower -like "*$KL*") {
            Add-CheckResult -Category "Keylogger" -Check "Suspicious Process" -Status "FAIL" -Details "POTENTIAL KEYLOGGER: $($Proc.Name) (PID: $($Proc.Id)) - Path: $($Proc.Path)"
            $KeyloggerFound = $true
        }
    }
}

if (-not $KeyloggerFound) {
    Add-CheckResult -Category "Keylogger" -Check "Known Keylogger Processes" -Status "PASS" -Details "None detected"
}

# Check for processes with keyboard hook capabilities (SetWindowsHookEx indicators)
Write-Report -Message "  Checking for processes loaded in multiple contexts (hook indicator)..." -Status "INFO"

# Look for suspicious DLLs that might be injected
$SuspiciousDLLs = @(
    "hook.dll", "keyhook.dll", "kbhook.dll", "keyboard.dll",
    "logger.dll", "capture.dll", "monitor.dll", "spy.dll"
)

$LoadedModules = Get-Process | ForEach-Object {
    try {
        $_.Modules | Select-Object ModuleName, FileName
    } catch {}
} | Where-Object { $_.ModuleName }

$HookDLLFound = $false
foreach ($Module in $LoadedModules) {
    $ModLower = $Module.ModuleName.ToLower()
    foreach ($DLL in $SuspiciousDLLs) {
        if ($ModLower -like "*$DLL*") {
            Add-CheckResult -Category "Keylogger" -Check "Suspicious DLL" -Status "WARNING" -Details "POTENTIAL HOOK DLL: $($Module.ModuleName) - $($Module.FileName)"
            $HookDLLFound = $true
        }
    }
}

if (-not $HookDLLFound) {
    Add-CheckResult -Category "Keylogger" -Check "Suspicious Hook DLLs" -Status "PASS" -Details "None detected"
}

# Check for keyboard filter drivers (kernel-level keyloggers)
Write-Report -Message "  Checking keyboard filter drivers..." -Status "INFO"

$KbdDrivers = Get-WmiObject Win32_SystemDriver | Where-Object {
    $_.DisplayName -like "*keyboard*" -or
    $_.Name -like "*kbd*" -or
    $_.PathName -like "*kbfiltr*"
}

$StandardKbdDrivers = @("kbdclass", "kbdhid", "i8042prt")
foreach ($Driver in $KbdDrivers) {
    if ($StandardKbdDrivers -contains $Driver.Name.ToLower()) {
        Add-CheckResult -Category "Keylogger" -Check "Keyboard Driver" -Status "PASS" -Details "$($Driver.Name) (Standard Windows driver)"
    } else {
        Add-CheckResult -Category "Keylogger" -Check "Keyboard Driver" -Status "WARNING" -Details "NON-STANDARD: $($Driver.Name) - $($Driver.PathName)" -Remediation "Investigate this driver"
    }
}

# ============================================================================
# SECTION 7: ADDITIONAL SECURITY CHECKS
# ============================================================================
Write-Report -Message "`n=== ADDITIONAL SECURITY CHECKS ===" -Status "HEADER"

# SMBv1 Status
try {
    $SMBv1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    if ($SMBv1 -and $SMBv1.State -eq "Enabled") {
        Add-CheckResult -Category "Security" -Check "SMBv1 Protocol" -Status "FAIL" -Details "ENABLED - Vulnerable to EternalBlue" -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"
    } else {
        Add-CheckResult -Category "Security" -Check "SMBv1 Protocol" -Status "PASS" -Details "Disabled"
    }
} catch {
    # Try alternative method
    $SMBv1Server = Get-SmbServerConfiguration -ErrorAction SilentlyContinue | Select-Object EnableSMB1Protocol
    if ($SMBv1Server -and $SMBv1Server.EnableSMB1Protocol) {
        Add-CheckResult -Category "Security" -Check "SMBv1 Protocol" -Status "FAIL" -Details "ENABLED" -Remediation "Set-SmbServerConfiguration -EnableSMB1Protocol `$false"
    } else {
        Add-CheckResult -Category "Security" -Check "SMBv1 Protocol" -Status "PASS" -Details "Disabled or not applicable"
    }
}

# RDP Status
try {
    $RDPKey = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction Stop
    if ($RDPKey.fDenyTSConnections -eq 0) {
        # RDP is enabled - check NLA
        $NLAKey = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue
        if ($NLAKey -and $NLAKey.UserAuthentication -eq 1) {
            Add-CheckResult -Category "Security" -Check "Remote Desktop" -Status "WARNING" -Details "Enabled with NLA (Network Level Authentication)" -Remediation "Disable if not needed"
        } else {
            Add-CheckResult -Category "Security" -Check "Remote Desktop" -Status "FAIL" -Details "Enabled WITHOUT NLA - vulnerable!" -Remediation "Enable NLA or disable RDP"
        }
    } else {
        Add-CheckResult -Category "Security" -Check "Remote Desktop" -Status "PASS" -Details "Disabled"
    }
} catch {
    Add-CheckResult -Category "Security" -Check "Remote Desktop" -Status "INFO" -Details "Cannot determine status"
}

# Secure Boot
try {
    $SecureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
    if ($SecureBoot) {
        Add-CheckResult -Category "Security" -Check "Secure Boot" -Status "PASS" -Details "Enabled"
    } else {
        Add-CheckResult -Category "Security" -Check "Secure Boot" -Status "WARNING" -Details "Disabled" -Remediation "Enable in BIOS/UEFI if supported"
    }
} catch {
    Add-CheckResult -Category "Security" -Check "Secure Boot" -Status "INFO" -Details "Not supported or cannot determine (Legacy BIOS?)"
}

# BitLocker
try {
    $BitLocker = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
    if ($BitLocker.ProtectionStatus -eq "On") {
        Add-CheckResult -Category "Security" -Check "BitLocker (C:)" -Status "PASS" -Details "Enabled and protecting"
    } else {
        Add-CheckResult -Category "Security" -Check "BitLocker (C:)" -Status "WARNING" -Details "Not enabled" -Remediation "Enable-BitLocker -MountPoint 'C:'"
    }
} catch {
    Add-CheckResult -Category "Security" -Check "BitLocker (C:)" -Status "INFO" -Details "Not available or cannot determine"
}

# PowerShell Execution Policy
$ExecPolicy = Get-ExecutionPolicy
if ($ExecPolicy -eq "Unrestricted" -or $ExecPolicy -eq "Bypass") {
    Add-CheckResult -Category "Security" -Check "PowerShell Execution Policy" -Status "WARNING" -Details "$ExecPolicy - allows unsigned scripts" -Remediation "Set-ExecutionPolicy RemoteSigned"
} else {
    Add-CheckResult -Category "Security" -Check "PowerShell Execution Policy" -Status "PASS" -Details $ExecPolicy
}

# PowerShell Script Block Logging
$ScriptBlockLog = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
if ($ScriptBlockLog -and $ScriptBlockLog.EnableScriptBlockLogging -eq 1) {
    Add-CheckResult -Category "Security" -Check "PS Script Block Logging" -Status "PASS" -Details "Enabled"
} else {
    Add-CheckResult -Category "Security" -Check "PS Script Block Logging" -Status "WARNING" -Details "Disabled - recommended for forensics" -Remediation "Enable via Group Policy or registry"
}

# Windows Update
try {
    $LastUpdate = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($LastUpdate -and $LastUpdate.InstalledOn) {
        $DaysSinceUpdate = (New-TimeSpan -Start $LastUpdate.InstalledOn -End (Get-Date)).Days
        if ($DaysSinceUpdate -le 30) {
            Add-CheckResult -Category "Security" -Check "Windows Updates" -Status "PASS" -Details "Last update: $($LastUpdate.InstalledOn.ToString('yyyy-MM-dd')) ($DaysSinceUpdate days ago)"
        } elseif ($DaysSinceUpdate -le 60) {
            Add-CheckResult -Category "Security" -Check "Windows Updates" -Status "WARNING" -Details "Last update: $($LastUpdate.InstalledOn.ToString('yyyy-MM-dd')) ($DaysSinceUpdate days ago)"
        } else {
            Add-CheckResult -Category "Security" -Check "Windows Updates" -Status "FAIL" -Details "Last update: $($LastUpdate.InstalledOn.ToString('yyyy-MM-dd')) ($DaysSinceUpdate days ago) - OUTDATED"
        }
    }
} catch {
    Add-CheckResult -Category "Security" -Check "Windows Updates" -Status "INFO" -Details "Cannot determine last update"
}

# ============================================================================
# SECTION 8: NETWORK SECURITY (DNS, Hosts, Proxy)
# ============================================================================
Write-Report -Message "`n=== NETWORK SECURITY ===" -Status "HEADER"

# DNS Settings Check
Write-Report -Message "  Checking DNS settings..." -Status "INFO"

$NetworkAdapters = Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses }

# Known safe DNS servers
$SafeDNS = @(
    "8.8.8.8", "8.8.4.4",           # Google
    "1.1.1.1", "1.0.0.1",           # Cloudflare
    "9.9.9.9", "149.112.112.112",   # Quad9
    "208.67.222.222", "208.67.220.220",  # OpenDNS
    "127.0.0.1"                     # Localhost (common for VPNs/Pi-hole)
)

foreach ($Adapter in $NetworkAdapters) {
    foreach ($DNS in $Adapter.ServerAddresses) {
        # Skip link-local and private ranges that are likely internal
        if ($DNS -match "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|169\.254\.)") {
            Add-CheckResult -Category "Network" -Check "DNS Server" -Status "INFO" -Details "$($Adapter.InterfaceAlias): $DNS (Private/Internal)"
        } elseif ($SafeDNS -contains $DNS) {
            Add-CheckResult -Category "Network" -Check "DNS Server" -Status "PASS" -Details "$($Adapter.InterfaceAlias): $DNS (Known safe)"
        } else {
            Add-CheckResult -Category "Network" -Check "DNS Server" -Status "WARNING" -Details "$($Adapter.InterfaceAlias): $DNS (Unknown - verify this is expected)" -Remediation "Set-DnsClientServerAddress -InterfaceAlias '$($Adapter.InterfaceAlias)' -ServerAddresses '8.8.8.8','8.8.4.4'"
        }
    }
}

# Hosts File Check
Write-Report -Message "  Checking hosts file for suspicious entries..." -Status "INFO"

$HostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
if (Test-Path $HostsFile) {
    $HostsContent = Get-Content $HostsFile -ErrorAction SilentlyContinue

    # Known suspicious patterns in hosts file
    $SuspiciousHostPatterns = @(
        "google\.com", "microsoft\.com", "windows\.com", "windowsupdate\.com",
        "kaspersky", "norton", "mcafee", "avast", "avg\.com", "malwarebytes",
        "symantec", "eset\.com", "bitdefender", "sophos",
        "facebook\.com", "paypal\.com", "amazon\.com", "ebay\.com",
        "bank", "secure", "login", "account"
    )

    $SuspiciousHostEntries = @()
    foreach ($Line in $HostsContent) {
        $Line = $Line.Trim()
        # Skip comments and empty lines
        if ($Line -and -not $Line.StartsWith("#")) {
            foreach ($Pattern in $SuspiciousHostPatterns) {
                if ($Line -match $Pattern) {
                    $SuspiciousHostEntries += $Line
                    break
                }
            }
        }
    }

    if ($SuspiciousHostEntries.Count -gt 0) {
        foreach ($Entry in $SuspiciousHostEntries) {
            Add-CheckResult -Category "Network" -Check "Hosts File" -Status "FAIL" -Details "SUSPICIOUS ENTRY: $Entry" -Remediation "Review and remove from $HostsFile"
        }
    } else {
        # Count non-comment entries
        $EntryCount = ($HostsContent | Where-Object { $_ -and -not $_.Trim().StartsWith("#") -and $_.Trim() -ne "" }).Count
        Add-CheckResult -Category "Network" -Check "Hosts File" -Status "PASS" -Details "$EntryCount custom entries (no suspicious patterns)"
    }
} else {
    Add-CheckResult -Category "Network" -Check "Hosts File" -Status "WARNING" -Details "Cannot read hosts file"
}

# System Proxy Settings
Write-Report -Message "  Checking proxy settings..." -Status "INFO"

$ProxySettings = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
if ($ProxySettings.ProxyEnable -eq 1) {
    $ProxyServer = $ProxySettings.ProxyServer
    Add-CheckResult -Category "Network" -Check "System Proxy" -Status "WARNING" -Details "ENABLED: $ProxyServer" -Remediation "Verify this proxy is legitimate"
} else {
    Add-CheckResult -Category "Network" -Check "System Proxy" -Status "PASS" -Details "No system proxy configured"
}

# AutoConfig URL (PAC file)
if ($ProxySettings.AutoConfigURL) {
    Add-CheckResult -Category "Network" -Check "Proxy AutoConfig" -Status "WARNING" -Details "PAC URL: $($ProxySettings.AutoConfigURL)" -Remediation "Verify this PAC file is legitimate"
}

# ============================================================================
# SECTION 9: CERTIFICATE TRUST
# ============================================================================
Write-Report -Message "`n=== CERTIFICATE TRUST ===" -Status "HEADER"

Write-Report -Message "  Checking for suspicious root certificates..." -Status "INFO"

# Get non-Microsoft root certificates
$RootCerts = Get-ChildItem -Path Cert:\LocalMachine\Root

# Known legitimate third-party root CAs (partial list)
$KnownLegitCAs = @(
    "DigiCert", "GlobalSign", "Comodo", "GoDaddy", "Entrust", "Thawte",
    "VeriSign", "GeoTrust", "Symantec", "StartCom", "ISRG", "Let's Encrypt",
    "Amazon", "Google Trust", "Apple", "Sectigo", "QuoVadis", "IdenTrust"
)

$SuspiciousCerts = @()
foreach ($Cert in $RootCerts) {
    $Subject = $Cert.Subject
    $Issuer = $Cert.Issuer
    $Thumbprint = $Cert.Thumbprint

    # Check if it's a Microsoft cert
    $IsMicrosoft = $Subject -like "*Microsoft*" -or $Issuer -like "*Microsoft*"

    # Check if it's a known legitimate CA
    $IsKnownLegit = $false
    foreach ($CA in $KnownLegitCAs) {
        if ($Subject -like "*$CA*" -or $Issuer -like "*$CA*") {
            $IsKnownLegit = $true
            break
        }
    }

    # Flag self-signed certs that aren't from known CAs
    $IsSelfSigned = $Subject -eq $Issuer

    if (-not $IsMicrosoft -and -not $IsKnownLegit) {
        # Check for known malicious patterns
        $MaliciousPatterns = @("Superfish", "eDellRoot", "PrivDog", "Komodia", "MITM")
        $IsMalicious = $false
        foreach ($Pattern in $MaliciousPatterns) {
            if ($Subject -like "*$Pattern*" -or $Cert.FriendlyName -like "*$Pattern*") {
                $IsMalicious = $true
                break
            }
        }

        if ($IsMalicious) {
            Add-CheckResult -Category "Certificates" -Check "Root Certificate" -Status "FAIL" -Details "KNOWN MALICIOUS: $Subject" -Remediation "Remove-Item 'Cert:\LocalMachine\Root\$Thumbprint'"
        } elseif ($IsSelfSigned) {
            Add-CheckResult -Category "Certificates" -Check "Root Certificate" -Status "WARNING" -Details "SELF-SIGNED (review): $Subject" -Remediation "Verify legitimacy or remove from Cert:\LocalMachine\Root"
        } else {
            Add-CheckResult -Category "Certificates" -Check "Root Certificate" -Status "INFO" -Details "Non-Microsoft: $Subject"
        }
    }
}

# ============================================================================
# SECTION 10: CREDENTIAL PROTECTION
# ============================================================================
Write-Report -Message "`n=== CREDENTIAL PROTECTION ===" -Status "HEADER"

# LSA Protection (RunAsPPL)
$LSAProtection = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
if ($LSAProtection -and $LSAProtection.RunAsPPL -eq 1) {
    Add-CheckResult -Category "Credentials" -Check "LSA Protection (RunAsPPL)" -Status "PASS" -Details "Enabled - LSASS is protected"
} else {
    Add-CheckResult -Category "Credentials" -Check "LSA Protection (RunAsPPL)" -Status "WARNING" -Details "Disabled - LSASS vulnerable to credential dumping" -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Value 1"
}

# Credential Guard
try {
    $DeviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
    $CredGuardRunning = $DeviceGuard.SecurityServicesRunning -contains 1

    if ($CredGuardRunning) {
        Add-CheckResult -Category "Credentials" -Check "Credential Guard" -Status "PASS" -Details "Running"
    } else {
        Add-CheckResult -Category "Credentials" -Check "Credential Guard" -Status "INFO" -Details "Not running (may not be supported on this hardware)"
    }
} catch {
    Add-CheckResult -Category "Credentials" -Check "Credential Guard" -Status "INFO" -Details "Cannot determine status"
}

# WDigest plaintext passwords
$WDigest = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue
if ($WDigest -and $WDigest.UseLogonCredential -eq 1) {
    Add-CheckResult -Category "Credentials" -Check "WDigest Plaintext" -Status "FAIL" -Details "ENABLED - Passwords stored in plaintext!" -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value 0"
} else {
    Add-CheckResult -Category "Credentials" -Check "WDigest Plaintext" -Status "PASS" -Details "Disabled (passwords not in plaintext)"
}

# ============================================================================
# SECTION 11: ADVANCED PERSISTENCE CHECKS
# ============================================================================
Write-Report -Message "`n=== ADVANCED PERSISTENCE ===" -Status "HEADER"

# WMI Event Subscriptions (common malware persistence)
Write-Report -Message "  Checking WMI event subscriptions..." -Status "INFO"

$WMIFilters = Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
$WMIConsumers = Get-WmiObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue
$WMIBindings = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue

$WMIPersistence = @()

if ($WMIFilters) {
    foreach ($Filter in $WMIFilters) {
        $WMIPersistence += "Filter: $($Filter.Name) - Query: $($Filter.Query)"
    }
}

if ($WMIConsumers) {
    foreach ($Consumer in $WMIConsumers) {
        if ($Consumer.__CLASS -eq "CommandLineEventConsumer") {
            $WMIPersistence += "CommandLineConsumer: $($Consumer.Name) - Cmd: $($Consumer.CommandLineTemplate)"
        } elseif ($Consumer.__CLASS -eq "ActiveScriptEventConsumer") {
            $WMIPersistence += "ScriptConsumer: $($Consumer.Name) - SUSPICIOUS (script execution)"
        }
    }
}

if ($WMIPersistence.Count -gt 0) {
    foreach ($WMI in $WMIPersistence) {
        Add-CheckResult -Category "Persistence" -Check "WMI Subscription" -Status "WARNING" -Details $WMI -Remediation "Review and remove if unauthorized"
    }
} else {
    Add-CheckResult -Category "Persistence" -Check "WMI Subscriptions" -Status "PASS" -Details "None found"
}

# Image File Execution Options (IFEO) - Debugger hijacking
Write-Report -Message "  Checking IFEO debugger entries..." -Status "INFO"

$IFEOPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
$IFEOKeys = Get-ChildItem -Path $IFEOPath -ErrorAction SilentlyContinue

$IFEOHijacks = @()
foreach ($Key in $IFEOKeys) {
    $Debugger = Get-ItemProperty -Path $Key.PSPath -Name "Debugger" -ErrorAction SilentlyContinue
    if ($Debugger.Debugger) {
        # Check if it's a legitimate debugger
        $DebuggerPath = $Debugger.Debugger.ToLower()
        $LegitDebuggers = @("devenv", "windbg", "ollydbg", "x64dbg", "idaq", "immunity")
        $IsLegit = $false
        foreach ($Legit in $LegitDebuggers) {
            if ($DebuggerPath -like "*$Legit*") {
                $IsLegit = $true
                break
            }
        }

        if (-not $IsLegit) {
            $IFEOHijacks += "$($Key.PSChildName) -> $($Debugger.Debugger)"
        }
    }

    # Check for SilentProcessExit (another persistence technique)
    $GlobalFlag = Get-ItemProperty -Path $Key.PSPath -Name "GlobalFlag" -ErrorAction SilentlyContinue
    if ($GlobalFlag.GlobalFlag -eq 512) {
        $SilentExit = Get-ItemProperty -Path "$($Key.PSPath)\SilentProcessExit" -ErrorAction SilentlyContinue
        if ($SilentExit.MonitorProcess) {
            $IFEOHijacks += "SilentProcessExit: $($Key.PSChildName) -> $($SilentExit.MonitorProcess)"
        }
    }
}

if ($IFEOHijacks.Count -gt 0) {
    foreach ($Hijack in $IFEOHijacks) {
        Add-CheckResult -Category "Persistence" -Check "IFEO Hijack" -Status "FAIL" -Details "SUSPICIOUS: $Hijack" -Remediation "Remove the Debugger value from registry"
    }
} else {
    Add-CheckResult -Category "Persistence" -Check "IFEO Debugger" -Status "PASS" -Details "No suspicious entries"
}

# AppInit_DLLs (DLL injection)
$AppInit32 = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -Name "AppInit_DLLs" -ErrorAction SilentlyContinue
$AppInit64 = Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows" -Name "AppInit_DLLs" -ErrorAction SilentlyContinue

if ($AppInit32.AppInit_DLLs -or $AppInit64.AppInit_DLLs) {
    $DLLs = @($AppInit32.AppInit_DLLs, $AppInit64.AppInit_DLLs) | Where-Object { $_ }
    foreach ($DLL in $DLLs) {
        Add-CheckResult -Category "Persistence" -Check "AppInit_DLLs" -Status "WARNING" -Details "DLL injection configured: $DLL" -Remediation "Remove from HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
    }
} else {
    Add-CheckResult -Category "Persistence" -Check "AppInit_DLLs" -Status "PASS" -Details "Not configured"
}

# ============================================================================
# SECTION 12: SYSTEM RECOVERY STATUS
# ============================================================================
Write-Report -Message "`n=== SYSTEM RECOVERY STATUS ===" -Status "HEADER"

# Volume Shadow Copy Service
$VSSService = Get-Service -Name VSS -ErrorAction SilentlyContinue
if ($VSSService) {
    if ($VSSService.StartType -eq "Disabled") {
        Add-CheckResult -Category "Recovery" -Check "Volume Shadow Copy" -Status "FAIL" -Details "SERVICE DISABLED - Ransomware indicator!" -Remediation "Set-Service -Name VSS -StartupType Manual"
    } else {
        Add-CheckResult -Category "Recovery" -Check "Volume Shadow Copy" -Status "PASS" -Details "Service: $($VSSService.StartType)"
    }
}

# Check if shadow copies exist
$ShadowCopies = Get-WmiObject -Class Win32_ShadowCopy -ErrorAction SilentlyContinue
if ($ShadowCopies) {
    $CopyCount = @($ShadowCopies).Count
    Add-CheckResult -Category "Recovery" -Check "Shadow Copies" -Status "PASS" -Details "$CopyCount shadow copies available"
} else {
    Add-CheckResult -Category "Recovery" -Check "Shadow Copies" -Status "WARNING" -Details "No shadow copies found" -Remediation "Enable System Protection and create restore points"
}

# Windows Recovery Environment
try {
    $REStatus = reagentc /info 2>&1 | Out-String
    if ($REStatus -match "Enabled") {
        Add-CheckResult -Category "Recovery" -Check "Recovery Environment" -Status "PASS" -Details "Windows RE is enabled"
    } elseif ($REStatus -match "Disabled") {
        Add-CheckResult -Category "Recovery" -Check "Recovery Environment" -Status "WARNING" -Details "Windows RE is disabled" -Remediation "reagentc /enable"
    }
} catch {
    Add-CheckResult -Category "Recovery" -Check "Recovery Environment" -Status "INFO" -Details "Cannot determine status"
}

# ============================================================================
# SECTION 13: SUSPICIOUS SCHEDULED TASKS
# ============================================================================
Write-Report -Message "`n=== SUSPICIOUS SCHEDULED TASKS ===" -Status "HEADER"

$SuspiciousTaskPatterns = @(
    "powershell", "cmd.exe", "wscript", "cscript",
    "mshta", "regsvr32", "rundll32", "certutil",
    "bitsadmin", "AppData", "Temp", "ProgramData",
    "http://", "https://", "ftp://", ".ps1", ".vbs", ".bat"
)

$Tasks = Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" }

Write-Report -Message "  Checking $($Tasks.Count) active scheduled tasks..." -Status "INFO"

$SuspiciousTaskCount = 0
foreach ($Task in $Tasks) {
    try {
        $TaskInfo = Get-ScheduledTaskInfo -TaskName $Task.TaskName -TaskPath $Task.TaskPath -ErrorAction SilentlyContinue
        $Actions = $Task.Actions

        foreach ($Action in $Actions) {
            $ActionPath = "$($Action.Execute) $($Action.Arguments)"
            $IsSuspicious = $false

            foreach ($Pattern in $SuspiciousTaskPatterns) {
                if ($ActionPath -like "*$Pattern*") {
                    $IsSuspicious = $true
                    break
                }
            }

            if ($IsSuspicious) {
                $SuspiciousTaskCount++
                Add-CheckResult -Category "Tasks" -Check "Suspicious Task" -Status "WARNING" -Details "$($Task.TaskPath)$($Task.TaskName): $ActionPath"
            }
        }
    } catch {}
}

if ($SuspiciousTaskCount -eq 0) {
    Add-CheckResult -Category "Tasks" -Check "Scheduled Tasks" -Status "PASS" -Details "No suspicious patterns detected in active tasks"
} else {
    Write-Report -Message "  Found $SuspiciousTaskCount task(s) with suspicious patterns - review recommended" -Status "WARNING"
}

# ============================================================================
# SECTION 14: STARTUP ITEMS
# ============================================================================
Write-Report -Message "`n=== STARTUP ITEMS ===" -Status "HEADER"

$StartupPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
)

foreach ($Path in $StartupPaths) {
    $Items = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
    if ($Items) {
        $Props = $Items.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" }
        foreach ($Prop in $Props) {
            $Value = $Prop.Value
            $IsSuspicious = $false

            foreach ($Pattern in $SuspiciousTaskPatterns) {
                if ($Value -like "*$Pattern*") {
                    $IsSuspicious = $true
                    break
                }
            }

            if ($IsSuspicious) {
                Add-CheckResult -Category "Startup" -Check "Startup Item" -Status "WARNING" -Details "$($Prop.Name): $Value"
            } else {
                Add-CheckResult -Category "Startup" -Check "Startup Item" -Status "INFO" -Details "$($Prop.Name): $Value"
            }
        }
    }
}

# ============================================================================
# SUMMARY
# ============================================================================
Write-Report -Message "`n================================================================================`nSUMMARY`n================================================================================" -Status "HEADER"

$SummaryText = @"
Total Checks: $($Results.Summary.Pass + $Results.Summary.Warning + $Results.Summary.Fail + $Results.Summary.Info)
  PASS:    $($Results.Summary.Pass)
  WARNING: $($Results.Summary.Warning)
  FAIL:    $($Results.Summary.Fail)
  INFO:    $($Results.Summary.Info)
"@

Write-Host ""
Write-Host $SummaryText
Add-Content -Path $ReportFile -Value $SummaryText

# Determine overall status
if ($Results.Summary.Fail -gt 0) {
    Write-Host ""
    Write-Host "  OVERALL: ISSUES FOUND - Review FAIL items above" -ForegroundColor Red
    Add-Content -Path $ReportFile -Value "`nOVERALL: ISSUES FOUND - Review FAIL items above"
} elseif ($Results.Summary.Warning -gt 0) {
    Write-Host ""
    Write-Host "  OVERALL: WARNINGS - Review WARNING items above" -ForegroundColor Yellow
    Add-Content -Path $ReportFile -Value "`nOVERALL: WARNINGS - Review WARNING items above"
} else {
    Write-Host ""
    Write-Host "  OVERALL: PASS - No critical issues found" -ForegroundColor Green
    Add-Content -Path $ReportFile -Value "`nOVERALL: PASS - No critical issues found"
}

Add-Content -Path $ReportFile -Value "`n================================================================================`nReport generated: $($Results.Timestamp)`n================================================================================"

# Export JSON if requested
if ($JsonOutput) {
    $Results | ConvertTo-Json -Depth 10 | Set-Content -Path $JsonFile
    Write-Host ""
    Write-Host "  JSON output: $JsonFile" -ForegroundColor Gray
}

Write-Host ""
Write-Host "  Report saved: $ReportFile" -ForegroundColor Gray
Write-Host ""

#endregion
