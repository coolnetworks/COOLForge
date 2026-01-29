<#
.SYNOPSIS
    Security Baseline Checker - Comprehensive Windows security audit

.DESCRIPTION
    Performs comprehensive offline security checks (36 sections):

    CORE SECURITY (Sections 1-14):
    - Windows Defender status and exclusions audit
    - Firewall status (all profiles)
    - UAC configuration and user accounts
    - Keylogger indicators (hooks, processes, drivers)
    - SMBv1, RDP, Secure Boot, BitLocker, PowerShell logging
    - DNS hijacking, hosts file tampering, proxy settings
    - Rogue root certificate detection
    - Credential protection (LSA, WDigest, Credential Guard)
    - Advanced persistence (WMI, IFEO, AppInit_DLLs)
    - System recovery (VSS, Windows RE)
    - Scheduled tasks and startup items audit

    ADVANCED CHECKS (Sections 15-22):
    - Browser extensions (Chrome, Edge, Firefox)
    - Recently modified executables in system folders
    - Alternate Data Streams (ADS)
    - Print Monitor DLLs, SSP DLLs, Netsh Helper DLLs
    - Office add-ins and startup items
    - Recently accessed files and Prefetch analysis

    INCIDENT RESPONSE (Sections 23-36):
    - Temp files audit (user/system/browser cache)
    - Proxy hijacking (system, Chrome, Firefox, WPAD)
    - Browser hijacking (shortcut tampering, homepage, search)
    - File association hijacking (EXE, COM, BAT, etc.)
    - Event log analysis (logon failures, new accounts, services)
    - SMART disk health and disk space
    - Executables in suspicious locations
    - Network indicators (connections, listeners, ARP, SMB)
    - USB/external device history
    - Ransomware indicators (encrypted files, ransom notes)
    - PowerShell command history analysis
    - IFEO extended (GlobalFlag, SilentProcessExit)
    - Broken shortcuts and orphaned directories
    - Windows policies hijacking (disabled Task Manager, etc.)

.PARAMETER OutputPath
    Path for the report file. Defaults to script directory.

.PARAMETER JsonOutput
    Also output results as JSON for programmatic parsing.

.EXAMPLE
    .\Check-SecurityBaseline.ps1
    .\Check-SecurityBaseline.ps1 -OutputPath "C:\Reports"

.NOTES
    Version: 2.0.0
    Requires: Administrator privileges
    Runs offline - no internet required
    36 security check sections
#>

param(
    [string]$OutputPath = "",
    [switch]$JsonOutput
)

#region Initialization
$ErrorActionPreference = "SilentlyContinue"
$ScriptVersion = "2.0.0"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if ([string]::IsNullOrEmpty($OutputPath)) {
    $OutputPath = $ScriptDir
}

# Generate timestamp
$Timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$ReportFile = Join-Path $OutputPath "SecurityBaseline-$Timestamp.txt"
$JsonFile = Join-Path $OutputPath "SecurityBaseline-$Timestamp.json"
$HashFile = Join-Path $OutputPath "SuspiciousHashes-$Timestamp.txt"

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

# Remediation items collection - populated during scan, processed at end
$Script:RemediationItems = @()

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

function Add-RemediationItem {
    param(
        [string]$Category,
        [string]$Description,
        [string]$Risk,
        [scriptblock]$Action,
        [string]$ActionDescription
    )

    $Script:RemediationItems += @{
        Category = $Category
        Description = $Description
        Risk = $Risk
        Action = $Action
        ActionDescription = $ActionDescription
    }
}

# Hash logging for suspicious files - outputs to SuspiciousHashes-*.txt for VirusTotal checking
$Script:HashCount = 0
$Script:HashFileInitialized = $false

function Add-SuspiciousHash {
    param(
        [string]$FilePath,
        [string]$Category,
        [string]$Reason
    )

    if (-not (Test-Path $FilePath)) { return }

    try {
        # Initialize hash file on first use
        if (-not $Script:HashFileInitialized) {
            $Header = @"
================================================================================
SUSPICIOUS FILE HASHES - $($env:COMPUTERNAME)
================================================================================
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

Check these hashes at: https://www.virustotal.com/gui/home/search
Or use: vt search <hash> (if you have VT CLI installed)

FORMAT: MD5 | SHA256 | Size | Category | Path
================================================================================

"@
            $Header | Out-File -FilePath $HashFile -Encoding UTF8
            $Script:HashFileInitialized = $true
        }

        $FileInfo = Get-Item $FilePath
        $MD5 = (Get-FileHash -Path $FilePath -Algorithm MD5).Hash
        $SHA256 = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash
        $Size = "{0:N0} bytes" -f $FileInfo.Length

        $HashEntry = "$MD5 | $SHA256 | $Size | $Category | $FilePath"
        Add-Content -Path $HashFile -Value $HashEntry
        $Script:HashCount++

    } catch {
        # Silently skip files we can't hash (locked, access denied, etc.)
    }
}

function Invoke-Remediation {
    if ($Script:RemediationItems.Count -eq 0) {
        Write-Host ""
        Write-Host "  No remediable issues found." -ForegroundColor Green
        return
    }

    Write-Host ""
    Write-Host "  ================================================================================" -ForegroundColor Cyan
    Write-Host "                         REMEDIATION PHASE" -ForegroundColor Cyan
    Write-Host "  ================================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Found $($Script:RemediationItems.Count) item(s) that can be fixed." -ForegroundColor Yellow
    Write-Host "  You will be prompted for each item individually." -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Options: [Y] Yes, fix  [N] No, skip  [A] Fix all remaining  [Q] Quit remediation" -ForegroundColor Gray
    Write-Host ""

    $fixAll = $false
    $fixedCount = 0
    $skippedCount = 0

    for ($i = 0; $i -lt $Script:RemediationItems.Count; $i++) {
        $item = $Script:RemediationItems[$i]
        $num = $i + 1

        Write-Host "  --------------------------------------------------------------------------------" -ForegroundColor DarkGray
        Write-Host "  [$num/$($Script:RemediationItems.Count)] $($item.Category)" -ForegroundColor White
        Write-Host "  Issue: $($item.Description)" -ForegroundColor Yellow
        Write-Host "  Risk:  $($item.Risk)" -ForegroundColor $(if ($item.Risk -eq "High") { "Red" } elseif ($item.Risk -eq "Medium") { "Yellow" } else { "Gray" })
        Write-Host "  Fix:   $($item.ActionDescription)" -ForegroundColor Cyan
        Write-Host ""

        if ($fixAll) {
            $choice = "Y"
        } else {
            $choice = ""
            while ($choice -notmatch "^[YNAQ]$") {
                Write-Host "  Fix this item? [Y/N/A/Q]: " -NoNewline -ForegroundColor White
                $choice = (Read-Host).ToUpper()
                if ($choice -eq "") { $choice = "N" }
            }
        }

        switch ($choice) {
            "Y" {
                try {
                    & $item.Action
                    Write-Host "  [FIXED] $($item.Description)" -ForegroundColor Green
                    Add-Content -Path $ReportFile -Value "[REMEDIATED] $($item.Category): $($item.Description)"
                    $fixedCount++
                } catch {
                    Write-Host "  [ERROR] Failed to fix: $($_.Exception.Message)" -ForegroundColor Red
                    Add-Content -Path $ReportFile -Value "[REMEDIATION FAILED] $($item.Category): $($item.Description) - $($_.Exception.Message)"
                }
            }
            "N" {
                Write-Host "  [SKIPPED] $($item.Description)" -ForegroundColor Gray
                $skippedCount++
            }
            "A" {
                $fixAll = $true
                try {
                    & $item.Action
                    Write-Host "  [FIXED] $($item.Description)" -ForegroundColor Green
                    Add-Content -Path $ReportFile -Value "[REMEDIATED] $($item.Category): $($item.Description)"
                    $fixedCount++
                } catch {
                    Write-Host "  [ERROR] Failed to fix: $($_.Exception.Message)" -ForegroundColor Red
                    Add-Content -Path $ReportFile -Value "[REMEDIATION FAILED] $($item.Category): $($item.Description) - $($_.Exception.Message)"
                }
            }
            "Q" {
                Write-Host ""
                Write-Host "  Remediation cancelled. $fixedCount fixed, $skippedCount skipped, $($Script:RemediationItems.Count - $i) remaining." -ForegroundColor Yellow
                return
            }
        }
        Write-Host ""
    }

    Write-Host "  ================================================================================" -ForegroundColor Cyan
    Write-Host "  REMEDIATION COMPLETE" -ForegroundColor Cyan
    Write-Host "  Fixed: $fixedCount   Skipped: $skippedCount" -ForegroundColor White
    Write-Host "  ================================================================================" -ForegroundColor Cyan
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

# Look for suspicious DLLs that might be injected (excluding legitimate Windows DLLs)
$SuspiciousDLLs = @(
    "hook.dll", "keyhook.dll", "kbhook.dll",
    "keylogger.dll", "capture.dll", "spy.dll"
)
# Legitimate Windows DLLs to ignore (even if name contains suspicious patterns)
$LegitMonitorDLLs = @(
    "MsCtfMonitor.dll",      # Windows Text Services Framework
    "InprocLogger.dll",      # Windows component
    "PerfMonitor.dll",       # Windows Performance Monitor
    "WmiPerfClass.dll"       # WMI Performance
)

$LoadedModules = Get-Process | ForEach-Object {
    try {
        $_.Modules | Select-Object ModuleName, FileName
    } catch {}
} | Where-Object { $_.ModuleName }

$HookDLLFound = $false
foreach ($Module in $LoadedModules) {
    $ModLower = $Module.ModuleName.ToLower()
    # Skip known legitimate Windows DLLs
    $IsLegit = $false
    foreach ($LegitDLL in $LegitMonitorDLLs) {
        if ($Module.ModuleName -eq $LegitDLL) {
            $IsLegit = $true
            break
        }
    }
    if (-not $IsLegit) {
        foreach ($DLL in $SuspiciousDLLs) {
            if ($ModLower -like "*$DLL*") {
                Add-CheckResult -Category "Keylogger" -Check "Suspicious DLL" -Status "WARNING" -Details "POTENTIAL HOOK DLL: $($Module.ModuleName) - $($Module.FileName)"
                $HookDLLFound = $true
            }
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

# Standard Windows keyboard drivers including Hyper-V and wireless
$StandardKbdDrivers = @("kbdclass", "kbdhid", "i8042prt", "hyperkbd", "wirelesskeyboardfilter", "hidclass")
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

# Known legitimate third-party root CAs (comprehensive list)
$KnownLegitCAs = @(
    "DigiCert", "GlobalSign", "Comodo", "GoDaddy", "Entrust", "Thawte",
    "VeriSign", "GeoTrust", "Symantec", "StartCom", "ISRG", "Let's Encrypt",
    "Amazon", "Google Trust", "Apple", "Sectigo", "QuoVadis", "IdenTrust",
    "DST Root", "Baltimore", "CyberTrust", "USERTrust", "SSL.com", "Starfield",
    "SecureTrust", "Certum", "Unizeto", "SECOM", "T-TeleSec", "Deutsche Telekom",
    "Hotspot 2.0", "WFA", "Buypass", "AddTrust", "Trustwave", "Network Solutions",
    "SwissSign", "Sonera", "Staat der Nederlanden", "ACCV", "FNMT", "AC Camerfirma",
    "Autoridad", "Certigna", "E-Tugra", "emSign", "GDCA", "Hongkong Post",
    "Izenpe", "Krajowa Izba", "NetLock", "OISTE", "PKI", "TWCA", "TrustCor"
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

# Known legitimate Windows WMI subscriptions to ignore
$LegitWMIFilters = @(
    "SCM Event Log Filter",           # Service Control Manager logging
    "BVTFilter",                       # Windows built-in
    "Microsoft-Windows-*",            # Windows components
    "WMI Event Filter"                # Standard Windows
)

$WMIPersistence = @()

if ($WMIFilters) {
    foreach ($Filter in $WMIFilters) {
        # Skip known legitimate filters
        $IsLegit = $false
        foreach ($LegitFilter in $LegitWMIFilters) {
            if ($Filter.Name -like $LegitFilter) {
                $IsLegit = $true
                break
            }
        }
        if (-not $IsLegit) {
            $WMIPersistence += "Filter: $($Filter.Name) - Query: $($Filter.Query)"
        }
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

# Known legitimate Windows task paths (not suspicious)
$LegitimateTaskPaths = @(
    "\Microsoft\Windows\",
    "\Microsoft\Office\",
    "\Microsoft\EdgeUpdate\",
    "\Adobe Acrobat Update Task",
    "\GoogleUpdateTask",
    "\OneDrive"
)

# Patterns that are suspicious ONLY if not in legitimate paths
$SuspiciousPatterns = @(
    "powershell.*-enc", "powershell.*-nop", "powershell.*hidden",
    "cmd.exe.*/c.*http", "mshta.*http", "mshta.*javascript",
    "regsvr32.*/s.*/u", "regsvr32.*scrobj",
    "certutil.*-decode", "certutil.*-urlcache",
    "bitsadmin.*transfer"
)

# High-risk patterns (always suspicious regardless of path)
$HighRiskPatterns = @(
    "\\Temp\\.*\.exe", "\\AppData\\Local\\Temp\\",
    "\\Users\\Public\\", "\\ProgramData\\.*\.exe$",
    "pastebin\.com", "githubusercontent\.com/.*\.ps1",
    "iex.*downloadstring", "invoke-expression.*webclient"
)

$Tasks = Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" }
Write-Report -Message "  Checking $($Tasks.Count) active scheduled tasks..." -Status "INFO"

$SuspiciousTaskCount = 0
foreach ($Task in $Tasks) {
    try {
        $TaskFullPath = "$($Task.TaskPath)$($Task.TaskName)"
        $Actions = $Task.Actions

        # Skip known legitimate Windows tasks
        $IsLegitimate = $false
        foreach ($LegitPath in $LegitimateTaskPaths) {
            if ($TaskFullPath -like "*$LegitPath*") {
                $IsLegitimate = $true
                break
            }
        }

        foreach ($Action in $Actions) {
            $ActionPath = "$($Action.Execute) $($Action.Arguments)"
            $IsSuspicious = $false
            $SuspicionReason = ""

            # Check high-risk patterns (always flag)
            foreach ($Pattern in $HighRiskPatterns) {
                if ($ActionPath -match $Pattern) {
                    $IsSuspicious = $true
                    $SuspicionReason = "High-risk pattern: $Pattern"
                    break
                }
            }

            # Check suspicious patterns (only if not legitimate task)
            if (-not $IsSuspicious -and -not $IsLegitimate) {
                foreach ($Pattern in $SuspiciousPatterns) {
                    if ($ActionPath -match $Pattern) {
                        $IsSuspicious = $true
                        $SuspicionReason = "Suspicious pattern: $Pattern"
                        break
                    }
                }
            }

            if ($IsSuspicious) {
                $SuspiciousTaskCount++
                Add-CheckResult -Category "Tasks" -Check "Suspicious Task" -Status "WARNING" -Details "$TaskFullPath`: $ActionPath"

                # Add remediation item
                $taskName = $Task.TaskName
                $taskPath = $Task.TaskPath
                Add-RemediationItem -Category "Scheduled Task" `
                    -Description "$TaskFullPath - $SuspicionReason" `
                    -Risk "High" `
                    -ActionDescription "Disable scheduled task (can be re-enabled if legitimate)" `
                    -Action ([scriptblock]::Create("Disable-ScheduledTask -TaskName '$taskName' -TaskPath '$taskPath'"))
            }
        }
    } catch {}
}

if ($SuspiciousTaskCount -eq 0) {
    Add-CheckResult -Category "Tasks" -Check "Scheduled Tasks" -Status "PASS" -Details "No suspicious patterns detected in active tasks"
} else {
    Write-Report -Message "  Found $SuspiciousTaskCount task(s) with suspicious patterns" -Status "WARNING"
}

# ============================================================================
# SECTION 14: STARTUP ITEMS
# ============================================================================
Write-Report -Message "`n=== STARTUP ITEMS ===" -Status "HEADER"

# Known legitimate startup items
$LegitimateStartupNames = @(
    "SecurityHealth", "Windows Defender", "WindowsDefender",
    "iTunesHelper", "Adobe", "Acrobat", "Google", "Microsoft",
    "Realtek", "Intel", "NVIDIA", "AMD", "Logitech", "Synaptics",
    "Brother", "HP", "Canon", "Epson", "Dell", "Lenovo", "ASUS"
)

# Suspicious patterns for startup items
$StartupSuspiciousPatterns = @(
    "\\Temp\\", "\\AppData\\Local\\Temp\\",
    "powershell.*-enc", "powershell.*-nop", "powershell.*hidden",
    "cmd\.exe.*/c", "mshta", "wscript.*http", "cscript.*http",
    "regsvr32.*/s", "certutil", "bitsadmin",
    "\\Users\\Public\\", "pastebin\.com", "bit\.ly"
)

$StartupPaths = @(
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; Scope = "Machine" },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"; Scope = "Machine" },
    @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; Scope = "User" },
    @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"; Scope = "User" },
    @{ Path = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"; Scope = "Machine (32-bit)" }
)

foreach ($PathInfo in $StartupPaths) {
    $Path = $PathInfo.Path
    $Items = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
    if ($Items) {
        $Props = $Items.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" }
        foreach ($Prop in $Props) {
            $Name = $Prop.Name
            $Value = $Prop.Value
            $IsSuspicious = $false
            $SuspicionReason = ""

            # Check if it's a known legitimate startup
            $IsLegitimate = $false
            foreach ($LegitName in $LegitimateStartupNames) {
                if ($Name -match $LegitName -or $Value -match $LegitName) {
                    $IsLegitimate = $true
                    break
                }
            }

            # Check for suspicious patterns
            foreach ($Pattern in $StartupSuspiciousPatterns) {
                if ($Value -match $Pattern) {
                    $IsSuspicious = $true
                    $SuspicionReason = "Matches suspicious pattern: $Pattern"
                    break
                }
            }

            # Check if exe exists and is signed (for non-legitimate items)
            if (-not $IsLegitimate -and -not $IsSuspicious) {
                $ExePath = $Value -replace '^"([^"]+)".*', '$1' -replace "^'([^']+)'.*", '$1' -replace ' .*$', ''
                if ($ExePath -and (Test-Path $ExePath -ErrorAction SilentlyContinue)) {
                    $Sig = Get-AuthenticodeSignature -FilePath $ExePath -ErrorAction SilentlyContinue
                    if ($Sig.Status -ne "Valid") {
                        $IsSuspicious = $true
                        $SuspicionReason = "Unsigned or invalid signature"
                    }
                } elseif ($ExePath -and $ExePath -notmatch "^%") {
                    $IsSuspicious = $true
                    $SuspicionReason = "Executable not found: $ExePath"
                }
            }

            if ($IsSuspicious) {
                Add-CheckResult -Category "Startup" -Check "Startup Item" -Status "WARNING" -Details "$Name`: $Value"

                # Add remediation item
                $regPath = $Path
                $propName = $Name
                Add-RemediationItem -Category "Startup Item ($($PathInfo.Scope))" `
                    -Description "$Name - $SuspicionReason" `
                    -Risk "High" `
                    -ActionDescription "Remove startup entry from registry" `
                    -Action ([scriptblock]::Create("Remove-ItemProperty -Path '$regPath' -Name '$propName' -Force"))
            } else {
                Add-CheckResult -Category "Startup" -Check "Startup Item" -Status "INFO" -Details "$Name`: $Value"
            }
        }
    }
}

# ============================================================================
# SECTION 15: BROWSER EXTENSIONS
# ============================================================================
Write-Report -Message "`n=== BROWSER EXTENSIONS ===" -Status "HEADER"

# Chrome Extensions
Write-Report -Message "  Checking Chrome extensions..." -Status "INFO"

$ChromeExtPaths = @(
    "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions",
    "$env:LOCALAPPDATA\Google\Chrome\User Data\Profile *\Extensions"
)

$ChromeExtCount = 0
foreach ($BasePath in $ChromeExtPaths) {
    $ExtFolders = Get-ChildItem -Path $BasePath -Directory -ErrorAction SilentlyContinue
    foreach ($Ext in $ExtFolders) {
        $ManifestPath = Get-ChildItem -Path $Ext.FullName -Recurse -Filter "manifest.json" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($ManifestPath) {
            try {
                $Manifest = Get-Content $ManifestPath.FullName -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
                $ExtName = if ($Manifest.name) { $Manifest.name } else { $Ext.Name }
                # Flag extensions with broad permissions
                $Permissions = $Manifest.permissions -join ", "
                if ($Permissions -match "(<all_urls>|http://\*|https://\*|webRequest|webRequestBlocking|nativeMessaging)") {
                    Add-CheckResult -Category "Browser" -Check "Chrome Extension" -Status "WARNING" -Details "$ExtName - High permissions: $Permissions"
                } else {
                    Add-CheckResult -Category "Browser" -Check "Chrome Extension" -Status "INFO" -Details $ExtName
                }
                $ChromeExtCount++
            } catch {}
        }
    }
}

if ($ChromeExtCount -eq 0) {
    Add-CheckResult -Category "Browser" -Check "Chrome Extensions" -Status "INFO" -Details "None found or Chrome not installed"
}

# Edge Extensions
Write-Report -Message "  Checking Edge extensions..." -Status "INFO"

$EdgeExtPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"
$EdgeExtCount = 0

if (Test-Path $EdgeExtPath) {
    $ExtFolders = Get-ChildItem -Path $EdgeExtPath -Directory -ErrorAction SilentlyContinue
    foreach ($Ext in $ExtFolders) {
        $ManifestPath = Get-ChildItem -Path $Ext.FullName -Recurse -Filter "manifest.json" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($ManifestPath) {
            try {
                $Manifest = Get-Content $ManifestPath.FullName -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
                $ExtName = if ($Manifest.name) { $Manifest.name } else { $Ext.Name }
                $Permissions = $Manifest.permissions -join ", "
                if ($Permissions -match "(<all_urls>|http://\*|https://\*|webRequest|webRequestBlocking|nativeMessaging)") {
                    Add-CheckResult -Category "Browser" -Check "Edge Extension" -Status "WARNING" -Details "$ExtName - High permissions: $Permissions"
                } else {
                    Add-CheckResult -Category "Browser" -Check "Edge Extension" -Status "INFO" -Details $ExtName
                }
                $EdgeExtCount++
            } catch {}
        }
    }
}

if ($EdgeExtCount -eq 0) {
    Add-CheckResult -Category "Browser" -Check "Edge Extensions" -Status "INFO" -Details "None found or Edge not installed"
}

# Firefox Extensions
Write-Report -Message "  Checking Firefox extensions..." -Status "INFO"

$FirefoxProfiles = "$env:APPDATA\Mozilla\Firefox\Profiles"
$FirefoxExtCount = 0

if (Test-Path $FirefoxProfiles) {
    $Profiles = Get-ChildItem -Path $FirefoxProfiles -Directory -ErrorAction SilentlyContinue
    foreach ($Profile in $Profiles) {
        $ExtensionsJson = Join-Path $Profile.FullName "extensions.json"
        if (Test-Path $ExtensionsJson) {
            try {
                $ExtData = Get-Content $ExtensionsJson -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
                foreach ($Addon in $ExtData.addons) {
                    if ($Addon.type -eq "extension" -and $Addon.active) {
                        Add-CheckResult -Category "Browser" -Check "Firefox Extension" -Status "INFO" -Details "$($Addon.defaultLocale.name) - $($Addon.id)"
                        $FirefoxExtCount++
                    }
                }
            } catch {}
        }
    }
}

if ($FirefoxExtCount -eq 0) {
    Add-CheckResult -Category "Browser" -Check "Firefox Extensions" -Status "INFO" -Details "None found or Firefox not installed"
}

# ============================================================================
# SECTION 16: RECENTLY MODIFIED EXECUTABLES
# ============================================================================
Write-Report -Message "`n=== RECENTLY MODIFIED EXECUTABLES ===" -Status "HEADER"

Write-Report -Message "  Checking for executables modified in last 7 days..." -Status "INFO"

$SystemPaths = @(
    "$env:SystemRoot\System32",
    "$env:SystemRoot\SysWOW64",
    "$env:SystemRoot",
    "$env:ProgramFiles",
    "${env:ProgramFiles(x86)}"
)

$RecentDate = (Get-Date).AddDays(-7)
$RecentExeCount = 0

foreach ($SysPath in $SystemPaths) {
    if (Test-Path $SysPath) {
        $RecentExes = Get-ChildItem -Path $SysPath -Filter "*.exe" -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt $RecentDate } |
            Select-Object -First 10

        foreach ($Exe in $RecentExes) {
            # Check if signed
            $Sig = Get-AuthenticodeSignature -FilePath $Exe.FullName -ErrorAction SilentlyContinue
            $SignStatus = if ($Sig.Status -eq "Valid") { "Signed" } else { "UNSIGNED" }

            if ($SignStatus -eq "UNSIGNED") {
                Add-CheckResult -Category "RecentExe" -Check "Modified Executable" -Status "WARNING" -Details "UNSIGNED: $($Exe.FullName) - Modified: $($Exe.LastWriteTime)"
                Add-SuspiciousHash -FilePath $Exe.FullName -Category "UnsignedRecentExe" -Reason "Unsigned executable modified recently"
            } else {
                Add-CheckResult -Category "RecentExe" -Check "Modified Executable" -Status "INFO" -Details "$($Exe.Name) - $($Exe.LastWriteTime) ($SignStatus)"
            }
            $RecentExeCount++
        }
    }
}

if ($RecentExeCount -eq 0) {
    Add-CheckResult -Category "RecentExe" -Check "Recently Modified Executables" -Status "PASS" -Details "No executables modified in system folders in last 7 days"
}

# ============================================================================
# SECTION 17: ALTERNATE DATA STREAMS (ADS)
# ============================================================================
Write-Report -Message "`n=== ALTERNATE DATA STREAMS ===" -Status "HEADER"

Write-Report -Message "  Checking for suspicious ADS in common locations..." -Status "INFO"

$ADSPaths = @(
    "$env:SystemRoot\System32",
    "$env:TEMP",
    "$env:USERPROFILE\Downloads",
    "$env:APPDATA",
    "$env:LOCALAPPDATA\Temp"
)

$ADSCount = 0
foreach ($ADSPath in $ADSPaths) {
    if (Test-Path $ADSPath) {
        # Get files with alternate data streams (excluding common legitimate streams)
        # Zone.Identifier = download source tracking
        # SmartScreen = Windows SmartScreen metadata
        # StreamedFileState = OneDrive/cloud sync state
        # SummaryInformation = Office document metadata
        $FilesWithADS = Get-ChildItem -Path $ADSPath -File -ErrorAction SilentlyContinue | ForEach-Object {
            $Streams = Get-Item -Path $_.FullName -Stream * -ErrorAction SilentlyContinue |
                Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' -and
                               $_.Stream -ne 'SmartScreen' -and $_.Stream -ne 'StreamedFileState' -and
                               $_.Stream -notlike '*SummaryInformation*' }
            if ($Streams) {
                [PSCustomObject]@{
                    File = $_.FullName
                    Streams = ($Streams.Stream -join ", ")
                }
            }
        }

        foreach ($ADS in $FilesWithADS) {
            Add-CheckResult -Category "ADS" -Check "Alternate Data Stream" -Status "WARNING" -Details "$($ADS.File) has ADS: $($ADS.Streams)"
            $ADSCount++
            if ($ADSCount -ge 20) { break }
        }
    }
    if ($ADSCount -ge 20) { break }
}

if ($ADSCount -eq 0) {
    Add-CheckResult -Category "ADS" -Check "Alternate Data Streams" -Status "PASS" -Details "No suspicious ADS found in common locations"
} else {
    Write-Report -Message "  Found $ADSCount file(s) with alternate data streams" -Status "WARNING"
}

# ============================================================================
# SECTION 18: PRINT MONITOR DLLs
# ============================================================================
Write-Report -Message "`n=== PRINT MONITOR DLLs ===" -Status "HEADER"

Write-Report -Message "  Checking print monitors for suspicious DLLs..." -Status "INFO"

$PrintMonitorPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors"
$PrintMonitors = Get-ChildItem -Path $PrintMonitorPath -ErrorAction SilentlyContinue

# Known legitimate print monitors
$LegitMonitors = @(
    "Local Port", "Standard TCP/IP Port", "USB Monitor", "WSD Port",
    "Microsoft Shared Fax Monitor", "Send To Microsoft OneNote",
    "Appmon", "TCPMON.DLL", "localspl.dll", "usbmon.dll", "wsdmon.dll"
)

foreach ($Monitor in $PrintMonitors) {
    $DriverProp = Get-ItemProperty -Path $Monitor.PSPath -Name "Driver" -ErrorAction SilentlyContinue
    if ($DriverProp.Driver) {
        $MonitorName = $Monitor.PSChildName
        $DriverDLL = $DriverProp.Driver

        $IsLegit = $false
        foreach ($Legit in $LegitMonitors) {
            if ($MonitorName -like "*$Legit*" -or $DriverDLL -like "*$Legit*") {
                $IsLegit = $true
                break
            }
        }

        if ($IsLegit) {
            Add-CheckResult -Category "PrintMon" -Check "Print Monitor" -Status "INFO" -Details "$MonitorName - $DriverDLL"
        } else {
            # Check if DLL exists and is signed
            $DLLPath = if (Test-Path $DriverDLL) { $DriverDLL } else { "$env:SystemRoot\System32\$DriverDLL" }
            if (Test-Path $DLLPath) {
                $Sig = Get-AuthenticodeSignature -FilePath $DLLPath -ErrorAction SilentlyContinue
                if ($Sig.Status -ne "Valid") {
                    Add-CheckResult -Category "PrintMon" -Check "Print Monitor" -Status "FAIL" -Details "SUSPICIOUS UNSIGNED: $MonitorName - $DriverDLL"
                } else {
                    Add-CheckResult -Category "PrintMon" -Check "Print Monitor" -Status "WARNING" -Details "Non-standard: $MonitorName - $DriverDLL (Signed by: $($Sig.SignerCertificate.Subject))"
                }
            } else {
                Add-CheckResult -Category "PrintMon" -Check "Print Monitor" -Status "WARNING" -Details "Non-standard: $MonitorName - $DriverDLL (DLL not found)"
            }
        }
    }
}

# ============================================================================
# SECTION 19: SECURITY SUPPORT PROVIDERS (SSP)
# ============================================================================
Write-Report -Message "`n=== SECURITY SUPPORT PROVIDERS ===" -Status "HEADER"

Write-Report -Message "  Checking Security Support Provider DLLs..." -Status "INFO"

# SSPs can be used to capture credentials
$SSPPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$SecurityPackages = (Get-ItemProperty -Path $SSPPath -Name "Security Packages" -ErrorAction SilentlyContinue)."Security Packages"

# Known legitimate SSPs
$LegitSSPs = @(
    "kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u",
    "cloudap", "livessp", "wsauth", "negoexts", "negotiate"
)

if ($SecurityPackages) {
    foreach ($SSP in $SecurityPackages) {
        if ([string]::IsNullOrWhiteSpace($SSP)) { continue }

        $IsLegit = $LegitSSPs -contains $SSP.ToLower()

        if ($IsLegit) {
            Add-CheckResult -Category "SSP" -Check "Security Package" -Status "PASS" -Details "$SSP (Standard Windows SSP)"
        } else {
            Add-CheckResult -Category "SSP" -Check "Security Package" -Status "FAIL" -Details "SUSPICIOUS: $SSP - Non-standard SSP (potential credential stealer)" -Remediation "Investigate and remove from HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages"
        }
    }
}

# Also check LSA OSConfig Security Packages
$OSConfigSSP = (Get-ItemProperty -Path "$SSPPath\OSConfig" -Name "Security Packages" -ErrorAction SilentlyContinue)."Security Packages"
if ($OSConfigSSP) {
    foreach ($SSP in $OSConfigSSP) {
        if ([string]::IsNullOrWhiteSpace($SSP)) { continue }
        $IsLegit = $LegitSSPs -contains $SSP.ToLower()
        if (-not $IsLegit) {
            Add-CheckResult -Category "SSP" -Check "OSConfig Security Package" -Status "FAIL" -Details "SUSPICIOUS: $SSP in OSConfig"
        }
    }
}

# ============================================================================
# SECTION 20: NETSH HELPER DLLs
# ============================================================================
Write-Report -Message "`n=== NETSH HELPER DLLs ===" -Status "HEADER"

Write-Report -Message "  Checking Netsh helper DLLs..." -Status "INFO"

$NetshHelperPath = "HKLM:\SOFTWARE\Microsoft\NetSh"
$NetshHelpers = Get-ItemProperty -Path $NetshHelperPath -ErrorAction SilentlyContinue

if ($NetshHelpers) {
    $Props = $NetshHelpers.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" }
    foreach ($Prop in $Props) {
        $DLLPath = $Prop.Value

        # Expand environment variables
        $DLLPath = [Environment]::ExpandEnvironmentVariables($DLLPath)

        # If just a filename (no path), assume it's in System32
        if (-not ($DLLPath -like "*\*" -or $DLLPath -like "*/*")) {
            $FullPath = Join-Path $env:SystemRoot "System32\$DLLPath"
            if (Test-Path $FullPath) {
                $Sig = Get-AuthenticodeSignature -FilePath $FullPath -ErrorAction SilentlyContinue
                if ($Sig.Status -eq "Valid" -and $Sig.SignerCertificate.Subject -like "*Microsoft*") {
                    # Standard Windows netsh helper - don't report (too noisy)
                } else {
                    Add-CheckResult -Category "Netsh" -Check "Netsh Helper" -Status "WARNING" -Details "$($Prop.Name) - $FullPath (Non-Microsoft or unsigned)"
                }
            } else {
                Add-CheckResult -Category "Netsh" -Check "Netsh Helper" -Status "WARNING" -Details "$($Prop.Name) - $DLLPath (DLL not found in System32)"
            }
        }
        # Check if it's in System32 (expected location)
        elseif ($DLLPath -like "*System32*" -or $DLLPath -like "*system32*") {
            if (Test-Path $DLLPath) {
                $Sig = Get-AuthenticodeSignature -FilePath $DLLPath -ErrorAction SilentlyContinue
                if ($Sig.Status -eq "Valid" -and $Sig.SignerCertificate.Subject -like "*Microsoft*") {
                    # Standard Windows netsh helper - don't report (too noisy)
                } else {
                    Add-CheckResult -Category "Netsh" -Check "Netsh Helper" -Status "WARNING" -Details "$($Prop.Name) - $DLLPath (Non-Microsoft or unsigned)"
                }
            }
        } else {
            Add-CheckResult -Category "Netsh" -Check "Netsh Helper" -Status "FAIL" -Details "SUSPICIOUS LOCATION: $($Prop.Name) - $DLLPath" -Remediation "Remove from HKLM:\SOFTWARE\Microsoft\NetSh"
        }
    }
}

# ============================================================================
# SECTION 21: OFFICE ADD-INS
# ============================================================================
Write-Report -Message "`n=== OFFICE ADD-INS ===" -Status "HEADER"

Write-Report -Message "  Checking Microsoft Office add-ins and startup items..." -Status "INFO"

# Office startup folders
$OfficeStartupPaths = @(
    "$env:APPDATA\Microsoft\Word\STARTUP",
    "$env:APPDATA\Microsoft\Excel\XLSTART",
    "$env:APPDATA\Microsoft\Outlook",
    "$env:APPDATA\Microsoft\AddIns"
)

foreach ($OffPath in $OfficeStartupPaths) {
    if (Test-Path $OffPath) {
        $OfficeFiles = Get-ChildItem -Path $OffPath -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -match "\.(dll|xla|xlam|dotm|dot|wll|ppa|ppam|vsto)$" }

        foreach ($OffFile in $OfficeFiles) {
            Add-CheckResult -Category "Office" -Check "Office Startup" -Status "WARNING" -Details "$($OffFile.FullName)" -Remediation "Verify this add-in is legitimate"
        }
    }
}

# Registry-based Office add-ins
$OfficeAddinPaths = @(
    "HKCU:\SOFTWARE\Microsoft\Office\*\*\Addins",
    "HKLM:\SOFTWARE\Microsoft\Office\*\*\Addins",
    "HKCU:\SOFTWARE\Wow6432Node\Microsoft\Office\*\*\Addins",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Office\*\*\Addins"
)

$AddinCount = 0
foreach ($AddinPath in $OfficeAddinPaths) {
    $Addins = Get-ChildItem -Path $AddinPath -ErrorAction SilentlyContinue
    foreach ($Addin in $Addins) {
        $LoadBehavior = (Get-ItemProperty -Path $Addin.PSPath -Name "LoadBehavior" -ErrorAction SilentlyContinue).LoadBehavior
        $Manifest = (Get-ItemProperty -Path $Addin.PSPath -Name "Manifest" -ErrorAction SilentlyContinue).Manifest
        $Description = (Get-ItemProperty -Path $Addin.PSPath -Name "Description" -ErrorAction SilentlyContinue).Description

        if ($LoadBehavior -ge 2) {
            # Add-in is configured to load
            $Details = "$($Addin.PSChildName)"
            if ($Description) { $Details += " - $Description" }
            if ($Manifest) { $Details += " ($Manifest)" }

            Add-CheckResult -Category "Office" -Check "Office Add-in" -Status "INFO" -Details $Details
            $AddinCount++
        }
    }
}

if ($AddinCount -eq 0) {
    Add-CheckResult -Category "Office" -Check "Office Add-ins" -Status "INFO" -Details "No active Office add-ins found"
}

# ============================================================================
# SECTION 22: RECENTLY ACCESSED FILES
# ============================================================================
Write-Report -Message "`n=== RECENTLY ACCESSED FILES ===" -Status "HEADER"

Write-Report -Message "  Checking recently accessed files for suspicious activity..." -Status "INFO"

# Recent items folder
$RecentPath = "$env:APPDATA\Microsoft\Windows\Recent"
if (Test-Path $RecentPath) {
    $RecentItems = Get-ChildItem -Path $RecentPath -Filter "*.lnk" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 50

    $SuspiciousExtensions = @(".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".scr", ".pif", ".msi")
    $SuspiciousRecentCount = 0

    $Shell = New-Object -ComObject WScript.Shell

    foreach ($Item in $RecentItems) {
        try {
            $Shortcut = $Shell.CreateShortcut($Item.FullName)
            $TargetPath = $Shortcut.TargetPath

            if ($TargetPath) {
                $TargetExt = [System.IO.Path]::GetExtension($TargetPath).ToLower()

                if ($SuspiciousExtensions -contains $TargetExt) {
                    # Check if from suspicious location
                    if ($TargetPath -match "(\\Temp\\|\\Downloads\\|\\AppData\\Local\\Temp)") {
                        Add-CheckResult -Category "Recent" -Check "Recent File" -Status "WARNING" -Details "Suspicious: $TargetPath (accessed: $($Item.LastWriteTime))"
                        $SuspiciousRecentCount++
                    }
                }
            }
        } catch {}
    }

    if ($SuspiciousRecentCount -eq 0) {
        Add-CheckResult -Category "Recent" -Check "Recent Files" -Status "PASS" -Details "No suspicious recently accessed executables from temp/download locations"
    }
}

# Prefetch files (shows what was executed)
Write-Report -Message "  Checking Prefetch for recently executed programs..." -Status "INFO"

$PrefetchPath = "$env:SystemRoot\Prefetch"
if (Test-Path $PrefetchPath) {
    $RecentPrefetch = Get-ChildItem -Path $PrefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 20

    $SuspiciousPrefetch = @(
        "MIMIKATZ", "PROCDUMP", "PSEXEC", "WMIC", "CERTUTIL",
        "BITSADMIN", "MSHTA", "REGSVR32", "RUNDLL32", "POWERSHELL",
        "CMD.EXE", "CSCRIPT", "WSCRIPT"
    )

    foreach ($Pf in $RecentPrefetch) {
        $PfName = $Pf.BaseName.Split("-")[0].ToUpper()

        foreach ($Susp in $SuspiciousPrefetch) {
            if ($PfName -like "*$Susp*") {
                Add-CheckResult -Category "Recent" -Check "Prefetch" -Status "WARNING" -Details "$($Pf.BaseName) - Last run: $($Pf.LastWriteTime)"
                break
            }
        }
    }
}

# ============================================================================
# SECTION 23: TEMP FILES AUDIT
# ============================================================================
Write-Report -Message "`n=== TEMP FILES AUDIT ===" -Status "HEADER"

Write-Report -Message "  WHY THIS MATTERS:" -Status "INFO"
Write-Report -Message "  Malware often drops executables in temp folders because they're writable" -Status "INFO"
Write-Report -Message "  by all users and rarely monitored. Finding EXE/DLL/SCR files in temp" -Status "INFO"
Write-Report -Message "  folders is suspicious. Large browser caches may contain malicious content." -Status "INFO"
Write-Report -Message "" -Status "INFO"
Write-Report -Message "  Checking temp folders for suspicious content..." -Status "INFO"

# Check temp folder sizes and suspicious files
$TempPaths = @(
    @{ Path = "$env:TEMP"; Name = "User Temp" },
    @{ Path = "$env:SystemRoot\Temp"; Name = "System Temp" },
    @{ Path = "$env:SystemRoot\Prefetch"; Name = "Prefetch" }
)

foreach ($TempInfo in $TempPaths) {
    if (Test-Path $TempInfo.Path) {
        $Files = Get-ChildItem -Path $TempInfo.Path -File -Recurse -ErrorAction SilentlyContinue
        $TotalSize = ($Files | Measure-Object -Property Length -Sum).Sum / 1MB
        $ExeCount = ($Files | Where-Object { $_.Extension -match "\.(exe|dll|scr|bat|cmd|ps1|vbs|js)$" }).Count

        $Status = "INFO"
        $Details = "$($TempInfo.Name): $([math]::Round($TotalSize, 2)) MB, $($Files.Count) files"

        if ($ExeCount -gt 0) {
            $Status = "WARNING"
            $Details += ", $ExeCount executables found"
        }

        Add-CheckResult -Category "TempFiles" -Check "Temp Folder" -Status $Status -Details $Details

        # List executables in temp and hash them
        if ($ExeCount -gt 0 -and $TempInfo.Name -ne "Prefetch") {
            $Exes = $Files | Where-Object { $_.Extension -match "\.(exe|dll|scr)$" } | Select-Object -First 10
            foreach ($Exe in $Exes) {
                Add-CheckResult -Category "TempFiles" -Check "Temp Executable" -Status "WARNING" -Details "$($Exe.FullName) ($([math]::Round($Exe.Length/1KB, 2)) KB)"
                Add-SuspiciousHash -FilePath $Exe.FullName -Category "TempExecutable" -Reason "Executable in temp folder"
            }
        }
    }
}

# Check browser cache sizes
Write-Report -Message "  Checking browser cache sizes..." -Status "INFO"

$BrowserCachePaths = @(
    @{ Path = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache"; Name = "Chrome Cache" },
    @{ Path = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache"; Name = "Edge Cache" },
    @{ Path = "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles"; Name = "Firefox Cache" }
)

foreach ($Cache in $BrowserCachePaths) {
    if (Test-Path $Cache.Path) {
        $CacheFiles = Get-ChildItem -Path $Cache.Path -File -Recurse -ErrorAction SilentlyContinue
        $CacheSize = ($CacheFiles | Measure-Object -Property Length -Sum).Sum / 1MB

        $Status = if ($CacheSize -gt 500) { "WARNING" } else { "INFO" }
        Add-CheckResult -Category "TempFiles" -Check "Browser Cache" -Status $Status -Details "$($Cache.Name): $([math]::Round($CacheSize, 2)) MB"
    }
}

# ============================================================================
# SECTION 24: PROXY SETTINGS HIJACKING
# ============================================================================
Write-Report -Message "`n=== PROXY SETTINGS CHECK ===" -Status "HEADER"

Write-Report -Message "  WHY THIS MATTERS:" -Status "INFO"
Write-Report -Message "  Malware can redirect all web traffic through attacker-controlled proxies" -Status "INFO"
Write-Report -Message "  to intercept passwords, inject ads, or block security updates. PAC files" -Status "INFO"
Write-Report -Message "  and WPAD can be abused for man-in-the-middle attacks. Unexpected proxy" -Status "INFO"
Write-Report -Message "  settings should be investigated and removed." -Status "INFO"
Write-Report -Message "" -Status "INFO"
Write-Report -Message "  Checking for proxy hijacking..." -Status "INFO"

# System proxy settings (Internet Options)
$IEProxyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
$ProxyEnable = (Get-ItemProperty -Path $IEProxyPath -Name "ProxyEnable" -ErrorAction SilentlyContinue).ProxyEnable
$ProxyServer = (Get-ItemProperty -Path $IEProxyPath -Name "ProxyServer" -ErrorAction SilentlyContinue).ProxyServer
$AutoConfigURL = (Get-ItemProperty -Path $IEProxyPath -Name "AutoConfigURL" -ErrorAction SilentlyContinue).AutoConfigURL

if ($ProxyEnable -eq 1 -and $ProxyServer) {
    Add-CheckResult -Category "Proxy" -Check "System Proxy" -Status "WARNING" -Details "Proxy enabled: $ProxyServer"
} else {
    Add-CheckResult -Category "Proxy" -Check "System Proxy" -Status "PASS" -Details "No system proxy configured"
}

if ($AutoConfigURL) {
    # PAC files can be used for traffic interception
    $Status = "WARNING"
    if ($AutoConfigURL -match "^(http://|file://|https?://127\.|https?://localhost)") {
        $Status = "FAIL"
    }
    Add-CheckResult -Category "Proxy" -Check "PAC Auto-Config" -Status $Status -Details "PAC URL: $AutoConfigURL"
} else {
    Add-CheckResult -Category "Proxy" -Check "PAC Auto-Config" -Status "PASS" -Details "No PAC auto-config URL"
}

# WPAD check
$WPADDisabled = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -ErrorAction SilentlyContinue).WpadOverride
if (-not $WPADDisabled) {
    Add-CheckResult -Category "Proxy" -Check "WPAD" -Status "INFO" -Details "WPAD auto-discovery enabled (potential for WPAD attacks)"
}

# Chrome proxy settings
$ChromePrefsPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Preferences"
if (Test-Path $ChromePrefsPath) {
    try {
        $ChromePrefs = Get-Content $ChromePrefsPath -Raw | ConvertFrom-Json
        if ($ChromePrefs.proxy -and $ChromePrefs.proxy.mode -ne "system") {
            Add-CheckResult -Category "Proxy" -Check "Chrome Proxy" -Status "WARNING" -Details "Chrome has custom proxy settings: $($ChromePrefs.proxy.mode)"
        }
    } catch {}
}

# Firefox proxy settings
$FFProfilePath = "$env:APPDATA\Mozilla\Firefox\Profiles"
if (Test-Path $FFProfilePath) {
    $FFProfiles = Get-ChildItem -Path $FFProfilePath -Directory -ErrorAction SilentlyContinue
    foreach ($Profile in $FFProfiles) {
        $PrefsFile = Join-Path $Profile.FullName "prefs.js"
        if (Test-Path $PrefsFile) {
            $PrefsContent = Get-Content $PrefsFile -Raw -ErrorAction SilentlyContinue
            if ($PrefsContent -match 'network\.proxy\.type.*[1-5]') {
                Add-CheckResult -Category "Proxy" -Check "Firefox Proxy" -Status "WARNING" -Details "Firefox has custom proxy settings in $($Profile.Name)"
            }
        }
    }
}

# ============================================================================
# SECTION 25: BROWSER HIJACKING
# ============================================================================
Write-Report -Message "`n=== BROWSER HIJACKING CHECK ===" -Status "HEADER"

Write-Report -Message "  WHY THIS MATTERS:" -Status "INFO"
Write-Report -Message "  Adware and browser hijackers modify browser shortcuts to add URLs that" -Status "INFO"
Write-Report -Message "  force the browser to open malicious/ad sites on every launch. They also" -Status "INFO"
Write-Report -Message "  change homepage and default search engines to monetize your searches." -Status "INFO"
Write-Report -Message "  Even after removal, these settings often persist and need manual cleanup." -Status "INFO"
Write-Report -Message "" -Status "INFO"
Write-Report -Message "  Checking browser shortcuts for tampering..." -Status "INFO"

# Check browser shortcut targets for URL injection
$ShortcutLocations = @(
    "$env:PUBLIC\Desktop",
    "$env:USERPROFILE\Desktop",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs"
)

$BrowserExes = @("chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe", "opera.exe")
$Shell = New-Object -ComObject WScript.Shell
$TamperedShortcuts = 0

foreach ($Location in $ShortcutLocations) {
    if (Test-Path $Location) {
        $Shortcuts = Get-ChildItem -Path $Location -Filter "*.lnk" -Recurse -ErrorAction SilentlyContinue
        foreach ($Shortcut in $Shortcuts) {
            try {
                $SC = $Shell.CreateShortcut($Shortcut.FullName)
                $Target = $SC.TargetPath
                $Args = $SC.Arguments

                # Check if it's a browser shortcut
                $IsBrowser = $false
                foreach ($Browser in $BrowserExes) {
                    if ($Target -like "*$Browser*") {
                        $IsBrowser = $true
                        break
                    }
                }

                if ($IsBrowser -and $Args) {
                    # Browser shortcuts shouldn't have URLs in arguments (hijacking indicator)
                    if ($Args -match "^https?://" -or $Args -match "^www\.") {
                        Add-CheckResult -Category "Browser" -Check "Shortcut Hijack" -Status "FAIL" -Details "Tampered: $($Shortcut.Name) -> $Args"
                        $TamperedShortcuts++
                    }
                }
            } catch {}
        }
    }
}

if ($TamperedShortcuts -eq 0) {
    Add-CheckResult -Category "Browser" -Check "Shortcut Hijack" -Status "PASS" -Details "No tampered browser shortcuts found"
}

# Check default browser homepage/search (Chrome)
Write-Report -Message "  Checking browser homepage and search settings..." -Status "INFO"

$ChromePrefsPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Preferences"
if (Test-Path $ChromePrefsPath) {
    try {
        $ChromePrefs = Get-Content $ChromePrefsPath -Raw | ConvertFrom-Json

        # Check homepage
        if ($ChromePrefs.homepage) {
            $Homepage = $ChromePrefs.homepage
            $SuspiciousHomepages = @("search", "home", "start", "newtab", "default")
            $IsSuspicious = $false
            foreach ($Susp in $SuspiciousHomepages) {
                if ($Homepage -match $Susp -and $Homepage -notmatch "(google|microsoft|bing|duckduckgo|yahoo)") {
                    $IsSuspicious = $true
                }
            }
            if ($IsSuspicious) {
                Add-CheckResult -Category "Browser" -Check "Chrome Homepage" -Status "WARNING" -Details "Potentially hijacked homepage: $Homepage"
            }
        }

        # Check search engine
        if ($ChromePrefs.default_search_provider_data -and $ChromePrefs.default_search_provider_data.template_url_data) {
            $SearchURL = $ChromePrefs.default_search_provider_data.template_url_data.url
            if ($SearchURL -and $SearchURL -notmatch "(google|bing|duckduckgo|yahoo|ecosia)") {
                Add-CheckResult -Category "Browser" -Check "Chrome Search" -Status "WARNING" -Details "Non-standard search engine: $SearchURL"
            }
        }
    } catch {}
}

# ============================================================================
# SECTION 26: FILE ASSOCIATION HIJACKING
# ============================================================================
Write-Report -Message "`n=== FILE ASSOCIATION CHECK ===" -Status "HEADER"

Write-Report -Message "  WHY THIS MATTERS:" -Status "INFO"
Write-Report -Message "  Malware can hijack file associations so that when you run an EXE, BAT," -Status "INFO"
Write-Report -Message "  or other executable, the malware runs instead (or in addition). This is" -Status "INFO"
Write-Report -Message "  a persistence technique - every time ANY program runs, the malware runs." -Status "INFO"
Write-Report -Message "  A hijacked .exe association can make the system nearly unusable." -Status "INFO"
Write-Report -Message "" -Status "INFO"
Write-Report -Message "  Checking file associations for hijacking..." -Status "INFO"

$CriticalAssociations = @(
    @{ Extension = ".exe"; Expected = '"%1" %*' },
    @{ Extension = ".com"; Expected = '"%1" %*' },
    @{ Extension = ".bat"; Expected = '"%1" %*' },
    @{ Extension = ".cmd"; Expected = '"%1" %*' },
    @{ Extension = ".ps1"; Expected = $null },  # Variable
    @{ Extension = ".vbs"; Expected = $null },
    @{ Extension = ".js"; Expected = $null },
    @{ Extension = ".reg"; Expected = $null }
)

foreach ($Assoc in $CriticalAssociations) {
    $Ext = $Assoc.Extension

    # Get file type
    $FileType = (Get-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\$Ext" -ErrorAction SilentlyContinue).'(default)'

    if ($FileType) {
        # Get command
        $Command = (Get-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\$FileType\shell\open\command" -ErrorAction SilentlyContinue).'(default)'

        if ($Command) {
            $Status = "INFO"
            $Details = "$Ext -> $Command"

            # Check for suspicious redirections
            if ($Command -match "(cmd\.exe.*\/c|powershell|wscript|cscript)" -and $Ext -eq ".exe") {
                $Status = "FAIL"
                $Details = "HIJACKED: $Ext -> $Command"
            }

            Add-CheckResult -Category "FileAssoc" -Check "File Association" -Status $Status -Details $Details
        }
    }
}

# Check exefile specifically (common target)
$ExeCommand = (Get-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\exefile\shell\open\command" -ErrorAction SilentlyContinue).'(default)'
if ($ExeCommand -and $ExeCommand -ne '"%1" %*') {
    Add-CheckResult -Category "FileAssoc" -Check "EXE Handler" -Status "FAIL" -Details "exefile handler modified: $ExeCommand"
} else {
    Add-CheckResult -Category "FileAssoc" -Check "EXE Handler" -Status "PASS" -Details "exefile handler is default"
}

# ============================================================================
# SECTION 27: EVENT LOG ANALYSIS
# ============================================================================
Write-Report -Message "`n=== EVENT LOG ANALYSIS ===" -Status "HEADER"

Write-Report -Message "  Analyzing security-relevant event logs (last 7 days)..." -Status "INFO"

$StartDate = (Get-Date).AddDays(-7)

# Check if Security log is accessible
$CanReadSecurityLog = $true
try {
    $null = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop
} catch {
    $CanReadSecurityLog = $false
    Add-CheckResult -Category "EventLog" -Check "Security Log Access" -Status "WARNING" -Details "Cannot read Security log (requires admin)"
}

if ($CanReadSecurityLog) {
    # Event ID 1102 - Audit log cleared (CRITICAL)
    $ClearedLogs = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=1102; StartTime=$StartDate} -ErrorAction SilentlyContinue
    if ($ClearedLogs) {
        foreach ($Event in $ClearedLogs) {
            Add-CheckResult -Category "EventLog" -Check "Log Cleared" -Status "FAIL" -Details "Security log was cleared on $($Event.TimeCreated)"
        }
    } else {
        Add-CheckResult -Category "EventLog" -Check "Log Cleared" -Status "PASS" -Details "No log clearing events found"
    }

    # Event ID 4720 - User account created
    $NewUsers = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4720; StartTime=$StartDate} -ErrorAction SilentlyContinue
    if ($NewUsers) {
        foreach ($Event in $NewUsers | Select-Object -First 5) {
            $UserName = ($Event.Properties[0]).Value
            Add-CheckResult -Category "EventLog" -Check "Account Created" -Status "WARNING" -Details "User '$UserName' created on $($Event.TimeCreated)"
        }
    }

    # Event ID 4625 - Failed logon attempts (brute force indicator)
    $FailedLogons = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=$StartDate} -ErrorAction SilentlyContinue
    $FailedCount = ($FailedLogons | Measure-Object).Count
    if ($FailedCount -gt 50) {
        Add-CheckResult -Category "EventLog" -Check "Failed Logons" -Status "WARNING" -Details "$FailedCount failed logon attempts in last 7 days (potential brute force)"
    } elseif ($FailedCount -gt 0) {
        Add-CheckResult -Category "EventLog" -Check "Failed Logons" -Status "INFO" -Details "$FailedCount failed logon attempts in last 7 days"
    }

    # Event ID 4672 - Special privileges assigned (admin logon)
    $PrivLogons = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4672; StartTime=$StartDate} -ErrorAction SilentlyContinue
    $PrivCount = ($PrivLogons | Measure-Object).Count
    Add-CheckResult -Category "EventLog" -Check "Privilege Logons" -Status "INFO" -Details "$PrivCount privileged logon events in last 7 days"
}

# System log - Event ID 7045 - Service installed
$NewServices = Get-WinEvent -FilterHashtable @{LogName='System'; ID=7045; StartTime=$StartDate} -ErrorAction SilentlyContinue
if ($NewServices) {
    foreach ($Event in $NewServices | Select-Object -First 10) {
        $ServiceName = ($Event.Properties[0]).Value
        $ServicePath = ($Event.Properties[1]).Value
        $Status = "INFO"

        # Flag suspicious service paths
        if ($ServicePath -match "(\\Temp\\|\\AppData\\|\\Downloads\\|powershell|cmd\.exe)") {
            $Status = "WARNING"
        }

        Add-CheckResult -Category "EventLog" -Check "Service Installed" -Status $Status -Details "$ServiceName -> $ServicePath"
    }
}

# Task Scheduler log - Event ID 106 - Scheduled task registered
try {
    $NewTasks = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational'; ID=106; StartTime=$StartDate} -ErrorAction SilentlyContinue
    if ($NewTasks) {
        foreach ($Event in $NewTasks | Select-Object -First 10) {
            $TaskName = ($Event.Properties[0]).Value
            Add-CheckResult -Category "EventLog" -Check "Task Created" -Status "INFO" -Details "Task '$TaskName' created on $($Event.TimeCreated)"
        }
    }
} catch {}

# PowerShell script block logging - Event ID 4104
try {
    $PSScriptBlocks = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104; StartTime=$StartDate} -MaxEvents 100 -ErrorAction SilentlyContinue

    $SuspiciousPS = @("Invoke-Mimikatz", "Invoke-Empire", "Invoke-PSInject", "Get-Keystrokes", "Invoke-DllInjection",
                      "Invoke-Shellcode", "Invoke-WMIMethod", "Invoke-ReflectivePEInjection", "Download", "DownloadString",
                      "IEX", "Invoke-Expression", "EncodedCommand", "FromBase64", "bypass", "hidden", "-nop", "-w hidden")

    foreach ($Event in $PSScriptBlocks) {
        $ScriptBlock = $Event.Properties[2].Value
        foreach ($Susp in $SuspiciousPS) {
            if ($ScriptBlock -match $Susp) {
                Add-CheckResult -Category "EventLog" -Check "Suspicious PowerShell" -Status "WARNING" -Details "Found '$Susp' in script block at $($Event.TimeCreated)"
                break
            }
        }
    }
} catch {}

# ============================================================================
# SECTION 28: SMART DISK HEALTH
# ============================================================================
Write-Report -Message "`n=== SMART DISK HEALTH ===" -Status "HEADER"

Write-Report -Message "  Checking disk SMART status..." -Status "INFO"

try {
    $Disks = Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction SilentlyContinue

    foreach ($Disk in $Disks) {
        if ($Disk.PredictFailure) {
            Add-CheckResult -Category "Disk" -Check "SMART Status" -Status "FAIL" -Details "Disk predicting failure: $($Disk.InstanceName)"
        }
    }

    # Get disk info
    $PhysicalDisks = Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction SilentlyContinue
    foreach ($Disk in $PhysicalDisks) {
        $Status = if ($Disk.Status -eq "OK") { "PASS" } else { "WARNING" }
        $SizeGB = [math]::Round($Disk.Size / 1GB, 2)
        Add-CheckResult -Category "Disk" -Check "Disk Status" -Status $Status -Details "$($Disk.Model) - $SizeGB GB - Status: $($Disk.Status)"
    }

    # Check disk space (low space can indicate ransomware)
    $Volumes = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue
    foreach ($Vol in $Volumes) {
        $FreePercent = [math]::Round(($Vol.FreeSpace / $Vol.Size) * 100, 1)
        $FreeGB = [math]::Round($Vol.FreeSpace / 1GB, 2)

        $Status = "PASS"
        if ($FreePercent -lt 5) { $Status = "FAIL" }
        elseif ($FreePercent -lt 15) { $Status = "WARNING" }

        Add-CheckResult -Category "Disk" -Check "Disk Space" -Status $Status -Details "$($Vol.DeviceID) $FreeGB GB free ($FreePercent%)"
    }
} catch {
    Add-CheckResult -Category "Disk" -Check "SMART Status" -Status "INFO" -Details "Could not query SMART status"
}

# ============================================================================
# SECTION 29: EXECUTABLES IN SUSPICIOUS LOCATIONS
# ============================================================================
Write-Report -Message "`n=== EXECUTABLES IN SUSPICIOUS LOCATIONS ===" -Status "HEADER"

Write-Report -Message "  WHY THIS MATTERS:" -Status "INFO"
Write-Report -Message "  Legitimate software installs to Program Files. Malware hides in unusual" -Status "INFO"
Write-Report -Message "  locations: Downloads, Temp, Documents, PerfLogs, C:\Intel, or the Recycle" -Status "INFO"
Write-Report -Message "  Bin. These locations are writable without admin rights and often overlooked." -Status "INFO"
Write-Report -Message "  Any EXE/DLL/SCR in these folders should be investigated." -Status "INFO"
Write-Report -Message "" -Status "INFO"
Write-Report -Message "  Checking for executables in suspicious locations..." -Status "INFO"

$SuspiciousLocations = @(
    @{ Path = "$env:USERPROFILE\Downloads"; Name = "Downloads" },
    @{ Path = "$env:TEMP"; Name = "User Temp" },
    @{ Path = "$env:SystemRoot\Temp"; Name = "System Temp" },
    @{ Path = "$env:USERPROFILE\Documents"; Name = "Documents" },
    @{ Path = "$env:LOCALAPPDATA\Temp"; Name = "LocalAppData Temp" },
    @{ Path = "$env:PUBLIC\Documents"; Name = "Public Documents" },
    @{ Path = "$env:SystemDrive\PerfLogs"; Name = "PerfLogs" },
    @{ Path = "$env:SystemDrive\Intel"; Name = "C:\Intel" },
    @{ Path = "$env:SystemDrive\Recovery"; Name = "C:\Recovery" }
)

$ExeExtensions = @("*.exe", "*.dll", "*.scr", "*.bat", "*.cmd", "*.ps1", "*.vbs", "*.js", "*.hta", "*.pif")

foreach ($Loc in $SuspiciousLocations) {
    if (Test-Path $Loc.Path) {
        $Executables = @()
        foreach ($Ext in $ExeExtensions) {
            $Executables += Get-ChildItem -Path $Loc.Path -Filter $Ext -Recurse -ErrorAction SilentlyContinue
        }

        if ($Executables.Count -gt 0) {
            Add-CheckResult -Category "SuspiciousExe" -Check "Location Check" -Status "WARNING" -Details "$($Loc.Name): $($Executables.Count) executables found"

            # List first 5 and hash them
            foreach ($Exe in ($Executables | Select-Object -First 5)) {
                $SizeKB = [math]::Round($Exe.Length / 1KB, 2)
                Add-CheckResult -Category "SuspiciousExe" -Check "Suspicious File" -Status "WARNING" -Details "$($Exe.FullName) ($SizeKB KB)"
                Add-SuspiciousHash -FilePath $Exe.FullName -Category "SuspiciousLocation" -Reason $Loc.Name
            }
        }
    }
}

# Check Recycle Bin for executables
$RecycleBinPath = "C:\`$Recycle.Bin"
if (Test-Path $RecycleBinPath) {
    $RecycleExes = Get-ChildItem -Path $RecycleBinPath -Filter "*.exe" -Recurse -Force -ErrorAction SilentlyContinue
    if ($RecycleExes.Count -gt 0) {
        Add-CheckResult -Category "SuspiciousExe" -Check "Recycle Bin" -Status "INFO" -Details "$($RecycleExes.Count) executables in Recycle Bin"
    }
}

# ============================================================================
# SECTION 30: NETWORK INDICATORS
# ============================================================================
Write-Report -Message "`n=== NETWORK INDICATORS ===" -Status "HEADER"

Write-Report -Message "  WHY THIS MATTERS:" -Status "INFO"
Write-Report -Message "  Active malware maintains connections to command-and-control (C2) servers." -Status "INFO"
Write-Report -Message "  Look for: connections on unusual ports (4444, 5555, 31337), processes like" -Status "INFO"
Write-Report -Message "  powershell/cmd with outbound connections, or multiple IPs sharing one MAC" -Status "INFO"
Write-Report -Message "  (ARP spoofing). Unknown listening ports may indicate backdoors." -Status "INFO"
Write-Report -Message "" -Status "INFO"
Write-Report -Message "  Checking active network connections..." -Status "INFO"

# Active TCP connections with process info
$Connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
    Where-Object { $_.RemoteAddress -notmatch "^(127\.|::1|0\.0\.0\.0)" }

$SuspiciousPorts = @(4444, 5555, 6666, 7777, 8888, 9999, 1234, 31337, 12345, 54321)
$ConnectionCount = 0

foreach ($Conn in $Connections) {
    try {
        $Process = Get-Process -Id $Conn.OwningProcess -ErrorAction SilentlyContinue
        $ProcessName = if ($Process) { $Process.ProcessName } else { "Unknown" }

        $Status = "INFO"
        if ($SuspiciousPorts -contains $Conn.RemotePort -or $SuspiciousPorts -contains $Conn.LocalPort) {
            $Status = "WARNING"
        }

        # Only log non-standard connections
        if ($Conn.RemotePort -notin @(80, 443, 53) -or $Status -eq "WARNING") {
            Add-CheckResult -Category "Network" -Check "TCP Connection" -Status $Status -Details "$ProcessName -> $($Conn.RemoteAddress):$($Conn.RemotePort)"
            $ConnectionCount++
        }
    } catch {}

    if ($ConnectionCount -ge 20) { break }  # Limit output
}

# Listening ports
Write-Report -Message "  Checking listening ports..." -Status "INFO"

$Listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalAddress -notmatch "^(::1|127\.0\.0\.1)$" }

$SuspiciousListeners = @()
foreach ($Listener in $Listeners) {
    try {
        $Process = Get-Process -Id $Listener.OwningProcess -ErrorAction SilentlyContinue
        $ProcessName = if ($Process) { $Process.ProcessName } else { "Unknown" }

        # Flag unusual listeners
        if ($Listener.LocalPort -in $SuspiciousPorts -or
            ($ProcessName -match "(powershell|cmd|wscript|cscript|mshta)")) {
            Add-CheckResult -Category "Network" -Check "Suspicious Listener" -Status "WARNING" -Details "$ProcessName listening on port $($Listener.LocalPort)"
        }
    } catch {}
}

# ARP cache check
Write-Report -Message "  Checking ARP cache for anomalies..." -Status "INFO"

$ArpCache = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Reachable" }
$MacAddresses = $ArpCache | Group-Object LinkLayerAddress | Where-Object { $_.Count -gt 1 }

foreach ($DupMac in $MacAddresses) {
    if ($DupMac.Count -gt 1) {
        $IPs = ($DupMac.Group | Select-Object -ExpandProperty IPAddress) -join ", "
        Add-CheckResult -Category "Network" -Check "ARP Anomaly" -Status "WARNING" -Details "MAC $($DupMac.Name) maps to multiple IPs: $IPs (possible ARP spoofing)"
    }
}

# Active SMB shares
$Shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch "^(ADMIN\$|C\$|IPC\$)$" }
foreach ($Share in $Shares) {
    Add-CheckResult -Category "Network" -Check "SMB Share" -Status "INFO" -Details "Share: $($Share.Name) -> $($Share.Path)"
}

# ============================================================================
# SECTION 31: USB/EXTERNAL DEVICE HISTORY
# ============================================================================
Write-Report -Message "`n=== USB/EXTERNAL DEVICE HISTORY ===" -Status "HEADER"

Write-Report -Message "  WHY THIS MATTERS:" -Status "INFO"
Write-Report -Message "  USB devices are a common malware infection vector. Knowing what devices" -Status "INFO"
Write-Report -Message "  have been connected helps trace infection sources. If investigating a" -Status "INFO"
Write-Report -Message "  breach, USB history shows what storage devices may have exfiltrated data" -Status "INFO"
Write-Report -Message "  or introduced malware to the system." -Status "INFO"
Write-Report -Message "" -Status "INFO"
Write-Report -Message "  Checking USB device history..." -Status "INFO"

# USB storage devices from registry
$USBStorPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"
if (Test-Path $USBStorPath) {
    $USBDevices = Get-ChildItem -Path $USBStorPath -ErrorAction SilentlyContinue

    $USBCount = 0
    foreach ($Device in $USBDevices) {
        $Instances = Get-ChildItem -Path $Device.PSPath -ErrorAction SilentlyContinue
        foreach ($Instance in $Instances) {
            $FriendlyName = (Get-ItemProperty -Path $Instance.PSPath -Name "FriendlyName" -ErrorAction SilentlyContinue).FriendlyName
            if ($FriendlyName) {
                Add-CheckResult -Category "USB" -Check "USB History" -Status "INFO" -Details "Previously connected: $FriendlyName"
                $USBCount++
            }
        }
        if ($USBCount -ge 10) { break }
    }

    if ($USBCount -eq 0) {
        Add-CheckResult -Category "USB" -Check "USB History" -Status "INFO" -Details "No USB storage device history found"
    }
}

# Currently mounted removable drives
$RemovableDrives = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=2" -ErrorAction SilentlyContinue
foreach ($Drive in $RemovableDrives) {
    Add-CheckResult -Category "USB" -Check "Removable Drive" -Status "INFO" -Details "Currently mounted: $($Drive.DeviceID) ($($Drive.VolumeName))"
}

# ============================================================================
# SECTION 32: RANSOMWARE INDICATORS
# ============================================================================
Write-Report -Message "`n=== RANSOMWARE INDICATORS ===" -Status "HEADER"

Write-Report -Message "  WHY THIS MATTERS:" -Status "INFO"
Write-Report -Message "  Ransomware encrypts files and leaves telltale signs: files with extensions" -Status "INFO"
Write-Report -Message "  like .locky, .cerber, .wannacry, .lockbit, and ransom notes (README.txt," -Status "INFO"
Write-Report -Message "  HOW_TO_DECRYPT, etc.). Early detection of these indicators is critical." -Status "INFO"
Write-Report -Message "  Finding these files means the system is compromised and needs isolation." -Status "INFO"
Write-Report -Message "" -Status "INFO"
Write-Report -Message "  Checking for ransomware indicators..." -Status "INFO"

# Known ransomware file extensions (excluding .mp3 which is legitimate audio format)
$RansomwareExtensions = @(
    ".locky", ".zepto", ".cerber", ".cerber2", ".cerber3", ".crypt", ".crypted",
    ".enc", ".locked", ".crypto", ".crinf", ".r5a", ".XRNT", ".XTBL", ".R16M01D05",
    ".pzdc", ".good", ".LOL!", ".OMG!", ".RDM", ".RRK", ".encryptedRSA", ".crysis", ".dharma",
    ".wallet", ".onion", ".zzzzz", ".micro", ".xxx", ".ttt", ".osiris", ".thor",
    ".aesir", ".odin", ".shit", ".amber", ".wncry", ".wcry", ".wanna", ".wannacry",
    ".petya", ".notpetya", ".GandCrab", ".KRAB", ".CRAB", ".sage", ".globe", ".ryuk",
    ".RYK", ".maze", ".egregor", ".conti", ".lockbit", ".blackcat", ".alphv"
)
# Note: .encrypted removed - too many false positives with Excel temp files (~$*.xlsx.encrypted)

$RansomwareFound = 0
$SearchPaths = @("$env:USERPROFILE\Documents", "$env:USERPROFILE\Desktop", "$env:PUBLIC\Documents")

foreach ($SearchPath in $SearchPaths) {
    if (Test-Path $SearchPath) {
        foreach ($Ext in $RansomwareExtensions) {
            $EncryptedFiles = Get-ChildItem -Path $SearchPath -Filter "*$Ext" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 3
            foreach ($File in $EncryptedFiles) {
                Add-CheckResult -Category "Ransomware" -Check "Encrypted File" -Status "FAIL" -Details "Potential ransomware: $($File.FullName)"
                $RansomwareFound++
            }
        }
        if ($RansomwareFound -ge 10) { break }
    }
}

# Check for ransom notes (specific patterns, not generic folder names)
$RansomNotePatterns = @(
    "DECRYPT*.txt", "HOW_TO_DECRYPT*.txt", "HELP_DECRYPT*.txt", "RECOVERY_*.txt",
    "RESTORE_*.txt", "_readme.txt", "@Please_Read_Me@*.txt", "HELP_YOUR_FILES*.txt",
    "YOUR_FILES_ARE*.txt", "*RANSOM*.txt", "*DECRYPT_INSTRUCTION*.txt", "_HELP_*.txt",
    "!README!.txt", "!!!README!!!.txt", "READ_ME_*.txt", "*_RECOVER_*.txt"
)

foreach ($SearchPath in $SearchPaths) {
    if (Test-Path $SearchPath) {
        foreach ($Pattern in $RansomNotePatterns) {
            $Notes = Get-ChildItem -Path $SearchPath -Filter $Pattern -Recurse -ErrorAction SilentlyContinue | Select-Object -First 2
            foreach ($Note in $Notes) {
                Add-CheckResult -Category "Ransomware" -Check "Ransom Note" -Status "FAIL" -Details "Potential ransom note: $($Note.FullName)"
            }
        }
    }
}

if ($RansomwareFound -eq 0) {
    Add-CheckResult -Category "Ransomware" -Check "Ransomware Check" -Status "PASS" -Details "No known ransomware indicators found"
}

# ============================================================================
# SECTION 33: POWERSHELL HISTORY
# ============================================================================
Write-Report -Message "`n=== POWERSHELL HISTORY ===" -Status "HEADER"

Write-Report -Message "  WHY THIS MATTERS:" -Status "INFO"
Write-Report -Message "  PowerShell is the #1 tool for attackers on Windows. The PSReadLine history" -Status "INFO"
Write-Report -Message "  file records commands run interactively. Look for: Invoke-WebRequest," -Status "INFO"
Write-Report -Message "  DownloadString, IEX, encoded commands, -bypass, -hidden flags, and known" -Status "INFO"
Write-Report -Message "  attack tools like Mimikatz. This can reveal attacker activity." -Status "INFO"
Write-Report -Message "" -Status "INFO"
Write-Report -Message "  Checking PowerShell command history..." -Status "INFO"

# PSReadline history file
$PSHistoryPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"

if (Test-Path $PSHistoryPath) {
    $History = Get-Content $PSHistoryPath -Tail 500 -ErrorAction SilentlyContinue

    $SuspiciousCommands = @(
        "Invoke-WebRequest", "Invoke-RestMethod", "DownloadString", "DownloadFile",
        "IEX", "Invoke-Expression", "EncodedCommand", "FromBase64String", "bypass",
        "-nop", "-noprofile", "-w hidden", "-windowstyle hidden", "Net.WebClient",
        "Start-BitsTransfer", "certutil", "bitsadmin", "Invoke-Mimikatz", "sekurlsa",
        "Get-Credential", "ConvertTo-SecureString", "reg add", "reg delete", "schtasks",
        "New-Service", "sc create", "Add-MpPreference", "Set-MpPreference -Exclusion"
    )

    $FoundSuspicious = @()
    foreach ($Cmd in $History) {
        foreach ($Susp in $SuspiciousCommands) {
            if ($Cmd -match [regex]::Escape($Susp)) {
                $FoundSuspicious += @{ Command = $Cmd; Pattern = $Susp }
                break
            }
        }
    }

    if ($FoundSuspicious.Count -gt 0) {
        Add-CheckResult -Category "PSHistory" -Check "PS History" -Status "WARNING" -Details "Found $($FoundSuspicious.Count) suspicious commands in history"
        foreach ($Item in ($FoundSuspicious | Select-Object -First 5)) {
            $TruncatedCmd = if ($Item.Command.Length -gt 100) { $Item.Command.Substring(0, 100) + "..." } else { $Item.Command }
            Add-CheckResult -Category "PSHistory" -Check "Suspicious Command" -Status "WARNING" -Details $TruncatedCmd
        }
    } else {
        Add-CheckResult -Category "PSHistory" -Check "PS History" -Status "PASS" -Details "No suspicious commands found in PowerShell history"
    }

    Add-CheckResult -Category "PSHistory" -Check "History Size" -Status "INFO" -Details "PowerShell history: $($History.Count) commands"
} else {
    Add-CheckResult -Category "PSHistory" -Check "PS History" -Status "INFO" -Details "No PowerShell history file found"
}

# ============================================================================
# SECTION 34: IFEO EXTENDED CHECK
# ============================================================================
Write-Report -Message "`n=== IFEO EXTENDED CHECK ===" -Status "HEADER"

Write-Report -Message "  WHY THIS MATTERS:" -Status "INFO"
Write-Report -Message "  Image File Execution Options (IFEO) can attach a debugger to any process." -Status "INFO"
Write-Report -Message "  Attackers abuse this to hijack executables: when you run notepad.exe," -Status "INFO"
Write-Report -Message "  malware runs instead. SilentProcessExit monitoring is another technique" -Status "INFO"
Write-Report -Message "  to run code when specific processes terminate. Both are persistence methods." -Status "INFO"
Write-Report -Message "" -Status "INFO"
Write-Report -Message "  Checking Image File Execution Options for abuse..." -Status "INFO"

$IFEOPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
$IFEOIssuesFound = $false

try {
    if (Test-Path $IFEOPath) {
        $IFEOEntries = Get-ChildItem -Path $IFEOPath -ErrorAction SilentlyContinue

        foreach ($Entry in $IFEOEntries) {
            try {
                $ExeName = $Entry.PSChildName
                if (-not $ExeName) { continue }

                $Debugger = (Get-ItemProperty -Path $Entry.PSPath -Name "Debugger" -ErrorAction SilentlyContinue).Debugger
                $GlobalFlag = (Get-ItemProperty -Path $Entry.PSPath -Name "GlobalFlag" -ErrorAction SilentlyContinue).GlobalFlag

                # Check for debugger hijacking
                if ($Debugger) {
                    # Whitelist legitimate debuggers
                    if ($Debugger -notmatch "(devenv|vsjitdebugger|windbg|ntsd|cdb|procdump)") {
                        Add-CheckResult -Category "IFEO" -Check "Debugger Hijack" -Status "FAIL" -Details "$ExeName -> $Debugger"
                        $IFEOIssuesFound = $true

                        # Add remediation item
                        $regPath = $Entry.PSPath
                        Add-RemediationItem -Category "IFEO Debugger Hijack" `
                            -Description "$ExeName hijacked by: $Debugger" `
                            -Risk "High" `
                            -ActionDescription "Remove Debugger value from IFEO registry key" `
                            -Action ([scriptblock]::Create("Remove-ItemProperty -Path '$regPath' -Name 'Debugger' -Force"))
                    }
                }

                # GlobalFlag for monitoring (sometimes abused)
                if ($GlobalFlag) {
                    # Check SilentProcessExit monitoring (separate registry location)
                    $SilentProcessExitPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\$ExeName"
                    if (Test-Path $SilentProcessExitPath -ErrorAction SilentlyContinue) {
                        $MonitorProcess = (Get-ItemProperty -Path $SilentProcessExitPath -Name "MonitorProcess" -ErrorAction SilentlyContinue).MonitorProcess
                        if ($MonitorProcess) {
                            Add-CheckResult -Category "IFEO" -Check "Silent Process Exit" -Status "WARNING" -Details "$ExeName monitored by $MonitorProcess"
                            $IFEOIssuesFound = $true

                            # Add remediation item
                            $spePath = $SilentProcessExitPath
                            Add-RemediationItem -Category "SilentProcessExit Monitor" `
                                -Description "$ExeName monitored by $MonitorProcess" `
                                -Risk "Medium" `
                                -ActionDescription "Remove SilentProcessExit registry key for $ExeName" `
                                -Action ([scriptblock]::Create("Remove-Item -Path '$spePath' -Recurse -Force"))
                        }
                    }
                }
            } catch {
                # Skip individual entry errors
            }
        }
    }
} catch {
    Add-CheckResult -Category "IFEO" -Check "IFEO Check" -Status "INFO" -Details "Unable to check IFEO registry"
}

if (-not $IFEOIssuesFound) {
    Add-CheckResult -Category "IFEO" -Check "IFEO Check" -Status "PASS" -Details "No suspicious IFEO entries found"
}

# ============================================================================
# SECTION 35: BROKEN SHORTCUTS / ORPHANED DIRECTORIES
# ============================================================================
Write-Report -Message "`n=== BROKEN SHORTCUTS / ORPHANED DIRECTORIES ===" -Status "HEADER"

Write-Report -Message "  WHY THIS MATTERS:" -Status "INFO"
Write-Report -Message "  Broken shortcuts pointing to missing files may indicate malware that was" -Status "INFO"
Write-Report -Message "  partially removed or moved. Orphaned folders in Program Files (with no" -Status "INFO"
Write-Report -Message "  executables) are remnants of uninstalled software - sometimes malware" -Status "INFO"
Write-Report -Message "  that antivirus removed but left folders behind. Cleanup improves hygiene." -Status "INFO"
Write-Report -Message "" -Status "INFO"
Write-Report -Message "  Checking for broken shortcuts..." -Status "INFO"

$Shell = New-Object -ComObject WScript.Shell
$ShortcutPaths = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs",
    "$env:USERPROFILE\Desktop",
    "$env:PUBLIC\Desktop"
)

$BrokenShortcuts = 0
foreach ($Path in $ShortcutPaths) {
    if (Test-Path $Path) {
        $Shortcuts = Get-ChildItem -Path $Path -Filter "*.lnk" -Recurse -ErrorAction SilentlyContinue
        foreach ($Shortcut in $Shortcuts) {
            try {
                $SC = $Shell.CreateShortcut($Shortcut.FullName)
                $Target = $SC.TargetPath

                if ($Target -and -not (Test-Path $Target)) {
                    Add-CheckResult -Category "Shortcuts" -Check "Broken Shortcut" -Status "INFO" -Details "$($Shortcut.Name) -> $Target (missing)"
                    $BrokenShortcuts++
                }
            } catch {}

            if ($BrokenShortcuts -ge 15) { break }
        }
    }
}

if ($BrokenShortcuts -eq 0) {
    Add-CheckResult -Category "Shortcuts" -Check "Broken Shortcuts" -Status "PASS" -Details "No broken shortcuts found"
}

# Check for orphaned Program Files directories
Write-Report -Message "  Checking for orphaned Program Files directories..." -Status "INFO"

$ProgramDirs = @("$env:ProgramFiles", "${env:ProgramFiles(x86)}")
$OrphanedDirs = 0

foreach ($ProgramDir in $ProgramDirs) {
    if (Test-Path $ProgramDir) {
        $SubDirs = Get-ChildItem -Path $ProgramDir -Directory -ErrorAction SilentlyContinue
        foreach ($Dir in $SubDirs) {
            # Check if directory has any executables
            $Exes = Get-ChildItem -Path $Dir.FullName -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            $Dlls = Get-ChildItem -Path $Dir.FullName -Filter "*.dll" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1

            if (-not $Exes -and -not $Dlls) {
                # No executables - might be orphaned
                $FileCount = (Get-ChildItem -Path $Dir.FullName -File -Recurse -ErrorAction SilentlyContinue | Measure-Object).Count
                if ($FileCount -lt 5) {
                    Add-CheckResult -Category "Shortcuts" -Check "Orphaned Dir" -Status "INFO" -Details "$($Dir.FullName) (no executables, $FileCount files)"
                    $OrphanedDirs++
                }
            }

            if ($OrphanedDirs -ge 10) { break }
        }
    }
}

# ============================================================================
# SECTION 36: WINDOWS POLICIES HIJACKING
# ============================================================================
Write-Report -Message "`n=== WINDOWS POLICIES CHECK ===" -Status "HEADER"

Write-Report -Message "  WHY THIS MATTERS:" -Status "INFO"
Write-Report -Message "  Malware often disables Windows security features via registry policies:" -Status "INFO"
Write-Report -Message "  Task Manager, Registry Editor, Command Prompt, Control Panel, and Defender." -Status "INFO"
Write-Report -Message "  This prevents users from investigating or removing the infection. Some" -Status "INFO"
Write-Report -Message "  ransomware also damages Safe Mode to prevent recovery. These must be fixed." -Status "INFO"
Write-Report -Message "" -Status "INFO"
Write-Report -Message "  Checking for malicious policy restrictions..." -Status "INFO"

$PolicyChecks = @(
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "DisableTaskMgr"; Description = "Task Manager disabled" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "DisableRegistryTools"; Description = "Registry Editor disabled" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "DisableCMD"; Description = "Command Prompt disabled" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoRun"; Description = "Run dialog disabled" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoControlPanel"; Description = "Control Panel disabled" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoFolderOptions"; Description = "Folder Options disabled" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoDrives"; Description = "Drives hidden" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoViewOnDrive"; Description = "Drive access restricted" },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "DisableTaskMgr"; Description = "Task Manager disabled (system)" },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "DisableRegistryTools"; Description = "Registry Editor disabled (system)" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; Name = "DisableAntiSpyware"; Description = "Windows Defender disabled by policy" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableRealtimeMonitoring"; Description = "Real-time protection disabled by policy" }
)

$RestrictionsFound = 0
foreach ($Check in $PolicyChecks) {
    if (Test-Path $Check.Path) {
        $Value = (Get-ItemProperty -Path $Check.Path -Name $Check.Name -ErrorAction SilentlyContinue).$($Check.Name)
        if ($Value -eq 1) {
            Add-CheckResult -Category "Policies" -Check "Policy Restriction" -Status "FAIL" -Details $Check.Description
            $RestrictionsFound++
        }
    }
}

if ($RestrictionsFound -eq 0) {
    Add-CheckResult -Category "Policies" -Check "Policy Restrictions" -Status "PASS" -Details "No malicious policy restrictions found"
}

# Check for hidden files/folders policy
$ShowHidden = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -ErrorAction SilentlyContinue).Hidden
$ShowSuperHidden = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSuperHidden" -ErrorAction SilentlyContinue).ShowSuperHidden

if ($ShowHidden -eq 2 -or $ShowSuperHidden -eq 0) {
    Add-CheckResult -Category "Policies" -Check "Hidden Files" -Status "INFO" -Details "Hidden files/folders are not shown (malware may hide this way)"
}

# Check for Safe Mode restrictions (ransomware often disables)
$SafeBootPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot"
if (-not (Test-Path "$SafeBootPath\Minimal") -or -not (Test-Path "$SafeBootPath\Network")) {
    Add-CheckResult -Category "Policies" -Check "Safe Mode" -Status "FAIL" -Details "Safe Mode registry keys may be damaged or removed"
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

# Output hash file summary
if ($Script:HashCount -gt 0) {
    Write-Host "  Hashes saved: $HashFile ($Script:HashCount files)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  To check hashes against VirusTotal:" -ForegroundColor Cyan
    Write-Host "    1. Visit https://www.virustotal.com/gui/home/search" -ForegroundColor Gray
    Write-Host "    2. Paste MD5 or SHA256 hash from the file" -ForegroundColor Gray
    Write-Host "    3. Review detection results" -ForegroundColor Gray
}

# ============================================================================
# REMEDIATION PHASE
# ============================================================================
if ($Script:RemediationItems.Count -gt 0) {
    Write-Host ""
    Write-Host "  --------------------------------------------------------------------------------" -ForegroundColor DarkGray
    $response = ""
    while ($response -notmatch "^[YN]$") {
        Write-Host "  $($Script:RemediationItems.Count) issue(s) can be fixed. Enter remediation phase? [Y/N]: " -NoNewline -ForegroundColor Yellow
        $response = (Read-Host).ToUpper()
    }
    if ($response -eq "Y") {
        Invoke-Remediation
    } else {
        Write-Host "  Remediation skipped." -ForegroundColor Gray
    }
}

Write-Host ""

#endregion
