<#
.SYNOPSIS
    Creates a new Level.io client with standardized group hierarchy.

.DESCRIPTION
    This script creates a new client (company or personal) in Level.io with a
    standardized group structure for one or more sites.

    The client group name is prefixed with emojis indicating:
    - Client type: Business (U+1F3E2) or Personal (U+1F6D6)
    - Priority level: 1-5 using keycap number emojis

    Example: A priority 1 business "AcmeCorp" becomes: (building)(1)AcmeCorp

    Structure created:
    CLIENT_NAME
    +-- SITE1
    |   +-- WS (Workstations)
    |   |   +-- (window) WIN
    |   |   +-- (penguin) LINUX (optional)
    |   |   +-- (apple) MAC (optional)
    |   +-- SRV (Servers)
    |       +-- (window) WIN
    |       +-- (penguin) LINUX (optional)
    |       +-- (apple) MAC (optional)
    +-- SITE2
        +-- ...

    The script guides you through:
    1. Client name
    2. Client type (Business/Personal)
    3. Priority level (1-5)
    4. Platform support (Mac? Linux?)
    5. Site creation loop
    6. Custom field configuration

.NOTES
    Version:          2026.01.13.02
    Target Platform:  Windows PowerShell 5.1+

    API Documentation: https://levelapi.readme.io/

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge

.EXAMPLE
    .\New-LevelClient.ps1

    Interactive mode - prompts for all options.

.EXAMPLE
    .\New-LevelClient.ps1 -CompanyName "ClientA"

    Creates client "ClientA", prompts for type, priority, and sites.

.EXAMPLE
    .\New-LevelClient.ps1 -CompanyName "ClientA" -IncludeMac -IncludeLinux

    Creates client with Mac and Linux groups at all sites.

.EXAMPLE
    .\New-LevelClient.ps1 -DryRun

    Preview what would be created without making changes.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$CompanyName,

    [Parameter(Mandatory = $false)]
    [string]$ParentGroupName,

    [Parameter(Mandatory = $false)]
    [string]$ApiKey,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeMac,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeLinux,

    [Parameter(Mandatory = $false)]
    [switch]$DryRun
)

# ============================================================
# IMPORT SHARED MODULE
# ============================================================

# Try current folder first (for standalone deployment), then parent folder (for repo structure)
$ModulePath = Join-Path $PSScriptRoot "modules\COOLForge-Common.psm1"
if (-not (Test-Path $ModulePath)) {
    $ModulePath = Join-Path (Split-Path $PSScriptRoot -Parent) "modules\COOLForge-Common.psm1"
}

if (-not (Test-Path $ModulePath)) {
    Write-Host "[X] Module not found: $ModulePath" -ForegroundColor Red
    Write-Host "    Please ensure COOLForge-Common.psm1 is in the modules/ folder." -ForegroundColor Yellow
    exit 1
}

Import-Module $ModulePath -Force -DisableNameChecking

# ============================================================
# CONFIGURATION
# ============================================================

$Script:ConfigFileName = ".COOLForge_Lib-setup.json"
$Script:ConfigPath = Join-Path $PSScriptRoot $Script:ConfigFileName
$Script:LevelApiBaseUrl = "https://api.level.io/v2"
$Script:ResolvedApiKey = $null

# Track created groups for summary
$Script:CreatedGroups = @()

# Platform emojis (using Unicode code points to avoid encoding issues)
$Script:EmojiWin = [char]::ConvertFromUtf32(0x1FA9F)    # Window emoji
$Script:EmojiLinux = [char]::ConvertFromUtf32(0x1F427)  # Penguin emoji
$Script:EmojiMac = [char]::ConvertFromUtf32(0x1F34E)    # Apple emoji

# Client type emojis
$Script:EmojiBusiness = [char]::ConvertFromUtf32(0x1F3E2)  # Office building U+1F3E2
$Script:EmojiPersonal = [char]::ConvertFromUtf32(0x1F6D6)  # Hut U+1F6D6

# Priority number emojis (keycap digits 1-5)
$Script:EmojiPriority = @{
    1 = "1" + [char]::ConvertFromUtf32(0xFE0F) + [char]::ConvertFromUtf32(0x20E3)  # 1️⃣
    2 = "2" + [char]::ConvertFromUtf32(0xFE0F) + [char]::ConvertFromUtf32(0x20E3)  # 2️⃣
    3 = "3" + [char]::ConvertFromUtf32(0xFE0F) + [char]::ConvertFromUtf32(0x20E3)  # 3️⃣
    4 = "4" + [char]::ConvertFromUtf32(0xFE0F) + [char]::ConvertFromUtf32(0x20E3)  # 4️⃣
    5 = "5" + [char]::ConvertFromUtf32(0xFE0F) + [char]::ConvertFromUtf32(0x20E3)  # 5️⃣
}

# ============================================================
# HELPER FUNCTIONS
# ============================================================

function New-LevelGroup {
    <#
    .SYNOPSIS
        Creates a new group in Level.io.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [string]$ParentId
    )

    if ($DryRun) {
        Write-Host "  [DRY-RUN] Would create: $Name" -ForegroundColor Yellow
        return @{
            id   = "dry-run-$([guid]::NewGuid().ToString().Substring(0,8))"
            name = $Name
        }
    }

    $Body = @{
        name = $Name
    }

    if (-not [string]::IsNullOrWhiteSpace($ParentId)) {
        $Body.parent_id = $ParentId
    }

    $Result = Invoke-LevelApiCall -Uri "$Script:LevelApiBaseUrl/groups" -ApiKey $Script:ResolvedApiKey -Method "POST" -Body $Body

    if ($Result.Success) {
        $Script:CreatedGroups += @{
            Id   = $Result.Data.id
            Name = $Name
        }
        return $Result.Data
    }
    else {
        Write-LevelError "Failed to create group '$Name': $($Result.Error)"
        return $null
    }
}

# ============================================================
# MAIN SCRIPT
# ============================================================

Write-Header "New Level.io Group Structure"

Write-Host "This tool creates a standardized group hierarchy for a new company/site."
Write-Host ""

if ($DryRun) {
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host " DRY RUN MODE - No changes will be made" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host ""
}

# Load saved configuration for API key
$SavedConfig = Get-SavedConfig -Path $Script:ConfigPath

# Get API Key
if (-not [string]::IsNullOrWhiteSpace($ApiKey)) {
    $Script:ResolvedApiKey = $ApiKey
}
elseif ($SavedConfig -and $SavedConfig.CoolForge_ApiKeyEncrypted) {
    $DecryptedKey = Unprotect-ApiKey -EncryptedText $SavedConfig.CoolForge_ApiKeyEncrypted
    if ($DecryptedKey) {
        Write-LevelInfo "Using saved API key."
        $Script:ResolvedApiKey = $DecryptedKey
    }
}
elseif ($SavedConfig -and $SavedConfig.ApiKeyEncrypted) {
    $DecryptedKey = Unprotect-ApiKey -EncryptedText $SavedConfig.ApiKeyEncrypted
    if ($DecryptedKey) {
        Write-LevelInfo "Using saved API key."
        $Script:ResolvedApiKey = $DecryptedKey
    }
}

if ([string]::IsNullOrWhiteSpace($Script:ResolvedApiKey)) {
    Write-Host ""
    Write-Host "Get your API key at: https://app.level.io/api-keys" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Enter your Level.io API key: " -NoNewline -ForegroundColor Yellow
    $SecureKey = Read-Host -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureKey)
    $Script:ResolvedApiKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
}

if ([string]::IsNullOrWhiteSpace($Script:ResolvedApiKey)) {
    Write-LevelError "API key is required. Exiting."
    exit 1
}

# Test API connection
Write-Header "Testing API Connection"

Write-Host "Connecting to Level.io API..." -ForegroundColor DarkGray
$AllGroups = Get-LevelGroups -ApiKey $Script:ResolvedApiKey -BaseUrl $Script:LevelApiBaseUrl

if ($null -eq $AllGroups) {
    Write-LevelError "Could not connect to Level.io API. Please check your API key."
    exit 1
}

Write-LevelSuccess "Connected! Found $($AllGroups.Count) existing groups."

# ============================================================
# GET COMPANY NAME
# ============================================================

Write-Header "Company Configuration"

if ([string]::IsNullOrWhiteSpace($CompanyName)) {
    Write-Host "Enter the company or client name." -ForegroundColor White
    Write-Host "Example: AcmeCorp, ClientA, etc." -ForegroundColor DarkGray
    Write-Host ""

    $CompanyName = Read-UserInput -Prompt "Company name" -Default ""

    if ([string]::IsNullOrWhiteSpace($CompanyName)) {
        Write-LevelError "Company name is required. Exiting."
        exit 1
    }
}

# ============================================================
# CLIENT TYPE AND PRIORITY
# ============================================================

Write-Header "Client Classification"

Write-Host "What type of client is this?" -ForegroundColor Cyan
Write-Host ""
Write-Host "  [B] Business / Company  $Script:EmojiBusiness" -ForegroundColor Yellow
Write-Host "  [P] Personal / Home user  $Script:EmojiPersonal" -ForegroundColor Yellow
Write-Host ""

$ClientTypeChoice = Read-UserInput -Prompt "Client type" -Default "B"
$IsBusiness = $ClientTypeChoice.ToUpper() -ne "P"

if ($IsBusiness) {
    $ClientTypeEmoji = $Script:EmojiBusiness
    Write-LevelInfo "Client type: Business $Script:EmojiBusiness"
}
else {
    $ClientTypeEmoji = $Script:EmojiPersonal
    Write-LevelInfo "Client type: Personal $Script:EmojiPersonal"
}

Write-Host ""
Write-Host "What is the priority level? (1 = highest, 5 = lowest)" -ForegroundColor Cyan
Write-Host ""
Write-Host "  [1] Critical / VIP  $($Script:EmojiPriority[1])" -ForegroundColor Yellow
Write-Host "  [2] High priority  $($Script:EmojiPriority[2])" -ForegroundColor Yellow
Write-Host "  [3] Normal  $($Script:EmojiPriority[3])" -ForegroundColor Yellow
Write-Host "  [4] Low priority  $($Script:EmojiPriority[4])" -ForegroundColor Yellow
Write-Host "  [5] Minimal  $($Script:EmojiPriority[5])" -ForegroundColor Yellow
Write-Host ""

$PriorityChoice = Read-UserInput -Prompt "Priority (1-5)" -Default "3"
if ($PriorityChoice -match '^[1-5]$') {
    $PriorityLevel = [int]$PriorityChoice
}
else {
    $PriorityLevel = 3
    Write-LevelWarning "Invalid priority, defaulting to 3"
}

$PriorityEmoji = $Script:EmojiPriority[$PriorityLevel]
Write-LevelInfo "Priority: $PriorityLevel $PriorityEmoji"

# Build the full company group name with emoji prefix
$FullCompanyName = "$ClientTypeEmoji$PriorityEmoji$CompanyName"

Write-Host ""
Write-Host "Company group will be named: $FullCompanyName" -ForegroundColor Green

# Check if company group already exists (check both with and without emojis)
$ExistingCompany = $AllGroups | Where-Object {
    $_.name -ieq $FullCompanyName -or $_.name -ieq $CompanyName
} | Select-Object -First 1

if ($ExistingCompany) {
    Write-LevelWarning "A group named '$($ExistingCompany.name)' already exists!"
    if (-not (Read-YesNo -Prompt "Continue and add sites under existing group" -Default $false)) {
        Write-LevelInfo "Cancelled."
        exit 0
    }
}

# ============================================================
# SELECT PARENT GROUP (OPTIONAL)
# ============================================================

Write-Header "Parent Group"

$ParentGroupId = $null

if (-not [string]::IsNullOrWhiteSpace($ParentGroupName)) {
    $ParentGroup = $AllGroups | Where-Object { $_.name -ieq $ParentGroupName } | Select-Object -First 1
    if ($ParentGroup) {
        $ParentGroupId = $ParentGroup.id
        Write-LevelInfo "Will create under: $($ParentGroup.name)"
    }
    else {
        Write-LevelWarning "Parent group '$ParentGroupName' not found. Will create at root level."
    }
}
else {
    Write-Host "Where should the company group be created?" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [R] Root level (no parent)" -ForegroundColor Yellow
    Write-Host "  [S] Select a parent group" -ForegroundColor Yellow
    Write-Host ""

    $ParentChoice = Read-UserInput -Prompt "Choice" -Default "R"

    if ($ParentChoice.ToUpper() -eq "S") {
        Write-Host ""
        Write-Host "Available groups:" -ForegroundColor Cyan

        $Index = 1
        $GroupList = @()
        foreach ($G in $AllGroups | Sort-Object name) {
            Write-Host "  [$Index] $($G.name)" -ForegroundColor White
            $GroupList += $G
            $Index++
        }

        Write-Host ""
        $ParentNum = Read-UserInput -Prompt "Select parent group number" -Default ""

        if ($ParentNum -match '^\d+$') {
            $ParentIdx = [int]$ParentNum
            if ($ParentIdx -ge 1 -and $ParentIdx -le $GroupList.Count) {
                $ParentGroupId = $GroupList[$ParentIdx - 1].id
                Write-LevelInfo "Will create under: $($GroupList[$ParentIdx - 1].name)"
            }
        }
    }
    else {
        Write-LevelInfo "Will create at root level."
    }
}

# ============================================================
# COMPANY-WIDE PLATFORM CONFIGURATION
# ============================================================

Write-Header "Company Platform Configuration"

Write-Host "These questions determine the default platforms for all sites." -ForegroundColor Cyan
Write-Host "You can override per-site if needed." -ForegroundColor DarkGray
Write-Host "(Windows groups are always created)" -ForegroundColor DarkGray
Write-Host ""

# Company-wide defaults
$Script:CompanyHasMac = $IncludeMac.IsPresent
$Script:CompanyHasLinux = $IncludeLinux.IsPresent

if (-not $IncludeMac.IsPresent) {
    $Script:CompanyHasMac = Read-YesNo -Prompt "Does this company have any Macs" -Default $false
}
if (-not $IncludeLinux.IsPresent) {
    $Script:CompanyHasLinux = Read-YesNo -Prompt "Does this company have any Linux devices" -Default $true
}

Write-Host ""
if ($Script:CompanyHasMac) {
    Write-LevelInfo "Mac groups will be created by default at each site"
}
if ($Script:CompanyHasLinux) {
    Write-LevelInfo "Linux groups will be created by default at each site"
}

# ============================================================
# CREATE COMPANY GROUP
# ============================================================

Write-Header "Creating Company Group"

$CompanyGroup = $null
if ($ExistingCompany) {
    $CompanyGroup = $ExistingCompany
    Write-LevelInfo "Using existing group: $($ExistingCompany.name)"
}
else {
    Write-Host "Creating: $FullCompanyName" -ForegroundColor DarkGray
    $CompanyGroup = New-LevelGroup -Name $FullCompanyName -ParentId $ParentGroupId
    if (-not $CompanyGroup) {
        Write-LevelError "Failed to create company group. Exiting."
        exit 1
    }
    Write-LevelSuccess "Created: $FullCompanyName"
}

# ============================================================
# SITE CREATION LOOP
# ============================================================

$SiteNumber = 1
$ContinueAddingSites = $true

while ($ContinueAddingSites) {
    Write-Header "Site #$SiteNumber Configuration"

    # Get site name
    $DefaultSiteName = if ($SiteNumber -eq 1) { "Main" } else { "" }
    Write-Host "Enter the site or location name." -ForegroundColor White
    Write-Host "Example: HQ, Main, Sydney, Branch1, etc." -ForegroundColor DarkGray
    Write-Host ""

    $SiteName = Read-UserInput -Prompt "Site name" -Default $DefaultSiteName

    if ([string]::IsNullOrWhiteSpace($SiteName)) {
        Write-LevelWarning "No site name provided."
        if ($SiteNumber -eq 1) {
            Write-LevelError "At least one site is required. Exiting."
            exit 1
        }
        break
    }

    # Check for existing site under this company
    $ExistingSite = $AllGroups | Where-Object {
        $_.name -ieq $SiteName -and $_.parent_id -eq $CompanyGroup.id
    } | Select-Object -First 1

    if ($ExistingSite) {
        Write-LevelWarning "Site '$SiteName' already exists under $FullCompanyName!"
        if (-not (Read-YesNo -Prompt "Skip and continue to next site" -Default $true)) {
            continue
        }
        else {
            $SiteNumber++
            $ContinueAddingSites = Read-YesNo -Prompt "Add another site" -Default $false
            continue
        }
    }

    # Per-site platform overrides
    Write-Host ""
    Write-Host "Platform configuration for $SiteName" -ForegroundColor Cyan
    Write-Host "(Press Enter to use company defaults)" -ForegroundColor DarkGray
    Write-Host ""

    # Determine site-specific settings (default to company settings)
    $SiteHasMacWs = $Script:CompanyHasMac
    $SiteHasMacSrv = $Script:CompanyHasMac
    $SiteHasLinuxWs = $Script:CompanyHasLinux
    $SiteHasLinuxSrv = $Script:CompanyHasLinux

    # Only ask for overrides if company has the platform
    if ($Script:CompanyHasMac) {
        $SiteHasMacWs = Read-YesNo -Prompt "  Mac workstations at this site" -Default $true
        $SiteHasMacSrv = Read-YesNo -Prompt "  Mac servers at this site" -Default $false
    }

    if ($Script:CompanyHasLinux) {
        $SiteHasLinuxWs = Read-YesNo -Prompt "  Linux workstations at this site" -Default $false
        $SiteHasLinuxSrv = Read-YesNo -Prompt "  Linux servers at this site" -Default $true
    }

    # Preview site structure
    Write-Host ""
    Write-Host "Site structure to create:" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  $FullCompanyName" -ForegroundColor DarkGray
    Write-Host "  └── $SiteName" -ForegroundColor Green
    Write-Host "      ├── WS" -ForegroundColor Green
    Write-Host "      │   ├── $Script:EmojiWin WIN" -ForegroundColor White
    if ($SiteHasLinuxWs) {
        Write-Host "      │   ├── $Script:EmojiLinux LINUX" -ForegroundColor White
    }
    if ($SiteHasMacWs) {
        Write-Host "      │   └── $Script:EmojiMac MAC" -ForegroundColor White
    }
    Write-Host "      └── SRV" -ForegroundColor Green
    Write-Host "          ├── $Script:EmojiWin WIN" -ForegroundColor White
    if ($SiteHasLinuxSrv) {
        Write-Host "          ├── $Script:EmojiLinux LINUX" -ForegroundColor White
    }
    if ($SiteHasMacSrv) {
        Write-Host "          └── $Script:EmojiMac MAC" -ForegroundColor White
    }
    Write-Host ""

    if (-not $DryRun) {
        if (-not (Read-YesNo -Prompt "Create this site structure" -Default $true)) {
            Write-LevelInfo "Skipped site: $SiteName"
            $ContinueAddingSites = Read-YesNo -Prompt "Add another site" -Default $false
            continue
        }
    }

    # Create site groups
    Write-Host ""
    Write-Host "Creating site: $SiteName" -ForegroundColor Cyan

    # Create site group
    Write-Host "  Creating: $SiteName" -ForegroundColor DarkGray
    $SiteGroup = New-LevelGroup -Name $SiteName -ParentId $CompanyGroup.id
    if (-not $SiteGroup) {
        Write-LevelError "  Failed to create site group."
        $ContinueAddingSites = Read-YesNo -Prompt "Try another site" -Default $false
        continue
    }
    Write-LevelSuccess "  Created: $SiteName"

    # Create WS (Workstations) group
    Write-Host "  Creating: WS" -ForegroundColor DarkGray
    $WsGroup = New-LevelGroup -Name "WS" -ParentId $SiteGroup.id
    if ($WsGroup) {
        Write-LevelSuccess "  Created: WS"

        # Create workstation platform groups
        Write-Host "    Creating: $Script:EmojiWin WIN" -ForegroundColor DarkGray
        $WsWin = New-LevelGroup -Name "$Script:EmojiWin WIN" -ParentId $WsGroup.id
        if ($WsWin) { Write-LevelSuccess "    Created: $Script:EmojiWin WIN" }

        if ($SiteHasLinuxWs) {
            Write-Host "    Creating: $Script:EmojiLinux LINUX" -ForegroundColor DarkGray
            $WsLinux = New-LevelGroup -Name "$Script:EmojiLinux LINUX" -ParentId $WsGroup.id
            if ($WsLinux) { Write-LevelSuccess "    Created: $Script:EmojiLinux LINUX" }
        }

        if ($SiteHasMacWs) {
            Write-Host "    Creating: $Script:EmojiMac MAC" -ForegroundColor DarkGray
            $WsMac = New-LevelGroup -Name "$Script:EmojiMac MAC" -ParentId $WsGroup.id
            if ($WsMac) { Write-LevelSuccess "    Created: $Script:EmojiMac MAC" }
        }
    }

    # Create SRV (Servers) group
    Write-Host "  Creating: SRV" -ForegroundColor DarkGray
    $SrvGroup = New-LevelGroup -Name "SRV" -ParentId $SiteGroup.id
    if ($SrvGroup) {
        Write-LevelSuccess "  Created: SRV"

        # Create server platform groups
        Write-Host "    Creating: $Script:EmojiWin WIN" -ForegroundColor DarkGray
        $SrvWin = New-LevelGroup -Name "$Script:EmojiWin WIN" -ParentId $SrvGroup.id
        if ($SrvWin) { Write-LevelSuccess "    Created: $Script:EmojiWin WIN" }

        if ($SiteHasLinuxSrv) {
            Write-Host "    Creating: $Script:EmojiLinux LINUX" -ForegroundColor DarkGray
            $SrvLinux = New-LevelGroup -Name "$Script:EmojiLinux LINUX" -ParentId $SrvGroup.id
            if ($SrvLinux) { Write-LevelSuccess "    Created: $Script:EmojiLinux LINUX" }
        }

        if ($SiteHasMacSrv) {
            Write-Host "    Creating: $Script:EmojiMac MAC" -ForegroundColor DarkGray
            $SrvMac = New-LevelGroup -Name "$Script:EmojiMac MAC" -ParentId $SrvGroup.id
            if ($SrvMac) { Write-LevelSuccess "    Created: $Script:EmojiMac MAC" }
        }
    }

    Write-Host ""
    Write-LevelSuccess "Site '$SiteName' created!"

    # Ask about adding more sites
    $SiteNumber++
    $ContinueAddingSites = Read-YesNo -Prompt "Add another site" -Default $false
}

# ============================================================
# CUSTOM FIELD CONFIGURATION
# ============================================================

Write-Header "Custom Field Configuration"

Write-Host "Now configure custom field values for the new groups." -ForegroundColor Cyan
Write-Host "Press Enter to inherit from parent/organization (no override)." -ForegroundColor DarkGray
Write-Host "Enter a value to set it specifically for that group." -ForegroundColor DarkGray
Write-Host ""

# Get all custom fields
$CustomFields = Get-LevelCustomFields -ApiKey $Script:ResolvedApiKey -BaseUrl $Script:LevelApiBaseUrl

if (-not $CustomFields -or $CustomFields.Count -eq 0) {
    Write-LevelInfo "No custom fields found. Skipping configuration."
}
else {
    Write-Host "Found $($CustomFields.Count) custom field(s)." -ForegroundColor DarkGray
    Write-Host ""

    # Ask if user wants to configure custom fields
    if (Read-YesNo -Prompt "Configure custom fields for new groups" -Default $true) {

        # Process each created group (company first, then sites/subgroups)
        foreach ($Group in $Script:CreatedGroups) {
            Write-Host ""
            Write-Host "----------------------------------------" -ForegroundColor DarkGray
            Write-Host "Group: $($Group.Name)" -ForegroundColor Cyan
            Write-Host "----------------------------------------" -ForegroundColor DarkGray

            $FieldsConfigured = 0

            foreach ($Field in $CustomFields) {
                # Skip admin-only fields display for cleaner output (still configurable)
                $AdminTag = if ($Field.admin_only) { " [admin]" } else { "" }

                Write-Host ""
                Write-Host "  $($Field.name)$AdminTag" -ForegroundColor Yellow

                # Get current/inherited value for context
                $CurrentValue = ""
                if (-not $DryRun) {
                    $GroupFields = Get-LevelEntityCustomFields -ApiKey $Script:ResolvedApiKey -EntityType "folder" -EntityId $Group.Id
                    if ($GroupFields -and $GroupFields.PSObject.Properties[$Field.name]) {
                        $CurrentValue = $GroupFields.($Field.name)
                    }
                }

                if (-not [string]::IsNullOrWhiteSpace($CurrentValue)) {
                    Write-Host "  Current/inherited: $CurrentValue" -ForegroundColor DarkGray
                }
                else {
                    Write-Host "  Current/inherited: (empty/inherit)" -ForegroundColor DarkGray
                }

                $NewValue = Read-UserInput -Prompt "  Value (Enter to inherit)" -Default ""

                if (-not [string]::IsNullOrWhiteSpace($NewValue)) {
                    if ($DryRun) {
                        Write-Host "  [DRY-RUN] Would set: $NewValue" -ForegroundColor Yellow
                    }
                    else {
                        $SetResult = Set-LevelCustomFieldValue -ApiKey $Script:ResolvedApiKey `
                            -EntityType "folder" -EntityId $Group.Id `
                            -FieldReference $Field.name -Value $NewValue

                        if ($SetResult) {
                            Write-LevelSuccess "  Set: $($Field.name) = $NewValue"
                            $FieldsConfigured++
                        }
                        else {
                            Write-LevelWarning "  Failed to set value"
                        }
                    }
                }
                else {
                    Write-Host "  (inheriting from parent)" -ForegroundColor DarkGray
                }
            }

            if ($FieldsConfigured -gt 0) {
                Write-LevelInfo "Configured $FieldsConfigured field(s) for $($Group.Name)"
            }
        }
    }
    else {
        Write-LevelInfo "Skipped custom field configuration. Groups will inherit all values."
    }
}

# ============================================================
# SUMMARY
# ============================================================

Write-Header "Complete"

if ($DryRun) {
    Write-Host "Dry run complete. No changes were made." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "To create the groups, run without -DryRun" -ForegroundColor White
}
else {
    $SitesCreated = $SiteNumber - 1
    Write-Host "Group structure created successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Company: $FullCompanyName" -ForegroundColor Cyan
    Write-Host "Sites created: $SitesCreated" -ForegroundColor Cyan
    Write-Host "Total groups: $($Script:CreatedGroups.Count)" -ForegroundColor Cyan
    Write-Host ""

    # Show tree of created groups
    Write-Host "Created groups:" -ForegroundColor White
    foreach ($Group in $Script:CreatedGroups) {
        Write-Host "  - $($Group.Name)" -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "You can now assign devices to these groups in Level.io." -ForegroundColor DarkGray
}

Write-Host ""



