# Send-LevelSupportQuestions.ps1
# Checks LEVEL-SUPPORT-QUESTIONS.md for new questions, emails them to Level support,
# and moves them to LEVEL-SUPPORT-SUBMITTED.md
#
# Usage: Run manually or schedule with Task Scheduler
# Example: schtasks /create /tn "Send Level Questions" /tr "powershell -File E:\COOLForge\tools\Send-LevelSupportQuestions.ps1" /sc hourly /mo 4

param(
    [string]$SmtpServer = "192.168.189.1",
    [string]$FromAddress = "allen@cool.net.au",
    [string]$ToAddress = "support@level.io",
    [string]$RepoPath = "E:\COOLForge",
    [string]$BackupPath = "E:\supportquestions",
    [switch]$WhatIf
)

$QuestionsFile = Join-Path $RepoPath "mynotes\LEVEL-SUPPORT-QUESTIONS.md"
$SubmittedFile = Join-Path $RepoPath "mynotes\LEVEL-SUPPORT-SUBMITTED.md"
$Today = Get-Date -Format "yyyy-MM-dd"
$Timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"

# Ensure backup folder exists
if (!(Test-Path $BackupPath)) {
    New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null
}

# Read the questions file
$QuestionsContent = Get-Content $QuestionsFile -Raw

# Find the "Pending Questions for Level.io" section - capture everything from that header to the footer
if ($QuestionsContent -notmatch '(?s)## Pending Questions for Level\.io\s*\r?\n(.+?)(?=\r?\n\*Document created|\z)') {
    Write-Host "No pending questions section found."
    exit 0
}

$PendingSection = $Matches[1].Trim()

# Check if there are actual questions (not just the "no pending" message or empty)
if ($PendingSection -match '^\*No pending questions' -or $PendingSection -match '^\*All submitted' -or $PendingSection -match '^---\s*$') {
    Write-Host "No new questions to send."
    exit 0
}

# Parse questions - look for ### headers
$Questions = @()
$CurrentQuestion = $null

foreach ($Line in ($PendingSection -split '\r?\n')) {
    if ($Line -match '^### (.+)$') {
        if ($CurrentQuestion) {
            $Questions += $CurrentQuestion
        }
        $CurrentQuestion = @{
            Title = $Matches[1].Trim()
            Content = @()
        }
    }
    elseif ($CurrentQuestion) {
        $CurrentQuestion.Content += $Line
    }
}
if ($CurrentQuestion) {
    $Questions += $CurrentQuestion
}

if ($Questions.Count -eq 0) {
    Write-Host "No questions found to send."
    exit 0
}

Write-Host "Found $($Questions.Count) question(s) to send:"

foreach ($Q in $Questions) {
    Write-Host "  - $($Q.Title)"

    $BodyLines = $Q.Content -join "`n"
    $Body = @"
Hi Level Support,

$($Q.Title)

$BodyLines

Thanks,
Allen
"@

    $Subject = "Question: $($Q.Title)"

    if ($WhatIf) {
        Write-Host "    [WhatIf] Would send email with subject: $Subject"
    }
    else {
        try {
            Send-MailMessage -SmtpServer $SmtpServer -From $FromAddress -To $ToAddress -Cc $FromAddress -Subject $Subject -Body $Body
            Write-Host "    Sent email: $Subject"
        }
        catch {
            Write-Error "Failed to send email for '$($Q.Title)': $_"
            continue
        }
    }
}

if ($WhatIf) {
    Write-Host "[WhatIf] Would update files. Run without -WhatIf to make changes."
    exit 0
}

# Build submitted entries
$SubmittedEntries = ""
foreach ($Q in $Questions) {
    # Join content lines, preserving structure (question already has **Question:** etc.)
    $BodyLines = ($Q.Content | Where-Object { $_.Trim() }) -join "`n`n"
    $SubmittedEntries += @"

---

## $($Q.Title)

**Submitted:** $Today

$BodyLines

**Response:**

"@
}

# Read submitted file and insert new entries before the last entry
$SubmittedContent = Get-Content $SubmittedFile -Raw

# Find the last "---" before EOF and insert before it, or append
if ($SubmittedContent -match '(.*\*\*Response:\*\*\s*\r?\n\r?\n---\s*)$') {
    # Append after the last complete entry
    $SubmittedContent = $SubmittedContent.TrimEnd() + "`n" + $SubmittedEntries
}
else {
    # Just append
    $SubmittedContent = $SubmittedContent.TrimEnd() + "`n" + $SubmittedEntries
}

# Update questions file - clear pending section (must match search regex pattern)
$NewQuestionsContent = $QuestionsContent -replace `
    '(?s)(## Pending Questions for Level\.io\s*\r?\n).+?(?=\r?\n\*Document created|\z)', `
    "`$1`n*No pending questions - all submitted. See [LEVEL-SUPPORT-SUBMITTED.md](LEVEL-SUPPORT-SUBMITTED.md)*`n`n"

# Backup files before writing
$QuestionsBackup = Join-Path $BackupPath "LEVEL-SUPPORT-QUESTIONS_$Timestamp.md"
$SubmittedBackup = Join-Path $BackupPath "LEVEL-SUPPORT-SUBMITTED_$Timestamp.md"
$LatestFile = Join-Path $BackupPath "LATEST.md"
Copy-Item -Path $QuestionsFile -Destination $QuestionsBackup -Force
if (Test-Path $SubmittedFile) {
    Copy-Item -Path $SubmittedFile -Destination $SubmittedBackup -Force
}

# Create combined latest file
$LatestContent = @"
# Level.io Support - Combined Backup
# Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

================================================================================
FILE: LEVEL-SUPPORT-QUESTIONS.md (Pending)
================================================================================

$QuestionsContent

================================================================================
FILE: LEVEL-SUPPORT-SUBMITTED.md (Submitted)
================================================================================

$SubmittedContent
"@
[System.IO.File]::WriteAllText($LatestFile, $LatestContent, [System.Text.UTF8Encoding]::new($true))
Write-Host "[*] Backups saved to $BackupPath"

# Write files
[System.IO.File]::WriteAllText($SubmittedFile, $SubmittedContent, [System.Text.UTF8Encoding]::new($true))
[System.IO.File]::WriteAllText($QuestionsFile, $NewQuestionsContent, [System.Text.UTF8Encoding]::new($true))

Write-Host "Done. Sent $($Questions.Count) question(s) and updated tracking files."
