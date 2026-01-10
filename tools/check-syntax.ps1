# Set UTF-8 encoding for proper emoji handling
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$errors = @()
# Only check the main project folders, exclude testsetup and testing folders
# Testing folder has emoji literals that may not parse correctly on all systems
$foldersToCheck = @(
    "E:\COOLForge\modules",
    "E:\COOLForge\scripts",
    "E:\COOLForge\launchers",
    "E:\COOLForge\templates",
    "E:\COOLForge\tools",
    "E:\COOLForge\automations"
)

$allFiles = @()
foreach ($folder in $foldersToCheck) {
    if (Test-Path $folder) {
        $allFiles += Get-ChildItem -Path $folder -Recurse -Filter "*.ps1"
    }
}

Write-Host "Checking $($allFiles.Count) PowerShell files..."

foreach ($file in $allFiles) {
    $parseErrors = $null
    $tokens = $null
    try {
        $null = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$parseErrors)
        if ($parseErrors -and $parseErrors.Count -gt 0) {
            foreach ($err in $parseErrors) {
                $errors += [PSCustomObject]@{
                    File = $file.Name
                    Line = $err.Extent.StartLineNumber
                    Message = $err.Message
                }
            }
        }
    } catch {
        $errors += [PSCustomObject]@{
            File = $file.Name
            Line = 0
            Message = "Parse exception: $($_.Exception.Message)"
        }
    }
}

if ($errors.Count -gt 0) {
    Write-Host "`nSyntax errors found:" -ForegroundColor Red
    $errors | Format-Table File, Line, Message -AutoSize -Wrap
    exit 1
} else {
    Write-Host "All $($allFiles.Count) scripts pass syntax check" -ForegroundColor Green
    exit 0
}
