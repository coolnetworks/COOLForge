# Cross-reference validation for custom fields and tags
# Verifies that fields/tags used in scripts are defined in definitions/*.json

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

# Determine project root from script location
$ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if (-not (Test-Path "$ProjectRoot\modules")) {
    $ProjectRoot = Split-Path $PSScriptRoot -Parent
}

# Load definition files
$CustomFieldsPath = "$ProjectRoot\definitions\custom-fields.json"
$TagsPath = "$ProjectRoot\definitions\tags.json"

if (-not (Test-Path $CustomFieldsPath)) {
    Write-Host "Missing: definitions/custom-fields.json" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $TagsPath)) {
    Write-Host "Missing: definitions/tags.json" -ForegroundColor Red
    exit 1
}

Write-Host "Loading definition files..."
$CustomFields = Get-Content $CustomFieldsPath -Raw | ConvertFrom-Json
$Tags = Get-Content $TagsPath -Raw | ConvertFrom-Json

# Extract all defined field names
$DefinedFields = @()
foreach ($group in $CustomFields.fields.PSObject.Properties) {
    foreach ($field in $group.Value) {
        $DefinedFields += $field.name
        if ($field.legacyNames) {
            $DefinedFields += $field.legacyNames
        }
    }
}
$DefinedFields = $DefinedFields | Sort-Object -Unique
Write-Host "  Found $($DefinedFields.Count) defined custom fields"

# Extract all defined tag patterns (from softwareDefinitions)
$DefinedTags = @()
foreach ($sw in $Tags.softwareDefinitions.PSObject.Properties) {
    $DefinedTags += $sw.Value.tags
}
# Add global tags
foreach ($gt in $Tags.globalTags.tags) {
    $DefinedTags += $gt.emoji
}
$DefinedTags = $DefinedTags | Sort-Object -Unique
Write-Host "  Found $($DefinedTags.Count) defined tags"

# Scan scripts for field and tag usage
$foldersToCheck = @(
    "$ProjectRoot\modules",
    "$ProjectRoot\scripts",
    "$ProjectRoot\launchers",
    "$ProjectRoot\start_here"
)

$allFiles = @()
foreach ($folder in $foldersToCheck) {
    if (Test-Path $folder) {
        $allFiles += Get-ChildItem -Path $folder -Recurse -Filter "*.ps1"
        $allFiles += Get-ChildItem -Path $folder -Recurse -Filter "*.psm1"
    }
}

Write-Host "Scanning $($allFiles.Count) files for field/tag usage..."

$undefinedFields = @{}
$undefinedTags = @{}

foreach ($file in $allFiles) {
    $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
    if (-not $content) { continue }

    $relativePath = $file.FullName.Replace($ProjectRoot, ".")

    # Find {{cf_*}} patterns (Level.io custom field references)
    $fieldMatches = [regex]::Matches($content, '\{\{cf_([a-z0-9_]+)\}\}')
    foreach ($match in $fieldMatches) {
        $fieldName = $match.Groups[1].Value
        if ($fieldName -notin $DefinedFields) {
            if (-not $undefinedFields.ContainsKey($fieldName)) {
                $undefinedFields[$fieldName] = @()
            }
            if ($relativePath -notin $undefinedFields[$fieldName]) {
                $undefinedFields[$fieldName] += $relativePath
            }
        }
    }

    # Find emoji+SOFTWARE tag patterns (limited to known emoji prefixes to reduce false positives)
    # Looking for patterns like: "HUNTRESS", "UNCHECKY" with emoji prefixes
    $tagPatterns = @(
        # Install emoji U+1F64F
        '\u{1F64F}([A-Z_]+)',
        # Remove emoji U+1F6AB
        '\u{1F6AB}([A-Z_]+)',
        # Pin emoji U+1F4CC
        '\u{1F4CC}([A-Z_]+)',
        # Reinstall emoji U+1F504
        '\u{1F504}([A-Z_]+)',
        # Checkmark U+2705
        '\u{2705}([A-Z_]+)'
    )

    # Also check for literal emoji patterns in the content
    $emojiPrefixes = @(
        [char]::ConvertFromUtf32(0x1F64F),  # Pray/Install
        [char]::ConvertFromUtf32(0x1F6AB),  # Prohibited/Remove
        [char]::ConvertFromUtf32(0x1F4CC),  # Pushpin/Pin
        [char]::ConvertFromUtf32(0x1F504),  # Arrows/Reinstall
        [char]::ConvertFromUtf32(0x2705)    # Checkmark
    )

    foreach ($prefix in $emojiPrefixes) {
        $tagMatches = [regex]::Matches($content, [regex]::Escape($prefix) + '([A-Z][A-Z0-9_]+)')
        foreach ($match in $tagMatches) {
            $tagName = $prefix + $match.Groups[1].Value
            # Check if this exact tag is defined
            $found = $false
            foreach ($definedTag in $DefinedTags) {
                if ($definedTag -eq $tagName) {
                    $found = $true
                    break
                }
            }
            if (-not $found -and $tagName -notmatch 'SOFTWARENAME') {
                if (-not $undefinedTags.ContainsKey($tagName)) {
                    $undefinedTags[$tagName] = @()
                }
                if ($relativePath -notin $undefinedTags[$tagName]) {
                    $undefinedTags[$tagName] += $relativePath
                }
            }
        }
    }
}

$hasErrors = $false

if ($undefinedFields.Count -gt 0) {
    $hasErrors = $true
    Write-Host "`nUndefined custom fields (not in definitions/custom-fields.json):" -ForegroundColor Red
    foreach ($field in $undefinedFields.GetEnumerator() | Sort-Object Name) {
        Write-Host "  $($field.Key)" -ForegroundColor Yellow
        foreach ($file in $field.Value) {
            Write-Host "    - $file" -ForegroundColor Gray
        }
    }
}

if ($undefinedTags.Count -gt 0) {
    $hasErrors = $true
    Write-Host "`nUndefined tags (not in definitions/tags.json):" -ForegroundColor Red
    foreach ($tag in $undefinedTags.GetEnumerator() | Sort-Object Name) {
        Write-Host "  $($tag.Key)" -ForegroundColor Yellow
        foreach ($file in $tag.Value) {
            Write-Host "    - $file" -ForegroundColor Gray
        }
    }
}

if ($hasErrors) {
    Write-Host "`nAdd missing definitions to the appropriate JSON file" -ForegroundColor Yellow
    exit 1
} else {
    Write-Host "All fields and tags are properly defined" -ForegroundColor Green
    exit 0
}
