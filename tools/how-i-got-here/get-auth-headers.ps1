$har = Get-Content 'E:\DLScripts\importautomation.level.io.har' -Raw | ConvertFrom-Json

Write-Host "=== All unique headers in GraphQL requests ===" -ForegroundColor Cyan

$allHeaders = @{}

foreach ($entry in $har.log.entries) {
    if ($entry.request.url -match 'api.level.io/graphql') {
        foreach ($header in $entry.request.headers) {
            if (-not $allHeaders.ContainsKey($header.name)) {
                $allHeaders[$header.name] = $header.value
            }
        }
    }
}

foreach ($name in ($allHeaders.Keys | Sort-Object)) {
    $val = $allHeaders[$name]
    if ($val.Length -gt 80) { $val = $val.Substring(0, 80) + "..." }
    Write-Host "  $name : $val"
}

Write-Host ""
Write-Host "Total unique headers: $($allHeaders.Count)" -ForegroundColor Gray
