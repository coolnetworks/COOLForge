$token = "eyJhbGciOiJIUzI1NiJ9.eyJlbWFpbCI6ImFsbGVuQGNvb2wubmV0LmF1IiwiZXhwIjoxNzY3MDcyMzUzfQ.sREVct73T1-69pJ2h1SWdjiPSM7niw8IleyzP1eGSnY"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Invoke-Query {
    param($Query, $Variables = @{})

    $headers = @{
        "Authorization" = $token
        "Content-Type" = "application/json"
        "Origin" = "https://app.level.io"
    }

    $body = @{
        query = $Query
        variables = $Variables
    } | ConvertTo-Json -Depth 10 -Compress

    $response = Invoke-WebRequest -Uri "https://api.level.io/graphql" -Method POST -Headers $headers -Body $body -UseBasicParsing
    return ($response.Content | ConvertFrom-Json)
}

# Try different enum values for group type
$enumValues = @("AUTOMATION", "automation", "Automation", "AUTOMATION_GROUP", "automations")

Write-Host "=== Testing GroupTypeEnum values ===" -ForegroundColor Cyan
foreach ($val in $enumValues) {
    $query = "query { groups(type: $val) { nodes { id } } }"
    Write-Host "Trying: $val" -ForegroundColor Gray
    $result = Invoke-Query -Query $query
    if ($result.errors) {
        $msg = $result.errors[0].message
        if ($msg -notmatch "invalid value") {
            Write-Host "  Different error: $msg" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  SUCCESS with $val - found $($result.data.groups.nodes.Count) groups" -ForegroundColor Green
    }
}

# Try without type argument
Write-Host ""
Write-Host "=== Try groups without type ===" -ForegroundColor Cyan
$result = Invoke-Query -Query "query { groups { nodes { id __typename } } }"
if ($result.errors) {
    Write-Host "Error: $($result.errors[0].message)" -ForegroundColor Yellow
} else {
    $types = $result.data.groups.nodes | Group-Object __typename
    Write-Host "Found groups:" -ForegroundColor Green
    $types | ForEach-Object { Write-Host "  $($_.Name): $($_.Count)" -ForegroundColor Gray }
}
