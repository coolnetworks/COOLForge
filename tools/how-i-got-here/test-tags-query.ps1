$token = "eyJhbGciOiJIUzI1NiJ9.eyJlbWFpbCI6ImFsbGVuQGNvb2wubmV0LmF1IiwiZXhwIjoxNzY3MDcyMzUzfQ.sREVct73T1-69pJ2h1SWdjiPSM7niw8IleyzP1eGSnY"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Invoke-Query {
    param($Query)

    $headers = @{
        "Authorization" = $token
        "Content-Type" = "application/json"
        "Origin" = "https://app.level.io"
    }

    $body = @{ query = $Query } | ConvertTo-Json -Compress

    $response = Invoke-WebRequest -Uri "https://api.level.io/graphql" -Method POST -Headers $headers -Body $body -UseBasicParsing
    return ($response.Content | ConvertFrom-Json)
}

# Test tags with different fields
Write-Host "Testing tag fields..." -ForegroundColor Cyan
$result = Invoke-Query -Query "query { tagSearch { nodes { id name userStyle } } }"
if ($result.errors) {
    Write-Host "Error with userStyle: $($result.errors[0].message)" -ForegroundColor Yellow
    # Try without userStyle
    $result = Invoke-Query -Query "query { tagSearch { nodes { id name } } }"
}
Write-Host "Tags: $($result.data.tagSearch.nodes.Count)" -ForegroundColor Green

# Test custom fields
Write-Host ""
Write-Host "Testing custom fields..." -ForegroundColor Cyan
$cfQueries = @(
    "query { customFieldSearch { nodes { id name fieldType defaultValue } } }",
    "query { customFields { id name } }",
    "query { organization { customFields { id name } } }"
)

foreach ($q in $cfQueries) {
    Write-Host "  Trying: $($q.Substring(0, [Math]::Min(60, $q.Length)))..." -ForegroundColor Gray
    $result = Invoke-Query -Query $q
    if ($result.errors) {
        Write-Host "    Error: $($result.errors[0].message)" -ForegroundColor Yellow
    } else {
        Write-Host "    SUCCESS!" -ForegroundColor Green
        break
    }
}
