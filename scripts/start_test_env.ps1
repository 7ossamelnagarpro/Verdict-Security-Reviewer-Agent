param(
    [Parameter(Mandatory = $true)]
    [string]$AppPath,
    [int]$Port = 5000,
    [string]$Python = "python",
    [switch]$TrustedLab
)

$ErrorActionPreference = "Stop"
if (-not $TrustedLab) {
    throw "This legacy launcher executes app.py directly on the host. Use it only for a reviewed trusted lab with -TrustedLab; untrusted project execution is unsupported."
}
$resolvedApp = (Resolve-Path -LiteralPath $AppPath).Path
$appFile = Join-Path $resolvedApp "app.py"
if (-not (Test-Path -LiteralPath $appFile -PathType Leaf)) {
    throw "Test application must contain app.py: $resolvedApp"
}

$runtimeUrl = "http://127.0.0.1:$Port"
$env:SECURITY_REVIEWER_RUNTIME_URL = $runtimeUrl
$env:SECURITY_REVIEWER_TEST_ENV = "1"

Write-Host "Starting authorized local test target: $runtimeUrl"
Write-Host "Runtime URL exported as SECURITY_REVIEWER_RUNTIME_URL"
Write-Host "Keep this window open while the security pipeline runs."

Push-Location $resolvedApp
try {
    & $Python $appFile
}
finally {
    Pop-Location
}
