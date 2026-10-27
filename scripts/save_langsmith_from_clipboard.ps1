$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent $PSScriptRoot
$python = Join-Path $repo '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw 'Local Python environment is unavailable.'
}

$token = Get-Clipboard -Raw
if ([string]::IsNullOrWhiteSpace($token) -or
    $token.Length -lt 20 -or
    $token -notmatch '^[A-Za-z0-9_-]+$') {
    throw 'Clipboard does not contain a single API key. Copy only the LangSmith token and retry.'
}

try {
    $token | & $python -m keyring set VerdictSecurityReviewer langsmith
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not save the LangSmith key to the Windows credential vault.'
    }
    Remove-Item Env:LANGSMITH_API_KEY -ErrorAction SilentlyContinue
    Set-Clipboard -Value ''
    Write-Host 'LangSmith key saved in Windows credential vault. Clipboard cleared.'
}
finally {
    $token = $null
}
