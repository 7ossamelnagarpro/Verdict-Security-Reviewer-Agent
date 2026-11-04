param(
    [string]$Project = 'Verdict-Security-Reviewer-Agent-local'
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$python = Join-Path $repo '.venv\Scripts\python.exe'

if ($Project -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') {
    throw 'Project must be 1-64 letters, digits, dots, underscores or hyphens.'
}
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw 'Local Python environment is unavailable. Run scripts\install_local.ps1 first.'
}
& $python -c 'import langsmith, langgraph'
if ($LASTEXITCODE -ne 0) {
    throw 'LangSmith or LangGraph is not installed in the local Python environment.'
}

if ([string]::IsNullOrWhiteSpace($env:LANGSMITH_API_KEY)) {
    # Use the same OS credential vault as the web UI. The key never appears in
    # the command line or repository; PowerShell captures the helper's output.
    $vaultLookup = @'
from security_reviewer_v2.web.credentials import get_secret
key = get_secret("langsmith")
if key:
    print(key)
'@
    $vaultKey = $vaultLookup | & $python -
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not read the LangSmith key from the OS credential vault.'
    }
    if (-not [string]::IsNullOrWhiteSpace($vaultKey)) {
        $env:LANGSMITH_API_KEY = $vaultKey
    }
}

if ([string]::IsNullOrWhiteSpace($env:LANGSMITH_API_KEY)) {
    $secret = Read-Host 'LangSmith API key (input hidden; never saved to the repository)' -AsSecureString
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
    try {
        $env:LANGSMITH_API_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
    if ([string]::IsNullOrWhiteSpace($env:LANGSMITH_API_KEY)) {
        throw 'A LangSmith API key is required to enable tracing.'
    }
}

# The agent graphs can carry source code, credentials and vulnerability evidence
# in their state. Hide payloads before tracing is enabled in this shell.
$env:LANGSMITH_HIDE_INPUTS = 'true'
$env:LANGSMITH_HIDE_OUTPUTS = 'true'
# Only sanitized numeric token usage metadata is sent; prompts and outputs stay hidden.
$env:LANGSMITH_HIDE_METADATA = 'false'
$env:LANGSMITH_PROJECT = $Project
$env:LANGSMITH_TRACING = 'true'

Write-Host "LangSmith tracing enabled for project '$Project' in this PowerShell session."
Write-Host 'Trace inputs, outputs and metadata are hidden. Run names, timing and errors may still be sent.'
Write-Host 'Now start the local web UI or pipeline from this same PowerShell window.'
