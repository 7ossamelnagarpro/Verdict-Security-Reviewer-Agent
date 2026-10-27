param(
    [int]$Port = 8765,
    [switch]$NoLangSmith
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$python = Join-Path $repo '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) {
    throw "Local environment not found. Run scripts\install_local.ps1 first."
}
if ($NoLangSmith) {
    $env:LANGSMITH_TRACING = 'false'
    Write-Host 'LangSmith tracing disabled for this launch.'
}
else {
    & (Join-Path $PSScriptRoot 'enable_langsmith.ps1')
}
$env:Path = "$(Join-Path $repo '.venv\Scripts');$env:Path"
Write-Host "Starting local web control plane at http://127.0.0.1:$Port"
& $python (Join-Path $repo 'scripts\run_local_web.py') --host 127.0.0.1 --port $Port
