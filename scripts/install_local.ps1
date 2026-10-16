param(
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$PythonLauncher = "py"
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path $RepoRoot).Path
$venv = Join-Path $root ".venv"
$python = Join-Path $venv "Scripts\python.exe"

if (-not (Test-Path $python)) {
    & $PythonLauncher -3.11 -m venv $venv
    if ($LASTEXITCODE -ne 0) { throw "Python 3.11 virtual environment creation failed." }
}

& $python -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw "pip upgrade failed." }
Push-Location $root
try {
    & $python -m pip install -e ".[dev]"
    if ($LASTEXITCODE -ne 0) { throw "Project installation failed." }
}
finally {
    Pop-Location
}

Write-Host "Local installation is ready: $venv"
Write-Host "Install Semgrep CE, CodeQL CLI, Gitleaks and Trivy separately, then configure Groq or Ollama in the current session."
