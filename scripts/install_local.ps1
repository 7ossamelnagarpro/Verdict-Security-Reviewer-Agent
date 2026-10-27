param(
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$PythonLauncher = "py",
    [switch]$InstallSemgrep,
    [switch]$InstallZap,
    [switch]$NoShortcut
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path $RepoRoot).Path
$venv = Join-Path $root ".venv"
$python = Join-Path $venv "Scripts\python.exe"

if (-not (Test-Path $python)) {
    $runtime = & $PythonLauncher -3 -c 'import sys; print(sys.executable if sys.version_info >= (3,11) else "")'
    if ($LASTEXITCODE -ne 0 -or -not $runtime) { throw "Install Python 3.11 or newer, then retry." }
    & $runtime -m venv $venv
    if ($LASTEXITCODE -ne 0) { throw "Python virtual environment creation failed." }
}

& $python -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw "pip upgrade failed." }
Push-Location $root
try {
    & $python -m pip install -e .
    if ($LASTEXITCODE -ne 0) { throw "Project installation failed." }
    if ($InstallSemgrep) {
        & $python -m pip install -e '.[scanners]'
        if ($LASTEXITCODE -ne 0) { throw "Verified scanner installation failed." }
    }
    if ($InstallZap) {
        & docker pull ghcr.io/zaproxy/zaproxy:stable
        if ($LASTEXITCODE -ne 0) { throw "ZAP image download failed. Start Docker Desktop and retry." }
    }
}
finally {
    Pop-Location
}

Write-Host "Local installation is ready: $venv"
if (-not $NoShortcut) {
    $desktopPath = [Environment]::GetFolderPath('Desktop')
    $shortcutPath = Join-Path $desktopPath 'Verdict Security Reviewer.lnk'
    $shortcut = (New-Object -ComObject WScript.Shell).CreateShortcut($shortcutPath)
    $shortcut.TargetPath = Join-Path $venv 'Scripts\pythonw.exe'
    $shortcut.Arguments = '"' + (Join-Path $root 'scripts\launch_local.py') + '"'
    $shortcut.WorkingDirectory = $root
    $shortcut.Description = 'Open the local Verdict security workspace'
    $shortcut.Save()
    Write-Host "Desktop shortcut ready: $shortcutPath"
}
Write-Host 'Open Verdict from your desktop. System setup shows missing tools; existing tools are reused.'
Write-Host 'Optional: rerun with -InstallSemgrep or -InstallZap to prepare those components.'
