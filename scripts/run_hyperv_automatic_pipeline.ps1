param(
    [Parameter(Mandatory = $true)][string]$VmStorageRoot,
    [Parameter(Mandatory = $true)][string]$WheelDirectory,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [string]$CodeQLBundle,
    [switch]$RuntimeMutating = $true,
    [switch]$AiDiscovery,
    [ValidateSet('ollama', 'groq')][string]$AiProvider = 'groq',
    [string]$AiModel
)

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this automatic VM pipeline from Administrator PowerShell.'
}
$projectRoot = Split-Path -Parent $PSScriptRoot
$project = Join-Path $projectRoot 'targets\security-lab-web'
$python = Join-Path $projectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw 'The project virtual environment is missing.'
}
if ($env:SECURITY_REVIEWER_RUNTIME_URL) {
    throw 'Clear SECURITY_REVIEWER_RUNTIME_URL before isolated VM scanning; host URLs cannot be mixed with guest evidence.'
}
$output = [IO.Path]::GetFullPath($OutputDirectory)
if ($output.StartsWith(([IO.Path]::GetFullPath($project)).TrimEnd('\') + '\',
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'OutputDirectory must be outside the scanned target source tree.'
}
if (Test-Path -LiteralPath $output) {
    throw 'Choose a new output directory; existing reports are never overwritten.'
}
if (-not $CodeQLBundle) {
    $CodeQLBundle = Join-Path (Split-Path -Parent $projectRoot) 'tools\codeql-2.27.1\codeql'
}
if (-not (Test-Path -LiteralPath (Join-Path $CodeQLBundle 'codeql.exe') -PathType Leaf)) {
    throw "CodeQL is required. Its executable was not found in: $CodeQLBundle"
}
if (-not $AiModel) {
    $AiModel = if ($AiProvider -eq 'groq') { 'openai/gpt-oss-120b' } else { 'qwen2.5-coder:7b' }
}
if ($AiProvider -eq 'groq' -and [string]::IsNullOrWhiteSpace($env:GROQ_API_KEY)) {
    throw 'AI Discovery is required. Set GROQ_API_KEY in this PowerShell session before starting the VM; do not put it on the command line or in a project file.'
}

$runId = [guid]::NewGuid().ToString('N').Substring(0, 8)
$workerName = "SecurityReviewer-Pilot-$runId"
$start = Join-Path $PSScriptRoot 'start_hyperv_educational_pilot.ps1'
$finish = Join-Path $PSScriptRoot 'finish_hyperv_educational_pilot.ps1'
$pipeline = Join-Path $PSScriptRoot 'run_pre_review_pipeline.py'

Write-Host 'Checking all four required scanner adapters before starting the VM.'
& $python $pipeline $project --scanner-preflight-only --require-all-scanners --codeql-bundle $CodeQLBundle
if ($LASTEXITCODE -ne 0) {
    throw 'A required scanner is not ready. The VM was not started; fix the preflight errors and retry.'
}

Write-Host "Starting automatic isolated static + DAST scan: $runId"
$startArgs = @{ VmStorageRoot = $VmStorageRoot; WheelDirectory = $WheelDirectory;
    RunId = $runId; AutomaticRuntime = $true }
if ($RuntimeMutating) { $startArgs.MutatingChecks = $true }
& $start @startArgs

$deadline = (Get-Date).AddMinutes(20)
while ((Get-Date) -lt $deadline) {
    $worker = Get-VM -Name $workerName -ErrorAction Stop
    if ($worker.State -eq 'Off') { break }
    Start-Sleep -Seconds 10
}
$worker = Get-VM -Name $workerName -ErrorAction Stop
if ($worker.State -ne 'Off') {
    Stop-VM -Name $workerName -TurnOff -Force -ErrorAction Stop
    throw "Automatic worker exceeded 20 minutes; it was powered off and preserved for inspection: $workerName"
}

& $finish -RunId $runId -VmStorageRoot $VmStorageRoot -AutomaticRuntime

$pipelineArgs = @($pipeline, $project, '--output', $output,
    '--isolated-runtime-run-id', $runId, '--require-dast', '--require-sast',
    '--require-all-scanners', '--codeql-bundle', $CodeQLBundle,
    '--ai-provider', $AiProvider, '--ai-model', $AiModel)
& $python @pipelineArgs
if ($LASTEXITCODE -ne 0) {
    throw "Static + isolated DAST pipeline failed after the VM was safely removed; inspect $output"
}
Write-Host "Automatic scan completed: $output"
Write-Host "Disposable worker removed: $workerName"
