param(
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{8}$')][string]$RunId,
    [Parameter(Mandatory = $true)][string]$VmStorageRoot,
    [switch]$AutomaticRuntime
)

$ErrorActionPreference = 'Stop'
$baseName = 'SecurityReviewer-Ubuntu-Base'
$checkpointName = if ($AutomaticRuntime) { 'Ubuntu-AutoScan-Ready' } else { 'Ubuntu-Docker-Ready' }
$expectedMode = if ($AutomaticRuntime) { 'automatic_runtime_scan' } else { 'manual_health_smoke' }
$expectedTestKind = if ($AutomaticRuntime) { 'isolated_runtime_scan' } else { 'local_health_smoke_only' }
$workerName = "SecurityReviewer-Pilot-$RunId"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Open Windows PowerShell as Administrator for Hyper-V operations.'
}
$storageRoot = (Resolve-Path -LiteralPath $VmStorageRoot -ErrorAction Stop).Path.TrimEnd('\')
$pilotRoot = [IO.Path]::GetFullPath((Join-Path $storageRoot 'pilot-runs')).TrimEnd('\')
$runRoot = [IO.Path]::GetFullPath((Join-Path $pilotRoot $RunId)).TrimEnd('\')
if (-not $runRoot.StartsWith($pilotRoot + '\', [StringComparison]::OrdinalIgnoreCase) -or
    $runRoot -eq $pilotRoot -or -not (Test-Path -LiteralPath $runRoot -PathType Container)) {
    throw 'Pilot run path is missing or outside the intended storage root.'
}
$resolvedRunRoot = (Resolve-Path -LiteralPath $runRoot -ErrorAction Stop).Path.TrimEnd('\')
if ($resolvedRunRoot -ne $runRoot) { throw 'Pilot run path resolves somewhere unexpected.' }
$recordPath = Join-Path $runRoot 'pilot-run.json'
if (-not (Test-Path -LiteralPath $recordPath -PathType Leaf)) {
    throw 'Pilot identity marker is absent; nothing will be removed.'
}
$record = Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json
if ($record.run_id -cne $RunId -or $record.worker_vm_name -cne $workerName -or
    $record.status -cne 'started' -or $record.mode -cne $expectedMode -or
    $record.checkpoint_name -cne $checkpointName) {
    throw 'Pilot identity marker does not match this run.'
}
$base = Get-VM -Name $baseName -ErrorAction Stop
$worker = Get-VM -Name $workerName -ErrorAction Stop
if ($base.State -ne 'Off' -or $worker.State -ne 'Off' -or
    [string]$base.Id -ne [string]$record.base_vm_id -or $base.Id -eq $worker.Id) {
    throw 'Expected two distinct, powered-off VMs and the original base identity.'
}
if (@(Get-VMNetworkAdapter -VMName $baseName | Where-Object SwitchName).Count -ne 0 -or
    @(Get-VMNetworkAdapter -VMName $workerName | Where-Object SwitchName).Count -ne 0) {
    throw 'Both base and pilot worker must have disconnected network adapters.'
}
$snapshot = @(Get-VMSnapshot -VMName $baseName | Where-Object Name -eq $checkpointName)
if ($snapshot.Count -ne 1 -or [string]$snapshot[0].Id -ne [string]$record.checkpoint_id) {
    throw 'The permanent base checkpoint changed; inspect it before cleanup.'
}

$baseFilesRoot = Join-Path $storageRoot $baseName
$baseDisks = @(Get-ChildItem -LiteralPath $baseFilesRoot -Recurse -File |
    Where-Object { $_.Extension -in '.vhdx', '.avhdx' } | Sort-Object FullName)
Write-Host 'Checking SHA-256 hashes of the permanent base disks.'
$currentHashes = @($baseDisks | ForEach-Object {
    [pscustomobject]@{ path = $_.FullName.Substring($baseFilesRoot.Length + 1);
                       sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
})
$before = @($record.base_disk_hashes | ForEach-Object { "$($_.path):$($_.sha256)" } | Sort-Object)
$after = @($currentHashes | ForEach-Object { "$($_.path):$($_.sha256)" } | Sort-Object)
if ($before.Count -ne $after.Count -or @(Compare-Object -ReferenceObject $before -DifferenceObject $after).Count -gt 0) {
    throw 'Permanent base disk hashes changed; the pilot worker is preserved for inspection.'
}

$exchange = [IO.Path]::GetFullPath((Join-Path $runRoot 'exchange.vhdx'))
$drives = @(Get-VMHardDiskDrive -VMName $workerName -ErrorAction Stop)
if ($drives.Count -lt 2 -or @($drives | Where-Object {
    -not [IO.Path]::GetFullPath($_.Path).StartsWith($runRoot + '\',
        [StringComparison]::OrdinalIgnoreCase)
}).Count -ne 0) {
    throw 'A pilot disk is outside its isolated run directory; nothing will be removed.'
}
foreach ($vmDisk in $drives) {
    $diskPath = $vmDisk.Path
    while ($diskPath) {
        $diskPath = [IO.Path]::GetFullPath($diskPath)
        if (-not $diskPath.StartsWith($runRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'A pilot disk parent points outside its isolated run directory.'
        }
        $diskPath = (Get-VHD -Path $diskPath -ErrorAction Stop).ParentPath
    }
}
$exchangeDrive = @($drives | Where-Object {
    [IO.Path]::GetFullPath($_.Path) -ieq $exchange })
if ($exchangeDrive.Count -ne 1) { throw 'Expected one attached exchange disk.' }
$exchangeDrive[0] | Remove-VMHardDiskDrive -ErrorAction Stop

$report = $null
$mounted = $false
try {
    $virtualDisk = Mount-VHD -Path $exchange -Passthru -ErrorAction Stop
    $mounted = $true
    $disk = $virtualDisk | Get-Disk -ErrorAction Stop
    $volumes = @(Get-Partition -DiskNumber $disk.Number -ErrorAction Stop |
        Get-Volume -ErrorAction SilentlyContinue | Where-Object FileSystemLabel -eq 'SRPILOT')
    if ($volumes.Count -ne 1 -or -not $volumes[0].DriveLetter) {
        throw 'The expected SRPILOT exchange volume is unavailable.'
    }
    $reportPath = "$($volumes[0].DriveLetter):\report.json"
    if (-not (Test-Path -LiteralPath $reportPath -PathType Leaf) -or
        (Get-Item -LiteralPath $reportPath).Length -gt 65536) {
        throw 'Bounded guest report is missing or oversized; worker preserved.'
    }
    $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    if ($report.schema_version -cne '1.0' -or $report.run_id -cne $RunId -or
        $report.target_id -cne 'security-lab-web' -or
        $report.test_kind -cne $expectedTestKind -or
        $report.status -notin @('passed', 'failed', 'health_timeout',
                                 'unexpected_http_status', 'app_exited_before_health')) {
        throw 'Guest report identity or schema is invalid; worker preserved.'
    }
    if ($report.status -cne 'passed' -or $report.http_status -ne 200) {
        throw 'Guest health check did not pass with HTTP 200; worker preserved for inspection.'
    }
    $runtimeFiles = @()
    if ($AutomaticRuntime) {
        $projectRoot = Split-Path -Parent $PSScriptRoot
        $trustedTools = @{
            worker = Join-Path $PSScriptRoot 'hyperv_autoscan_guest.py'
            web_runtime = Join-Path $projectRoot 'src\security_reviewer_v2\scanners\web_runtime.py'
            authorization = Join-Path $PSScriptRoot 'scan_tt_authorization.py'
        }
        foreach ($name in $trustedTools.Keys) {
            $expected = (Get-FileHash -LiteralPath $trustedTools[$name] -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($report.trusted_tool_sha256.$name -cne $expected) {
                throw "Guest trusted tool $name differs from the reviewed host version; worker preserved."
            }
        }
        foreach ($fileName in @('runtime.json', 'authorization.json')) {
            $source = "$($volumes[0].DriveLetter):\$fileName"
            if (-not (Test-Path -LiteralPath $source -PathType Leaf) -or
                (Get-Item -LiteralPath $source).Length -gt 1MB) {
                throw "Guest DAST output $fileName is missing or oversized; worker preserved."
            }
            $expectedHash = $report.output_sha256.$fileName
            if (-not ($expectedHash -cmatch '^[0-9a-f]{64}$') -or
                (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expectedHash) {
                throw "Guest DAST output $fileName failed SHA-256 validation; worker preserved."
            }
            $payload = Get-Content -LiteralPath $source -Raw | ConvertFrom-Json
            $expectedSource = if ($fileName -eq 'runtime.json') { 'web-runtime' } else { 'tt-authorization-runtime' }
            if ($payload.status -cne 'completed' -or $payload.source -cne $expectedSource -or
                $payload.target -cne 'http://127.0.0.1:5000' -or @($payload.results).Count -lt 1) {
                throw "Guest DAST output $fileName is incomplete or belongs to another target."
            }
            $runtimeFiles += [pscustomobject]@{ Name = $fileName; Source = $source }
        }
    }
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $reportsRoot = Join-Path $projectRoot $(if ($AutomaticRuntime) { 'reports\hyperv-autoscan' } else { 'reports\hyperv-pilot' })
    $resultRoot = Join-Path $reportsRoot $RunId
    if (Test-Path -LiteralPath $resultRoot) {
        throw 'Result directory already exists; refusing to overwrite a previous report.'
    }
    New-Item -ItemType Directory -Path $resultRoot -Force -ErrorAction Stop | Out-Null
    Copy-Item -LiteralPath $reportPath -Destination (Join-Path $resultRoot 'guest-report.json') -ErrorAction Stop
    foreach ($runtimeFile in $runtimeFiles) {
        Copy-Item -LiteralPath $runtimeFile.Source -Destination (Join-Path $resultRoot $runtimeFile.Name) -ErrorAction Stop
    }
}
finally {
    if ($mounted) { Dismount-VHD -Path $exchange -ErrorAction Stop }
}

# Only a uniquely named, powered-off worker with all disks inside this run
# directory can reach this point. Its base VM and checkpoints are untouched.
Remove-VM -Name $workerName -Force -ErrorAction Stop
if (Get-VM -Name $workerName -ErrorAction SilentlyContinue) {
    throw 'Pilot worker is still registered; run directory was not removed.'
}
Remove-Item -LiteralPath $runRoot -Recurse -Force -ErrorAction Stop
$lifecycle = [ordered]@{ schema_version = '1.0'; run_id = $RunId;
    guest_status = $report.status; worker_removed = $true;
    base_checkpoint_unchanged = $true; base_disk_sha256_unchanged = $true;
    network_isolation = 'no_vm_switch'; result = 'guest-report.json';
    runtime_scan = [bool]$AutomaticRuntime;
    trusted_tools_matched = [bool]$AutomaticRuntime }
$lifecycle | ConvertTo-Json -Depth 4 |
    Set-Content -LiteralPath (Join-Path $resultRoot 'lifecycle.json') -Encoding UTF8
Write-Host "Pilot complete. Worker $workerName was removed."
Write-Host "Guest status: $($report.status)"
Write-Host "Reports: $resultRoot"
Write-Host 'Permanent base checkpoint and disk SHA-256 values are unchanged.'
