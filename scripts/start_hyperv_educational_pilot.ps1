param(
    [Parameter(Mandatory = $true)][string]$VmStorageRoot,
    [Parameter(Mandatory = $true)][string]$WheelDirectory,
    [ValidatePattern('^[0-9a-f]{8}$')][string]$RunId,
    [switch]$AutomaticRuntime,
    [switch]$MutatingChecks
)

$ErrorActionPreference = 'Stop'
$baseName = 'SecurityReviewer-Ubuntu-Base'
$checkpointName = if ($AutomaticRuntime) { 'Ubuntu-AutoScan-Ready' } else { 'Ubuntu-Docker-Ready' }
if ($MutatingChecks -and -not $AutomaticRuntime) {
    throw 'Mutating checks require automatic runtime mode.'
}
$projectRoot = Split-Path -Parent $PSScriptRoot
$targetRoot = Join-Path $projectRoot 'targets\security-lab-web'
$guestRunner = Join-Path $PSScriptRoot 'hyperv_pilot_guest.py'
$stager = Join-Path $PSScriptRoot 'stage_hyperv_pilot.py'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Open Windows PowerShell as Administrator for Hyper-V operations.'
}
$storageRoot = (Resolve-Path -LiteralPath $VmStorageRoot -ErrorAction Stop).Path.TrimEnd('\')
$wheelRoot = (Resolve-Path -LiteralPath $WheelDirectory -ErrorAction Stop).Path
if (-not (Test-Path -LiteralPath $storageRoot -PathType Container) -or
    -not (Test-Path -LiteralPath $wheelRoot -PathType Container)) {
    throw 'VM storage and Linux wheel cache must be existing directories.'
}
if (-not (Test-Path -LiteralPath $targetRoot -PathType Container)) {
    throw 'The reviewed Security Lab Web target is unavailable.'
}
$base = Get-VM -Name $baseName -ErrorAction Stop
if ($base.State -ne 'Off') { throw 'The permanent base VM must be Off.' }
if (@(Get-VMNetworkAdapter -VMName $baseName | Where-Object SwitchName).Count -ne 0) {
    throw 'The permanent base VM network adapter must be disconnected.'
}
$snapshot = @(Get-VMSnapshot -VMName $baseName -ErrorAction Stop |
    Where-Object Name -eq $checkpointName)
if ($snapshot.Count -ne 1) { throw "Expected exactly one $checkpointName checkpoint." }
$drive = (Get-PSDrive -Name ([IO.Path]::GetPathRoot($storageRoot).Substring(0, 1)))
if ($drive.Free -lt 25GB) { throw 'At least 25 GiB of free storage is required for this pilot.' }
$python = Join-Path $projectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    $python = (Get-Command python.exe -ErrorAction Stop).Source
}

$runId = if ($RunId) { $RunId } else { [guid]::NewGuid().ToString('N').Substring(0, 8) }
$workerName = "SecurityReviewer-Pilot-$runId"
$pilotRoot = Join-Path $storageRoot 'pilot-runs'
$runRoot = Join-Path $pilotRoot $runId
if (Get-VM -Name $workerName -ErrorAction SilentlyContinue) {
    throw 'A VM with the generated pilot identity already exists.'
}
if (Test-Path -LiteralPath $runRoot) { throw 'Pilot run directory already exists.' }
$baseFilesRoot = Join-Path $storageRoot $baseName
if (-not (Test-Path -LiteralPath $baseFilesRoot -PathType Container)) {
    throw 'Base VM storage directory does not match the supplied root.'
}
$baseDisks = @(Get-ChildItem -LiteralPath $baseFilesRoot -Recurse -File |
    Where-Object { $_.Extension -in '.vhdx', '.avhdx' } | Sort-Object FullName)
if ($baseDisks.Count -lt 1 -or @($baseDisks | Where-Object {
    $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count -gt 0) {
    throw 'Base disk inventory is empty or contains reparse points.'
}
Write-Host 'Hashing the permanent base disks before the pilot. This may take a few minutes.'
$baseHashes = @($baseDisks | ForEach-Object {
    [pscustomobject]@{ path = $_.FullName.Substring($baseFilesRoot.Length + 1);
                       sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
})

New-Item -ItemType Directory -Path $runRoot -Force -ErrorAction Stop | Out-Null
$recordPath = Join-Path $runRoot 'pilot-run.json'
$record = [ordered]@{ schema_version = '1.0'; run_id = $runId; worker_vm_name = $workerName;
    base_vm_id = [string]$base.Id; checkpoint_id = [string]$snapshot[0].Id;
    checkpoint_name = $checkpointName;
    mode = if ($AutomaticRuntime) { 'automatic_runtime_scan' } else { 'manual_health_smoke' };
    base_disk_hashes = $baseHashes; status = 'preparing' }
$record | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $recordPath -Encoding UTF8

try {
    $exportRoot = Join-Path $runRoot 'checkpoint-export'
    New-Item -ItemType Directory -Path $exportRoot -ErrorAction Stop | Out-Null
    Write-Host "Exporting only the $checkpointName checkpoint."
    Export-VMSnapshot -VMSnapshot $snapshot[0] -Path $exportRoot -ErrorAction Stop
    $configFiles = @(Get-ChildItem -LiteralPath $exportRoot -Recurse -File -Filter '*.vmcx')
    if ($configFiles.Count -ne 1) {
        throw "Expected one exported VM configuration, found $($configFiles.Count)."
    }
    $workerRoot = Join-Path $runRoot 'worker'
    New-Item -ItemType Directory -Path $workerRoot -ErrorAction Stop | Out-Null
    $imported = @(Import-VM -Path $configFiles[0].FullName -Copy -GenerateNewId `
        -VirtualMachinePath $workerRoot -VhdDestinationPath $workerRoot -ErrorAction Stop)
    if ($imported.Count -ne 1 -or $imported[0].Id -eq $base.Id) {
        throw 'The checkpoint did not import as one independent VM.'
    }
    Rename-VM -VM $imported[0] -NewName $workerName -ErrorAction Stop
    Set-VM -Name $workerName -AutomaticStartAction Nothing `
        -AutomaticCheckpointsEnabled $false -ErrorAction Stop
    if ($AutomaticRuntime) {
        # Only the disposable fixed-target worker is reduced; the permanent
        # base and its checkpoints retain their original memory settings.
        Set-VMMemory -VMName $workerName -StartupBytes 4GB `
            -DynamicMemoryEnabled $false -ErrorAction Stop
    }
    if (@(Get-VMNetworkAdapter -VMName $workerName | Where-Object SwitchName).Count -ne 0) {
        Get-VMNetworkAdapter -VMName $workerName | Disconnect-VMNetworkAdapter -ErrorAction Stop
        throw 'The imported VM had a network connection; it was disconnected and left Off for inspection.'
    }
    foreach ($vmDisk in @(Get-VMHardDiskDrive -VMName $workerName -ErrorAction Stop)) {
        $diskPath = $vmDisk.Path
        while ($diskPath) {
            $diskPath = [IO.Path]::GetFullPath($diskPath)
            if (-not $diskPath.StartsWith($runRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
                throw 'An imported disk or parent points outside the disposable run directory.'
            }
            $diskPath = (Get-VHD -Path $diskPath -ErrorAction Stop).ParentPath
        }
    }

    $exchange = Join-Path $runRoot 'exchange.vhdx'
    New-VHD -Path $exchange -Dynamic -SizeBytes 256MB -ErrorAction Stop | Out-Null
    $mounted = $false
    try {
        $virtualDisk = Mount-VHD -Path $exchange -Passthru -ErrorAction Stop
        $mounted = $true
        $disk = $virtualDisk | Get-Disk -ErrorAction Stop
        $partition = $disk | Initialize-Disk -PartitionStyle MBR -PassThru -ErrorAction Stop |
            New-Partition -UseMaximumSize -AssignDriveLetter -ErrorAction Stop
        $volume = $partition | Format-Volume -FileSystem FAT32 -NewFileSystemLabel SRPILOT `
            -Confirm:$false -Force -ErrorAction Stop
        $driveLetter = $volume.DriveLetter
        if (-not $driveLetter) { $driveLetter = $partition.DriveLetter }
        if (-not $driveLetter) { throw 'Exchange disk has no Windows drive letter.' }
        $exchangeRoot = "${driveLetter}:\"
        $stageArgs = @('--target', $targetRoot, '--wheels', $wheelRoot,
            '--exchange', $exchangeRoot, '--run-id', $runId, '--guest-runner', $guestRunner)
        if ($AutomaticRuntime) { $stageArgs += '--automatic-runtime' }
        if ($MutatingChecks) { $stageArgs += '--mutating-checks' }
        & $python $stager @stageArgs
        if ($LASTEXITCODE -ne 0) { throw 'Staging the fixed educational app failed.' }
        if (-not (Test-Path -LiteralPath (Join-Path $exchangeRoot 'manifest.json'))) {
            throw 'Exchange manifest was not written.'
        }
    }
    finally {
        if ($mounted) { Dismount-VHD -Path $exchange -ErrorAction Stop }
    }
    Add-VMHardDiskDrive -VMName $workerName -ControllerType SCSI -Path $exchange -ErrorAction Stop
    if (@(Get-VMNetworkAdapter -VMName $workerName | Where-Object SwitchName).Count -ne 0) {
        throw 'Pilot VM became network-connected unexpectedly; refusing to start.'
    }
    Start-VM -Name $workerName -ErrorAction Stop
    $record.status = 'started'
    $record | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $recordPath -Encoding UTF8
    Write-Host "Started isolated pilot VM: $workerName"
    Write-Host "Run ID: $runId"
    Write-Host 'The VM has NO network switch. Open its console in Hyper-V Manager.'
    if ($AutomaticRuntime) {
        Write-Host 'The trusted Ubuntu boot service will run the bounded DAST checks and power off the worker.'
    } else {
        Write-Host 'Inside Ubuntu, mount the SRPILOT disk and run pilot_guest.py as documented.'
    }
    Write-Host "After the guest is Off, finish with -RunId $runId."
}
catch {
    Write-Warning "Pilot preparation failed. Inspect only the generated worker $workerName and directory $runRoot."
    throw
}
