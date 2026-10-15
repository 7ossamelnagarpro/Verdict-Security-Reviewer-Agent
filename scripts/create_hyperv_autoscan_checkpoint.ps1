param(
    [Parameter(Mandatory = $true)][string]$VmStorageRoot
)

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Open Administrator PowerShell to checkpoint the provisioned base VM.'
}
$storageRoot = (Resolve-Path -LiteralPath $VmStorageRoot -ErrorAction Stop).Path.TrimEnd('\')
$baseName = 'SecurityReviewer-Ubuntu-Base'
$base = Get-VM -Name $baseName -ErrorAction Stop
if ($base.State -ne 'Off') { throw 'The provisioned base VM must be Off.' }
if (@(Get-VMNetworkAdapter -VMName $baseName | Where-Object SwitchName).Count -ne 0) {
    throw 'Disconnect the temporary provisioning network before checkpointing.'
}
if (-not (Test-Path -LiteralPath (Join-Path $storageRoot $baseName) -PathType Container)) {
    throw 'Base VM storage does not match the supplied root.'
}
$prior = @(Get-VMSnapshot -VMName $baseName | Where-Object Name -eq 'Ubuntu-Docker-Ready')
$automatic = @(Get-VMSnapshot -VMName $baseName | Where-Object Name -eq 'Ubuntu-AutoScan-Ready')
if ($prior.Count -ne 1 -or $automatic.Count -ne 0) {
    throw 'Expected one preserved Docker-ready checkpoint and no existing auto-scan checkpoint.'
}
Checkpoint-VM -Name $baseName -SnapshotName 'Ubuntu-AutoScan-Ready' -ErrorAction Stop
$automatic = @(Get-VMSnapshot -VMName $baseName | Where-Object Name -eq 'Ubuntu-AutoScan-Ready')
if ($automatic.Count -ne 1) { throw 'Auto-scan checkpoint was not created exactly once.' }
Write-Host 'Created Ubuntu-AutoScan-Ready. The earlier Ubuntu-Docker-Ready checkpoint remains.'
Get-VMSnapshot -VMName $baseName | Select-Object Name,CreationTime
