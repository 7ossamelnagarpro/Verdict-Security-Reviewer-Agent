$ErrorActionPreference = 'Stop'
$vmName = 'SecurityReviewer-Ubuntu-Base'
$switchName = 'Default Switch'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Open PowerShell as Administrator to configure the base VM.'
}

$vm = Get-VM -Name $vmName -ErrorAction Stop
if ($vm.State -ne 'Off') {
    throw 'The base VM must be Off before connecting the temporary provisioning network.'
}
if ($vm.AutomaticCheckpointsEnabled) {
    throw 'Disable automatic checkpoints before provisioning the base VM.'
}
if (-not (Get-VMSnapshot -VMName $vmName -ErrorAction Stop | Where-Object Name -eq 'Ubuntu-Clean-Base')) {
    throw 'The Ubuntu-Clean-Base checkpoint is missing. No network was connected.'
}

$adapters = @(Get-VMNetworkAdapter -VMName $vmName -ErrorAction Stop)
if ($adapters.Count -ne 1 -or $adapters[0].SwitchName) {
    throw 'Expected exactly one disconnected network adapter. No change was made.'
}
$switch = Get-VMSwitch -Name $switchName -ErrorAction Stop
if ($switch.SwitchType -ne 'Internal') {
    throw 'The selected switch is not Internal. No change was made.'
}

Connect-VMNetworkAdapter -VMNetworkAdapter $adapters[0] -SwitchName $switchName -ErrorAction Stop
try {
    Start-VM -Name $vmName -ErrorAction Stop
} catch {
    Get-VMNetworkAdapter -VMName $vmName -ErrorAction Stop |
        Disconnect-VMNetworkAdapter -ErrorAction Stop
    throw
}

$connected = @(Get-VMNetworkAdapter -VMName $vmName -ErrorAction Stop |
    Where-Object SwitchName -eq $switchName)
if ($connected.Count -ne 1) {
    Get-VMNetworkAdapter -VMName $vmName -ErrorAction Stop |
        Disconnect-VMNetworkAdapter -ErrorAction Stop
    throw 'Network verification failed; the VM adapter was disconnected.'
}

Write-Host 'Base VM started with the temporary setup network.'
Write-Host 'Use only for trusted Ubuntu/Docker provisioning. Do not load a target repository.'
Write-Host 'Disconnect the adapter after provisioning, before creating a ready checkpoint.'
Get-VM -Name $vmName | Select-Object Name, State
Get-VMNetworkAdapter -VMName $vmName | Select-Object Name, SwitchName
