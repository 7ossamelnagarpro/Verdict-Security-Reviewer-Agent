$ErrorActionPreference = 'Stop'
$vmName = 'SecurityReviewer-Ubuntu-Base'
$expectedSwitch = 'Default Switch'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Open PowerShell as Administrator to configure the base VM.'
}

$adapters = @(Get-VMNetworkAdapter -VMName $vmName -ErrorAction Stop)
if ($adapters.Count -ne 1) {
    throw 'Expected exactly one base VM network adapter. No change was made.'
}
if ($adapters[0].SwitchName -and $adapters[0].SwitchName -ne $expectedSwitch) {
    throw 'The VM is connected to an unexpected switch. Inspect it manually.'
}
if ($adapters[0].SwitchName) {
    Disconnect-VMNetworkAdapter -VMNetworkAdapter $adapters[0] -ErrorAction Stop
}

$remaining = @(Get-VMNetworkAdapter -VMName $vmName -ErrorAction Stop |
    Where-Object SwitchName)
if ($remaining.Count -ne 0) {
    throw 'The base VM network adapter is still connected.'
}

Write-Host 'Base VM network adapter is disconnected. No VM or checkpoint was deleted.'
Get-VMNetworkAdapter -VMName $vmName | Select-Object Name, SwitchName
