param(
    [Parameter(Mandatory = $true)][string]$GuestAddress,
    [string]$GuestUser = 'hosssam'
)

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run from Administrator PowerShell while the trusted base VM is on the temporary setup network.'
}
$parsed = $null
if (-not [Net.IPAddress]::TryParse($GuestAddress, [ref]$parsed) -or
    $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
    [Net.IPAddress]::IsLoopback($parsed)) {
    throw 'GuestAddress must be the base VM IPv4 address on the temporary setup network.'
}
if ($GuestUser -cnotmatch '^[a-z_][a-z0-9_-]{0,31}$') {
    throw 'GuestUser must be a local Ubuntu username.'
}
$baseName = 'SecurityReviewer-Ubuntu-Base'
$base = Get-VM -Name $baseName -ErrorAction Stop
$adapters = @(Get-VMNetworkAdapter -VMName $baseName -ErrorAction Stop)
if ($base.State -ne 'Running' -or $adapters.Count -ne 1 -or
    $adapters[0].SwitchName -ne 'Default Switch') {
    throw 'The trusted base VM must be Running on its temporary Default Switch for one-time provisioning.'
}
$destination = "${GuestUser}@${GuestAddress}"
$remote = '/tmp/sr-autoscan-install'
& ssh $destination "mkdir -p $remote && chmod 700 $remote"
if ($LASTEXITCODE -ne 0) { throw 'Could not prepare the trusted guest install directory.' }
$files = @(
    (Join-Path $PSScriptRoot 'hyperv_autoscan_guest.py'),
    (Join-Path $PSScriptRoot 'hyperv_pilot_guest.py'),
    (Join-Path $PSScriptRoot 'scan_tt_authorization.py'),
    (Join-Path $PSScriptRoot 'hyperv_autoscan_entry.sh'),
    (Join-Path $PSScriptRoot 'hyperv-autoscan.service'),
    (Join-Path $PSScriptRoot 'install_hyperv_autoscan_guest.sh'),
    (Join-Path (Split-Path -Parent $PSScriptRoot) 'src\security_reviewer_v2\scanners\web_runtime.py')
)
foreach ($file in $files) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Trusted worker file missing: $file" }
}
& scp @files "${destination}:${remote}/"
if ($LASTEXITCODE -ne 0) { throw 'Could not copy trusted worker files into the base VM.' }
& ssh -tt $destination "sudo bash $remote/install_hyperv_autoscan_guest.sh"
if ($LASTEXITCODE -ne 0) { throw 'Trusted Ubuntu auto-scan service installation failed.' }
Write-Host 'One-time guest service installed. Verify it, power off the base VM, disconnect its adapter, then create Ubuntu-AutoScan-Ready.'
