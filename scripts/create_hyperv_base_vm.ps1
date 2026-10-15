param(
    [Parameter(Mandatory = $true)]
    [string]$IsoPath,
    [Parameter(Mandatory = $true)]
    [string]$VmStorageRoot
)

$ErrorActionPreference = 'Stop'
$vmName = 'SecurityReviewer-Ubuntu-Base'
$expectedIsoSha256 = '97f3d7ffb032c3eb3b23d2c8be9cc76e60c2c1f2c0146ba5ba9fe01cafae0fd8'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Open a separate PowerShell window as Administrator to create the base VM.'
}

$iso = (Resolve-Path -LiteralPath $IsoPath -ErrorAction Stop).Path
if (-not (Test-Path -LiteralPath $iso -PathType Leaf)) {
    throw 'The Ubuntu Server ISO does not exist.'
}
$actualIsoSha256 = (Get-FileHash -LiteralPath $iso -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualIsoSha256 -ne $expectedIsoSha256) {
    throw "Ubuntu ISO SHA-256 mismatch. Expected $expectedIsoSha256; received $actualIsoSha256. No VM was created."
}

$storageRoot = (Resolve-Path -LiteralPath $VmStorageRoot -ErrorAction Stop).Path
if (-not (Test-Path -LiteralPath $storageRoot -PathType Container)) {
    throw 'VM storage root must be an existing directory.'
}
if ((Get-PSDrive -Name ([IO.Path]::GetPathRoot($storageRoot).Substring(0, 1))).Free -lt 70GB) {
    throw 'At least 70 GB of free disk space is required before creating this 60 GB dynamic VHDX.'
}
if (Get-VM -Name $vmName -ErrorAction SilentlyContinue) {
    throw "A VM named $vmName already exists. Nothing was changed."
}

$vmPath = Join-Path $storageRoot $vmName
$diskPath = Join-Path $vmPath "$vmName.vhdx"
if (Test-Path -LiteralPath $vmPath) {
    throw "The intended VM directory already exists: $vmPath. Nothing was changed."
}
New-Item -ItemType Directory -Path $vmPath -ErrorAction Stop | Out-Null

# Omitting -SwitchName is intentional: the VM starts with no network connection.
New-VM -Name $vmName -Generation 2 -MemoryStartupBytes 6GB `
    -NewVHDPath $diskPath -NewVHDSizeBytes 60GB -Path $vmPath -ErrorAction Stop | Out-Null
Set-VMProcessor -VMName $vmName -Count 2 -ErrorAction Stop
Set-VM -Name $vmName -AutomaticStartAction Nothing -ErrorAction Stop
Add-VMDvdDrive -VMName $vmName -Path $iso -ErrorAction Stop | Out-Null
$dvd = Get-VMDvdDrive -VMName $vmName -ErrorAction Stop | Where-Object { $_.Path -eq $iso } | Select-Object -First 1
if (-not $dvd) {
    throw 'The Ubuntu ISO could not be found on the new VM DVD drive.'
}
Set-VMFirmware -VMName $vmName -EnableSecureBoot On `
    -SecureBootTemplate MicrosoftUEFICertificateAuthority -FirstBootDevice $dvd -ErrorAction Stop

$connected = @(Get-VMNetworkAdapter -VMName $vmName -ErrorAction Stop | Where-Object { $_.SwitchName })
if ($connected.Count -gt 0) {
    Get-VMNetworkAdapter -VMName $vmName | Disconnect-VMNetworkAdapter -ErrorAction Stop
    throw 'A network adapter was unexpectedly connected and has been disconnected. Inspect the VM before starting it.'
}

Write-Host "Created $vmName with Ubuntu installation media and no network switch."
Get-VM -Name $vmName | Select-Object Name, State, Generation, MemoryStartup
Get-VMNetworkAdapter -VMName $vmName | Select-Object Name, SwitchName
Write-Host 'The VM has not been started, and Ubuntu has not yet been installed.'
