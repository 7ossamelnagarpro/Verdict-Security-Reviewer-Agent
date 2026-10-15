"""Read-only Hyper-V host readiness check for a future disposable VM worker.

This module deliberately does not create a VM, enable Windows features, mount
the target repository, or execute its code. Host readiness is not guest
isolation validation.
"""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path


_HOST_QUERY = r"""
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$computer = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
[pscustomobject]@{
  os_name = [string]$os.Caption
  is_administrator = [bool]$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  hypervisor_present = [bool]$computer.HypervisorPresent
  hyperv_module_available = [bool](Get-Module -ListAvailable -Name Hyper-V)
  vm_commands_available = [bool](Get-Command Get-VM -ErrorAction SilentlyContinue)
  memory_gib = [math]::Round($computer.TotalPhysicalMemory / 1GB, 1)
} | ConvertTo-Json -Compress
"""


@dataclass(frozen=True)
class HyperVHostReadiness:
    schema_version: str
    status: str
    os_name: str
    is_administrator: bool
    hypervisor_present: bool
    hyperv_module_available: bool
    vm_commands_available: bool
    memory_gib: float | None
    storage_free_gib: float | None
    missing: tuple[str, ...]
    notes: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def inspect_hyperv_host(
    storage_root: str | Path, *, system_name: str | None = None,
    powershell_executable: str | None = None, runner=subprocess.run,
) -> HyperVHostReadiness:
    """Inventory host prerequisites; never enable features or launch a VM."""
    root = Path(storage_root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("VM storage root must be an existing directory")
    free_gib = round(shutil.disk_usage(root).free / (1024 ** 3), 1)
    missing: list[str] = []
    notes = [
        "Read-only host check; no VM, image, switch, guest network, or cleanup policy has been validated.",
        "Untrusted repositories must be copied into a disposable VM, never mounted from the host.",
    ]
    if (system_name or platform.system()) != "Windows":
        missing.append("This backend requires a Windows Hyper-V host")
        return HyperVHostReadiness("1.0", "blocked", platform.system(), False, False,
                                   False, False, None, free_gib, tuple(missing), tuple(notes))
    powershell = powershell_executable or shutil.which("powershell.exe")
    if not powershell:
        missing.append("Windows PowerShell is unavailable")
        return HyperVHostReadiness("1.0", "blocked", "Windows", False, False,
                                   False, False, None, free_gib, tuple(missing), tuple(notes))
    try:
        completed = runner([powershell, "-NoProfile", "-NonInteractive", "-Command", _HOST_QUERY],
                           capture_output=True, text=True, timeout=20, check=False)
        if completed.returncode != 0:
            raise RuntimeError("Hyper-V host inventory could not complete")
        host = json.loads(completed.stdout)
        if not isinstance(host, dict) or any(type(host.get(key)) is not bool for key in (
            "is_administrator", "hypervisor_present", "hyperv_module_available", "vm_commands_available"
        )) or not isinstance(host.get("os_name"), str) or not isinstance(host.get("memory_gib"), (int, float)):
            raise ValueError("Hyper-V host inventory returned unexpected data")
    except (OSError, subprocess.TimeoutExpired, RuntimeError, ValueError, json.JSONDecodeError):
        missing.append("Hyper-V host inventory failed; no VM operation is permitted")
        return HyperVHostReadiness("1.0", "blocked", "Windows", False, False,
                                   False, False, None, free_gib, tuple(missing), tuple(notes))
    if not host["is_administrator"]:
        missing.append("Administrator rights are required for initial Hyper-V setup")
    if not host["hyperv_module_available"] or not host["vm_commands_available"]:
        missing.append("Hyper-V management tools are unavailable")
    if not host["hypervisor_present"]:
        missing.append("No active hypervisor was detected")
    if free_gib < 40:
        missing.append("Less than 40 GiB of free VM storage is available")
    if host["memory_gib"] < 8:
        missing.append("Less than 8 GiB of host memory is available")
    status = "blocked" if missing else "host_tools_ready"
    return HyperVHostReadiness("1.0", status, host["os_name"], host["is_administrator"],
                               host["hypervisor_present"], host["hyperv_module_available"],
                               host["vm_commands_available"], float(host["memory_gib"]),
                               free_gib, tuple(missing), tuple(notes))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only Hyper-V readiness check; does not create a VM")
    parser.add_argument("--storage", type=Path, required=True,
                        help="existing directory on the drive intended for temporary VM disks")
    args = parser.parse_args(argv)
    result = inspect_hyperv_host(args.storage)
    print(json.dumps(result.to_dict(), indent=2))
    return 0 if result.status == "host_tools_ready" else 2


if __name__ == "__main__":
    raise SystemExit(main())
