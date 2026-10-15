# Disposable Hyper-V worker for untrusted targets

The existing host-side `docker_compose` mode is **trusted-lab only**. Marking a
repository `authorized_for_testing` confirms scan permission; it does not
establish that its build scripts or Compose file are safe to run on the host.
Unknown projects require a separate VM execution boundary.

## Intended flow

1. The host accepts the repository and an explicit, out-of-repository run
   specification. It does not run project scripts or containers.
2. A fresh Linux VM is created from a pinned, verified base image. Give it a
   unique identity and a bounded CPU, memory, disk, and lifetime budget.
3. Transfer a copy of the project into the VM. Do not map a host drive, pass
   through devices, expose the Docker socket, or forward host/cloud keys.
4. Inside the guest, prepare dependencies and test data from approved run
   instructions. Run scanners and the target there, with only disposable test
   credentials. The guest network must be explicitly scoped; unrestricted
   internet or LAN access is not a safe default.
5. Export only structured reports through a controlled channel. Treat their
   contents as untrusted input. Terminate the VM, dispose of its writable disk,
   and record whether cleanup succeeded.

The target app and scanners can initially share one VM to keep resource use
manageable. A later, stronger setup can separate them into two VMs on an
isolated test network so a compromised app cannot alter scanner processes or
results. VM isolation lowers risk but does not make malicious code harmless.

## Current implementation status

Run the **read-only** host check from the repository root:

```powershell
.venv\Scripts\python.exe -m security_reviewer_v2.test_environment.hyperv --storage 'F:\(1) projects\SEC'
```

It reports Windows/Hyper-V tooling, administrative setup rights, host memory,
and free disk space. `host_tools_ready` means only these host prerequisites
passed. It does not test an Ubuntu image, VM creation, private networking,
guest provisioning, result transfer, or cleanup. The VM runner is **not yet
implemented**, so untrusted project startup remains blocked.

A separate administrator-only bootstrap script,
`scripts/create_hyperv_base_vm.ps1`, creates a **base installation VM**, not a
per-scan disposable worker. It requires the official
`ubuntu-24.04.5-live-server-amd64.iso` and validates its SHA-256 against
Ubuntu's published checksum before creating a Generation 2 VM with 6 GiB
startup memory, two virtual processors, and a 60 GiB dynamic VHDX. It omits
`-SwitchName`, verifies that no network adapter is connected, and leaves the VM
powered off. Ubuntu installation inside it is a separate manual step. The base VM must not
receive an untrusted target repository; it is only a clean source for future
disposable workers. The expected ISO checksum comes from
[Ubuntu's release checksums](https://releases.ubuntu.com/24.04/SHA256SUMS).

## Provision the permanent base, not a scan worker

After installing Ubuntu, power it off, create a deliberate `Ubuntu-Clean-Base`
checkpoint, and disable automatic checkpoints. The base stays on disk; the
future per-scan workers will be disposable copies, not repeated Ubuntu installs.

From an Administrator PowerShell session, run
`scripts/connect_hyperv_base_for_provisioning.ps1` only while the base VM is
Off. The script checks the clean checkpoint and disconnected adapter, then
connects the base to the existing `Default Switch` and starts it. This network
is for **trusted OS and Docker provisioning only**. Never transfer or run an
untrusted target on the connected base.

Inside Ubuntu, check that the guest has an IP address and can reach Ubuntu and
Docker's package repositories. The repository's
`scripts/provision_ubuntu_base_docker.sh` follows Docker's [Ubuntu apt-repository
installation](https://docs.docker.com/engine/install/ubuntu/) for Ubuntu 24.04
amd64: it upgrades OS packages, installs Docker Engine and Compose, and checks
the daemon. Transfer this reviewed script to the guest user's home directory
over SSH, compare its SHA-256 on host and guest, then run it with `sudo bash`.
It refuses conflicting Docker packages rather than uninstalling them silently.
Do not add the guest user to the `docker` group; that group is effectively
root-equivalent. Keep Docker access under `sudo` in the base.

After installation and any required reboot, verify Docker and Compose. Then run
`scripts/disconnect_hyperv_base_after_provisioning.ps1` from Administrator
PowerShell. It disconnects only this base VM's adapter when attached to the
expected switch; it does not delete anything. Confirm that the guest has no
external network access, shut it down cleanly, and create a second deliberate
checkpoint (for example `Ubuntu-Docker-Ready`) while Off. A checkpoint is a
convenient rollback point, **not a separate backup** or a complete isolation
boundary.

These provisioning scripts do not create per-scan clones, transfer a project,
run Docker Compose for an unknown repository, or export reports. Until a
disposable worker and its private network/result channel are implemented and
tested, the project must continue to block untrusted target execution.

## Offline educational pilot (not a generic worker)

The fixed Security Lab Web pilot has a narrower purpose: prove that a fresh VM
can be copied from `Ubuntu-Docker-Ready`, run a local health test without a
network switch, return a bounded report, and be removed without changing the
base VM. It is **not** an arbitrary-repository executor, a vulnerability scan,
or an automatic runtime target for the main pipeline. An operator still mounts the exchange
disk and starts the test from the Ubuntu console; nothing in the target can
silently supply startup instructions.

The reviewed lab target needs `Flask==3.1.3`. Download its Linux CPython 3.12
wheels on the Windows host **before** creating the isolated worker. These go to
a local cache outside the scanned target; no guest network access is needed:

```powershell
python -m pip download --only-binary=:all: --platform manylinux2014_x86_64 `
  --python-version 3.12 --implementation cp --abi cp312 `
  --dest 'F:\(1) projects\SEC\vm\pilot-wheels' `
  -r 'F:\(1) projects\SEC\agentic-security-reviewer-v2\targets\security-lab-web\requirements.txt'
```

From **Administrator PowerShell**, start the pilot. The script validates the
powered-off, disconnected base; hashes its virtual disks; exports the named
checkpoint; imports a separate VM with a new ID; stages only four fixed lab
source files and seven bounded wheels on a FAT32 exchange VHDX; attaches it
to the worker; and starts the worker with **no virtual switch**:

```powershell
& 'F:\(1) projects\SEC\agentic-security-reviewer-v2\scripts\start_hyperv_educational_pilot.ps1' `
  -VmStorageRoot 'F:\(1) projects\SEC\vm' `
  -WheelDirectory 'F:\(1) projects\SEC\vm\pilot-wheels'
```

Record the printed eight-character Run ID and worker VM name. In that worker's
Ubuntu console only, log in and run:

```bash
sudo mkdir -p /mnt/sr-pilot
sudo mount -t vfat -o uid=$(id -u),gid=$(id -g),umask=077 /dev/disk/by-label/SRPILOT /mnt/sr-pilot
python3 /mnt/sr-pilot/pilot_guest.py --exchange /mnt/sr-pilot
sudo umount /mnt/sr-pilot
sudo poweroff
```

The guest runner extracts size-bounded archives, checks staged SHA-256 values,
starts the lab app with Flask debug/reloader disabled on `127.0.0.1:5000`,
performs only a GET health check, stops the app, and writes `report.json` to
the exchange disk. It does **not** assert that vulnerabilities were found.

Once the worker is Off, finish from **Administrator PowerShell**, replacing the
example ID with the ID printed by the start script:

```powershell
& 'F:\(1) projects\SEC\agentic-security-reviewer-v2\scripts\finish_hyperv_educational_pilot.ps1' `
  -RunId '1234abcd' -VmStorageRoot 'F:\(1) projects\SEC\vm'
```

The finish script rejects a mismatched VM, a connected adapter, a changed base
checkpoint or base-disk hash, disks outside that run's directory, and a missing,
oversized, or non-passing report. Only after an HTTP 200 health check and those
other checks does it copy the report to
`reports/hyperv-pilot/<run-id>/`, remove the uniquely named Off worker and its
run directory, and record `lifecycle.json`. If a check fails, the worker is
preserved for inspection; never remove it by a broad wildcard. The permanent
base and its checkpoints are never cleanup targets.

The first completed run, `070ca44b`, recorded HTTP 200 and `passed` in
`reports/hyperv-pilot/070ca44b/guest-report.json`. Its lifecycle record says
the disposable worker was removed and the permanent base checkpoint and disk
hashes were unchanged. The pipeline can import those two bounded records for
the fixed target using an explicit run ID:

```powershell
.venv\Scripts\python.exe scripts\run_pre_review_pipeline.py `
  targets\security-lab-web --output reports\security-lab-web-with-pilot `
  --isolated-pilot-run-id 070ca44b
```

This historical health-only import still uses the full pipeline, so current
runs also require configured AI Discovery. It does not satisfy `--require-dast`.

This validates the current `app.py` fingerprint before the pipeline scans
source code. It writes `isolated-pilot-evidence.json`, includes the smoke result
in `pre-review-summary.json` and `security-review-report.md`, and records an
explicit DAST coverage gap. It **does not** boot another VM, expose a guest URL,
or count the smoke result as a vulnerability finding. An ambient
`SECURITY_REVIEWER_RUNTIME_URL` or `--runtime-url` cannot be combined with this
flag, to avoid mixing an unrelated live target with the archived VM evidence.

This pilot's worker is deliberately networkless, stronger than relying on a
`Private` switch for a one-VM smoke test. It does not prove generic Compose,
DAST, CodeQL, account provisioning, or unattended guest operation. Pipeline
execution of unknown projects remains blocked until the broader worker protocol
is implemented.

If Hyper-V is absent, Microsoft documents enabling it from an Administrator
PowerShell session with `Enable-WindowsOptionalFeature -Online -FeatureName
Microsoft-Hyper-V -All`, followed by a restart. This changes the host and is
not run by the project or its profiler. Verify its state after reboot. See
[Microsoft's installation instructions](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/get-started/Install-Hyper-V?pivots=windows&tabs=powershell).

Before allowing the first untrusted repository, implement and test: a pinned
guest image, guest command protocol with allowlisted operations, private
network policy, authenticated report extraction, cleanup-on-failure, and an
end-to-end test that leaves no running VM or writable project disk. Do not
silently fall back to host Compose when any VM prerequisite fails.
