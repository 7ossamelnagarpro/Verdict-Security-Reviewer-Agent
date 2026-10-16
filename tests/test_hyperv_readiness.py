"""The VM readiness probe is read-only and fails closed."""

from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace
from pathlib import Path

import pytest

from security_reviewer_v2.test_environment.hyperv import inspect_hyperv_host


def test_non_windows_host_is_blocked_without_running_commands(tmp_path: Path) -> None:
    def runner(*_args, **_kwargs):
        raise AssertionError("No command should be run")

    result = inspect_hyperv_host(tmp_path, system_name="Linux", runner=runner)
    assert result.status == "blocked"
    assert any("Windows Hyper-V" in reason for reason in result.missing)


def test_windows_host_readiness_uses_only_a_fixed_read_only_query(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Keep this unit test independent of the runner's actual free disk space.
    # The production readiness check must still enforce its real storage limit.
    monkeypatch.setattr(
        "security_reviewer_v2.test_environment.hyperv.shutil.disk_usage",
        lambda _root: SimpleNamespace(free=80 * 1024**3),
    )
    calls = []

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        payload = {"os_name": "Windows 10 Pro", "is_administrator": True,
                   "hypervisor_present": True, "hyperv_module_available": True,
                   "vm_commands_available": True, "memory_gib": 16.0}
        return subprocess.CompletedProcess(argv, 0, json.dumps(payload), "")

    result = inspect_hyperv_host(tmp_path, system_name="Windows",
                                 powershell_executable="powershell.exe", runner=runner)
    assert result.status == "host_tools_ready"
    argv, kwargs = calls[0]
    assert argv[:4] == ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command"]
    assert str(tmp_path) not in argv[-1]
    assert "New-VM" not in argv[-1]
    assert "Enable-WindowsOptionalFeature" not in argv[-1]
    assert kwargs["timeout"] == 20
    assert result.notes


def test_missing_management_tools_and_admin_rights_block_vm_setup(tmp_path: Path) -> None:
    payload = {"os_name": "Windows 10 Pro", "is_administrator": False,
               "hypervisor_present": True, "hyperv_module_available": False,
               "vm_commands_available": False, "memory_gib": 16.0}

    def runner(argv, **_kwargs):
        return subprocess.CompletedProcess(argv, 0, json.dumps(payload), "")

    result = inspect_hyperv_host(tmp_path, system_name="Windows",
                                 powershell_executable="powershell.exe", runner=runner)
    assert result.status == "blocked"
    assert any("Administrator" in reason for reason in result.missing)
    assert any("management tools" in reason for reason in result.missing)


def test_invalid_host_output_fails_closed(tmp_path: Path) -> None:
    def runner(argv, **_kwargs):
        return subprocess.CompletedProcess(argv, 0, "unexpected output", "")

    result = inspect_hyperv_host(tmp_path, system_name="Windows",
                                 powershell_executable="powershell.exe", runner=runner)
    assert result.status == "blocked"
    assert any("inventory failed" in reason for reason in result.missing)
