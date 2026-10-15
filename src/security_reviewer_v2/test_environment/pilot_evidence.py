"""Validate completed, fixed-target Hyper-V pilot evidence for the pipeline.

This is historical smoke-test evidence, not a runtime URL or vulnerability scan.
Only the project's own pilot result directory is accepted.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


_RUN_ID = re.compile(r"[0-9a-f]{8}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_REPORT_BYTES = 64 * 1024


def _read_bounded_json(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > _MAX_REPORT_BYTES:
        raise ValueError(f"Pilot evidence is missing, linked, or oversized: {path.name}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"Pilot evidence is not valid JSON: {path.name}") from error
    if not isinstance(payload, dict):
        raise ValueError(f"Pilot evidence must be an object: {path.name}")
    return payload


def load_completed_pilot(
    run_id: str, *, project_root: Path, repository_root: Path,
) -> dict[str, object]:
    """Import a completed Security Lab Web pilot without launching anything."""
    if not _RUN_ID.fullmatch(run_id):
        raise ValueError("Pilot run ID must be eight lowercase hexadecimal characters")
    repository = repository_root.resolve(strict=True)
    project = project_root.resolve(strict=True)
    target = (repository / "targets" / "security-lab-web").resolve(strict=True)
    if project != target:
        raise ValueError("Hyper-V pilot evidence only applies to the fixed Security Lab Web target")
    result_root = repository / "reports" / "hyperv-pilot" / run_id
    if (not result_root.is_dir() or result_root.is_symlink() or
            result_root.resolve(strict=True) != result_root.absolute()):
        raise ValueError("Completed pilot result directory is unavailable")
    guest_path = result_root / "guest-report.json"
    lifecycle_path = result_root / "lifecycle.json"
    guest = _read_bounded_json(guest_path)
    lifecycle = _read_bounded_json(lifecycle_path)
    if (guest.get("schema_version") != "1.0" or guest.get("run_id") != run_id or
            guest.get("target_id") != "security-lab-web" or
            guest.get("test_kind") != "local_health_smoke_only" or
            guest.get("status") != "passed" or type(guest.get("http_status")) is not int or
            guest["http_status"] != 200 or guest.get("network_required") is not False):
        raise ValueError("Guest pilot report did not record a passing, networkless HTTP 200 smoke test")
    if (lifecycle.get("schema_version") != "1.0" or lifecycle.get("run_id") != run_id or
            lifecycle.get("guest_status") != "passed" or
            lifecycle.get("worker_removed") is not True or
            lifecycle.get("base_checkpoint_unchanged") is not True or
            lifecycle.get("base_disk_sha256_unchanged") is not True or
            lifecycle.get("network_isolation") != "no_vm_switch" or
            lifecycle.get("result") != guest_path.name):
        raise ValueError("Pilot lifecycle did not attest safe worker cleanup and unchanged base disks")
    app_hash = guest.get("app_sha256")
    if not isinstance(app_hash, str) or not _SHA256.fullmatch(app_hash):
        raise ValueError("Guest report has no valid application fingerprint")
    current_hash = hashlib.sha256((project / "app.py").read_bytes()).hexdigest()
    if app_hash != current_hash:
        raise ValueError("Security Lab Web source changed since the isolated pilot")
    return {
        "schema_version": "1.0",
        "status": "passed",
        "run_id": run_id,
        "target_id": "security-lab-web",
        "test_kind": "local_health_smoke_only",
        "http_status": 200,
        "app_sha256": app_hash,
        "worker_removed": True,
        "base_checkpoint_unchanged": True,
        "base_disk_sha256_unchanged": True,
        "network_isolation": "no_vm_switch",
        "guest_report_path": str(guest_path),
        "lifecycle_path": str(lifecycle_path),
        "limitations": [
            "Historical local health smoke only; no vulnerability or DAST result was produced inside the VM.",
            "The networkless worker offered no runtime URL to the host pipeline.",
        ],
    }
