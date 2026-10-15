"""Import verified bounded DAST results from an automatic Hyper-V worker."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


_RUN_ID = re.compile(r"[0-9a-f]{8}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_BYTES = 1024 * 1024


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > _MAX_BYTES:
        raise ValueError(f"Isolated runtime artifact is missing, linked, or oversized: {path.name}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"Isolated runtime artifact is invalid JSON: {path.name}") from error
    if not isinstance(payload, dict):
        raise ValueError(f"Isolated runtime artifact must be an object: {path.name}")
    return payload


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_isolated_runtime(
    run_id: str, *, project_root: Path, repository_root: Path,
) -> dict[str, object]:
    """Check identity, source fingerprint, guest output hashes, and cleanup."""
    if not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id):
        raise ValueError("Runtime run ID must be eight lowercase hexadecimal characters")
    repository = repository_root.resolve(strict=True)
    project = project_root.resolve(strict=True)
    target = (repository / "targets" / "security-lab-web").resolve(strict=True)
    if project != target:
        raise ValueError("Automatic isolated DAST currently supports only Security Lab Web")
    result_root = repository / "reports" / "hyperv-autoscan" / run_id
    if (not result_root.is_dir() or result_root.is_symlink() or
            result_root.resolve(strict=True) != result_root.absolute()):
        raise ValueError("Completed isolated runtime result directory is unavailable")
    guest_path = result_root / "guest-report.json"
    lifecycle_path = result_root / "lifecycle.json"
    guest = _read_json(guest_path)
    lifecycle = _read_json(lifecycle_path)
    if (guest.get("schema_version") != "1.0" or guest.get("run_id") != run_id or
            guest.get("target_id") != "security-lab-web" or
            guest.get("test_kind") != "isolated_runtime_scan" or
            guest.get("status") != "passed" or type(guest.get("http_status")) is not int or
            guest["http_status"] != 200 or guest.get("network_required") is not False or
            type(guest.get("mutating_checks_enabled")) is not bool):
        raise ValueError("Guest did not attest a passing networkless DAST run")
    if (lifecycle.get("schema_version") != "1.0" or lifecycle.get("run_id") != run_id or
            lifecycle.get("guest_status") != "passed" or
            lifecycle.get("worker_removed") is not True or
            lifecycle.get("base_checkpoint_unchanged") is not True or
            lifecycle.get("base_disk_sha256_unchanged") is not True or
            lifecycle.get("network_isolation") != "no_vm_switch" or
            lifecycle.get("runtime_scan") is not True or
            lifecycle.get("trusted_tools_matched") is not True or
            lifecycle.get("result") != "guest-report.json"):
        raise ValueError("Isolated runtime lifecycle did not attest safe cleanup")
    app_hash = guest.get("app_sha256")
    if (not isinstance(app_hash, str) or not _SHA256.fullmatch(app_hash) or
            _sha256(project / "app.py") != app_hash):
        raise ValueError("Security Lab Web source changed since isolated DAST")
    output_hashes = guest.get("output_sha256")
    probe_counts = guest.get("probe_counts")
    if not isinstance(output_hashes, dict) or not isinstance(probe_counts, dict):
        raise ValueError("Guest DAST output inventory is missing")
    result_paths: dict[str, str] = {}
    counts: dict[str, int] = {}
    for filename, expected_source in (("runtime.json", "web-runtime"),
                                      ("authorization.json", "tt-authorization-runtime")):
        path = result_root / filename
        payload = _read_json(path)
        expected_hash = output_hashes.get(filename)
        expected_count = probe_counts.get(filename)
        if (not isinstance(expected_hash, str) or not _SHA256.fullmatch(expected_hash) or
                _sha256(path) != expected_hash or
                payload.get("schema_version") != "1.0" or
                payload.get("source") != expected_source or
                payload.get("target") != "http://127.0.0.1:5000" or
                payload.get("status") != "completed" or
                not isinstance(payload.get("results"), list) or
                type(expected_count) is not int or expected_count < 1 or
                len(payload["results"]) != expected_count):
            raise ValueError(f"Isolated DAST result did not match guest evidence: {filename}")
        result_paths[filename] = str(path)
        counts[filename] = expected_count
    return {
        "schema_version": "1.0", "status": "passed", "run_id": run_id,
        "target_id": "security-lab-web", "test_kind": "isolated_runtime_scan",
        "http_status": 200, "app_sha256": app_hash,
        "mutating_checks_enabled": guest["mutating_checks_enabled"],
        "network_isolation": "no_vm_switch", "worker_removed": True,
        "base_checkpoint_unchanged": True, "base_disk_sha256_unchanged": True,
        "probe_counts": counts, "result_paths": result_paths,
        "guest_report_path": str(guest_path), "lifecycle_path": str(lifecycle_path),
        "limitations": [
            "DAST checks are fixed Security Lab Web HTTP probes, not generic browser or business-workflow coverage.",
            "The guest had no external network; dependency artifacts were staged before VM startup.",
        ],
    }
