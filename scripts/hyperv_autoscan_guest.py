"""Trusted boot-time worker for the fixed, networkless Security Lab Web VM.

Install this in the base VM once. The target archive is data until launched as
the unprivileged ``nobody`` user; only this trusted worker writes scan reports.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

try:
    import pwd
except ImportError:  # Unit tests also import this module on Windows.
    pwd = None

if __package__:
    from .hyperv_pilot_guest import (
        MAX_ARCHIVE_BYTES, _health_check, extract_bounded,
        require_disconnected_network, sha256,
    )
else:
    from hyperv_pilot_guest import (
        MAX_ARCHIVE_BYTES, _health_check, extract_bounded,
        require_disconnected_network, sha256,
    )


SCHEMA_VERSION = "1.0"
MAX_SCANNER_OUTPUT = 1024 * 1024
SCANNERS = (
    ("runtime.json", "web_runtime.py"),
    ("authorization.json", "scan_tt_authorization.py"),
)


def _validate_manifest(exchange: Path) -> dict[str, object]:
    manifest = json.loads((exchange / "manifest.json").read_text(encoding="utf-8"))
    if (not isinstance(manifest, dict) or manifest.get("schema_version") != SCHEMA_VERSION or
            manifest.get("mode") != "automatic_runtime_scan" or
            manifest.get("target_id") != "security-lab-web" or
            not isinstance(manifest.get("run_id"), str) or
            len(manifest["run_id"]) != 8 or
            any(char not in "0123456789abcdef" for char in manifest["run_id"]) or
            type(manifest.get("mutating_checks")) is not bool or
            not isinstance(manifest.get("files"), dict)):
        raise ValueError("invalid_automatic_manifest")
    files = manifest["files"]
    wheel_names = [name for name in files if isinstance(name, str) and name.endswith(".whl")]
    if len(files) != 8 or len(wheel_names) != 7 or "security-lab-web.zip" not in files:
        raise ValueError("missing_automatic_assets")
    for name, expected in files.items():
        if (not isinstance(name, str) or Path(name).name != name or
                not isinstance(expected, str) or len(expected) != 64):
            raise ValueError("invalid_asset_manifest")
        source = exchange / name
        if (not source.is_file() or source.is_symlink() or
                source.stat().st_size > MAX_ARCHIVE_BYTES or sha256(source) != expected):
            raise ValueError("asset_hash_mismatch")
    return manifest


def _give_target_ownership(path: Path, uid: int, gid: int) -> None:
    for item in (path, *path.rglob("*")):
        if item.is_symlink():
            raise ValueError("target_symlink_rejected")
        os.chown(item, uid, gid)


def _run_scanner(script: Path, output: Path, *, mutating: bool = False) -> int:
    if not script.is_file() or script.is_symlink():
        raise RuntimeError("trusted_scanner_unavailable")
    command = [sys.executable, str(script), "--base-url", "http://127.0.0.1:5000",
               "--output", str(output)]
    if mutating:
        command.append("--mutating")
    completed = subprocess.run(command, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=240, check=False,
                               env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"})
    if completed.returncode != 0 or not output.is_file() or output.stat().st_size > MAX_SCANNER_OUTPUT:
        raise RuntimeError("scanner_failed_or_output_oversized")
    payload = json.loads(output.read_text(encoding="utf-8"))
    if (not isinstance(payload, dict) or payload.get("status") != "completed" or
            not isinstance(payload.get("results"), list) or not payload["results"]):
        raise RuntimeError("scanner_output_incomplete")
    return len(payload["results"])


def run_automatic_scan(exchange: Path, tools_root: Path) -> dict[str, object]:
    if pwd is None or os.geteuid() != 0 or sys.version_info[:2] != (3, 12):
        raise RuntimeError("expected_root_python_3_12")
    manifest = _validate_manifest(exchange)
    require_disconnected_network()
    started = time.monotonic()
    nobody = pwd.getpwnam("nobody")
    with tempfile.TemporaryDirectory(prefix="sr-autoscan-") as temporary:
        root = Path(temporary)
        os.chmod(root, 0o711)
        source_root = root / "project"
        dependencies = root / "dependencies"
        extract_bounded(exchange / "security-lab-web.zip", source_root)
        for wheel_name in sorted(name for name in manifest["files"] if name.endswith(".whl")):
            extract_bounded(exchange / wheel_name, dependencies)
        if (not (source_root / "app.py").is_file() or
                sha256(source_root / "app.py") != manifest.get("app_sha256")):
            raise ValueError("app_source_changed")
        _give_target_ownership(source_root, nobody.pw_uid, nobody.pw_gid)
        home = root / "home"
        home.mkdir()
        os.chown(home, nobody.pw_uid, nobody.pw_gid)
        environment = {"PATH": "/usr/bin:/bin", "HOME": str(home),
                       "PYTHONPATH": str(dependencies), "PYTHONDONTWRITEBYTECODE": "1",
                       "PYTHONUNBUFFERED": "1"}
        command = [sys.executable, "-c", "from app import app, init_db; init_db(); "
                   "app.run(host='127.0.0.1', port=5000, debug=False, use_reloader=False)"]
        process = subprocess.Popen(command, cwd=source_root, env=environment,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, start_new_session=True,
                                   user=nobody.pw_uid, group=nobody.pw_gid)
        try:
            status, http_status = _health_check(process)
            if status != "passed" or http_status != 200:
                raise RuntimeError("app_health_failed")
            counts: dict[str, int] = {}
            hashes: dict[str, str] = {}
            for filename, script_name in SCANNERS:
                temporary_output = root / filename
                counts[filename] = _run_scanner(
                    tools_root / script_name, temporary_output,
                    mutating=bool(manifest["mutating_checks"]) and filename == "runtime.json",
                )
                destination = exchange / filename
                shutil.copyfile(temporary_output, destination)
                hashes[filename] = sha256(destination)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
    return {"schema_version": SCHEMA_VERSION, "run_id": manifest["run_id"],
            "target_id": "security-lab-web", "test_kind": "isolated_runtime_scan",
            "status": "passed", "http_status": 200, "app_sha256": manifest["app_sha256"],
            "network_required": False, "mutating_checks_enabled": manifest["mutating_checks"],
            "trusted_tool_sha256": {
                "worker": sha256(Path(__file__)),
                "web_runtime": sha256(tools_root / "web_runtime.py"),
                "authorization": sha256(tools_root / "scan_tt_authorization.py"),
            },
            "output_sha256": hashes, "probe_counts": counts,
            "elapsed_seconds": round(time.monotonic() - started, 2)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exchange", type=Path, default=Path("/mnt/sr-pilot"))
    args = parser.parse_args()
    try:
        report = run_automatic_scan(args.exchange, Path(__file__).resolve().parent)
    except Exception as error:  # Boot service must always leave a bounded failure artifact.
        run_id = None
        try:
            supplied = json.loads((args.exchange / "manifest.json").read_text(encoding="utf-8"))
            if isinstance(supplied, dict) and isinstance(supplied.get("run_id"), str):
                run_id = supplied["run_id"]
        except (OSError, ValueError):
            pass
        report = {"schema_version": SCHEMA_VERSION, "run_id": run_id,
                  "target_id": "security-lab-web", "test_kind": "isolated_runtime_scan",
                  "status": "failed", "error_type": type(error).__name__}
        reason = str(error)
        if reason and len(reason) <= 80 and all(char.islower() or char.isdigit() or char == "_"
                                                for char in reason):
            report["error_code"] = reason
    temporary = args.exchange / "report.tmp"
    temporary.write_text(json.dumps(report, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, args.exchange / "report.json")
    print(json.dumps({"status": report["status"], "run_id": report["run_id"]}))
    return 0 if report["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
