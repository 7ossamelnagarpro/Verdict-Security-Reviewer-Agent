"""Offline Security Lab Web smoke test inside a disposable Ubuntu VM.

Only the reviewed host-side pilot launcher should stage this file. The scanned
project is data until this script deliberately starts it inside the guest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath


SCHEMA_VERSION = "1.0"
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_MEMBER_BYTES = 8 * 1024 * 1024
MAX_MEMBERS = 512


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def extract_bounded(archive: Path, destination: Path) -> None:
    """Extract a small zip without traversal, links, or zip bombs."""
    total = 0
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as source:
        members = source.infolist()
        if len(members) > MAX_MEMBERS:
            raise ValueError("archive_member_limit")
        for member in members:
            parts = PurePosixPath(member.filename)
            mode = (member.external_attr >> 16) & 0xFFFF
            if (parts.is_absolute() or not parts.parts or
                    any(part in {"", ".", ".."} for part in parts.parts) or
                    "\\" in member.filename or ":" in member.filename or
                    stat.S_ISLNK(mode)):
                raise ValueError("unsafe_archive_path")
            if member.file_size > MAX_MEMBER_BYTES:
                raise ValueError("archive_member_size_limit")
            total += member.file_size
            if total > MAX_ARCHIVE_BYTES:
                raise ValueError("archive_total_size_limit")
            target = destination.joinpath(*parts.parts)
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with source.open(member) as reader, target.open("xb") as writer:
                shutil.copyfileobj(reader, writer, length=1024 * 1024)


def _health_check(process: subprocess.Popen[bytes]) -> tuple[str, int | None]:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return "app_exited_before_health", None
        try:
            with opener.open("http://127.0.0.1:5000/", timeout=2) as response:
                response.read(256)
                return ("passed" if response.status == 200 else "unexpected_http_status",
                        response.status)
        except urllib.error.HTTPError as error:
            return "unexpected_http_status", error.code
        except (OSError, urllib.error.URLError):
            time.sleep(0.5)
    return "health_timeout", None


def require_disconnected_network(interfaces: Path = Path("/sys/class/net")) -> None:
    """Fail closed if a non-loopback guest link has carrier."""
    if not interfaces.is_dir():
        raise RuntimeError("network_state_unavailable")
    for interface in interfaces.iterdir():
        if interface.name == "lo":
            continue
        try:
            state = (interface / "operstate").read_text(encoding="ascii").strip()
        except OSError as error:
            raise RuntimeError("network_state_unavailable") from error
        if state not in {"down", "dormant", "lowerlayerdown"}:
            raise RuntimeError("network_link_present")


def run_pilot(exchange: Path) -> dict[str, object]:
    manifest_path = exchange / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if (manifest.get("schema_version") != SCHEMA_VERSION or
            manifest.get("target_id") != "security-lab-web" or
            not isinstance(manifest.get("run_id"), str) or
            not isinstance(manifest.get("files"), dict)):
        raise ValueError("invalid_manifest")
    files = manifest["files"]
    wheel_names = sorted(name for name in files if name.endswith(".whl"))
    if "security-lab-web.zip" not in files or len(wheel_names) != 7:
        raise ValueError("missing_pilot_assets")
    for name, expected in files.items():
        if (not isinstance(name, str) or Path(name).name != name or
                not isinstance(expected, str) or len(expected) != 64):
            raise ValueError("invalid_asset_manifest")
        path = exchange / name
        if not path.is_file() or path.stat().st_size > MAX_ARCHIVE_BYTES or sha256(path) != expected:
            raise ValueError("asset_hash_mismatch")
    if sys.version_info[:2] != (3, 12):
        raise RuntimeError("expected_python_3_12")
    require_disconnected_network()

    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="sr-pilot-") as temporary:
        root = Path(temporary)
        source_root = root / "project"
        dependencies = root / "dependencies"
        extract_bounded(exchange / "security-lab-web.zip", source_root)
        for wheel_name in wheel_names:
            extract_bounded(exchange / wheel_name, dependencies)
        if not (source_root / "app.py").is_file():
            raise ValueError("app_source_missing")
        if sha256(source_root / "app.py") != manifest.get("app_sha256"):
            raise ValueError("app_source_changed")
        environment = {"PATH": "/usr/bin:/bin", "HOME": str(root),
                       "PYTHONPATH": str(dependencies), "PYTHONDONTWRITEBYTECODE": "1",
                       "PYTHONUNBUFFERED": "1"}
        # Importing the project is intentional here: only the disposable guest
        # runs it. Disable Flask's debug reloader to keep one bounded process.
        command = [sys.executable, "-c", "from app import app, init_db; "
                   "init_db(); app.run(host='127.0.0.1', port=5000, "
                   "debug=False, use_reloader=False)"]
        process = subprocess.Popen(command, cwd=source_root, env=environment,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            status, http_status = _health_check(process)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": manifest["run_id"],
        "target_id": "security-lab-web",
        "status": status,
        "http_status": http_status,
        "app_sha256": manifest["app_sha256"],
        "network_required": False,
        "test_kind": "local_health_smoke_only",
        "elapsed_seconds": round(time.monotonic() - started, 2),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exchange", type=Path, default=Path("/mnt/sr-pilot"))
    args = parser.parse_args()
    report: dict[str, object]
    try:
        report = run_pilot(args.exchange)
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, json.JSONDecodeError) as error:
        run_id = None
        try:
            supplied = json.loads((args.exchange / "manifest.json").read_text(encoding="utf-8"))
            if isinstance(supplied.get("run_id"), str):
                run_id = supplied["run_id"]
        except (OSError, ValueError, AttributeError):
            pass
        report = {"schema_version": SCHEMA_VERSION, "run_id": run_id,
                  "target_id": "security-lab-web", "status": "failed",
                  "error_type": type(error).__name__, "test_kind": "local_health_smoke_only"}
    report_path = args.exchange / "report.json"
    temporary_path = args.exchange / "report.tmp"
    temporary_path.write_text(json.dumps(report, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary_path, report_path)
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
