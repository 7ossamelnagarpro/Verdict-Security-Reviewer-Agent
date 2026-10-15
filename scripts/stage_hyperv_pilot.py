"""Stage one fixed educational target on an offline VM exchange disk."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import zipfile
from pathlib import Path


SOURCE_FILES = (
    "app.py", "requirements.txt", "files/report.txt", "secret_do_not_serve.txt",
)
WHEEL_PREFIXES = (
    "blinker-", "click-", "flask-", "itsdangerous-", "jinja2-",
    "markupsafe-", "werkzeug-",
)


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def stage(target: Path, wheels: Path, exchange: Path, run_id: str,
          guest_runner: Path, *, automatic_runtime: bool = False,
          mutating_checks: bool = False) -> dict[str, object]:
    if mutating_checks and not automatic_runtime:
        raise ValueError("Mutating checks require automatic runtime mode")
    if len(run_id) != 8 or any(char not in "0123456789abcdef" for char in run_id):
        raise ValueError("run_id must be eight lowercase hexadecimal characters")
    if not target.is_dir() or not wheels.is_dir() or not exchange.is_dir():
        raise ValueError("Target, wheel cache and exchange disk must exist")
    if not guest_runner.is_file() or guest_runner.is_symlink():
        raise ValueError("Trusted guest runner is unavailable")
    sources: list[tuple[str, Path]] = []
    for relative in SOURCE_FILES:
        file = target / relative
        if not file.is_file() or file.is_symlink() or not file.resolve().is_relative_to(target.resolve()):
            raise ValueError(f"Required educational source is missing or unsafe: {relative}")
        if file.stat().st_size > 1024 * 1024:
            raise ValueError(f"Educational source exceeds 1 MiB: {relative}")
        sources.append((relative, file))
    if (target / "requirements.txt").read_text(encoding="utf-8").strip() != "Flask==3.1.3":
        raise ValueError("Pilot only supports the reviewed Flask==3.1.3 target")
    selected: list[Path] = []
    for prefix in WHEEL_PREFIXES:
        matches = sorted(wheels.glob(f"{prefix}*.whl"))
        if len(matches) != 1 or matches[0].is_symlink() or matches[0].stat().st_size > 8 * 1024 * 1024:
            raise ValueError(f"Expected one bounded Linux wheel for {prefix}")
        selected.append(matches[0])
    if not any("cp312" in wheel.name and "manylinux" in wheel.name for wheel in selected
               if wheel.name.startswith("markupsafe-")):
        raise ValueError("MarkupSafe must be a CPython 3.12 manylinux wheel")
    archive = exchange / "security-lab-web.zip"
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED) as output:
        for relative, source in sources:
            info = zipfile.ZipInfo(relative, date_time=(2024, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            output.writestr(info, source.read_bytes())
    manifest_files = {archive.name: digest(archive)}
    for wheel in selected:
        destination = exchange / wheel.name
        shutil.copyfile(wheel, destination)
        manifest_files[wheel.name] = digest(destination)
    shutil.copyfile(guest_runner, exchange / "pilot_guest.py")
    manifest: dict[str, object] = {
        "schema_version": "1.0", "run_id": run_id,
        "target_id": "security-lab-web", "app_sha256": digest(target / "app.py"),
        "mode": "automatic_runtime_scan" if automatic_runtime else "manual_health_smoke",
        "mutating_checks": bool(mutating_checks) if automatic_runtime else False,
        "files": dict(sorted(manifest_files.items())),
    }
    (exchange / "manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--wheels", type=Path, required=True)
    parser.add_argument("--exchange", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--guest-runner", type=Path, required=True)
    parser.add_argument("--automatic-runtime", action="store_true")
    parser.add_argument("--mutating-checks", action="store_true")
    args = parser.parse_args()
    if args.mutating_checks and not args.automatic_runtime:
        parser.error("Mutating checks require automatic runtime mode")
    result = stage(args.target, args.wheels, args.exchange, args.run_id,
                   args.guest_runner, automatic_runtime=args.automatic_runtime,
                   mutating_checks=args.mutating_checks)
    print(json.dumps({"run_id": result["run_id"], "asset_count": len(result["files"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
