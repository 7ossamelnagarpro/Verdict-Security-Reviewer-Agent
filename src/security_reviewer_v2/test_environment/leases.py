"""Recoverable ownership records for resources created by one review job."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


def register(name: str, *, config: dict | None = None) -> tuple[Path, Path | None]:
    if not re.fullmatch(r"sr-(?:test|zap)-[a-z0-9]+", name):
        raise ValueError("Unexpected runtime resource name")
    root = Path(
        os.environ.get("VERDICT_LEASE_ROOT")
        or tempfile.mkdtemp(prefix="verdict-lease-")
    )
    root.mkdir(parents=True, exist_ok=True)
    snapshot = root / f"{name}.compose.json" if config is not None else None
    if snapshot:
        snapshot.write_text(json.dumps(config), encoding="utf-8")
    lease = root / f"{name}.lease.json"
    lease.write_text(
        json.dumps(
            {
                "name": name,
                "kind": "compose" if config is not None else "container",
                "snapshot": snapshot.name if snapshot else None,
                "active": True,
            }
        ),
        encoding="utf-8",
    )
    return lease, snapshot


def release(lease: Path) -> None:
    data = json.loads(lease.read_text(encoding="utf-8"))
    data["active"] = False
    lease.write_text(json.dumps(data), encoding="utf-8")
    if data.get("snapshot"):
        target = lease.parent / data["snapshot"]
        if target.resolve().parent == lease.parent.resolve():
            target.unlink(missing_ok=True)


def cleanup(root: Path, *, runner=subprocess.run) -> list[str]:
    errors = []
    docker = shutil.which("docker")
    for lease in root.glob("*.lease.json"):
        try:
            data = json.loads(lease.read_text(encoding="utf-8"))
            name = data["name"]
            if not data.get("active"):
                continue
            if not docker or not re.fullmatch(r"sr-(?:test|zap)-[a-z0-9]+", name):
                raise ValueError("Docker or resource identity is unavailable")
            if data["kind"] == "compose":
                snapshot = (root / data["snapshot"]).resolve()
                if snapshot.parent != root.resolve() or not snapshot.is_file():
                    raise ValueError("Cleanup configuration is unavailable")
                result = runner(
                    [
                        docker,
                        "compose",
                        "-f",
                        str(snapshot),
                        "-p",
                        name,
                        "down",
                        "--volumes",
                        "--remove-orphans",
                    ],
                    capture_output=True,
                    timeout=120,
                )
                checked = runner(
                    [
                        docker,
                        "ps",
                        "-a",
                        "--filter",
                        f"label=com.docker.compose.project={name}",
                        "--format",
                        "{{.ID}}",
                    ],
                    capture_output=True,
                    timeout=30,
                )
            else:
                # rm reports an error for an already-removed --rm container; verify absence below.
                runner([docker, "rm", "--force", name], capture_output=True, timeout=30)
                result = subprocess.CompletedProcess([], 0)
                checked = runner(
                    [
                        docker,
                        "ps",
                        "-a",
                        "--filter",
                        f"name=^/{name}$",
                        "--format",
                        "{{.ID}}",
                    ],
                    capture_output=True,
                    timeout=30,
                )
            if result.returncode or checked.returncode or checked.stdout.strip():
                raise RuntimeError("Resource removal could not be verified")
            release(lease)
        except (
            OSError,
            ValueError,
            KeyError,
            RuntimeError,
            subprocess.TimeoutExpired,
        ) as error:
            errors.append(f"{lease.stem}: {error}")
    return errors
