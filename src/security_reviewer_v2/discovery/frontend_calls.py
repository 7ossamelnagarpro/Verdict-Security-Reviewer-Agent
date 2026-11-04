"""Conservative, snapshot-checked frontend API call inventory."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path, PurePosixPath
from typing import Any

_FRONTEND_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
_SKIP_DIRS = {"node_modules", "vendor", "dist", "build", "coverage", ".git"}
_FETCH = re.compile(r"\b(?:window\.)?fetch\s*\(\s*(['\"])(/[^'\"\r\n]{0,255})\1")
_AXIOS = re.compile(
    r"\baxios\.(get|post|put|patch|delete)\s*\(\s*(['\"])(/[^'\"\r\n]{0,255})\2",
    re.IGNORECASE,
)
_METHOD = re.compile(
    r"\bmethod\s*:\s*(['\"])(GET|POST|PUT|PATCH|DELETE)\1", re.IGNORECASE
)


def collect_frontend_calls(
    project_root: str | Path,
    profile_artifact: dict[str, Any] | None,
    *,
    max_files: int = 64,
    max_total_bytes: int = 2_000_000,
) -> dict[str, Any]:
    """Extract literal same-origin calls without executing JavaScript or reading secrets."""
    snapshot = (
        profile_artifact.get("project_snapshot")
        if isinstance(profile_artifact, dict)
        else None
    )
    profile = (
        profile_artifact.get("profile") if isinstance(profile_artifact, dict) else None
    )
    if not isinstance(snapshot, dict) or not isinstance(profile, dict):
        return {
            "status": "unavailable",
            "calls": [],
            "gaps": ["Profiler snapshot is unavailable."],
        }
    root = Path(project_root).resolve()
    if snapshot.get("root_path") != os.path.normcase(str(root)):
        return {
            "status": "unavailable",
            "calls": [],
            "gaps": ["Profiler snapshot belongs to another project."],
        }
    records = snapshot.get("files")
    inventory = profile.get("inventory")
    if not isinstance(records, list) or not isinstance(inventory, list):
        return {
            "status": "unavailable",
            "calls": [],
            "gaps": ["Profiler source inventory is unavailable."],
        }
    hashes = {
        item["path"]: item["sha256"]
        for item in records
        if isinstance(item, dict)
        and isinstance(item.get("path"), str)
        and isinstance(item.get("sha256"), str)
    }
    paths = sorted(
        {
            item["path"]
            for item in inventory
            if isinstance(item, dict)
            and item.get("category") == "source"
            and isinstance(item.get("path"), str)
            and PurePosixPath(item["path"]).suffix.lower() in _FRONTEND_SUFFIXES
            and not set(PurePosixPath(item["path"]).parts) & _SKIP_DIRS
        }
    )
    gaps = []
    if len(paths) > max_files:
        gaps.append(
            f"Frontend inventory limited to {max_files} of {len(paths)} source files."
        )
    calls: list[dict[str, Any]] = []
    total_bytes = 0
    for relative in paths[:max_files]:
        parts = PurePosixPath(relative).parts
        if not parts or any(part in {".", ".."} for part in parts) or ":" in parts[0]:
            gaps.append(f"Unsafe frontend source path skipped: {relative[:120]}")
            continue
        path = root.joinpath(*parts)
        try:
            current = root
            for part in parts:
                current /= part
                if current.is_symlink():
                    raise ValueError("symlinked source")
            if not path.resolve(strict=True).is_relative_to(root):
                raise ValueError("outside project or symlinked")
            size = path.stat().st_size
            if size > 128_000 or total_bytes + size > max_total_bytes:
                raise ValueError("source read budget exceeded")
            data = path.read_bytes()
            if (
                b"\x00" in data
                or hashes.get(relative) != hashlib.sha256(data).hexdigest()
            ):
                raise ValueError("source differs from profiler snapshot")
            source = data.decode("utf-8")
        except (OSError, UnicodeError, ValueError) as error:
            gaps.append(f"Frontend source {relative[:120]} was not inspected: {error}")
            continue
        total_bytes += len(data)
        for match in _FETCH.finditer(source):
            route = match.group(2)
            if route.startswith("//"):
                continue
            tail = source[match.end() : match.end() + 180]
            method_match = _METHOD.search(tail.split(")", 1)[0])
            method = (
                method_match.group(2).upper()
                if method_match
                else "GET"
                if tail.lstrip().startswith(")")
                else "GET_or_configured"
            )
            calls.append(
                _call(relative, source, match.start(), method, route, "fetch_literal")
            )
        for match in _AXIOS.finditer(source):
            route = match.group(3)
            if route.startswith("//"):
                continue
            calls.append(
                _call(
                    relative,
                    source,
                    match.start(),
                    match.group(1).upper(),
                    route,
                    "axios_literal",
                )
            )
        if len(calls) >= 100:
            calls = calls[:100]
            gaps.append("Frontend API call inventory reached its 100-call limit.")
            break
    calls.sort(
        key=lambda item: (
            item["source"]["file"],
            item["source"]["line"],
            item["method"],
            item["path"],
        )
    )
    return {
        "status": "completed" if not gaps else "partial",
        "calls": calls,
        "gaps": gaps,
    }


def _call(
    file: str, source: str, offset: int, method: str, path: str, evidence: str
) -> dict[str, Any]:
    return {
        "method": method,
        "path": path.split("?", 1)[0],
        "source": {"file": file, "line": source.count("\n", 0, offset) + 1},
        "evidence_kind": evidence,
        "status": "static_reference_not_runtime_proof",
    }
