"""Bind a saved scan plan to the profiled project and its discovered file contents."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .discovery import discover_project
from .models import ProfileResult, ProfilerLimits, ProfilerPolicy


SNAPSHOT_VERSION = "1.1"


def create_saved_profile_artifact(
    result: ProfileResult,
    project_root: str | Path,
    *,
    limits: ProfilerLimits | None = None,
    policy: ProfilerPolicy | None = None,
) -> dict[str, Any]:
    """Save content hashes, never file contents, beside a profiler result."""
    root = Path(project_root).resolve()
    active_limits = limits or ProfilerLimits()
    active_policy = policy or ProfilerPolicy()
    payload = result.to_dict()
    snapshot = _make_snapshot(
        root,
        payload,
        limits=active_limits,
        allow_symlinks=active_policy.allow_symlinks,
        discovery_exclusions=active_policy.additional_discovery_exclusions,
    )
    payload["project_snapshot"] = snapshot
    return payload


def validate_saved_profile_artifact(
    payload: dict[str, Any], project_root: str | Path
) -> str:
    """Reject a different root, changed files, or an edited saved scan plan."""
    saved = payload.get("project_snapshot")
    if not isinstance(saved, dict) or saved.get("version") != SNAPSHOT_VERSION:
        raise ValueError("Saved profile lacks a project snapshot; rerun the profiler")
    root = Path(project_root).resolve()
    if saved.get("root_path") != os.path.normcase(str(root)):
        raise ValueError("Saved profile belongs to a different project root")
    try:
        options = saved["discovery_options"]
        limits = ProfilerLimits(**options["limits"])
        limits.validate()
        allow_symlinks = options["allow_symlinks"]
        exclusions = tuple(options["exclusions"])
        if not isinstance(allow_symlinks, bool) or not all(
            isinstance(value, str) for value in exclusions
        ):
            raise ValueError("Invalid snapshot discovery options")
        current = _make_snapshot(
            root,
            payload,
            limits=limits,
            allow_symlinks=allow_symlinks,
            discovery_exclusions=exclusions,
        )
    except (KeyError, TypeError, OSError) as error:
        raise ValueError("Saved profile snapshot is invalid or cannot be checked") from error
    if current != saved:
        raise ValueError("Saved profile is stale: project files or scan plan changed; rerun the profiler")
    return current["fingerprint"]


def _make_snapshot(
    root: Path,
    payload: dict[str, Any],
    *,
    limits: ProfilerLimits,
    allow_symlinks: bool,
    discovery_exclusions: tuple[str, ...],
) -> dict[str, Any]:
    policy = ProfilerPolicy(
        allow_symlinks=allow_symlinks,
        additional_discovery_exclusions=discovery_exclusions,
    )
    discovery = discover_project(root, limits=limits, policy=policy)
    actual_inventory = [asdict(record) for record in discovery.files]
    if actual_inventory != payload["profile"]["inventory"]:
        raise ValueError("Project inventory changed since profiling; rerun the profiler")
    files = []
    for record in discovery.files:
        path = root / record.path
        if path.is_symlink() and not allow_symlinks:
            raise ValueError(f"Project file became a symlink: {record.path}")
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(root):
            raise ValueError(f"Project file resolves outside its root: {record.path}")
        before = resolved.stat()
        digest = hashlib.sha256()
        with resolved.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        after = resolved.stat()
        if (
            before.st_size != record.size_bytes
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
        ):
            raise ValueError(f"Project file changed while hashing: {record.path}")
        files.append({"path": record.path, "sha256": digest.hexdigest()})
    body = {
        "version": SNAPSHOT_VERSION,
        "root_path": os.path.normcase(str(root)),
        "discovery_options": {
            "limits": asdict(limits),
            "allow_symlinks": allow_symlinks,
            "exclusions": list(discovery_exclusions),
        },
        "inventory_sha256": _digest(payload["profile"]["inventory"]),
        "scan_plan_sha256": _digest(payload["scan_plan"]),
        # Binds the ingested graph summary so it cannot be edited after review.
        "code_graph_sha256": _digest(payload.get("code_graph")),
        "files": files,
    }
    return {**body, "fingerprint": _digest(body)}


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
