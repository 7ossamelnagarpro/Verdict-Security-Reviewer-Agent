"""Optional, local codebase-memory-mcp indexing evidence.

This adapter does not turn graph nodes into security findings.  Indexing is a
separate, best-effort preparation step for later application-map work.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path


def index_codebase(
    project_root: Path,
    *,
    timeout_seconds: int = 300,
    executable: str | None = None,
) -> dict[str, object]:
    """Index an authorized local project and return bounded provenance only."""
    project = project_root.resolve()
    if not project.is_dir():
        raise ValueError(f"Project directory is unavailable: {project}")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")

    binary = executable or shutil.which("codebase-memory-mcp")
    result: dict[str, object] = {
        "schema_version": "1.0",
        "tool": "codebase-memory-mcp",
        "project_root": str(project),
        "status": "unavailable" if binary is None else "failed",
        "version": None,
        "index_path": None,
        "node_count": None,
        "edge_count": None,
        "storage": "tool-managed local cache; not a Verdict finding",
    }
    if binary is None:
        result["reason"] = "executable_not_found"
        return result

    try:
        version = subprocess.run(
            [binary, "--version"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=10,
            check=False,
        )
        if version.returncode == 0:
            result["version"] = (version.stdout or version.stderr).strip()[:120] or None
    except (OSError, subprocess.TimeoutExpired):
        pass  # Version reporting is optional; the index attempt still matters.

    try:
        completed = subprocess.run(
            [
                binary,
                "cli",
                "index_repository",
                "--repo-path",
                str(project),
                "--persistence",
                "false",
            ],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout_seconds,
            check=False,
            cwd=project,
        )
    except subprocess.TimeoutExpired:
        result["reason"] = "index_timeout"
        return result
    except OSError:
        result["reason"] = "index_process_failed"
        return result

    if completed.returncode != 0:
        result["reason"] = "index_nonzero_exit"
        result["exit_code"] = completed.returncode
        return result

    # Current CLI releases return JSON; older releases can print a compact
    # human-readable summary. Keep only bounded counts, never raw tool output.
    summary = completed.stdout[:4096]
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        payload = None
    if isinstance(payload, dict):
        tool_status = payload.get("status")
        result["index_status"] = tool_status if isinstance(tool_status, str) else None
        if isinstance(payload.get("project"), str):
            result["graph_project"] = payload["project"]
        for source_key, destination_key in (
            ("nodes", "node_count"),
            ("edges", "edge_count"),
            ("not_indexed_files_count", "not_indexed_files_count"),
            ("skipped_count", "skipped_count"),
            ("parse_partial_count", "parse_partial_count"),
            ("parse_unusable_count", "parse_unusable_count"),
        ):
            value = payload.get(source_key)
            if isinstance(value, int) and not isinstance(value, bool):
                result[destination_key] = value
        if tool_status == "indexed":
            result["status"] = "completed"
        else:
            result["status"] = "failed"
            result["reason"] = "index_status_not_indexed"
        return result

    counts = re.search(r"(\d+)\s+nodes?,\s*(\d+)\s+edges?", summary, re.IGNORECASE)
    if counts:
        result["node_count"] = int(counts.group(1))
        result["edge_count"] = int(counts.group(2))
    index_path = re.search(r"(?m)^\s*db:\s*(.+?)\s*$", summary)
    if index_path:
        result["index_path"] = index_path.group(1)
    result["status"] = "completed"
    return result


def read_indexed_routes(
    graph_project: str,
    *,
    executable: str | None = None,
    timeout_seconds: int = 30,
) -> dict[str, object]:
    """Read bounded Route nodes from an already-indexed local graph."""
    if not graph_project or len(graph_project) > 256:
        raise ValueError("graph_project must be a non-empty, bounded name")
    binary = executable or shutil.which("codebase-memory-mcp")
    if binary is None:
        return {"status": "unavailable", "routes": [], "reason": "executable_not_found"}
    routes: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    offset = 0
    page_size = 50
    page_limit = 10
    total: int | None = None
    incomplete = False
    for _ in range(page_limit):
        try:
            completed = subprocess.run(
                [
                    binary,
                    "cli",
                    "search_graph",
                    "--project",
                    graph_project,
                    "--label",
                    "Route",
                    "--limit",
                    str(page_size),
                    "--offset",
                    str(offset),
                    "--format",
                    "json",
                    "--max-output-tokens",
                    "20000",
                ],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return {"status": "failed", "routes": [], "reason": "graph_query_failed"}
        if completed.returncode != 0:
            return {
                "status": "failed",
                "routes": [],
                "reason": "graph_query_nonzero_exit",
            }
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError:
            return {
                "status": "failed",
                "routes": [],
                "reason": "invalid_graph_response",
            }
        if not isinstance(payload, dict) or not isinstance(payload.get("groups"), list):
            return {
                "status": "failed",
                "routes": [],
                "reason": "invalid_graph_response",
            }
        if isinstance(payload.get("total"), int):
            total = payload["total"]
        for group in payload["groups"]:
            if not isinstance(group, dict) or not isinstance(group.get("file"), str):
                continue
            rows = group.get("rows")
            if not isinstance(rows, list):
                continue
            for row in rows:
                if not isinstance(row, list) or not row or not isinstance(row[0], str):
                    continue
                match = re.fullmatch(
                    r"__route__(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|ANY)__(/.+|/)",
                    row[0],
                )
                if not match:
                    continue
                item = {
                    "method": match.group(1),
                    "path": match.group(2),
                    "file": group["file"],
                }
                key = (item["method"], item["path"], item["file"])
                if key not in seen:
                    seen.add(key)
                    routes.append(item)
        has_more = bool(payload.get("has_more") or payload.get("truncated"))
        if not has_more:
            break
        next_offset = payload.get("next_offset")
        offset = next_offset if isinstance(next_offset, int) else offset + page_size
    else:
        incomplete = True
    if total is not None and len(routes) < total:
        incomplete = True
    return {
        "status": "partial" if incomplete else "completed",
        "routes": routes,
        "total": total,
        "reason": "graph_route_limit" if incomplete else None,
    }
