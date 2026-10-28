"""Read-only ingestion of a code-knowledge-graph file (e.g. Graphify's graph.json).

Design rules:
* The profiler never executes Graphify. A separate orchestrator step builds the
  graph; this module only reads the resulting JSON file.
* The graph is treated as untrusted input. Only paths that match the profiled
  inventory are kept, and only counts/paths are stored. Node labels, docstrings
  and any other free text are dropped so they can never reach a downstream LLM
  agent as an injection vector.
* The exact graph.json schema is NOT assumed. Node-link style graphs
  (``nodes`` + ``edges``/``links``) with common key aliases are accepted; if the
  shape is not recognized the summary says so and the planner ignores it.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath
from typing import Any

from .models import (
    CodeGraphHotspot,
    CodeGraphSummary,
    CrossComponentEdge,
    FileCategory,
    ProjectProfile,
)

MAX_GRAPH_BYTES = 64 * 1024 * 1024
MAX_HOTSPOTS = 20
MAX_CROSS_EDGES = 50
MAX_SAMPLE = 25

_NODE_FILE_KEYS = ("file", "path", "source_file", "file_path", "filepath", "filename")
_NODE_ID_KEYS = ("id", "key", "name")
_EDGE_SOURCE_KEYS = ("source", "from", "src")
_EDGE_TARGET_KEYS = ("target", "to", "dst")
_EDGE_LIST_KEYS = ("edges", "links", "relationships")


def load_code_graph(
    graph_path: str | Path,
    *,
    root: Path,
    profile: ProjectProfile,
    max_bytes: int = MAX_GRAPH_BYTES,
) -> CodeGraphSummary:
    """Summarize a graph file. Never raises on malformed content."""
    path = Path(graph_path).expanduser()
    try:
        size = path.stat().st_size
    except OSError as error:
        return _empty("unreadable", None, (f"Graph file not readable: {type(error).__name__}",))
    if size > max_bytes:
        return _empty("too_large", None, (f"Graph file is {size} bytes; limit is {max_bytes}.",))
    try:
        raw = path.read_bytes()
    except OSError as error:
        return _empty("unreadable", None, (f"Graph file not readable: {type(error).__name__}",))
    digest = hashlib.sha256(raw).hexdigest()
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return _empty("unreadable", digest, ("Graph file is not valid UTF-8 JSON.",))

    nodes, edges = _extract(data)
    if not nodes:
        return _empty(
            "unrecognized",
            digest,
            ("Graph JSON has no recognizable node list; hints were ignored.",),
        )

    inventory = {item.path for item in profile.inventory}
    source_files = {
        item.path for item in profile.inventory if item.category is FileCategory.SOURCE
    }
    roots = sorted(
        ((c.root, c.component_id) for c in profile.components),
        key=lambda pair: (-_depth(pair[0]), pair[0]),
    )

    node_file: dict[str, str] = {}
    graph_files: set[str] = set()
    stale: set[str] = set()
    for node in nodes:
        if not isinstance(node, dict):
            continue
        node_id = _first_str(node, _NODE_ID_KEYS)
        raw_file = _first_str(node, _NODE_FILE_KEYS)
        candidate = raw_file or node_id
        normalized = _normalize(candidate, root) if candidate else None
        if normalized is None:
            continue
        if normalized in inventory:
            graph_files.add(normalized)
            if node_id is not None:
                node_file[node_id] = normalized
        elif raw_file:
            stale.add(normalized)

    neighbors: dict[str, set[str]] = defaultdict(set)
    cross: Counter[tuple[str, str]] = Counter()
    edge_total = 0
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        edge_total += 1
        a = node_file.get(str(edge.get(_pick(edge, _EDGE_SOURCE_KEYS), "")))
        b = node_file.get(str(edge.get(_pick(edge, _EDGE_TARGET_KEYS), "")))
        if not a or not b or a == b:
            continue
        neighbors[a].add(b)
        neighbors[b].add(a)
        ca, cb = _component_for(a, roots), _component_for(b, roots)
        if ca and cb and ca != cb:
            cross[(ca, cb)] += 1

    ranked = sorted(
        ((len(peers), path) for path, peers in neighbors.items() if path in source_files),
        key=lambda pair: (-pair[0], pair[1].casefold()),
    )[:MAX_HOTSPOTS]
    hotspots = tuple(
        CodeGraphHotspot(path=p, component_id=_component_for(p, roots), connected_files=n)
        for n, p in ranked
    )
    uncovered = sorted(source_files - graph_files, key=str.casefold)
    warnings: list[str] = []
    if stale:
        warnings.append(
            f"{len(stale)} graph file(s) are not in the current inventory; the graph may be stale."
        )
    return CodeGraphSummary(
        schema_status="recognized",
        graph_sha256=digest,
        node_count=len(nodes),
        edge_count=edge_total,
        files_in_graph=len(graph_files),
        covered_source_files=len(source_files & graph_files),
        uncovered_source_count=len(uncovered),
        uncovered_source_sample=tuple(uncovered[:MAX_SAMPLE]),
        stale_graph_file_count=len(stale),
        hotspots=hotspots,
        cross_component_edges=tuple(
            CrossComponentEdge(a, b, n)
            for (a, b), n in sorted(cross.items(), key=lambda kv: (-kv[1], kv[0]))[:MAX_CROSS_EDGES]
        ),
        warnings=tuple(warnings),
    )


def hotspot_scores(summary: CodeGraphSummary | None) -> dict[str, int]:
    if summary is None or summary.schema_status != "recognized":
        return {}
    return {item.path: item.connected_files for item in summary.hotspots}


def _empty(status: str, digest: str | None, warnings: tuple[str, ...]) -> CodeGraphSummary:
    return CodeGraphSummary(
        schema_status=status, graph_sha256=digest, node_count=0, edge_count=0,
        files_in_graph=0, covered_source_files=0, uncovered_source_count=0,
        uncovered_source_sample=(), stale_graph_file_count=0, hotspots=(),
        cross_component_edges=(), warnings=warnings,
    )


def _extract(data: Any) -> tuple[list[Any], list[Any]]:
    if not isinstance(data, dict):
        return [], []
    nodes = data.get("nodes")
    if not isinstance(nodes, list):
        return [], []
    for key in _EDGE_LIST_KEYS:
        edges = data.get(key)
        if isinstance(edges, list):
            return nodes, edges
    return nodes, []


def _first_str(mapping: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, str) and value:
            return value
        if isinstance(value, int) and not isinstance(value, bool) and key in _NODE_ID_KEYS:
            return str(value)
    return None


def _pick(mapping: dict[str, Any], keys: tuple[str, ...]) -> str:
    return next((key for key in keys if key in mapping), keys[0])


def _normalize(raw: str, root: Path) -> str | None:
    """Return a root-relative POSIX path, or None if it escapes the root."""
    text = raw.replace("\\", "/")
    if "\x00" in text or len(text) > 4096:
        return None
    candidate = Path(text)
    if candidate.is_absolute():
        try:
            text = candidate.resolve(strict=False).relative_to(root).as_posix()
        except ValueError:
            return None
    parts = [part for part in PurePosixPath(text).parts if part not in {"", "."}]
    if not parts or ".." in parts:
        return None
    return "/".join(parts)


def _component_for(path: str, roots: list[tuple[str, str]]) -> str | None:
    parent = str(PurePosixPath(path).parent)
    for root, component_id in roots:
        if root == "." or parent == root or parent.startswith(root + "/"):
            return component_id
    return None


def _depth(root: str) -> int:
    return 0 if root == "." else len(PurePosixPath(root).parts)
