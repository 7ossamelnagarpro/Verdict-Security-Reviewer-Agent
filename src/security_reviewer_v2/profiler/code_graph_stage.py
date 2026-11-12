"""Build the code-knowledge graph that the profiler ingests (two-pass flow).

Why this module exists
----------------------
``profiler.code_graph`` only *reads* a ``graph.json``; the profiler never builds it and the scanner
orchestrator skips the planned ``code_graph`` enrichment task (there is no adapter for it). Nothing in the
pipeline therefore produced the graph, so hotspots never reached prioritization or AI Discovery.

This stage closes that gap *outside* the scanner orchestrator, as the existing design documents require:

1. If ``GRAPHIFY_COMMAND`` is set (or ``--graphify-command`` is passed), run Graphify with it. The command is a
   template split with ``shlex`` and executed **without a shell**; ``{project}`` and ``{output}`` are replaced.
   Graphify's headless flags are not verified in the registry, so none are hard-coded here.
2. Otherwise (or if Graphify fails / writes nothing usable) fall back to a deterministic built-in graph of
   import edges between the profiled source files. The fallback is reported as ``engine="builtin"`` so reports
   never claim Graphify produced it.

The graph file is always written *outside* the scanned project, never changes project files, and is treated by
``load_code_graph`` as untrusted input (paths only, counts only).
"""

from __future__ import annotations

import ast
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from .models import FileCategory, ProfileResult

GRAPH_FILENAME = "graph.json"
MAX_FILES = 20_000
MAX_FILE_BYTES = 1_000_000
GRAPHIFY_TIMEOUT_SECONDS = 900

_JS_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")
_JS_IMPORT = re.compile(
    r"""(?:import\s+(?:[\w*{}\s,$]+\s+from\s+)?|export\s+[\w*{}\s,$]+\s+from\s+|require\s*\(\s*|import\s*\(\s*)['"]([^'"\n]+)['"]"""
)


@dataclass(frozen=True)
class CodeGraphBuild:
    status: str                      # built | failed | disabled
    engine: str | None               # graphify | builtin | None
    path: Path | None
    warnings: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, object]:
        return {"status": self.status, "engine": self.engine,
                "path": str(self.path) if self.path else None, "warnings": list(self.warnings)}


def build_code_graph(
    project_root: Path,
    profile: ProfileResult,
    output_dir: Path,
    *,
    graphify_command: str | None = None,
    allow_builtin_fallback: bool = True,
) -> CodeGraphBuild:
    """Produce ``<output_dir>/graph.json`` for the profiled project. Never raises for graph problems."""
    root = project_root.resolve()
    output_dir = output_dir.resolve()
    if output_dir == root or output_dir.is_relative_to(root):
        return CodeGraphBuild("failed", None, None, ("Code-graph output must be outside the scanned project.",))
    output_dir.mkdir(parents=True, exist_ok=True)
    target = output_dir / GRAPH_FILENAME
    warnings: list[str] = []

    command = graphify_command if graphify_command is not None else os.environ.get("GRAPHIFY_COMMAND", "")
    if command.strip():
        built, note = _run_graphify(command, root, output_dir, target)
        if built:
            return CodeGraphBuild("built", "graphify", target, tuple(warnings))
        warnings.append(note)
    else:
        warnings.append("GRAPHIFY_COMMAND is not set; Graphify was not executed.")

    if not allow_builtin_fallback:
        return CodeGraphBuild("failed", None, None, tuple(warnings))
    try:
        graph = build_builtin_graph(root, profile)
        target.write_text(json.dumps(graph, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (OSError, ValueError) as error:
        warnings.append(f"Built-in code graph failed: {type(error).__name__}.")
        return CodeGraphBuild("failed", None, None, tuple(warnings))
    warnings.append("Using the deterministic built-in import graph (not Graphify).")
    return CodeGraphBuild("built", "builtin", target, tuple(warnings))


# --------------------------------------------------------------------------- Graphify (external, optional)
def _run_graphify(template: str, root: Path, output_dir: Path, target: Path) -> tuple[bool, str]:
    try:
        parts = shlex.split(template)
    except ValueError:
        return False, "GRAPHIFY_COMMAND could not be parsed."
    if not parts:
        return False, "GRAPHIFY_COMMAND is empty."
    argv = [part.replace("{project}", str(root)).replace("{output}", str(target)) for part in parts]
    executable = shutil.which(argv[0]) or (argv[0] if Path(argv[0]).is_file() else None)
    if executable is None:
        return False, f"Graphify executable was not found: {argv[0]}"
    argv[0] = executable
    before = _tree_stamp(root)
    # Run from a scratch directory so a tool that writes ``graphify-out/`` into its cwd cannot touch the project.
    with tempfile.TemporaryDirectory(prefix="verdict-graphify-") as scratch:
        try:
            completed = subprocess.run(argv, cwd=scratch, capture_output=True, text=True, encoding="utf-8",
                                       errors="replace", timeout=GRAPHIFY_TIMEOUT_SECONDS, check=False,
                                       env=_graphify_environment())
        except (OSError, subprocess.TimeoutExpired) as error:
            return False, f"Graphify did not finish: {type(error).__name__}."
        if completed.returncode != 0:
            return False, f"Graphify exited with code {completed.returncode}."
        produced = next((candidate for candidate in (target, Path(scratch) / "graphify-out" / GRAPH_FILENAME,
                                                     Path(scratch) / GRAPH_FILENAME) if candidate.is_file()), None)
        if produced is None:
            return False, "Graphify finished but produced no graph.json."
        if produced != target:
            shutil.copyfile(produced, target)
    if _tree_stamp(root) != before:
        target.unlink(missing_ok=True)
        return False, "Graphify modified the scanned project; its graph was discarded."
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        target.unlink(missing_ok=True)
        return False, "Graphify wrote an unreadable graph.json."
    if not isinstance(data, dict) or not isinstance(data.get("nodes"), list) or not data["nodes"]:
        target.unlink(missing_ok=True)
        return False, "Graphify graph.json has no nodes."
    return True, ""


def _graphify_environment() -> dict[str, str]:
    """Do not forward provider keys to a third-party CLI."""
    kept = {"PATH", "Path", "HOME", "USERPROFILE", "SYSTEMROOT", "TEMP", "TMP", "LANG", "LC_ALL", "VIRTUAL_ENV"}
    return {name: value for name, value in os.environ.items() if name in kept}


def _tree_stamp(root: Path) -> tuple[int, int]:
    """Cheap change detector (file count + newest mtime) over the project, ignoring VCS/dependency folders."""
    count = newest = 0
    skip = {".git", "node_modules", ".venv", "__pycache__"}
    for current, directories, files in os.walk(root):
        directories[:] = [name for name in directories if name not in skip]
        for name in files:
            try:
                stat = os.stat(os.path.join(current, name))
            except OSError:
                continue
            count += 1
            newest = max(newest, stat.st_mtime_ns)
    return count, newest


# --------------------------------------------------------------------------- built-in deterministic graph
def build_builtin_graph(root: Path, profile: ProfileResult) -> dict[str, object]:
    """Node-link graph of import edges between profiled source files (``nodes`` + ``edges`` with ``file``)."""
    sources = sorted(item.path for item in profile.profile.inventory if item.category is FileCategory.SOURCE)
    if len(sources) > MAX_FILES:
        sources = sources[:MAX_FILES]
    known = set(sources)
    py_index = _python_module_index(sources)
    edges: set[tuple[str, str]] = set()
    for relative in sources:
        text = _read(root, relative)
        if text is None:
            continue
        if relative.endswith(".py"):
            targets = _python_imports(text, relative, py_index, known)
        elif relative.endswith(_JS_SUFFIXES):
            targets = _js_imports(text, relative, known)
        else:
            targets = set()
        edges.update((relative, target) for target in targets if target != relative)
    return {
        "directed": True,
        "generator": "verdict-builtin-import-graph",
        "nodes": [{"id": path, "file": path, "kind": "file"} for path in sources],
        "edges": [{"source": a, "target": b, "relation": "imports"} for a, b in sorted(edges)],
    }


def _read(root: Path, relative: str) -> str | None:
    path = (root / relative)
    try:
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(root) or resolved.is_symlink() or resolved.stat().st_size > MAX_FILE_BYTES:
            return None
        return resolved.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _python_module_index(sources: list[str]) -> dict[str, str | None]:
    """Dotted-suffix -> file. A suffix shared by several files maps to ``None`` (ambiguous; never guessed)."""
    index: dict[str, str | None] = {}
    for relative in sources:
        if not relative.endswith(".py"):
            continue
        parts = list(PurePosixPath(relative).with_suffix("").parts)
        if parts and parts[-1] == "__init__":
            parts = parts[:-1]
        for start in range(len(parts)):
            name = ".".join(parts[start:])
            if not name:
                continue
            index[name] = relative if index.get(name, relative) == relative else None
    return index


def _python_imports(text: str, relative: str, index: dict[str, str | None], known: set[str]) -> set[str]:
    try:
        tree = ast.parse(text, filename=relative)
    except (SyntaxError, ValueError):
        return set()
    package = list(PurePosixPath(relative).parent.parts)
    found: set[str] = set()

    def add(dotted: str) -> bool:
        match = index.get(dotted)
        if match:
            found.add(match)
            return True
        return False

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                _longest_prefix(alias.name, add)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base_parts = package[: max(0, len(package) - (node.level - 1))]
                module = ".".join([*base_parts, *(node.module.split(".") if node.module else [])])
                for alias in node.names:
                    if not add(f"{module}.{alias.name}" if module else alias.name):
                        _relative_candidate(module, known, found)
            elif node.module:
                hit = _longest_prefix(node.module, add)
                for alias in node.names:
                    add(f"{node.module}.{alias.name}")
                _ = hit
    return found


def _longest_prefix(dotted: str, add) -> bool:
    parts = dotted.split(".")
    for end in range(len(parts), 0, -1):
        if add(".".join(parts[:end])):
            return True
    return False


def _relative_candidate(module: str, known: set[str], found: set[str]) -> None:
    base = module.replace(".", "/")
    for candidate in (f"{base}.py", f"{base}/__init__.py"):
        if candidate in known:
            found.add(candidate)
            return


def _js_imports(text: str, relative: str, known: set[str]) -> set[str]:
    found: set[str] = set()
    directory = PurePosixPath(relative).parent
    for match in _JS_IMPORT.finditer(text):
        spec = match.group(1)
        if not spec.startswith("."):
            continue
        joined = PurePosixPath(os.path.normpath(str(directory / spec))).as_posix()
        if joined.startswith(".."):
            continue
        candidates = [joined, *(joined + suffix for suffix in _JS_SUFFIXES),
                      *(f"{joined}/index{suffix}" for suffix in _JS_SUFFIXES)]
        hit = next((item for item in candidates if item in known), None)
        if hit:
            found.add(hit)
    return found
