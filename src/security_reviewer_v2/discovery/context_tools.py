"""Read-only, bounded context requests made during AI discovery."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any, Callable

from .models import ContextExchange, DiscoveryConfig
from .scope import _read_source, _source_paths


class ContextBroker:
    """Resolve explicit source windows or Python symbols from the profiled root."""

    def __init__(
        self,
        project_root: str | Path,
        config: DiscoveryConfig,
        profile_artifact: dict[str, Any] | None,
        redact: Callable[[str], str],
    ) -> None:
        self.root = Path(project_root).resolve(strict=True)
        self.config = config
        self.redact = redact
        paths, hashes, inventory_gaps = _source_paths(self.root, profile_artifact)
        self.paths = tuple(paths)
        self.allowed = set(paths)
        self.hashes = hashes
        self.inventory_gaps = inventory_gaps
        self.cache: dict[str, tuple[str, ...]] = {}
        self.bytes_read = 0
        self.seen_requests: set[tuple[int, str | None, str | None, int | None, int | None]] = set()

    def fetch(self, raw: Any, *, batch_index: int, round_index: int) -> ContextExchange:
        if not isinstance(raw, dict):
            return self._result(batch_index, round_index, None, None, None, None, "rejected", None, None, None, None, "Request must be an object.")
        path = raw.get("path") if isinstance(raw.get("path"), str) else None
        symbol = raw.get("symbol") if isinstance(raw.get("symbol"), str) else None
        start = raw.get("start_line") if type(raw.get("start_line")) is int else None
        end = raw.get("end_line") if type(raw.get("end_line")) is int else None
        if path is not None and len(path) > 500:
            return self._result(batch_index, round_index, path[:500], symbol, start, end, "rejected", None, None, None, None, "Requested path is too long.")
        path = path.replace("\\", "/").strip() if path else None
        symbol = symbol.strip()[:160] if symbol else None
        requested_path, requested_start, requested_end = path, start, end
        key = (batch_index, path, symbol, start, end)
        if key in self.seen_requests:
            return self._result(batch_index, round_index, path, symbol, start, end, "rejected", None, None, None, None, "Repeated context request.")
        self.seen_requests.add(key)
        if not symbol and start is None:
            return self._result(batch_index, round_index, path, symbol, start, end, "rejected", None, None, None, None, "Provide a Python symbol or a start line.")
        if path is not None and path not in self.allowed:
            return self._result(batch_index, round_index, path, symbol, start, end, "rejected", None, None, None, None, "Path is outside the profiled source inventory.")
        if path is None:
            if symbol is None:
                return self._result(batch_index, round_index, path, symbol, start, end, "rejected", None, None, None, None, "Path is required for a line request.")
            matches: list[tuple[str, int, int]] = []
            for candidate in self.paths[:self.config.max_files_considered]:
                if not candidate.endswith(".py"):
                    continue
                try:
                    lines = self._load(candidate)
                except ValueError:
                    continue
                matches.extend((candidate, first, last) for first, last in _python_symbols(lines, symbol))
                if len(matches) > 1:
                    break
            if len(matches) != 1:
                note = "Symbol was not found uniquely within the bounded Python source inventory."
                return self._result(batch_index, round_index, path, symbol, start, end, "unavailable", None, None, None, None, note)
            path, start, end = matches[0]
        try:
            lines = self._load(path)
        except ValueError as error:
            return self._result(batch_index, round_index, path, symbol, start, end, "unavailable", None, None, None, None, str(error))
        relocated_from: str | None = None
        if symbol is not None and raw.get("path") is not None:
            matches = _python_symbols(lines, symbol) if path.endswith(".py") else []
            if len(matches) != 1:
                # The model often names the right function in the wrong file (a caller instead of the definition).
                # Fall back to one bounded inventory search; accept only a single, unambiguous definition.
                found = self._find_symbol_elsewhere(symbol, exclude=path) if not matches else None
                if found is None:
                    return self._result(batch_index, round_index, path, symbol, start, end, "unavailable", None, None, None, None, "Symbol is absent or ambiguous in the requested Python file.")
                relocated_from = path
                path, start, end = found
                try:
                    lines = self._load(path)
                except ValueError as error:
                    return self._result(batch_index, round_index, requested_path, symbol, requested_start, requested_end, "unavailable", None, None, None, None, str(error))
            else:
                start, end = matches[0]
        if start is None or start < 1 or start > len(lines):
            return self._result(batch_index, round_index, path, symbol, start, end, "rejected", None, None, None, None, "Start line is outside the source file.")
        if end is None:
            end = min(len(lines), start + self.config.max_context_lines - 1)
        if end < start:
            return self._result(batch_index, round_index, path, symbol, start, end, "rejected", None, None, None, None, "End line precedes start line.")
        bounded_end = min(end, len(lines), start + self.config.max_context_lines - 1)
        snippet = "\n".join(f"{number}: {lines[number - 1]}" for number in range(start, bounded_end + 1))
        redacted = self.redact(snippet)
        truncated = bounded_end < end or len(redacted) > self.config.max_context_response_chars
        code = redacted[:self.config.max_context_response_chars]
        notes = []
        if relocated_from:
            notes.append(f"Symbol is not defined in {relocated_from}; resolved its single definition in {path}.")
        if truncated:
            notes.append("Context was truncated by line or character budget.")
        note = " ".join(notes) or None
        return self._result(batch_index, round_index, requested_path, symbol, requested_start, requested_end, "collected", path, start, bounded_end, code, note)

    def _find_symbol_elsewhere(self, symbol: str, *, exclude: str) -> tuple[str, int, int] | None:
        """The one Python definition of ``symbol`` in the profiled inventory outside ``exclude``, else None."""
        found: list[tuple[str, int, int]] = []
        for candidate in self.paths[:self.config.max_files_considered]:
            if candidate == exclude or not candidate.endswith(".py"):
                continue
            try:
                lines = self._load(candidate)
            except ValueError:
                continue
            found.extend((candidate, first, last) for first, last in _python_symbols(lines, symbol))
            if len(found) > 1:
                return None
        return found[0] if found else None

    def _load(self, path: str) -> tuple[str, ...]:
        if path in self.cache:
            return self.cache[path]
        lines, size = _read_source(self.root, path, self.hashes, self.config, self.bytes_read)
        if self.bytes_read + size > self.config.max_enrichment_total_bytes:
            raise ValueError("On-demand context byte budget exceeded.")
        self.bytes_read += size
        self.cache[path] = lines
        return lines

    @staticmethod
    def _result(
        batch_index: int, round_index: int, requested_path: str | None,
        symbol: str | None, requested_start: int | None, requested_end: int | None,
        status: str, resolved_path: str | None, resolved_start: int | None,
        resolved_end: int | None, code: str | None, note: str | None,
    ) -> ContextExchange:
        return ContextExchange(batch_index, round_index, requested_path, symbol,
                               requested_start, requested_end, status, resolved_path,
                               resolved_start, resolved_end, code, note)


def _python_symbols(lines: tuple[str, ...], wanted: str) -> list[tuple[int, int]]:
    try:
        tree = ast.parse("\n".join(lines))
    except (SyntaxError, ValueError):
        return []
    matches: list[tuple[int, int]] = []

    def visit(node: ast.AST, parents: tuple[str, ...]) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                qualified = ".".join((*parents, child.name))
                if wanted in {child.name, qualified}:
                    matches.append((child.lineno, getattr(child, "end_lineno", child.lineno)))
                visit(child, (*parents, child.name))
            else:
                visit(child, parents)

    visit(tree, ())
    return matches
