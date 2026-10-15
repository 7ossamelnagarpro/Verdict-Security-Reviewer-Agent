"""Conservative, auditable correction of AI-cited Python line numbers.

Only exact source text at one nearby line in the same enclosing function may
move. A profiler-attested source snapshot is mandatory; this never repairs a
security claim or treats a source match as proof of exploitability.
"""

from __future__ import annotations

import ast
import io
import re
import tokenize
from dataclasses import replace
from typing import TYPE_CHECKING

from .models import CandidateAnchor

if TYPE_CHECKING:
    from .context_tools import ContextBroker


MAX_LINE_SHIFT = 2
_NUMBERED = re.compile(r"(\d+):\s*(\S.*)")


def repair_citations(
    *,
    path: str | None,
    start_line: int | None,
    end_line: int | None,
    evidence: tuple[str, ...],
    entry_point: CandidateAnchor | None,
    sensitive_operation: CandidateAnchor | None,
    broker: ContextBroker,
    allowed_paths: set[str],
) -> tuple[tuple[str, ...], CandidateAnchor | None, CandidateAnchor | None, tuple[str, ...]]:
    """Return corrected citations and notes, or the unchanged input.

    The same-function boundary and unique exact match prevent a nearby but
    unrelated statement from being silently used as supporting evidence.
    """
    if broker.hashes is None or not path or path.replace("\\", "/") not in allowed_paths:
        return evidence, entry_point, sensitive_operation, ()
    if not path.casefold().endswith(".py"):
        return evidence, entry_point, sensitive_operation, ()
    try:
        lines = broker._load(path.replace("\\", "/"))
        tree = ast.parse("\n".join(lines), filename=path)
    except (ValueError, SyntaxError):
        return evidence, entry_point, sensitive_operation, ()

    notes: list[str] = []
    repaired_evidence: list[str] = []
    for item in evidence:
        match = _NUMBERED.fullmatch(item.strip())
        if match is None:
            repaired_evidence.append(item)
            continue
        cited_line = int(match.group(1))
        literal = match.group(2).strip()
        if 1 <= cited_line <= len(lines) and lines[cited_line - 1].strip() == literal:
            repaired_evidence.append(item)
            continue
        corrected = _unique_nearby_line(lines, tree, cited_line, (literal,),
                                        start_line=start_line, end_line=end_line)
        if corrected is None:
            repaired_evidence.append(item)
            continue
        repaired_evidence.append(f"{corrected}: {literal}")
        notes.append(f"source_citation_reanchored:evidence:{path}:{cited_line}->{corrected}")

    def repair_anchor(anchor: CandidateAnchor | None, role: str) -> CandidateAnchor | None:
        if anchor is None or anchor.path.replace("\\", "/") != path.replace("\\", "/"):
            return anchor
        if anchor.path.replace("\\", "/") not in allowed_paths:
            return anchor
        cited = tuple(_NUMBERED.sub(r"\2", part.strip()).strip()
                      for part in anchor.code.splitlines() if part.strip())
        if not cited or len(cited) > 5:
            return anchor
        if _physical_lines_equal(lines, anchor.line, cited):
            return anchor
        corrected = _unique_nearby_line(lines, tree, anchor.line, cited,
                                        start_line=None, end_line=None)
        if corrected is None and len(cited) == 1:
            corrected = _unique_nearby_python_tokens(lines, tree, anchor.line, cited[0])
        if corrected is None or corrected == anchor.line:
            return anchor
        notes.append(f"source_citation_reanchored:{role}:{anchor.path}:{anchor.line}->{corrected}")
        return replace(anchor, line=corrected)

    return (tuple(repaired_evidence), repair_anchor(entry_point, "entry_point"),
            repair_anchor(sensitive_operation, "sensitive_operation"), tuple(notes))


def _physical_lines_equal(lines: tuple[str, ...], first: int, cited: tuple[str, ...]) -> bool:
    return (first >= 1 and first + len(cited) - 1 <= len(lines)
            and all(lines[first + offset - 1].strip() == value
                    for offset, value in enumerate(cited)))


def _function_bounds(tree: ast.Module, cited_line: int) -> tuple[int, int] | None:
    matches: list[tuple[int, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        first = min((decorator.lineno for decorator in node.decorator_list), default=node.lineno)
        last = getattr(node, "end_lineno", node.lineno)
        if first <= cited_line <= last:
            matches.append((first, last))
    return min(matches, key=lambda bounds: bounds[1] - bounds[0]) if matches else None


def _unique_nearby_line(
    lines: tuple[str, ...], tree: ast.Module, cited_line: int, cited: tuple[str, ...],
    *, start_line: int | None, end_line: int | None,
) -> int | None:
    bounds = _function_bounds(tree, cited_line)
    if bounds is None:
        return None
    first = max(bounds[0], cited_line - MAX_LINE_SHIFT)
    last = min(bounds[1], cited_line + MAX_LINE_SHIFT)
    matches = [line for line in range(first, last + 1)
               if (start_line is None or line >= start_line)
               and (end_line is None or line + len(cited) - 1 <= end_line)
               and _function_bounds(tree, line) == bounds
               and _function_bounds(tree, line + len(cited) - 1) == bounds
               and _physical_lines_equal(lines, line, cited)]
    return matches[0] if len(matches) == 1 else None


def _python_tokens(source: str) -> tuple[tuple[int, str], ...] | None:
    ignored = {tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT,
               tokenize.ENDMARKER, tokenize.COMMENT, tokenize.ENCODING}
    try:
        return tuple((item.type, item.string)
                     for item in tokenize.generate_tokens(io.StringIO(source).readline)
                     if item.type not in ignored)
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return None


def _unique_nearby_python_tokens(
    lines: tuple[str, ...], tree: ast.Module, cited_line: int, code: str,
) -> int | None:
    """Match one complete Python statement, allowing only layout differences."""
    expected = _python_tokens(code)
    bounds = _function_bounds(tree, cited_line)
    if bounds is None or expected is None or len(expected) < 3:
        return None
    first = max(bounds[0], cited_line - MAX_LINE_SHIFT)
    last = min(bounds[1], cited_line + MAX_LINE_SHIFT)
    matches = [start for start in range(first, last + 1)
               if _function_bounds(tree, start) == bounds
               and any(_function_bounds(tree, start + span - 1) == bounds
                       and _python_tokens("\n".join(lines[start - 1:start - 1 + span])) == expected
                       for span in range(1, min(5, bounds[1] - start + 1) + 1))]
    return matches[0] if len(matches) == 1 else None
