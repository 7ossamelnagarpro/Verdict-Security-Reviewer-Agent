"""Collect bounded source evidence for merged scanner findings."""

from __future__ import annotations

import ast
import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from security_reviewer_v2.normalization.merge_models import MergedFinding, MergeResult
from security_reviewer_v2.normalization.models import FindingLocation, UnifiedFinding

from .models import (
    CONTEXT_SCHEMA_VERSION,
    ContextPolicy,
    ContextResult,
    ContextStatus,
    ContextSummary,
    EvidenceContext,
    FindingContext,
    SourceExcerpt,
    SymbolContext,
)


class ContextCollectionError(ValueError):
    """Raised when context collection cannot safely start."""


@dataclass(frozen=True)
class _LoadedFile:
    relative_path: str
    lines: tuple[str, ...]
    digest: str
    size: int
    python_tree: ast.Module | None


class _SourceReader:
    def __init__(
        self, root: Path, policy: ContextPolicy, profile_artifact: dict[str, Any] | None
    ) -> None:
        self.root = root
        self.policy = policy
        self.cache: dict[str, _LoadedFile] = {}
        self.bytes_read = 0
        self.expected_hashes: dict[str, str] | None = None
        self.index: tuple[str, ...] | None = None
        self.runtime_routes: tuple[tuple[str, str | None, str, int], ...] | None = None
        if profile_artifact is not None:
            snapshot = profile_artifact.get("project_snapshot")
            profile = profile_artifact.get("profile")
            inventory = profile.get("inventory") if isinstance(profile, dict) else None
            if not isinstance(snapshot, dict) or not isinstance(inventory, list):
                raise ContextCollectionError("profile_snapshot_unavailable")
            if snapshot.get("root_path") != os.path.normcase(str(root)):
                raise ContextCollectionError("profile_root_mismatch")
            records = snapshot.get("files")
            if not isinstance(records, list):
                raise ContextCollectionError("profile_file_hashes_unavailable")
            try:
                self.expected_hashes = {
                    str(item["path"]): str(item["sha256"]) for item in records
                }
                self.index = tuple(sorted({str(item["path"]) for item in inventory}))
            except (KeyError, TypeError) as error:
                raise ContextCollectionError("invalid_profile_inventory") from error
            if set(self.index) != set(self.expected_hashes):
                raise ContextCollectionError("profile_inventory_hash_mismatch")

    def _paths(self) -> tuple[str, ...]:
        if self.index is None:
            # Compatibility for standalone calls without a saved profile. Do
            # one bounded walk, never an rglob for every unresolved finding.
            paths: list[str] = []
            for directory, names, files in os.walk(self.root, followlinks=False):
                names[:] = sorted(
                    name for name in names if not (Path(directory) / name).is_symlink()
                )
                for name in sorted(files):
                    path = Path(directory) / name
                    if not path.is_symlink():
                        paths.append(path.relative_to(self.root).as_posix())
                    if len(paths) > 100_000:
                        raise ContextCollectionError(
                            "fallback_file_index_limit_exceeded"
                        )
            self.index = tuple(paths)
        return self.index

    def load(self, raw_path: str) -> _LoadedFile:
        relative = _normal_relative_path(raw_path)
        if relative in self.cache:
            return self.cache[relative]
        lexical = self.root.joinpath(*PurePosixPath(relative).parts)
        if not lexical.exists():
            # Some scanners emit paths relative to their configured source
            # root (for example ``routes/login.ts`` becomes ``login.ts``).
            # Resolve only a unique in-root suffix match; ambiguity remains
            # unavailable rather than guessing between files.
            matches = [
                self.root.joinpath(*PurePosixPath(path).parts)
                for path in self._paths()
                if path == relative or path.endswith("/" + relative)
            ]
            if len(matches) == 1:
                lexical = matches[0]
        if not self.policy.follow_symlinks and _contains_symlink(self.root, lexical):
            raise ContextCollectionError(f"symlink_skipped:{relative}")
        try:
            resolved = lexical.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise ContextCollectionError(f"source_unavailable:{relative}") from error
        try:
            resolved.relative_to(self.root)
        except ValueError as error:
            raise ContextCollectionError(f"path_outside_project:{relative}") from error
        if not resolved.is_file():
            raise ContextCollectionError(f"not_a_file:{relative}")
        try:
            size = resolved.stat().st_size
        except OSError as error:
            raise ContextCollectionError(f"metadata_unavailable:{relative}") from error
        if size > self.policy.max_file_bytes:
            raise ContextCollectionError(f"file_limit_exceeded:{relative}:{size}")
        if self.bytes_read + size > self.policy.max_total_bytes:
            raise ContextCollectionError(f"total_read_limit_exceeded:{relative}")
        try:
            data = resolved.read_bytes()
        except OSError as error:
            raise ContextCollectionError(f"read_failed:{relative}") from error
        if b"\x00" in data:
            raise ContextCollectionError(f"binary_file_skipped:{relative}")
        try:
            source = data.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ContextCollectionError(f"non_utf8_file_skipped:{relative}") from error
        actual_relative = resolved.relative_to(self.root).as_posix()
        digest = hashlib.sha256(data).hexdigest()
        if self.expected_hashes is not None:
            expected = self.expected_hashes.get(actual_relative)
            if expected is None:
                raise ContextCollectionError(f"source_not_in_profile:{actual_relative}")
            if expected != digest:
                raise ContextCollectionError(
                    f"source_changed_since_profile:{actual_relative}"
                )
        tree = None
        if actual_relative.casefold().endswith(".py"):
            try:
                tree = ast.parse(source, filename=actual_relative)
            except (SyntaxError, ValueError):
                tree = None
        loaded = _LoadedFile(
            relative_path=actual_relative,
            lines=tuple(source.splitlines()),
            digest=digest,
            size=len(data),
            python_tree=tree,
        )
        self.cache[relative] = loaded
        self.cache.setdefault(actual_relative, loaded)
        self.bytes_read += len(data)
        return loaded


def collect_context(
    merged: MergeResult,
    *,
    project_root: str | Path,
    policy: ContextPolicy | None = None,
    profile_artifact: dict[str, Any] | None = None,
) -> ContextResult:
    """Create deterministic, bounded context without executing target code."""
    selected_policy = policy or ContextPolicy()
    selected_policy.validate()
    root = Path(project_root)
    if not root.exists() or not root.is_dir():
        raise ContextCollectionError(
            f"Project root is not a readable directory: {root}"
        )
    try:
        root = root.resolve(strict=True)
        next(root.iterdir(), None)
    except OSError as error:
        raise ContextCollectionError(f"Project root is not readable: {root}") from error

    reader = _SourceReader(root, selected_policy, profile_artifact)
    contexts: list[FindingContext] = []
    global_warnings: list[str] = []
    gaps: list[str] = list(merged.coverage_gaps)
    evidence_count = 0
    excerpts_count = 0
    unavailable_count = 0

    for finding in merged.findings:
        context = _finding_context(finding, reader, selected_policy)
        contexts.append(context)
        items = (
            context.primary,
            *context.additional_primaries,
            *context.code_flow,
            *context.related,
        )
        evidence_count += len(items)
        excerpts_count += sum(item.excerpt is not None for item in items)
        unavailable_count += sum(item.excerpt is None for item in items)
        global_warnings.extend(context.warnings)
        if context.primary.excerpt is None:
            gaps.append(
                f"{finding.merged_finding_id}: primary source context is unavailable."
            )
        for item in context.additional_primaries:
            if item.excerpt is None:
                gaps.append(
                    f"{finding.merged_finding_id}: source {item.source_finding_id} primary context is unavailable."
                )

    if not merged.findings:
        status = {
            "complete": ContextStatus.COMPLETE,
            "partial": ContextStatus.PARTIAL,
            "failed": ContextStatus.FAILED,
        }[merged.status.value]
    elif all(
        item.primary.excerpt is None
        and all(source.excerpt is None for source in item.additional_primaries)
        for item in contexts
    ):
        status = ContextStatus.FAILED
    elif unavailable_count or merged.status.value != "complete":
        status = ContextStatus.PARTIAL
    else:
        status = ContextStatus.COMPLETE
    return ContextResult(
        schema_version=CONTEXT_SCHEMA_VERSION,
        status=status,
        project_root=root.as_posix(),
        findings=tuple(contexts),
        warnings=tuple(sorted(set(global_warnings))),
        coverage_gaps=tuple(sorted(set(gaps))),
        summary=ContextSummary(
            input_findings=len(merged.findings),
            contexts_created=len(contexts),
            evidence_locations=evidence_count,
            excerpts_collected=excerpts_count,
            files_read=len({item.relative_path for item in reader.cache.values()}),
            bytes_read=reader.bytes_read,
            unavailable_locations=unavailable_count,
        ),
    )


def _finding_context(
    finding: MergedFinding,
    reader: _SourceReader,
    policy: ContextPolicy,
) -> FindingContext:
    canonical = finding.canonical_finding
    primary_location = (
        _runtime_source_location(canonical, reader) or finding.primary_location
    )
    primary = _collect_evidence(
        reader,
        policy,
        evidence_type="primary",
        scanner_id=canonical.scanner.scanner_id,
        rule_id=canonical.rule_id,
        location=primary_location,
        message=canonical.message,
        source_finding_id=canonical.finding_id,
    )
    additional_primaries = tuple(
        _collect_evidence(
            reader,
            policy,
            evidence_type="primary",
            scanner_id=source.scanner.scanner_id,
            rule_id=source.rule_id,
            location=source.primary_location,
            message=source.message,
            source_finding_id=source.finding_id,
        )
        for source in finding.source_findings
        if source != canonical
    )
    flow_items: list[EvidenceContext] = []
    related_items: list[EvidenceContext] = []
    for source in finding.source_findings:
        flow_items.extend(_flow_contexts(source, reader, policy))
        for related in source.related_locations:
            related_items.append(
                _collect_evidence(
                    reader,
                    policy,
                    evidence_type="related",
                    scanner_id=source.scanner.scanner_id,
                    rule_id=source.rule_id,
                    location=related.location,
                    message=related.message,
                )
            )
    flow = tuple(sorted(_deduplicate(flow_items), key=_evidence_sort_key))
    related = tuple(sorted(_deduplicate(related_items), key=_evidence_sort_key))
    warnings = tuple(
        sorted(
            {
                item.warning
                for item in (primary, *additional_primaries, *flow, *related)
                if item.warning is not None
            }
        )
    )
    return FindingContext(
        merged_finding_id=finding.merged_finding_id,
        title=canonical.title,
        severity=finding.severity.value,
        confidence=finding.confidence.value,
        cwes=finding.cwes,
        scanners=finding.scanners,
        primary=primary,
        code_flow=flow,
        related=related,
        warnings=warnings,
        additional_primaries=additional_primaries,
    )


def _runtime_source_location(
    finding: UnifiedFinding, reader: _SourceReader
) -> FindingLocation | None:
    """Resolve a unique Python HTTP route to source without importing target code.

    The original HTTP location remains in the normalized finding. This only
    supplies source context to review when an exact route-template match exists.
    """
    if "dast" not in finding.categories:
        return None
    routes = _runtime_routes(reader)
    if finding.rule_id == "web.cors-reflection":
        matches = [
            (path, line) for route, _, path, line in routes if route == "@after_request"
        ]
    else:
        path = finding.primary_location.path.split("?", 1)[0]
        # Runtime contracts may retain capture placeholders rather than values.
        path = re.sub(r"\{\{[A-Za-z_][A-Za-z0-9_]*\}\}", "1", path)
        method = (finding.runtime_evidence or {}).get("method")
        matches = [
            (source_path, line)
            for route, route_method, source_path, line in routes
            if route != "@after_request"
            and (not method or not route_method or route_method == method)
            and re.fullmatch(_route_pattern(route), path)
        ]
    if len(matches) != 1:
        return None
    source_path, line = matches[0]
    return FindingLocation(source_path, line, None, line, None)


def _route_pattern(route: str) -> str:
    parts = re.split(r"(\{[^{}]+\}|<[^<>]+>)", route)
    return "".join(
        ".+"
        if part.startswith("<path:")
        else "[^/]+"
        if part.startswith(("{", "<"))
        else re.escape(part)
        for part in parts
    )


def _runtime_routes(
    reader: _SourceReader,
) -> tuple[tuple[str, str | None, str, int], ...]:
    if reader.runtime_routes is not None:
        return reader.runtime_routes
    routes: list[tuple[str, str | None, str, int]] = []
    inspected = 0
    for path in reader._paths():
        if not path.endswith(".py") or any(
            part in {"tests", ".venv", "venv", "site-packages"}
            for part in PurePosixPath(path).parts
        ):
            continue
        if inspected >= 100 or reader.bytes_read >= 1_000_000:
            break
        inspected += 1
        try:
            loaded = reader.load(path)
        except ContextCollectionError:
            continue
        if loaded.python_tree is None:
            continue
        for node in ast.walk(loaded.python_tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if (
                    isinstance(decorator, ast.Attribute)
                    and decorator.attr == "after_request"
                ):
                    routes.append(
                        ("@after_request", None, loaded.relative_path, node.lineno)
                    )
                if not isinstance(decorator, ast.Call) or not isinstance(
                    decorator.func, ast.Attribute
                ):
                    continue
                verb = decorator.func.attr.lower()
                if (
                    verb
                    not in {"route", "get", "post", "put", "patch", "delete", "head"}
                    or not decorator.args
                ):
                    continue
                route = decorator.args[0]
                if (
                    isinstance(route, ast.Constant)
                    and isinstance(route.value, str)
                    and route.value.startswith("/")
                ):
                    routes.append(
                        (
                            route.value,
                            None if verb == "route" else verb.upper(),
                            loaded.relative_path,
                            node.lineno,
                        )
                    )
    reader.runtime_routes = tuple(routes)
    return reader.runtime_routes


def _flow_contexts(
    finding: UnifiedFinding,
    reader: _SourceReader,
    policy: ContextPolicy,
) -> list[EvidenceContext]:
    return [
        _collect_evidence(
            reader,
            policy,
            evidence_type="code_flow",
            scanner_id=finding.scanner.scanner_id,
            rule_id=finding.rule_id,
            location=step.location,
            message=step.message,
            flow_index=step.flow_index,
            thread_index=step.thread_index,
            step_index=step.step_index,
        )
        for step in finding.code_flow
    ]


def _collect_evidence(
    reader: _SourceReader,
    policy: ContextPolicy,
    *,
    evidence_type: str,
    scanner_id: str,
    rule_id: str,
    location: FindingLocation,
    message: str | None,
    flow_index: int | None = None,
    thread_index: int | None = None,
    step_index: int | None = None,
    source_finding_id: str | None = None,
) -> EvidenceContext:
    try:
        loaded = reader.load(location.path)
        if location.start_line is None:
            # Dependency, secret, and configuration findings may identify a
            # file but not a source line. Preserve useful bounded evidence
            # instead of treating a valid file-level finding as unavailable.
            end = min(len(loaded.lines), policy.max_symbol_lines)
            excerpt = _excerpt(loaded, 1, max(1, end))
            return EvidenceContext(
                evidence_type=evidence_type,
                scanner_id=scanner_id,
                rule_id=rule_id,
                location=location,
                message=message,
                flow_index=flow_index,
                thread_index=thread_index,
                step_index=step_index,
                excerpt=excerpt,
                enclosing_symbol=None,
                collection_status="file_context",
                warning=None,
                source_finding_id=source_finding_id,
            )
        if location.start_line < 1:
            raise ContextCollectionError(
                f"invalid_line:{loaded.relative_path}:{location.start_line}"
            )
        if location.start_line > max(1, len(loaded.lines)):
            raise ContextCollectionError(
                f"line_out_of_range:{loaded.relative_path}:{location.start_line}"
            )
        excerpt = _window_excerpt(loaded, location.start_line, policy)
        symbol = _python_symbol(loaded, location.start_line, policy)
        return EvidenceContext(
            evidence_type=evidence_type,
            scanner_id=scanner_id,
            rule_id=rule_id,
            location=location,
            message=message,
            flow_index=flow_index,
            thread_index=thread_index,
            step_index=step_index,
            excerpt=excerpt,
            enclosing_symbol=symbol,
            collection_status="collected",
            warning=None,
            source_finding_id=source_finding_id,
        )
    except ContextCollectionError as error:
        warning = str(error)
        return EvidenceContext(
            evidence_type=evidence_type,
            scanner_id=scanner_id,
            rule_id=rule_id,
            location=location,
            message=message,
            flow_index=flow_index,
            thread_index=thread_index,
            step_index=step_index,
            excerpt=None,
            enclosing_symbol=None,
            collection_status="unavailable",
            warning=warning,
            source_finding_id=source_finding_id,
        )


def _window_excerpt(
    loaded: _LoadedFile,
    line: int,
    policy: ContextPolicy,
) -> SourceExcerpt:
    start = max(1, line - policy.window_before)
    end = min(len(loaded.lines), line + policy.window_after)
    return _excerpt(loaded, start, end)


def _excerpt(loaded: _LoadedFile, start: int, end: int) -> SourceExcerpt:
    width = len(str(end))
    code = "\n".join(
        f"{number:>{width}} | {loaded.lines[number - 1]}"
        for number in range(start, end + 1)
    )
    return SourceExcerpt(
        path=loaded.relative_path,
        start_line=start,
        end_line=end,
        code=code,
        content_sha256=loaded.digest,
    )


def _python_symbol(
    loaded: _LoadedFile,
    line: int,
    policy: ContextPolicy,
) -> SymbolContext | None:
    if loaded.python_tree is None:
        return None
    candidates: list[tuple[ast.AST, tuple[str, ...]]] = []

    def visit(node: ast.AST, parents: tuple[str, ...]) -> None:
        name = getattr(node, "name", None)
        current = parents
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(node, "end_lineno", node.lineno)
            if node.lineno <= line <= end:
                candidates.append((node, parents))
            current = (*parents, str(name))
        for child in ast.iter_child_nodes(node):
            visit(child, current)

    visit(loaded.python_tree, ())
    if not candidates:
        return None
    node, parents = min(
        candidates,
        key=lambda item: (
            getattr(item[0], "end_lineno", item[0].lineno) - item[0].lineno,
            -len(item[1]),
        ),
    )
    node_end = getattr(node, "end_lineno", node.lineno)
    excerpt_end = min(node_end, node.lineno + policy.max_symbol_lines - 1)
    kind = "class" if isinstance(node, ast.ClassDef) else "function"
    return SymbolContext(
        language="python",
        kind=kind,
        name=str(node.name),
        qualified_name=".".join((*parents, str(node.name))),
        start_line=node.lineno,
        end_line=node_end,
        excerpt=_excerpt(loaded, node.lineno, excerpt_end),
        truncated=excerpt_end < node_end,
    )


def _normal_relative_path(raw_path: str) -> str:
    text = str(raw_path).replace("\\", "/").strip()
    path = PurePosixPath(text)
    if (
        not text
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ContextCollectionError(f"unsafe_relative_path:{text or '<empty>'}")
    if path.parts and ":" in path.parts[0]:
        raise ContextCollectionError(f"unsafe_relative_path:{text}")
    return path.as_posix()


def _contains_symlink(root: Path, candidate: Path) -> bool:
    current = root
    try:
        relative_parts = candidate.relative_to(root).parts
    except ValueError:
        return True
    for part in relative_parts:
        current = current / part
        try:
            if current.is_symlink():
                return True
        except OSError:
            return True
    return False


def _deduplicate(items: list[EvidenceContext]) -> list[EvidenceContext]:
    result: list[EvidenceContext] = []
    seen: set[tuple[object, ...]] = set()
    for item in items:
        key = (
            item.evidence_type,
            item.scanner_id,
            item.rule_id,
            item.flow_index,
            item.thread_index,
            item.step_index,
            item.location.path.casefold(),
            item.location.start_line,
            item.location.start_column,
        )
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def _evidence_sort_key(item: EvidenceContext) -> tuple[object, ...]:
    return (
        item.scanner_id,
        item.rule_id,
        item.flow_index if item.flow_index is not None else -1,
        item.thread_index if item.thread_index is not None else -1,
        item.step_index if item.step_index is not None else -1,
        item.location.path.casefold(),
        item.location.start_line or 0,
    )
