"""Deterministic, bounded selection of places for AI discovery to inspect."""

from __future__ import annotations

import ast
import hashlib
import os
import re
import time
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Any

from security_reviewer_v2.normalization.merge_models import MergeResult
from security_reviewer_v2.prioritization.models import RiskResult
from security_reviewer_v2.context.models import ContextResult

from .models import DiscoveryConfig, DiscoveryTarget


SOURCE_SUFFIXES = {".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".java", ".go", ".php", ".rb", ".cs"}
SKIP_DIRS = {".git", ".venv", "node_modules", "vendor", "dist", "build", "coverage", "__pycache__"}
PATH_HINT = re.compile(r"auth|user|profile|order|admin|route|controller|api|coupon|checkout|payment|upload|file|session|access", re.I)
AUTH_HINT = re.compile(r"\b(?:auth|authoriz\w*|permission\w*|owner\w*|user_id|users?|role|admin|profile|orders?|coupon|checkout|session|accounts?)\b", re.I)
INPUT_HINT = re.compile(r"\brequest\b|\breq\.|\bparams\b|\bquery\b|\bbody\b|@\w+\.route|@\w+\.(?:get|post|put|delete)|\b(?:app|router)\.(?:get|post|put|patch|delete)\s*\(|\broute\s*\(", re.I)
RISK_CONTEXT_BEFORE = 12      # source lines shown before a scanner-flagged line
RISK_CONTEXT_AFTER = 25       # ... and after it
RISK_CONTEXT_MAX_LINES = 60
SENSITIVE_HINT = re.compile(r"secret|debug|environ|password|token|credential", re.I)


@dataclass(frozen=True)
class DiscoveryScope:
    targets: tuple[DiscoveryTarget, ...]
    snippets: dict[str, str]
    gap_evidence: tuple[str, ...]
    warnings: tuple[str, ...]
    coverage_gaps: tuple[str, ...]


def plan_discovery_scope(
    merged: MergeResult,
    risk: RiskResult,
    context: ContextResult,
    *,
    project_root: str | Path,
    config: DiscoveryConfig,
    profile_artifact: dict[str, Any] | None = None,
    additional_coverage_gaps: tuple[str, ...] = (),
) -> DiscoveryScope:
    root = Path(project_root).resolve(strict=True)
    paths, expected_hashes, inventory_gaps = _source_paths(root, profile_artifact)
    warnings: list[str] = []
    gaps: list[str] = list(inventory_gaps)
    profile_body = profile_artifact.get("profile") if isinstance(profile_artifact, dict) else None
    plan_body = profile_artifact.get("scan_plan") if isinstance(profile_artifact, dict) else None
    gap_evidence = tuple(sorted(set(
        (*getattr(merged, "coverage_gaps", ()), *getattr(context, "coverage_gaps", ()), *getattr(risk, "coverage_gaps", ()),
         *additional_coverage_gaps,
         *(profile_body.get("coverage_gaps", ()) if isinstance(profile_body, dict) else ()),
         *(plan_body.get("coverage_gaps", ()) if isinstance(plan_body, dict) else ()))
    )))
    finding_lines: dict[str, set[int]] = {}
    for finding in getattr(merged, "findings", ()):
        for source in finding.source_findings:
            location = source.primary_location
            if location.start_line is not None:
                finding_lines.setdefault(location.path.replace("\\", "/"), set()).add(location.start_line)

    # Inspect a bounded, deterministic mix of unflagged and flagged source
    # files. Profiler inventory, when supplied, avoids a second tree walk.
    unflagged = [path for path in paths if path not in finding_lines]
    flagged = [path for path in paths if path in finding_lines]
    key = lambda path: (-bool(PATH_HINT.search(path)), path.casefold())
    unflagged.sort(key=key)
    flagged.sort(key=key)
    half = max(1, config.max_files_considered // 2)
    considered = (unflagged[:half] + flagged[:config.max_files_considered - min(half, len(unflagged))])[:config.max_files_considered]
    if len(considered) < config.max_files_considered:
        considered += unflagged[half:half + config.max_files_considered - len(considered)]
    if len(considered) < len(paths):
        gaps.append(f"Discovery scored {len(considered)} of {len(paths)} source files; the remainder were outside its file budget.")

    gap_targets: list[DiscoveryTarget] = []
    no_finding_targets: list[DiscoveryTarget] = []
    hotspot_targets: list[DiscoveryTarget] = []
    snippets: dict[str, str] = {}
    read_cache: dict[str, tuple[str, ...]] = {}   # files already read, so risk targets do not re-read (or re-count) them
    bytes_read = 0
    for relative in considered:
        try:
            lines, size = _read_source(root, relative, expected_hashes, config, bytes_read)
        except ValueError as error:
            warnings.append(f"{relative}: {error}")
            gaps.append(f"Discovery could not inspect {relative}: {error}")
            continue
        bytes_read += size
        if not lines:
            continue
        read_cache[relative] = lines
        hotspots = _hotspots(relative, lines, finding_lines.get(relative, set()))
        matched_gaps = tuple(gap[:240] for gap in gap_evidence if relative in gap)
        if matched_gaps:
            start, end = hotspots[0][:2] if hotspots else _fallback_window(lines)
            target = _file_target("coverage_gap", relative, start, end, matched_gaps)
            gap_targets.append(target)
            snippets[target.target_id] = _numbered_window(lines, start, end)
        if relative not in finding_lines:
            start, end = hotspots[0][:2] if hotspots else _fallback_window(lines)
            reasons = ("No scanner finding has a primary location in this source file; this is not proof it was unscanned.",)
            target = _file_target("no_findings", relative, start, end, reasons)
            no_finding_targets.append(target)
            snippets[target.target_id] = _numbered_window(lines, start, end)
        else:
            for start, end, score in hotspots[:3]:
                reasons = (f"Security-relevant function/window scored {score} by deterministic input, authorization, and sink signals; no scanner primary finding is inside it.",)
                target = _file_target("unflagged_hotspot", relative, start, end, reasons)
                hotspot_targets.append(target)
                snippets[target.target_id] = _numbered_window(lines, start, end)

    high = [
        DiscoveryTarget(item.merged_finding_id, "risk_finding", getattr(getattr(item, "primary_location", None), "path", None),
                        getattr(getattr(item, "primary_location", None), "start_line", None),
                        getattr(getattr(item, "primary_location", None), "end_line", None),
                        (f"Risk rank {getattr(item, 'rank', '?')}; score {getattr(item, 'risk_score', '?')}; selected for deep review.",))
        for item in risk.findings if item.selected_for_deep_review
    ]
    # A risk target used to carry only the merged scanner excerpt, so the model re-read the merge result and never
    # saw the surrounding source.  Give it the real code window around the finding as well.
    for target in high:
        if not target.path or target.start_line is None:
            continue
        relative = target.path.replace("\\", "/")
        lines = read_cache.get(relative)
        if lines is None:
            try:
                lines, size = _read_source(root, relative, expected_hashes, config, bytes_read)
            except ValueError as error:
                warnings.append(f"{relative}: {error}")
                continue
            bytes_read += size
            read_cache[relative] = lines
        if not lines:
            continue
        end_line = target.end_line if target.end_line is not None else target.start_line
        start = max(1, min(target.start_line, len(lines)) - RISK_CONTEXT_BEFORE)
        end = min(len(lines), max(end_line, target.start_line) + RISK_CONTEXT_AFTER)
        snippets[target.target_id] = _numbered_window(lines, start, min(end, start + RISK_CONTEXT_MAX_LINES - 1))

    interleaved: list[DiscoveryTarget] = []
    for index in range(max((len(gap_targets), len(no_finding_targets), len(hotspot_targets)), default=0)):
        for category in (gap_targets, no_finding_targets, hotspot_targets):
            if index < len(category):
                interleaved.append(category[index])
    explore = _unique_targets(tuple(interleaved))
    ordered: list[DiscoveryTarget] = []
    for index in range(max(len(explore), len(high))):
        if index < len(explore):
            ordered.append(explore[index])
        if index < len(high):
            ordered.append(high[index])
    chosen = ordered[:config.max_planned_targets]
    if len(ordered) > len(chosen):
        gaps.append(f"{len(ordered) - len(chosen)} discovery targets exceed the overall planning limit; they were not inspected.")
    return DiscoveryScope(tuple(chosen), snippets, gap_evidence, tuple(sorted(set(warnings))), tuple(sorted(set(gaps))))


def _source_paths(root: Path, profile: dict[str, Any] | None) -> tuple[list[str], dict[str, str] | None, tuple[str, ...]]:
    if profile is not None:
        snapshot = profile.get("project_snapshot")
        body = profile.get("profile")
        inventory = body.get("inventory") if isinstance(body, dict) else None
        if not isinstance(snapshot, dict) or not isinstance(inventory, list):
            raise ValueError("A saved profiler artifact with inventory and snapshot is required")
        if snapshot.get("root_path") != os.path.normcase(str(root)):
            raise ValueError("Profiler artifact belongs to a different project root")
        records = snapshot.get("files")
        if not isinstance(records, list):
            raise ValueError("Profiler artifact lacks file hashes")
        hashes = {str(record["path"]): str(record["sha256"]) for record in records}
        paths = sorted({str(record["path"]) for record in inventory
                        if record.get("category") == "source"
                        and Path(str(record["path"])).suffix.casefold() in SOURCE_SUFFIXES
                        and not (set(PurePosixPath(str(record["path"])).parts) & SKIP_DIRS)})
        return paths, hashes, ()
    paths: list[str] = []
    limit = 10_000
    visited = 0
    started = time.monotonic()
    for directory, names, files in os.walk(root, followlinks=False):
        visited += len(names) + len(files)
        if visited > 50_000 or time.monotonic() - started > 10:
            return sorted(paths), None, ("Fallback source inventory reached its entry or time limit; supply a profiler artifact for complete indexing.",)
        names[:] = sorted(name for name in names if name not in SKIP_DIRS and not (Path(directory) / name).is_symlink())
        for name in sorted(files):
            path = Path(directory) / name
            if path.suffix.casefold() in SOURCE_SUFFIXES and not path.is_symlink():
                paths.append(path.relative_to(root).as_posix())
                if len(paths) >= limit:
                    return sorted(paths), None, (f"Fallback source inventory reached its {limit}-file limit; supply a profiler artifact for complete indexing.",)
    return sorted(paths), None, ()


def _read_source(root: Path, relative: str, hashes: dict[str, str] | None, config: DiscoveryConfig, total: int) -> tuple[tuple[str, ...], int]:
    path = PurePosixPath(relative)
    if not path.parts or path.is_absolute() or any(part in {".", ".."} for part in path.parts) or ":" in path.parts[0]:
        raise ValueError("unsafe source path")
    candidate = root.joinpath(*path.parts)
    current = root
    for part in path.parts:
        current /= part
        if current.is_symlink():
            raise ValueError("symlinked source skipped")
    try:
        resolved = candidate.resolve(strict=True)
        if not resolved.is_relative_to(root) or not resolved.is_file():
            raise ValueError("source outside project or not a file")
        size = resolved.stat().st_size
        if size > config.max_source_file_bytes or total + size > config.max_total_source_bytes:
            raise ValueError("source read budget exceeded")
        data = resolved.read_bytes()
        if len(data) != size or b"\x00" in data:
            raise ValueError("source changed during read or is binary")
        if hashes is not None and hashes.get(relative) != hashlib.sha256(data).hexdigest():
            raise ValueError("source hash differs from profiler snapshot")
        return tuple(data.decode("utf-8").splitlines()), len(data)
    except (OSError, UnicodeDecodeError) as error:
        raise ValueError("source could not be read as UTF-8") from error


def _hotspots(relative: str, lines: tuple[str, ...], finding_lines: set[int]) -> list[tuple[int, int, int]]:
    regions: list[tuple[int, int, str, bool]] = []
    if relative.endswith(".py"):
        try:
            tree = ast.parse("\n".join(lines), filename=relative)
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or not getattr(node, "end_lineno", None):
                    continue
                decorators = node.decorator_list
                start = min((decorator.lineno for decorator in decorators), default=node.lineno)
                children = tuple(ast.walk(node))
                names = [child.id for child in children if isinstance(child, ast.Name)]
                names += [child.attr for child in children if isinstance(child, ast.Attribute)]
                names += [child.arg for child in children if isinstance(child, ast.arg)]
                routes = [child.value for decorator in decorators for child in ast.walk(decorator)
                          if isinstance(child, ast.Constant) and isinstance(child.value, str)]
                route = any(
                    isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Attribute)
                    and decorator.func.attr in {"route", "get", "post", "put", "patch", "delete"}
                    for decorator in decorators
                )
                regions.append((start, min(len(lines), node.end_lineno), " ".join((*names, *routes)), route))
        except (SyntaxError, ValueError):
            pass
    if not regions:
        windows = {(max(1, line - 8), min(len(lines), line + 8)) for line, text in enumerate(lines, 1)
                   if INPUT_HINT.search(text)}
        regions = [(start, end, "\n".join(lines[start - 1:end]), False) for start, end in sorted(windows)]
    scored: list[tuple[int, int, int]] = []
    for start, end, signals, route in regions:
        if any(start <= line <= end for line in finding_lines):
            continue
        auth = bool(AUTH_HINT.search(signals))
        boundary = route or bool(INPUT_HINT.search(signals))
        sink = bool(re.search(r"\b(?:execute|subprocess|system|open|send_file|send_from_directory|eval|pickle|save|set_cookie)\b", signals, re.I))
        sensitive = bool(SENSITIVE_HINT.search(signals))
        if not (boundary and (auth or sink or sensitive)):
            continue
        score = 3 * auth + 2 * boundary + sink + sensitive + bool(route and "<" in signals)
        scored.append((start, min(end, start + 79), score))
    return sorted(set(scored), key=lambda item: (-item[2], item[0]))


def _fallback_window(lines: tuple[str, ...]) -> tuple[int, int]:
    """Window for a file with no scored hotspot: the first line with an input/authorization/sensitive signal, so the
    model is not shown only the import header (the old behaviour was always lines 1-40)."""
    for number, text in enumerate(lines, 1):
        if INPUT_HINT.search(text) or AUTH_HINT.search(text) or SENSITIVE_HINT.search(text):
            start = max(1, number - 8)
            return start, min(len(lines), start + 59)
    return 1, min(len(lines), 40)


def _file_target(kind: str, path: str, start: int, end: int, reasons: tuple[str, ...]) -> DiscoveryTarget:
    return DiscoveryTarget(f"file:{path}#L{start}-{end}", kind, path, start, end, reasons)


def _unique_targets(targets: tuple[DiscoveryTarget, ...]) -> list[DiscoveryTarget]:
    seen: dict[tuple[str | None, int | None, int | None], int] = {}
    result: list[DiscoveryTarget] = []
    for target in targets:
        key = (target.path, target.start_line, target.end_line)
        if key not in seen:
            seen[key] = len(result)
            result.append(target)
        else:
            index = seen[key]
            reasons = tuple(dict.fromkeys((*result[index].reasons, *target.reasons)))
            result[index] = replace(result[index], reasons=reasons)
    return result


def _numbered_window(lines: tuple[str, ...], start: int, end: int) -> str:
    return "\n".join(f"{line}: {lines[line - 1]}" for line in range(start, end + 1))
