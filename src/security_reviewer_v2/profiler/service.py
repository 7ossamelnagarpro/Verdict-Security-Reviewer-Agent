"""Public API for project profiling and scan planning."""

from __future__ import annotations

from dataclasses import replace
import re
from pathlib import Path

from .analysis import analyze_discovery
from .discovery import discover_project
from .code_graph import load_code_graph
from .models import (
    Completeness,
    ProfileResult,
    ProfilerLimits,
    ProfilerPolicy,
    ProjectProfile,
    SCHEMA_VERSION,
)
from .planner import create_scan_plan
from .registry import REGISTRY_VERSION, load_builtin_registry


def profile_project(
    project_path: str | Path,
    *,
    limits: ProfilerLimits | None = None,
    policy: ProfilerPolicy | None = None,
    code_graph_path: str | Path | None = None,
) -> ProfileResult:
    """Profile a local directory and create a deterministic, non-executing plan."""
    selected_limits = limits or ProfilerLimits()
    selected_policy = policy or ProfilerPolicy()
    discovery = discover_project(
        project_path,
        limits=selected_limits,
        policy=selected_policy,
    )
    registry = load_builtin_registry()
    components, git, targets, exclusions, analysis_warnings = analyze_discovery(
        discovery,
        policy=selected_policy,
    )
    reader_warnings = tuple(discovery.reader.warnings)
    completeness = discovery.completeness
    summary = replace(
        discovery.summary,
        content_bytes_read=discovery.reader.total_bytes_read,
    )
    gaps = _profile_coverage_gaps(components, discovery, analysis_warnings)
    profile = ProjectProfile(
        schema_version=SCHEMA_VERSION,
        root_name=discovery.root.name,
        completeness=completeness,
        inventory=discovery.files,
        inventory_summary=summary,
        components=components,
        git=git,
        targets=targets,
        exclusions=exclusions,
        skipped=discovery.skipped,
        warnings=tuple(sorted(set(discovery.warnings + analysis_warnings + reader_warnings))),
        coverage_gaps=gaps,
        policy_version=selected_policy.version,
        registry_version=REGISTRY_VERSION,
    )
    # Pass 2 of the two-pass flow: ingest an already-built code graph (read-only,
    # never executed here) so the planner can use its hints.
    code_graph = (
        load_code_graph(code_graph_path, root=discovery.root, profile=profile)
        if code_graph_path is not None
        else None
    )
    plan = create_scan_plan(
        profile,
        policy=selected_policy,
        registry=registry,
        code_graph=code_graph,
    )
    return ProfileResult(profile=profile, scan_plan=plan, code_graph=code_graph)


def _is_exact_pin(version: str | None) -> bool:
    """``==1.2.3`` (Python) or a bare ``1.2.3`` (npm); ranges, wildcards and unpinned names are not exact."""
    return bool(version) and re.fullmatch(r"(?:===?\s*)?\d+(?:\.\d+)*(?:[A-Za-z0-9.+-]*)", version.strip()) is not None and "*" not in version


def _profile_coverage_gaps(components, discovery, warnings) -> tuple[str, ...]:
    gaps: list[str] = []
    for component in components:
        if not component.languages and component.kind != "infrastructure":
            gaps.append(
                f"No supported language detector identified application source in {component.component_id}."
            )
        if component.languages and not component.dependency_files:
            gaps.append(
                f"Dependency/SCA coverage is unknown for component {component.component_id}: "
                "no supported manifest or lockfile was found."
            )
        manifests = tuple(item for item in component.dependency_files if item.kind == "manifest")
        has_lockfile = any(item.kind == "lockfile" for item in component.dependency_files)
        if manifests and not has_lockfile and any(item.dependencies for item in manifests):
            direct = [record for item in manifests for record in item.dependencies]
            pinned = (f" All {len(direct)} direct dependencies are exactly pinned; their transitive dependencies are not recorded."
                      if direct and all(_is_exact_pin(record.version) for record in direct) else "")
            gaps.append(
                f"Resolved transitive dependency versions are unverified for component "
                f"{component.component_id}: a manifest was found, but no supported lockfile.{pinned}"
            )
        for dependency_file in component.dependency_files:
            if dependency_file.parse_status in {"invalid", "unreadable", "detected_only", "truncated"}:
                gaps.append(
                    f"Dependency metadata is incomplete for {dependency_file.path} "
                    f"({dependency_file.parse_status})."
                )
    for item in discovery.skipped:
        if item.cause.value in {"resource_limit", "read_error", "disappeared", "outside_root"}:
            gaps.append(f"Discovery skipped {item.path}: {item.reason}")
    if discovery.reader.resource_limit_hit:
        gaps.append("Content-reading limits reduced framework or dependency evidence coverage.")
    return tuple(sorted(set(gaps)))
