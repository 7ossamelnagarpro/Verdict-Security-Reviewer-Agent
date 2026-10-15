"""Public API for project profiling and scan planning."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from .analysis import analyze_discovery
from .discovery import discover_project
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
    plan = create_scan_plan(
        profile,
        policy=selected_policy,
        registry=registry,
    )
    return ProfileResult(profile=profile, scan_plan=plan)


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
            gaps.append(
                f"Resolved transitive dependency versions are unverified for component "
                f"{component.component_id}: a manifest was found, but no supported lockfile."
            )
        for dependency_file in component.dependency_files:
            if dependency_file.parse_status in {"invalid", "unreadable", "detected_only"}:
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
