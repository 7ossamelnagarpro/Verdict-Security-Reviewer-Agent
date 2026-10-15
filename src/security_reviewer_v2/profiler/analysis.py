"""Deterministic component, language, framework, dependency, and target detection."""

from __future__ import annotations

import ast
import hashlib
import json
import re
import tomllib
from collections import Counter, defaultdict
from dataclasses import replace
from pathlib import Path, PurePosixPath
from typing import Any

from .discovery import DiscoveryResult, LOCKFILE_NAMES, language_for_file
from .models import (
    ComponentProfile,
    Confidence,
    DependencyFile,
    DependencyRecord,
    Detection,
    Evidence,
    ExclusionRecord,
    FileCategory,
    GitMetadata,
    ProfilerPolicy,
    TargetMetadata,
)


COMPONENT_MANIFESTS = {
    "pyproject.toml",
    "requirements.txt",
    "package.json",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "gemfile",
    "cargo.toml",
}

FRAMEWORK_RULES = {
    "python": {
        "flask": ("flask", ("import flask", "from flask")),
        "django": ("django", ("import django", "from django")),
        "fastapi": ("fastapi", ("import fastapi", "from fastapi")),
    },
    "javascript": {
        "express": ("express", ("require('express", 'require("express', "from 'express", 'from "express')),
        "react": ("react", ("from 'react", 'from "react', "require('react", 'require("react')),
        "next.js": ("next", ("from 'next", 'from "next', "require('next", 'require("next')),
        "vue": ("vue", ("from 'vue", 'from "vue', "require('vue", 'require("vue')),
    },
    "typescript": {
        "express": ("express", ("from 'express", 'from "express')),
        "react": ("react", ("from 'react", 'from "react')),
        "next.js": ("next", ("from 'next", 'from "next')),
        "vue": ("vue", ("from 'vue", 'from "vue')),
    },
}


def analyze_discovery(
    discovery: DiscoveryResult,
    *,
    policy: ProfilerPolicy,
) -> tuple[
    tuple[ComponentProfile, ...],
    GitMetadata,
    TargetMetadata,
    tuple[ExclusionRecord, ...],
    tuple[str, ...],
]:
    """Derive project facts from a bounded inventory without executing code."""
    warnings: list[str] = []
    component_roots = _discover_component_roots(discovery)
    assigned = _assign_files(discovery, component_roots)
    components: list[ComponentProfile] = []

    for root in component_roots:
        component_id = _component_id(root)
        files = assigned[root]
        dependency_files, dependency_warnings = _detect_dependencies(
            discovery, files, component_id
        )
        warnings.extend(dependency_warnings)
        languages = _detect_languages(files, component_id)
        frameworks = _detect_frameworks(
            discovery,
            files,
            component_id,
            languages,
            dependency_files,
        )
        manifest_evidence = tuple(
            Evidence(
                path=item.path,
                evidence_type="component_manifest",
                detail=f"{PurePosixPath(item.path).name} defines a project boundary",
            )
            for item in files
            if PurePosixPath(item.path).name.casefold() in COMPONENT_MANIFESTS
        )
        iac_evidence = tuple(
            Evidence(
                path=item.path,
                evidence_type="infrastructure_file",
                detail="Infrastructure files form a standalone component",
            )
            for item in files
            if item.extension == ".tf"
        )
        kind = "workspace" if _is_workspace_root(discovery, root) else "application"
        if not manifest_evidence and iac_evidence and not languages:
            kind = "infrastructure"
        evidence = manifest_evidence or iac_evidence or (
            Evidence(
                path=root,
                evidence_type="conservative_root",
                detail="No stronger component boundary was available",
            ),
        )
        if not manifest_evidence and not iac_evidence:
            warnings.append(
                f"Component boundary for {root} is conservative because no supported manifest "
                "or workspace definition was found."
            )
        confidence = Confidence.HIGH if manifest_evidence else Confidence.MEDIUM
        components.append(
            ComponentProfile(
                component_id=component_id,
                root=root,
                kind=kind,
                confidence=confidence,
                evidence=tuple(sorted(evidence, key=lambda item: item.path.casefold())),
                languages=languages,
                frameworks=frameworks,
                dependency_files=dependency_files,
                file_count=len(files),
                total_bytes=sum(item.size_bytes for item in files),
            )
        )

    components.sort(key=lambda item: (_root_depth(item.root), item.root.casefold()))
    git = _detect_git(discovery.root)
    targets = _detect_targets(discovery)
    exclusions = _build_exclusion_records(policy)
    return tuple(components), git, targets, exclusions, tuple(sorted(set(warnings)))


def _discover_component_roots(discovery: DiscoveryResult) -> tuple[str, ...]:
    manifest_roots: set[str] = set()
    iac_roots: set[str] = set()
    for item in discovery.files:
        path = PurePosixPath(item.path)
        name = path.name.casefold()
        parent = _normalize_root(str(path.parent))
        if name in COMPONENT_MANIFESTS:
            manifest_roots.add(parent)
        elif item.extension == ".tf":
            iac_roots.add(parent)
    roots = set(manifest_roots)
    for iac_root in iac_roots:
        if iac_root not in manifest_roots and not any(
            root != "." and _is_within(iac_root, root) for root in manifest_roots
        ):
            roots.add(iac_root)
    if not roots:
        roots.add(".")
    return tuple(sorted(roots, key=lambda value: (_root_depth(value), value.casefold())))


def _assign_files(
    discovery: DiscoveryResult,
    roots: tuple[str, ...],
) -> dict[str, tuple[Any, ...]]:
    assigned: dict[str, list[Any]] = {root: [] for root in roots}
    by_specificity = sorted(roots, key=lambda value: (-_root_depth(value), value.casefold()))
    for item in discovery.files:
        parent = str(PurePosixPath(item.path).parent)
        for root in by_specificity:
            if _is_within(parent, root):
                assigned[root].append(item)
                break
    return {
        root: tuple(sorted(items, key=lambda item: item.path.casefold()))
        for root, items in assigned.items()
    }


def _detect_languages(files: tuple[Any, ...], component_id: str) -> tuple[Detection, ...]:
    evidence_by_language: dict[str, list[Evidence]] = defaultdict(list)
    counts: Counter[str] = Counter()
    for item in files:
        if item.category not in {FileCategory.SOURCE, FileCategory.TEST}:
            continue
        language = language_for_file(item)
        if not language:
            continue
        counts[language] += 1
        if len(evidence_by_language[language]) < 5:
            evidence_by_language[language].append(
                Evidence(
                    path=item.path,
                    evidence_type="source_extension",
                    detail=f"{item.extension} maps to {language}",
                )
            )
    detections = [
        Detection(
            name=language,
            component_id=component_id,
            confidence=Confidence.HIGH if count >= 2 else Confidence.MEDIUM,
            evidence=tuple(evidence_by_language[language]),
        )
        for language, count in sorted(counts.items())
    ]
    return tuple(detections)


def _detect_frameworks(
    discovery: DiscoveryResult,
    files: tuple[Any, ...],
    component_id: str,
    languages: tuple[Detection, ...],
    dependency_files: tuple[DependencyFile, ...],
) -> tuple[Detection, ...]:
    declared: dict[str, list[str]] = defaultdict(list)
    for dependency_file in dependency_files:
        for dependency in dependency_file.dependencies:
            declared[dependency.name.casefold()].append(dependency_file.path)

    language_names = {item.name for item in languages}
    source_files = [
        item
        for item in files
        if item.category in {FileCategory.SOURCE, FileCategory.TEST}
        and item.size_bytes <= discovery.reader.limits.max_content_read_bytes
    ]
    results: list[Detection] = []
    seen: set[tuple[str, str]] = set()
    for language in sorted(language_names):
        for framework, (dependency_name, markers) in FRAMEWORK_RULES.get(language, {}).items():
            dependency_paths = declared.get(dependency_name.casefold(), [])
            import_paths: list[str] = []
            for source_file in source_files:
                source_language = language_for_file(source_file)
                if source_language not in {language, "javascript" if language == "typescript" else language}:
                    continue
                content = discovery.reader.read(source_file.path)
                if content is not None and _source_uses_dependency(
                    source_language or language,
                    content,
                    dependency_name,
                    markers,
                ):
                    import_paths.append(source_file.path)
                    if len(import_paths) >= 3:
                        break
            if not dependency_paths and not import_paths:
                continue
            key = (framework, component_id)
            if key in seen:
                continue
            seen.add(key)
            evidence = [
                Evidence(
                    path=path,
                    evidence_type="dependency_declaration",
                    detail=f"Declares dependency {dependency_name}",
                )
                for path in sorted(set(dependency_paths))
            ]
            evidence.extend(
                Evidence(
                    path=path,
                    evidence_type="source_import",
                    detail=f"Source contains an import indicator for {framework}",
                )
                for path in sorted(set(import_paths))
            )
            if dependency_paths and import_paths:
                confidence = Confidence.HIGH
            elif import_paths:
                confidence = Confidence.MEDIUM
            else:
                confidence = Confidence.LOW
            results.append(
                Detection(
                    name=framework,
                    component_id=component_id,
                    confidence=confidence,
                    evidence=tuple(evidence),
                )
            )
    return tuple(sorted(results, key=lambda item: item.name))


def _source_uses_dependency(
    language: str,
    content: str,
    dependency_name: str,
    markers: tuple[str, ...],
) -> bool:
    if language == "python":
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return False
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                if any(alias.name.split(".", 1)[0].casefold() == dependency_name.casefold() for alias in node.names):
                    return True
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module.split(".", 1)[0].casefold() == dependency_name.casefold():
                    return True
        return False
    if language in {"javascript", "typescript"}:
        escaped = re.escape(dependency_name)
        patterns = (
            rf"(?m)^\s*import(?:[\s\S]*?from\s*)?[\"']{escaped}(?:/[^\"']*)?[\"']",
            rf"(?m)^\s*(?:const|let|var)\s+.+?=\s*require\(\s*[\"']{escaped}(?:/[^\"']*)?[\"']\s*\)",
        )
        return any(re.search(pattern, content) for pattern in patterns)
    return any(marker in content for marker in markers)


def _detect_dependencies(
    discovery: DiscoveryResult,
    files: tuple[Any, ...],
    component_id: str,
) -> tuple[tuple[DependencyFile, ...], list[str]]:
    results: list[DependencyFile] = []
    warnings: list[str] = []
    dependency_records = [
        item
        for item in files
        if item.category in {FileCategory.DEPENDENCY_MANIFEST, FileCategory.LOCKFILE}
    ]
    paths = {item.path for item in dependency_records}
    for item in dependency_records:
        name = PurePosixPath(item.path).name.casefold()
        content = discovery.reader.read(item.path)
        if content is None:
            warning = f"Dependency file could not be read within limits: {item.path}"
            warnings.append(warning)
            results.append(
                DependencyFile(
                    path=item.path,
                    component_id=component_id,
                    ecosystem=_ecosystem_for(name),
                    package_manager=_manager_for(name),
                    kind="lockfile" if name in LOCKFILE_NAMES else "manifest",
                    parse_status="unreadable",
                    warnings=(warning,),
                )
            )
            continue
        dependencies: tuple[DependencyRecord, ...] = ()
        parse_status = "detected_only"
        local_warnings: list[str] = []
        try:
            if name == "pyproject.toml":
                dependencies = _parse_pyproject(content)
                parse_status = "parsed"
            elif name.startswith("requirements") and name.endswith(".txt"):
                dependencies = _parse_requirements(content)
                parse_status = "parsed_constraints"
            elif name == "package.json":
                dependencies = _parse_package_json(content, resolved=False)
                parse_status = "parsed"
            elif name in {"package-lock.json", "npm-shrinkwrap.json"}:
                dependencies = _parse_package_lock(content)
                parse_status = "parsed_resolved"
            elif name == "pipfile.lock":
                dependencies = _parse_pipfile_lock(content)
                parse_status = "parsed_resolved"
            else:
                local_warnings.append(
                    "File type is detected, but full dependency parsing is not implemented"
                )
        except (json.JSONDecodeError, tomllib.TOMLDecodeError, ValueError, TypeError) as error:
            parse_status = "invalid"
            local_warnings.append(f"Invalid dependency file: {type(error).__name__}")
        linked = _find_linked_dependency_file(item.path, paths)
        for warning in local_warnings:
            warnings.append(f"{item.path}: {warning}")
        results.append(
            DependencyFile(
                path=item.path,
                component_id=component_id,
                ecosystem=_ecosystem_for(name),
                package_manager=_manager_for(name),
                kind="lockfile" if name in LOCKFILE_NAMES else "manifest",
                parse_status=parse_status,
                linked_file=linked,
                dependencies=dependencies,
                warnings=tuple(local_warnings),
            )
        )
    return tuple(sorted(results, key=lambda item: item.path.casefold())), warnings


def _parse_pyproject(content: str) -> tuple[DependencyRecord, ...]:
    data = tomllib.loads(content)
    records: list[DependencyRecord] = []
    project = data.get("project", {})
    for value in project.get("dependencies", []) or []:
        name, version = _split_python_requirement(str(value))
        records.append(DependencyRecord(name, version, "constraint", "runtime"))
    for group, values in (project.get("optional-dependencies", {}) or {}).items():
        for value in values or []:
            name, version = _split_python_requirement(str(value))
            records.append(DependencyRecord(name, version, "constraint", f"optional:{group}"))
    poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {}) or {}
    for name, value in poetry.items():
        if name.casefold() == "python":
            continue
        version = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
        records.append(DependencyRecord(name, version, "constraint", "runtime"))
    return _unique_dependencies(records)


def _parse_requirements(content: str) -> tuple[DependencyRecord, ...]:
    records: list[DependencyRecord] = []
    for line in content.splitlines():
        clean = line.strip()
        if not clean or clean.startswith(("#", "-")):
            continue
        clean = clean.split(" #", 1)[0].strip()
        name, version = _split_python_requirement(clean)
        records.append(DependencyRecord(name, version, "constraint", "runtime"))
    return _unique_dependencies(records)


def _parse_package_json(content: str, *, resolved: bool) -> tuple[DependencyRecord, ...]:
    data = json.loads(content)
    records: list[DependencyRecord] = []
    for key, scope in (
        ("dependencies", "runtime"),
        ("devDependencies", "development"),
        ("optionalDependencies", "optional"),
        ("peerDependencies", "peer"),
    ):
        values = data.get(key, {}) or {}
        if not isinstance(values, dict):
            raise ValueError(f"{key} must be an object")
        for name, version in values.items():
            records.append(
                DependencyRecord(
                    str(name),
                    str(version),
                    "resolved" if resolved else "constraint",
                    scope,
                )
            )
    return _unique_dependencies(records)


def _parse_package_lock(content: str) -> tuple[DependencyRecord, ...]:
    data = json.loads(content)
    records: list[DependencyRecord] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for path, metadata in packages.items():
            if not path or not isinstance(metadata, dict):
                continue
            name = metadata.get("name") or str(path).split("node_modules/")[-1]
            version = metadata.get("version")
            if name and version:
                records.append(DependencyRecord(str(name), str(version), "resolved", "resolved"))
    elif isinstance(data.get("dependencies"), dict):
        for name, metadata in data["dependencies"].items():
            if isinstance(metadata, dict) and metadata.get("version"):
                records.append(
                    DependencyRecord(str(name), str(metadata["version"]), "resolved", "resolved")
                )
    return _unique_dependencies(records)


def _parse_pipfile_lock(content: str) -> tuple[DependencyRecord, ...]:
    data = json.loads(content)
    records: list[DependencyRecord] = []
    for key, scope in (("default", "runtime"), ("develop", "development")):
        for name, metadata in (data.get(key, {}) or {}).items():
            if isinstance(metadata, dict):
                version = metadata.get("version")
            else:
                version = metadata
            records.append(DependencyRecord(str(name), str(version) if version else None, "resolved", scope))
    return _unique_dependencies(records)


def _split_python_requirement(value: str) -> tuple[str, str | None]:
    match = re.match(r"^\s*([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*(.*)$", value)
    if not match:
        raise ValueError("Invalid Python dependency declaration")
    name = match.group(1)
    version = match.group(2).strip() or None
    return name, version


def _unique_dependencies(records: list[DependencyRecord]) -> tuple[DependencyRecord, ...]:
    unique = {
        (item.name.casefold(), item.version or "", item.scope, item.version_kind): item
        for item in records
    }
    return tuple(sorted(unique.values(), key=lambda item: (item.name.casefold(), item.scope)))


def _find_linked_dependency_file(path: str, all_paths: set[str]) -> str | None:
    pure = PurePosixPath(path)
    name = pure.name.casefold()
    parent = pure.parent
    candidates: tuple[str, ...]
    if name == "package.json":
        candidates = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")
    elif name == "pyproject.toml":
        candidates = ("poetry.lock", "uv.lock", "pipfile.lock")
    else:
        candidates = ()
    for candidate in candidates:
        linked = str(parent / candidate).replace("\\", "/")
        if linked.startswith("./"):
            linked = linked[2:]
        if linked in all_paths:
            return linked
    return None


def _ecosystem_for(name: str) -> str:
    if name in {"pyproject.toml", "requirements.txt", "poetry.lock", "uv.lock", "pipfile", "pipfile.lock"} or name.startswith("requirements"):
        return "python"
    if name in {"package.json", "package-lock.json", "npm-shrinkwrap.json"}:
        return "npm"
    if name == "yarn.lock":
        return "yarn"
    if name == "pnpm-lock.yaml":
        return "pnpm"
    if name in {"go.mod", "go.sum"}:
        return "go"
    if name in {"pom.xml"}:
        return "maven"
    if name in {"build.gradle", "build.gradle.kts", "gradle.lockfile"}:
        return "gradle"
    if name in {"gemfile", "gemfile.lock"}:
        return "ruby"
    if name in {"cargo.toml", "cargo.lock"}:
        return "cargo"
    return "unknown"


def _manager_for(name: str) -> str:
    mapping = {
        "package.json": "npm-compatible",
        "package-lock.json": "npm",
        "npm-shrinkwrap.json": "npm",
        "yarn.lock": "yarn",
        "pnpm-lock.yaml": "pnpm",
        "pyproject.toml": "python-project",
        "poetry.lock": "poetry",
        "uv.lock": "uv",
        "pipfile": "pipenv",
        "pipfile.lock": "pipenv",
        "go.mod": "go-modules",
        "go.sum": "go-modules",
        "pom.xml": "maven",
        "build.gradle": "gradle",
        "build.gradle.kts": "gradle",
        "gemfile": "bundler",
        "gemfile.lock": "bundler",
        "cargo.toml": "cargo",
        "cargo.lock": "cargo",
    }
    if name.startswith("requirements"):
        return "pip"
    return mapping.get(name, "unknown")


def _detect_git(root: Path) -> GitMetadata:
    marker = root / ".git"
    if marker.is_dir():
        history = "shallow" if (marker / "shallow").exists() else "metadata_present_unverified"
        return GitMetadata(True, "directory", ".git", history)
    if marker.is_file():
        try:
            prefix = marker.read_text(encoding="utf-8", errors="replace")[:4096].strip()
            valid = prefix.casefold().startswith("gitdir:")
        except OSError:
            valid = False
        return GitMetadata(
            True,
            "worktree_file",
            ".git",
            "metadata_present_unverified" if valid else "marker_unreadable_or_invalid",
        )
    return GitMetadata(False, "none", None, "unavailable")


def _detect_targets(discovery: DiscoveryResult) -> TargetMetadata:
    dockerfiles: list[str] = []
    compose: list[str] = []
    iac: list[str] = []
    ci: list[str] = []
    secret_candidates: list[str] = []
    runtime_manifests: list[str] = []
    for item in discovery.files:
        path = PurePosixPath(item.path)
        name = path.name.casefold()
        lower_path = item.path.casefold()
        if name == "dockerfile" or name.startswith("dockerfile."):
            dockerfiles.append(item.path)
        if name in {"compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml"}:
            compose.append(item.path)
        if item.extension in {".tf", ".tfvars"} or name in {"template.yaml", "template.yml"}:
            iac.append(item.path)
        if (
            lower_path.startswith(".github/workflows/") and item.extension in {".yml", ".yaml"}
        ) or name in {".gitlab-ci.yml", "azure-pipelines.yml", "circle.yml"}:
            ci.append(item.path)
        if item.category not in {FileCategory.BINARY, FileCategory.VENDOR, FileCategory.GENERATED}:
            secret_candidates.append(item.path)
        if name in {"security-review-runtime.json", "idor-dast.json"}:
            runtime_manifests.append(item.path)
    return TargetMetadata(
        dockerfiles=tuple(sorted(dockerfiles)),
        compose_files=tuple(sorted(compose)),
        iac_files=tuple(sorted(iac)),
        ci_files=tuple(sorted(ci)),
        secret_candidate_files=tuple(sorted(secret_candidates)),
        runtime_manifests=tuple(sorted(runtime_manifests)),
    )


def _build_exclusion_records(policy: ProfilerPolicy) -> tuple[ExclusionRecord, ...]:
    records: list[ExclusionRecord] = []
    groups = (
        ("sast", policy.sast_exclusions),
        ("dependencies", policy.dependency_exclusions),
        ("secrets", policy.secret_exclusions),
        ("configuration", policy.configuration_exclusions),
    )
    for scope, patterns in groups:
        for pattern in patterns:
            records.append(
                ExclusionRecord(
                    scope=scope,
                    pattern=pattern,
                    reason="Default or explicit scan-scope policy",
                    effect=f"Excluded from {scope} tasks only",
                )
            )
    for pattern in policy.additional_discovery_exclusions:
        records.append(
            ExclusionRecord(
                scope="discovery",
                pattern=pattern,
                reason="Explicit profiler override",
                effect="May reduce project discovery coverage",
            )
        )
    return tuple(sorted(records, key=lambda item: (item.scope, item.pattern)))


def _is_workspace_root(discovery: DiscoveryResult, root: str) -> bool:
    package_path = "package.json" if root == "." else f"{root}/package.json"
    if package_path not in discovery.absolute_paths:
        return False
    content = discovery.reader.read(package_path)
    if not content:
        return False
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return False
    return bool(data.get("workspaces"))


def _component_id(root: str) -> str:
    digest = hashlib.sha256(root.encode("utf-8")).hexdigest()[:10]
    return f"component-{digest}"


def _normalize_root(value: str) -> str:
    return "." if value in {"", "."} else value.replace("\\", "/")


def _is_within(path: str, root: str) -> bool:
    if root == ".":
        return True
    return path == root or path.startswith(root + "/")


def _root_depth(root: str) -> int:
    return 0 if root == "." else len(PurePosixPath(root).parts)
