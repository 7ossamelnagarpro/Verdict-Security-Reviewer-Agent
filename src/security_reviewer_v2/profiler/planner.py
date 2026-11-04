"""Explainable scan planning based on profiles and pinned capabilities."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import PurePosixPath

from .models import (
    ComponentProfile,
    Evidence,
    PlanStatus,
    PrerequisiteState,
    ProfilerPolicy,
    ProjectProfile,
    ScannerCapability,
    ScanPlan,
    ScanTask,
    ScanType,
)
from .registry import REGISTRY_VERSION


def create_scan_plan(
    profile: ProjectProfile,
    *,
    policy: ProfilerPolicy,
    registry: tuple[ScannerCapability, ...],
) -> ScanPlan:
    """Create stable planning decisions without executing scanner binaries."""
    capabilities = {item.scanner_id: item for item in registry}
    tasks: list[ScanTask] = []
    gaps = list(profile.coverage_gaps)
    warnings: list[str] = []

    for component in profile.components:
        for language_detection in component.languages:
            language = language_detection.name
            matched_sast = False
            for scanner_id in ("semgrep-ce", "codeql-cli"):
                capability = capabilities.get(scanner_id)
                if capability is None or ScanType.SAST not in capability.scan_types:
                    continue
                if language not in capability.languages:
                    continue
                matched_sast = True
                large = _is_large_component(component, policy)
                targets = _sast_targets(
                    profile,
                    component,
                    scanner_id=scanner_id,
                    policy=policy,
                )
                for chunk_index, target_chunk in enumerate(targets):
                    reasons = [
                        f"Component contains supported {language} source code.",
                        _sast_complement_reason(scanner_id),
                    ]
                    if large:
                        reasons.append(
                            "Large component uses deterministic scoped SAST targets to reduce "
                            "per-process cost; CodeQL remains component-wide for data-flow coverage."
                        )
                    if len(targets) > 1:
                        reasons.append(
                            f"This is SAST scope {chunk_index + 1} of {len(targets)} for the component."
                        )
                    tasks.append(
                        _task(
                            scanner=capability,
                            scan_type=ScanType.SAST,
                            component=component,
                            target_paths=target_chunk,
                            language_or_ecosystem=language,
                            mode=capability.modes[0],
                            exclusions=policy.sast_exclusions,
                            evidence=language_detection.evidence,
                            reasons=tuple(reasons),
                            policy=policy,
                            resource_class="large" if large else "standard",
                        )
                    )
            if not matched_sast:
                gaps.append(
                    f"No registered SAST capability supports language '{language}' "
                    f"in component {component.component_id}."
                )

        for dependency_file in component.dependency_files:
            capability = capabilities.get("trivy")
            if capability is None:
                gaps.append(
                    "Trivy capability is absent; dependency targets are uncovered."
                )
                continue
            if dependency_file.ecosystem not in capability.ecosystems:
                gaps.append(
                    f"Dependency ecosystem '{dependency_file.ecosystem}' in "
                    f"{dependency_file.path} is detected but unsupported by the registry."
                )
                continue
            evidence = (
                Evidence(
                    path=dependency_file.path,
                    evidence_type="dependency_target",
                    detail=(
                        f"{dependency_file.kind} for {dependency_file.ecosystem}; "
                        f"parse status {dependency_file.parse_status}"
                    ),
                ),
            )
            reasons = [
                f"Detected a supported {dependency_file.ecosystem} dependency file.",
                "SCA covers known dependency vulnerabilities; SAST does not replace it.",
            ]
            if dependency_file.kind != "lockfile":
                reasons.append(
                    "Only declared constraints may be available; resolved transitive coverage can be incomplete."
                )
            tasks.append(
                _task(
                    scanner=capability,
                    scan_type=ScanType.SCA,
                    component=component,
                    target_paths=(dependency_file.path,),
                    language_or_ecosystem=dependency_file.ecosystem,
                    mode="filesystem",
                    exclusions=policy.dependency_exclusions,
                    evidence=evidence,
                    reasons=tuple(reasons),
                    policy=policy,
                )
            )
            if dependency_file.parse_status in {
                "invalid",
                "unreadable",
                "detected_only",
            }:
                gaps.append(
                    f"Dependency coverage for {dependency_file.path} is limited "
                    f"because its profile status is {dependency_file.parse_status}."
                )

    gitleaks = capabilities.get("gitleaks")
    trivy = capabilities.get("trivy")
    secret_scanner = gitleaks
    if (
        "gitleaks" in policy.disabled_scanners
        or "gitleaks" not in policy.enabled_scanners
    ):
        secret_scanner = trivy
    if secret_scanner is not None and profile.targets.secret_candidate_files:
        tasks.append(
            _task(
                scanner=secret_scanner,
                scan_type=ScanType.SECRETS,
                component=None,
                target_paths=(".",),
                language_or_ecosystem=None,
                mode="directory"
                if secret_scanner.scanner_id == "gitleaks"
                else "filesystem",
                exclusions=policy.secret_exclusions,
                evidence=(
                    Evidence(
                        path=".",
                        evidence_type="text_file_scope",
                        detail=(
                            f"{len(profile.targets.secret_candidate_files)} current files are eligible; "
                            "file contents were not included in the profile"
                        ),
                    ),
                ),
                reasons=(
                    "Current-file secret scanning is useful even when Git metadata is absent.",
                    "Secret scanning is separate from SAST and dependency analysis.",
                ),
                policy=policy,
            )
        )
    else:
        gaps.append("No current-file secret scanning task could be planned.")

    if profile.git.present and gitleaks is not None:
        tasks.append(
            _task(
                scanner=gitleaks,
                scan_type=ScanType.SECRETS,
                component=None,
                target_paths=(".",),
                language_or_ecosystem=None,
                mode="git_history",
                exclusions=policy.secret_exclusions,
                evidence=(
                    Evidence(
                        path=profile.git.marker_path or ".git",
                        evidence_type="git_metadata",
                        detail=f"Git marker kind: {profile.git.marker_kind}",
                    ),
                ),
                reasons=(
                    "Git metadata is present, so historical secret scanning may be possible.",
                    f"History status is {profile.git.history_status} and must be verified later.",
                ),
                policy=policy,
                force_unverified=True,
            )
        )

    misconfiguration_targets = tuple(
        sorted(
            set(
                profile.targets.dockerfiles
                + profile.targets.compose_files
                + profile.targets.iac_files
                + profile.targets.ci_files
            )
        )
    )
    if trivy is not None and misconfiguration_targets:
        tasks.append(
            _task(
                scanner=trivy,
                scan_type=ScanType.MISCONFIGURATION,
                component=None,
                target_paths=misconfiguration_targets,
                language_or_ecosystem=None,
                mode="filesystem",
                exclusions=policy.configuration_exclusions,
                evidence=tuple(
                    Evidence(
                        path=path,
                        evidence_type="configuration_target",
                        detail="Supported configuration target",
                    )
                    for path in misconfiguration_targets
                ),
                reasons=(
                    "Configuration or Infrastructure-as-Code targets were discovered.",
                    "Misconfiguration analysis is distinct from source and dependency scanning.",
                ),
                policy=policy,
            )
        )

    if profile.targets.dockerfiles and trivy is not None:
        tasks.append(
            _task(
                scanner=trivy,
                scan_type=ScanType.CONTAINER_IMAGE,
                component=None,
                target_paths=(),
                language_or_ecosystem=None,
                mode="image",
                exclusions=(),
                evidence=tuple(
                    Evidence(
                        path=path,
                        evidence_type="dockerfile",
                        detail="A Dockerfile exists, but it is not a built image",
                    )
                    for path in profile.targets.dockerfiles
                ),
                reasons=(
                    "A Dockerfile alone does not provide a container image target.",
                ),
                policy=policy,
                explicit_status=PlanStatus.NOT_APPLICABLE,
            )
        )

    # Runtime DAST is opt-in: a manifest proves that the project declares a
    # test target, but the orchestrator still verifies reachability and
    # identities before executing any request.
    idor_capability = capabilities.get("idor-dast")
    if idor_capability is not None:
        for manifest in profile.targets.runtime_manifests:
            tasks.append(
                _task(
                    scanner=idor_capability,
                    scan_type=ScanType.DAST,
                    component=None,
                    target_paths=(manifest,),
                    language_or_ecosystem=None,
                    mode="differential_authorization",
                    exclusions=(),
                    evidence=(
                        Evidence(
                            path=manifest,
                            evidence_type="runtime_manifest",
                            detail="Explicit runtime manifest opts the project into read-only authorization probing.",
                        ),
                    ),
                    reasons=(
                        "Project explicitly declares a runtime authorization test target.",
                        "Execution remains blocked until the adapter verifies the target and synthetic identities.",
                    ),
                    policy=policy,
                )
            )

    tasks = _coalesce_codeql(_deduplicate_tasks(tasks))
    if profile.completeness.value != "complete":
        warnings.append(
            f"Profiling was {profile.completeness.value}; the scan plan may omit undiscovered targets."
        )
    return ScanPlan(
        schema_version=profile.schema_version,
        policy_version=policy.version,
        registry_version=REGISTRY_VERSION,
        tasks=tuple(sorted(tasks, key=lambda item: item.task_id)),
        coverage_gaps=tuple(sorted(set(gaps))),
        warnings=tuple(sorted(set(warnings))),
    )


def _task(
    *,
    scanner: ScannerCapability,
    scan_type: ScanType,
    component: ComponentProfile | None,
    target_paths: tuple[str, ...],
    language_or_ecosystem: str | None,
    mode: str,
    exclusions: tuple[str, ...],
    evidence: tuple[Evidence, ...],
    reasons: tuple[str, ...],
    policy: ProfilerPolicy,
    force_unverified: bool = False,
    explicit_status: PlanStatus | None = None,
    resource_class: str = "standard",
) -> ScanTask:
    prerequisite_state = _prerequisite_state(scanner, policy)
    if force_unverified and prerequisite_state == PrerequisiteState.AVAILABLE:
        prerequisite_state = PrerequisiteState.UNVERIFIED
    if explicit_status is not None:
        status = explicit_status
    elif (
        scanner.scanner_id in policy.disabled_scanners
        or scanner.scanner_id not in policy.enabled_scanners
    ):
        status = PlanStatus.DISABLED_BY_POLICY
    elif prerequisite_state == PrerequisiteState.MISSING:
        status = PlanStatus.BLOCKED
    elif prerequisite_state == PrerequisiteState.UNVERIFIED:
        status = PlanStatus.NEEDS_VERIFICATION
    else:
        status = PlanStatus.SELECTED
    component_id = component.component_id if component else None
    identity = "|".join(
        (
            scanner.scanner_id,
            scan_type.value,
            component_id or "project",
            ",".join(sorted(target_paths)),
            language_or_ecosystem or "",
            mode,
        )
    )
    task_id = "task-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12]
    return ScanTask(
        task_id=task_id,
        scanner_id=scanner.scanner_id,
        scan_type=scan_type,
        component_id=component_id,
        target_paths=tuple(sorted(target_paths)),
        language_or_ecosystem=language_or_ecosystem,
        mode=mode,
        rule_references=scanner.rule_references,
        exclusions=tuple(sorted(exclusions)),
        evidence=tuple(
            sorted(evidence, key=lambda item: (item.path, item.evidence_type))
        ),
        reasons=reasons,
        prerequisites=scanner.prerequisites,
        prerequisite_status=prerequisite_state,
        status=status,
        resource_class=resource_class,
    )


def _is_large_component(component: ComponentProfile, policy: ProfilerPolicy) -> bool:
    return (
        component.file_count >= policy.large_component_file_threshold
        or component.total_bytes >= policy.large_component_byte_threshold
    )


def _sast_targets(
    profile: ProjectProfile,
    component: ComponentProfile,
    *,
    scanner_id: str,
    policy: ProfilerPolicy,
) -> tuple[tuple[str, ...], ...]:
    """Return stable bounded scopes for expensive SAST on large components.

    Semgrep can safely receive multiple directory/file targets. CodeQL keeps
    one component source root so cross-file data-flow queries remain intact.
    """
    if scanner_id != "semgrep-ce" or not _is_large_component(component, policy):
        return ((component.root,),)
    root = PurePosixPath(component.root)
    candidates: set[str] = set()
    for item in profile.inventory:
        if item.category.value != "source":
            continue
        path = PurePosixPath(item.path)
        if component.root != "." and not _path_within(path, root):
            continue
        relative = path.relative_to(root) if component.root != "." else path
        if len(relative.parts) <= 1:
            candidates.add(path.as_posix())
        else:
            first = relative.parts[0]
            candidates.add(
                (root / first).as_posix() if component.root != "." else first
            )
    if not candidates:
        return ((component.root,),)
    ordered = sorted(candidates, key=str.casefold)
    chunks = [
        tuple(ordered[index : index + policy.sast_chunk_size])
        for index in range(0, len(ordered), policy.sast_chunk_size)
    ]
    return tuple(chunks)


def _path_within(path: PurePosixPath, root: PurePosixPath) -> bool:
    return path == root or root in path.parents


def _coalesce_codeql(tasks: list[ScanTask]) -> list[ScanTask]:
    """Reuse a covering source root; keep evidence of every covered component."""
    output = [t for t in tasks if t.scanner_id != "codeql-cli"]
    selected: list[ScanTask] = []
    for task in sorted(
        (t for t in tasks if t.scanner_id == "codeql-cli"),
        key=lambda t: (len(PurePosixPath(t.target_paths[0]).parts), t.task_id),
    ):
        language = (
            "javascript"
            if task.language_or_ecosystem in {"javascript", "typescript"}
            else task.language_or_ecosystem
        )
        task = replace(task, language_or_ecosystem=language)
        for index, parent in enumerate(selected):
            same_policy = (
                parent.language_or_ecosystem,
                parent.status,
                parent.exclusions,
                parent.rule_references,
                parent.prerequisites,
                parent.mode,
            ) == (
                task.language_or_ecosystem,
                task.status,
                task.exclusions,
                task.rule_references,
                task.prerequisites,
                task.mode,
            )
            covers = parent.target_paths[0] == "." or _path_within(
                PurePosixPath(task.target_paths[0]),
                PurePosixPath(parent.target_paths[0]),
            )
            # Custom path-sensitive exclusions must not silently remove child
            # coverage. Keep separate scopes unless policy is the standard one.
            standard_exclusions = set(ProfilerPolicy().sast_exclusions)
            if (
                same_policy
                and covers
                and (
                    parent.target_paths == task.target_paths
                    or set(task.exclusions) <= standard_exclusions
                )
            ):
                selected[index] = replace(
                    parent,
                    evidence=tuple(
                        sorted(
                            set(parent.evidence + task.evidence),
                            key=lambda e: (e.path, e.evidence_type, e.detail),
                        )
                    ),
                    reasons=parent.reasons
                    + (
                        f"Also covers {task.component_id} at {task.target_paths[0]} ({language}); shared database avoids duplicate extraction.",
                    ),
                )
                break
        else:
            selected.append(task)
    return output + selected


def _prerequisite_state(
    scanner: ScannerCapability,
    policy: ProfilerPolicy,
) -> PrerequisiteState:
    states = [
        policy.prerequisite_states.get(name, PrerequisiteState.UNVERIFIED)
        for name in scanner.prerequisites
    ]
    if any(state == PrerequisiteState.MISSING for state in states):
        return PrerequisiteState.MISSING
    if states and all(state == PrerequisiteState.AVAILABLE for state in states):
        return PrerequisiteState.AVAILABLE
    return PrerequisiteState.UNVERIFIED


def _sast_complement_reason(scanner_id: str) -> str:
    if scanner_id == "semgrep-ce":
        return "Semgrep provides fast rule-based pattern coverage."
    return "CodeQL adds query-based data-flow coverage complementary to Semgrep."


def _deduplicate_tasks(tasks: list[ScanTask]) -> list[ScanTask]:
    unique: dict[str, ScanTask] = {}
    for task in tasks:
        # Semgrep's configured rules are language-aware and can scan a mixed
        # JavaScript/TypeScript scope in one invocation. Do not run the exact
        # same target twice merely because profiling found two language labels.
        if task.scanner_id == "semgrep-ce":
            identity = "|".join(
                (
                    task.scanner_id,
                    task.scan_type.value,
                    task.component_id or "project",
                    ",".join(task.target_paths),
                    task.mode,
                )
            )
        else:
            identity = task.task_id
        unique.setdefault(identity, task)
    return list(unique.values())
