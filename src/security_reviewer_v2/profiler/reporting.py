"""Human-readable rendering for project profiling results."""

from __future__ import annotations

from .models import ProfileResult


def render_markdown(result: ProfileResult) -> str:
    """Render the same profile and scan plan used by the machine-readable JSON."""
    profile = result.profile
    plan = result.scan_plan
    summary = profile.inventory_summary
    lines = [
        "# Project Profile Report",
        "",
        "> This report describes project discovery and planned security scans. It is not a vulnerability report.",
        "",
        "## Project Summary",
        "",
        f"- **Project root:** `{profile.root_name}`",
        f"- **Profiling status:** `{profile.completeness.value}`",
        f"- **Schema version:** `{profile.schema_version}`",
        f"- **Files discovered:** {summary.total_files}",
        f"- **Files skipped:** {summary.skipped_count}",
        f"- **Components:** {len(profile.components)}",
        f"- **Git metadata:** {'available' if profile.git.present else 'not detected'}",
        "",
        "## Inventory",
        "",
        "| Category | Count |",
        "|---|---:|",
    ]
    for category, count in sorted(summary.by_category.items()):
        lines.append(f"| {_cell(category)} | {count} |")
    lines.extend(["", "## Components", ""])
    if profile.components:
        for component in profile.components:
            lines.extend([
                f"### `{component.component_id}`", "",
                f"- **Root:** `{component.root}`",
                f"- **Kind:** `{component.kind}`",
                f"- **Confidence:** `{component.confidence.value}`",
                f"- **Inventory:** {component.file_count} files / {component.total_bytes} bytes",
                f"- **Languages:** {_names(component.languages)}",
                f"- **Frameworks:** {_names(component.frameworks)}",
            ])
            if component.dependency_files:
                lines.append("- **Dependency files:**")
                for dependency_file in component.dependency_files:
                    lines.append(
                        f"  - `{dependency_file.path}` ({dependency_file.ecosystem}, {dependency_file.parse_status})"
                    )
            else:
                lines.append("- **Dependency files:** none detected")
            lines.append("")
    else:
        lines.extend(["No components were detected.", ""])
    lines.extend(["## Planned Scan Tasks", ""])
    if plan.tasks:
        lines.extend([
            "| Scanner | Type | Target | Mode | Status |",
            "|---|---|---|---|---|",
        ])
        for task in plan.tasks:
            target = ", ".join(task.target_paths) or "project"
            lines.append(
                f"| `{_cell(task.scanner_id)}` | `{task.scan_type.value}` | `{_cell(target)}` | "
                f"`{_cell(task.mode)}` | `{task.status.value}` |"
            )
        lines.append("")
        for task in plan.tasks:
            lines.extend([
                f"### `{task.task_id}`", "",
                f"- **Scanner:** `{task.scanner_id}`",
                f"- **Reasons:** {_items(task.reasons)}",
                f"- **Prerequisites:** {_items(task.prerequisites)}",
                f"- **Prerequisite status:** `{task.prerequisite_status.value}`",
                f"- **Resource class:** `{task.resource_class}`",
                "",
            ])
    else:
        lines.extend(["No scan tasks were selected.", ""])
    lines.extend(["## Coverage Gaps", ""])
    lines.extend(_bullet_or_none(tuple(sorted(set(profile.coverage_gaps + plan.coverage_gaps)))))
    lines.extend(["", "## Warnings", ""])
    lines.extend(_bullet_or_none(tuple(profile.warnings) + tuple(plan.warnings)))
    lines.extend(["", "## Skipped Items", ""])
    if profile.skipped:
        lines.extend(f"- `{item.path}` — {item.reason} (`{item.cause.value}`)" for item in profile.skipped)
    else:
        lines.append("None.")
    lines.extend([
        "", "## Interpretation", "",
        "The tasks above are a plan. The Scanner Orchestrator must still verify executables, rules, databases, and other prerequisites before execution.",
        "A complete profile means project discovery completed within its limits; it does not mean every security scan ran or every dependency version is known.",
        "Runtime URLs, test accounts, and application reachability are not verified by this profiler. No DAST task in this report does not mean that dynamic testing is unnecessary.",
        "",
    ])
    return "\n".join(lines)


def _cell(value: str) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _names(items) -> str:
    values = [f"`{_cell(item.name)}`" for item in items]
    return ", ".join(values) if values else "none detected"


def _items(items) -> str:
    values = [f"`{_cell(item)}`" for item in items]
    return ", ".join(values) if values else "none recorded"


def _bullet_or_none(items: tuple[str, ...]) -> list[str]:
    return [f"- {item}" for item in items] if items else ["None."]
