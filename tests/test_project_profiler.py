"""Behavioral tests for safe discovery, profiling, and scan planning."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from security_reviewer_v2.profiler import (
    Completeness,
    PlanStatus,
    PrerequisiteState,
    ProfilerLimits,
    ProfilerPolicy,
    profile_project,
)
from security_reviewer_v2.profiler.discovery import ProfilingInputError
from security_reviewer_v2.profiler.reporting import render_markdown
from security_reviewer_v2.profiler.review_gate import (
    ReviewAction,
    create_review_decision,
)


def write(root: Path, relative: str, content: str = "") -> Path:
    destination = root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content, encoding="utf-8")
    return destination


def test_profiles_simple_python_project_and_selects_complementary_sast(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        "pyproject.toml",
        '[project]\nname = "demo"\ndependencies = ["Flask>=3"]\n',
    )
    write(tmp_path, "app.py", "from flask import Flask\napp = Flask(__name__)\n")

    result = profile_project(tmp_path)

    component = result.profile.components[0]
    assert [item.name for item in component.languages] == ["python"]
    flask = next(item for item in component.frameworks if item.name == "flask")
    assert flask.confidence.value == "high"
    sast_scanners = {
        task.scanner_id
        for task in result.scan_plan.tasks
        if task.scan_type.value == "sast"
    }
    assert sast_scanners == {"semgrep-ce", "codeql-cli"}


def test_profiles_typescript_manifest_and_resolved_lockfile(tmp_path: Path) -> None:
    write(
        tmp_path,
        "package.json",
        json.dumps({"name": "web", "dependencies": {"express": "^5.0.0"}}),
    )
    write(
        tmp_path,
        "package-lock.json",
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "web"},
                    "node_modules/express": {"name": "express", "version": "5.1.0"},
                },
            }
        ),
    )
    write(tmp_path, "src/server.ts", "import express from 'express';\nexpress();\n")

    result = profile_project(tmp_path)

    component = result.profile.components[0]
    assert [item.name for item in component.languages] == ["typescript"]
    lockfile = next(
        item for item in component.dependency_files if item.kind == "lockfile"
    )
    assert lockfile.parse_status == "parsed_resolved"
    assert lockfile.dependencies[0].version == "5.1.0"


def test_monorepo_keeps_backend_frontend_and_infrastructure_separate(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        "package.json",
        json.dumps({"private": True, "workspaces": ["frontend"]}),
    )
    write(tmp_path, "backend/pyproject.toml", '[project]\nname="api"\n')
    write(tmp_path, "backend/api.py", "print('not executed')\n")
    write(tmp_path, "frontend/package.json", json.dumps({"name": "frontend"}))
    write(tmp_path, "frontend/index.ts", "export const value = 1;\n")
    write(tmp_path, "infrastructure/main.tf", 'resource "null_resource" "x" {}\n')

    result = profile_project(tmp_path)

    roots = {component.root: component.kind for component in result.profile.components}
    assert roots["."] == "workspace"
    assert roots["backend"] == "application"
    assert roots["frontend"] == "application"
    assert roots["infrastructure"] == "infrastructure"
    backend = next(item for item in result.profile.components if item.root == "backend")
    frontend = next(
        item for item in result.profile.components if item.root == "frontend"
    )
    assert [item.name for item in backend.languages] == ["python"]
    assert [item.name for item in frontend.languages] == ["typescript"]


def test_vendor_only_language_is_not_application_evidence(tmp_path: Path) -> None:
    write(tmp_path, "vendor/library.py", "print('vendor')\n")
    write(tmp_path, "README.md", "No application source here.\n")

    result = profile_project(tmp_path)

    assert not result.profile.components[0].languages
    assert any(item.path == "vendor" for item in result.profile.skipped)


def test_framework_dependency_without_import_has_low_confidence(tmp_path: Path) -> None:
    write(
        tmp_path, "pyproject.toml", '[project]\nname="demo"\ndependencies=["Flask"]\n'
    )
    write(tmp_path, "app.py", "value = 'Flask is only text'\n")

    result = profile_project(tmp_path)

    framework = result.profile.components[0].frameworks[0]
    assert framework.name == "flask"
    assert framework.confidence.value == "low"
    assert {item.evidence_type for item in framework.evidence} == {
        "dependency_declaration"
    }


def test_no_git_still_plans_current_file_secret_scan(tmp_path: Path) -> None:
    write(tmp_path, "main.py", "value = 1\n")

    result = profile_project(tmp_path)

    assert result.profile.git.present is False
    tasks = [
        task
        for task in result.scan_plan.tasks
        if task.scanner_id == "gitleaks" and task.mode == "directory"
    ]
    assert len(tasks) == 1


def test_missing_dependency_manifest_is_a_visible_coverage_gap(tmp_path: Path) -> None:
    write(tmp_path, "app.py", "from flask import Flask\napp = Flask(__name__)\n")

    result = profile_project(tmp_path)

    assert result.profile.completeness == Completeness.COMPLETE
    assert any(
        "no supported manifest or lockfile" in gap
        for gap in result.profile.coverage_gaps
    )
    assert not any(task.scan_type.value == "sca" for task in result.scan_plan.tasks)
    assert "no supported manifest or lockfile" in render_markdown(result)


def test_manifest_without_lockfile_plans_sca_and_reports_version_limit(
    tmp_path: Path,
) -> None:
    write(tmp_path, "app.py", "from flask import Flask\napp = Flask(__name__)\n")
    write(tmp_path, "requirements.txt", "Flask==3.1.3\n")

    result = profile_project(tmp_path)

    assert any(
        task.scan_type.value == "sca" and task.scanner_id == "trivy"
        for task in result.scan_plan.tasks
    )
    assert result.profile.components[0].frameworks[0].confidence.value == "high"
    assert any("no supported lockfile" in gap for gap in result.profile.coverage_gaps)
    assert "no supported lockfile" in render_markdown(result)


def test_security_lab_fixture_keeps_labels_outside_scan_root() -> None:
    project = Path(__file__).resolve().parents[1]
    target = project / "targets" / "security-lab-web"
    ground_truth = project / "benchmark" / "security_lab_web_ground_truth.json"

    result = profile_project(target)

    assert ground_truth.is_file()
    assert not (target / "ground_truth.json").exists()
    assert all("ground_truth" not in item.path for item in result.profile.inventory)
    assert any(
        task.scan_type.value == "sca" and task.scanner_id == "trivy"
        for task in result.scan_plan.tasks
    )


def test_git_worktree_file_is_distinguished_from_git_directory(tmp_path: Path) -> None:
    write(tmp_path, ".git", "gitdir: ../repo/.git/worktrees/demo\n")
    write(tmp_path, "main.py", "value = 1\n")

    result = profile_project(tmp_path)

    assert result.profile.git.present is True
    assert result.profile.git.marker_kind == "worktree_file"
    assert any(task.mode == "git_history" for task in result.scan_plan.tasks)


def test_dockerfile_plans_misconfiguration_but_not_an_image_scan(
    tmp_path: Path,
) -> None:
    write(tmp_path, "Dockerfile", "FROM python:3.13\n")
    write(tmp_path, "main.py", "value = 1\n")

    result = profile_project(tmp_path)

    assert result.profile.targets.dockerfiles == ("Dockerfile",)
    assert any(
        task.scan_type.value == "misconfiguration" for task in result.scan_plan.tasks
    )
    image_task = next(
        task
        for task in result.scan_plan.tasks
        if task.scan_type.value == "container_image"
    )
    assert image_task.status == PlanStatus.NOT_APPLICABLE
    assert image_task.target_paths == ()


def test_env_ignored_by_git_remains_in_secret_scope(tmp_path: Path) -> None:
    write(tmp_path, ".gitignore", ".env\n")
    write(tmp_path, ".env", "EXAMPLE_PLACEHOLDER=value\n")
    write(tmp_path, "main.py", "value = 1\n")

    result = profile_project(tmp_path)

    assert ".env" in result.profile.targets.secret_candidate_files
    secret_task = next(
        task for task in result.scan_plan.tasks if task.scanner_id == "gitleaks"
    )
    assert ".env" not in secret_task.exclusions


def test_malformed_manifest_is_reported_without_aborting(tmp_path: Path) -> None:
    write(tmp_path, "package.json", "{ definitely not valid json")
    write(tmp_path, "index.js", "console.log('safe fixture');\n")

    result = profile_project(tmp_path)

    dependency_file = result.profile.components[0].dependency_files[0]
    assert dependency_file.parse_status == "invalid"
    assert any(
        "Invalid dependency file" in warning for warning in result.profile.warnings
    )
    assert any("incomplete" in gap for gap in result.profile.coverage_gaps)


def test_unsupported_language_is_visible_as_coverage_gap(tmp_path: Path) -> None:
    write(tmp_path, "index.php", "<?php echo 'fixture'; ?>\n")

    result = profile_project(tmp_path)

    assert [item.name for item in result.profile.components[0].languages] == ["php"]
    assert any(
        "supports language 'php'" in gap for gap in result.scan_plan.coverage_gaps
    )
    assert "supports language 'php'" in render_markdown(result)


def test_missing_prerequisite_blocks_only_affected_tasks(tmp_path: Path) -> None:
    write(tmp_path, "main.py", "value = 1\n")
    policy = ProfilerPolicy(
        prerequisite_states={
            "codeql_executable": PrerequisiteState.MISSING,
            "language_query_pack": PrerequisiteState.AVAILABLE,
            "semgrep_executable": PrerequisiteState.AVAILABLE,
            "semgrep_rules": PrerequisiteState.AVAILABLE,
        }
    )

    result = profile_project(tmp_path, policy=policy)

    codeql = next(
        task for task in result.scan_plan.tasks if task.scanner_id == "codeql-cli"
    )
    semgrep = next(
        task for task in result.scan_plan.tasks if task.scanner_id == "semgrep-ce"
    )
    assert codeql.status == PlanStatus.BLOCKED
    assert semgrep.status == PlanStatus.SELECTED


def test_symlink_outside_root_is_never_followed(tmp_path: Path) -> None:
    project = tmp_path / "project"
    outside = tmp_path / "outside"
    project.mkdir()
    outside.mkdir()
    write(outside, "outside.py", "value = 1\n")
    link = project / "linked"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"Symlink creation is unavailable on this Windows setup: {error}")

    default_result = profile_project(project)
    allowed_result = profile_project(
        project, policy=ProfilerPolicy(allow_symlinks=True)
    )

    assert any(
        item.path == "linked" and item.cause.value == "symlink"
        for item in default_result.profile.skipped
    )
    assert any(
        item.path == "linked" and item.cause.value == "outside_root"
        for item in allowed_result.profile.skipped
    )
    assert all(
        item.path != "linked/outside.py" for item in allowed_result.profile.inventory
    )


def test_file_limit_marks_profile_partial_and_reports_skip(tmp_path: Path) -> None:
    write(tmp_path, "a.py", "a = 1\n")
    write(tmp_path, "b.py", "b = 2\n")

    result = profile_project(tmp_path, limits=ProfilerLimits(max_files=1))

    assert result.profile.completeness == Completeness.PARTIAL
    assert any(item.cause.value == "resource_limit" for item in result.profile.skipped)
    assert result.scan_plan.warnings


def test_content_evidence_limit_does_not_claim_files_were_omitted(
    tmp_path: Path,
) -> None:
    write(tmp_path, "main.py", "from flask import Flask\napp = Flask(__name__)\n")

    result = profile_project(
        tmp_path,
        limits=ProfilerLimits(max_total_content_bytes=1),
    )

    assert result.profile.completeness == Completeness.COMPLETE
    assert result.profile.inventory_summary.total_files == 1
    assert any("Content-reading limits" in gap for gap in result.profile.coverage_gaps)


def test_large_component_splits_semgrep_but_keeps_codeql_component_scope(
    tmp_path: Path,
) -> None:
    write(tmp_path, "package.json", json.dumps({"name": "large"}))
    for index in range(5):
        write(tmp_path, f"src{index}/module.py", "value = 1\n")
    policy = ProfilerPolicy(
        large_component_file_threshold=3,
        large_component_byte_threshold=1_000_000,
        sast_chunk_size=2,
    )

    result = profile_project(tmp_path, policy=policy)

    semgrep = [
        task for task in result.scan_plan.tasks if task.scanner_id == "semgrep-ce"
    ]
    codeql = [
        task for task in result.scan_plan.tasks if task.scanner_id == "codeql-cli"
    ]
    assert len(semgrep) == 3
    assert all(task.resource_class == "large" for task in semgrep + codeql)
    assert all(len(task.target_paths) <= 2 for task in semgrep)
    assert all(task.target_paths == (".",) for task in codeql)
    assert all("scoped SAST targets" in task.reasons[-2] for task in semgrep)


def test_semgrep_does_not_duplicate_mixed_language_scope(tmp_path: Path) -> None:
    write(tmp_path, "package.json", json.dumps({"name": "mixed"}))
    write(tmp_path, "app.js", "const value = 1\n")
    write(tmp_path, "app.ts", "const value: number = 1\n")

    result = profile_project(tmp_path)

    semgrep = [
        task for task in result.scan_plan.tasks if task.scanner_id == "semgrep-ce"
    ]
    assert len(semgrep) == 1


def test_explicit_policy_disables_scanner_without_hiding_decision(
    tmp_path: Path,
) -> None:
    write(tmp_path, "main.py", "value = 1\n")
    policy = ProfilerPolicy(
        enabled_scanners=("codeql-cli", "gitleaks", "trivy"),
        disabled_scanners=("semgrep-ce",),
    )

    result = profile_project(tmp_path, policy=policy)

    semgrep = next(
        task for task in result.scan_plan.tasks if task.scanner_id == "semgrep-ce"
    )
    assert semgrep.status == PlanStatus.DISABLED_BY_POLICY


def test_results_are_stable_and_tasks_are_deduplicated(tmp_path: Path) -> None:
    write(
        tmp_path, "pyproject.toml", '[project]\nname="demo"\ndependencies=["Flask"]\n'
    )
    write(tmp_path, "app.py", "from flask import Flask\n")

    first = profile_project(tmp_path).to_dict()
    second = profile_project(tmp_path).to_dict()

    assert first == second
    task_ids = [item["task_id"] for item in first["scan_plan"]["tasks"]]
    assert len(task_ids) == len(set(task_ids))
    assert "timestamp" not in json.dumps(first).casefold()


def test_profiler_does_not_execute_project_scripts(tmp_path: Path) -> None:
    marker = tmp_path / "executed.txt"
    write(
        tmp_path,
        "setup.py",
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n",
    )
    write(tmp_path, "main.py", "value = 1\n")

    profile_project(tmp_path)

    assert not marker.exists()


def test_invalid_project_path_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ProfilingInputError):
        profile_project(tmp_path / "missing")


def test_profiler_source_text_does_not_create_framework_false_positives(
    tmp_path: Path,
) -> None:
    write(tmp_path, "pyproject.toml", '[project]\nname="demo"\n')
    write(
        tmp_path,
        "detector.py",
        "MARKERS = ('from django', 'from fastapi', 'from flask')\n",
    )

    result = profile_project(tmp_path)

    assert result.profile.components[0].frameworks == ()


def test_markdown_report_uses_profile_and_plan(tmp_path: Path) -> None:
    write(tmp_path, "app.py", "from flask import Flask\n")

    report = render_markdown(profile_project(tmp_path))

    assert "# Project Profile Report" in report
    assert "## Project Summary" in report
    assert "## Planned Scan Tasks" in report
    assert "`semgrep-ce`" in report
    assert "## Coverage Gaps" in report


def test_review_gate_supports_planned_broad_and_cancel_without_mutating_plan(
    tmp_path: Path,
) -> None:
    write(tmp_path, "app.py", "print('demo')\n")
    result = profile_project(tmp_path)
    original_plan = result.scan_plan

    planned = create_review_decision(result, ReviewAction.APPROVE_PLAN)
    broad = create_review_decision(result, ReviewAction.BROAD_SCAN)
    cancelled = create_review_decision(result, ReviewAction.CANCEL)

    assert planned.execution_scope == "planned"
    assert broad.execution_scope == "broad"
    assert cancelled.execution_scope == "none"
    assert planned.approved is True
    assert cancelled.approved is False
    assert result.scan_plan == original_plan
