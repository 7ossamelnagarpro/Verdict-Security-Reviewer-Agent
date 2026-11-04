"""Behavioral coverage for bounded, non-redundant CodeQL execution."""

import json
import sys
from dataclasses import replace
from pathlib import Path

from test_scanner_orchestrator import FakeAdapter, make_plan, make_task

from security_reviewer_v2.orchestrator import OrchestratorPolicy, ScannerOrchestrator
from security_reviewer_v2.profiler import profile_project
from security_reviewer_v2.scanners import AdapterRegistry
from security_reviewer_v2.scanners.codeql import CodeQLAdapter, CodeQLConfig
from security_reviewer_v2.scanners.models import ExecutionRequest


def test_nested_mixed_languages_share_database_and_preserve_evidence(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "main.js").write_text("let x=1")
    (tmp_path / "frontend").mkdir()
    (tmp_path / "frontend/package.json").write_text("{}")
    (tmp_path / "frontend/main.ts").write_text("let y:number=1")
    profile = profile_project(tmp_path)
    tasks = [t for t in profile.scan_plan.tasks if t.scanner_id == "codeql-cli"]
    assert len(tasks) == 1
    assert tasks[0].target_paths == (".",)
    assert tasks[0].language_or_ecosystem == "javascript"
    assert any(e.path.startswith("frontend/") for e in tasks[0].evidence)
    assert profile.to_dict() == profile_project(tmp_path).to_dict()


def test_independent_components_remain_independent(tmp_path):
    for name in ("api", "web"):
        folder = tmp_path / name
        folder.mkdir()
        (folder / "package.json").write_text("{}")
        (folder / "main.ts").write_text("let x=1")
    tasks = [
        t
        for t in profile_project(tmp_path).scan_plan.tasks
        if t.scanner_id == "codeql-cli"
    ]
    assert {t.target_paths for t in tasks} == {("api",), ("web",)}


def test_codeql_stage_budgets_resources_and_exclusions(tmp_path):
    task = replace(
        make_task("codeql-cli"),
        mode="standard_query_suite",
        language_or_ecosystem="javascript",
        exclusions=("**/node_modules/**",),
    )
    config = CodeQLConfig(
        executable=str(Path(sys.executable)),
        query_suites={"javascript": str(tmp_path / "javascript-security-extended.qls")},
        threads=2,
        ram_mb=4096,
        extraction_timeout_seconds=10,
        analysis_timeout_seconds=20,
    )
    request = ExecutionRequest("test", task, str(tmp_path), str(tmp_path), 30)
    plan = CodeQLAdapter(config).build_execution_plan(request)
    assert [c.timeout_seconds for c in plan.commands] == [10, 20]
    assert "--language=javascript-typescript" in plan.commands[0].arguments
    assert "--ram=4096" in plan.commands[1].arguments
    assert json.loads((tmp_path / "extraction-config.json").read_text()) == {
        "paths-ignore": ["**/node_modules/**"]
    }


def test_scanner_budget_override_reaches_runner(tmp_path):
    class RecordingAdapter(FakeAdapter):
        def build_execution_plan(self, request):
            self.budget = request.timeout_seconds
            return super().build_execution_plan(request)

    adapter = RecordingAdapter("fake")
    summary = ScannerOrchestrator(
        AdapterRegistry((adapter,)),
        policy=OrchestratorPolicy(
            task_timeout_seconds=0.001, scanner_timeouts={"fake": 5}
        ),
    ).execute(
        make_plan(make_task("fake")), project_root=tmp_path, runs_root=tmp_path / "runs"
    )
    assert adapter.budget == 5
    assert summary.status.value == "completed"
