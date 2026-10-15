"""A saved scanner run can be normalized without merging its findings."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.normalize_saved_run import normalize_run


RAW_PAYLOADS = {
    "semgrep-ce": {"version": "1.178.0", "results": [], "errors": []},
    "codeql-cli": {"version": "2.1.0", "runs": []},
    "gitleaks": [],
    "trivy": {"SchemaVersion": 2, "Results": [{"Target": "requirements.txt"}]},
}


def make_run(tmp_path: Path, scanners: tuple[str, ...]) -> Path:
    run = tmp_path / "run-example"
    run.mkdir()
    tasks = []
    for scanner in scanners:
        relative = f"{scanner}/task-{scanner}/result.json"
        source = run / relative
        source.parent.mkdir(parents=True)
        source.write_text(json.dumps(RAW_PAYLOADS[scanner]), encoding="utf-8")
        tasks.append({
            "scanner_id": scanner,
            "task_id": f"task-{scanner}",
            "status": "completed",
            "raw_outputs": [relative],
        })
    (run / "execution-summary.json").write_text(json.dumps({
        "run_id": run.name,
        "status": "completed",
        "coverage_gaps": ["Missing lockfile"],
        "tasks": tasks,
    }), encoding="utf-8")
    return run


def test_normalizes_each_scanner_separately_and_preserves_zero_results(tmp_path: Path) -> None:
    run = make_run(tmp_path, tuple(RAW_PAYLOADS))
    output = tmp_path / "normalized"

    summary = normalize_run(run, output)

    assert summary["status"] == "completed"
    assert summary["input_results"] == 0
    assert summary["normalized_findings"] == 0
    assert summary["skipped_results"] == 0
    assert summary["coverage_gaps"] == ["Missing lockfile"]
    assert len(summary["outputs"]) == 4
    assert all(item["status"] == "complete" for item in summary["outputs"])
    for item in summary["outputs"]:
        normalized = json.loads(
            (output / item["normalized_output"]).read_text(encoding="utf-8")
        )
        assert normalized["findings"] == []
    assert not (output / "merged.json").exists()


def test_missing_raw_output_is_a_failure_not_zero_findings(tmp_path: Path) -> None:
    run = make_run(tmp_path, ("semgrep-ce",))
    (run / "semgrep-ce/task-semgrep-ce/result.json").unlink()

    summary = normalize_run(run, tmp_path / "normalized")

    assert summary["status"] == "failed"
    assert summary["outputs"][0]["status"] == "failed"
    assert "missing" in summary["outputs"][0]["reason"]


def test_raw_output_cannot_escape_run_directory(tmp_path: Path) -> None:
    run = make_run(tmp_path, ("semgrep-ce",))
    execution = json.loads((run / "execution-summary.json").read_text(encoding="utf-8"))
    execution["tasks"][0]["raw_outputs"] = ["../outside.json"]
    (run / "execution-summary.json").write_text(json.dumps(execution), encoding="utf-8")

    summary = normalize_run(run, tmp_path / "normalized")

    assert summary["status"] == "failed"
    assert summary["outputs"][0]["normalized_output"] is None
