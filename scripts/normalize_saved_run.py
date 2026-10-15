"""Normalize one completed scanner run without merging or reviewing findings."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Callable

from security_reviewer_v2.normalization.codeql import (
    NormalizationInputError,
    normalize_codeql_sarif_file,
)
from security_reviewer_v2.normalization.gitleaks import normalize_gitleaks_json_file
from security_reviewer_v2.normalization.semgrep import normalize_semgrep_json_file
from security_reviewer_v2.normalization.trivy import normalize_trivy_json_file
from security_reviewer_v2.normalization.models import NormalizationResult


NORMALIZERS: dict[str, Callable[[Path], NormalizationResult]] = {
    "codeql-cli": normalize_codeql_sarif_file,
    "semgrep-ce": normalize_semgrep_json_file,
    "gitleaks": normalize_gitleaks_json_file,
    "trivy": normalize_trivy_json_file,
}


def normalize_run(run_directory: Path, output_directory: Path) -> dict:
    """Write one normalized file per raw output and a stage-level status report."""
    run = run_directory.resolve()
    output = output_directory.resolve()
    if not run.is_dir():
        raise ValueError(f"Scanner run directory is unavailable: {run}")
    try:
        execution = json.loads((run / "execution-summary.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Scanner execution summary is unavailable or invalid") from error
    if not isinstance(execution, dict) or execution.get("run_id") != run.name:
        raise ValueError("Execution summary does not match the selected run directory")
    if not isinstance(execution.get("tasks"), list):
        raise ValueError("Execution summary has no task list")
    output.mkdir(parents=True, exist_ok=True)

    records: list[dict] = []
    for task in execution["tasks"]:
        scanner_id = task["scanner_id"]
        task_id = task["task_id"]
        raw_outputs = task.get("raw_outputs", [])
        if task.get("status") != "completed":
            records.append({
                "scanner_id": scanner_id, "task_id": task_id,
                "status": "not_normalized", "reason": f"Scanner task status: {task.get('status')}",
                "raw_output": None, "normalized_output": None,
                "input_results": 0, "normalized_findings": 0, "skipped_results": 0,
                "warning_count": 0,
            })
            continue
        normalizer = NORMALIZERS.get(scanner_id)
        if normalizer is None or not isinstance(raw_outputs, list) or not raw_outputs:
            records.append({
                "scanner_id": scanner_id, "task_id": task_id,
                "status": "failed", "reason": "No supported normalizer or raw output",
                "raw_output": None, "normalized_output": None,
                "input_results": 0, "normalized_findings": 0, "skipped_results": 0,
                "warning_count": 0,
            })
            continue
        for index, relative in enumerate(raw_outputs):
            try:
                if not isinstance(relative, str) or Path(relative).is_absolute():
                    raise ValueError("Raw output path is not relative")
                source = (run / relative).resolve()
                if not source.is_relative_to(run) or not source.is_file():
                    raise ValueError("Raw output is missing or outside the scanner run")
                normalized = normalizer(source)
                destination = (
                    output / scanner_id / task_id / f"result-{index}.normalized.json"
                ).resolve()
                if not destination.is_relative_to(output):
                    raise ValueError("Normalized output path escaped its directory")
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(
                    json.dumps(normalized.to_dict(), indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                records.append({
                    "scanner_id": scanner_id, "task_id": task_id,
                    "status": normalized.status.value,
                    "reason": None,
                    "raw_output": relative,
                    "normalized_output": destination.relative_to(output).as_posix(),
                    "input_results": normalized.summary.input_results,
                    "normalized_findings": normalized.summary.normalized_findings,
                    "skipped_results": normalized.summary.skipped_results,
                    "warning_count": len(normalized.warnings),
                })
            except (NormalizationInputError, OSError, ValueError) as error:
                records.append({
                    "scanner_id": scanner_id, "task_id": task_id,
                    "status": "failed", "reason": str(error),
                    "raw_output": relative, "normalized_output": None,
                    "input_results": 0, "normalized_findings": 0, "skipped_results": 0,
                    "warning_count": 0,
                })

    complete = sum(item["status"] == "complete" for item in records)
    status = "completed" if complete == len(records) and records else (
        "partial" if complete else "failed"
    )
    summary = {
        "schema_version": "1.0",
        "source_run_id": execution["run_id"],
        "status": status,
        "source_execution_status": execution.get("status"),
        "input_results": sum(item["input_results"] for item in records),
        "normalized_findings": sum(item["normalized_findings"] for item in records),
        "skipped_results": sum(item["skipped_results"] for item in records),
        "warning_count": sum(item["warning_count"] for item in records),
        "coverage_gaps": execution.get("coverage_gaps", []),
        "outputs": records,
    }
    (output / "normalization-summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Normalize only a saved scanner run")
    parser.add_argument("run_directory", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        summary = normalize_run(args.run_directory, args.output)
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps(summary, indent=2))
    return 0 if summary["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
