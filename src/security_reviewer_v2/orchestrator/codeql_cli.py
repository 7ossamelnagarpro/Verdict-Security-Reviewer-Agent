"""Repeatable isolated CodeQL runs, one source-root/language task per run."""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import replace
from pathlib import Path

from security_reviewer_v2.profiler import profile_project
from security_reviewer_v2.profiler.models import _to_primitive
from security_reviewer_v2.scanners import AdapterRegistry
from security_reviewer_v2.scanners.codeql import CodeQLAdapter, CodeQLConfig

from .service import OrchestratorPolicy, ScannerOrchestrator


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project", type=Path)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--suite",
        choices=("security-extended", "security-and-quality"),
        default="security-extended",
    )
    parser.add_argument("--threads", type=int, default=2)
    parser.add_argument("--ram-mb", type=int, default=4096)
    parser.add_argument("--extract-timeout", type=float, default=900)
    parser.add_argument("--analyze-timeout", type=float, default=1800)
    args = parser.parse_args(argv)
    bundle = args.bundle.resolve()
    suites = {}
    for language in ("javascript", "python", "ruby"):
        matches = sorted(
            bundle.glob(
                f"qlpacks/codeql/{language}-queries/*/codeql-suites/{language}-{args.suite}.qls"
            )
        )
        if len(matches) > 1:
            parser.error(
                f"Multiple {language} pack versions: select a bundle containing one version"
            )
        if matches:
            suites[language] = str(matches[0])
    adapter = CodeQLAdapter(
        CodeQLConfig(
            executable=str(bundle / ("codeql.exe" if os.name == "nt" else "codeql")),
            query_suites=suites,
            search_path=str(bundle / "qlpacks"),
            threads=args.threads,
            ram_mb=args.ram_mb,
            extraction_timeout_seconds=args.extract_timeout,
            analysis_timeout_seconds=args.analyze_timeout,
        )
    )
    result = profile_project(args.project)
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "profile.json").write_text(
        json.dumps(result.to_dict(), indent=2), encoding="utf-8"
    )
    tasks = [
        replace(
            t, rule_references=(suites.get(t.language_or_ecosystem, "unavailable"),)
        )
        for t in result.scan_plan.tasks
        if t.scanner_id == "codeql-cli"
    ]
    (args.output / "codeql-plan.json").write_text(
        json.dumps(_to_primitive(tasks), indent=2), encoding="utf-8"
    )
    orchestrator = ScannerOrchestrator(
        AdapterRegistry((adapter,)),
        policy=OrchestratorPolicy(
            scanner_timeouts={"codeql-cli": args.extract_timeout + args.analyze_timeout}
        ),
    )
    summaries = []
    for task in tasks:
        print(
            f"Starting {task.task_id}: {task.language_or_ecosystem} {task.target_paths}",
            flush=True,
        )
        summary = orchestrator.execute(
            replace(result.scan_plan, tasks=(task,)),
            project_root=args.project,
            runs_root=args.output,
            run_id=task.task_id,
        )
        summaries.append(summary.to_dict())
        (args.output / "codeql-results.json").write_text(
            json.dumps(
                {
                    "suite": args.suite,
                    "planned_tasks": len(tasks),
                    "finished_tasks": len(summaries),
                    "runs": summaries,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"Finished {task.task_id}: {summary.status.value}", flush=True)
    return 0 if tasks and all(s["status"] == "completed" for s in summaries) else 1


if __name__ == "__main__":
    raise SystemExit(main())
