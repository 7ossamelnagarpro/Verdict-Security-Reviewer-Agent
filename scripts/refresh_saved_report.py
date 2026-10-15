"""Re-render one completed run without starting a VM or scanner."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any

from security_reviewer_v2.reporting import write_final_report


def _read(directory: Path, name: str, *, required: bool = False) -> dict[str, Any] | None:
    path = directory / name
    if not path.is_file():
        if required:
            raise ValueError(f"Required saved report artifact is missing: {name}")
        return None
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict):
        raise ValueError(f"Saved report artifact must be an object: {name}")
    return payload


def refresh(directory: Path) -> Path:
    directory = directory.resolve(strict=True)
    summary = _read(directory, "pre-review-summary.json", required=True)
    merged = _read(directory, "merged.json", required=True)
    review = _read(directory, "security-review.json", required=True)
    policy = _read(directory, "policy-gate.json", required=True)
    if not isinstance(summary.get("project"), str):
        raise ValueError("Saved summary has no project identity")
    report = directory / "security-review-report.md"
    backup = directory / "security-review-report.before-observations.md"
    if report.is_file() and not backup.exists():
        shutil.copy2(report, backup)
    write_final_report(
        report, project=summary["project"], review=review, policy=policy,
        triage=_read(directory, "candidate-triage.json"),
        verification=_read(directory, "verification.json"),
        discovery=_read(directory, "ai-discovery.json"),
        discovery_required_satisfied=(summary.get("ai_discovery") or {}).get("satisfied"),
        isolated_pilot=_read(directory, "isolated-pilot-evidence.json"),
        isolated_runtime=_read(directory, "isolated-runtime-evidence.json"),
        docker_runtime=_read(directory, "docker-runtime-evidence.json"),
        merged=merged, risk=_read(directory, "risk.json"),
        execution=_read(directory, "execution.json"),
        coverage_gaps=summary.get("coverage_gaps", []),
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="directory of one completed saved run")
    args = parser.parse_args()
    path = refresh(args.output)
    print(json.dumps({"status": "rendered", "report": str(path)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
