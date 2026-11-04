"""Re-ground saved AI candidates and re-triage without runtime, scanner, or AI calls.

Writes a separate derivative directory. The original scan and its security
review remain immutable; newly formed groups still require security review.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from security_reviewer_v2.context.candidate_collector import collect_candidate_context
from security_reviewer_v2.discovery.agent import reground_saved_discovery
from security_reviewer_v2.discovery.serialization import load_discovery_result
from security_reviewer_v2.normalization import load_merge_result
from security_reviewer_v2.triage import triage_candidates
from security_reviewer_v2.verification import verify_discovery


def _read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def _attest_snapshot(project: Path, profile: dict[str, Any]) -> None:
    snapshot = profile.get("project_snapshot")
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("files"), list):
        raise ValueError("Saved profile lacks an attested file inventory")
    if os.path.normcase(str(project)) != os.path.normcase(
        str(snapshot.get("root_path", ""))
    ):
        raise ValueError("Saved profile belongs to a different project root")
    if not snapshot["files"]:
        raise ValueError("Saved source inventory is empty")
    for item in snapshot["files"]:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("path"), str)
            or not isinstance(item.get("sha256"), str)
        ):
            raise ValueError("Saved source inventory contains an invalid entry")
        source = (project / item["path"]).resolve(strict=True)
        if not source.is_relative_to(project) or not source.is_file():
            raise ValueError(
                f"Saved source path is outside the project: {item['path']}"
            )
        if hashlib.sha256(source.read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError(f"Source changed since the saved scan: {item['path']}")


def _write(path: Path, value: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def reverify(report_dir: Path, output_dir: Path) -> dict[str, Any]:
    report_dir = report_dir.resolve(strict=True)
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise ValueError(
            "Choose a new output directory; saved reports are never overwritten"
        )
    summary = _read_object(report_dir / "pre-review-summary.json")
    profile = _read_object(report_dir / "profile.json")
    previous_verification = _read_object(report_dir / "verification.json")
    previous_triage = _read_object(report_dir / "candidate-triage.json")
    project_name = summary.get("project")
    if summary.get("status") != "completed" or not isinstance(project_name, str):
        raise ValueError(
            "Source report must be a completed scan with a project identity"
        )
    project = Path(project_name).resolve(strict=True)
    if output_dir.is_relative_to(report_dir) or output_dir.is_relative_to(project):
        raise ValueError(
            "Output directory must be outside the saved report and scanned source tree"
        )
    _attest_snapshot(project, profile)

    discovery = load_discovery_result(report_dir / "ai-discovery.json")
    merged = load_merge_result(report_dir / "merged.json")
    regrounded = reground_saved_discovery(
        discovery, project_root=project, profile_artifact=profile
    )
    context = collect_candidate_context(
        regrounded, project_root=project, profile_artifact=profile
    )
    if context.summary.unavailable_locations:
        raise ValueError("Saved candidate source context is no longer fully available")
    verification = verify_discovery(
        regrounded, project_root=project, candidate_context=context
    )
    triage = triage_candidates(regrounded, verification, merged, project_root=project)

    before = previous_triage.get("summary") or {}
    result = {
        "status": "postscan_source_reverification",
        "source_report": str(report_dir),
        "source_sha256_attested": True,
        "vm_scanner_and_ai_calls": 0,
        "security_review_rerun": False,
        "vulnerability_verdicts_unchanged": True,
        "old_verification": {
            "confirmed_source": sum(
                item.get("disposition") == "confirmed"
                for item in previous_verification.get("records", [])
            ),
            "needs_more_evidence": sum(
                item.get("disposition") == "needs_more_evidence"
                for item in previous_verification.get("records", [])
            ),
        },
        "new_verification": {
            "confirmed_source": sum(
                item.disposition.value == "confirmed" for item in verification.records
            ),
            "needs_more_evidence": sum(
                item.disposition.value == "needs_more_evidence"
                for item in verification.records
            ),
        },
        "old_triage": before,
        "new_triage": triage.to_dict()["summary"],
        "note": "Confirmed source evidence is not a confirmed vulnerability. New issue groups require separate security review.",
    }
    output_dir.mkdir(parents=True)
    _write(output_dir / "ai-discovery-regrounded.json", regrounded.to_dict())
    _write(output_dir / "candidate-context.json", context.to_dict())
    _write(output_dir / "verification.json", verification.to_dict())
    _write(output_dir / "candidate-triage.json", triage.to_dict())
    _write(output_dir / "postscan-summary.json", result)
    return {**result, "output": str(output_dir)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report_dir", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(
        json.dumps(reverify(args.report_dir, args.output), ensure_ascii=False, indent=2)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
