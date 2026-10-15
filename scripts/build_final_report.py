"""Build policy and human-readable report from a saved review bundle."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from security_reviewer_v2.policy import evaluate_policy
from security_reviewer_v2.reporting import write_final_report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--project", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--triage", type=Path, help="optional candidate triage artifact")
    parser.add_argument("--verification", type=Path, help="optional source-verification artifact")
    args = parser.parse_args()
    bundle = json.loads(args.bundle.read_text(encoding="utf-8"))
    review = bundle.get("review", bundle)
    triage = json.loads(args.triage.read_text(encoding="utf-8")) if args.triage else None
    verification = json.loads(args.verification.read_text(encoding="utf-8")) if args.verification else None
    policy = evaluate_policy(review, triage_payload=triage).to_dict()
    args.output.mkdir(parents=True, exist_ok=True)
    def saved(name: str) -> dict | None:
        path = args.output / name
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None

    summary = saved("pre-review-summary.json") or {}
    (args.output / "policy-gate.json").write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8")
    write_final_report(args.output / "security-review-report.md", project=args.project, review=review,
                       policy=policy, triage=triage, verification=verification,
                       isolated_pilot=saved("isolated-pilot-evidence.json"),
                       isolated_runtime=saved("isolated-runtime-evidence.json"),
                       docker_runtime=saved("docker-runtime-evidence.json"),
                       merged=saved("merged.json"), risk=saved("risk.json"),
                       execution=saved("execution.json"),
                       coverage_gaps=summary.get("coverage_gaps", []))
    print(json.dumps({"status": policy["status"], "blocking": policy["blocking"], "output": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
