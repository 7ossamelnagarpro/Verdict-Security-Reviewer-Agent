"""Summarise several held-out evaluations of the same lab: spread across runs and per-case stability.

An LLM-backed scan does not give the same answer twice, so one evaluation is one sample.  This reads N
``evaluation.json`` files (from ``evaluate_verdict_comprehensive.py``) and reports the mean, minimum and maximum of each
headline metric, and for every known-positive case how many runs detected it:

* stable   - detected in every run
* flaky    - detected in some runs only (the interesting ones: variance, not capability)
* never    - detected in no run

It only reads saved evaluation files; no scanner, ground truth or AI is involved.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
from statistics import mean
from typing import Any

METRICS = ("detected", "needs_review", "not_detected", "positive_case_recall_lower_bound", "positive_groups",
           "precision_on_labeled", "precision_lower_bound_in_scope", "precision_lower_bound", "safe_control_specificity",
           "safe_controls_flagged", "unlabeled_groups")


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or "cases" not in value or "summary" not in value:
        raise ValueError(f"Not an evaluation file: {path}")
    return value


def aggregate(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Spread of each metric and stability of each known-positive case across ``results``."""
    if len(results) < 2:
        raise ValueError("Aggregation needs at least two evaluations")
    targets = {item.get("target") for item in results}
    if len(targets) != 1:
        raise ValueError(f"Evaluations are for different targets: {sorted(map(str, targets))}")
    case_ids = [sorted(row["id"] for row in item["cases"]) for item in results]
    if any(ids != case_ids[0] for ids in case_ids):
        raise ValueError("Evaluations do not contain the same cases")

    metrics: dict[str, dict[str, Any]] = {}
    for name in METRICS:
        values = [item["summary"][name] for item in results if isinstance(item["summary"].get(name), (int, float))]
        if values:
            metrics[name] = {"runs": len(values), "mean": round(mean(values), 4), "min": min(values), "max": max(values)}

    detected_in: dict[str, int] = Counter()
    meta: dict[str, dict[str, Any]] = {}
    for item in results:
        for row in item["cases"]:
            if row["ground_truth"] != "confirmed_vulnerability":
                continue
            meta.setdefault(row["id"], {"category": row["category"], "location": row["location"]})
            detected_in[row["id"]] += row["status"] == "detected"
    total = len(results)
    cases = [{"id": case_id, **info, "detected_runs": detected_in[case_id], "runs": total,
              "stability": "stable" if detected_in[case_id] == total else "never" if detected_in[case_id] == 0 else "flaky"}
             for case_id, info in sorted(meta.items())]
    return {"schema_version": "1.0", "target": next(iter(targets)), "runs": total,
            "generated_at": datetime.now(timezone.utc).isoformat(), "metrics": metrics,
            "stability": dict(Counter(item["stability"] for item in cases)), "cases": cases}


def markdown(result: dict[str, Any]) -> str:
    lines = [f"# Evaluation spread · {result['runs']} runs", "", f"Target: `{result['target']}`", "",
             "| Metric | Mean | Min | Max | Runs |", "|---|---|---|---|---|"]
    lines += [f"| {name} | {item['mean']} | {item['min']} | {item['max']} | {item['runs']} |"
              for name, item in result["metrics"].items()]
    stability = result["stability"]
    lines += ["", f"Known-positive cases: **{stability.get('stable', 0)} stable**, **{stability.get('flaky', 0)} flaky** "
              f"(detected in some runs only), **{stability.get('never', 0)} never detected**.", ""]
    for label in ("flaky", "never"):
        rows = [item for item in result["cases"] if item["stability"] == label]
        lines += [f"## {label.capitalize()} cases", ""]
        lines += [f"- {item['id']} · {item['category']} · `{item['location']}` — detected {item['detected_runs']}/{item['runs']}"
                  for item in rows] or ["- None"]
        lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evaluations", type=Path, nargs="+", help="evaluation.json files of the same lab")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    result = aggregate([_read(path) for path in args.evaluations])
    args.output_dir.mkdir(parents=True, exist_ok=False)
    (args.output_dir / "aggregate.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    (args.output_dir / "aggregate.md").write_text(markdown(result), encoding="utf-8")
    print(json.dumps({"runs": result["runs"], "stability": result["stability"]}))


if __name__ == "__main__":
    main()
