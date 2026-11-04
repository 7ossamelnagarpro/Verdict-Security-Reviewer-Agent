"""Post-scan, held-out evaluation of a saved Security Lab Web review.

The mapping is deliberately external to the scan root and is never passed to
the scanner or either agent. Correlation is curated, not a production deduper.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def audit_review(
    ground_truth: dict[str, Any], review: dict[str, Any], mapping: dict[str, Any]
) -> dict[str, Any]:
    gt_findings = ground_truth.get("findings", [])
    reviews = review.get("reviews", [])
    issues = mapping.get("issues", [])
    if ground_truth.get("fixture") != mapping.get("fixture"):
        raise ValueError("Ground truth and audit mapping describe different fixtures")
    gt_by_id = {
        item["id"]: item
        for item in gt_findings
        if item.get("expected_status") == "vulnerable"
    }
    review_by_id = {item["candidate_id"]: item for item in reviews}
    if len(gt_by_id) != len(
        [item for item in gt_findings if item.get("expected_status") == "vulnerable"]
    ):
        raise ValueError("Duplicate ground-truth IDs")
    if len(review_by_id) != len(reviews):
        raise ValueError("Duplicate review IDs")

    assigned: set[str] = set()
    issue_ids: set[str] = set()
    matched_gt: set[str] = set()
    audited_issues: list[dict[str, Any]] = []
    for issue in issues:
        issue_id = issue["issue_id"]
        if issue_id in issue_ids:
            raise ValueError(f"Duplicate audit issue ID: {issue_id}")
        issue_ids.add(issue_id)
        review_ids = issue["review_ids"]
        if not review_ids:
            raise ValueError(f"Audit issue has no reviews: {issue_id}")
        gt_id = issue.get("ground_truth_id")
        if gt_id is not None:
            if gt_id not in gt_by_id:
                raise ValueError(f"Unknown ground-truth ID: {gt_id}")
            if gt_id in matched_gt:
                raise ValueError(
                    f"Ground-truth case split across audit issues: {gt_id}"
                )
            matched_gt.add(gt_id)
        source_ids: set[str] = set()
        verdicts: set[str] = set()
        for review_id in review_ids:
            if review_id not in review_by_id:
                raise ValueError(f"Unknown review ID in mapping: {review_id}")
            if review_id in assigned:
                raise ValueError(
                    f"Review assigned to multiple audit issues: {review_id}"
                )
            assigned.add(review_id)
            source_ids.update(review_by_id[review_id].get("source_ids", []))
            verdicts.add(review_by_id[review_id].get("verdict", "unknown"))
        audited_issues.append(
            {
                "issue_id": issue_id,
                "ground_truth_id": gt_id,
                "review_ids": review_ids,
                "source_ids": sorted(source_ids),
                "model_verdicts": sorted(verdicts),
                "note": issue["note"],
            }
        )
    if assigned != set(review_by_id):
        raise ValueError(f"Unmapped review IDs: {sorted(set(review_by_id) - assigned)}")

    missing = [
        item["id"]
        for item in gt_findings
        if item.get("expected_status") == "vulnerable" and item["id"] not in matched_gt
    ]
    matched_review_groups = sum(
        len(item["review_ids"])
        for item in audited_issues
        if item["ground_truth_id"] is not None
    )
    outside_review_groups = len(reviews) - matched_review_groups
    return {
        "schema_version": "1.0",
        "fixture": ground_truth["fixture"],
        "evaluation_scope": "saved_security_review_only",
        "review_status": review.get("status", "unknown"),
        "reviewed_groups": len(reviews),
        "audited_issue_buckets": len(audited_issues),
        "groups_collapsed_within_audit_buckets": len(reviews) - len(audited_issues),
        "ground_truth_positive_cases": len(gt_by_id),
        "ground_truth_matched_cases": len(matched_gt),
        "ground_truth_missed_ids": missing,
        "positive_case_recall": round(len(matched_gt) / len(gt_by_id), 4)
        if gt_by_id
        else None,
        "matched_review_groups": matched_review_groups,
        "outside_ground_truth_review_groups": outside_review_groups,
        "precision": None,
        "precision_note": "The fixture declares positive cases only. An unlisted claim is not automatically a false positive; precision, specificity, accuracy and F1 are not defensible from this data.",
        "scope_note": "This scores only the selected saved review groups, not every scanner/runtime result or AI candidates still awaiting evidence. A ground-truth match does not prove the model's full explanation or exploitability.",
        "issues": audited_issues,
    }


def render_audit(audit: dict[str, Any], ground_truth: dict[str, Any]) -> str:
    issue_by_gt = {
        item["ground_truth_id"]: item
        for item in audit["issues"]
        if item["ground_truth_id"] is not None
    }
    lines = [
        "# Security Lab Web — Review Quality Audit",
        "",
        "This is a **post-scan benchmark audit**. The held-out answers were not sent to the scanners or agents.",
        "The original per-group review remains unchanged for traceability.",
        "",
        "## What the numbers mean",
        "",
        f"- Raw model-reviewed groups: **{audit['reviewed_groups']}**.",
        f"- Curated issue buckets after correlating repeated claims: **{audit['audited_issue_buckets']}**. These buckets are not all proven vulnerabilities.",
        f"- Repeated review groups within those buckets: **{audit['groups_collapsed_within_audit_buckets']}**.",
        (
            f"- Declared ground-truth cases matched: **{audit['ground_truth_matched_cases']}/{audit['ground_truth_positive_cases']}** "
            f"(positive-case recall **{audit['positive_case_recall']:.1%}**)."
        ),
        f"- Review groups matching declared cases: **{audit['matched_review_groups']}**; outside the declared cases: **{audit['outside_ground_truth_review_groups']}**.",
        (
            "- Precision, accuracy and F1: **not measurable** here. The benchmark lists no safe/negative cases, "
            "and an unlisted issue is not automatically false."
        ),
        "",
        (
            "This evaluates the **saved review only**. It does not score all earlier runtime scans, and it does not "
            "promote AI candidates still waiting for evidence."
        ),
        "",
        "## Declared benchmark cases",
        "",
        "| Ground-truth ID | Case | Review result | Raw groups |",
        "| --- | --- | --- | ---: |",
    ]
    for item in ground_truth["findings"]:
        if item.get("expected_status") != "vulnerable":
            continue
        match = issue_by_gt.get(item["id"])
        lines.append(
            f"| `{item['id']}` | {item['title']} | {'Matched' if match else 'Not found in saved review'} | "
            f"{len(match['review_ids']) if match else 0} |"
        )
    lines += ["", "## Correlated review evidence", ""]
    for issue in audit["issues"]:
        if issue["ground_truth_id"] is None:
            continue
        lines += [
            f"### {issue['issue_id']} — {issue['ground_truth_id']}",
            "",
            f"- Model verdicts: {', '.join(issue['model_verdicts'])}.",
            f"- Raw review groups: {', '.join(f'`{value}`' for value in issue['review_ids'])}.",
            f"- Source IDs retained: {', '.join(f'`{value}`' for value in issue['source_ids'])}.",
            f"- Audit note: {issue['note']}",
            "",
        ]
    lines += [
        "## Claims outside the declared ground truth",
        "",
        "These are **not automatically false positives**. Several need stronger evidence or narrower wording.",
        "",
    ]
    for issue in audit["issues"]:
        if issue["ground_truth_id"] is not None:
            continue
        lines += [
            (
                f"- **{issue['issue_id']}** ({len(issue['review_ids'])} raw group(s)): {issue['note']} "
                f"Review IDs: {', '.join(f'`{value}`' for value in issue['review_ids'])}."
            )
        ]
    lines += [
        "",
        "## Important quality corrections",
        "",
        "- The target is Flask, not Django. Django ORM/template recommendations and labels in some model verdicts are inapplicable.",
        "- An exception message or SQL error text is not the same as a Python stack trace.",
        "- A missing cookie flag does not demonstrate the separate predictable-token weakness.",
        "- `/admin` exposing SSNs does not demonstrate the separate `/debug` exposure case.",
        "- Model labels such as `confirmed_vulnerability` are **model judgments**, not independent runtime proof.",
        "- The pipeline's raw policy decisions were not rewritten by this held-out audit; release decisions require independent validation.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ground-truth", type=Path, required=True)
    parser.add_argument("--review", type=Path, required=True)
    parser.add_argument("--mapping", type=Path, required=True)
    parser.add_argument("--output-prefix", type=Path, required=True)
    args = parser.parse_args()
    ground_truth = json.loads(args.ground_truth.read_text(encoding="utf-8"))
    review = json.loads(args.review.read_text(encoding="utf-8"))
    mapping = json.loads(args.mapping.read_text(encoding="utf-8"))
    result = audit_review(ground_truth, review, mapping)
    args.output_prefix.parent.mkdir(parents=True, exist_ok=True)
    args.output_prefix.with_suffix(".json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    args.output_prefix.with_suffix(".md").write_text(
        render_audit(result, ground_truth), encoding="utf-8"
    )
    print(
        json.dumps(
            {
                key: result[key]
                for key in (
                    "reviewed_groups",
                    "audited_issue_buckets",
                    "ground_truth_matched_cases",
                    "ground_truth_positive_cases",
                    "positive_case_recall",
                    "outside_ground_truth_review_groups",
                )
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
