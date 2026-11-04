"""Post-scan, fixture-specific coverage audit; never feed truth to the scanner.

This checks exact rule/endpoint or source anchors and final verdicts. It does
not estimate precision: the educational truth set has no negative cases.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

# Exact identities keep an upload-filename path warning from counting as the
# distinct HTML-upload-and-serve scenario, or search XSS as stored XSS.
STATIC = {
    "TT-SQLI-001": ("py/sql-injection", 135, 160),
    "TT-SQLI-002": ("py/sql-injection", 166, 180),
    "TT-XSS-001": ("py/reflective-xss", 166, 180),
    "TT-XSS-002": ("py/reflective-xss", 183, 207),
    "TT-PATH-001": ("py/path-injection", 256, 264),
    "TT-CMD-001": ("py/command-line-injection", 270, 278),
    "TT-ERROR-001": ("py/stack-trace-exposure", 135, 180),
}
RUNTIME = {
    "TT-IDOR-001": ("auth.idor", "/orders/101"),
    "TT-IDOR-002": ("auth.idor", "/profile/2"),
    "TT-XSS-001": ("web.reflected-xss", "/search"),
    "TT-XSS-002": ("web.stored-xss", "/comments"),
    "TT-AUTH-001": ("auth.broken-access-control", "/admin"),
    "TT-SESSION-001": ("web.predictable-session-token", "/login"),
    "TT-EXPOSURE-001": ("web.sensitive-data-exposure", "/debug"),
    "TT-ERROR-001": ("web.verbose-error", "/search"),
    "TT-BRUTE-001": ("web.missing-brute-force-protection", "/login"),
    "TT-CORS-001": ("web.cors-reflection", "/"),
    "TT-UPLOAD-001": ("web.insecure-file-upload", "/upload"),
}
POSITIVE_VERDICTS = {"confirmed_vulnerability", "likely_vulnerability"}


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def _static_match(case_id: str, source: dict[str, Any]) -> bool:
    signature = STATIC.get(case_id)
    if signature is None:
        return False
    rule, first, last = signature
    location = source.get("primary_location") or {}
    line = location.get("start_line")
    source_rule = str(source.get("rule_id", ""))
    if case_id == "TT-XSS-002":
        # A raw-HTML alert in the comments renderer is relevant, but is not
        # enough by itself to prove the write-then-read stored-XSS workflow.
        rule_matches = source_rule == rule or "raw-html" in source_rule
    else:
        rule_matches = source_rule == rule
    return (
        rule_matches
        and location.get("path") == "app.py"
        and type(line) is int
        and first <= line <= last
    )


def _runtime_match(case_id: str, source: dict[str, Any]) -> bool:
    signature = RUNTIME.get(case_id)
    if signature is None:
        return False
    rule, path = signature
    return (
        source.get("rule_id") == rule
        and (source.get("primary_location") or {}).get("path") == path
    )


def _runtime_facts_sufficient(
    case_id: str, facts: dict[str, Any] | None, attested_app_sha256: str | None = None
) -> bool:
    if not isinstance(facts, dict):
        return False
    if case_id in {"TT-IDOR-001", "TT-IDOR-002"}:
        return (
            facts.get("owner_status") == facts.get("cross_user_status") == 200
            and facts.get("response_equal") is True
        )
    if case_id == "TT-AUTH-001":
        return facts.get("alice_status") == 200
    if case_id == "TT-SESSION-001":
        return (
            facts.get("login_status") in {200, 302}
            and facts.get("token_shape") == "tok-<numeric-id>-staticsalt"
        )
    if case_id == "TT-EXPOSURE-001":
        keys = facts.get("response_keys")
        return (
            facts.get("status") == 200
            and isinstance(keys, list)
            and bool({"secret_key", "env"} & set(keys))
        )
    if case_id == "TT-BRUTE-001":
        # Bounded requests alone are insufficient. Only the isolated fixture's
        # source-matched direct handler and hook review can corroborate them.
        attempts, statuses = facts.get("attempt_count"), facts.get("statuses")
        return (
            type(attempts) is int
            and 5 <= attempts <= 16
            and isinstance(statuses, list)
            and len(statuses) == attempts
            and all(type(status) is int and status == 401 for status in statuses)
            and facts.get("source_guard_absent") is True
            and facts.get("source_scope") == "isolated_fixture_login_and_hooks"
            and facts.get("source_path") == "app.py"
            and type(facts.get("source_line")) is int
            and facts["source_line"] > 0
            and isinstance(attested_app_sha256, str)
            and facts.get("source_sha256") == attested_app_sha256
        )
    if case_id == "TT-CORS-001":
        return (
            facts.get("allow_origin") == "https://attacker.example"
            and facts.get("allow_credentials") == "true"
        )
    if case_id == "TT-XSS-001":
        return facts.get("status") == 200 and facts.get("payload_reflected") is True
    if case_id == "TT-XSS-002":
        return (
            facts.get("post_status") in {200, 302}
            and facts.get("get_status") == 200
            and facts.get("payload_reflected") is True
        )
    if case_id == "TT-ERROR-001":
        status = facts.get("status")
        return (
            type(status) is int
            and status >= 500
            and facts.get("error_marker_present") is True
        )
    if case_id == "TT-UPLOAD-001":
        return (
            facts.get("upload_status") in {200, 302}
            and facts.get("serve_status") == 200
            and str(facts.get("content_type", "")).split(";", 1)[0].lower()
            == "text/html"
        )
    return False


def _profile_ai_confirmed(candidate: dict[str, Any], review: dict[str, Any]) -> bool:
    anchor = candidate.get("entry_point") or {}
    missing = candidate.get("missing_check") or {}
    observation = str(missing.get("observation", "")).lower()
    return (
        review.get("verdict") in POSITIVE_VERDICTS
        and anchor.get("path") == "app.py"
        and "/profile/<int:user_id>" in str(anchor.get("code", ""))
        and "session" in observation
        and "requested" in observation
        and len(review.get("evidence") or []) > 1
    )


def evaluate(
    report_dir: Path,
    truth_path: Path,
    *,
    review_path: Path | None = None,
    triage_path: Path | None = None,
) -> dict[str, Any]:
    truth = _read(truth_path)
    expected = truth.get("findings", [])
    if len(expected) != 15 or len({case.get("id") for case in expected}) != 15:
        raise ValueError("Expected exactly 15 unique educational benchmark cases")
    merged = _read(report_dir / "merged.json")
    reviews = _read(review_path or report_dir / "security-review.json")
    discovery = _read(report_dir / "ai-discovery.json")
    docker_path = report_dir / "docker-runtime-evidence.json"
    docker = _read(docker_path) if docker_path.is_file() else {}
    attested_app_sha256 = None
    if (
        docker.get("status") == "passed"
        and docker.get("target_id") == "security-lab-web"
        and docker.get("backend") == "docker_compose"
        and docker.get("stack_removed") is True
        and isinstance(docker.get("app_sha256"), str)
    ):
        attested_app_sha256 = docker["app_sha256"]
    selected_triage_path = triage_path or report_dir / "candidate-triage.json"
    triage = (
        _read(selected_triage_path)
        if selected_triage_path.is_file()
        else {"groups": []}
    )
    if review_path is not None:
        merged_ids = {
            item.get("merged_finding_id")
            for item in merged.get("findings", [])
            if isinstance(item, dict)
        }
        candidate_ids = {
            item.get("candidate_id")
            for item in discovery.get("candidates", [])
            if isinstance(item, dict)
        }
        expected_sources = {
            group["group_id"]: (
                *group.get("scanner_finding_ids", []),
                *group.get("candidate_ids", []),
            )
            for group in triage.get("groups", [])
            if isinstance(group, dict)
        }
        if not expected_sources:
            raise ValueError(
                "A derived review requires its matching saved triage groups"
            )
        if any(
            any(
                source_id not in merged_ids
                for source_id in group.get("scanner_finding_ids", [])
            )
            or any(
                source_id not in candidate_ids
                for source_id in group.get("candidate_ids", [])
            )
            for group in triage.get("groups", [])
            if isinstance(group, dict)
        ):
            raise ValueError(
                "Derived triage groups do not match the saved scan findings"
            )
        for review in reviews.get("reviews", []):
            if (
                not isinstance(review, dict)
                or review.get("candidate_id") not in expected_sources
                or tuple(review.get("source_ids", []))
                != expected_sources[review["candidate_id"]]
            ):
                raise ValueError("Derived review and triage groups do not match")
    scanner_to_group = {
        source_id: group.get("group_id")
        for group in triage.get("groups", [])
        if isinstance(group, dict)
        for source_id in group.get("scanner_finding_ids", [])
    }
    candidate_to_group = {
        source_id: group.get("group_id")
        for group in triage.get("groups", [])
        if isinstance(group, dict)
        for source_id in group.get("candidate_ids", [])
    }
    by_review = {
        item.get("candidate_id"): item
        for item in reviews.get("reviews", [])
        if isinstance(item, dict)
    }
    candidates = {
        item.get("candidate_id"): item
        for item in discovery.get("candidates", [])
        if isinstance(item, dict)
    }
    rows: list[dict[str, Any]] = []
    for case in expected:
        case_id = case["id"]
        signals: list[str] = []
        supported: list[str] = []
        for finding in merged.get("findings", []):
            if not isinstance(finding, dict):
                continue
            finding_id = finding.get("merged_finding_id")
            group_id = scanner_to_group.get(finding_id, finding_id)
            review = by_review.get(group_id, {})
            for source in finding.get("source_findings", []):
                if not isinstance(source, dict):
                    continue
                static = _static_match(case_id, source)
                runtime = _runtime_match(case_id, source)
                if not static and not runtime:
                    continue
                signals.append(str(group_id))
                if (
                    review.get("verdict") in POSITIVE_VERDICTS
                    and review.get("evidence")
                    and (
                        (static and case_id != "TT-XSS-002")
                        or (
                            runtime
                            and _runtime_facts_sufficient(
                                case_id,
                                source.get("runtime_evidence"),
                                attested_app_sha256,
                            )
                        )
                    )
                ):
                    supported.append(str(group_id))
        if case_id == "TT-IDOR-002":
            for candidate_id, candidate in candidates.items():
                group_id = candidate_to_group.get(candidate_id, candidate_id)
                if _profile_ai_confirmed(candidate, by_review.get(group_id, {})):
                    signals.append(str(group_id))
                    supported.append(str(group_id))
        status = (
            "detected"
            if supported
            else "insufficient_evidence"
            if signals
            else "not_detected"
        )
        supported_verdicts = sorted(
            {by_review[group_id]["verdict"] for group_id in supported}
        )
        rows.append(
            {
                "id": case_id,
                "title": case["title"],
                "status": status,
                "supporting_groups": sorted(set(supported)),
                "supporting_model_verdicts": supported_verdicts,
                "signal_groups": sorted(set(signals)),
            }
        )
    counts = {
        name: sum(row["status"] == name for row in rows)
        for name in ("detected", "insufficient_evidence", "not_detected")
    }
    verdict_counts = {
        "confirmed_case": sum(
            "confirmed_vulnerability" in row["supporting_model_verdicts"]
            for row in rows
        ),
        "likely_only_case": sum(
            row["status"] == "detected"
            and "confirmed_vulnerability" not in row["supporting_model_verdicts"]
            and "likely_vulnerability" in row["supporting_model_verdicts"]
            for row in rows
        ),
    }
    return {
        "schema_version": "1.0",
        "fixture": "security-lab-web",
        "status": "post_scan_audit",
        "counts": counts,
        "model_verdict_counts": verdict_counts,
        "cases": rows,
        "limitations": [
            "The fixture contains positive cases only; precision and F1 are not estimated.",
            "A model verdict is not independent exploit proof.",
            "The brute-force result is bounded to the attested educational fixture; it does not prove that every deployment lacks external controls.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report_dir", type=Path)
    parser.add_argument(
        "--ground-truth",
        type=Path,
        default=Path(__file__).resolve().parents[1]
        / "benchmark"
        / "security_lab_web_ground_truth.json",
    )
    parser.add_argument(
        "--review", type=Path, help="completed review from a separate derived report"
    )
    parser.add_argument(
        "--triage", type=Path, help="triage from the same derived report as --review"
    )
    parser.add_argument(
        "--output", type=Path, help="optional JSON file outside the scan target"
    )
    args = parser.parse_args()
    if args.review is not None and args.triage is None:
        parser.error(
            "--review from a derived report requires --triage from the same report"
        )
    result = evaluate(
        args.report_dir,
        args.ground_truth,
        review_path=args.review,
        triage_path=args.triage,
    )
    encoded = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
