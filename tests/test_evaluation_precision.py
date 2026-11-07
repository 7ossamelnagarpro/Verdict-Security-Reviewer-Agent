from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.aggregate_evaluations import aggregate, markdown as aggregate_markdown
from scripts.evaluate_verdict_comprehensive import ROOT, TRUTH, evaluate, html_report, markdown
from security_reviewer_v2.reporting.evaluation_precision import (
    HARDENING_CATEGORIES, audit, case_handlers, load_handlers, normalize_route, parse_case_route, resolve_location)

LAB = ROOT / "targets" / "verdict-comprehensive-lab"
APP = '''\
from fastapi import FastAPI
app = FastAPI()

@app.get("/orders/{order_id}")
def read_order(order_id: int):
    return {}

@app.get("/orders/verified")
def verified_orders():
    return {}

@app.post("/comments")
@app.get("/comments")
def comments():
    return {}
'''


@pytest.fixture()
def app_root(tmp_path: Path) -> Path:
    (tmp_path / "api").mkdir()
    (tmp_path / "api" / "app.py").write_text(APP, encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_app.py").write_text('@app.get("/ignored")\ndef t():\n    pass\n', encoding="utf-8")
    return tmp_path


def test_route_normalisation_and_case_locations() -> None:
    assert normalize_route("/orders/{{order_id}}?x=1") == normalize_route("/orders/{id}/") == "/orders/{}"
    assert normalize_route("/") == "/"
    assert parse_case_route("POST+GET /comments") == (frozenset({"POST", "GET"}), "/comments")
    assert parse_case_route("GET /files?name=") == (frozenset({"GET"}), "/files")
    assert parse_case_route("compose.yaml") is None
    assert parse_case_route("api/app.py:principal") is None
    assert parse_case_route(None) is None


def test_handlers_come_from_route_decorators_only(app_root: Path) -> None:
    handlers = load_handlers(app_root)
    assert sorted(item.key for item in handlers) == ["GET /comments", "GET /orders/verified", "GET /orders/{}", "POST /comments"]
    assert not any("ignored" in item.template for item in handlers)          # the tests/ directory is not the application
    assert {item.key for item in case_handlers("POST+GET /comments", handlers)} == {"POST /comments", "GET /comments"}
    assert case_handlers("GET /missing", handlers) == ()


def test_findings_are_placed_on_routes_by_url_or_by_file_and_line(app_root: Path) -> None:
    handlers = load_handlers(app_root)
    by_url = resolve_location("/orders/{{order_id}}", None, "get", handlers)
    assert [item.key for item in by_url] == ["GET /orders/{}"]
    assert [item.key for item in resolve_location("/orders/7", None, None, handlers)] == ["GET /orders/{}"]
    assert [item.key for item in resolve_location("/orders/verified", None, None, handlers)] == ["GET /orders/verified"]  # most specific
    assert [item.key for item in resolve_location("/orders/7", None, "POST", handlers)] == []                           # wrong verb
    line = next(item.start for item in handlers if item.key == "GET /orders/{}") + 1
    assert [item.key for item in resolve_location("api\\app.py", line, None, handlers)] == ["GET /orders/{}"]
    assert resolve_location("api/app.py", "12", None, handlers) == ()
    assert resolve_location("", 3, None, handlers) == ()


def _case(case_id: str, label: str, location: str, category: str = "idor") -> dict:
    return {"id": case_id, "label": label, "location": location, "category": category}


def _source(rule: str, path: str, *, categories: tuple[str, ...] = ("dast", "runtime"), method: str | None = None,
            scanner: str = "web-runtime") -> dict:
    source = {"rule_id": rule, "primary_location": {"path": path, "start_line": 1}, "categories": list(categories),
              "scanner": {"scanner_id": scanner}}
    if method:
        source["runtime_evidence"] = {"method": method}
    return source


def _audit(app_root: Path, groups: dict, findings: dict, reviews: dict, strict: dict | None = None, candidates: dict | None = None):
    cases = [_case("C01", "confirmed_vulnerability", "GET /orders/{id}"),
             _case("C02", "confirmed_vulnerability", "POST+GET /comments", "stored_xss"),
             _case("C03", "confirmed_vulnerability", "GET /healthz", "cors"),
             _case("S01", "safe_control", "GET /orders/verified", "authorization"),
             _case("S02", "safe_control", "GET /nowhere", "authorization"),
             _case("S03", "safe_control", "GET /orders/{id}", "response_headers")]
    return audit(cases=cases, handlers=load_handlers(app_root), groups=groups, reviews=reviews, findings=findings,
                 candidates=candidates or {}, strict_matches=strict or {})


def test_every_positive_group_lands_in_exactly_one_outcome(app_root: Path) -> None:
    findings = {
        "f-match": {"source_findings": [_source("workflow.x", "/orders/1")]},
        "f-safe": {"source_findings": [_source("workflow.y", "/orders/verified")]},
        "f-dep": {"source_findings": [_source("CVE-1", "requirements.txt", categories=("sca",), scanner="trivy")]},
        "f-header": {"source_findings": [_source("zap.10038", "/orders/verified")]},
        "f-none": {"source_findings": [_source("py/odd", "api/elsewhere.py", categories=("sast",), scanner="codeql-cli")]},
    }
    groups = {name: {"scanner_finding_ids": [name], "candidate_ids": []} for name in findings}
    groups["ai"] = {"scanner_finding_ids": [], "candidate_ids": ["ai-1"]}
    reviews = {name: {"verdict": "likely_vulnerability"} for name in groups}
    reviews["f-none"] = {"verdict": "false_positive"}
    candidates = {"ai-1": {"candidate_id": "ai-1", "title": "AI", "path": "api/app.py", "start_line": 1,
                           "sensitive_operation": {"path": "api/app.py", "line": 12}}}
    result = _audit(app_root, groups, findings, reviews, strict={"f-match": {"C01"}}, candidates=candidates)
    outcome = {row["group_id"]: row["outcome"] for row in result["groups"]}
    assert outcome["f-match"] == "matched"
    assert outcome["f-safe"] == "safe_control"
    assert outcome["f-dep"] == "outside_scope"          # a dependency advisory is not in the answer key
    assert outcome["f-header"] == "outside_scope"       # a header alert is not a failure of an authorization control
    assert outcome["f-none"] == "unlabeled"
    assert outcome["ai"] == "known_endpoint"           # line 12 sits on POST /comments, the endpoint of case C02
    summary = result["summary"]
    assert summary["positive_groups"] == 5             # the false_positive verdict is not a positive finding
    assert summary["matched_groups"] == 1 and summary["safe_control_groups"] == 1
    assert summary["precision_on_labeled"] == 0.5
    assert summary["precision_lower_bound"] == 0.2
    assert summary["precision_lower_bound_in_scope"] == pytest.approx(1 / 3, abs=1e-4)
    assert sum(summary[key] for key in ("matched_groups", "known_endpoint_groups", "safe_control_groups",
                                        "outside_scope_groups", "unlabeled_groups")) == summary["positive_groups"]


def test_safe_control_status_clean_flagged_or_not_assessable(app_root: Path) -> None:
    findings = {"f-safe": {"source_findings": [_source("workflow.y", "/orders/verified")]}}
    groups = {"f-safe": {"scanner_finding_ids": ["f-safe"], "candidate_ids": []}}
    flagged = _audit(app_root, groups, findings, {"f-safe": {"verdict": "likely_vulnerability"}})["safe_controls"]
    assert flagged["S01"] == {"status": "flagged", "flagged_by": ["f-safe"]}
    assert flagged["S02"]["status"] == "not_assessable"        # no such route in the source
    clean = _audit(app_root, groups, findings, {"f-safe": {"verdict": "needs_more_evidence"}})
    assert clean["safe_controls"]["S01"]["status"] == "clean"  # only positive verdicts count against a control
    assert clean["summary"]["safe_control_specificity"] == 1.0  # not-assessable controls are left out of the ratio


def test_hardening_alerts_only_count_against_hardening_controls(app_root: Path) -> None:
    assert {"cookie_flags", "response_headers", "cors"} == set(HARDENING_CATEGORIES)
    findings = {"hdr": {"source_findings": [_source("zap.10038", "/orders/1")]}}
    groups = {"hdr": {"scanner_finding_ids": ["hdr"], "candidate_ids": []}}
    result = _audit(app_root, groups, findings, {"hdr": {"verdict": "likely_vulnerability"}})
    assert result["safe_controls"]["S03"]["status"] == "flagged"     # S03 is the response-headers control on that route
    assert next(row for row in result["groups"] if row["group_id"] == "hdr")["safe_controls"] == ["S03"]


def test_ai_candidate_is_never_a_detection_but_is_placed_on_its_endpoint(app_root: Path) -> None:
    candidates = {"ai-1": {"candidate_id": "ai-1", "title": "No sanitisation", "path": "api/app.py", "start_line": 1,
                           "sensitive_operation": {"path": "api/app.py", "line": 15}}}
    groups = {"g": {"scanner_finding_ids": [], "candidate_ids": ["ai-1"]}}
    result = _audit(app_root, groups, {}, {"g": {"verdict": "likely_vulnerability", "title": "AI finding"}}, candidates=candidates)
    row = result["groups"][0]
    assert row["origins"] == ["ai_discovery"] and row["outcome"] == "known_endpoint" and row["known_cases"] == ["C02"]
    assert result["summary"]["matched_groups"] == 0
    assert [item["group_id"] for item in result["endpoint_groups"]["C02"]] == ["g"]


def _evaluate(source_root, merged: list, groups: list, reviews: list, discovery=None):
    truth = json.loads(TRUTH.read_text(encoding="utf-8"))
    return evaluate(truth, {"project": "targets/verdict-comprehensive-lab"}, {"status": "completed", "findings": merged},
                    {"groups": groups}, {"status": "completed", "reviews": reviews}, source_root=source_root, discovery=discovery)


def test_strict_audit_is_unchanged_and_unaudited_output_keeps_its_old_shape() -> None:
    result = _evaluate(None, [], [], [])
    assert result["schema_version"] == "1.1" and "adjudication_queue" not in result
    assert result["summary"]["precision"] is None and result["summary"]["f1"] is None
    assert {row["status"] for row in result["cases"] if row["ground_truth"] == "safe_control"} == {"safe_control_not_assessed"}
    assert "Safe controls — specificity not assessed" in markdown(result)
    assert all("has_signature" in row for row in result["cases"])


@pytest.mark.skipif(not LAB.is_dir(), reason="lab source not available")
def test_audited_evaluation_end_to_end_on_the_lab() -> None:
    me = {"merged_finding_id": "m-me", "source_findings": [{
        "rule_id": "workflow.excessive_data.1", "primary_location": {"path": "/me"}, "categories": ["dast", "runtime"],
        "scanner": {"scanner_id": "web-runtime"},
        "runtime_evidence": {"status": 200, "expected_statuses": [200], "assertion_results": [False]}}]}
    safe = {"merged_finding_id": "m-safe", "source_findings": [_source("workflow.order_owner.3", "/orders/{{order_id}}/verified")]}
    groups = [{"group_id": "m-me", "scanner_finding_ids": ["m-me"], "candidate_ids": []},
              {"group_id": "m-safe", "scanner_finding_ids": ["m-safe"], "candidate_ids": []},
              {"group_id": "ai-g", "scanner_finding_ids": [], "candidate_ids": ["ai-1"]}]
    reviews = [{"candidate_id": "m-me", "source_ids": ["m-me"], "verdict": "confirmed_vulnerability", "severity": "high", "title": "Excess data"},
               {"candidate_id": "m-safe", "source_ids": ["m-safe"], "verdict": "likely_vulnerability", "severity": "medium", "title": "Verified order"},
               {"candidate_id": "ai-g", "source_ids": ["ai-1"], "verdict": "likely_vulnerability", "severity": "medium", "title": "Stored XSS?"}]
    discovery = {"candidates": [{"candidate_id": "ai-1", "title": "Stored XSS?", "path": "api/extra.py", "start_line": 161,
                                 "sensitive_operation": {"path": "api/extra.py", "line": 165}}],
                 "usage": {"provider_calls": 8, "rate_limit_wait_seconds": 12.5, "unrelated": 1}}
    result = _evaluate(LAB, [me, safe], groups, reviews, discovery)
    summary, rows = result["summary"], {row["id"]: row for row in result["cases"]}
    assert result["schema_version"] == "1.2"
    assert rows["C24"]["status"] == "detected" and rows["C24"]["origins"] == ["dynamic"]
    assert summary["detections_by_origin"] == {"dynamic": 1}
    assert summary["safe_controls_flagged"] >= 1 and summary["safe_controls_clean"] + summary["safe_controls_flagged"] + summary["safe_controls_not_assessable"] == 27
    assert any(row["status"] == "safe_control_flagged" and row["flagged_by"] == ["m-safe"] for row in rows.values())
    assert summary["not_detected_without_signature"] <= summary["not_detected"]
    assert "C06" in summary["ai_discovery_on_undetected_endpoints"]          # the AI candidate sits on POST /comments
    assert summary["detected"] == 1                                         # the AI candidate was not credited
    assert result["scan_provenance"]["ai_discovery_usage"] == {"provider_calls": 8, "rate_limit_wait_seconds": 12.5}
    assert [item["group_id"] for item in result["safe_control_hits"]] == ["m-safe"]
    text, page = markdown(result), html_report(result)
    for needle in ("Adjudication queue", "Safe-control hits", "Verdict calibration", "Precision bounds", "Detection origin"):
        assert needle in text or needle in page
    assert "safe control flagged" in page.lower() or "safe_control_flagged" in page
    assert page.count("<script") == 2 and "http://" not in page and "https://" not in page


def _evaluation(detected: set[str], target: str = "lab") -> dict:
    cases = [{"id": f"C0{i}", "ground_truth": "confirmed_vulnerability", "category": "x", "location": f"GET /{i}",
              "status": "detected" if f"C0{i}" in detected else "not_detected"} for i in range(1, 5)]
    return {"target": target, "cases": cases,
            "summary": {"detected": len(detected), "needs_review": 0, "not_detected": 4 - len(detected),
                        "positive_case_recall_lower_bound": len(detected) / 4}}


def test_aggregation_reports_spread_and_per_case_stability() -> None:
    result = aggregate([_evaluation({"C01", "C02"}), _evaluation({"C01", "C03"}), _evaluation({"C01"})])
    assert result["metrics"]["detected"] == {"runs": 3, "mean": 1.6667, "min": 1, "max": 2}
    stability = {item["id"]: item["stability"] for item in result["cases"]}
    assert stability == {"C01": "stable", "C02": "flaky", "C03": "flaky", "C04": "never"}
    assert result["stability"] == {"stable": 1, "flaky": 2, "never": 1}
    assert "2 flaky" in aggregate_markdown(result)


def test_aggregation_rejects_mixed_or_single_inputs() -> None:
    with pytest.raises(ValueError, match="at least two"):
        aggregate([_evaluation({"C01"})])
    with pytest.raises(ValueError, match="different targets"):
        aggregate([_evaluation({"C01"}), _evaluation({"C01"}, target="other")])
    short = _evaluation({"C01"})
    short["cases"] = short["cases"][:3]
    with pytest.raises(ValueError, match="same cases"):
        aggregate([_evaluation({"C01"}), short])
