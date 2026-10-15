"""Runtime facts must survive every handoff to the final review."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from security_reviewer_v2.context import collect_context
from security_reviewer_v2.discovery.models import (
    CandidateAnchor, CandidateDisposition, CandidateFinding,
    CandidateMissingCheck, DiscoveryResult, DiscoveryStatus,
)
from security_reviewer_v2.normalization.authorization import normalize_authorization_json_file
from security_reviewer_v2.normalization.merge import merge_normalized_findings
from security_reviewer_v2.normalization.runtime import normalize_runtime_json_file
from security_reviewer_v2.normalization.serialization import merge_result_from_dict, normalization_result_from_dict
from security_reviewer_v2.reporting import render_final_report
from security_reviewer_v2.reviewers.agent import _build_prompt
from security_reviewer_v2.triage import triage_candidates
from security_reviewer_v2.verification.models import (
    VerificationDisposition, VerificationRecord, VerificationResult,
)
from scripts.evaluate_security_lab_15 import evaluate
from security_reviewer_v2.scanners import web_runtime


def _probe(tmp_path: Path, filename: str, rule: str, path: str, evidence: dict) -> Path:
    output = tmp_path / filename
    output.write_text(json.dumps({"results": [{
        "rule_id": rule, "title": rule, "path": path, "vulnerable": True,
        "severity": "high", "confidence": "high", "evidence": evidence,
    }]}), encoding="utf-8")
    return output


def test_authorization_facts_and_source_reach_review_and_report(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text(
        'from flask import Flask\napp = Flask(__name__)\n'
        '@app.route("/profile/<int:user_id>")\n'
        'def profile(user_id):\n'
        '    return {"user_id": user_id}\n', encoding="utf-8")
    source = _probe(tmp_path, "authorization.json", "auth.idor", "/profile/2", {
        "owner_status": 200, "cross_user_status": 200, "response_equal": True,
        "password": "must never leave the raw probe", "response_body": "private",
    })
    normalized = normalize_authorization_json_file(source)
    assert normalized.findings[0].runtime_evidence == {
        "cross_user_status": 200, "owner_status": 200, "response_equal": True,
    }
    reloaded = normalization_result_from_dict(normalized.to_dict())
    merged = merge_normalized_findings([reloaded])
    merged = merge_result_from_dict(merged.to_dict())
    context = collect_context(merged, project_root=project)
    assert context.findings[0].primary.excerpt is not None
    assert context.findings[0].primary.enclosing_symbol is not None
    assert context.findings[0].primary.enclosing_symbol.name == "profile"
    prompt = _build_prompt([], {}, list(merged.findings), context, project, 1)
    item = json.loads(prompt.split("\n\n", 1)[1])["items"][0]
    assert item["runtime_probe_facts"][0]["facts"]["response_equal"] is True
    assert "def profile" in item["source_symbol"]
    assert "private" not in prompt
    report = render_final_report(project=str(project), review={"status": "not_run"},
                                 policy={"status": "not_run"}, merged=merged.to_dict())
    assert "Bounded runtime evidence" in report
    assert "response_equal" in report
    assert "private" not in report


def test_cors_facts_map_to_after_request_source(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        'from flask import Flask\napp = Flask(__name__)\n'
        '@app.after_request\n'
        'def add_cors(response):\n'
        '    response.headers["Access-Control-Allow-Origin"] = "*"\n'
        '    return response\n', encoding="utf-8")
    source = _probe(tmp_path, "authorization.json", "web.cors-reflection", "/", {
        "status": 200, "allow_origin": "https://attacker.example", "allow_credentials": "true",
    })
    merged = merge_normalized_findings([normalize_authorization_json_file(source)])
    context = collect_context(merged, project_root=tmp_path)
    assert context.findings[0].primary.enclosing_symbol.name == "add_cors"


def test_runtime_facts_are_bounded_and_do_not_claim_more_than_observed(tmp_path: Path) -> None:
    source = _probe(tmp_path, "runtime.json", "web.missing-brute-force-protection", "/login", {
        "attempt_count": 5, "statuses": [401] * 5,
        "token_value": "secret", "content_type": "x" * 500,
    })
    finding = normalize_runtime_json_file(source).findings[0]
    assert finding.runtime_evidence["attempt_count"] == 5
    assert finding.runtime_evidence["statuses"] == [401] * 5
    assert "token_value" not in finding.runtime_evidence
    assert len(finding.runtime_evidence["content_type"]) == 128


def test_saved_upload_evidence_explains_separate_serving_request_to_review(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        'from flask import Flask\napp = Flask(__name__)\n'
        '@app.route("/upload", methods=["POST"])\n'
        'def upload():\n    return "saved"\n'
        '@app.route("/uploads/<path:filename>")\n'
        'def serve_upload(filename):\n    return filename\n', encoding="utf-8")
    source = _probe(tmp_path, "runtime.json", "web.insecure-file-upload", "/upload", {
        "upload_status": 200, "serve_status": 200,
        "content_type": "text/html; charset=utf-8",
    })
    merged = merge_normalized_findings([normalize_runtime_json_file(source)])
    context = collect_context(merged, project_root=tmp_path)
    prompt = _build_prompt([], {}, list(merged.findings), context, tmp_path, 1)
    item = json.loads(prompt.split("\n\n", 1)[1])["items"][0]
    fact = item["runtime_probe_facts"][0]
    assert fact["facts"]["serve_status"] == 200
    assert "separate GET /uploads/<test filename>" in fact["probe_contract"]
    assert "test marker appeared" in fact["probe_contract"]
    assert "not establish browser JavaScript execution" in fact["probe_contract"]


def test_attested_login_guard_is_explained_as_separate_evidence(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        'from flask import Flask\napp = Flask(__name__)\n'
        '@app.route("/login", methods=["POST"])\n'
        'def login():\n    return "invalid", 401\n', encoding="utf-8")
    source = _probe(tmp_path, "runtime.json", "web.missing-brute-force-protection", "/login", {
        "attempt_count": 5, "statuses": [401] * 5, "source_guard_absent": True,
        "source_scope": "isolated_fixture_login_and_hooks",
    })
    merged = merge_normalized_findings([normalize_runtime_json_file(source)])
    context = collect_context(merged, project_root=tmp_path)
    prompt = _build_prompt([], {}, list(merged.findings), context, tmp_path, 1)
    fact = json.loads(prompt.split("\n\n", 1)[1])["items"][0]["runtime_probe_facts"][0]
    assert "source-hash-matched check" in fact["probe_contract"]
    assert "do not prove absence" in fact["probe_contract"]


def test_grounded_profile_idor_joins_exact_runtime_route(tmp_path: Path) -> None:
    source = _probe(tmp_path, "authorization.json", "auth.idor", "/profile/2", {
        "owner_status": 200, "cross_user_status": 200, "response_equal": True,
    })
    merged = merge_normalized_findings([normalize_authorization_json_file(source)])
    candidate = CandidateFinding(
        "ai-profile", "Excessive sensitive data exposure in user profile endpoint",
        "Privacy/Authorization", "high", "medium", "app.py", 10, 20,
        ("profile source",), "No authorization for another user", "ai_discovery",
        CandidateDisposition.SUPPORTED, (),
        entry_point=CandidateAnchor("app.py", 10, '@app.route("/profile/<int:user_id>")'),
        missing_check=CandidateMissingCheck(
            "app.py", 15, "requested user_id == session user_id",
            "No check that the requested user_id matches the session user"),
    )
    discovery = DiscoveryResult("1.2", DiscoveryStatus.COMPLETED, "test", "test", (),
                                (candidate,), (), (), {})
    verification = VerificationResult("1.0", "completed", str(tmp_path), (
        VerificationRecord(candidate.candidate_id, VerificationDisposition.CONFIRMED,
                           "app.py", 10, 20, ("source_grounded",), (), ()),
    ), ())
    triage = triage_candidates(discovery, verification, merged)
    assert len(triage.groups) == 1
    assert triage.groups[0].scanner_finding_ids == (merged.findings[0].merged_finding_id,)
    assert triage.groups[0].candidate_ids == ("ai-profile",)
    assert triage.records[0].disposition.value == "scanner_overlap"


def test_postscan_audit_does_not_confuse_upload_path_warning_with_html_upload(tmp_path: Path) -> None:
    truth = Path(__file__).resolve().parents[1] / "benchmark" / "security_lab_web_ground_truth.json"
    merged = {"findings": [{
        "merged_finding_id": "path-warning",
        "source_findings": [{"rule_id": "py/path-injection",
                             "primary_location": {"path": "app.py", "start_line": 323}}],
    }]}
    review = {"reviews": [{"candidate_id": "path-warning", "verdict": "confirmed_vulnerability",
                           "evidence": ["file path comes from filename"]}]}
    (tmp_path / "merged.json").write_text(json.dumps(merged), encoding="utf-8")
    (tmp_path / "security-review.json").write_text(json.dumps(review), encoding="utf-8")
    (tmp_path / "ai-discovery.json").write_text('{"candidates": []}', encoding="utf-8")
    initial = {row["id"]: row for row in evaluate(tmp_path, truth)["cases"]}
    assert initial["TT-UPLOAD-001"]["status"] == "not_detected"

    merged["findings"].append({
        "merged_finding_id": "html-upload",
        "source_findings": [{"rule_id": "web.insecure-file-upload",
                             "primary_location": {"path": "/upload"},
                             "runtime_evidence": {"upload_status": 200, "serve_status": 200,
                                                  "content_type": "text/plain"}}],
    })
    review["reviews"].append({"candidate_id": "html-upload", "verdict": "confirmed_vulnerability",
                              "evidence": ["uploaded file returned"]})
    (tmp_path / "merged.json").write_text(json.dumps(merged), encoding="utf-8")
    (tmp_path / "security-review.json").write_text(json.dumps(review), encoding="utf-8")
    result = {row["id"]: row for row in evaluate(tmp_path, truth)["cases"]}
    assert result["TT-UPLOAD-001"]["status"] == "insufficient_evidence"

    merged["findings"][1]["source_findings"][0]["runtime_evidence"]["content_type"] = "text/html; charset=utf-8"
    (tmp_path / "merged.json").write_text(json.dumps(merged), encoding="utf-8")
    result = {row["id"]: row for row in evaluate(tmp_path, truth)["cases"]}
    assert result["TT-UPLOAD-001"]["status"] == "detected"

    review["reviews"][1]["candidate_id"] = "html-upload-group"
    (tmp_path / "security-review.json").write_text(json.dumps(review), encoding="utf-8")
    (tmp_path / "candidate-triage.json").write_text(json.dumps({"groups": [{
        "group_id": "html-upload-group", "scanner_finding_ids": ["html-upload"],
        "candidate_ids": [],
    }]}), encoding="utf-8")
    grouped = {row["id"]: row for row in evaluate(tmp_path, truth)["cases"]}
    assert grouped["TT-UPLOAD-001"]["status"] == "detected"
    assert grouped["TT-UPLOAD-001"]["supporting_groups"] == ["html-upload-group"]


def test_postscan_audit_reads_derived_review_and_attested_docker_guard(tmp_path: Path) -> None:
    truth = Path(__file__).resolve().parents[1] / "benchmark" / "security_lab_web_ground_truth.json"
    scan = tmp_path / "scan"
    derived = tmp_path / "derived"
    scan.mkdir()
    derived.mkdir()
    facts = {"attempt_count": 5, "statuses": [401] * 5,
             "source_guard_absent": True, "source_scope": "isolated_fixture_login_and_hooks",
             "source_path": "app.py", "source_line": 136, "source_sha256": "attested-hash"}
    (scan / "merged.json").write_text(json.dumps({"findings": [{
        "merged_finding_id": "brute", "source_findings": [{
            "rule_id": "web.missing-brute-force-protection",
            "primary_location": {"path": "/login"}, "runtime_evidence": facts,
        }],
    }]}), encoding="utf-8")
    (scan / "ai-discovery.json").write_text('{"candidates": []}', encoding="utf-8")
    manifest = {"status": "passed", "target_id": "security-lab-web",
                "backend": "docker_compose", "stack_removed": True,
                "app_sha256": "attested-hash"}
    (scan / "docker-runtime-evidence.json").write_text(json.dumps(manifest), encoding="utf-8")
    (derived / "candidate-triage.json").write_text(json.dumps({"groups": [{
        "group_id": "brute", "scanner_finding_ids": ["brute"], "candidate_ids": [],
    }]}), encoding="utf-8")
    review = {"reviews": [{"candidate_id": "brute", "source_ids": ["brute"],
                           "verdict": "likely_vulnerability", "evidence": ["bounded source and runtime facts"]}]}
    (derived / "security-review.json").write_text(json.dumps(review), encoding="utf-8")
    result = evaluate(scan, truth, review_path=derived / "security-review.json",
                      triage_path=derived / "candidate-triage.json")
    case = next(row for row in result["cases"] if row["id"] == "TT-BRUTE-001")
    assert case["status"] == "detected"
    assert case["supporting_model_verdicts"] == ["likely_vulnerability"]
    assert result["model_verdict_counts"]["likely_only_case"] == 1

    manifest["stack_removed"] = False
    (scan / "docker-runtime-evidence.json").write_text(json.dumps(manifest), encoding="utf-8")
    untrusted = evaluate(scan, truth, review_path=derived / "security-review.json",
                         triage_path=derived / "candidate-triage.json")
    assert next(row for row in untrusted["cases"] if row["id"] == "TT-BRUTE-001")["status"] == "insufficient_evidence"

    review["reviews"][0]["source_ids"] = ["a-different-scan"]
    (derived / "security-review.json").write_text(json.dumps(review), encoding="utf-8")
    with pytest.raises(ValueError, match="do not match"):
        evaluate(scan, truth, review_path=derived / "security-review.json",
                 triage_path=derived / "candidate-triage.json")


def test_existing_guest_mutating_probes_cover_stored_xss_and_html_upload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    html_marker = b"<script>security_test_marker</script>"

    def request(_client, _base, path, *, data=None, files=None, **_kwargs):
        if path == "/":
            return 200, {}, b"ready"
        if path.startswith("/search?q=%3Cscript"):
            return 200, {}, b"<script>alert(1)</script>"
        if path == "/search?q=%27%22%22%22":
            return 500, {}, b"DB ERROR: query: redacted"
        if path == "/login" and data and data.get("password") == "alice123":
            return 302, {"Set-Cookie": "token=tok-1-staticsalt"}, b""
        if path == "/login":
            return 401, {}, b""
        if path == "/debug":
            return 200, {}, b'{"secret_key":"hidden","env":{}}'
        if path == "/comments" and data:
            return 302, {}, b""
        if path == "/comments":
            return 200, {}, b"<img src=x onerror=alert(1)>"
        if path == "/upload" and files:
            return 200, {}, b"saved"
        if path == "/uploads/security-reviewer-test.html":
            return 200, {"Content-Type": "text/html; charset=utf-8"}, html_marker
        raise AssertionError(path)

    monkeypatch.setattr(web_runtime, "_request", request)
    result = web_runtime.run_checks(web_runtime.RuntimeConfig(
        "http://127.0.0.1:5000", tmp_path / "runtime.json", mutating=True))
    by_rule = {item["rule_id"]: item for item in result["results"]}
    assert result["mutating_checks_enabled"] is True
    assert len(result["results"]) == 7
    assert by_rule["web.stored-xss"]["vulnerable"] is True
    assert by_rule["web.insecure-file-upload"]["vulnerable"] is True
    assert by_rule["web.insecure-file-upload"]["evidence"]["content_type"].startswith("text/html")
    assert by_rule["web.insecure-file-upload"]["evidence"]["marker_present"] is True
