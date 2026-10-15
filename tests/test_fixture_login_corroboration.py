"""The fixture-only login corroboration must fail closed on protected variants."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from scripts.evaluate_security_lab_15 import evaluate
from scripts.run_pre_review_pipeline import _enrich_login_runtime_batch
from security_reviewer_v2.normalization.runtime import normalize_runtime_json_file
from security_reviewer_v2.scanners.fixture_login_corroboration import corroborate_fixture_login


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "targets" / "security-lab-web"
TRUTH = ROOT / "benchmark" / "security_lab_web_ground_truth.json"


def _runtime(statuses: list[int]) -> dict:
    return {"results": [{"rule_id": "web.missing-brute-force-protection",
                         "path": "/login", "vulnerable": 429 not in statuses,
                         "evidence": {"attempt_count": len(statuses),
                                      "statuses": statuses}}]}


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_unprotected_fixture_has_source_matched_bounded_evidence() -> None:
    facts = corroborate_fixture_login(FIXTURE, _runtime([401] * 5), _hash(FIXTURE / "app.py"))
    assert facts is not None
    assert facts["source_guard_absent"] is True
    assert facts["source_path"] == "app.py"
    assert facts["attempt_count"] == 5
    assert facts["statuses"] == [401] * 5
    assert "password" not in json.dumps(facts)


def test_only_login_finding_changes_when_evidence_is_attached(tmp_path: Path) -> None:
    payload = {"results": [
        {"rule_id": "web.reflected-xss", "path": "/search", "title": "XSS",
         "vulnerable": True, "evidence": {"status": 200, "payload_reflected": True}},
        {"rule_id": "web.missing-brute-force-protection", "path": "/login",
         "title": "Rate limit", "vulnerable": True,
         "evidence": {"attempt_count": 5, "statuses": [401] * 5}},
    ]}
    runtime_path = tmp_path / "runtime.json"
    runtime_path.write_text(json.dumps(payload), encoding="utf-8")
    original = normalize_runtime_json_file(runtime_path)
    facts = corroborate_fixture_login(FIXTURE, payload, _hash(FIXTURE / "app.py"))
    enriched = _enrich_login_runtime_batch(original, facts)
    assert enriched.findings[0] == original.findings[0]
    assert enriched.findings[1].finding_id == original.findings[1].finding_id
    assert enriched.findings[1].runtime_evidence["source_guard_absent"] is True
    assert _enrich_login_runtime_batch(original, None) == original


def test_protected_or_unattested_fixture_does_not_get_corroboration(tmp_path: Path) -> None:
    app = tmp_path / "app.py"
    original = (FIXTURE / "app.py").read_text(encoding="utf-8")
    app.write_text(original, encoding="utf-8")
    assert corroborate_fixture_login(tmp_path, _runtime([401] * 5), "0" * 64) is None
    assert corroborate_fixture_login(tmp_path, _runtime([401, 401, 429, 429, 429]),
                                     _hash(app)) is None
    protected = original.replace('    db = get_db()\n',
                                 '    if request.headers.get("X-Blocked"):\n'
                                 '        return "Too many requests", 429\n'
                                 '    db = get_db()\n', 1)
    app.write_text(protected, encoding="utf-8")
    assert corroborate_fixture_login(tmp_path, _runtime([401] * 5), _hash(app)) is None
    app.write_text(original + '\napp.before_request(lambda: None)\n', encoding="utf-8")
    assert corroborate_fixture_login(tmp_path, _runtime([401] * 5), _hash(app)) is None
    protected_helper = original.replace(
        '    if db is None:\n',
        '    if attempts > 5:\n        raise RuntimeError("locked")\n'
        '    if db is None:\n', 1)
    app.write_text(protected_helper, encoding="utf-8")
    assert corroborate_fixture_login(tmp_path, _runtime([401] * 5), _hash(app)) is None


def test_audit_requires_positive_review_and_attested_source(tmp_path: Path) -> None:
    facts = corroborate_fixture_login(FIXTURE, _runtime([401] * 5), _hash(FIXTURE / "app.py"))
    assert facts is not None
    merged = {"findings": [{"merged_finding_id": "brute",
                            "source_findings": [{
                                "rule_id": "web.missing-brute-force-protection",
                                "primary_location": {"path": "/login"},
                                "runtime_evidence": facts}]}]}
    review = {"reviews": [{"candidate_id": "brute",
                           "verdict": "likely_vulnerability",
                           "evidence": ["Five unblocked attempts", "Direct login handler and hooks inspected"]}]}
    isolated = {"status": "passed", "network_isolation": "no_vm_switch",
                "worker_removed": True, "app_sha256": facts["source_sha256"]}
    (tmp_path / "merged.json").write_text(json.dumps(merged), encoding="utf-8")
    (tmp_path / "security-review.json").write_text(json.dumps(review), encoding="utf-8")
    (tmp_path / "ai-discovery.json").write_text('{"candidates": []}', encoding="utf-8")
    (tmp_path / "isolated-runtime-evidence.json").write_text(json.dumps(isolated), encoding="utf-8")
    cases = {case["id"]: case for case in evaluate(tmp_path, TRUTH)["cases"]}
    assert cases["TT-BRUTE-001"]["status"] == "detected"
    review["reviews"][0]["verdict"] = "needs_more_evidence"
    (tmp_path / "security-review.json").write_text(json.dumps(review), encoding="utf-8")
    cases = {case["id"]: case for case in evaluate(tmp_path, TRUTH)["cases"]}
    assert cases["TT-BRUTE-001"]["status"] == "insufficient_evidence"
    review["reviews"][0]["verdict"] = "likely_vulnerability"
    (tmp_path / "security-review.json").write_text(json.dumps(review), encoding="utf-8")
    isolated["app_sha256"] = "0" * 64
    (tmp_path / "isolated-runtime-evidence.json").write_text(json.dumps(isolated), encoding="utf-8")
    cases = {case["id"]: case for case in evaluate(tmp_path, TRUTH)["cases"]}
    assert cases["TT-BRUTE-001"]["status"] == "insufficient_evidence"
