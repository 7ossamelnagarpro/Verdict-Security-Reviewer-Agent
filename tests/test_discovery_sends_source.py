"""Discovery must send repository *source code* to the model, not only the merged scanner results.

Regression for: LangSmith showed the merge result (known findings / scanner excerpts) but no code, and discovery
finished almost immediately.
"""

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace as NS

from security_reviewer_v2.agents.tracing import call_model, make_scrubber
from security_reviewer_v2.discovery.agent import _build_prompt
from security_reviewer_v2.discovery.graph import _prompt_summary, BatchProgress
from security_reviewer_v2.discovery.models import DiscoveryConfig
from security_reviewer_v2.discovery.scope import DiscoveryScope, plan_discovery_scope

VULNERABLE = '''import sqlite3
from flask import request

@app.route("/orders/<int:order_id>")
def view_order(order_id):
    row = db.execute("SELECT * FROM orders WHERE id = " + str(order_id))
    return row
'''


def _location(path, line):
    return NS(path=path, start_line=line, end_line=line)


def _project(tmp_path: Path, count: int = 3):
    hashes = {}
    for index in range(count):
        path = tmp_path / f"mod_{index}.py"
        path.write_text(VULNERABLE + "\n".join(f"# filler {n}" for n in range(60)), encoding="utf-8")
        hashes[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    profile = {
        "profile": {"inventory": [{"path": name, "category": "source"} for name in hashes]},
        "project_snapshot": {"root_path": os.path.normcase(str(tmp_path.resolve())),
                             "files": [{"path": n, "sha256": h} for n, h in hashes.items()]},
    }
    return profile


def _inputs(flagged: int, known: int):
    findings = [
        NS(merged_finding_id=f"m{i}", primary_location=_location(f"mod_{i}.py", 6),
           canonical_finding=NS(title="SQL injection through string concatenation"),
           source_findings=[NS(primary_location=_location(f"mod_{i}.py", 6))])
        for i in range(flagged)
    ]
    findings += [
        NS(merged_finding_id=f"k{i}", primary_location=_location("mod_0.py", 20 + i),
           canonical_finding=NS(title="Semgrep finding with a reasonably long descriptive title"),
           source_findings=[NS(primary_location=_location("mod_0.py", 20 + i))])
        for i in range(known)
    ]
    merged = NS(findings=findings, coverage_gaps=())
    risk = NS(findings=[NS(merged_finding_id=f"m{i}", primary_location=_location(f"mod_{i}.py", 6), rank=i + 1,
                           risk_score=90, selected_for_deep_review=True) for i in range(flagged)],
              coverage_gaps=())
    return merged, risk, NS(findings=[], coverage_gaps=())


def test_risk_targets_carry_the_source_around_the_finding(tmp_path):
    profile = _project(tmp_path)
    merged, risk, context = _inputs(flagged=2, known=0)
    scope = plan_discovery_scope(merged, risk, context, project_root=tmp_path, config=DiscoveryConfig(model="x"),
                                 profile_artifact=profile)
    risk_targets = [item for item in scope.targets if item.kind == "risk_finding"]
    assert risk_targets, "risk findings must still be planned"
    for target in risk_targets:
        window = scope.snippets[target.target_id]
        assert "6:     row = db.execute(" in window          # the flagged line itself, with its number
        assert "def view_order(order_id)" in window         # and the function around it


def test_prompt_contains_source_for_every_target_kind(tmp_path):
    profile = _project(tmp_path)
    merged, risk, context = _inputs(flagged=2, known=0)
    scope = plan_discovery_scope(merged, risk, context, project_root=tmp_path, config=DiscoveryConfig(model="x"),
                                 profile_artifact=profile)
    prompt, targets, _ = _build_prompt(merged, context, risk, scope, 16_000)
    records = json.loads(prompt.partition("\n\n")[2])["targets"]
    assert len(records) == len(targets) > 0
    assert all(record.get("code") for record in records), [r["kind"] for r in records if not r.get("code")]
    assert {record["kind"] for record in records} >= {"risk_finding", "no_findings"}


def test_code_comes_before_the_merge_derived_lists_and_survives_trace_truncation(tmp_path):
    profile = _project(tmp_path)
    merged, risk, context = _inputs(flagged=2, known=40)
    scope = plan_discovery_scope(merged, risk, context, project_root=tmp_path, config=DiscoveryConfig(model="x"),
                                 profile_artifact=profile)
    prompt, _, _ = _build_prompt(merged, context, risk, scope, 16_000)
    payload = prompt.partition("\n\n")[2]
    assert payload.index('"targets"') < payload.index('"known_findings"')
    # LangSmith "redacted" mode cuts every string at 4,000 characters; the code must already be inside that window.
    assert '"code"' in make_scrubber("redacted")(prompt)


def test_known_findings_cannot_crowd_out_the_source(tmp_path):
    profile = _project(tmp_path)
    merged, risk, context = _inputs(flagged=2, known=200)
    scope = plan_discovery_scope(merged, risk, context, project_root=tmp_path, config=DiscoveryConfig(model="x"),
                                 profile_artifact=profile)
    prompt, targets, _ = _build_prompt(merged, context, risk, scope, 8_000)
    body = json.loads(prompt.partition("\n\n")[2])
    assert len(prompt) <= 8_000
    assert len(json.dumps(body["known_findings"], separators=(",", ":"))) <= 8_000 * 0.15 + 100
    assert len(targets) >= 3


def test_trace_summary_reaches_langsmith_inputs_but_not_the_provider(tmp_path):
    seen = {}

    class Provider:
        name, model = "fake", "m"

        def discover(self, prompt, **options):
            seen.update(options)
            return {"candidates": []}, {}

    raw, _ = call_model(Provider(), "discover", "prompt", span="s", trace_summary={"targets": 1}, timeout_seconds=5)
    assert raw == {"candidates": []}
    assert "trace_summary" not in seen and seen["timeout_seconds"] == 5


def test_prompt_summary_reports_files_lines_and_code_amount(tmp_path):
    profile = _project(tmp_path)
    merged, risk, context = _inputs(flagged=2, known=0)
    scope = plan_discovery_scope(merged, risk, context, project_root=tmp_path, config=DiscoveryConfig(model="x"),
                                 profile_artifact=profile)
    prompt, targets, _ = _build_prompt(merged, context, risk, scope, 16_000)
    summary = _prompt_summary(BatchProgress(1, targets, prompt, frozenset()))
    assert summary["targets_with_source_code"] == len(targets)
    assert summary["source_code_chars"] > 0
    assert any(line.startswith("risk_finding mod_") for line in summary["target_list"])
    assert all(len(line) <= 190 for line in summary["target_list"])   # stays readable in LangSmith metadata mode


def test_file_without_hotspot_is_not_reduced_to_its_import_header(tmp_path):
    body = "\n".join(f"import module_{n}" for n in range(60)) + "\n\ndef load(user_id):\n    return token_for(user_id)\n"
    (tmp_path / "util.py").write_text(body, encoding="utf-8")
    profile = {
        "profile": {"inventory": [{"path": "util.py", "category": "source"}]},
        "project_snapshot": {"root_path": os.path.normcase(str(tmp_path.resolve())),
                             "files": [{"path": "util.py", "sha256": hashlib.sha256(body.encode()).hexdigest()}]},
    }
    merged, risk, context = NS(findings=[], coverage_gaps=()), NS(findings=[], coverage_gaps=()), NS(findings=[], coverage_gaps=())
    scope = plan_discovery_scope(merged, risk, context, project_root=tmp_path, config=DiscoveryConfig(model="x"),
                                 profile_artifact=profile)
    window = next(iter(scope.snippets.values()))
    assert "def load(user_id)" in window and "token_for" in window
