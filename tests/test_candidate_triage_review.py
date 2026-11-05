"""End-to-end grouping and lossless, bounded review scheduling with a fake model."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from security_reviewer_v2.discovery.models import (
    CandidateAnchor,
    CandidateDisposition,
    CandidateFinding,
    DiscoveryResult,
    DiscoveryStatus,
)
from security_reviewer_v2.normalization.merge_models import (
    MergedFinding,
    MergeResult,
    MergeStatus,
    MergeSummary,
)
from security_reviewer_v2.normalization.models import (
    CodeFlowStep,
    FindingConfidence,
    FindingLocation,
    FindingSeverity,
    ScannerProvenance,
    UnifiedFinding,
)
from security_reviewer_v2.policy import evaluate_policy
from security_reviewer_v2.reporting import render_final_report
from security_reviewer_v2.reviewers import run_security_review
from security_reviewer_v2.triage import triage_candidates
from security_reviewer_v2.verification.models import (
    VerificationDisposition,
    VerificationRecord,
    VerificationResult,
)


def scanner(item_id: str, line: int, family: str = "sql") -> MergedFinding:
    rule = {
        "sql": "py/sql-injection",
        "xss": "py/reflective-xss",
        "command": "py/command-line-injection",
    }[family]
    location = FindingLocation("app.py", line, 1, line, 10, "unsafe_code()")
    source = UnifiedFinding(
        item_id,
        "1.0",
        ScannerProvenance("codeql-cli", "CodeQL", "1", 0, line, None),
        rule,
        rule,
        None,
        "Source reaches sink",
        FindingSeverity.HIGH,
        None,
        FindingConfidence.HIGH,
        (),
        ("security",),
        location,
        (),
        (),
        {},
        None,
        None,
    )
    return MergedFinding(
        item_id,
        "1.0",
        source,
        (source,),
        ("codeql-cli",),
        (rule,),
        FindingSeverity.HIGH,
        FindingConfidence.HIGH,
        (),
        ("security",),
        location,
        ("single_source_finding",),
    )


def merged(*items: MergedFinding) -> MergeResult:
    return MergeResult(
        "1.0",
        MergeStatus.COMPLETE,
        items,
        (),
        (),
        (),
        MergeSummary(1, len(items), len(items), 0),
    )


def candidate(
    item_id: str, category: str, line: int, *, path: str = "app.py"
) -> CandidateFinding:
    return CandidateFinding(
        item_id,
        category,
        category,
        "high",
        "medium",
        path,
        line,
        line,
        ("unsafe_code()",),
        "Requires semantic review",
        "ai_discovery",
        CandidateDisposition.SUPPORTED,
        (),
    )


def discovery(*items: CandidateFinding) -> DiscoveryResult:
    return DiscoveryResult(
        "1.2", DiscoveryStatus.COMPLETED, "test", "test", (), items, (), (), {}
    )


def verified(
    *items: CandidateFinding,
    disposition: VerificationDisposition = VerificationDisposition.CONFIRMED,
) -> VerificationResult:
    return VerificationResult(
        "1.0",
        "completed",
        "test-root",
        tuple(
            VerificationRecord(
                item.candidate_id,
                disposition,
                item.path,
                item.start_line,
                item.end_line,
                ("source_grounded",),
                item.evidence,
                (),
            )
            for item in items
        ),
        (),
    )


class EchoReviewer:
    name = "fake"
    model = "fake-model"

    def __init__(
        self, *, omit_first_batch: bool = False, fail_after: int | None = None
    ) -> None:
        self.calls: list[list[str]] = []
        self.omit_first_batch = omit_first_batch
        self.fail_after = fail_after

    def review(
        self, prompt: str, *, timeout_seconds: int, max_reviews: int
    ) -> tuple[list[dict], dict]:
        if self.fail_after is not None and len(self.calls) >= self.fail_after:
            raise RuntimeError("provider unavailable")
        payload = json.loads(prompt.split("\n\n", 1)[1])
        ids = [item["candidate"]["candidate_id"] for item in payload["items"]]
        assert 1 <= len(ids) <= max_reviews
        assert len(prompt) <= 50_000
        self.calls.append(ids)
        if self.omit_first_batch and len(self.calls) == 1:
            ids = ids[:1]
        return (
            [
                {
                    "candidate_id": item_id,
                    "verdict": "needs_more_evidence",
                    "severity": "medium",
                    "confidence": "low",
                    "title": "Test review",
                    "evidence": ["inspected"],
                }
                for item_id in ids
            ],
            {
                "input_tokens": 10,
                "prompt_tokens": 10,
                "completion_tokens": 5,
                "total_tokens": 15,
            },
        )


class SingleGroupReviewer(EchoReviewer):
    max_review_groups_per_request = 1


class ConfirmingReviewer(EchoReviewer):
    def review(
        self, prompt: str, *, timeout_seconds: int, max_reviews: int
    ) -> tuple[list[dict], dict]:
        ids = [
            item["candidate"]["candidate_id"]
            for item in json.loads(prompt.split("\n\n", 1)[1])["items"]
        ]
        self.calls.append(ids)
        return (
            [
                {
                    "candidate_id": item_id,
                    "verdict": "confirmed_vulnerability",
                    "severity": "high",
                    "confidence": "high",
                    "title": "Active debug",
                    "evidence": ["debug=True in source"],
                }
                for item_id in ids
            ],
            {},
        )


def test_same_endpoint_different_vulnerabilities_are_not_grouped() -> None:
    sql = candidate("ai-sql", "SQL Injection", 10)
    xss = candidate("ai-xss", "Reflected XSS", 10)
    triage = triage_candidates(
        discovery(sql, xss),
        verified(sql, xss),
        merged(scanner("scan-sql", 10, "sql"), scanner("scan-xss", 10, "xss")),
    )
    assert len(triage.groups) == 2
    assert {record.disposition.value for record in triage.records} == {
        "scanner_overlap"
    }
    assert triage.records[0].group_id != triage.records[1].group_id


def test_sql_source_alerts_join_only_their_explicit_codeql_sink_flow(
    tmp_path: Path,
) -> None:
    sink = scanner("sql-sink", 50, "sql")
    steps = tuple(
        CodeFlowStep(
            0, 0, index, FindingLocation("app.py", line, 1, line, 10), None, None
        )
        for index, line in enumerate((45, 47, 50))
    )
    sink_source = replace(sink.canonical_finding, code_flow=steps)
    sink = replace(sink, canonical_finding=sink_source, source_findings=(sink_source,))

    def semgrep(item_id: str, line: int) -> MergedFinding:
        base = scanner(item_id, line, "sql")
        source = replace(
            base.canonical_finding,
            scanner=ScannerProvenance("semgrep-ce", "Semgrep", "1", 0, line, None),
            rule_id=f"tainted-sql-{line}",
        )
        return replace(
            base,
            canonical_finding=source,
            source_findings=(source,),
            scanners=("semgrep-ce",),
            rule_ids=(source.rule_id,),
        )

    matched = (semgrep("source-45", 45), semgrep("source-47", 47))
    nearby = semgrep("nearby-48", 48)
    triage = triage_candidates(discovery(), verified(), merged(sink, *matched, nearby))
    assert len(triage.groups) == 2
    grouped = next(group for group in triage.groups if group.group_id == "sql-sink")
    assert set(grouped.scanner_finding_ids) == {"sql-sink", "source-45", "source-47"}
    assert next(
        group for group in triage.groups if group.group_id == "nearby-48"
    ).scanner_finding_ids == ("nearby-48",)
    review = run_security_review(
        discovery(),
        verified(),
        provider=EchoReviewer(),
        project_root=tmp_path,
        merged=merged(sink, *matched, nearby),
        triage=triage,
    )
    assert len(review.reviews) == 2
    assert set(
        next(
            item for item in review.reviews if item.candidate_id == "sql-sink"
        ).source_ids
    ) == {
        "sql-sink",
        "source-45",
        "source-47",
    }


def test_groups_same_issue_and_retains_every_source_id() -> None:
    first = candidate("ai-one", "Missing ownership check", 50)
    second = candidate("ai-two", "IDOR", 51)
    triage = triage_candidates(
        discovery(first, second), verified(first, second), merged()
    )
    assert len(triage.groups) == 1
    assert triage.groups[0].candidate_ids == ("ai-one", "ai-two")
    assert [record.disposition.value for record in triage.records] == [
        "novel_candidate",
        "candidate_overlap",
    ]


def test_runtime_admin_and_source_candidate_share_one_group() -> None:
    base = scanner("admin-runtime", 10)
    location = FindingLocation("/admin", None, None, None, None)
    source = replace(
        base.canonical_finding,
        rule_id="auth.broken-access-control",
        title="Admin panel accessible to non-admin",
        primary_location=location,
        scanner=ScannerProvenance(
            "authorization-dast", "Authorization DAST", "1", 0, 0, None
        ),
        categories=("dast", "authorization"),
        cwes=(),
    )
    runtime = replace(
        base,
        canonical_finding=source,
        source_findings=(source,),
        primary_location=location,
        scanners=("authorization-dast",),
        categories=("dast", "authorization"),
        cwes=(),
    )
    ai = replace(
        candidate("ai-admin", "Authorization", 12),
        entry_point=CandidateAnchor("app.py", 10, '@app.route("/admin")'),
    )
    triage = triage_candidates(discovery(ai), verified(ai), merged(runtime))
    assert len(triage.groups) == 1
    assert triage.groups[0].scanner_finding_ids == ("admin-runtime",)
    assert triage.groups[0].candidate_ids == ("ai-admin",)


def test_xss_flow_grouping_keeps_distinct_source_and_response_branch(
    tmp_path: Path,
) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        '@app.route("/search")\n'
        "def search():\n"
        '    q = request.args.get("q", "")\n'
        "    try:\n"
        "        pass\n"
        "    except Exception:\n"
        "        return q\n"
        '    html = f"<h2>{q}</h2>"\n'
        "    html += str(row)\n"
        "    return html\n",
        encoding="utf-8",
    )
    sink = scanner("xss-sink", 11, "xss")
    flow = tuple(
        CodeFlowStep(
            0, 0, index, FindingLocation("app.py", line, 1, line, 10), None, None
        )
        for index, line in enumerate((4, 9, 10, 11))
    )
    sink_source = replace(sink.canonical_finding, code_flow=flow)
    sink = replace(sink, canonical_finding=sink_source, source_findings=(sink_source,))

    def semgrep(item_id: str, line: int) -> MergedFinding:
        base = scanner(item_id, line, "xss")
        source = replace(
            base.canonical_finding,
            scanner=ScannerProvenance("semgrep-ce", "Semgrep", "1", 0, line, None),
            rule_id="python.flask.security.injection.raw-html-format.raw-html-format",
        )
        return replace(
            base,
            canonical_finding=source,
            source_findings=(source,),
            scanners=("semgrep-ce",),
            rule_ids=(source.rule_id,),
        )

    reflected = semgrep("direct-q", 9)
    other_source = semgrep("db-row", 10)
    error = scanner("error-xss", 8, "xss")
    runtime_base = scanner("runtime-xss", 1, "xss")
    runtime_source = replace(
        runtime_base.canonical_finding,
        scanner=ScannerProvenance("web-runtime", "Web Runtime", "1", 0, 0, None),
        rule_id="web.reflected-xss",
        primary_location=FindingLocation("/search", None, None, None, None),
        runtime_evidence={"status": 200, "payload_reflected": True},
        cwes=(),
    )
    runtime = replace(
        runtime_base,
        canonical_finding=runtime_source,
        source_findings=(runtime_source,),
        primary_location=runtime_source.primary_location,
        scanners=("web-runtime",),
        cwes=(),
    )
    triage = triage_candidates(
        discovery(),
        verified(),
        merged(sink, reflected, other_source, error, runtime),
        project_root=tmp_path,
    )
    grouped = next(group for group in triage.groups if group.group_id == "xss-sink")
    assert set(grouped.scanner_finding_ids) == {"xss-sink", "direct-q", "runtime-xss"}
    assert {group.group_id for group in triage.groups} == {
        "xss-sink",
        "db-row",
        "error-xss",
    }


def test_deployment_scope_prevents_debug_source_from_blocking_docker(
    tmp_path: Path,
) -> None:
    base = scanner("debug-source", 10)
    source = replace(
        base.canonical_finding, rule_id="py/flask-debug", title="Flask debug mode"
    )
    finding = replace(base, canonical_finding=source, source_findings=(source,))
    context = {
        "backend": "docker_compose",
        "flask_debug": False,
        "basis": "hash-matched Dockerfile CMD without Compose command/entrypoint override",
    }
    provider = ConfirmingReviewer()
    result = run_security_review(
        discovery(),
        verified(),
        provider=provider,
        project_root=tmp_path,
        merged=merged(finding),
        deployment_context=context,
    )
    assert result.reviews[0].verdict.value == "needs_more_evidence"
    assert "debug=False" in result.reviews[0].explanation
    assert evaluate_policy(result.to_dict()).decisions[0].action == "warn"
    without_attestation = run_security_review(
        discovery(),
        verified(),
        provider=ConfirmingReviewer(),
        project_root=tmp_path,
        merged=merged(finding),
    )
    assert without_attestation.reviews[0].verdict.value == "confirmed_vulnerability"
    assert evaluate_policy(without_attestation.to_dict()).decisions[0].action == "block"
    active_debug = run_security_review(
        discovery(),
        verified(),
        provider=ConfirmingReviewer(),
        project_root=tmp_path,
        merged=merged(finding),
        deployment_context={**context, "flask_debug": True},
    )
    assert active_debug.reviews[0].verdict.value == "confirmed_vulnerability"


def test_inconclusive_and_rejected_candidates_are_visible_without_review_groups() -> (
    None
):
    uncertain = candidate("ai-uncertain", "IDOR", 50)
    rejected = candidate("ai-rejected", "IDOR", 60)
    verification = VerificationResult(
        "1.0",
        "completed",
        "root",
        (
            replace(
                verified(uncertain).records[0],
                disposition=VerificationDisposition.NEEDS_MORE_EVIDENCE,
            ),
            replace(
                verified(rejected).records[0],
                disposition=VerificationDisposition.REJECTED,
            ),
        ),
        (),
    )
    triage = triage_candidates(discovery(uncertain, rejected), verification, merged())
    assert [record.disposition.value for record in triage.records] == [
        "needs_more_evidence",
        "rejected",
    ]
    assert triage.groups == ()
    assert triage.summary.input_ai_candidates == 2


def test_review_batches_all_groups_without_global_cutoff(tmp_path: Path) -> None:
    findings = tuple(scanner(f"scan-{index}", 10 + index * 10) for index in range(11))
    novel = candidate("ai-novel", "IDOR", 200)
    disc = discovery(novel)
    verification = verified(novel)
    triage = triage_candidates(disc, verification, merged(*findings))
    provider = EchoReviewer()
    result = run_security_review(
        disc,
        verification,
        provider=provider,
        project_root=tmp_path,
        merged=merged(*findings),
        triage=triage,
        max_reviews=2,
    )
    assert result.status == "completed"
    assert len(result.reviews) == len(triage.groups)
    assert result.pending_ids == ()
    assert result.usage["expected_groups"] == len(triage.groups)
    assert result.usage["reviewed_groups"] == len(triage.groups)
    assert result.usage["prompt_tokens"] == 10 * len(provider.calls)
    assert all(len(batch) <= 2 for batch in provider.calls)
    assert len({item.candidate_id for item in result.reviews}) == len(triage.groups)


def test_provider_can_limit_reviews_to_one_group_per_request(tmp_path: Path) -> None:
    findings = tuple(scanner(f"scan-{index}", 10 + index * 10) for index in range(5))
    provider = SingleGroupReviewer()
    result = run_security_review(
        discovery(),
        verified(),
        provider=provider,
        project_root=tmp_path,
        merged=merged(*findings),
        max_reviews=10,
    )
    assert result.status == "completed"
    assert len(provider.calls) == len(findings)
    assert all(len(batch) == 1 for batch in provider.calls)
    assert len(result.reviews) == len(findings)


def test_missing_model_response_is_retried_and_never_silently_dropped(
    tmp_path: Path,
) -> None:
    findings = (scanner("scan-one", 10), scanner("scan-two", 30))
    provider = EchoReviewer(omit_first_batch=True)
    empty = discovery()
    verification = verified()
    result = run_security_review(
        empty,
        verification,
        provider=provider,
        project_root=tmp_path,
        merged=merged(*findings),
        max_reviews=2,
    )
    assert result.status == "completed"
    assert len(result.reviews) == 2
    assert len(provider.calls) == 2


def test_provider_failure_marks_remaining_groups_pending(tmp_path: Path) -> None:
    findings = tuple(scanner(f"scan-{index}", 10 + index * 10) for index in range(5))
    provider = EchoReviewer(fail_after=1)
    result = run_security_review(
        discovery(),
        verified(),
        provider=provider,
        project_root=tmp_path,
        merged=merged(*findings),
        max_reviews=2,
    )
    assert result.status == "partial"
    assert len(result.reviews) == 2
    assert len(result.pending_ids) == 3
    assert set(result.pending_ids).isdisjoint(
        {item.candidate_id for item in result.reviews}
    )


def test_format_failure_retries_once_and_keeps_reviewing_other_groups(
    tmp_path: Path,
) -> None:
    findings = tuple(scanner(f"scan-{index}", 10 + index * 10) for index in range(3))

    class FormatFailureReviewer(SingleGroupReviewer):
        def __init__(self):
            super().__init__()
            self.failures = 0

        def review(self, prompt, *, timeout_seconds, max_reviews):
            ids = [
                item["candidate"]["candidate_id"]
                for item in json.loads(prompt.split("\n\n", 1)[1])["items"]
            ]
            if ids == ["scan-0"] and self.failures < 2:
                self.failures += 1
                raise RuntimeError(
                    "AI provider request failed with HTTP 400 (json_validate_failed)"
                )
            return super().review(
                prompt, timeout_seconds=timeout_seconds, max_reviews=max_reviews
            )

    provider = FormatFailureReviewer()
    result = run_security_review(
        discovery(),
        verified(),
        provider=provider,
        project_root=tmp_path,
        merged=merged(*findings),
    )
    assert result.status == "partial"
    assert result.pending_ids == ("scan-0",)
    assert {item.candidate_id for item in result.reviews} == {"scan-1", "scan-2"}
    assert provider.failures == 2


def test_review_checkpoint_can_resume_without_repeating_completed_groups(
    tmp_path: Path,
) -> None:
    findings = tuple(scanner(f"scan-{index}", 10 + index * 10) for index in range(5))
    first_provider = EchoReviewer(fail_after=1)
    snapshots = []
    first = run_security_review(
        discovery(),
        verified(),
        provider=first_provider,
        project_root=tmp_path,
        merged=merged(*findings),
        max_reviews=2,
        on_progress=snapshots.append,
    )
    second_provider = EchoReviewer()
    resumed = run_security_review(
        discovery(),
        verified(),
        provider=second_provider,
        project_root=tmp_path,
        merged=merged(*findings),
        max_reviews=2,
        prior_reviews=first.reviews,
    )

    assert len(snapshots) == 1
    assert len(snapshots[0].reviews) == 2
    assert first.status == "partial"
    assert resumed.status == "completed"
    assert len(resumed.reviews) == 5
    assert resumed.usage["reused_groups"] == 2
    assert all(
        item_id not in {item.candidate_id for item in first.reviews}
        for call in second_provider.calls
        for item_id in call
    )


def test_prior_verdict_is_not_reused_when_ai_evidence_joins_group(
    tmp_path: Path,
) -> None:
    scanner_items = merged(scanner("scan-sql", 10), scanner("scan-other", 70))
    old = run_security_review(
        discovery(),
        verified(),
        provider=EchoReviewer(),
        project_root=tmp_path,
        merged=scanner_items,
    )
    ai = candidate("ai-sql", "SQL Injection", 10)
    new_discovery = discovery(ai)
    new_verification = verified(ai)
    triage = triage_candidates(new_discovery, new_verification, scanner_items)
    provider = EchoReviewer()
    updated = run_security_review(
        new_discovery,
        new_verification,
        provider=provider,
        project_root=tmp_path,
        merged=scanner_items,
        triage=triage,
        prior_reviews=old.reviews,
    )
    assert updated.status == "completed"
    assert updated.usage["reused_groups"] == 1
    assert provider.calls == [["scan-sql"]]
    assert next(
        item for item in updated.reviews if item.candidate_id == "scan-sql"
    ).source_ids == (
        "scan-sql",
        "ai-sql",
    )


def test_policy_and_report_expose_unresolved_and_unreviewed_groups() -> None:
    review = {
        "status": "partial",
        "reviews": [],
        "pending_ids": ["scan-one"],
        "usage": {"expected_groups": 1},
    }
    triage = {
        "summary": {"input_ai_candidates": 1, "needs_more_evidence": 1},
        "records": [
            {"candidate_id": "ai-uncertain", "disposition": "needs_more_evidence"}
        ],
    }

    policy = evaluate_policy(review, triage_payload=triage)
    report = render_final_report(
        project="test", review=review, policy=policy.to_dict(), triage=triage
    )

    assert policy.status == "incomplete"
    assert policy.blocking is False
    assert "ai-uncertain" in report
    assert "scan-one" in report
    assert "pending: **1**" in report


def test_review_receives_linked_discovery_probe_as_inconclusive_context(
    tmp_path: Path,
) -> None:
    ai = candidate("ai-new", "SQL Injection", 10)

    class CapturingReviewer(EchoReviewer):
        def review(self, prompt, *, timeout_seconds, max_reviews):
            self.prompt_items = json.loads(prompt.split("\n\n", 1)[1])["items"]
            return super().review(
                prompt, timeout_seconds=timeout_seconds, max_reviews=max_reviews
            )

    provider = CapturingReviewer()
    run_security_review(
        discovery(ai),
        verified(ai),
        provider=provider,
        project_root=tmp_path,
        merged=merged(),
        discovery_test_evidence={
            "candidates": [
                {
                    "candidate_id": "ai-new",
                    "probes": [
                        {
                            "proposal_id": "route-1",
                            "method": "GET",
                            "path": "/account",
                            "http_status": 200,
                            "security_assertion": "not_defined",
                            "conclusion": "inconclusive",
                        }
                    ],
                    "workflow_tests": [
                        {
                            "workflow_id": "excessive-data",
                            "method": "GET",
                            "path": "/me",
                            "http_status": 200,
                            "result": "violated",
                        }
                    ],
                }
            ]
        },
    )
    assert (
        provider.prompt_items[0]["discovery_test_evidence"][0]["probes"][0][
            "conclusion"
        ]
        == "inconclusive"
    )
    assert (
        provider.prompt_items[0]["discovery_test_evidence"][0]["workflow_tests"][0][
            "result"
        ]
        == "violated"
    )


def test_failed_declared_workflow_routes_unverified_candidate_to_cautious_review(
    tmp_path: Path,
) -> None:
    ai = candidate("ai-runtime", "Sensitive data exposure", 20)
    evidence = {
        "candidates": [
            {
                "candidate_id": ai.candidate_id,
                "probes": [],
                "workflow_tests": [
                    {
                        "workflow_id": "excessive-data",
                        "method": "GET",
                        "path": "/me",
                        "http_status": 200,
                        "result": "violated",
                    }
                ],
            }
        ]
    }
    unverified = verified(ai, disposition=VerificationDisposition.NEEDS_MORE_EVIDENCE)
    triage = triage_candidates(
        discovery(ai), unverified, merged(), discovery_test_evidence=evidence
    )
    assert triage.records[0].disposition.value == "uncertain_overlap"
    assert triage.groups[0].candidate_ids == (ai.candidate_id,)
    provider = EchoReviewer()
    result = run_security_review(
        discovery(ai),
        unverified,
        provider=provider,
        project_root=tmp_path,
        merged=merged(),
        triage=triage,
        discovery_test_evidence=evidence,
    )
    assert result.status == "completed"
    assert provider.calls == [[ai.candidate_id]]


def test_passed_workflow_does_not_promote_unverified_candidate() -> None:
    ai = candidate("ai-uncertain", "Authentication", 20)
    evidence = {
        "candidates": [
            {
                "candidate_id": ai.candidate_id,
                "workflow_tests": [{"result": "passed"}],
            }
        ]
    }
    triage = triage_candidates(
        discovery(ai),
        verified(ai, disposition=VerificationDisposition.NEEDS_MORE_EVIDENCE),
        merged(),
        discovery_test_evidence=evidence,
    )
    assert triage.records[0].disposition.value == "needs_more_evidence"
    assert triage.records[0].group_id is None
