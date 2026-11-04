import hashlib
import io
import json
import os
import urllib.error
from pathlib import Path
from types import SimpleNamespace

import pytest

from security_reviewer_v2.discovery import agent as agent_module
from security_reviewer_v2.discovery import provider as provider_module
from security_reviewer_v2.discovery.agent import (
    DiscoveryAgent,
    _build_prompt,
    _line_contains,
    _redact,
    reground_saved_discovery,
)
from security_reviewer_v2.discovery.context_tools import ContextBroker
from security_reviewer_v2.discovery.models import (
    CandidateAnchor,
    CandidateDisposition,
    CandidateFinding,
    CandidateMissingCheck,
    DiscoveryConfig,
    DiscoveryResult,
    DiscoveryStatus,
    DiscoveryTarget,
)
from security_reviewer_v2.discovery.provider import GroqProvider
from security_reviewer_v2.discovery.scope import DiscoveryScope
from security_reviewer_v2.verification import verify_discovery


class FakeProvider:
    name = "fake"
    model = "test-model"

    def __init__(self):
        self.prompt = None

    def discover(self, prompt, *, timeout_seconds, max_candidates):
        self.prompt = prompt
        return (
            [
                {
                    "title": "Possible authorization issue",
                    "category": "authorization",
                    "severity": "high",
                    "confidence": "medium",
                    "path": "app.py",
                    "start_line": 1,
                    "end_line": 1,
                    "evidence": ["request id is used before ownership check"],
                    "reasoning": "The candidate requires verification.",
                },
                {
                    "title": "Invented path",
                    "category": "unknown",
                    "severity": "low",
                    "confidence": "low",
                    "path": "../outside.py",
                    "start_line": 1,
                    "evidence": ["untrusted"],
                },
            ],
            {"prompt_tokens": 10},
        )


def test_multiline_python_anchor_requires_contiguous_tokens_on_cited_line():
    lines = (
        '@app.route("/profile/<int:user_id>")',
        "def profile(user_id):",
        "    row = db.execute(",
        '        "SELECT id, username FROM users WHERE id = ?", (user_id,)',
        "    ).fetchone()",
        "    return row",
    )
    broker = SimpleNamespace(_load=lambda _path: lines)
    assert _line_contains(
        broker,
        "app.py",
        1,
        '@app.route("/profile/<int:user_id>")\ndef profile(user_id):',
    )
    assert _line_contains(
        broker,
        "app.py",
        3,
        'row = db.execute("SELECT id, username FROM users WHERE id = ?", (user_id,)).fetchone()',
    )
    assert not _line_contains(
        broker,
        "app.py",
        2,
        'row = db.execute("SELECT id, username FROM users WHERE id = ?", (user_id,)).fetchone()',
    )
    assert not _line_contains(
        broker,
        "app.py",
        3,
        'row = db.execute("SELECT ssn FROM users WHERE id = ?", (user_id,)).fetchone()',
    )


def test_saved_regrounding_keeps_original_scope_and_rejected_candidates(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text(
        '@app.route("/orders/<int:order_id>")\ndef view_order(order_id):\n'
        '    row = db.execute("SELECT * FROM orders WHERE id = ?", (order_id,))\n'
        "    return row\n",
        encoding="utf-8",
    )
    profile = {
        "profile": {"inventory": [{"path": "app.py", "category": "source"}]},
        "project_snapshot": {
            "root_path": os.path.normcase(str(tmp_path.resolve())),
            "files": [
                {
                    "path": "app.py",
                    "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                }
            ],
        },
    }
    title = "Order ownership"
    candidate_id = (
        "ai-" + hashlib.sha256((title + "app.py" + "1").encode()).hexdigest()[:16]
    )
    candidate = CandidateFinding(
        candidate_id,
        title,
        "Authorization",
        "high",
        "medium",
        "app.py",
        1,
        4,
        ('3:     row = db.execute("SELECT * FROM orders WHERE id = ?", (order_id,))',),
        "review required",
        "ai_discovery",
        CandidateDisposition.INCONCLUSIVE,
        (),
        CandidateAnchor(
            "app.py",
            1,
            '@app.route("/orders/<int:order_id>")\ndef view_order(order_id):',
        ),
        CandidateAnchor(
            "app.py",
            3,
            'row = db.execute("SELECT * FROM orders WHERE id = ?", (order_id,))',
        ),
        CandidateMissingCheck(
            "app.py", 4, "check owner", "No owner check before return"
        ),
        ("Is this endpoint meant to be owner-only?",),
    )
    result = DiscoveryResult(
        "1.2",
        DiscoveryStatus.PARTIAL,
        "test",
        "test",
        ("file:app.py",),
        (candidate,),
        (),
        (),
        {},
        (DiscoveryTarget("file:app.py", "source", "app.py", 1, 4, ()),),
    )
    updated = reground_saved_discovery(
        result, project_root=tmp_path, profile_artifact=profile
    )
    assert updated.candidates[0].verification is CandidateDisposition.SUPPORTED
    assert result.candidates[0].verification is CandidateDisposition.INCONCLUSIVE

    rejected = CandidateFinding(
        "rejected",
        title,
        "Authorization",
        "high",
        "medium",
        "app.py",
        1,
        4,
        candidate.evidence,
        "",
        "ai_discovery",
        CandidateDisposition.REJECTED,
        (),
    )
    rejected_result = DiscoveryResult(
        "1.2", DiscoveryStatus.PARTIAL, "test", "test", (), (rejected,), (), (), {}, ()
    )
    unchanged = reground_saved_discovery(
        rejected_result, project_root=tmp_path, profile_artifact=profile
    )
    assert unchanged.candidates[0] == rejected


@pytest.mark.parametrize("operation", ("discover", "review"))
def test_groq_failure_reports_status_without_response_body(monkeypatch, operation):
    def reject(_request, _timeout):
        assert _request.get_header("User-agent").startswith(
            "agentic-security-reviewer-v2/"
        )
        raise urllib.error.HTTPError(
            "https://api.groq.com", 429, "sensitive details", {}, None
        )

    monkeypatch.setattr(provider_module, "_urlopen", reject)
    provider = GroqProvider(model="test-model", api_key="test-secret")
    with pytest.raises(RuntimeError, match=r"HTTP 429") as error:
        if operation == "discover":
            provider.discover("sample", timeout_seconds=10, max_candidates=1)
        else:
            provider.review("sample", timeout_seconds=10, max_reviews=1)
    assert "sensitive details" not in str(error.value)
    assert "test-secret" not in str(error.value)


def test_groq_discovery_uses_strict_schema_for_supported_model():
    response_format = provider_module._discovery_response_format("openai/gpt-oss-20b")
    assert response_format["type"] == "json_schema"
    assert response_format["json_schema"]["strict"] is True
    schema = response_format["json_schema"]["schema"]
    assert set(schema["required"]) == {"candidates", "context_requests"}
    assert schema["properties"]["candidates"]["items"]["properties"]["missing_check"][
        "type"
    ] == ["object", "null"]
    assert provider_module._discovery_response_format("another-model") == {
        "type": "json_object"
    }


def test_groq_waits_for_rate_limit_then_retries(monkeypatch):
    calls = []
    waits = []

    def open_once_recovered(_request, _timeout):
        calls.append(1)
        if len(calls) == 1:
            raise urllib.error.HTTPError(
                "https://api.groq.com",
                429,
                "limited",
                {"Retry-After": "2"},
                io.BytesIO(b'{"error":{"type":"rate_limit_error"}}'),
            )
        return io.BytesIO(
            b'{"choices":[{"message":{"content":"{\\"candidates\\":[],\\"context_requests\\":[]}"}}],"usage":{"prompt_tokens":3}}'
        )

    monkeypatch.setattr(provider_module, "_urlopen", open_once_recovered)
    monkeypatch.setattr(provider_module.time, "sleep", waits.append)
    result, usage = GroqProvider(
        model="openai/gpt-oss-120b", api_key="test-secret"
    ).discover("sample", timeout_seconds=10, max_candidates=1)
    assert result["candidates"] == []
    assert len(calls) == 2
    assert waits == [2.0]
    assert usage["retry_count"] == 1
    assert usage["rate_limit_wait_seconds"] == 2.0


def test_groq_retries_one_format_error_without_waiting(monkeypatch):
    calls = []

    def open_once_recovered(_request, _timeout):
        calls.append(1)
        if len(calls) == 1:
            raise urllib.error.HTTPError(
                "https://api.groq.com",
                400,
                "format error",
                {},
                io.BytesIO(b'{"error":{"code":"json_validate_failed"}}'),
            )
        return io.BytesIO(
            b'{"choices":[{"message":{"content":"{\\"candidates\\":[],\\"context_requests\\":[]}"}}]}'
        )

    monkeypatch.setattr(provider_module, "_urlopen", open_once_recovered)
    _, usage = GroqProvider(
        model="openai/gpt-oss-120b", api_key="test-secret"
    ).discover("sample", timeout_seconds=10, max_candidates=1)
    assert len(calls) == 2
    assert usage["retry_count"] == 1


def test_groq_discovery_falls_back_once_after_strict_schema_400(monkeypatch):
    modes = []

    def open_json_fallback(request, _timeout):
        mode = json.loads(request.data)["response_format"]["type"]
        modes.append(mode)
        if mode == "json_schema":
            raise urllib.error.HTTPError(
                "https://api.groq.com",
                400,
                "bad request",
                {},
                io.BytesIO(b'{"error":{"message":"format failure"}}'),
            )
        return io.BytesIO(
            b'{"choices":[{"message":{"content":"{\\"candidates\\":[],\\"context_requests\\":[]}"}}]}'
        )

    monkeypatch.setattr(provider_module, "_urlopen", open_json_fallback)
    result, usage = GroqProvider(
        model="openai/gpt-oss-120b", api_key="test-secret"
    ).discover(
        "sample",
        timeout_seconds=10,
        max_candidates=1,
    )
    assert modes == ["json_schema", "json_object"]
    assert result == {
        "candidates": [],
        "context_requests": [],
        "omitted_candidates": 0,
        "omitted_context_requests": 0,
    }
    assert usage["format_fallback_count"] == 1
    assert usage["retry_count"] == 1


def test_groq_discovery_rejects_malformed_json_fallback(monkeypatch):
    def open_malformed_fallback(request, _timeout):
        if json.loads(request.data)["response_format"]["type"] == "json_schema":
            raise urllib.error.HTTPError(
                "https://api.groq.com", 400, "bad request", {}, None
            )
        return io.BytesIO(
            b'{"choices":[{"message":{"content":"{\\"candidates\\":[{}],\\"context_requests\\":[]}"}}]}'
        )

    monkeypatch.setattr(provider_module, "_urlopen", open_malformed_fallback)
    with pytest.raises(RuntimeError, match="fallback did not match"):
        GroqProvider(model="openai/gpt-oss-120b", api_key="test-secret").discover(
            "sample",
            timeout_seconds=10,
            max_candidates=1,
        )


def test_groq_discovery_never_falls_back_on_authentication_error(monkeypatch):
    modes = []

    def reject_auth(request, _timeout):
        modes.append(json.loads(request.data)["response_format"]["type"])
        raise urllib.error.HTTPError(
            "https://api.groq.com", 401, "unauthorized", {}, None
        )

    monkeypatch.setattr(provider_module, "_urlopen", reject_auth)
    with pytest.raises(RuntimeError, match="HTTP 401"):
        GroqProvider(model="openai/gpt-oss-120b", api_key="test-secret").discover(
            "sample",
            timeout_seconds=10,
            max_candidates=1,
        )
    assert modes == ["json_schema"]


def test_discovery_verifies_paths_and_keeps_candidates_bounded(tmp_path: Path):
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    risk = SimpleNamespace(
        findings=[
            SimpleNamespace(merged_finding_id="f-1", selected_for_deep_review=True)
        ]
    )
    context = SimpleNamespace(findings=[])
    result = DiscoveryAgent(FakeProvider(), DiscoveryConfig(max_targets=1)).run(
        SimpleNamespace(), context, risk, project_root=tmp_path
    )
    assert (
        result.status.value == "completed"
    )  # max_targets is per batch; later targets are still processed
    assert len(result.batches) == 2
    assert result.candidates[0].verification == CandidateDisposition.INCONCLUSIVE
    assert result.candidates[1].verification == CandidateDisposition.REJECTED


def test_upstream_limitations_do_not_make_successful_discovery_partial(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "def read_account(request):\n    return request.user\n", encoding="utf-8"
    )
    empty = SimpleNamespace(findings=(), coverage_gaps=())

    class EmptyProvider:
        name = "fake"
        model = "test"

        def discover(self, prompt, *, timeout_seconds, max_candidates):
            return {"candidates": [], "context_requests": []}, {}

    result = DiscoveryAgent(EmptyProvider()).run(
        empty,
        empty,
        empty,
        project_root=tmp_path,
        additional_coverage_gaps=("Browser crawl is GET-only.",),
    )
    assert result.status is DiscoveryStatus.COMPLETED
    assert "Browser crawl is GET-only." in result.coverage_gaps
    assert result.coverage_accounting == {
        "discovery_gaps": [],
        "inherited_limitations": ["Browser crawl is GET-only."],
        "context_notes": [],
    }


@pytest.mark.parametrize(
    "budget_gap",
    (
        "1 Application Map hints were omitted from the discovery prompt budget.",
        "1 source windows were shortened by the prompt character budget.",
    ),
)
def test_discovery_reduces_batch_when_context_does_not_fit(
    monkeypatch, tmp_path: Path, budget_gap: str
):
    (tmp_path / "app.py").write_text(
        "def first(request):\n    return request.user\n", encoding="utf-8"
    )
    (tmp_path / "auth.py").write_text(
        "def second(request):\n    return request.user\n", encoding="utf-8"
    )
    first = DiscoveryTarget("file:app.py", "source", "app.py", 1, 2, ())
    second = DiscoveryTarget("file:auth.py", "source", "auth.py", 1, 2, ())
    scope = DiscoveryScope(
        (first, second),
        {
            first.target_id: "1: def first(request):",
            second.target_id: "1: def second(request):",
        },
        (),
        (),
        (),
    )
    monkeypatch.setattr(
        agent_module, "plan_discovery_scope", lambda *args, **kwargs: scope
    )
    original = agent_module._build_prompt

    def budgeted_prompt(*args, **kwargs):
        prompt, targets, gaps = original(*args, **kwargs)
        if len(args[3].targets) > 1:
            gaps = (*gaps, budget_gap)
        return prompt, targets, gaps

    monkeypatch.setattr(agent_module, "_build_prompt", budgeted_prompt)
    empty = SimpleNamespace(findings=(), coverage_gaps=())

    class EmptyProvider:
        name = "fake"
        model = "test"

        def discover(self, prompt, *, timeout_seconds, max_candidates):
            return {"candidates": [], "context_requests": []}, {}

    result = DiscoveryAgent(
        EmptyProvider(), DiscoveryConfig(max_targets=2, max_batches=2)
    ).run(
        empty,
        empty,
        empty,
        project_root=tmp_path,
    )
    assert result.status is DiscoveryStatus.COMPLETED
    assert result.usage["targets"] == 2
    assert len(result.batches) == 2
    assert not result.coverage_accounting["discovery_gaps"]


def _inputs(root: Path):
    source = root / "app.py"
    source.write_text(
        "from flask import request, session\n"
        "def flagged():\n"
        "    return request.args.get('q')\n"
        "\n"
        "@app.route('/orders/<int:order_id>')\n"
        "def view_order(order_id):\n"
        "    user_id = session['user_id']\n"
        "    return db.execute('SELECT * FROM orders WHERE id = ?', (order_id,))\n",
        encoding="utf-8",
    )
    (root / "auth.py").write_text(
        "def authorize(user_id):\n    return True\n", encoding="utf-8"
    )
    (root / ".env").write_text("SECRET_KEY=not-for-model\n", encoding="utf-8")
    location = SimpleNamespace(path="app.py", start_line=3, end_line=3)
    source_finding = SimpleNamespace(primary_location=location)
    finding = SimpleNamespace(
        merged_finding_id="f-1",
        canonical_finding=SimpleNamespace(title="Known finding"),
        primary_location=location,
        source_findings=(source_finding,),
    )
    merged = SimpleNamespace(findings=(finding,), coverage_gaps=())
    rank = SimpleNamespace(
        merged_finding_id="f-1",
        selected_for_deep_review=True,
        primary_location=location,
        rank=1,
        risk_score=80,
    )
    risk = SimpleNamespace(findings=(rank,), coverage_gaps=())
    context = SimpleNamespace(findings=(), coverage_gaps=())
    paths = ("app.py", "auth.py")
    profile = {
        "profile": {
            "inventory": [{"path": path, "category": "source"} for path in paths],
            "coverage_gaps": [],
        },
        "scan_plan": {"coverage_gaps": ["Authorization coverage gap in auth.py"]},
        "project_snapshot": {
            "root_path": os.path.normcase(str(root.resolve())),
            "files": [
                {
                    "path": path,
                    "sha256": hashlib.sha256((root / path).read_bytes()).hexdigest(),
                }
                for path in paths
            ],
        },
    }
    return merged, context, risk, profile


def test_discovery_balances_risk_gaps_unflagged_files_and_hotspots(tmp_path: Path):
    merged, context, risk, profile = _inputs(tmp_path)
    provider = FakeProvider()
    result = DiscoveryAgent(provider, DiscoveryConfig(max_targets=4)).run(
        merged,
        context,
        risk,
        project_root=tmp_path,
        profile_artifact=profile,
    )
    kinds = {item.kind for item in result.target_plan}
    assert "risk_finding" in kinds
    assert "coverage_gap" in kinds or "no_findings" in kinds
    assert "unflagged_hotspot" in kinds
    body = json.loads(provider.prompt.split("\n\n", 1)[1])
    assert {item["target_id"] for item in body["targets"]} == set(result.scope)
    assert "view_order" in provider.prompt
    assert "not-for-model" not in provider.prompt


def test_discovery_rejects_stale_unflagged_file_and_reports_gap(tmp_path: Path):
    merged, context, risk, profile = _inputs(tmp_path)
    (tmp_path / "auth.py").write_text(
        "def changed():\n    return False\n", encoding="utf-8"
    )
    provider = FakeProvider()
    result = DiscoveryAgent(provider, DiscoveryConfig(max_targets=4)).run(
        merged,
        context,
        risk,
        project_root=tmp_path,
        profile_artifact=profile,
    )
    assert result.status.value in {"completed", "partial"}
    assert any("source hash differs" in gap for gap in result.coverage_gaps)
    assert all(item.path != "auth.py" for item in result.target_plan)


def test_prompt_budget_keeps_json_valid_and_scope_truthful(tmp_path: Path):
    merged, context, risk, profile = _inputs(tmp_path)
    provider = FakeProvider()
    result = DiscoveryAgent(
        provider, DiscoveryConfig(max_targets=4, max_context_chars=1_000)
    ).run(
        merged,
        context,
        risk,
        project_root=tmp_path,
        profile_artifact=profile,
    )
    if provider.prompt is not None:
        body = json.loads(provider.prompt.split("\n\n", 1)[1])
        assert {item["target_id"] for item in body["targets"]}.issubset(
            set(result.scope)
        )
        assert len(provider.prompt.split("\n\n", 1)[1]) <= 1_000
    assert len(result.target_plan) >= len(body["targets"])


def test_javascript_route_without_findings_is_sampled_and_out_of_scope_candidate_rejected(
    tmp_path: Path,
):
    source = tmp_path / "api.js"
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    source.write_text(
        "router.get('/users/:id', (req, res) => {\n"
        "  const userId = req.params.id;\n"
        "  return res.json(db.findUser(userId));\n"
        "});\n",
        encoding="utf-8",
    )
    profile = {
        "profile": {
            "inventory": [{"path": "api.js", "category": "source"}],
            "coverage_gaps": [],
        },
        "scan_plan": {"coverage_gaps": []},
        "project_snapshot": {
            "root_path": os.path.normcase(str(tmp_path.resolve())),
            "files": [
                {
                    "path": "api.js",
                    "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                }
            ],
        },
    }
    provider = FakeProvider()
    empty = SimpleNamespace(findings=(), coverage_gaps=())
    result = DiscoveryAgent(provider, DiscoveryConfig(max_targets=2)).run(
        empty,
        empty,
        empty,
        project_root=tmp_path,
        profile_artifact=profile,
        additional_coverage_gaps=(
            "Scanner did not support this JavaScript component.",
        ),
    )
    assert result.target_plan[0].kind == "no_findings"
    assert "router.get" in provider.prompt
    assert "Scanner did not support" in provider.prompt
    assert result.candidates[0].verification == CandidateDisposition.REJECTED
    assert (
        "not included in the bounded discovery scope"
        in result.candidates[0].verification_notes[0]
    )


def test_prompt_redacts_secret_assignments():
    assert "do-not-send" not in _redact("SECRET_KEY = 'do-not-send'")
    assert "do-not-send" not in _redact("api_key: 'do-not-send'")


def test_discovery_processes_all_planned_targets_in_batches(tmp_path: Path):
    merged, context, risk, profile = _inputs(tmp_path)

    class CountingProvider:
        name = "fake"
        model = "test"

        def __init__(self):
            self.prompts = []

        def discover(self, prompt, *, timeout_seconds, max_candidates):
            self.prompts.append(prompt)
            return {"candidates": [], "context_requests": []}, {
                "prompt_tokens": 7,
                "completion_tokens": 3,
            }

    provider = CountingProvider()
    result = DiscoveryAgent(
        provider,
        DiscoveryConfig(
            max_targets=1,
            input_cost_per_million_tokens_usd=1,
            output_cost_per_million_tokens_usd=2,
        ),
    ).run(merged, context, risk, project_root=tmp_path, profile_artifact=profile)
    assert len(result.batches) == len(result.target_plan) >= 3
    assert result.usage["provider_calls"] == len(result.batches)
    assert result.usage["estimated_cost_usd"] == len(result.batches) * 13 / 1_000_000
    assert not any(
        "planned discovery targets were not inspected" in gap
        for gap in result.coverage_gaps
    )
    assert all(
        batch.usage["estimated_cost_usd"] == 0.000013 for batch in result.batches
    )


def test_discovery_splits_format_failed_batch_without_losing_targets(tmp_path: Path):
    merged, context, risk, profile = _inputs(tmp_path)

    class FormatSensitiveProvider:
        name = "fake"
        model = "test"

        def __init__(self):
            self.sizes = []
            self.failed_once = False

        def discover(self, prompt, *, timeout_seconds, max_candidates):
            size = len(json.loads(prompt.split("\n\n", 1)[1])["targets"])
            self.sizes.append(size)
            if size > 1 and not self.failed_once:
                self.failed_once = True
                raise RuntimeError(
                    "AI provider request failed with HTTP 400 (json_validate_failed)"
                )
            return {"candidates": [], "context_requests": []}, {}

    provider = FormatSensitiveProvider()
    result = DiscoveryAgent(provider, DiscoveryConfig(max_targets=4)).run(
        merged, context, risk, project_root=tmp_path, profile_artifact=profile
    )
    assert provider.sizes[0] > 1
    assert max(provider.sizes[1:]) < provider.sizes[0]
    assert result.usage["format_split_calls"] == 1
    assert result.usage["planned_targets"] == result.usage["targets"]
    assert all(batch.status == "completed" for batch in result.batches)


def test_discovery_can_request_function_context_and_ground_structured_candidate(
    tmp_path: Path,
):
    merged, context, risk, profile = _inputs(tmp_path)

    class RequestingProvider:
        name = "fake"
        model = "test"

        def __init__(self):
            self.prompts = []

        def discover(self, prompt, *, timeout_seconds, max_candidates):
            self.prompts.append(prompt)
            if len(self.prompts) == 1:
                return {
                    "candidates": [],
                    "context_requests": [{"path": "auth.py", "symbol": "authorize"}],
                }, {"prompt_tokens": 5}
            return {
                "candidates": [
                    {
                        "title": "Possible authorization issue",
                        "path": "app.py",
                        "start_line": 8,
                        "end_line": 8,
                        "evidence": ["return db.execute"],
                        "category": "authorization",
                        "severity": "high",
                        "confidence": "medium",
                        "entry_point": {
                            "path": "app.py",
                            "line": 6,
                            "code": "def view_order(order_id):",
                        },
                        "sensitive_operation": {
                            "path": "app.py",
                            "line": 8,
                            "code": "return db.execute",
                        },
                        "missing_check": {
                            "path": "app.py",
                            "line": 8,
                            "expected_check": "order ownership",
                            "observation": "query uses order_id without user_id",
                        },
                        "remaining_questions": [
                            "Does another layer enforce ownership?"
                        ],
                    }
                ],
                "context_requests": [],
            }, {"completion_tokens": 3}

    provider = RequestingProvider()
    result = DiscoveryAgent(provider, DiscoveryConfig(max_targets=10)).run(
        merged, context, risk, project_root=tmp_path, profile_artifact=profile
    )
    assert len(result.context_exchanges) == 1
    assert result.context_exchanges[0].status == "collected"
    assert "def authorize" in provider.prompts[1]
    assert result.candidates[0].verification is CandidateDisposition.SUPPORTED
    assert result.candidates[0].remaining_questions
    assert (
        verify_discovery(result, project_root=tmp_path).records[0].disposition.value
        == "confirmed"
    )


def test_discovery_unstructured_candidate_never_becomes_verified(tmp_path: Path):
    merged, context, risk, profile = _inputs(tmp_path)

    class UnstructuredProvider:
        name = "fake"
        model = "test"

        def discover(self, prompt, *, timeout_seconds, max_candidates):
            return {
                "candidates": [
                    {
                        "title": "Possible issue",
                        "path": "app.py",
                        "start_line": 8,
                        "evidence": ["return db.execute"],
                    }
                ],
                "context_requests": [],
            }, {}

    result = DiscoveryAgent(UnstructuredProvider()).run(
        merged, context, risk, project_root=tmp_path, profile_artifact=profile
    )
    assert result.candidates[0].verification is CandidateDisposition.INCONCLUSIVE
    assert (
        verify_discovery(result, project_root=tmp_path).records[0].disposition.value
        == "needs_more_evidence"
    )


def test_context_request_outside_profile_is_rejected(tmp_path: Path):
    merged, context, risk, profile = _inputs(tmp_path)

    class BadRequestProvider:
        name = "fake"
        model = "test"

        def __init__(self):
            self.count = 0

        def discover(self, prompt, *, timeout_seconds, max_candidates):
            self.count += 1
            return (
                {
                    "candidates": [],
                    "context_requests": [{"path": "../outside.py", "start_line": 1}],
                }
                if self.count == 1
                else {"candidates": [], "context_requests": []}
            ), {}

    result = DiscoveryAgent(BadRequestProvider()).run(
        merged, context, risk, project_root=tmp_path, profile_artifact=profile
    )
    assert result.context_exchanges[0].status == "rejected"
    assert result.context_exchanges[0].code is None
    assert any("context request rejected" in gap for gap in result.coverage_gaps)


def test_batch_failure_keeps_prior_results_and_marks_remaining_scope(tmp_path: Path):
    merged, context, risk, profile = _inputs(tmp_path)

    class FailingProvider:
        name = "fake"
        model = "test"

        def __init__(self):
            self.calls = 0

        def discover(self, prompt, *, timeout_seconds, max_candidates):
            self.calls += 1
            if self.calls == 2:
                raise RuntimeError("provider unavailable")
            return {"candidates": [], "context_requests": []}, {"prompt_tokens": 4}

    result = DiscoveryAgent(FailingProvider(), DiscoveryConfig(max_targets=1)).run(
        merged, context, risk, project_root=tmp_path, profile_artifact=profile
    )
    assert result.status.value == "partial"
    assert len(result.scope) == 1
    assert result.batches[1].status == "failed"
    assert result.batches[1].provider_calls == 1
    assert any("not inspected" in gap for gap in result.coverage_gaps)


def test_malformed_model_batch_does_not_prevent_later_batches(tmp_path: Path):
    merged, context, risk, profile = _inputs(tmp_path)

    class SometimesMalformed:
        name = "fake"
        model = "test"

        def __init__(self):
            self.calls = 0

        def discover(self, prompt, *, timeout_seconds, max_candidates):
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError(
                    "Ollama returned non-JSON content (done_reason=length, eval_count=512)"
                )
            return {"candidates": [], "context_requests": []}, {}

    provider = SometimesMalformed()
    result = DiscoveryAgent(provider, DiscoveryConfig(max_targets=1)).run(
        merged, context, risk, project_root=tmp_path, profile_artifact=profile
    )
    assert result.status.value == "partial"
    assert provider.calls == len(result.batches) >= 3
    assert len(result.scope) == len(result.batches) - 1
    assert any("did not complete" in gap for gap in result.coverage_gaps)


def test_batch_limit_reports_uninspected_targets(tmp_path: Path):
    merged, context, risk, profile = _inputs(tmp_path)

    class EmptyProvider:
        name = "fake"
        model = "test"

        def discover(self, prompt, *, timeout_seconds, max_candidates):
            return {"candidates": [], "context_requests": []}, {}

    result = DiscoveryAgent(
        EmptyProvider(), DiscoveryConfig(max_targets=1, max_batches=1)
    ).run(merged, context, risk, project_root=tmp_path, profile_artifact=profile)
    assert result.status.value == "partial"
    assert result.usage["planned_targets"] > result.usage["targets"]
    assert any(
        "planned discovery targets were not inspected" in gap
        for gap in result.coverage_gaps
    )


def test_context_broker_rejects_stale_snapshot_and_duplicate_request(tmp_path: Path):
    _merged, _context, _risk, profile = _inputs(tmp_path)
    broker = ContextBroker(tmp_path, DiscoveryConfig(), profile, _redact)
    request = {"path": "auth.py", "symbol": "authorize"}
    (tmp_path / "auth.py").write_text(
        "def authorize(user_id):\n    return False\n", encoding="utf-8"
    )
    first = broker.fetch(request, batch_index=1, round_index=1)
    second = broker.fetch(request, batch_index=1, round_index=2)
    assert first.status == "unavailable"
    assert "hash differs" in first.note
    assert second.status == "rejected"
    assert second.code is None


def test_context_broker_finds_unique_python_symbol_without_path(tmp_path: Path):
    _merged, _context, _risk, profile = _inputs(tmp_path)
    broker = ContextBroker(tmp_path, DiscoveryConfig(), profile, _redact)
    exchange = broker.fetch({"symbol": "authorize"}, batch_index=1, round_index=1)
    assert exchange.status == "collected"
    assert exchange.resolved_path == "auth.py"
    assert exchange.resolved_start_line == 1


def test_structured_anchor_must_match_actual_source_line(tmp_path: Path):
    merged, context, risk, profile = _inputs(tmp_path)

    class InventingProvider:
        name = "fake"
        model = "test"

        def discover(self, prompt, *, timeout_seconds, max_candidates):
            return {
                "candidates": [
                    {
                        "title": "Invented anchor",
                        "path": "app.py",
                        "start_line": 8,
                        "evidence": ["return db.execute"],
                        "entry_point": {
                            "path": "app.py",
                            "line": 6,
                            "code": "def view_order(order_id):",
                        },
                        "sensitive_operation": {
                            "path": "app.py",
                            "line": 8,
                            "code": "db.delete_everything()",
                        },
                        "missing_check": {
                            "path": "app.py",
                            "line": 8,
                            "expected_check": "ownership",
                            "observation": "not seen",
                        },
                        "remaining_questions": ["Does a decorator check ownership?"],
                    }
                ],
                "context_requests": [],
            }, {}

    result = DiscoveryAgent(InventingProvider()).run(
        merged, context, risk, project_root=tmp_path, profile_artifact=profile
    )
    assert result.candidates[0].verification is CandidateDisposition.INCONCLUSIVE
    assert any(
        "Sensitive operation" in note
        for note in result.candidates[0].verification_notes
    )


def test_candidate_limit_does_not_stop_target_batches(tmp_path: Path):
    merged, context, risk, profile = _inputs(tmp_path)

    class ManyCandidates:
        name = "fake"
        model = "test"

        def __init__(self):
            self.calls = 0

        def discover(self, prompt, *, timeout_seconds, max_candidates):
            self.calls += 1
            return {
                "candidates": [
                    {
                        "title": f"Issue {self.calls}",
                        "path": "app.py",
                        "start_line": 8,
                        "evidence": ["return db.execute"],
                    }
                ],
                "context_requests": [],
            }, {}

    provider = ManyCandidates()
    result = DiscoveryAgent(
        provider, DiscoveryConfig(max_targets=1, max_total_candidates=1)
    ).run(merged, context, risk, project_root=tmp_path, profile_artifact=profile)
    assert provider.calls == len(result.target_plan) >= 3
    assert len(result.candidates) == 1
    assert any("candidate limit" in gap for gap in result.coverage_gaps)


def test_risk_target_fits_after_trimming_duplicate_background():
    location = SimpleNamespace(path="app.py", start_line=20, end_line=20)
    known = tuple(
        SimpleNamespace(
            merged_finding_id=f"known-{i}",
            primary_location=location,
            canonical_finding=SimpleNamespace(title="Known scanner issue"),
        )
        for i in range(30)
    )

    def evidence(scanner, index):
        return SimpleNamespace(
            scanner_id=scanner,
            rule_id=f"rule-{index}",
            location=location,
            excerpt=SimpleNamespace(code="x" * 600),
        )

    finding = SimpleNamespace(
        merged_finding_id="target",
        title="Deep review target",
        primary=evidence("codeql-cli", 0),
        additional_primaries=(
            evidence("semgrep-ce", 1),
            evidence("semgrep-ce", 2),
            evidence("semgrep-ce", 3),
        ),
        code_flow=(),
    )
    scope = DiscoveryScope(
        (DiscoveryTarget("target", "risk_finding", "app.py", 20, 20, ("high risk",)),),
        {},
        (),
        (),
        (),
    )
    prompt, included, gaps = _build_prompt(
        SimpleNamespace(findings=known),
        SimpleNamespace(findings=(finding,)),
        SimpleNamespace(findings=()),
        scope,
        4_500,
    )
    assert len(prompt) <= 4_500
    assert [item.target_id for item in included] == ["target"]
    assert any("known findings were omitted" in gap for gap in gaps)
    body = json.loads(prompt.split("\n\n", 1)[1])
    assert {item["scanner"] for item in body["targets"][0]["scanner_evidence"]} == {
        "codeql-cli",
        "semgrep-ce",
    }
