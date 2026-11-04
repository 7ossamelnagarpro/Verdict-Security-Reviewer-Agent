import pytest

from security_reviewer_v2.discovery.combine import combine_discovery_runs


def test_combining_completed_continuation_clears_only_resolved_run_gaps():
    base = {
        "schema_version": "1.2",
        "provider": "groq",
        "model": "test-model",
        "batches": [
            {
                "batch_index": 1,
                "status": "completed",
                "target_ids": ["a"],
                "candidate_ids": ["one"],
            },
            {
                "batch_index": 2,
                "status": "failed",
                "target_ids": ["b"],
                "candidate_ids": [],
            },
        ],
        "candidates": [{"candidate_id": "one", "verification": "supported"}],
        "target_plan": [{"target_id": "a"}, {"target_id": "b"}],
        "context_exchanges": [{"batch_index": 2, "status": "collected"}],
        "warnings": ["Discovery batch 2: HTTP 429"],
        "coverage_gaps": [
            "1 planned discovery targets were not inspected; c",
            "Discovery batch 2 did not complete; targets: b.",
            "Missing lockfile",
        ],
        "usage": {
            "planned_targets": 3,
            "targets": 2,
            "batches": 2,
            "provider_calls": 3,
            "prompt_tokens": 20,
        },
    }
    continuation = {
        "schema_version": "1.2",
        "provider": "groq",
        "model": "test-model",
        "batches": [
            {
                "batch_index": 1,
                "status": "completed",
                "target_ids": ["b"],
                "candidate_ids": ["two"],
            },
            {
                "batch_index": 2,
                "status": "completed",
                "target_ids": ["c"],
                "candidate_ids": [],
            },
        ],
        "candidates": [{"candidate_id": "two", "verification": "inconclusive"}],
        "target_plan": [{"target_id": "b"}, {"target_id": "c"}],
        "context_exchanges": [{"batch_index": 1, "status": "collected"}],
        "warnings": [],
        "coverage_gaps": [
            "Discovery run was restricted to explicitly selected target IDs.",
            "Missing lockfile",
        ],
        "usage": {
            "planned_targets": 2,
            "targets": 2,
            "batches": 2,
            "provider_calls": 2,
            "prompt_tokens": 30,
        },
    }
    combined = combine_discovery_runs(base, continuation)
    assert combined["scope"] == ["a", "b", "c"]
    assert (
        combined["status"] == "partial"
    )  # A dependency gap remains, not a Discovery coverage gap.
    assert combined["coverage_gaps"] == ["Missing lockfile"]
    assert combined["warnings"] == []
    assert [batch["batch_index"] for batch in combined["batches"]] == [1, 2, 3]
    assert combined["context_exchanges"] == [{"batch_index": 2, "status": "collected"}]
    assert len(combined["candidates"]) == 2
    assert combined["usage"]["prompt_tokens"] == 50
    assert combined["usage"]["provider_calls"] == 5
    assert combined["usage"]["attempted_batches"] == 4


def test_combining_rejects_duplicate_completed_target():
    base = {
        "schema_version": "1.2",
        "provider": "groq",
        "model": "test",
        "batches": [{"batch_index": 1, "status": "completed", "target_ids": ["a"]}],
        "usage": {"planned_targets": 2},
    }
    continuation = {
        "schema_version": "1.2",
        "provider": "groq",
        "model": "test",
        "batches": [
            {"batch_index": 1, "status": "completed", "target_ids": ["a", "b"]}
        ],
    }
    with pytest.raises(ValueError, match="more than one run"):
        combine_discovery_runs(base, continuation)


def test_combined_new_artifacts_keep_inherited_limitations_without_false_partial():
    base = {
        "schema_version": "1.2",
        "provider": "groq",
        "model": "test",
        "batches": [{"batch_index": 1, "status": "completed", "target_ids": ["a"]}],
        "usage": {"planned_targets": 2},
        "coverage_gaps": ["Browser GET-only"],
        "coverage_accounting": {
            "discovery_gaps": [],
            "inherited_limitations": ["Browser GET-only"],
            "context_notes": [],
        },
    }
    continuation = {
        "schema_version": "1.2",
        "provider": "groq",
        "model": "test",
        "batches": [{"batch_index": 1, "status": "completed", "target_ids": ["b"]}],
        "coverage_gaps": ["Browser GET-only"],
        "coverage_accounting": {
            "discovery_gaps": [],
            "inherited_limitations": ["Browser GET-only"],
            "context_notes": [],
        },
    }
    result = combine_discovery_runs(base, continuation)
    assert result["status"] == "completed"
    assert result["coverage_gaps"] == ["Browser GET-only"]
    assert result["coverage_accounting"]["discovery_gaps"] == []
