import pytest

from security_reviewer_v2.discovery.combine import combine_discovery_runs, remaining_target_ids


def test_combining_completed_continuation_clears_only_resolved_run_gaps():
    base = {
        "schema_version": "1.2", "provider": "groq", "model": "test-model",
        "batches": [
            {"batch_index": 1, "status": "completed", "target_ids": ["a"], "candidate_ids": ["one"]},
            {"batch_index": 2, "status": "failed", "target_ids": ["b"], "candidate_ids": []},
        ],
        "candidates": [{"candidate_id": "one", "verification": "supported"}],
        "target_plan": [{"target_id": "a"}, {"target_id": "b"}],
        "context_exchanges": [{"batch_index": 2, "status": "collected"}],
        "warnings": ["Discovery batch 2: HTTP 429"],
        "coverage_gaps": ["1 planned discovery targets were not inspected; c", "Discovery batch 2 did not complete; targets: b.", "Missing lockfile"],
        "usage": {"planned_targets": 3, "targets": 2, "batches": 2, "provider_calls": 3, "prompt_tokens": 20},
    }
    continuation = {
        "schema_version": "1.2", "provider": "groq", "model": "test-model",
        "batches": [
            {"batch_index": 1, "status": "completed", "target_ids": ["b"], "candidate_ids": ["two"]},
            {"batch_index": 2, "status": "completed", "target_ids": ["c"], "candidate_ids": []},
        ],
        "candidates": [{"candidate_id": "two", "verification": "inconclusive"}],
        "target_plan": [{"target_id": "b"}, {"target_id": "c"}],
        "context_exchanges": [{"batch_index": 1, "status": "collected"}],
        "warnings": [], "coverage_gaps": ["Discovery run was restricted to explicitly selected target IDs.", "Missing lockfile"],
        "usage": {"planned_targets": 2, "targets": 2, "batches": 2, "provider_calls": 2, "prompt_tokens": 30},
    }
    combined = combine_discovery_runs(base, continuation)
    assert combined["scope"] == ["a", "b", "c"]
    assert combined["status"] == "partial"  # A dependency gap remains, not a Discovery coverage gap.
    assert combined["coverage_gaps"] == ["Missing lockfile"]
    assert combined["warnings"] == []
    assert [batch["batch_index"] for batch in combined["batches"]] == [1, 2, 3]
    assert combined["context_exchanges"] == [{"batch_index": 2, "status": "collected"}]
    assert len(combined["candidates"]) == 2
    assert combined["usage"]["prompt_tokens"] == 50
    assert combined["usage"]["provider_calls"] == 5
    assert combined["usage"]["attempted_batches"] == 4


def test_combining_rejects_duplicate_completed_target():
    base = {"schema_version": "1.2", "provider": "groq", "model": "test", "batches": [
        {"batch_index": 1, "status": "completed", "target_ids": ["a"]}], "usage": {"planned_targets": 2}}
    continuation = {"schema_version": "1.2", "provider": "groq", "model": "test", "batches": [
        {"batch_index": 1, "status": "completed", "target_ids": ["a", "b"]}]}
    with pytest.raises(ValueError, match="more than one run"):
        combine_discovery_runs(base, continuation)


def _run(batches, planned=4, plan=("a", "b", "c", "d"), **extra):
    return {"schema_version": "1.2", "provider": "groq", "model": "m", "batches": batches, "candidates": [],
            "target_plan": [{"target_id": i} for i in plan], "context_exchanges": [], "warnings": [], "coverage_gaps": [],
            "usage": {"planned_targets": planned, "targets": 0, "provider_calls": 1, "prompt_tokens": 10}, **extra}


def _done(index, *ids):
    return {"batch_index": index, "status": "completed", "target_ids": list(ids), "candidate_ids": []}


def test_partial_combine_keeps_completed_batches_and_lists_what_is_left():
    base = _run([_done(1, "a"), {"batch_index": 2, "status": "failed", "target_ids": ["b", "c", "d"], "candidate_ids": []}],
                warnings=["Discovery batch 2: HTTP 429; provider asked to wait 1730 s"],
                coverage_gaps=["Discovery batch 2 did not complete; targets: b, c, d."])
    cont = _run([_done(1, "b"), {"batch_index": 2, "status": "failed", "target_ids": ["c", "d"], "candidate_ids": []}],
                warnings=["Discovery batch 2: HTTP 429"], coverage_gaps=["Discovery batch 2 did not complete; targets: c, d."])
    with pytest.raises(ValueError, match="incomplete"):
        combine_discovery_runs(base, cont)
    mid = combine_discovery_runs(base, cont, allow_partial=True)
    assert mid["scope"] == ["a", "b"] and mid["status"] == "partial"
    assert mid["unfinished_target_ids"] == ["c", "d"] and remaining_target_ids(mid) == ["c", "d"]
    assert any(g.startswith("2 planned discovery targets were not inspected;") for g in mid["coverage_gaps"])
    assert not any("did not complete" in g for g in mid["coverage_gaps"])
    assert all(w.startswith("Discovery resumption: ") for w in mid["warnings"])
    assert mid["usage"]["targets"] == 2 and mid["usage"]["planned_targets"] == 4


def test_partial_results_chain_until_everything_is_covered_and_stale_warnings_disappear():
    mid = combine_discovery_runs(
        _run([_done(1, "a"), {"batch_index": 2, "status": "failed", "target_ids": ["b", "c", "d"], "candidate_ids": []}],
             warnings=["Discovery batch 2: HTTP 429"]),
        _run([_done(1, "b")]), allow_partial=True)
    final = combine_discovery_runs(mid, _run([_done(1, "c", "d")]), allow_partial=True)
    assert final["scope"] == ["a", "b", "c", "d"] and "unfinished_target_ids" not in final
    assert final["warnings"] == [] and final["coverage_gaps"] == [] and final["status"] == "completed"
    assert final["usage"]["targets"] == final["usage"]["planned_targets"] == 4
    from security_reviewer_v2.discovery.completion import required_discovery_satisfied
    assert required_discovery_satisfied(final)


def test_partial_combine_still_rejects_a_continuation_that_completed_nothing():
    base = _run([_done(1, "a")])
    with pytest.raises(ValueError, match="completed no batches"):
        combine_discovery_runs(base, _run([{"batch_index": 1, "status": "failed", "target_ids": ["b"], "candidate_ids": []}]),
                               allow_partial=True)
