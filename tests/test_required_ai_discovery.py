"""A full scan cannot claim completion without real AI inspection."""

from security_reviewer_v2.discovery.completion import required_discovery_satisfied


def _result(*, status: str = "completed", planned: int = 2, inspected: int = 2,
            calls: int = 1, batch_status: str = "completed") -> dict:
    return {"status": status,
            "usage": {"planned_targets": planned, "targets": inspected, "provider_calls": calls},
            "batches": [{"status": batch_status}]}


def test_all_targets_and_successful_model_call_satisfy_required_stage() -> None:
    assert required_discovery_satisfied(_result())
    assert required_discovery_satisfied(_result(status="partial"))


def test_empty_failed_or_skipped_discovery_cannot_satisfy_required_stage() -> None:
    assert not required_discovery_satisfied(_result(planned=0, inspected=0))
    assert not required_discovery_satisfied(_result(inspected=1))
    assert not required_discovery_satisfied(_result(calls=0))
    assert not required_discovery_satisfied(_result(batch_status="failed"))
    assert not required_discovery_satisfied(_result(status="blocked"))
    assert not required_discovery_satisfied({"status": "disabled"})
