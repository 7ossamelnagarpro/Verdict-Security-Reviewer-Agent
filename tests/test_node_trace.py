"""Tests for agents.tracing.node_trace: used by agent_graph.py's dynamic_penetration_agent node
so it shows up as its own named run in LangSmith even though it makes no model calls itself."""

from __future__ import annotations

import pytest
from langsmith.run_helpers import tracing_context

from security_reviewer_v2.agents.tracing import node_trace


def test_node_trace_is_a_no_op_when_tracing_is_disabled():
    with node_trace("some_node", inputs={"a": 1}) as run:
        assert run is None


def test_node_trace_yields_a_run_when_tracing_is_enabled():
    with tracing_context(enabled=True, client=None):
        with node_trace("dynamic_penetration_agent", inputs={"candidates_confirmed_by_verification": 3}) as run:
            assert run is not None
            assert run.name == "dynamic_penetration_agent"
            assert run.inputs == {"candidates_confirmed_by_verification": 3}
            run.end(outputs={"status": "completed"})


def test_node_trace_never_swallows_an_exception_from_the_wrapped_block():
    with tracing_context(enabled=True, client=None):
        with pytest.raises(ValueError, match="boom"):
            with node_trace("dynamic_penetration_agent"):
                raise ValueError("boom")


def test_node_trace_falls_back_to_none_if_the_tracing_setup_itself_fails(monkeypatch):
    import security_reviewer_v2.agents.tracing as tracing_module

    def broken_trace(*args, **kwargs):
        raise RuntimeError("langsmith is unreachable")

    monkeypatch.setattr(tracing_module, "trace", broken_trace)
    with tracing_context(enabled=True, client=None):
        with node_trace("dynamic_penetration_agent") as run:
            assert run is None  # never raises, never blocks the pipeline
