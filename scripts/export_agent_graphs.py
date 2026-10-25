"""Write Mermaid diagrams of both LangGraph agents to ``docs/agents/`` (no model or network calls)."""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path
from types import SimpleNamespace

from security_reviewer_v2.discovery.graph import DiscoveryInputs, DiscoveryWorkflow
from security_reviewer_v2.discovery.models import DiscoveryConfig
from security_reviewer_v2.reviewers.graph import ReviewInputs, ReviewWorkflow


class _NullProvider:
    name, model = "none", "none"


def build_diagrams() -> dict[str, str]:
    with tempfile.TemporaryDirectory() as root:
        discovery = DiscoveryWorkflow.build_graph(_NullProvider(), DiscoveryConfig(), DiscoveryInputs(
            merged=SimpleNamespace(), context=SimpleNamespace(), risk=SimpleNamespace(), project_root=root))
        review = ReviewWorkflow(ReviewInputs(
            discovery=SimpleNamespace(candidates=()), verification=SimpleNamespace(records=()),
            provider=_NullProvider(), project_root=root)).compile()
        return {"discovery-agent": discovery.get_graph().draw_mermaid(),
                "security-review-agent": review.get_graph().draw_mermaid()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("docs/agents"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    for name, diagram in build_diagrams().items():
        (args.output / f"{name}.mmd").write_text(diagram, encoding="utf-8")
        print(args.output / f"{name}.mmd")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
