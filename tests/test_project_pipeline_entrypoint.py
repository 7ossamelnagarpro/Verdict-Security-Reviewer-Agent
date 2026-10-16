from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from scripts.run_project_pipeline import _command, _validate


def _args(tmp_path: Path, project: Path, *, provider: str = "ollama") -> argparse.Namespace:
    return argparse.Namespace(
        project=project,
        output=tmp_path / "reports",
        codeql_bundle=None,
        ai_provider=provider,
        ai_model=None,
        ai_max_targets=10,
        ai_max_batches=20,
        ai_max_planned_targets=128,
        ai_max_candidates=20,
        ai_max_enrichment_rounds=2,
        review_max_findings=3,
        require_all_scanners=False,
    )


def test_generic_entrypoint_accepts_arbitrary_project_and_stays_source_only(tmp_path: Path) -> None:
    project = tmp_path / "customer-app"
    project.mkdir()
    args = _args(tmp_path, project)

    validated_project, output = _validate(args)
    command = _command(args, project=validated_project, output=output)

    assert str(project) in command
    assert "--require-sast" in command
    assert "--require-dast" not in command
    assert "--runtime-url" not in command
    assert "--docker-runtime-run-id" not in command


def test_generic_entrypoint_rejects_output_inside_project(tmp_path: Path) -> None:
    project = tmp_path / "customer-app"
    project.mkdir()
    args = _args(tmp_path, project)
    args.output = project / "reports"

    with pytest.raises(ValueError, match="outside the scanned project"):
        _validate(args)


def test_generic_entrypoint_requires_groq_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = tmp_path / "customer-app"
    project.mkdir()
    args = _args(tmp_path, project, provider="groq")
    monkeypatch.delenv("GROQ_API_KEY", raising=False)

    with pytest.raises(ValueError, match="GROQ_API_KEY"):
        _validate(args)
