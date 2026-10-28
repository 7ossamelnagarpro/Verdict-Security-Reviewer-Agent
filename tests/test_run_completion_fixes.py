"""Regression tests for the fixes that make a pipeline run finish: Trivy DB, .env loading, LangSmith status."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

from security_reviewer_v2.agents import tracing
from security_reviewer_v2.discovery.agent import DiscoveryAgent
from security_reviewer_v2.discovery.models import DiscoveryConfig
from security_reviewer_v2.discovery.provider import ProviderResponseError
from security_reviewer_v2.envfile import load_env_file
from security_reviewer_v2.profiler.models import ScanType
from security_reviewer_v2.scanners.trivy import TrivyAdapter, TrivyConfig

from tests.test_additional_scanners import task
from tests.test_ai_discovery import _inputs

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="uses a shell-script fake of the trivy binary")

FAKE_TRIVY = """#!/bin/sh
case "$1" in
  --version) echo "Version: 0.71.2"; exit 0 ;;
esac
{body}
"""


def fake_trivy(tmp_path: Path, body: str) -> str:
    script = tmp_path / "trivy"
    script.write_text(FAKE_TRIVY.format(body=body), encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script.resolve())


def sca_database_check(adapter: TrivyAdapter, tmp_path: Path):
    checks = adapter.check_prerequisites(task("trivy", ScanType.SCA, mode="filesystem"), project_root=str(tmp_path))
    return next(item for item in checks if item.name == "trivy_databases")


# ------------------------------------------------------------------ Trivy vulnerability DB
@posix_only
def test_missing_trivy_db_is_downloaded_once_when_enabled(tmp_path):
    cache = tmp_path / "cache"
    executable = fake_trivy(tmp_path, 'for a in "$@"; do case "$a" in --cache-dir=*) d="${a#--cache-dir=}";; esac; done\n'
                                      'case " $* " in *" --download-db-only "*) mkdir -p "$d/db"; echo x > "$d/db/trivy.db"; echo "{}" > "$d/db/metadata.json"; exit 0;; esac; exit 1')
    adapter = TrivyAdapter(TrivyConfig(executable=executable, database_path=str(cache), auto_download_db=True))
    assert sca_database_check(adapter, tmp_path).status.value == "available"


@posix_only
def test_trivy_db_is_not_downloaded_unless_enabled(tmp_path):
    marker = tmp_path / "called"
    executable = fake_trivy(tmp_path, f'touch "{marker}"; exit 0')
    adapter = TrivyAdapter(TrivyConfig(executable=executable, database_path=str(tmp_path / "cache")))
    assert sca_database_check(adapter, tmp_path).status.value == "unverified"
    assert not marker.exists()                         # default stays offline: nothing is fetched by surprise


@posix_only
def test_failed_trivy_db_download_stays_unverified_and_says_why(tmp_path):
    executable = fake_trivy(tmp_path, 'echo "failed to download ghcr.io: connection refused" >&2; exit 1')
    adapter = TrivyAdapter(TrivyConfig(executable=executable, database_path=str(tmp_path / "cache"), auto_download_db=True))
    check = sca_database_check(adapter, tmp_path)
    assert check.status.value == "unverified"          # never silently "clean"
    assert "Automatic download" in check.detail and "connection refused" in check.detail


# ------------------------------------------------------------------ .env loading (WSL does not see PowerShell variables)
def test_env_file_loads_only_allowlisted_names_and_never_overrides(tmp_path, monkeypatch):
    # Work on a private copy of the environment so nothing can leak into other tests.
    names = {"LANGSMITH_API_KEY", "LANGSMITH_TRACING", "GROQ_API_KEY", "PATH_INJECTED", "LD_PRELOAD"}
    monkeypatch.setattr(os, "environ", {k: v for k, v in os.environ.items() if k not in names} | {"GROQ_API_KEY": "already-set"})
    env = tmp_path / ".env"
    env.write_text('# comment\nexport LANGSMITH_TRACING="true"\nLANGSMITH_API_KEY=lsv2_abc # trailing\n'
                   'GROQ_API_KEY=from-file\nLD_PRELOAD=/evil.so\nPATH_INJECTED=1\n', encoding="utf-8")
    loaded = load_env_file(tmp_path / "missing.env", env)
    assert sorted(loaded) == ["LANGSMITH_API_KEY", "LANGSMITH_TRACING"]
    assert os.environ["LANGSMITH_API_KEY"] == "lsv2_abc" and os.environ["LANGSMITH_TRACING"] == "true"
    assert os.environ["GROQ_API_KEY"] == "already-set" and "LD_PRELOAD" not in os.environ


def test_tracing_status_is_never_silent(monkeypatch):
    for name in ("LANGSMITH_TRACING", "LANGSMITH_TRACING_V2", "LANGCHAIN_TRACING_V2", "LANGCHAIN_TRACING",
                 "LANGSMITH_API_KEY", "LANGCHAIN_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    off = tracing.tracing_status()
    assert "OFF" in off and "LANGSMITH_API_KEY" in off and "WSL" in off
    monkeypatch.setenv("LANGSMITH_TRACING", "true")
    monkeypatch.setenv("LANGSMITH_API_KEY", "k")
    assert tracing.tracing_status().startswith("LangSmith tracing: ON")


# ------------------------------------------------------------------ Groq json_validate_failed must not end discovery
def test_json_validate_failed_on_every_batch_is_reported_per_target_not_as_a_blocked_stage(tmp_path):
    class Flaky:
        name, model = "fake", "test"

        def __init__(self):
            self.prompts = []

        def discover(self, prompt, *, timeout_seconds, max_candidates):
            self.prompts.append(prompt)
            if len(self.prompts) == 1:       # the first (multi-target) request breaks the model's JSON
                raise ProviderResponseError("AI provider request failed with HTTP 400 (json_validate_failed); model output 9 chars, not valid JSON")
            return {"candidates": [], "context_requests": []}, {"prompt_tokens": 1}

    merged, context, risk, profile = _inputs(tmp_path)
    provider = Flaky()
    result = DiscoveryAgent(provider, DiscoveryConfig(max_targets=10)).run(
        merged, context, risk, project_root=tmp_path, profile_artifact=profile)
    assert result.status.value != "blocked"              # the stage survived the bad answer
    assert len(provider.prompts) >= 2                    # ... by retrying a smaller request
    assert result.usage["targets"] == result.usage["planned_targets"] > 0   # and every target was still inspected
