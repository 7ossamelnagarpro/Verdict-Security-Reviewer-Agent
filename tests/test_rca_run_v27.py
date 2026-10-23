"""Regression tests for the run_v27 root causes (WSL paths, legacy Gitleaks, versions, Trivy cache, report)."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from security_reviewer_v2.reporting.final import render_final_report
from security_reviewer_v2.scanners import gitleaks as gitleaks_module
from security_reviewer_v2.scanners import trivy as trivy_module
from security_reviewer_v2.scanners.gitleaks import GitleaksAdapter, GitleaksConfig
from security_reviewer_v2.scanners.hostpaths import (
    needs_windows_paths,
    parse_version,
    to_windows_path,
    translate_arguments,
)
from security_reviewer_v2.scanners.trivy import TrivyConfig

from tests.test_additional_scanners import request, task
from security_reviewer_v2.profiler.models import ScanType


@pytest.mark.parametrize("text,expected", [
    ("8.30.1", "8.30.1"), ("v8.18.4", "8.18.4"), ("gitleaks version 8.30.1\n", "8.30.1"),
    ("Version: 0.71.2", "0.71.2"), ("1.178.0\n", "1.178.0"), ("no version here", None), ("", None),
])
def test_parse_version_accepts_v_prefix(text: str, expected: str | None) -> None:
    # "\b" never matched "v8.18.4": that is why Gitleaks reported "version could not be read".
    assert parse_version(text) == expected


def test_windows_executable_gets_windows_paths_for_wsl_mounts() -> None:
    exe = "/mnt/c/tools/codeql/codeql.exe"
    assert needs_windows_paths(exe)
    assert not needs_windows_paths("/usr/bin/trivy")
    assert to_windows_path("/mnt/c/Users/A B/run/db") == "C:\\Users\\A B\\run\\db"
    args = translate_arguments(exe, ("database", "create", "/mnt/c/Users/A/run/db",
                                     "--source-root=/mnt/d/proj", "--threads=2", "--language=python"))
    assert args == ("database", "create", "C:\\Users\\A\\run\\db",
                    "--source-root=D:\\proj", "--threads=2", "--language=python")


def test_linux_executable_arguments_are_untouched() -> None:
    args = ("scan", "--output=/mnt/c/x/result.json", "/mnt/c/x")
    assert translate_arguments("/usr/bin/semgrep", args) == args


def _mk(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def _fake_gitleaks(tmp_path: Path, *, modern: bool) -> Path:
    script = tmp_path / ("gl-new" if modern else "gl-old")
    body = "exit 0" if modern else 'echo "Error: unknown command \\"dir\\" for \\"gitleaks\\"" >&2; exit 1'
    script.write_text(f"#!/bin/sh\n{body}\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script


@pytest.mark.skipif(os.name == "nt", reason="uses a POSIX shell stub")
def test_gitleaks_falls_back_to_detect_when_dir_command_is_missing(tmp_path: Path) -> None:
    gitleaks_module._supports_dir_command.cache_clear()
    old = _fake_gitleaks(tmp_path, modern=False)
    adapter = GitleaksAdapter(GitleaksConfig(executable=str(old)))
    plan = adapter.build_execution_plan(request(_mk(tmp_path / "a"), task("gitleaks", ScanType.SECRETS, mode="directory")))
    arguments = plan.commands[0].arguments
    assert arguments[0] == "detect" and "--no-git" in arguments
    assert "--source=." in arguments and "--redact" in arguments and "--exit-code=0" in arguments
    generated = next(Path(a.split("=", 1)[1]) for a in arguments if a.startswith("--config="))
    assert "[allowlist]" in generated.read_text() and "[[allowlists]]" not in generated.read_text()


@pytest.mark.skipif(os.name == "nt", reason="uses a POSIX shell stub")
def test_gitleaks_keeps_dir_command_when_supported(tmp_path: Path) -> None:
    gitleaks_module._supports_dir_command.cache_clear()
    new = _fake_gitleaks(tmp_path, modern=True)
    adapter = GitleaksAdapter(GitleaksConfig(executable=str(new)))
    plan = adapter.build_execution_plan(request(_mk(tmp_path / "b"), task("gitleaks", ScanType.SECRETS, mode="directory")))
    assert plan.commands[0].arguments[0] == "dir"


def test_trivy_finds_linux_cache_dir_with_database(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Root cause: only Windows locations were probed, so ~/.cache/trivy/db was never found.
    cache = tmp_path / "home" / ".cache" / "trivy" / "db"
    cache.mkdir(parents=True)
    (cache / "trivy.db").write_bytes(b"x")
    (cache / "metadata.json").write_text("{}")
    for name in ("TRIVY_CACHE_DIR", "LOCALAPPDATA", "USERPROFILE", "XDG_CACHE_HOME"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    found = trivy_module._trivy_cache_dir(TrivyConfig(executable=str(tmp_path / "trivy")))
    assert found == (tmp_path / "home" / ".cache" / "trivy").resolve()
    assert trivy_module._has_vulnerability_db(found)


def _review(cid: str, title: str, severity: str, verdict: str) -> dict:
    return {"candidate_id": cid, "title": title, "severity": severity, "verdict": verdict,
            "confidence": "high", "explanation": "e", "impact": "i", "remediation": "r",
            "evidence": ["x = `a`"], "source_ids": []}


def test_report_states_decision_coverage_and_does_not_change_verdicts() -> None:
    review = {"status": "completed", "reviews": [
        _review("g1", "Sql Injection Db Cursor Execute", "high", "confirmed_vulnerability"),
        _review("g2", "Debug Enabled", "medium", "likely_vulnerability")]}
    policy = {"status": "failed", "blocking": True, "decisions": [
        {"candidate_id": "g1", "action": "block", "severity": "high", "verdict": "confirmed_vulnerability", "reason": "r1"},
        {"candidate_id": "g2", "action": "warn", "severity": "medium", "verdict": "likely_vulnerability", "reason": "r2"}]}
    execution = {"tasks": [
        {"scanner_id": "semgrep-ce", "status": "completed", "reason": "ok", "prerequisite_checks": []},
        {"scanner_id": "gitleaks", "status": "failed", "reason": "Command gitleaks-dir ended with failed",
         "prerequisite_checks": [{"name": "gitleaks_executable", "status": "available",
                                  "detail": "x (version check skipped)"}]},
        {"scanner_id": "trivy", "status": "skipped", "reason": "n/a", "prerequisite_checks": []}]}
    markdown = render_final_report(project="p", review=review, policy=policy, execution=execution,
                                   coverage_gaps=["gap one", "gap one", "gap two"])
    assert "**BLOCKED**" in markdown
    assert "1 of 2 scanner task(s) completed" in markdown          # skipped task not counted
    assert "SQL Injection DB Cursor Execute" in markdown            # acronym casing restored
    assert "## Findings at a Glance" in markdown and "## Recommended Next Steps" in markdown
    assert "Scanner version not verified" in markdown               # version tolerance is disclosed
    assert "**not performed**" in markdown                          # no DAST evidence
    assert markdown.count("gap one") == 1                           # gaps de-duplicated
    # data integrity: verdict/severity/action values pass through unchanged and in the right rows
    assert "| 1 | SQL Injection DB Cursor Execute | high | confirmed vulnerability | high | **block** |" in markdown
    assert "| 2 | Debug Enabled | medium | likely vulnerability | high | **warn** |" in markdown


def test_tool_lookup_accepts_native_and_exe_spellings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from security_reviewer_v2.scanners.hostpaths import find_codeql, resolve_tool
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    native = tmp_path / "linux-bundle"
    native.mkdir()
    (native / "codeql").write_text("")
    windows = tmp_path / "win-bundle"
    windows.mkdir()
    (windows / "codeql.exe").write_text("")
    assert find_codeql(native).name == "codeql"            # Linux / macOS bundle
    assert find_codeql(windows).name == "codeql.exe"       # Windows / WSL bundle
    assert find_codeql(tmp_path / "missing") is None
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "trivy.exe").write_text("")
    assert resolve_tool("trivy", tools).name == "trivy.exe"
    assert resolve_tool("gitleaks", tools) is None
