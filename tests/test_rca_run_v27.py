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
    # Legacy binaries must run on their built-in rules: a generated --config would replace them.
    assert not any(a.startswith("--config") for a in arguments)


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


# ---------------------------------------------------------------- release gate (explicit rules)
from security_reviewer_v2.policy import RULES, evaluate_policy
from security_reviewer_v2.policy.rules import RuleInput, decide

BLOCK = frozenset({"critical", "high"})


@pytest.mark.parametrize("verdict,severity,basis,scanner,rule,action", [
    ("confirmed_vulnerability", "high", "scanner_corroborated", "high", "RG-001", "block"),
    ("confirmed_vulnerability", "critical", "source_verified", "unknown", "RG-001", "block"),
    ("confirmed_vulnerability", "high", "ai_assertion_only", "unknown", "RG-002", "warn"),   # AI alone never blocks
    ("confirmed_vulnerability", "medium", "scanner_corroborated", "high", "RG-007", "block"),  # AI downgrade vs scanner high
    ("confirmed_vulnerability", "medium", "scanner_corroborated", "medium", "RG-006", "warn"),
    ("likely_vulnerability", "high", "scanner_corroborated", "high", "RG-003", "warn"),
    ("false_positive", "low", "ai_assertion_only", "unknown", "RG-004", "allow"),
    ("false_positive", "low", "scanner_corroborated", "high", "RG-005", "warn"),             # AI cannot wave away scanner high
    ("needs_more_evidence", "high", "ai_assertion_only", "unknown", "RG-006", "warn"),
])
def test_release_gate_rules_are_explicit_and_testable(verdict, severity, basis, scanner, rule, action) -> None:
    assert decide(RuleInput(verdict, severity, basis, scanner, BLOCK)) == (rule, action)
    assert RULES[rule].action == action


def _gate_inputs(ai_severity: str = "high", scanner_severity: str = "high", verified: bool = False):
    review = {"status": "completed", "reviews": [{"candidate_id": "grp", "severity": ai_severity,
                                                  "verdict": "confirmed_vulnerability"}]}
    triage = {"groups": [{"group_id": "grp", "scanner_finding_ids": ["merged-1"] if scanner_severity else [],
                          "candidate_ids": ["ai-1"] if verified else []}], "records": []}
    merged = {"findings": [{"merged_finding_id": "merged-1", "severity": scanner_severity, "scanners": ["semgrep-ce"],
                            "rule_ids": ["a.b.sql-injection"], "primary_location": {"path": "app.py", "start_line": 9}}]
              if scanner_severity else []}
    verification = {"records": [{"candidate_id": "ai-1", "disposition": "confirmed", "path": "app.py",
                                 "start_line": 9, "checks": ["file_exists"]}] if verified else []}
    return review, triage, merged, verification


def test_gate_records_rule_basis_evidence_and_blocking_reason() -> None:
    review, triage, merged, verification = _gate_inputs()
    result = evaluate_policy(review, triage_payload=triage, merged_payload=merged, verification_payload=verification)
    decision = result.decisions[0]
    assert (decision.action, decision.rule_id, decision.evidence_basis) == ("block", "RG-001", "scanner_corroborated")
    assert "RG-001" in decision.blocking_reason and "high scanner finding" in decision.blocking_reason
    assert decision.evidence and "semgrep-ce high at app.py:9" in decision.evidence[0]
    assert result.blocking and result.status == "failed" and result.rule_set.startswith("release-gate-rules/")


def test_gate_does_not_block_on_ai_assertion_alone() -> None:
    review, triage, merged, verification = _gate_inputs(scanner_severity="")
    result = evaluate_policy(review, triage_payload=triage, merged_payload=merged, verification_payload=verification)
    decision = result.decisions[0]
    assert (decision.action, decision.rule_id, decision.evidence_basis) == ("warn", "RG-002", "ai_assertion_only")
    assert not result.blocking and decision.blocking_reason == ""


def test_gate_accepts_source_verified_ai_finding() -> None:
    review, triage, merged, verification = _gate_inputs(ai_severity="critical", scanner_severity="", verified=True)
    decision = evaluate_policy(review, triage_payload=triage, merged_payload=merged,
                               verification_payload=verification).decisions[0]
    assert (decision.action, decision.evidence_basis) == ("block", "source_verified")


def test_legacy_call_without_evidence_keeps_previous_behaviour() -> None:
    review = {"status": "completed", "reviews": [{"candidate_id": "g", "severity": "high",
                                                  "verdict": "confirmed_vulnerability"}]}
    decision = evaluate_policy(review).decisions[0]
    assert decision.action == "block" and decision.evidence_basis == "not_assessed"


def test_report_has_professional_summary_section() -> None:
    review = {"status": "completed", "reviews": [
        _review("g1", "SQL Injection", "high", "confirmed_vulnerability"),
        _review("g2", "Debug Enabled", "medium", "likely_vulnerability"),
        _review("g3", "Cookie Flag", "low", "false_positive")]}
    policy = {"status": "failed", "blocking": True, "rule_set": "release-gate-rules/2", "decisions": [
        {"candidate_id": "g1", "action": "block", "severity": "high", "verdict": "confirmed_vulnerability",
         "reason": "r", "rule_id": "RG-001"},
        {"candidate_id": "g2", "action": "warn", "severity": "medium", "verdict": "likely_vulnerability", "reason": "r"},
        {"candidate_id": "g3", "action": "allow", "severity": "low", "verdict": "false_positive", "reason": "r"}]}
    execution = {"tasks": [{"scanner_id": "semgrep-ce", "status": "completed", "prerequisite_checks": []},
                           {"scanner_id": "gitleaks", "status": "failed", "prerequisite_checks": []}]}
    merged = {"findings": [], "summary": {"input_findings": 26, "merged_findings": 14, "duplicates_collapsed": 12}}
    text = render_final_report(project="p", review=review, policy=policy, execution=execution, merged=merged)
    summary = text.split("## Summary")[1].split("## Executive Summary")[0]
    assert text.index("## Summary") < text.index("## Executive Summary")
    assert "This release is **blocked**" in summary and "SQL Injection" in summary
    assert "| Release-blocking | **1** |" in summary and "| Need manual review (warn) | **1** |" in summary
    assert "**26** → **14**" in summary and "1 of 2" in summary
    assert "█" in summary and "Top priorities" in summary and "RG-001" in summary
    assert "partial" in summary and "not performed" in summary
