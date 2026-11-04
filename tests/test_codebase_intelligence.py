from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from security_reviewer_v2 import codebase_intelligence


def test_missing_binary_is_nonblocking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(codebase_intelligence.shutil, "which", lambda _: None)

    result = codebase_intelligence.index_codebase(tmp_path)

    assert result["status"] == "unavailable"
    assert result["reason"] == "executable_not_found"


def test_success_keeps_index_evidence_separate_from_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if command[1] == "--version":
            return subprocess.CompletedProcess(
                command, 0, "codebase-memory-mcp 1.2.3\n", ""
            )
        return subprocess.CompletedProcess(
            command,
            0,
            "Indexed repo: 12 nodes, 23 edges\n  db: C:/cache/graph.db\n",
            "",
        )

    monkeypatch.setattr(codebase_intelligence.subprocess, "run", fake_run)
    result = codebase_intelligence.index_codebase(tmp_path, executable="cbm")

    assert calls[1] == [
        "cbm",
        "cli",
        "index_repository",
        "--repo-path",
        str(tmp_path.resolve()),
        "--persistence",
        "false",
    ]
    assert result["status"] == "completed"
    assert result["node_count"] == 12
    assert result["edge_count"] == 23
    assert result["index_path"] == "C:/cache/graph.db"
    assert "findings" not in result


def test_json_index_summary_records_coverage_counts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        output = (
            "0.12.1"
            if command[1] == "--version"
            else (
                '{"status":"indexed","nodes":263,"edges":865,'
                '"not_indexed_files_count":0,"parse_partial_count":0}'
            )
        )
        return subprocess.CompletedProcess(command, 0, output, "")

    monkeypatch.setattr(codebase_intelligence.subprocess, "run", fake_run)
    result = codebase_intelligence.index_codebase(tmp_path, executable="cbm")

    assert result["status"] == "completed"
    assert result["node_count"] == 263
    assert result["edge_count"] == 865
    assert result["not_indexed_files_count"] == 0
    assert result["parse_partial_count"] == 0


def test_read_indexed_routes_parses_bounded_graph_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = (
        '{"groups":[{"file":"api/app.py","rows":'
        '[["__route__GET__/health","Route","",0,0],'
        '["__route__ANY__/form","Route","",0,0]]}],'
        '"total":2,"has_more":false}'
    )

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, output, "")

    monkeypatch.setattr(codebase_intelligence.subprocess, "run", fake_run)
    result = codebase_intelligence.read_indexed_routes(
        "local-project", executable="cbm"
    )

    assert result["status"] == "completed"
    assert result["routes"] == [
        {"method": "GET", "path": "/health", "file": "api/app.py"},
        {"method": "ANY", "path": "/form", "file": "api/app.py"},
    ]


def test_read_indexed_routes_collects_paginated_graph_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []
    pages = iter(
        [
            {
                "groups": [
                    {"file": "api/app.py", "rows": [["__route__GET__/one"]]}
                ],
                "total": 2,
                "has_more": True,
                "next_offset": 1,
            },
            {
                "groups": [
                    {"file": "api/app.py", "rows": [["__route__GET__/two"]]}
                ],
                "total": 2,
                "has_more": False,
            },
        ]
    )

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, json.dumps(next(pages)), "")

    monkeypatch.setattr(codebase_intelligence.subprocess, "run", fake_run)
    result = codebase_intelligence.read_indexed_routes("local-project", executable="cbm")

    assert result["status"] == "completed"
    assert result["total"] == 2
    assert [item["path"] for item in result["routes"]] == ["/one", "/two"]
    assert calls[1][calls[1].index("--offset") + 1] == "1"


@pytest.mark.parametrize(
    "outcome,reason",
    [
        (
            subprocess.CompletedProcess([], 2, "", "some sensitive error"),
            "index_nonzero_exit",
        ),
        (subprocess.TimeoutExpired([], 1), "index_timeout"),
        (OSError("failed"), "index_process_failed"),
    ],
)
def test_index_failure_is_recorded_without_log_leak(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    outcome: object,
    reason: str,
) -> None:
    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        if command[1] == "--version":
            return subprocess.CompletedProcess(command, 0, "1.2.3", "")
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome  # type: ignore[return-value]

    monkeypatch.setattr(codebase_intelligence.subprocess, "run", fake_run)
    result = codebase_intelligence.index_codebase(tmp_path, executable="cbm")

    assert result["status"] == "failed"
    assert result["reason"] == reason
    assert "sensitive" not in str(result)
