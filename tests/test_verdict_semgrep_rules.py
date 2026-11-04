"""Local, target-independent Semgrep rules and paired safe controls."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

from security_reviewer_v2.orchestrator.runner import ProcessRunner
from security_reviewer_v2.scanners.models import CommandSpec, ExecutionStatus
from security_reviewer_v2.scanners.semgrep import SemgrepConfig


def test_default_semgrep_rules_are_packaged_and_trusted() -> None:
    rules = Path(SemgrepConfig(executable=str(Path(__file__).resolve())).configs[-1])
    assert rules.is_absolute() and rules.is_file()
    assert "verdict.python" in rules.read_text(encoding="utf-8")


def test_local_rules_detect_unsafe_patterns_without_flagging_safe_controls(
    tmp_path: Path,
) -> None:
    local_semgrep = Path(sys.executable).with_name(
        "semgrep.exe" if sys.platform == "win32" else "semgrep"
    )
    semgrep = str(local_semgrep) if local_semgrep.is_file() else shutil.which("semgrep")
    if semgrep is None:
        pytest.skip("Semgrep is not installed in this test environment")
    unsafe = tmp_path / "unsafe.py"
    safe = tmp_path / "safe.py"
    unsafe.write_text(
        """import base64\nimport json\n\ndef issue():\n    return {"alg": "none", "typ": "JWT"}\n\ndef principal(raw):\n    return json.loads(base64.urlsafe_b64decode(raw))\n\ndef start(response, token):\n    response.set_cookie("session", token)\n""",
        encoding="utf-8",
    )
    safe.write_text(
        """import jwt\n\ndef principal(token, secret):\n    return jwt.decode(token, secret, algorithms=["HS256"])\n\ndef start(response, token):\n    response.set_cookie("session", token, httponly=True, samesite="strict")\n""",
        encoding="utf-8",
    )
    unsafe_compose = tmp_path / "unsafe" / "compose.yaml"
    safe_compose = tmp_path / "safe" / "compose.yaml"
    unsafe_compose.parent.mkdir()
    safe_compose.parent.mkdir()
    unsafe_compose.write_text(
        "services:\n  web:\n    environment:\n      APP_SECRET: lab-only-fixed-secret\n",
        encoding="utf-8",
    )
    safe_compose.write_text(
        'services:\n  web:\n    environment:\n      APP_SECRET: "${APP_SECRET}"\n',
        encoding="utf-8",
    )
    config = SemgrepConfig(executable=str(Path(__file__).resolve()))
    rules = config.configs[-1]
    result = ProcessRunner().run(
        CommandSpec(
            name="local-semgrep-rules",
            executable=str(Path(semgrep).resolve()),
            working_directory=str(tmp_path),
            timeout_seconds=180,
            arguments=(
                "scan",
                "--json",
                "--metrics=off",
                "--disable-version-check",
                "--no-git-ignore",
                f"--jobs={config.jobs}",
                f"--timeout={config.rule_timeout_seconds}",
                "--config",
                rules,
                str(tmp_path),
            ),
        ),
        log_directory=tmp_path / "logs",
        relative_to=tmp_path,
    )
    stderr = (tmp_path / result.stderr_log).read_text(encoding="utf-8")
    assert result.status == ExecutionStatus.COMPLETED, stderr
    findings = json.loads((tmp_path / result.stdout_log).read_text(encoding="utf-8"))[
        "results"
    ]
    unsafe_rules = {
        item["check_id"].rsplit(".", 1)[-1]
        for item in findings
        if Path(item["path"]).name == "unsafe.py"
    }
    assert unsafe_rules == {
        "unsigned-jwt-algorithm",
        "decoded-token-as-identity",
        "cookie-without-httponly",
    }
    assert not any(Path(item["path"]).name == "safe.py" for item in findings)
    assert any(
        item["check_id"].endswith("verdict.yaml.hardcoded-application-secret")
        and Path(item["path"]).parent.name == "unsafe"
        for item in findings
    )
    assert not any(Path(item["path"]).parent.name == "safe" for item in findings)
