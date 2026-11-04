"""Bounded subprocess execution for trusted scanner command specifications."""

from __future__ import annotations

import os
import re
import subprocess
import threading
import time
from pathlib import Path

from security_reviewer_v2.scanners.models import (
    CommandResult,
    CommandSpec,
    ExecutionStatus,
)

SAFE_ENVIRONMENT_KEYS = {
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATH",
    "PATHEXT",
    "TEMP",
    "TMP",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "USERPROFILE",
    "PROCESSOR_ARCHITECTURE",
    "NUMBER_OF_PROCESSORS",
    "HOME",
    "LANG",
    "LC_ALL",
}

REDACTION_PATTERNS = (
    re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*([^\s,;]+)"),
    re.compile(r"\b(?:gsk|ghp|github_pat)_[A-Za-z0-9_\-]{12,}\b"),
)


class ProcessRunner:
    def __init__(self, *, max_log_bytes: int = 1024 * 1024) -> None:
        if max_log_bytes <= 0:
            raise ValueError("max_log_bytes must be greater than zero")
        self.max_log_bytes = max_log_bytes

    def run(
        self,
        spec: CommandSpec,
        *,
        log_directory: Path,
        relative_to: Path,
    ) -> CommandResult:
        spec.validate()
        executable = Path(spec.executable)
        working_directory = Path(spec.working_directory)
        if not executable.is_file():
            raise FileNotFoundError(f"Scanner executable is unavailable: {executable}")
        if not working_directory.is_dir():
            raise FileNotFoundError(
                f"Command working directory is unavailable: {working_directory}"
            )
        log_directory.mkdir(parents=True, exist_ok=True)
        stdout_path = log_directory / f"{_safe_name(spec.name)}.stdout.log"
        stderr_path = log_directory / f"{_safe_name(spec.name)}.stderr.log"
        environment = {
            key: value
            for key, value in os.environ.items()
            if key.upper() in SAFE_ENVIRONMENT_KEYS
        }
        environment.update(spec.environment)

        started = time.monotonic()
        process = subprocess.Popen(
            [str(executable), *spec.arguments],
            cwd=str(working_directory),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        )
        stdout_state = {"written": 0, "truncated": False}
        stderr_state = {"written": 0, "truncated": False}
        stdout_thread = threading.Thread(
            target=_drain_stream,
            args=(process.stdout, stdout_path, self.max_log_bytes, stdout_state),
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=_drain_stream,
            args=(process.stderr, stderr_path, self.max_log_bytes, stderr_state),
            daemon=True,
        )
        stdout_thread.start()
        stderr_thread.start()
        timed_out = False
        try:
            exit_code = process.wait(timeout=spec.timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            _terminate_process_tree(process)
            try:
                exit_code = process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                exit_code = process.wait(timeout=5)
        except BaseException:
            _terminate_process_tree(process)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            stdout_thread.join(timeout=5)
            stderr_thread.join(timeout=5)
            raise
        stdout_thread.join(timeout=10)
        stderr_thread.join(timeout=10)
        duration = round(time.monotonic() - started, 6)
        if timed_out:
            status = ExecutionStatus.TIMED_OUT
        elif exit_code == 0:
            status = ExecutionStatus.COMPLETED
        else:
            status = ExecutionStatus.FAILED
        return CommandResult(
            name=spec.name,
            status=status,
            exit_code=exit_code,
            duration_seconds=duration,
            stdout_log=_relative_path(stdout_path, relative_to),
            stderr_log=_relative_path(stderr_path, relative_to),
            stdout_truncated=bool(stdout_state["truncated"]),
            stderr_truncated=bool(stderr_state["truncated"]),
        )


def _terminate_process_tree(process: subprocess.Popen) -> None:
    """Stop scanner children too (CodeQL launches a Java child on Windows)."""
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                shell=False,
                check=False,
            )
            return
        except (OSError, subprocess.TimeoutExpired):
            pass
    process.terminate()


def _drain_stream(
    stream, destination: Path, limit: int, state: dict[str, int | bool]
) -> None:
    with destination.open("w", encoding="utf-8", newline="\n") as output:
        while True:
            chunk = stream.read(8192)
            if not chunk:
                break
            text = _redact(chunk.decode("utf-8", errors="replace"))
            encoded = text.encode("utf-8")
            remaining = limit - int(state["written"])
            if remaining <= 0:
                state["truncated"] = True
                continue
            kept = encoded[:remaining]
            output.write(kept.decode("utf-8", errors="ignore"))
            state["written"] = int(state["written"]) + len(kept)
            if len(encoded) > len(kept):
                state["truncated"] = True
        if state["truncated"]:
            output.write("\n[log truncated by orchestrator]\n")


def _redact(text: str) -> str:
    redacted = text
    for pattern in REDACTION_PATTERNS:
        if pattern.groups >= 2:
            redacted = pattern.sub(
                lambda match: f"{match.group(1)}=[REDACTED]", redacted
            )
        else:
            redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-.") or "command"


def _relative_path(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()
