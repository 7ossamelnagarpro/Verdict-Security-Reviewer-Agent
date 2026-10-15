"""Safe, read-only differential authorization probe for educational targets."""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin

from security_reviewer_v2.profiler.models import ScanTask, ScanType

from .base import ScannerAdapter
from .models import (
    AdapterExecutionPlan,
    CheckStatus,
    CommandSpec,
    ExecutionRequest,
    PrerequisiteCheck,
)


@dataclass(frozen=True)
class IdoorConfig:
    executable: str
    base_url: str
    user_a_token: str
    user_b_token: str
    user_a_resource: str = "/idor/vulnerable/orders/100"
    user_b_resource: str = "/idor/vulnerable/orders/200"
    safe_resource_template: str = "/idor/safe/orders/{resource_id}"
    source_path: str = "app.py"

    def validate(self) -> None:
        if not Path(self.executable).is_absolute():
            raise ValueError("Python executable path must be absolute")
        if not self.base_url.startswith(("http://", "https://")):
            raise ValueError("IDOR target must use an http(s) URL")
        if not self.user_a_token or not self.user_b_token:
            raise ValueError("Two non-empty test identities are required")
        for value in (self.user_a_resource, self.user_b_resource, self.safe_resource_template):
            if not value.startswith("/") or "\x00" in value:
                raise ValueError("IDOR paths must be safe absolute URL paths")


class IdoorAdapter(ScannerAdapter):
    scanner_id = "idor-dast"

    def __init__(self, config: IdoorConfig) -> None:
        config.validate()
        self.config = config

    def supports(self, task: ScanTask) -> bool:
        return (
            task.scanner_id == self.scanner_id
            and task.scan_type == ScanType.DAST
            and task.mode == "differential_authorization"
        )

    def check_prerequisites(self, task: ScanTask, *, project_root: str) -> tuple[PrerequisiteCheck, ...]:
        reachable = _health_check(self.config.base_url)
        return (
            PrerequisiteCheck(
                "target_reachable",
                CheckStatus.AVAILABLE if reachable else CheckStatus.MISSING,
                "IDOR target health endpoint is reachable" if reachable else "IDOR target is not reachable",
            ),
            PrerequisiteCheck("test_identities", CheckStatus.AVAILABLE, "Two synthetic test identities are configured"),
            PrerequisiteCheck("safe_mode", CheckStatus.AVAILABLE, "Probe performs GET requests only"),
        )

    def build_execution_plan(self, request: ExecutionRequest) -> AdapterExecutionPlan:
        if not self.supports(request.task):
            raise ValueError("IDOR adapter does not support this task")
        task_dir = Path(request.task_directory).resolve()
        config_path = task_dir / "probe-config.json"
        config_path.write_text(
            json.dumps(
                {
                    "base_url": self.config.base_url,
                    "user_a_token": self.config.user_a_token,
                    "user_b_token": self.config.user_b_token,
                    "user_a_resource": self.config.user_a_resource,
                    "user_b_resource": self.config.user_b_resource,
                    "safe_resource_template": self.config.safe_resource_template,
                    "source_path": self.config.source_path,
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        output = task_dir / "result.json"
        return AdapterExecutionPlan(
            commands=(
                CommandSpec(
                    name="idor-differential-probe",
                    executable=str(Path(self.config.executable).resolve()),
                    arguments=("-m", "security_reviewer_v2.scanners.idor", "--config", str(config_path), "--output", str(output)),
                    working_directory=str(Path(request.project_root).resolve()),
                    timeout_seconds=request.timeout_seconds,
                ),
            ),
            expected_outputs=("result.json",),
        )

    def validate_outputs(self, request: ExecutionRequest, plan: AdapterExecutionPlan) -> tuple[bool, str]:
        valid, reason = super().validate_outputs(request, plan)
        if not valid:
            return valid, reason
        try:
            payload = json.loads((Path(request.task_directory) / "result.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            return False, f"IDOR output could not be parsed: {type(error).__name__}"
        if not isinstance(payload.get("results"), list):
            return False, "IDOR output has no results array"
        return True, "IDOR differential probe produced valid JSON output"


def _health_check(base_url: str) -> bool:
    try:
        with urllib.request.urlopen(urljoin(base_url.rstrip("/") + "/", "health"), timeout=3) as response:
            return 200 <= response.status < 300
    except (OSError, urllib.error.URLError):
        return False


def _request(url: str, token: str) -> tuple[int, str]:
    request = urllib.request.Request(url, headers={"X-Test-User": token}, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, response.read(512 * 1024).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read(512 * 1024).decode("utf-8", errors="replace")


def _probe(config: dict[str, str]) -> dict[str, object]:
    base = config["base_url"].rstrip("/") + "/"
    a_path, b_path = config["user_a_resource"], config["user_b_resource"]
    _, _ = _request(urljoin(base, a_path.lstrip("/")), config["user_a_token"])
    b_status, b_body = _request(urljoin(base, b_path.lstrip("/")), config["user_b_token"])
    cross_status, cross_body = _request(urljoin(base, b_path.lstrip("/")), config["user_a_token"])
    vulnerable = cross_status == b_status and 200 <= cross_status < 300 and cross_body == b_body
    result: dict[str, object] = {
        "rule_id": "idor.cross-user-resource-access",
        "title": "Cross-user resource access (possible IDOR)",
        "message": "User A received the same protected resource response as User B when requesting User B's resource.",
        "severity": "high",
        "confidence": "high" if vulnerable else "medium",
        "vulnerable": vulnerable,
        "path": config.get("source_path", "runtime://authorization"),
        "start_line": None,
        "evidence": {
            "user_b_status": b_status,
            "cross_user_status": cross_status,
            "resource": b_path,
            "safe_mode": True,
        },
    }
    safe_path = config.get("safe_resource_template", "").replace("{resource_id}", b_path.rsplit("/", 1)[-1])
    if safe_path:
        safe_status, safe_body = _request(urljoin(base, safe_path.lstrip("/")), config["user_a_token"])
        result["safe_counterpart"] = {
            "path": safe_path,
            "status": safe_status,
            "denied": safe_status in {403, 404},
            "body_changed": safe_body != b_body,
        }
    return {"results": [result]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a read-only differential IDOR probe")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    payload = _probe(json.loads(args.config.read_text(encoding="utf-8")))
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": "completed", "findings": sum(1 for item in payload["results"] if item["vulnerable"]), "output": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
