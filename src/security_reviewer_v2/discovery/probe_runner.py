"""Execute current-scan, source-backed GET proposals on disposable Compose."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import Any

from security_reviewer_v2.profiler import profile_project
from security_reviewer_v2.profiler.artifact import create_saved_profile_artifact
from security_reviewer_v2.scanners.generic_runtime import (
    GenericRuntimeConfig,
    run_generic_checks,
)
from security_reviewer_v2.test_environment import (
    load_environment_spec,
    plan_environment,
    provision_environment,
)

from .test_plan import bounded_probe_result, select_bounded_readonly_proposals


def run_current_discovery_probes(
    plan: dict[str, Any],
    *,
    project_root: Path,
    project_fingerprint: str,
    environment_config: Path,
    output_path: Path,
) -> dict[str, Any]:
    """Probe at most 20 exact GET routes; never infer a security expectation."""
    root = project_root.resolve(strict=True)
    proposals = select_bounded_readonly_proposals(
        plan, project_root=root, project_fingerprint=project_fingerprint
    )
    result = bounded_probe_result(
        proposals,
        None,
        health_path="/",
        project_fingerprint=project_fingerprint,
        source_plan="current-scan",
    )
    result["execution_mode"] = "disposable_compose"
    result["cleanup_verified"] = False
    if not proposals:
        result["cleanup_verified"] = True
        return result

    try:
        original_spec = load_environment_spec(environment_config, project_root=root)
        if (
            original_spec.mode != "docker_compose"
            or original_spec.trust_level != "trusted_local_project"
        ):
            raise ValueError(
                "Current Discovery GET probes require trusted local Compose"
            )
        # This fresh stack runs only anonymous GETs. Its earlier workflow and
        # account checks have already run in the original runtime session.
        spec = replace(
            original_spec,
            authorization_checks=False,
            mutating_checks=False,
            workflow_suite=None,
        )
        profile = profile_project(root)
        actual_fingerprint = create_saved_profile_artifact(profile, root)[
            "project_snapshot"
        ]["fingerprint"]
        if actual_fingerprint != project_fingerprint:
            raise ValueError("Project source changed since Discovery profiling")
        environment_plan = plan_environment(spec, project_root=root, profile=profile)
        if environment_plan.status != "ready_for_validation":
            raise ValueError(
                "Test environment is not ready for current Discovery probes"
            )
        docker = shutil.which("docker")
        if not docker:
            raise ValueError("Docker CLI is unavailable")
        with provision_environment(
            spec,
            environment_plan,
            project_root=root,
            allow_compose_execution=True,
            docker_executable=docker,
        ) as session:
            baseline = run_generic_checks(
                GenericRuntimeConfig(
                    session.base_url,
                    output_path,
                    spec.health_path,
                    spec.expected_status,
                    tuple(item["path"] for item in proposals),
                )
            )
            stack_name = session.project_name
        if not stack_name or not stack_name.startswith("sr-test-"):
            raise RuntimeError("Discovery probe stack identity was not verified")
        checked = subprocess.run(
            [
                docker,
                "ps",
                "--all",
                "--filter",
                f"label=com.docker.compose.project={stack_name}",
                "--format",
                "{{.ID}}",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if checked.returncode != 0 or checked.stdout.strip():
            raise RuntimeError("Discovery probe stack cleanup is unverified")
        observed = bounded_probe_result(
            proposals,
            baseline,
            health_path=spec.health_path,
            project_fingerprint=project_fingerprint,
            source_plan="current-scan",
        )
        observed["execution_mode"] = "disposable_compose"
        observed["cleanup_verified"] = True
        return observed
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        result["status"] = "blocked"
        result["warnings"] = [str(error)]
        return result
