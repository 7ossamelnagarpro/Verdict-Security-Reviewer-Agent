"""Plan and (only on explicit request) start an isolated test target."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from security_reviewer_v2.profiler import profile_project

from .manager import load_environment_spec, plan_environment, provision_environment


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project", type=Path)
    parser.add_argument("--config", type=Path, required=True, help="explicit user configuration outside the target repository")
    parser.add_argument("--output", type=Path, required=True, help="path for the prerequisite plan JSON")
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--smoke-test", action="store_true", help="start, check readiness, and immediately stop a Compose stack")
    actions.add_argument("--hold", action="store_true", help="keep the test stack running until Enter or Ctrl+C")
    parser.add_argument("--allow-compose-execution", action="store_true", help="explicitly permit a reviewed Compose recipe to execute")
    args = parser.parse_args(argv)

    project = args.project.resolve(strict=True)
    spec = load_environment_spec(args.config, project_root=project)
    profile = profile_project(project)
    plan = plan_environment(spec, project_root=project, profile=profile)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(plan.to_dict(), indent=2) + "\n", encoding="utf-8")
    print(json.dumps(plan.to_dict(), indent=2))
    if plan.status != "ready_for_validation":
        return 2
    if not (args.smoke_test or args.hold):
        return 0
    try:
        with provision_environment(spec, plan, project_root=project,
                                   allow_compose_execution=args.allow_compose_execution) as session:
            print(f"Test target ready at {session.base_url}; mode={session.mode}")
            if args.hold:
                print("Keep this terminal open during the scan. Press Enter or Ctrl+C to stop the test environment.")
                input()
    except KeyboardInterrupt:
        print("Stopping the test environment.")
    except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as error:
        print(f"Test environment could not become ready: {error}")
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
