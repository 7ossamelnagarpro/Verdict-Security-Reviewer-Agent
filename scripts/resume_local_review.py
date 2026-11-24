"""Resume saved AI stages in a new directory; never runs Docker or scanners."""
from __future__ import annotations
import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

from security_reviewer_v2.discovery.completion import required_discovery_satisfied
from security_reviewer_v2.profiler.artifact import validate_saved_profile_artifact


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project", type=Path)
    parser.add_argument("saved", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--provider", choices=("groq", "ollama", "openai", "openrouter", "gemini"), default="groq")
    parser.add_argument("--model", default="openai/gpt-oss-120b")
    args = parser.parse_args()
    if args.output.exists() or args.output.resolve().is_relative_to(args.project.resolve()):
        parser.error("Use a new output directory outside the project")
    profile = json.loads((args.saved / "profile.json").read_text(encoding="utf-8"))
    validate_saved_profile_artifact(profile, args.project)
    for name in ("merged.json", "context.json"):
        if not (args.saved / name).is_file():
            parser.error("Saved static evidence is incomplete")
    args.output.mkdir(parents=True)
    for name in ("profile.json", "merged.json", "context.json", "plan.json", "coverage-gaps.json",
                 "runtime.json", "workflow-evidence.json", "docker-runtime-evidence.json", "ai-discovery.json", "pre-review-summary.json",
                 "dynamic-penetration-test.json"):
        if (args.saved / name).is_file():
            shutil.copy2(args.saved / name, args.output / name)
    scripts = Path(__file__).resolve().parent
    discovery = args.output / "ai-discovery.json"
    complete = discovery.is_file() and required_discovery_satisfied(json.loads(discovery.read_text(encoding="utf-8")))
    if not complete:
        command = [sys.executable, str(scripts / "run_saved_ai_discovery.py"), str(args.project),
                   "--profile", str(args.output / "profile.json"), "--merged", str(args.output / "merged.json"),
                   "--context", str(args.output / "context.json"), "--output", str(discovery),
                   "--provider", args.provider, "--model", args.model]
        if subprocess.run(command, check=False).returncode:
            return 1
    validate_saved_profile_artifact(profile, args.project)
    command = [sys.executable, str(scripts / "run_saved_review_stages.py"), str(args.project), str(discovery),
               str(args.output / "merged.json"), str(args.output), "--profile", str(args.output / "profile.json"),
               "--scanner-context", str(args.output / "context.json"), "--review", "--provider", args.provider,
               "--model", args.model]
    for flag, name in (("--prior-review", "security-review.json"),
                       ("--docker-runtime-evidence", "docker-runtime-evidence.json"),
                       ("--runtime-evidence", "runtime.json"), ("--coverage-summary", "pre-review-summary.json"),
                       ("--penetration-test", "dynamic-penetration-test.json")):
        if (args.saved / name).is_file():
            command.extend([flag, str(args.saved / name)])
    result = subprocess.run(command, check=False).returncode
    (args.output / "resume-provenance.json").write_text(json.dumps({
        "source_report": str(args.saved.resolve()), "source_checked": True,
        "docker_rerun": False, "scanners_rerun": False, "discovery_reused": complete,
        "note": "Runtime and coverage artifacts are retained from the original scan, not executed again."
    }, indent=2), encoding="utf-8")
    runtime = args.output / "runtime.json"
    if runtime.is_file() and json.loads(runtime.read_text(encoding="utf-8")).get("status") != "completed":
        summary_path = args.output / "stage-summary.json"
        if summary_path.is_file():
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            summary.update(status="partial", runtime_status="partial", runtime_note="AI resumed; incomplete runtime tests must be executed in a new full run.")
            summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        return 1
    return result


if __name__ == "__main__":
    raise SystemExit(main())
