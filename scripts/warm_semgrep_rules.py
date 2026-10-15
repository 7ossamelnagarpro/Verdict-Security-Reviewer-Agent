"""Fetch and validate the pinned Semgrep Community rule packs once.

The normal scanner then reuses Semgrep's local cache instead of fetching packs
for every component task. This command is intentionally explicit and can be
run during environment setup or CI cache preparation.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("target", type=Path)
    parser.add_argument("--semgrep", default="semgrep")
    parser.add_argument("--output", type=Path, default=Path("scans/semgrep-rule-cache-warmup.json"))
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    command = [sys.executable, "-m", "semgrep", "scan", "--config", "p/python",
               "--config", "p/security-audit", "--config", "p/owasp-top-ten",
               "--dryrun", "--metrics=off", "--disable-version-check", "--json",
               f"--output={args.output}", str(args.target)]
    # Prefer the explicitly configured executable when it is not the module interpreter.
    if args.semgrep != "semgrep":
        command = [args.semgrep, *command[3:]]
    completed = subprocess.run(command, check=False)
    if completed.returncode == 0:
        print(f"Semgrep rule cache validated: {args.output}")
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
