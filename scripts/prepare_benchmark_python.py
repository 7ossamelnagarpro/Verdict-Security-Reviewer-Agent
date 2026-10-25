"""Copy a balanced sample of OWASP BenchmarkPython into a scan target.

The scan target gets only ``helpers/`` and the chosen ``testcode/`` files. The
expected-results CSV, the bundled tool results (``results/``) and the scripts are
**not** copied: the ground truth must never be visible to the scanners, the AI
Discovery or the review agent. A manifest (outside the target) records the sample.

    python scripts/prepare_benchmark_python.py --source ~/BenchmarkPython \
        --dest targets/owasp-benchmark-python --per-category 6
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import shutil
from collections import defaultdict
from pathlib import Path


def read_truth(csv_path: Path) -> list[dict[str, str]]:
    rows = []
    with csv_path.open(newline="", encoding="utf-8-sig") as handle:
        for row in csv.reader(line for line in handle if line.strip() and not line.lstrip().startswith("#")):
            if len(row) >= 4:
                name, category, real, cwe = (value.strip() for value in row[:4])
                rows.append({"test": name, "category": category, "vulnerable": real.lower() == "true", "cwe": cwe})
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", type=Path, required=True, help="clone of OWASP-Benchmark/BenchmarkPython")
    parser.add_argument("--dest", type=Path, required=True, help="scan target to create (must not exist)")
    parser.add_argument("--per-category", type=int, default=6, help="vulnerable AND safe tests per category (default 6)")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--manifest", type=Path, default=Path("benchmark/owasp_python_sample.json"))
    args = parser.parse_args()
    if args.dest.exists():
        parser.error(f"{args.dest} already exists; choose a new folder so an old sample is never mixed in")
    rows = read_truth(args.source / "expectedresults-0.1.csv")
    rnd = random.Random(args.seed)
    groups: dict[tuple[str, bool], list[dict]] = defaultdict(list)
    for row in rows:
        groups[(row["category"], row["vulnerable"])].append(row)
    chosen = []
    for key in sorted(groups):
        pool = sorted(groups[key], key=lambda r: r["test"])
        chosen += rnd.sample(pool, min(args.per_category, len(pool)))
    chosen.sort(key=lambda r: r["test"])
    (args.dest / "testcode").mkdir(parents=True)
    shutil.copytree(args.source / "helpers", args.dest / "helpers")
    for row in chosen:
        shutil.copy2(args.source / "testcode" / f"{row['test']}.py", args.dest / "testcode" / f"{row['test']}.py")
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(json.dumps({"source": "OWASP-Benchmark/BenchmarkPython v0.1", "seed": args.seed,
                                         "per_category": args.per_category, "tests": chosen}, indent=2) + "\n", encoding="utf-8")
    vulnerable = sum(r["vulnerable"] for r in chosen)
    print(f"Sampled {len(chosen)} tests ({vulnerable} vulnerable, {len(chosen) - vulnerable} safe) into {args.dest}")
    print(f"Manifest (keep outside the scan target): {args.manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
