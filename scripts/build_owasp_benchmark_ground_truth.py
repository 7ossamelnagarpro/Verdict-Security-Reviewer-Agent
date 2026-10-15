"""Convert OWASP Benchmark expectedresults CSV into our evaluation schema."""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", type=Path, default=Path("targets/owasp-benchmark-java/expectedresults-1.2.csv"))
    parser.add_argument("--output", type=Path, default=Path("benchmark/owasp_benchmark_java_ground_truth.json"))
    args = parser.parse_args()
    entries = []
    with args.csv.open(newline="", encoding="utf-8-sig") as handle:
        for row in csv.reader(line for line in handle if line.strip() and not line.lstrip().startswith("#")):
            if len(row) < 4:
                continue
            name, category, real, cwe = (value.strip() for value in row[:4])
            entries.append({
                "test_name": name,
                "category": category,
                "real_vulnerability": real.lower() == "true",
                "cwe": f"CWE-{cwe}" if cwe and cwe.isdigit() else cwe,
                "expected_status": "vulnerable" if real.lower() == "true" else "safe",
            })
    payload = {
        "schema_version": "1.0",
        "benchmark": "OWASP Benchmark for Java",
        "benchmark_version": "1.2",
        "source_csv": str(args.csv).replace("\\", "/"),
        "ground_truth_semantics": "real_vulnerability=true means the test is expected to be reported; false means it is a negative control.",
        "test_case_count": len(entries),
        "vulnerable_count": sum(1 for item in entries if item["real_vulnerability"]),
        "safe_count": sum(1 for item in entries if not item["real_vulnerability"]),
        "category_counts": dict(sorted(Counter(item["category"] for item in entries).items())),
        "test_cases": entries,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "completed", "test_cases": len(entries), "vulnerable": payload["vulnerable_count"], "safe": payload["safe_count"], "output": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
