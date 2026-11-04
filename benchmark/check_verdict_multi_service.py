"""Read-only benchmark shape check; it never runs target code or reveals ground truth to scanners."""

from __future__ import annotations

import json
from pathlib import Path


def main() -> int:
    path = Path(__file__).with_name("verdict-multi-service-scenarios.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    scenarios = data.get("scenarios", [])
    ids = [item.get("id") for item in scenarios]
    assert len(scenarios) == 18
    assert len(set(ids)) == len(ids)
    assert all(item.get("category") and item.get("location") for item in scenarios)
    print(f"benchmark shape valid: {len(scenarios)} scenarios")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
