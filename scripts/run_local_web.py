"""Start the localhost-only web control plane."""

from __future__ import annotations

import sys
from pathlib import Path

source_root = Path(__file__).resolve().parents[1] / "src"
if str(source_root) not in sys.path:
    sys.path.insert(0, str(source_root))

from security_reviewer_v2.web.app import main


if __name__ == "__main__":
    raise SystemExit(main())
