#!/usr/bin/env python3
"""Approve or revoke rows of the CWE catalog. Only the review fields change; no number is ever edited.

  python scripts/approve_cwe_rows.py --list
  python scripts/approve_cwe_rows.py --ids CWE-89 CWE-77 --reviewer "Your Name" --note "why"
  python scripts/approve_cwe_rows.py --ids CWE-89 --revoke
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))        # lets this script run without `pip install -e .`

from security_reviewer_v2.policy.catalog_approval import KIND_CATALOG, cli_main

if __name__ == "__main__":
    sys.exit(cli_main(KIND_CATALOG))
