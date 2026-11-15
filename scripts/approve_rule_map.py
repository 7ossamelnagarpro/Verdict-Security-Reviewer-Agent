#!/usr/bin/env python3
"""Approve or revoke rows of the rule -> CWE map. Only the review fields change; cwe and fixed_rating are never edited.

  python scripts/approve_rule_map.py --list
  python scripts/approve_rule_map.py --ids workflow.order_owner.3 --reviewer "Your Name" --note "why"
  python scripts/approve_rule_map.py --ids workflow.order_owner.3 --revoke
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))        # lets this script run without `pip install -e .`

from security_reviewer_v2.policy.catalog_approval import KIND_RULE_MAP, cli_main

if __name__ == "__main__":
    sys.exit(cli_main(KIND_RULE_MAP))
