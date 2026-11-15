#!/usr/bin/env python3
"""Build src/security_reviewer_v2/policy/cwe_catalog.yaml from the cached NVD data. No network.

  python scripts/build_cwe_catalog.py

Reads  data/cwe_raw/CWE-*.jsonl   (scripts/fetch_nvd_cwe_data.py)
       data/cwe_dictionary.json   (scripts/fetch_cwe_dictionary.py)
Writes the catalog and docs/cwe_catalog_review.md. Re-running keeps an approval only when the numbers it approved are
unchanged; otherwise the row goes back to draft and says why.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))        # lets this script run without `pip install -e .`

from security_reviewer_v2.policy.catalog_approval import write_document
from security_reviewer_v2.policy.cwe_catalog_builder import (EXPECTED_CWES, FILE_HEADER, CatalogBuildError,
                                                             CatalogConfig, build_catalog, render_review_doc)
from security_reviewer_v2.policy.cwe_dictionary import CweDictionaryError, load_dictionary



def main(argv=None) -> int:
    defaults = CatalogConfig()
    parser = argparse.ArgumentParser(description="Build the CWE catalog from data/cwe_raw (no network).")
    parser.add_argument("--raw-dir", default=str(ROOT / "data" / "cwe_raw"))
    parser.add_argument("--dictionary", default=None, help="default: data/cwe_dictionary.json")
    parser.add_argument("--out", default=str(ROOT / "src" / "security_reviewer_v2" / "policy" / "cwe_catalog.yaml"))
    parser.add_argument("--review-doc", default=str(ROOT / "docs" / "cwe_catalog_review.md"))
    parser.add_argument("--expected", nargs="+", type=int, default=list(EXPECTED_CWES),
                        help="CWE numbers that should have data (default: the 43 agreed ones)")
    parser.add_argument("--sample-cap", type=int, default=defaults.sample_cap)
    parser.add_argument("--min-sample", type=int, default=defaults.min_sample)
    parser.add_argument("--stable-high", type=float, default=defaults.stable_high_threshold)
    parser.add_argument("--stable-low", type=float, default=defaults.stable_low_threshold)
    args = parser.parse_args(argv)

    config = CatalogConfig(sample_cap=args.sample_cap, min_sample=args.min_sample,
                           stable_high_threshold=args.stable_high, stable_low_threshold=args.stable_low)
    try:
        dictionary = load_dictionary(args.dictionary)
    except CweDictionaryError as exc:
        print(f"error: {exc}")
        return 2
    out = Path(args.out)
    previous = None
    if out.is_file():
        try:
            previous = yaml.safe_load(out.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            previous = None
    try:
        catalog, report = build_catalog(Path(args.raw_dir), dictionary, config, args.expected, previous=previous)
    except CatalogBuildError as exc:
        print(f"error: {exc}")
        return 2
    if not catalog["rows"]:
        print(f"error: no CWE-*.jsonl files found in {args.raw_dir}; run scripts/fetch_nvd_cwe_data.py first")
        return 2

    out.parent.mkdir(parents=True, exist_ok=True)
    write_document(out, FILE_HEADER, catalog)
    doc = Path(args.review_doc)
    doc.parent.mkdir(parents=True, exist_ok=True)
    doc.write_text(render_review_doc(catalog, report), encoding="utf-8")

    print(f"wrote {out} ({report['rows']} rows) and {doc}")
    print(f"default_basis: {report['by_default_basis']}")
    print(f"status:        {report['by_status']}")
    print(f"\nNO DATA for {len(report['missing_data'])} of the {report['expected']} expected CWEs: "
          f"{', '.join(report['missing_data']) or 'none'}")
    print(f"REFUSED by MITRE ({len(report['refused_by_mitre'])}):")
    for cwe, reason in report["refused_by_mitre"]:
        print(f"  {cwe}: {reason}")
    if not report["refused_by_mitre"]:
        print("  none")
    print(f"needs a written note to approve (ALLOWED_WITH_REVIEW): {', '.join(report['needs_review_note']) or 'none'}")
    if report["source_incomplete"]:
        print(f"INCOMPLETE downloads (not usable until re-fetched): {', '.join(report['source_incomplete'])}")
    if report["approvals_carried_over"]:
        print(f"approvals kept (numbers unchanged): {', '.join(report['approvals_carried_over'])}")
    if report["approvals_invalidated"]:
        print(f"APPROVALS DROPPED (numbers changed): {', '.join(report['approvals_invalidated'])}")
    if report["approved_rows_dropped"]:
        print(f"APPROVED ROWS REMOVED (no data file now): {', '.join(report['approved_rows_dropped'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
