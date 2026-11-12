#!/usr/bin/env python3
"""Build a trusted CWE dictionary from the OFFICIAL MITRE CWE catalog (XML).

What it gives you, per CWE id: name, kind (weakness / category / view), status (e.g. Stable, Deprecated),
abstraction, and MITRE's own "Vulnerability Mapping Notes" usage: ALLOWED, ALLOWED_WITH_REVIEW, DISCOURAGED
or PROHIBITED. Nothing here is written by an LLM.

Output: data/cwe_dictionary.json   (+ the downloaded zip is cached in data/cwe_dictionary_raw/)

Usage:
  python fetch_cwe_dictionary.py                       # download, build, print the check table
  python fetch_cwe_dictionary.py --check 79 89 862     # print the table for these ids only
  python fetch_cwe_dictionary.py --zip-file cwec_latest.xml.zip   # use a file you downloaded by hand (zip or xml)

Standard library only. Python 3.9+.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import json
import re
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

SCRIPT_VERSION = "1.1"
CATALOG_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

# The 43 CWEs fetched from NVD + the alternatives proposed in rule_cwe_map.draft.yaml.
CHECK_DEFAULT = sorted({
    16, 22, 77, 78, 79, 89, 90, 94, 95, 200, 269, 284, 287, 306, 327, 328, 330, 338, 347, 352, 359, 434, 472, 502,
    532, 601, 611, 614, 639, 640, 693, 798, 841, 862, 863, 915, 918, 939, 942, 1004, 1021, 1284, 1321,
    20, 213, 215, 345, 489, 602, 613,
})

# Entries are detected generically: every child of a top-level container that carries an ID attribute is an entry,
# and its kind is its element name lower-cased (Weakness, Category, Grouping, View, ...). MITRE renamed Category to
# Grouping in newer catalogs, and this keeps working if it renames things again.
USAGES = {"ALLOWED", "ALLOWED_WITH_REVIEW", "DISCOURAGED", "PROHIBITED"}


class DictionaryError(RuntimeError):
    pass


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _text(element) -> str:
    return re.sub(r"\s+", " ", "".join(element.itertext())).strip()


# --------------------------------------------------------------------------- obtaining the catalog

def download(url: str, timeout: float = 120.0, attempts: int = 3) -> bytes:
    last = None
    for attempt in range(1, attempts + 1):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": f"verdict-cwe-dictionary/{SCRIPT_VERSION}"})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read()
        except (urllib.error.URLError, OSError) as exc:
            last = exc
            print(f"  ! download attempt {attempt}/{attempts} failed: {exc}", flush=True)
            time.sleep(3 * attempt)
    raise DictionaryError(
        f"could not download {url}: {last}\n"
        "Fallback: open https://cwe.mitre.org/data/downloads.html in a browser, download the XML zip, "
        "then run: python fetch_cwe_dictionary.py --zip-file <the downloaded file>")


def xml_from_bytes(raw: bytes) -> bytes:
    """Accept the zip from MITRE or a bare XML file."""
    if raw[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            names = [n for n in archive.namelist() if n.lower().endswith(".xml")]
            if not names:
                raise DictionaryError("the zip contains no .xml file")
            return archive.read(sorted(names)[0])
    return raw


# --------------------------------------------------------------------------- parsing (pure)

def parse_catalog(xml_bytes: bytes) -> dict:
    root = ET.fromstring(xml_bytes)
    if _local(root.tag) != "Weakness_Catalog":
        raise DictionaryError(f"unexpected root element <{_local(root.tag)}>; this is not a CWE catalog")
    entries: dict[str, dict] = {}
    for container in root:
        for element in container:
            if not element.get("ID"):
                continue
            kind = _local(element.tag).lower()
            cwe_id = f"CWE-{element.get('ID').strip()}"
            usage, rationale, reasons = None, "", []
            parents: list[str] = []
            for child in element:
                name = _local(child.tag)
                if name == "Mapping_Notes":
                    for note in child:
                        note_name = _local(note.tag)
                        if note_name == "Usage":
                            usage = _text(note).upper().replace("-", "_").replace(" ", "_") or None
                        elif note_name == "Rationale":
                            rationale = _text(note)[:400]
                        elif note_name == "Reasons":
                            reasons = [r.get("Type") for r in note if r.get("Type")]
                elif name == "Related_Weaknesses":
                    for related in child:
                        if related.get("Nature") == "ChildOf" and related.get("CWE_ID"):
                            parent = f"CWE-{related.get('CWE_ID').strip()}"
                            if parent not in parents:
                                parents.append(parent)
            entries[cwe_id] = {
                "id": cwe_id, "kind": kind, "name": element.get("Name"), "status": element.get("Status"),
                "abstraction": element.get("Abstraction"), "structure": element.get("Structure"),
                "usage": usage if usage in USAGES else usage, "usage_rationale": rationale or None,
                "usage_reasons": reasons, "parents": parents,
            }
    if not entries:
        raise DictionaryError("no Weakness/Category/View entries found; the file layout is not what was expected")
    return {"version": root.get("Version"), "date": root.get("Date"), "entries": entries}


def verdict(entry: dict | None) -> tuple[str, str]:
    """(verdict, reason). verdict: ok | needs_review_note | refuse."""
    if entry is None:
        return "refuse", "not found in the catalog"
    if str(entry.get("status") or "").casefold() in {"deprecated", "obsolete"}:
        return "refuse", f"status is {entry['status']}"
    usage = entry.get("usage")
    if usage == "ALLOWED":
        return "ok", "mapping usage ALLOWED"
    if usage == "ALLOWED_WITH_REVIEW":
        return "needs_review_note", "mapping usage ALLOWED_WITH_REVIEW: a reviewer note is required"
    if usage in {"DISCOURAGED", "PROHIBITED"}:
        return "refuse", f"mapping usage {usage}"
    return "needs_review_note", "no mapping usage in this catalog version: a reviewer note is required"


def validate_cwe(dictionary: dict, cwe) -> dict:
    """Importable validator. `cwe` can be 79, "79" or "CWE-79"."""
    match = re.fullmatch(r"(?:CWE-)?(\d{1,5})", str(cwe).strip(), re.IGNORECASE)
    key = f"CWE-{int(match.group(1))}" if match else str(cwe)
    entry = (dictionary.get("entries") or {}).get(key)
    result, reason = verdict(entry)
    return {"id": key, "exists": entry is not None, "verdict": result, "reason": reason,
            "usage": (entry or {}).get("usage"), "kind": (entry or {}).get("kind"),
            "status": (entry or {}).get("status"), "name": (entry or {}).get("name")}


# --------------------------------------------------------------------------- reporting

def summarize(dictionary: dict) -> str:
    entries = dictionary["entries"].values()
    kinds, usages = {}, {}
    for entry in entries:
        kinds[entry["kind"]] = kinds.get(entry["kind"], 0) + 1
        usages[entry["usage"] or "none"] = usages.get(entry["usage"] or "none", 0) + 1
    return (f"catalog version {dictionary['version']} ({dictionary['date']}); {len(dictionary['entries'])} entries; "
            f"kinds={kinds}; mapping usage={usages}")


def check_table(dictionary: dict, ids) -> str:
    lines = [f"{'CWE':<10}{'kind':<10}{'status':<12}{'usage':<22}{'verdict':<19}name", "-" * 100]
    counts = {"ok": 0, "needs_review_note": 0, "refuse": 0}
    for cwe in ids:
        info = validate_cwe(dictionary, cwe)
        counts[info["verdict"]] += 1
        if not info["exists"]:
            lines.append(f"{info['id']:<10}{'-':<10}{'-':<12}{'-':<22}{info['verdict']:<19}NOT FOUND")
            continue
        lines.append(f"{info['id']:<10}{info['kind']:<10}{str(info['status']):<12}{str(info['usage']):<22}"
                     f"{info['verdict']:<19}{(info['name'] or '')[:46]}")
    lines.append("-" * 100)
    lines.append(f"verdicts: ok={counts['ok']}  needs_review_note={counts['needs_review_note']}  "
                 f"refuse={counts['refuse']}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- main

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Build data/cwe_dictionary.json from the official MITRE CWE catalog.")
    parser.add_argument("--out", default="data/cwe_dictionary.json")
    parser.add_argument("--cache-dir", default="data/cwe_dictionary_raw")
    parser.add_argument("--zip-file", help="use a catalog you already downloaded (zip or xml) instead of the network")
    parser.add_argument("--url", default=CATALOG_URL, help=argparse.SUPPRESS)
    parser.add_argument("--check", nargs="+", help="ids to show in the table (default: the 43 + alternatives)")
    args = parser.parse_args(argv)

    try:
        if args.zip_file:
            raw = Path(args.zip_file).read_bytes()
            source = str(Path(args.zip_file))
        else:
            print(f"downloading {args.url} ...", flush=True)
            raw = download(args.url)
            cache = Path(args.cache_dir)
            cache.mkdir(parents=True, exist_ok=True)
            (cache / "cwec_latest.xml.zip").write_bytes(raw)
            source = args.url
        dictionary = parse_catalog(xml_from_bytes(raw))
    except (DictionaryError, zipfile.BadZipFile, ET.ParseError, OSError) as exc:
        print(f"error: {exc}", flush=True)
        return 1

    dictionary["meta"] = {
        "source": source, "downloaded_at_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sha256_of_input": hashlib.sha256(raw).hexdigest(), "script_version": SCRIPT_VERSION,
        "note": "Built from the official MITRE CWE catalog. Usage is MITRE's Vulnerability Mapping Notes.",
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(dictionary, indent=1, ensure_ascii=False), encoding="utf-8")
    print(summarize(dictionary), flush=True)
    print(f"wrote {out} ({out.stat().st_size / 1000:.0f} KB)\n", flush=True)

    ids = [re.sub(r"(?i)^cwe-", "", str(i)) for i in args.check] if args.check else CHECK_DEFAULT
    print(check_table(dictionary, ids), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
