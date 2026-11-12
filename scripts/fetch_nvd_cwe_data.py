#!/usr/bin/env python3
"""Fetch CVSS v3.1 data per CWE from the official NVD CVE API 2.0 and cache compact records on disk.

Why this exists: the CWE -> default CVSS vector table must be built from real data, not from memory.
This script ONLY collects data. A later step computes the statistics (most frequent vector, share, ...).

Output (default: data/cwe_raw/):
  CWE-<id>.jsonl      one compact record per CVE that has a CVSS v3.1 metric (sorted by published date)
  CWE-<id>.meta.json  progress and counts (resume-safe)
  cwe_names.json      official CWE names from MITRE (best effort; null when not fetched)
  MANIFEST.json       parameters, query date (UTC) and per-CWE summary

Usage:
  python fetch_nvd_cwe_data.py --probe                 # 1 quick request: checks connectivity and format
  python fetch_nvd_cwe_data.py                         # full run, default CWE list, resumable
  NVD_API_KEY=xxxx python fetch_nvd_cwe_data.py        # much faster with a free API key
  python fetch_nvd_cwe_data.py --cwe 79 89 --refresh   # re-fetch only these

Standard library only. Python 3.9+.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

SCRIPT_VERSION = "1.0"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MITRE_URL = "https://cwe-api.mitre.org/api/v1/cwe/weakness/"
API_KEY_URL = "https://nvd.nist.gov/developers/request-an-api-key"

# Default list: 43 CWEs the project actually meets (scanner/DAST/AI findings that have no authoritative severity of their own).
# Add more any time with --cwe or --cwe-file; already-complete CWEs are skipped on re-runs.
DEFAULT_CWES = [16, 22, 77, 78, 79, 89, 90, 94, 95, 200, 269, 284, 287, 306, 327, 328, 330, 338, 347, 352, 359,
                434, 472, 502, 532, 601, 611, 614, 639, 640, 693, 798, 841, 862, 863, 915, 918, 939, 942, 1004,
                1021, 1284, 1321]

VECTOR_RE = re.compile(
    r"^CVSS:3\.1/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]$"
)
RETRY_STATUS = {403, 429, 500, 502, 503, 504}
HTTP_WAITS = [35, 60, 90, 120, 180]      # NVD rate-limit windows are 30 s
NET_WAITS = [10, 20, 40, 80, 120]


class FetchError(RuntimeError):
    pass


def parse_cwe_id(value) -> int:
    match = re.fullmatch(r"(?:CWE-)?(\d{1,5})", str(value).strip(), re.IGNORECASE)
    if not match:
        raise ValueError(f"invalid CWE id: {value!r}")
    return int(match.group(1))


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- HTTP

class Fetcher:
    def __init__(self, api_key: str | None, min_interval: float, timeout: float, retry_scale: float):
        self.api_key = api_key or None
        self.min_interval = min_interval
        self.timeout = timeout
        self.retry_scale = retry_scale
        self._last = 0.0

    def _throttle(self) -> None:
        wait = self._last + self.min_interval - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()

    def get_json(self, url: str, params: dict | None = None, nvd: bool = True, max_retries: int | None = None):
        full = url + ("?" + urllib.parse.urlencode(params) if params else "")
        headers = {"User-Agent": f"verdict-cwe-fetch/{SCRIPT_VERSION}", "Accept": "application/json"}
        if nvd and self.api_key:
            headers["apiKey"] = self.api_key
        http_waits = HTTP_WAITS if max_retries is None else HTTP_WAITS[:max_retries]
        net_waits = NET_WAITS if max_retries is None else NET_WAITS[:max_retries]
        attempt = 0
        while True:
            if nvd:
                self._throttle()
            try:
                request = urllib.request.Request(full, headers=headers)
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    return json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                if exc.code not in RETRY_STATUS or attempt >= len(http_waits):
                    hint = ""
                    if exc.code in (403, 429):
                        hint = f" (probably NVD rate limiting; a free API key helps: {API_KEY_URL})"
                    raise FetchError(f"HTTP {exc.code} for {full}{hint}") from exc
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
                delay = float(retry_after) if retry_after and retry_after.isdigit() else http_waits[attempt]
                reason = f"HTTP {exc.code}"
            except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
                if attempt >= len(net_waits):
                    raise FetchError(f"network/format error for {full}: {exc}") from exc
                delay = net_waits[attempt]
                reason = type(exc).__name__
            attempt += 1
            wait = delay * self.retry_scale
            print(f"  ! {reason}; retry {attempt} in {wait:.0f}s", flush=True)
            time.sleep(wait)


# --------------------------------------------------------------------------- parsing

def _unique(items):
    seen, result = set(), []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def parse_vulnerability(entry: dict):
    """Return (record, None) or (None, reason). Pure function: no I/O."""
    cve = entry.get("cve") or {}
    cve_id = cve.get("id")
    if not cve_id:
        return None, "bad_vector"
    if str(cve.get("vulnStatus", "")).casefold() == "rejected":
        return None, "rejected"
    metrics = (cve.get("metrics") or {}).get("cvssMetricV31") or []
    if not metrics:
        return None, "no_cvss_v31"
    chosen = next((m for m in metrics if m.get("type") == "Primary"), metrics[0])
    data = chosen.get("cvssData") or {}
    vector = data.get("vectorString")
    if not isinstance(vector, str) or not VECTOR_RE.match(vector):
        return None, "bad_vector"
    primary, secondary = [], []
    for weakness in cve.get("weaknesses") or []:
        bucket = primary if weakness.get("type") == "Primary" else secondary
        for description in weakness.get("description") or []:
            value = description.get("value", "")
            if value.startswith("CWE-"):
                bucket.append(value)
    primary, secondary = _unique(primary), _unique(secondary)
    return {
        "cve": cve_id,
        "published": cve.get("published"),
        "vector": vector,
        "base_score": data.get("baseScore"),
        "severity": data.get("baseSeverity"),
        "metric_source": chosen.get("source"),
        "metric_type": chosen.get("type"),
        "cwe_primary": primary,
        "cwe_secondary": secondary,
        "cwe_count": len(_unique(primary + secondary)),
    }, None


# --------------------------------------------------------------------------- storage

def load_meta(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def save_meta(path: Path, meta: dict) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


def new_meta(cwe: int, page_size: int, with_key: bool) -> dict:
    return {
        "cwe": f"CWE-{cwe}", "script_version": SCRIPT_VERSION, "started_at": utc_now(), "finished_at": None,
        "page_size": page_size, "api_key_used": with_key, "total_results": None,
        "next_start_index": 0, "pages": 0, "complete": False,
        "counts": {"seen": 0, "kept": 0, "rejected": 0, "no_cvss_v31": 0, "bad_vector": 0,
                   "duplicates_removed": 0},
        "notes": ["paging by startIndex; records published during the run can shift pages slightly; "
                  "duplicates are removed on completion"],
    }


def finalize_file(path: Path, meta: dict) -> None:
    records, raw_lines = {}, 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            raw_lines += 1
            record = json.loads(line)
            records[record["cve"]] = record
    ordered = sorted(records.values(), key=lambda r: (r.get("published") or "", r["cve"]))
    tmp = path.with_suffix(".tmp")
    tmp.write_text("".join(json.dumps(r, ensure_ascii=False, separators=(",", ":")) + "\n" for r in ordered),
                   encoding="utf-8")
    os.replace(tmp, path)
    meta["counts"]["duplicates_removed"] += raw_lines - len(ordered)
    meta["counts"]["kept"] = len(ordered)


# --------------------------------------------------------------------------- fetching

def fetch_cwe(cwe: int, fetcher: Fetcher, out_dir: Path, base_url: str, page_size: int,
              max_pages: int, refresh: bool) -> dict:
    jpath = out_dir / f"CWE-{cwe}.jsonl"
    mpath = out_dir / f"CWE-{cwe}.meta.json"
    meta = None if refresh else load_meta(mpath)
    if meta and meta.get("complete") and jpath.exists():
        print(f"CWE-{cwe}: already complete ({meta['counts']['kept']} records), skipping", flush=True)
        return meta
    if not meta or refresh or not jpath.exists():
        meta = new_meta(cwe, page_size, bool(fetcher.api_key))
        jpath.write_text("", encoding="utf-8")
    pages_this_run = 0
    while True:
        if max_pages and pages_this_run >= max_pages:
            print(f"CWE-{cwe}: stopped by --max-pages; run again to resume", flush=True)
            break
        params = {"cweId": f"CWE-{cwe}", "resultsPerPage": page_size,
                  "startIndex": meta["next_start_index"]}
        data = fetcher.get_json(base_url, params)
        total = int(data.get("totalResults", 0))
        meta["total_results"] = total
        vulns = data.get("vulnerabilities") or []
        lines = []
        for entry in vulns:
            record, reason = parse_vulnerability(entry)
            meta["counts"]["seen"] += 1
            if record:
                lines.append(json.dumps(record, ensure_ascii=False, separators=(",", ":")))
            else:
                meta["counts"][reason] += 1
        if lines:
            with jpath.open("a", encoding="utf-8") as handle:
                handle.write("\n".join(lines) + "\n")
        meta["next_start_index"] += len(vulns)
        meta["pages"] += 1
        pages_this_run += 1
        save_meta(mpath, meta)
        if meta["pages"] == 1 and total:
            pages = math.ceil(total / page_size)
            print(f"CWE-{cwe}: {total} CVEs in NVD, ~{pages} page(s), "
                  f"~{pages * fetcher.min_interval:.0f}s minimum", flush=True)
        print(f"CWE-{cwe}: {min(meta['next_start_index'], total)}/{total} scanned", flush=True)
        if meta["next_start_index"] >= total:
            meta["complete"] = True
            break
        if not vulns:
            print(f"CWE-{cwe}: empty page before reaching totalResults; marked incomplete", flush=True)
            break
    if meta["complete"]:
        finalize_file(jpath, meta)
        meta["finished_at"] = utc_now()
        save_meta(mpath, meta)
        c = meta["counts"]
        print(f"CWE-{cwe}: done. kept={c['kept']} rejected={c['rejected']} "
              f"no_cvss_v31={c['no_cvss_v31']} bad_vector={c['bad_vector']} "
              f"duplicates_removed={c['duplicates_removed']}", flush=True)
    return meta


def fetch_names(ids, fetcher: Fetcher, names_url: str, out_path: Path) -> dict:
    existing = {}
    if out_path.exists():
        try:
            existing = json.loads(out_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            existing = {}
    result = {}
    for i in ids:
        key = f"CWE-{i}"
        if existing.get(key):
            result[key] = existing[key]
            continue
        name = None
        try:
            data = fetcher.get_json(names_url + str(i), nvd=False, max_retries=1)
            for weakness in data.get("Weaknesses") or []:
                if str(weakness.get("ID")) == str(i):
                    name = weakness.get("Name")
        except FetchError as exc:
            print(f"  ! name lookup failed for {key} ({exc}); stays null", flush=True)
        result[key] = name
        time.sleep(0.2)
    out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    missing = [k for k, v in result.items() if not v]
    print(f"names: {len(result) - len(missing)}/{len(result)} resolved"
          + (f"; missing {', '.join(missing)}" if missing else ""), flush=True)
    return result


def run_probe(fetcher: Fetcher, base_url: str, names_url: str) -> int:
    # NVD returns the OLDEST records first, and CVEs before 2019 have no CVSS v3.1,
    # so the probe reads the newest records (end of the list) instead of the first page.
    print("probe: checking CWE-79 on the newest records ...", flush=True)
    head = fetcher.get_json(base_url, {"cweId": "CWE-79", "resultsPerPage": 1, "startIndex": 0})
    total = int(head.get("totalResults", 0))
    start = max(0, total - 8)
    data = fetcher.get_json(base_url, {"cweId": "CWE-79", "resultsPerPage": 8, "startIndex": start})
    print(f"  totalResults={total}; reading records {start}..{total}", flush=True)
    ok = 0
    for entry in data.get("vulnerabilities") or []:
        record, reason = parse_vulnerability(entry)
        if record:
            ok += 1
            print(f"  {record['cve']} ({(record['published'] or '')[:10]}): {record['vector']} "
                  f"({record['severity']}) primary={record['cwe_primary']}", flush=True)
        else:
            cve = entry.get("cve") or {}
            keys = sorted((cve.get("metrics") or {}).keys())
            print(f"  {cve.get('id')}: skipped ({reason}); metric keys={keys}; "
                  f"vulnStatus={cve.get('vulnStatus')}", flush=True)
    name_ok = False
    if names_url:
        try:
            names = fetcher.get_json(names_url + "79", nvd=False)
            name_ok = bool(names and (names.get("Weaknesses") or [{}])[0].get("Name"))
        except FetchError:
            name_ok = False
    print(f"  MITRE name lookup: {'ok' if name_ok else 'NOT ok (names will stay null; not fatal)'}", flush=True)
    if ok:
        print(f"probe OK ({ok} usable CVSS v3.1 record(s) parsed)", flush=True)
        return 0
    print("probe: reached NVD but parsed 0 usable records among the newest ones; "
          "send me this whole output (the metric keys above show what the API returned)", flush=True)
    return 2


# --------------------------------------------------------------------------- main

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Fetch CVSS v3.1 data per CWE from the NVD CVE API 2.0.")
    parser.add_argument("--out", default="data/cwe_raw", help="output directory (default: data/cwe_raw)")
    parser.add_argument("--cwe", nargs="+", help="CWE ids (79 or CWE-79). Default: built-in list")
    parser.add_argument("--cwe-file", help="text file with one CWE id per line (# comments allowed)")
    parser.add_argument("--api-key", default=os.environ.get("NVD_API_KEY"), help="or env NVD_API_KEY")
    parser.add_argument("--page-size", type=int, default=2000, help="1..2000 (default 2000)")
    parser.add_argument("--max-pages", type=int, default=0, help="stop each CWE after N pages (0 = no limit)")
    parser.add_argument("--refresh", action="store_true", help="ignore previous progress and re-fetch")
    parser.add_argument("--skip-names", action="store_true", help="do not call MITRE for CWE names")
    parser.add_argument("--probe", action="store_true", help="one quick request to check access and format")
    parser.add_argument("--min-interval", type=float, default=None,
                        help="seconds between NVD requests (default 6.5 without key, 0.8 with key)")
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--base-url", default=NVD_URL, help=argparse.SUPPRESS)
    parser.add_argument("--names-url", default=MITRE_URL, help=argparse.SUPPRESS)
    parser.add_argument("--retry-scale", type=float, default=1.0, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    if not 1 <= args.page_size <= 2000:
        parser.error("--page-size must be between 1 and 2000")
    interval = args.min_interval if args.min_interval is not None else (0.8 if args.api_key else 6.5)
    fetcher = Fetcher(args.api_key, interval, args.timeout, args.retry_scale)
    if not args.api_key and not args.probe:
        print(f"note: no API key; limited to ~5 requests/30 s. A free key makes this much faster: {API_KEY_URL}",
              flush=True)

    try:
        if args.probe:
            return run_probe(fetcher, args.base_url, args.names_url)

        ids = []
        if args.cwe:
            ids += [parse_cwe_id(v) for v in args.cwe]
        if args.cwe_file:
            for line in Path(args.cwe_file).read_text(encoding="utf-8").splitlines():
                line = line.split("#", 1)[0].strip()
                if line:
                    ids.append(parse_cwe_id(line))
        if not ids:
            ids = list(DEFAULT_CWES)
        ids = _unique(ids)

        out_dir = Path(args.out)
        out_dir.mkdir(parents=True, exist_ok=True)
        print(f"fetching {len(ids)} CWE(s) into {out_dir}/ (resumable; Ctrl+C is safe)", flush=True)

        summary, failed = {}, []
        for cwe in ids:
            try:
                meta = fetch_cwe(cwe, fetcher, out_dir, args.base_url, args.page_size,
                                 args.max_pages, args.refresh)
            except FetchError as exc:
                print(f"CWE-{cwe}: FAILED ({exc}); progress is saved, rerun to resume", flush=True)
                failed.append(cwe)
                meta = load_meta(out_dir / f"CWE-{cwe}.meta.json") or {}
            if not meta.get("complete") and cwe not in failed:
                failed.append(cwe)
        for meta_path in sorted(out_dir.glob("CWE-*.meta.json"),
                                key=lambda p: int(p.name.split(".")[0].split("-")[1])):
            cached = load_meta(meta_path) or {}
            key = cached.get("cwe") or meta_path.name.split(".")[0]
            summary[key] = {"complete": bool(cached.get("complete")), "total_results": cached.get("total_results"),
                            "counts": cached.get("counts"), "file": meta_path.name.replace(".meta.json", ".jsonl")}

        names_status = "skipped"
        if not args.skip_names:
            names = fetch_names(ids, fetcher, args.names_url, out_dir / "cwe_names.json")
            names_status = f"{sum(1 for v in names.values() if v)}/{len(names)} resolved"
        manifest = {
            "script_version": SCRIPT_VERSION, "query_date_utc": utc_now(), "source": "NVD CVE API 2.0",
            "base_url": args.base_url, "page_size": args.page_size, "api_key_used": bool(args.api_key),
            "names_source": "MITRE CWE REST API (best effort)", "names_status": names_status,
            "cwe_summary": summary,
        }
        (out_dir / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False),
                                               encoding="utf-8")
        if failed:
            print(f"\nINCOMPLETE: {', '.join(f'CWE-{c}' for c in failed)}. Rerun the same command to resume.",
                  flush=True)
            return 1
        print("\nALL DONE. Next step: compute the statistics from the cached files (no network needed).",
              flush=True)
        return 0
    except KeyboardInterrupt:
        print("\ninterrupted; progress is saved. Rerun the same command to resume.", flush=True)
        return 130
    except FetchError as exc:
        print(f"fatal: {exc}", flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
