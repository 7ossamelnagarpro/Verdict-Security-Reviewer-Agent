"""Build the CWE catalog: a statistical reference per CWE, computed from the cached NVD records.

Inputs (all local, no network): ``data/cwe_raw/CWE-<n>.jsonl`` + ``.meta.json`` written by
``scripts/fetch_nvd_cwe_data.py`` and the MITRE dictionary used through ``cwe_dictionary.validate_cwe``.
Nothing here asks an LLM for a number and no vector is written from memory: every figure is counted from the records.

The catalog does not decide anything by itself. Rows start as ``draft_needs_human_review`` and only a person can approve
them (``catalog_approval``). The thresholds that turn a distribution into a ``default_basis`` are constants in
``CatalogConfig`` and are written into the catalog file so a reviewer can see which thresholds produced it.
"""
from __future__ import annotations

import hashlib
import json
import statistics
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import yaml

from .cwe_dictionary import validate_cwe

SCHEMA_VERSION = 1
CVSS_VERSION = "3.1"

STATUS_DRAFT = "draft_needs_human_review"
STATUS_APPROVED = "approved"
STATUS_REFUSED = "refused_by_mitre"
STATUS_SOURCE_INCOMPLETE = "source_incomplete"
STATUSES = (STATUS_DRAFT, STATUS_APPROVED, STATUS_REFUSED, STATUS_SOURCE_INCOMPLETE)

BASIS_STABLE_HIGH = "stable_high"
BASIS_STABLE_LOW = "stable_low"
BASIS_AMBIGUOUS = "ambiguous"
BASIS_INSUFFICIENT = "insufficient_data"
BASES = (BASIS_STABLE_HIGH, BASIS_STABLE_LOW, BASIS_AMBIGUOUS, BASIS_INSUFFICIENT)

RATINGS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")           # most severe first (used to break ties)
METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

# The 43 CWEs agreed for this project (the default list of scripts/fetch_nvd_cwe_data.py).
EXPECTED_CWES = (16, 22, 77, 78, 79, 89, 90, 94, 95, 200, 269, 284, 287, 306, 327, 328, 330, 338, 347, 352, 359,
                 434, 472, 502, 532, 601, 611, 614, 639, 640, 693, 798, 841, 862, 863, 915, 918, 939, 942, 1004,
                 1021, 1284, 1321)

REVIEW_FIELDS = ("status", "reviewed_by", "reviewed_at", "review_note")
FILE_HEADER = """\
# CWE catalog: a statistical reference per CWE, built by scripts/build_cwe_catalog.py
# from data/cwe_raw/ (NVD CVE API 2.0) and data/cwe_dictionary.json (official MITRE CWE catalog).
# Defaults are statistical, not official. Human review is required before any use.
# Every row starts as draft_needs_human_review. Nothing here is used until a person approves the row
# (scripts/approve_cwe_rows.py). Do not edit numbers by hand: rebuild instead.
"""


class CatalogBuildError(RuntimeError):
    pass


@dataclass(frozen=True)
class CatalogConfig:
    """Policy constants. They are copied into the catalog file under ``config``."""
    sample_cap: int = 300                      # newest N records per CWE
    min_sample: int = 30                       # below this a row is insufficient_data
    stable_high_threshold: float = 0.85        # High+Critical share >= this -> stable_high
    stable_low_threshold: float = 0.15         # High+Critical share <= this -> stable_low
    preferred_metric_source: str = "nvd@nist.gov"
    min_preferred_records: int = 30            # use only the preferred source when at least this many remain
    low_vector_agreement: float = 0.40         # reference vector share below this -> low_vector_agreement flag


# --------------------------------------------------------------------------- sampling

@dataclass(frozen=True)
class SampleSelection:
    records: list[dict]            # the sample, newest first, at most sample_cap
    pool: list[dict]               # every record that passed the filters (newest first), before the cap
    flags: list[str]


def cwe_key(value: int | str) -> str:
    text = str(value).strip()
    return text.upper() if text.upper().startswith("CWE-") else f"CWE-{int(text)}"


def _newest_first(records: Iterable[dict]) -> list[dict]:
    return sorted(records, key=lambda r: (r.get("published") or "", r.get("cve") or ""), reverse=True)


def select_sample(records: Sequence[dict], cwe_id: str, config: CatalogConfig) -> SampleSelection:
    """Primary-assigned records (else primary+secondary), prefer the NVD scorer, newest first, capped."""
    flags: list[str] = []
    pool = [r for r in records if cwe_id in (r.get("cwe_primary") or [])]
    if len(pool) < config.min_sample:
        pool = [r for r in records
                if cwe_id in (r.get("cwe_primary") or []) or cwe_id in (r.get("cwe_secondary") or [])]
        flags.append("weak_cwe_assignment")
    preferred = [r for r in pool if r.get("metric_source") == config.preferred_metric_source]
    if len(preferred) >= config.min_preferred_records:
        pool = preferred
    else:
        flags.append("non_nvd_scores_used")
    pool = _newest_first(pool)
    return SampleSelection(records=pool[:config.sample_cap], pool=pool, flags=flags)


# --------------------------------------------------------------------------- statistics

def _top(counter: Counter) -> tuple[str, int]:
    """Most common value; ties resolved alphabetically so the output is deterministic."""
    return sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[0]


def rating_of(record: Mapping[str, Any]) -> str | None:
    severity = str(record.get("severity") or "").upper()
    if severity in RATINGS:
        return severity
    score = record.get("base_score")
    if isinstance(score, (int, float)) and not isinstance(score, bool):
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0:
            return "LOW"
    return None


def parse_vector(vector: str) -> dict[str, str]:
    parts = vector.split("/")[1:]
    parsed = dict(part.split(":", 1) for part in parts if ":" in part)
    return {metric: parsed[metric] for metric in METRICS if metric in parsed}


def default_basis(sample_size: int, high_critical_share: float | None, config: CatalogConfig) -> str:
    if sample_size < config.min_sample or high_critical_share is None:
        return BASIS_INSUFFICIENT
    if high_critical_share >= config.stable_high_threshold:
        return BASIS_STABLE_HIGH
    if high_critical_share <= config.stable_low_threshold:
        return BASIS_STABLE_LOW
    return BASIS_AMBIGUOUS


def compute_stats(sample: Sequence[dict], config: CatalogConfig) -> dict[str, Any]:
    """Every figure is counted from the sample. Shares are rounded to 4 decimals for storage only."""
    n = len(sample)
    if n == 0:
        return {"sample_size": 0, "reference_vector": None, "reference_vector_share": None,
                "rating_distribution": {r: None for r in RATINGS}, "unrated_records": 0, "high_critical_share": None,
                "_modal_rating": None, "_modal_share": None, "per_metric_agreement": {m: None for m in METRICS},
                "nvd_median_base_score": None, "_hc_exact": None, "_mode_exact": None}
    vector, vector_count = _top(Counter(r["vector"] for r in sample if r.get("vector")))
    ratings = Counter(x for x in (rating_of(r) for r in sample) if x)
    rated = sum(ratings.values())
    distribution = {r: round(ratings[r] / rated, 4) if rated else None for r in RATINGS}
    hc_exact = (ratings["CRITICAL"] + ratings["HIGH"]) / rated if rated else None
    modal = None
    if rated:
        modal = sorted(RATINGS, key=lambda r: (-ratings[r], RATINGS.index(r)))[0]    # tie -> the more severe one
    agreement: dict[str, Any] = {}
    parsed = [parse_vector(r["vector"]) for r in sample if r.get("vector")]
    for metric in METRICS:
        counter = Counter(p[metric] for p in parsed if metric in p)
        if counter:
            value, count = _top(counter)
            agreement[metric] = {"value": value, "share": round(count / sum(counter.values()), 4)}
        else:
            agreement[metric] = None
    scores = [r["base_score"] for r in sample
              if isinstance(r.get("base_score"), (int, float)) and not isinstance(r.get("base_score"), bool)]
    return {
        "sample_size": n,
        "reference_vector": vector, "reference_vector_share": round(vector_count / n, 4),
        "rating_distribution": distribution, "unrated_records": n - rated,
        "high_critical_share": round(hc_exact, 4) if hc_exact is not None else None,
        "_modal_rating": modal, "_modal_share": round(ratings[modal] / rated, 4) if modal else None,
        "per_metric_agreement": agreement,
        "nvd_median_base_score": round(statistics.median(scores), 1) if scores else None,
        "_hc_exact": hc_exact, "_mode_exact": vector_count / n,
    }


def content_fingerprint(row: Mapping[str, Any]) -> str:
    """Hash of everything a reviewer approves (numbers, basis, flags, MITRE verdict); not of the review fields."""
    payload = {k: row.get(k) for k in (
        "id", "default_basis", "modal_rating", "sample_size", "reference_vector", "reference_vector_share",
        "rating_distribution", "high_critical_share", "per_metric_agreement", "nvd_median_base_score")}
    payload["flags"] = sorted(row.get("flags") or [])
    payload["mitre_verdict"] = (row.get("mitre") or {}).get("verdict")
    payload["mitre_usage"] = (row.get("mitre") or {}).get("usage")
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


# --------------------------------------------------------------------------- rows

def build_row(cwe_id: str, records: Sequence[dict], meta: Mapping[str, Any] | None, dictionary: Mapping[str, Any],
              config: CatalogConfig) -> dict[str, Any]:
    selection = select_sample(records, cwe_id, config)
    stats = compute_stats(selection.records, config)
    flags = list(selection.flags)
    check = validate_cwe(cwe_id, dictionary=dict(dictionary))
    incomplete = meta is not None and not meta.get("complete")

    basis = default_basis(stats["sample_size"], stats["_hc_exact"], config)
    if incomplete:
        basis = BASIS_INSUFFICIENT
        flags.append("source_incomplete")
    if stats["sample_size"] < config.min_sample:
        flags.append("small_sample")
    if stats["_mode_exact"] is not None and stats["sample_size"] >= config.min_sample \
            and stats["_mode_exact"] < config.low_vector_agreement:
        flags.append("low_vector_agreement")
    if len(selection.pool) > len(selection.records):
        all_time_mode, _ = _top(Counter(r["vector"] for r in selection.pool if r.get("vector")))
        if all_time_mode != stats["reference_vector"]:
            flags.append("unstable_over_time")
    if not check["name"]:
        flags.append("name_missing")

    if incomplete:
        status = STATUS_SOURCE_INCOMPLETE
    elif check["verdict"] == "refuse":
        status = STATUS_REFUSED
    else:
        status = STATUS_DRAFT
    published = [r["published"] for r in selection.records if r.get("published")]
    row = {
        "id": cwe_id, "name": check["name"], "status": status, "default_basis": basis,
        "modal_rating": stats["_modal_rating"] if basis in (BASIS_STABLE_HIGH, BASIS_STABLE_LOW) else None,
        "modal_rating_share": stats["_modal_share"] if basis in (BASIS_STABLE_HIGH, BASIS_STABLE_LOW) else None,
        "sample_size": stats["sample_size"], "candidates_after_filters": len(selection.pool),
        "records_in_cache": len(records),
        "sample_window": {"newest": max(published) if published else None, "oldest": min(published) if published else None},
        "reference_vector": stats["reference_vector"], "reference_vector_share": stats["reference_vector_share"],
        "rating_distribution": stats["rating_distribution"], "unrated_records": stats["unrated_records"],
        "high_critical_share": stats["high_critical_share"], "per_metric_agreement": stats["per_metric_agreement"],
        "nvd_median_base_score": stats["nvd_median_base_score"],
        "flags": sorted(set(flags)),
        "mitre": {"verdict": check["verdict"], "usage": check["usage"], "kind": check["kind"],
                  "dictionary_status": check["status"], "reason": check["reason"]},
        "needs_review_note": check["verdict"] == "needs_review_note",
        "reviewed_by": None, "reviewed_at": None, "review_note": None,
    }
    row["content_sha256"] = content_fingerprint(row)
    return row


# --------------------------------------------------------------------------- reading the cache

def read_records(path: Path) -> list[dict]:
    records = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise CatalogBuildError(f"{path}:{number}: not valid JSON ({exc.msg}); re-fetch this CWE") from exc
    return records


def _cwe_number(path: Path) -> int:
    return int(path.name.split(".")[0].split("-")[1])


def build_catalog(raw_dir: Path, dictionary: Mapping[str, Any], config: CatalogConfig | None = None,
                  expected: Iterable[int] = EXPECTED_CWES, now: datetime | None = None,
                  previous: Mapping[str, Any] | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return (catalog, report). ``previous`` is an older catalog whose approvals may carry over."""
    config = config or CatalogConfig()
    raw_dir = Path(raw_dir)
    files = sorted(raw_dir.glob("CWE-*.jsonl"), key=_cwe_number) if raw_dir.is_dir() else []
    rows = []
    for path in files:
        cwe_id = cwe_key(_cwe_number(path))
        meta_path = path.with_name(path.name.replace(".jsonl", ".meta.json"))
        meta = None
        if meta_path.is_file():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise CatalogBuildError(f"{meta_path}: not valid JSON ({exc.msg})") from exc
        rows.append(build_row(cwe_id, read_records(path), meta, dictionary, config))

    carried, invalidated, dropped = _carry_over_approvals(rows, previous)
    expected_keys = [cwe_key(n) for n in expected]
    present = {row["id"] for row in rows}
    manifest = {}
    if (raw_dir / "MANIFEST.json").is_file():
        try:
            manifest = json.loads((raw_dir / "MANIFEST.json").read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            manifest = {}
    moment = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
    catalog = {
        "schema_version": SCHEMA_VERSION, "cvss_version": CVSS_VERSION,
        "generated": {"at_utc": moment, "script": "scripts/build_cwe_catalog.py",
                      "nvd_query_date_utc": manifest.get("query_date_utc"),
                      "mitre_catalog_version": dictionary.get("version"), "mitre_catalog_date": dictionary.get("date")},
        "config": asdict(config),
        "rows": rows,
    }
    report = {
        "rows": len(rows), "expected": len(expected_keys),
        "missing_data": [k for k in expected_keys if k not in present],
        "not_expected": sorted((k for k in present if k not in expected_keys), key=lambda k: int(k[4:])),
        "by_default_basis": dict(Counter(r["default_basis"] for r in rows)),
        "by_status": dict(Counter(r["status"] for r in rows)),
        "refused_by_mitre": [(r["id"], r["mitre"]["reason"]) for r in rows if r["status"] == STATUS_REFUSED],
        "needs_review_note": [r["id"] for r in rows if r["needs_review_note"]],
        "source_incomplete": [r["id"] for r in rows if r["status"] == STATUS_SOURCE_INCOMPLETE],
        "approvals_carried_over": carried, "approvals_invalidated": invalidated, "approved_rows_dropped": dropped,
    }
    return catalog, report


def _carry_over_approvals(rows: list[dict], previous: Mapping[str, Any] | None):
    """An approval belongs to the numbers that were approved: identical content keeps it, any change drops it to draft."""
    carried, invalidated, dropped = [], [], []
    if not previous:
        return carried, invalidated, dropped
    old = {r.get("id"): r for r in previous.get("rows") or []}
    new_ids = {r["id"] for r in rows}
    for row in rows:
        before = old.get(row["id"])
        if not before or before.get("status") != STATUS_APPROVED:
            continue
        if before.get("content_sha256") == row["content_sha256"] and row["status"] == STATUS_DRAFT:
            row.update(status=STATUS_APPROVED, reviewed_by=before.get("reviewed_by"),
                       reviewed_at=before.get("reviewed_at"), review_note=before.get("review_note"))
            carried.append(row["id"])
        else:
            row["previous_approval_invalidated"] = {
                "reviewed_by": before.get("reviewed_by"), "reviewed_at": before.get("reviewed_at"),
                "review_note": before.get("review_note"),
                "reason": "the numbers, flags or MITRE verdict changed since it was approved" if row["status"] == STATUS_DRAFT
                          else f"the row is now {row['status']}"}
            invalidated.append(row["id"])
    dropped.extend(r_id for r_id, r in old.items() if r.get("status") == STATUS_APPROVED and r_id not in new_ids)
    return carried, invalidated, dropped


# --------------------------------------------------------------------------- rendering

def render_yaml(catalog: Mapping[str, Any]) -> str:
    body = yaml.safe_dump(dict(catalog), sort_keys=False, allow_unicode=True, width=120, default_flow_style=False)
    return FILE_HEADER + body


def _pct(value: float | None) -> str:
    return "-" if value is None else f"{value * 100:.0f}%"


def render_review_doc(catalog: Mapping[str, Any], report: Mapping[str, Any]) -> str:
    rows = catalog["rows"]
    cfg = catalog["config"]
    gen = catalog["generated"]
    lines = [
        "# CWE catalog review", "",
        f"Generated {gen['at_utc']} from NVD data queried {gen.get('nvd_query_date_utc') or 'unknown'} and the MITRE CWE "
        f"catalog {gen.get('mitre_catalog_version')} ({gen.get('mitre_catalog_date')}).", "",
        "**These are statistics, not official values. A row is unusable until a person approves it.**", "",
        "## How to read this", "",
        f"- Sample: records where the CWE is the primary assignment (else primary+secondary), scored by "
        f"`{cfg['preferred_metric_source']}` when at least {cfg['min_preferred_records']} remain, newest {cfg['sample_cap']}.",
        f"- `stable_high`: High+Critical share >= {cfg['stable_high_threshold']:.0%}. `stable_low`: <= "
        f"{cfg['stable_low_threshold']:.0%}. `insufficient_data`: fewer than {cfg['min_sample']} records. Anything else is "
        "`ambiguous`: the CWE alone does not decide the rating.",
        "- The two thresholds are policy choices, not standards. They live in `CatalogConfig`.",
        "- `needs_review_note`: MITRE says ALLOWED_WITH_REVIEW, so approving the row requires a written note.", "",
        "## All rows", "",
        "| CWE | Name | Status | Basis | n | High+Crit | Modal | Ref. vector share | Flags |",
        "|---|---|---|---|---:|---:|---|---:|---|",
    ]
    for r in rows:
        lines.append(f"| {r['id']} | {(r['name'] or '-')[:46]} | {r['status']} | {r['default_basis']} | {r['sample_size']} | "
                     f"{_pct(r['high_critical_share'])} | {r['modal_rating'] or '-'} | {_pct(r['reference_vector_share'])} | "
                     f"{', '.join(r['flags']) or '-'} |")
    lines += ["", "## Rows by default_basis", ""]
    for basis in BASES:
        ids = [r["id"] for r in rows if r["default_basis"] == basis]
        meaning = {BASIS_STABLE_HIGH: "the CWE alone is a reasonable High/Critical default",
                   BASIS_STABLE_LOW: "the CWE alone is a reasonable Medium/Low default",
                   BASIS_AMBIGUOUS: "the CWE alone does not decide; evidence-based metrics are required",
                   BASIS_INSUFFICIENT: "not enough data; a human decision is needed"}[basis]
        lines.append(f"- **{basis}** ({len(ids)}): {', '.join(ids) or 'none'}. _{meaning}._")
    lines += ["", "## Refused by MITRE (never usable)", ""]
    lines += [f"- {cwe}: {reason}" for cwe, reason in report["refused_by_mitre"]] or ["- none"]
    lines += ["", "## Approving these rows requires a written note (MITRE: ALLOWED_WITH_REVIEW)", "",
              ", ".join(report["needs_review_note"]) or "none"]
    lines += ["", "## Data not cached yet", "",
              (", ".join(report["missing_data"]) or "none") + ("" if not report["missing_data"] else
               "\n\nFetch them with `python scripts/fetch_nvd_cwe_data.py` and rebuild this catalog.")]
    if report["source_incomplete"]:
        lines += ["", "## Incomplete downloads (rebuild after re-fetching)", "", ", ".join(report["source_incomplete"])]
    if report["approvals_invalidated"]:
        lines += ["", "## Approvals dropped because the data changed", "", ", ".join(report["approvals_invalidated"])]
    lines += ["", "## What a reviewer should check", "",
              "- Do the reference vector and the rating distribution look plausible for this weakness in a typical web app?",
              "- For `ambiguous` rows, accept that the CWE alone cannot give a rating; approving only records that you looked.",
              "- Rows flagged `unstable_over_time`, `low_vector_agreement` or `non_nvd_scores_used` deserve a closer look.",
              "- CVSS 4.0-only records are excluded (this catalog is CVSS 3.1).", "",
              "## Approving", "",
              "```",
              'python scripts/approve_cwe_rows.py --ids CWE-89 CWE-77 --reviewer "Your Name" --note "why"',
              "```", ""]
    return "\n".join(lines)
