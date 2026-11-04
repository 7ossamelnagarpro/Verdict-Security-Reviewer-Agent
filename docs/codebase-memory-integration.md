# Default codebase-memory-mcp indexing

Verdict runs a local codebase index after the static scanner stage by default.
It is not a new vulnerability scanner. The index can corroborate routes in the separate
[Application Map](application-map.md). When indexing succeeds, the pre-review
pipeline passes bounded graph-route evidence to that map, which supplies only
validated, source-matched hints to discovery. Graph nodes are not findings and
do not directly change the release decision.

Install a trusted `codebase-memory-mcp` binary separately and make it available
on `PATH`. Full and static pipeline runs invoke it by default. Use
`--no-codebase-memory` only when an explicit opt-out is needed; Verdict does not
download or install the tool.
The upstream repository publishes an [MIT license](https://github.com/DeusData/codebase-memory-mcp/blob/main/LICENSE).

The run writes `codebase-intelligence.json` in the report directory. It records
the project snapshot fingerprint, tool version when available, indexing status,
and node/edge counts or index path only if the tool prints them. If the binary
is missing, times out, or exits with an error, the artifact says so and the
security review continues with an explicit Codebase Memory coverage gap. No graph
nodes are converted to findings.

The graph/database belongs to the external tool, normally under its local
cache (`~/.cache/codebase-memory-mcp`, or `CBM_CACHE_DIR` if configured). The
exact database path is reported only when returned by the CLI. CLI indexing
is one-shot: rerun indexing after changing the source. Keep the external cache
private because it may contain source-derived information; do not commit it.
Verdict explicitly passes `--persistence false` so this option does not ask
the tool to create a shareable graph artifact inside the scanned project.

The upstream tool's [README](https://github.com/DeusData/codebase-memory-mcp)
and [configuration reference](https://github.com/DeusData/codebase-memory-mcp/blob/main/docs/CONFIGURATION.md)
are the source of truth for its release-specific language coverage, ignored
files, cache behavior, and installation instructions. Verdict does not claim
that every source, documentation, Compose, or CI file was indexed merely
because the CLI exited successfully. That coverage needs a later, explicit
inventory check before the Application Map stage is considered complete.

## Current integration checkpoint

The `verdict-comprehensive-lab` index was rebuilt with `codebase-memory-mcp
0.12.1` on 2026-11-01. It contained 263 nodes and 860 edges, with zero files
left unindexed and zero partial or unusable parses. The bounded Route query
returned 71 graph routes. Route reads are paginated and deduplicated (50 rows
per page, with a bounded ten-page limit), so a `has_more` response is not
silently truncated. The Application Map corroborated 70 source routes and
retained one unmatched graph route for review; this is an evidence gap, not a
security finding.

## Baseline and evaluation

The saved comprehensive-lab evaluation from 2026-11-01 reports 21/35
known-positive cases detected (a 60% conservative lower bound), 8 cases with
no exact signal, and 6 needing review. The index itself is not credited with
improving those numbers. The next acceptance criterion is a fresh discovery
and evaluation run that measures whether the Application Map changes recall
and evidence completeness.
