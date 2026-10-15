# Context Collector V2

The Context Collector converts merged findings into bounded evidence packages
for later prioritization and security review. It is deterministic code, not an
LLM and not a RAG system.

## What it collects

For every merged finding it collects:

- a numbered source window around the canonical primary location **and each
  additional scanner's primary location**, with scanner/rule/finding IDs;
- every available scanner code-flow step, preserving scanner and rule origin;
- related scanner locations;
- the smallest enclosing Python function or class when Python syntax is valid;
- a SHA-256 digest of each source file. When a saved profiler artifact is
  supplied, the collector checks this against the profiler snapshot before
  releasing that file's context.

The collector uses all `source_findings`, not only the canonical finding, so
evidence contributed by another scanner is not discarded during merge.
In JSON schema 1.1, repeated windows and Python symbols appear once in
`shared_excerpts` and `shared_symbols`; evidence entries refer to them by ID.
The loader reconstructs the same in-memory evidence, including legacy 1.0
artifacts. This reduces artifact and eligible AI-prompt size without dropping
individual locations or provenance.
AI Discovery uses the compact representation only when its complete reference
table fits the configured prompt budget; otherwise it keeps the previous
bounded prompt. The Security Review Agent also receives additional scanners'
primary evidence explicitly.

## Safety and resource limits

The collector never executes target code. Paths must remain relative to the
selected project root. Symlinks are skipped by default, including symlinked
parent directories. Binary and non-UTF-8 files are skipped. Per-file and total
read limits are configurable, and repeated locations use an in-memory file
cache rather than reading the same file repeatedly.
The saved profiler inventory is the preferred path index. Standalone use
without a profile builds one bounded fallback index rather than searching the
tree again for every scanner path.

An unavailable secondary location makes the result `partial`; an unavailable
primary location is reported as a coverage gap. If every primary location is
unavailable, collection is `failed`. These states must not be treated as proof
that the project is safe.

Generated context may contain proprietary source code, so context artifacts
under `scans/context` are ignored by Git.

## Usage

After installing the project in editable mode:

```powershell
security-collect-context targets/target_app `
  scans/merged/target-app-20261002.merged.json `
  scans/context/target-app-20261002.context.json
```

For a profiled project, add `--profile reports/profile.json` so suffix
resolution uses the profiler inventory and changed source files are rejected.
The complete pipeline supplies its saved profile automatically and stops
before prioritization or AI review if source hashes changed.

Useful limits include `--window-before`, `--window-after`,
`--max-file-bytes`, `--max-total-bytes`, and `--max-symbol-lines`.

## Current limits

- Full enclosing-symbol extraction is currently implemented for Python.
- Other UTF-8 text languages receive reliable numbered windows but no claimed
  symbol name.
- It consumes scanner-provided flows; it does not invent missing call graphs.
- Semantic retrieval and embeddings are intentionally outside this stage.
