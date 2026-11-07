# AI Discovery Agent

AI Discovery is a required, bounded stage in every complete pipeline scan after risk prioritization. It produces candidate findings for areas that need more reasoning; it does not replace scanners, verification, or the final security review. A standalone scanner command is a diagnostic stage, not a completed pipeline scan.

## What it now inspects

The target planner is deterministic; the model does not decide which files it
may read. It balances high-risk merged findings with exploratory targets, even
when high-risk findings exist:

- source files whose scanner results have no primary finding;
- explicit coverage gaps that mention a known source path;
- security-relevant functions/windows with input, authorization, or sensitive
  sink signals but no scanner primary finding inside the window.

The profiler inventory and saved source hashes are used when available. A
changed or unreadable file is skipped and reported, not passed silently to
the model. Unlocalized coverage gaps are supplied as background evidence; the
planner does not pretend to know which file caused them. Target selection has
file, byte, overall planning, batch, candidate, and prompt-size budgets.
`--ai-max-targets` is the **per-batch** size, not a total run cutoff. Discovery
continues through planned targets until finished or an explicit limit/error is
reached. `batches` records each batch's targets, calls, prompt characters,
candidates, context requests, and provider usage. `usage` totals these values.
Token counts and duration are recorded when supplied by the provider. A USD
cost estimate is calculated only when both token rates are explicitly supplied
by the caller; local compute cost is not included. `target_plan`, `scope`, and
`coverage_gaps` show what was actually sent and what remained outside scope.
Prompts remain valid JSON rather than being cut in the middle.

Only snippets from selected source windows are sent initially, with basic
secret redaction. The model may ask for additional Python functions by name or
specific line windows. A read-only context broker resolves those requests
against the profiled source inventory and snapshot hashes, without executing
project code or accessing arbitrary paths. It limits bytes, lines, characters,
requests, and enrichment rounds. `context_exchanges` shows collected, rejected,
and unavailable requests. Symbol lookup currently supports Python;
line-window requests also support the other source suffixes in scope.

Each candidate should supply a grounded entry point, sensitive operation,
location where a security check appears missing, and remaining questions.
The discovery-stage check confirms that cited files, lines, and code anchors
exist in inspected context. Missing or inconsistent anchors produce an
`inconclusive` candidate and cannot become `confirmed` merely through the
deterministic Verification stage. **Neither stage proves that a check is absent
or that a finding is exploitable**; the Security Review Agent must assess that.

## What the model receives (and how to see it in LangSmith)

Every target sent to the model carries real source: exploratory targets carry their source window, and
`risk_finding` targets carry the code around the flagged line in addition to the merged scanner excerpt. The prompt
lists `targets` first and the merge-derived `known_findings` / `coverage_gaps` last (capped to 15% of the prompt), so
the code is visible even when LangSmith cuts a string at 4,000 characters (`SECURITY_REVIEWER_TRACE_CONTENT=redacted`).
Each `discovery-model-call` span also has a `summary` input (visible in the default `metadata` mode) listing, per
target, its kind, path, line range and the number of code characters sent. Use `--ai-max-files` and
`--ai-max-context-chars` to widen coverage of large repositories (together with `--ai-max-planned-targets` and
`--ai-max-batches`).

## Provider failures during discovery

A failure that happens *before* the request is sent (DNS, TLS, connection refused) is an outage and stops discovery at
once. A response that is **lost after the request was sent** (`connection_closed`, read `timeout`: typical for a long
generation by a large reasoning model) is retried: the batch is halved, the other targets go back to the queue, and
nothing is marked inspected until a call succeeds. Two such failures in a row are tolerated; the third stops discovery as
an outage, and any successful call resets the count. Each retry is recorded as a warning on the run. If lost responses
keep happening, shorten the generation with `GROQ_REASONING_EFFORT=low` or lower `--ai-max-context-chars`.

## Safety defaults

- The full pipeline always runs Discovery; `--ai-discovery` is accepted only for compatibility and cannot disable it.
- Groq with `openai/gpt-oss-120b` is the default. Set `GROQ_API_KEY` in the process environment through your secrets workflow before running a full scan. Do not place a key in arguments, project files, or reports. You can explicitly select local Ollama instead.
- Missing provider configuration stops the run before scanning. If provider calls fail or planned targets are not fully inspected, the saved report is marked incomplete and the command exits nonzero. Zero candidates is valid when all planned targets were inspected.
- Repository text is treated as untrusted data.
- The provider receives a bounded context window and a fixed candidate budget.
- Candidate paths, line numbers, and structured anchors are checked locally before they are marked `supported`.
- Repository snippets are sent to the selected provider. Select Ollama when the source must stay local; a Groq scan sends bounded source context to Groq.

## Example

```powershell
ollama pull qwen2.5-coder:7b
& .\.venv\Scripts\python.exe scripts\run_project_pipeline.py `
  targets\verdict-comprehensive-lab `
  --output reports\comprehensive-static-ai `
  --static-only `
  --codeql-bundle 'C:\path\to\codeql' `
  --ai-provider ollama --ai-model qwen2.5-coder:7b `
  --ai-max-targets 10 --ai-max-batches 20 --ai-max-candidates 20
```

The output is `ai-discovery.json`. The pre-review summary records whether the required stage was satisfied, provider calls, planned/inspected targets, failures, warnings, and coverage gaps; it does not treat a candidate as a confirmed vulnerability.

## Candidate context after Discovery

The pipeline now writes `candidate-context.json` after `ai-discovery.json`.
This is a separate, deterministic context package for **every** AI candidate,
including inconclusive ones. It collects a bounded window and, for Python,
the enclosing function around the candidate's primary location, entry point,
sensitive operation, claimed missing-check location, and end of a longer cited
range. It reuses the scanner Context Collector's file-size, total-byte,
symlink, source-hash, and read-only safeguards. AI paths must match the source
inventory exactly; unlike scanner paths, they are not guessed by suffix.
Repeated excerpts/symbols are stored once and referenced by ID in the JSON.
Best-effort secret redaction applies to collected source text, but it is not a
guarantee that arbitrary secrets are removed.

For an already saved Discovery result, no model or scanner run is needed:

```powershell
.venv\Scripts\python.exe -m security_reviewer_v2.context.candidate_cli `
  targets\security-lab-web `
  reports\stepwise-security-lab-web\discovery\groq-120b-combined-20261007.json `
  reports\stepwise-security-lab-web\discovery\candidate-context.json `
  --profile reports\stepwise-security-lab-web\profile.json
```

`complete` means all cited context locations were collected, `partial` means
some evidence or upstream Discovery coverage is missing, and `failed` means
none could be collected. Warnings and coverage gaps retain the reason. This
step does **not** prove a data flow, a missing security check, exploitability,
or candidate novelty; Verification, candidate triage, and security review have
those separate responsibilities. The Security Review Agent can consume this
package instead of re-reading candidate source lines when the full pipeline
runs. Verification then checks the source grounding, candidate triage groups
conservative overlaps, and the Security Review Agent reviews every eligible
issue group in bounded batches. Candidates still needing evidence remain
visible in the triage artifact and report; they are not security verdicts.

## Prompt packing, status and timing

- **Status.** `completed` means every planned target was inspected without a coverage loss. Only Discovery's own losses
  (uninspected targets, failed batches, truncated source, omitted candidates, unavailable context) make it `partial`.
  Caveats from other pipeline stages guide targeting but are not Discovery gaps. Trimmed duplicate hints and unresolved
  symbol guesses are reported as warnings.
- **Packing.** Blank source files are skipped. Lines that two targets in the same prompt share are sent once
  (`code_shared_with` names the target that carries them). A target that does not fit is deferred whole to the next batch;
  only a batch's first target is ever shrunk, and only if dropping reference data was not enough.
- **Duplicate hints.** Known findings in the inspected files are kept first when the list is trimmed.
- **Context requests.** A symbol requested from the wrong file is resolved when it has exactly one definition elsewhere
  in the inventory; ambiguous or missing symbols are never guessed.
- **Timing.** `usage.wall_seconds`, `usage.rate_limit_wait_seconds`, `usage.retry_count` and `usage.provider_calls`
  show how much of a run was provider rate-limit waiting rather than model time.
- **Coverage of endpoints.** A scanner-flagged file used to contribute at most three explicit hotspot targets, so most
  route handlers were only seen incidentally inside other targets' windows. Every route/function hotspot is now reviewed
  explicitly (`--ai-max-hotspots-per-file`, default 100; config `max_hotspots_per_file`). Equal scores are ordered
  state-changing handlers first, with a bump for upload/session/cookie/token/reset/webhook/redirect/login handlers, so
  if a planning or batch limit is hit the likelier-vulnerable handlers go first and the report states what was skipped.
  Full coverage costs more tokens (about twice the prompt volume on the lab project) and therefore more rate-limit time;
  lower the option for a faster, shallower run.
- **Reproducibility.** `GROQ_SEED=<int>` (opt-in, best effort) is sent as the request `seed`, so repeated runs of the same
  prompt are more alike. Model output can still vary between runs; compare several runs before concluding that a
  finding was lost.
- **Static only, and duplicates.** Discovery reads source and never runs the application, so every candidate carries
  `analysis: "static_source_review"`; dynamic corroboration is added later by triage only when a probe hit the same route.
  Candidates that state the same root cause (same sensitive operation and same missing-check location, or the same
  category when one side names no missing check) are merged into the strongest one at the end of the run. The merged ids
  stay in `duplicate_ids`, `usage.duplicate_candidates_merged` and a warning, so nothing disappears silently.
