# Verdict Security Reviewer — Architecture

Status: current repository architecture reference

Last reviewed: 2026-11-02

This document describes the architecture that is implemented in the repository
today. It is a design reference, not a promise that every optional runtime
capability is complete. The authoritative engineering rules remain in the
repository `AGENTS.md`.

## 1. Purpose and scope

Verdict is a local, pre-deployment security review system. It combines
deterministic static scanners, bounded runtime checks, source-context analysis,
AI-assisted discovery and review, conservative finding correlation, a policy
gate, and auditable reports.

The system is designed to answer three separate questions:

1. What signals did the scanners and runtime checks produce?
2. How did the Review Agent assess the correlated evidence?
3. Does the configured release policy allow, warn, or block release?

A signal, an AI assessment, and a policy decision are not interchangeable. A
completed scan is not proof that the application is vulnerability-free, and a
blocked release is not the same as a failed scan.

The default deployment is local and single-user. The local web UI is intended
for localhost use and is not a public multi-tenant service. Reports and
credentials are kept outside the scanned project where the runtime contract
requires it.

## 2. Architectural constraints and decisions

The following decisions are treated as current project constraints:

- The pipeline is bounded, evidence-first, and auditable.
- Static scanners, runtime tools, deterministic processing, and AI components
  remain separate responsibilities.
- Scanner silence is never interpreted as proof of safety.
- Discovery Agent output is a candidate or test proposal, not proof of an
  exploitable vulnerability.
- Review Agent verdicts are model assessments grounded in saved evidence. They
  are not independent exploit confirmation.
- Finding groups preserve their original observations and source IDs.
- Coverage gaps remain visible in reports; they are not silently converted into
  passes.
- Runtime access requires an explicitly authorized local URL or a reviewed,
  trusted disposable Docker Compose contract.
- Mutating workflows are bounded and allowed only for an explicitly trusted
  disposable target with declared cleanup behavior.
- Credentials are not written into project artifacts or exported contracts;
  local UI credentials use the OS vault.
- Codebase Memory is local supporting evidence, not a vulnerability scanner.
  Its graph nodes are not findings and do not directly change policy decisions.
- LangGraph coordinates the AI review workflow. Scanner execution and final
  report generation remain outside the LangGraph graphs.
- LangSmith tracing is optional observability and does not replace the local
  evaluation report.
- The repository does not add microservices, queues, or distributed
  infrastructure for ordinary local scans.

## 3. Runtime and repository boundaries

The repository is organized into these major areas:

| Area | Responsibility |
| --- | --- |
| `src/security_reviewer_v2/profiler` | Project inventory, language/dependency detection, and scan planning. |
| `src/security_reviewer_v2/scanners` | Scanner configurations, adapters, command plans, and scanner models. |
| `src/security_reviewer_v2/orchestrator` | Bounded subprocess execution, checkpoints, task status, and scanner orchestration. |
| `src/security_reviewer_v2/codebase_intelligence.py` | Optional/local Codebase Memory indexing and route evidence import. Enabled by default in the full pipeline, with an explicit opt-out. |
| `src/security_reviewer_v2/application_map.py` | Source-backed route and entry-point map, including bounded graph corroboration. |
| `src/security_reviewer_v2/context` | Bounded source context and candidate evidence collection. |
| `src/security_reviewer_v2/discovery` | Discovery Agent, scope planning, candidate validation, enrichment, and discovery test-plan generation. |
| `src/security_reviewer_v2/normalization` | Conversion of scanner/runtime output into the common finding schema and conservative merge/deduplication. |
| `src/security_reviewer_v2/prioritization` | Risk-based ordering; it does not remove findings or prove them. |
| `src/security_reviewer_v2/verification` and `src/security_reviewer_v2/triage` | Citation/source validation and evidence-gated candidate triage. |
| `src/security_reviewer_v2/reviewers` | Review Agent batching, evidence review, retries, and verdict serialization. |
| `src/security_reviewer_v2/policy` | Release policy decisions (`allow`, `warn`, `block`). |
| `src/security_reviewer_v2/agent_graph.py` | Outer LangGraph for Discovery, evidence processing, review, and policy. |
| `src/security_reviewer_v2/reporting` | Markdown/HTML report data and rendering, provenance, summaries, and evidence traces. |
| `src/security_reviewer_v2/web` | Local Flask/Waitress workspace, contracts, credentials, runtime controls, and report views. |
| `scripts` | User-facing pipeline, runtime, evaluation, report, installation, and maintenance entry points. |
| `targets` | Educational/disposable applications used for authorized local testing. |
| `benchmark` | Held-out scenarios and ground truth used only by evaluation commands. |
| `tests` | Unit, contract, integration-boundary, and behavior tests. |
| `docs` | Operational, architecture, contract, roadmap, and evaluation documentation. |

## 4. End-to-end pipeline

The full entry point is `scripts/run_pre_review_pipeline.py`. Its current
logical flow is:

```text
Readiness and preflight
  -> runtime setup or trusted runtime-evidence import
  -> project profile and scan plan
  -> static scanner execution
  -> Codebase Memory indexing
  -> source Application Map
  -> Discovery Agent
  -> approved/declared runtime plan and bounded DAST evidence
  -> normalization
  -> merge and deduplication
  -> bounded source context
  -> risk prioritization
  -> LangGraph evidence/review/policy workflow
  -> final Markdown/HTML report
  -> optional separate benchmark evaluation
```

The repository README documents the detailed numbered stages. The important
boundary is that scanners and runtime tools produce evidence before the AI
review graph; the report is generated after policy evaluation; evaluation is a
separate comparison against held-out labels.

### 4.1 Readiness and runtime safety

The entry point validates the project, output directory, AI provider, scanner
adapters, and any CodeQL bundle before a full scan. A runtime URL must be
explicit and loopback-authorized, or the caller must import a completed trusted
Docker/runtime artifact. A Compose file found inside a project does not by
itself authorize execution.

Runtime checks are bounded. The generic contract supports health and declared
GET probes, headers/cookies, optional browser crawling, ZAP evidence, and an
explicit workflow suite. Write steps and two-account checks are only accepted
within the declared trusted disposable boundary.

### 4.2 Static scanner layer

The automatic required scanner set is:

- Semgrep CE for local code rules and data-flow patterns.
- CodeQL CLI for supported source-language analysis.
- Gitleaks for secrets.
- Trivy for filesystem/dependency/configuration findings where supported.

Each scanner is invoked through an adapter and the `ScannerOrchestrator`.
Commands use argument vectors, bounded timeouts, isolated output directories,
redacted logs, and explicit terminal statuses. Normalizers convert supported
outputs into the common finding model while retaining scanner identity and
source location.

### 4.3 Codebase Memory and Application Map

Codebase Memory is a local structural index that can provide bounded route and
source relationships to the Application Map and Discovery Agent. It is not an
additional scanner and its graph is not counted as a vulnerability source.
The project documentation records the current integration checkpoint and the
known limits of the external tool. Index data remains in the tool's local
cache and is not committed to the repository.

The Application Map combines source declarations with validated graph hints.
Unmatched or incomplete routes are retained as evidence gaps rather than being
silently discarded.

### 4.4 LangGraph agents

The outer graph in `agent_graph.py` has these nodes:

```text
START
  -> ai_discovery
  -> candidate_context
  -> verification
  -> candidate_triage
  -> security_review OR skipped_review
  -> policy_gate
  -> END
```

If Discovery is unavailable or incomplete, the graph records the missing state
and does not present an incomplete review as complete. The Review Agent is
therefore downstream of evidence collection and candidate triage.

The Discovery Agent has its own bounded graph in
`discovery/agent.py`: it plans scope, prepares batches, calls the configured
provider, assesses candidates, optionally requests bounded context, and
finishes within configured batch/enrichment limits.

AI output is treated as untrusted data. Source anchors and citations are
validated before candidates can influence review. Provider failures, malformed
responses, missing context, and incomplete batches remain explicit in the
artifacts.

### 4.5 Finding model, policy, and reports

Normalization and merge/deduplication create issue groups from related scanner,
runtime, and agent observations. A group can contain multiple observations; a
group count must not be added to a raw observation count.

The Review Agent assigns evidence-based dispositions such as Confirmed, Likely,
False Positive, or Needs More Evidence. The policy gate then applies configured
release rules. The final report separates:

- original scanner/runtime observations;
- merged issue groups and their evidence;
- Review Agent assessments;
- policy decisions;
- coverage gaps and limitations.

The report is generated from saved artifacts by `reporting/final.py` and the
HTML renderer. It is not the benchmark ground truth.

## 5. Interfaces and artifacts

Important interfaces are file-based and typed:

- `CommandSpec` and execution models between scanner adapters and the
  orchestrator.
- Scanner JSON/SARIF outputs into normalizers.
- Common normalized finding models into merge, context, prioritization, and
  review.
- Runtime Contract JSON into bounded runtime checks.
- `codebase-intelligence.json`, `application-map.json`, and discovery artifacts
  into the agent graph.
- `security-review.json` and `policy-gate.json` into final reporting.
- `pre-review-summary.json`, Markdown, HTML, and evaluation artifacts as the
  saved run boundary.

Reports are written to the selected output directory, normally outside the
target project. Credentials, tokens, and raw sensitive response values must
not be placed in these artifacts.

## 6. Technology choices

- Python 3.11+ is the implementation language.
- Flask and Waitress provide the localhost workspace.
- LangGraph provides explicit, bounded state-machine orchestration for the AI
  stages.
- Semgrep, CodeQL, Gitleaks, and Trivy are external scanner tools behind
  adapters, not imported into core business logic.
- Docker Compose provides disposable educational runtime stacks when explicitly
  trusted.
- Playwright and ZAP are optional runtime coverage engines; their evidence is
  imported through bounded adapters and is not assumed to be available on every
  host.
- LangSmith is optional tracing/observability for agent calls.
- Pytest and Ruff are the configured development validation tools.

Existing dependencies should be reused. New dependencies require a documented
need and compatibility review.

## 7. Security and reliability boundaries

- Never hardcode or print credentials and API keys.
- Keep scanner commands shell-free and validate trusted executable paths.
- Treat target source, runtime responses, benchmark files, and LLM responses as
  untrusted input.
- Use disposable stacks and declared limits for mutating checks.
- Preserve raw observations and provenance so a model verdict can be audited.
- Fail closed for missing required scanners, required Discovery, pending review,
  or invalid runtime evidence.
- Report unavailable tools and untested areas explicitly.

## 8. Non-goals and known limitations

Verdict does not claim universal vulnerability detection, generic exploit
confirmation, unrestricted browser automation, arbitrary OAuth/MFA workflows,
race testing, GraphQL/WebSocket coverage, or a production isolation boundary.
Benchmark scores are meaningful only when the corresponding ground-truth
scope and denominators are present.

Changes to these boundaries, the pipeline order, or policy semantics require an
explicit architectural decision and an update to this document and the
implementation plan.
