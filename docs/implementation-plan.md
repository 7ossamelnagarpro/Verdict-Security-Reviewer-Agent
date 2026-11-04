# Verdict Security Reviewer — Implementation Plan

Status: implementation roadmap for the current repository

Last reviewed: 2026-11-02

This plan is based on the implementation currently present in the repository.
It separates completed work from remaining work and gives each future change a
testable acceptance boundary. It does not authorize changing the approved
pipeline order or policy behavior by itself.

## 1. Current baseline

The repository currently has:

- A local Flask/Waitress workspace and CLI pipeline entry points.
- A profiler and scanner plan with adapters for Semgrep, CodeQL, Gitleaks, and
  Trivy.
- Bounded subprocess execution, checkpoints, redacted logs, and required
  scanner preflight.
- Normalization, conservative finding merge/deduplication, context collection,
  risk prioritization, verification, triage, policy, and Markdown/HTML reports.
- A local Codebase Memory integration enabled by default in the full pipeline,
  with an explicit `--no-codebase-memory` opt-out.
- A source-backed Application Map and bounded Discovery Agent enrichment.
- A LangGraph outer review graph plus dedicated Discovery and Review Agent
  graphs.
- Runtime Contract support, disposable Docker targets, bounded DAST, optional
  ZAP/browser coverage, and declarative business workflows.
- Separate benchmark/evaluation scripts and target fixtures.
- Unit and contract tests covering the major deterministic boundaries.

The current implementation is substantial, but runtime coverage and evaluation
quality still depend on the selected target, installed tools, saved evidence,
and explicit runtime contract. A scan can therefore be complete while its
coverage remains narrower than the full application behavior.

## 2. Milestone status

| Milestone | Status | Evidence / next action |
| --- | --- | --- |
| Repository rules and baseline tests | Complete | `AGENTS.md`, `pyproject.toml`, pytest/Ruff configuration, and the existing test suite. |
| Scanner adapter/orchestrator foundation | Complete | Required scanner preflight, bounded commands, normalized outputs, and execution checkpoints. |
| Local Semgrep execution hardening | In progress | The local rule test now uses bounded process-tree cleanup and is included in the full suite; native Windows Semgrep remains slow and needs a separate performance improvement. |
| Codebase Memory integration | Implemented | `codebase_intelligence.py` and `docs/codebase-memory-integration.md`; paginated Route reads are deduplicated and bounded; keep measuring source/index coverage. |
| Application Map | Implemented with a known gap | Route evidence is merged conservatively; unmatched routes remain visible for review. |
| Discovery Agent | Implemented, bounded | LangGraph batches and enrichment work; data-flow and account extraction remain incomplete in some targets. |
| Discovery test-plan generation | Implemented, partially executable | Plans and approved read-only probes exist; write/role tests still require explicit workflow contracts. |
| Browser crawl | Implemented as optional bounded coverage | Same-origin discovery and evidence capture are supported; Playwright availability and form-action limits remain explicit. |
| DAST and ZAP integration | Implemented where runtime/tool prerequisites exist | Coverage is target/contract dependent and must be represented in saved evidence. |
| Business workflows | Implemented for declared contracts | Workflow steps, account verification, assertions, and cleanup are bounded; generic business-rule inference is not automatic. |
| Review Agent and policy gate | Implemented | Evidence review and release decisions are separated; pending groups remain visible. |
| Report shape and evidence trace | Implemented | Markdown/HTML report is generated from saved artifacts; continue improving scenario/output evidence. |
| Evaluation | Implemented as a separate command | Recall-style mapping exists; Precision and false-positive metrics require independently reviewed safe controls and denominators. |

## 3. Next milestones

### Milestone A — Stabilize local scanner execution

Objective: make required scanner tests and runs deterministic on supported
Windows/Linux environments.

Work:

- Keep scanner subprocesses bounded and terminate descendants on timeout.
- Document Semgrep native-Windows startup cost and avoid tests that leave child
  processes or open pipes.
- Keep scanner version pins and preflight diagnostics visible.
- Record duration, status, and stderr paths in execution artifacts.

Current progress: the previously excluded local Semgrep rules test now runs
through the project's process-tree-aware runner, so a timeout cannot leave
Semgrep descendants or open output pipes behind. The full suite includes this
test again. The remaining work is reducing the roughly 90-second native
Windows startup/scan cost, not restoring correctness of the rules.

Acceptance criteria:

- Required scanner preflight reports actionable missing/unavailable adapters.
- Scanner timeout tests leave no child processes.
- The full pytest suite passes without excluding the local Semgrep behavior
  test.
- Ruff passes on changed Python files.

### Milestone B — Complete Codebase Memory and Application Map evidence

Objective: improve source structure and route evidence without turning the graph
into a finding source.

Work:

- Keep indexing enabled by default and preserve explicit opt-out behavior.
- Record tool version, snapshot fingerprint, node/edge counts, and failure state.
- Compare source-declared routes with graph routes and retain unmatched routes.
- Read paginated graph responses without silently dropping routes; retain an
  explicit partial status when the bounded page limit is reached.
- Add bounded checks for ignored/unparsed files and route provenance.

Acceptance criteria:

- The artifact distinguishes successful indexing from incomplete coverage.
- Every Application Map entry has a source location or an explicit unknown.
- Graph evidence does not directly create findings or policy blocks.
- Tests cover missing tool, timeout, stale snapshot, and unmatched-route cases.

### Milestone C — Enrich Discovery Agent safely

Objective: find high-value review targets that static scanners do not describe
well, while keeping the agent bounded and auditable.

Work:

- Feed validated Application Map, frontend calls, scanner locations, and
  bounded source context into Discovery prompts.
- Improve candidate extraction for roles, accounts, state-changing routes,
  object ownership, and sensitive parameters.
- Preserve prompt budgets, batch limits, enrichment limits, and provider error
  handling.
- Store candidate citations, missing checks, and coverage accounting.

Acceptance criteria:

- Every candidate has a source anchor or is explicitly marked unsupported.
- Unsupported/uncited candidates cannot silently become review findings.
- Discovery status accurately distinguishes completed, partial, and failed.
- A held-out fixture measures candidate coverage without using its ground truth
  during the scan.

### Milestone D — Convert approved discovery into runtime tests

Objective: close the gap between “the agent suggested this” and “the runtime
actually tested this.”

Work:

- Validate approved plans against the current project fingerprint and source
  declarations.
- Generate only bounded, safe GET probes automatically.
- Keep role, account, write, and expected authorization behavior in explicit
  Runtime Contract workflow rules.
- Record each proposal, approval, execution status, request shape, response
  status, and cleanup result.

Acceptance criteria:

- No unapproved write operation is generated or executed.
- Approved probes appear in `approved-discovery-probes.json` with provenance.
- Invalid/stale plans are rejected with a clear coverage gap.
- Tests cover plan approval, fingerprint mismatch, and bounded probe limits.

### Milestone E — Expand browser and DAST coverage

Objective: discover and test behavior that source scanners cannot observe.

Work:

- Make Playwright availability a clear preflight result.
- Capture same-origin pages, links, forms, and API calls without storing secrets
  or response bodies unnecessarily.
- Add target-specific authenticated crawling only through explicit contracts.
- Keep ZAP baseline/active modes separate and label alerts as tool signals.
- Correlate browser/ZAP evidence with endpoints and issue groups.

Acceptance criteria:

- Browser/ZAP status is never reported as complete when the engine was absent or
  failed.
- Browser evidence identifies method, path, status, and provenance.
- Active/mutating modes require disposable-target authorization.
- Tests cover missing Playwright, same-origin limits, timeout, and cleanup.

### Milestone F — Strengthen business workflows and evidence

Objective: provide the mentor-requested scenario and output evidence for each
workflow finding.

Work:

- Store a redacted scenario summary: account/role, ordered steps, method/path,
  captures, expected result, observed status/assertion outcome, and violation.
- Preserve safe request/response metadata while excluding passwords, tokens,
  raw capture values, and sensitive bodies.
- Add explicit ownership, privilege, session, and state-transition suites to
  the disposable comprehensive lab.
- Ensure fresh-stack cleanup and independent workflow data.

Acceptance criteria:

- Each workflow observation links to its scenario and output artifact.
- A violation is clearly distinguished from proof of exploitability.
- Account identity is verified before role-based assertions are accepted.
- Tests cover setup failure, login failure, assertion failure, and cleanup.

### Milestone G — Improve Review Agent and reporting

Objective: make evidence interpretation understandable without conflating
signals, groups, verdicts, and policy decisions.

Work:

- Show source type (static, DAST, workflow, ZAP, browser, or agent) on each
  observation/group.
- Include scenario/evidence trace links where available.
- Keep Review Agent verdict counts separate from raw observations and policy
  blocks.
- Preserve coverage gaps and pending groups in both Markdown and HTML.

Acceptance criteria:

- Reports remain accurate when one issue has multiple observations.
- A reviewer can trace a verdict back to scanner/runtime evidence and source
  context.
- Report tests assert labels, counts, ordering, and omitted sections.
- HTML and Markdown are generated from the same saved data model.

### Milestone H — Evaluation and release readiness

Objective: measure improvements rather than equating more findings with better
security.

Work:

- Keep ground truth outside scanner and agent inputs.
- Calculate recall, precision, false-positive rate, route/workflow/role
  coverage, evidence completeness, and source-context completeness only when
  denominators are valid.
- Compare baseline and new runs by target and pipeline configuration.
- Produce a separate detailed evaluation artifact and summary.

Acceptance criteria:

- Every metric states its numerator, denominator, scope, and limitations.
- Known positives, safe controls, and unmatched findings are separately listed.
- A failed or partial runtime stage cannot be presented as full coverage.
- Evaluation tests catch stale labels and removed report headings.

## 4. Validation strategy

For each milestone:

1. Add or update behavior-oriented pytest tests.
2. Run the focused tests for the changed boundary.
3. Run Ruff on changed Python files.
4. Run the full test suite before declaring the milestone complete.
5. Run a disposable target scan when runtime behavior changed.
6. Review saved artifacts for secrets, provenance, status, and coverage gaps.
7. Record the result and remaining limitations in the relevant documentation.

No metric is considered improved solely because the number of findings
increased. A useful improvement must preserve evidence quality and show a
measurable effect on the relevant evaluation denominator.

## 5. Risks and mitigations

| Risk | Mitigation |
| --- | --- |
| External scanner unavailable or slow | Preflight, bounded execution, descendant cleanup, explicit status, and preserved logs. |
| AI hallucination or unsupported candidate | Source anchors, verification, bounded context, and evidence-gated triage. |
| Runtime mutation changes test data | Disposable Compose stack, declared workflow rules, fresh data, and cleanup verification. |
| Duplicate observations inflate counts | Stable source IDs, conservative merge keys, and separate observation/group counts. |
| Partial browser/ZAP coverage appears complete | Engine preflight and explicit runtime coverage artifacts. |
| Ground truth leaks into scans | Keep benchmark inputs in evaluation commands and outside target/pipeline inputs. |
| Report redesign breaks saved artifacts | Test the shared report model and keep Markdown/HTML renderers aligned. |

## 6. Decisions requiring approval before implementation

The following changes need explicit approval before coding:

- Reordering, adding, removing, or merging approved pipeline stages.
- Changing policy thresholds or the meaning of `confirmed`, `likely`, or
  `block`.
- Enabling new mutating runtime behavior for a target that is not explicitly
  disposable and authorized.
- Adding a new external dependency or scanner.
- Sending source, findings, credentials, or runtime data to an external AI or
  tracing provider.
- Changing the report contract in a way that breaks saved reports or evaluation
  consumers.

## 7. Definition of done

A milestone is complete only when its implementation, tests, documentation,
artifact/provenance behavior, and limitations are all reviewed. The final
project state should make it possible to answer, for every reported item:

- what produced the original signal;
- what scenario or source evidence supports it;
- what the Review Agent assessed;
- what policy decision followed; and
- what the pipeline did not test.
