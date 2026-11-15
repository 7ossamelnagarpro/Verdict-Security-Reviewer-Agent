<p align="center">
  <img src="assets/banner.svg" alt="Verdict: Security Reviewer Agent" width="100%">
</p>

<p align="center">
  <img alt="stage" src="https://img.shields.io/badge/stage-in%20development-2F6BFF?style=for-the-badge">
  <img alt="llm-agents" src="https://img.shields.io/badge/LLM%20agents-2-7A4DFF?style=for-the-badge">
  <img alt="testing-agent" src="https://img.shields.io/badge/testing%20agent-rule--based%20%2B%20optional%20AI%20planner-00A3A3?style=for-the-badge">
  <img alt="artifacts" src="https://img.shields.io/badge/artifacts-JSON%20%2B%20Markdown%20%2B%20HTML-FFB020?style=for-the-badge">
  <img alt="track" src="https://img.shields.io/badge/track-Data%20Science%20%26%20AI%20Agents-1E9E5A?style=for-the-badge">
</p>

<p align="center">
  <a href="#-overview">Overview</a> ·
  <a href="#-run-the-local-workspace">Run</a> ·
  <a href="#-the-problem">Problem</a> ·
  <a href="#-whats-different">What's different</a> ·
  <a href="#-pipeline">Pipeline</a> ·
  <a href="#-autonomous-penetration-testing-agent">Penetration Agent</a> ·
  <a href="#-coverage-map">Coverage</a> ·
  <a href="#-evaluation-plan">Evaluation</a>
</p>

---

## 🛡️ Overview

**Verdict** is a pre-deployment security review pipeline. For its trusted Security Lab Web fixture, it runs bounded DAST in a temporary Docker Compose stack, removes the stack, then runs four scanners, an **AI code-graph-aware Discovery stage**, an **Autonomous Penetration Testing Agent**, and an **AI Security Review** stage. Other local projects can use an authorized loopback Runtime Contract. Developers may explicitly approve their own trusted Compose project for automatic startup and bounded generic DAST; untrusted project execution is not enabled on the Docker host.

| | Role | In one line |
|---|---|---|
| 🔎 **Scanners** | Semgrep CE · CodeQL CLI · Gitleaks · Trivy + bounded DAST probes | Produce findings and saved runtime evidence |
| 🧭 **Code graph** | Two-pass profiling | Builds an import graph (via Graphify, or a built-in fallback) so file "hotspots" feed Discovery's ordering and risk prioritization |
| 🟣 **Agent 1: AI Discovery** | Step 10 — LLM | Inspects planned gaps and proposes candidates; separate source verification does not prove exploitability |
| 🟠 **Agent 2: Autonomous Penetration Testing** | Step 13 — rule-based, optional LLM planner | Takes each source-grounded candidate and actually tries to reproduce it against an isolated test stack, instead of only reasoning about it |
| 🟢 **Agent 3: Security Review** | Step 15 — LLM | Reviews eligible issue groups (now including the Penetration Agent's evidence) and records verdicts |
| 📈 **Saved artifacts** | Per-run JSON, Markdown and HTML | Preserve evidence, every penetration attempt, review status, policy decisions and coverage gaps; MLflow is not integrated |

**Team:** Hossam Elnagar · Safaa Abu Alsoud, internship / academic security research project.

## ▶️ Run the local workspace

Use Python 3.11 or newer. From the repository root, install the local workspace
and open the **Verdict Security Reviewer** desktop shortcut. Administrator
PowerShell is not required for the normal installation:

```powershell
& .\scripts\install_local.ps1
# Then open the Verdict Security Reviewer desktop shortcut.
```

The UI runs on `http://127.0.0.1:8765` and offers source-only reviews or
authorized DAST against a local app. For Docker reviews, start Docker Desktop
first. The installer can optionally prepare Semgrep and ZAP with
`-InstallSemgrep -InstallZap`; CodeQL, Gitleaks and Trivy are separate tools.
Use **System setup** in the UI to check what is available. See
[Local web deployment](docs/local-web-deployment.md) for the review modes and
first-use steps.

The dedicated CLI command below runs the trusted `targets/security-lab-web`
fixture. From the repository root, use a new output directory for each run:

```powershell
$repo = (Get-Location).Path
$scanOutput = Join-Path $repo ('reports\automatic-security-lab-docker-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))

& "$repo\.venv\Scripts\python.exe" "$repo\scripts\run_docker_automatic_pipeline.py" `
  --output $scanOutput `
  --codeql-bundle 'C:\path\to\codeql-2.27.1\codeql'
```

The CodeQL directory must contain the Windows `codeql.exe` executable, or a
Linux/WSL `codeql` launcher (both are detected automatically). Semgrep
CE, Gitleaks and Trivy must be installed and available to the process. The
readiness stage checks all four adapters before Docker starts and stops the run
if a required adapter, the CodeQL bundle, the AI provider or the output path
is not ready.

The automatic command uses Groq by default. Set `GROQ_API_KEY` only in the
PowerShell session that runs the scan; never commit an API key to this
repository. A local Ollama provider can be selected instead when its service
and model are already available:

```powershell
& "$repo\.venv\Scripts\python.exe" "$repo\scripts\run_docker_automatic_pipeline.py" `
  --output $scanOutput `
  --codeql-bundle 'C:\path\to\codeql-2.27.1\codeql' `
  --ai-provider ollama `
  --ai-model 'qwen2.5-coder:7b'
```

During a run, the pipeline validates the trusted Compose file, starts a
disposable loopback-only stack, performs the bounded DAST and two-user
authorization probes, saves and validates the runtime evidence, removes the
stack, then runs the four static scanners, the code graph build, AI
Discovery, the Autonomous Penetration Testing Agent, and Security Review.
The final JSON, Markdown and HTML artifacts are written to `$scanOutput`; the
temporary runtime evidence is also retained under `reports/docker-autoscan/`
for that run. A new output directory is required for every run, so previous
reports are not overwritten.

### Current scope and boundaries

- The dedicated educational Docker command runs **only**
  `targets/security-lab-web`. The generic project route can start a developer's
  own Compose project, but only after explicit trust, testing authorization and
  runtime validation; it does not run untrusted code automatically.
- Its default DAST is bounded HTTP and two-account authorization testing.
  Optional ZAP adds bounded traditional crawling/passive analysis or approved
  active tests, not exhaustive browser or business-workflow coverage.
- The Autonomous Penetration Testing Agent (see its own section below) opens
  its own, second, isolated session for a bounded adaptive-testing window; it
  never touches real data and is disabled by default unless a Runtime
  Contract is already supplied, in which case it reuses that same
  authorization automatically.
- Docker runs only explicitly trusted projects. Containers do not provide a
  safe execution boundary for arbitrary untrusted repositories; those projects
  can still receive a source-only review without starting their code.
- A run can be marked completed only when required DAST, all four scanners, AI
  Discovery and group review succeed. Completion does not mean the Policy
  Gate allowed release or that the application is safe.
- AI candidates remain evidence-gated and may be reported as needing more
  evidence. Groq token/rate limits can make the AI stage partial (the run's
  `pending_groups`/`pending_ids` can be finished later with
  `scripts/resume_local_review.py` without re-running scanners or Docker);
  Ollama is the local alternative.
- Trivy currently performs the supported filesystem/dependency/configuration
  checks; built-image scanning and MLflow integration are not implemented.

The fixed educational fixture is intentionally vulnerable and should not be
exposed on a public or shared network.

## 🧰 Review another local project

The project-agnostic entry point accepts any local source tree and runs the
static, AI Discovery and evidence-based review stages without starting the
project or executing its Docker files:

```powershell
$project = (Resolve-Path 'C:\Projects\my-app').Path
$output = Join-Path (Resolve-Path '.').Path ('reports\my-app-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))

& ".\.venv\Scripts\python.exe" ".\scripts\run_project_pipeline.py" `
  $project `
  --output $output `
  --static-only `
  --codeql-bundle 'C:\path\to\codeql-2.27.1\codeql' `
  --ai-provider ollama `
  --ai-model 'qwen2.5-coder:7b'
```

Source-only mode is the safe default for arbitrary projects. It runs the Project
Profiler, Scan Planner, applicable scanners, AI Discovery, verification,
triage, Security Review and final reporting. The output directory must be
new and outside the scanned project. Use `--require-all-scanners` when the
project contract requires every scanner adapter; otherwise the planner keeps
unsupported or not-applicable tools visible as coverage gaps.

For a complete scan — including the Autonomous Penetration Testing Agent —
omit `--static-only` and provide a Runtime Contract:

```powershell
& ".\.venv\Scripts\python.exe" ".\scripts\run_project_pipeline.py" `
  $project `
  --output $output `
  --runtime-contract 'C:\path\to\runtime-contract.json' `
  --allow-trusted-local-compose `
  --dast-engine zap-passive `
  --browser-dast `
  --penetration-ai-planner `
  --codeql-bundle 'C:\path\to\codeql-2.27.1\codeql' `
  --ai-provider ollama `
  --ai-model 'qwen2.5-coder:7b'
```

The full mode runs bounded generic DAST against the explicitly authorized
runtime before the static and AI stages, then builds the code graph, runs AI
Discovery, and — because a Runtime Contract was supplied — automatically opens
a **second**, isolated session for the Penetration Testing Agent, reusing the
same contract and the same `--allow-trusted-local-compose`/`--browser-dast`
trust decisions. Add `--penetration-ai-planner` to let an AI model (the same
provider/model already configured above) choose the Agent's next attack
template by reasoning over the hypothesis and every prior attempt, instead of
the built-in keyword table; add `--no-penetration-agent` to disable the Agent
entirely for a given run. An existing loopback app needs no startup command. A
reviewed trusted-local-project contract can start Compose with
`--allow-trusted-local-compose`; simple Flask, FastAPI and Express apps
can use an explicitly approved temporary startup template. The Guided Runtime
Contract in the UI can also declare account and business-workflow checks;
write workflows require an approved disposable Compose stack. The fixed
two-user probes tailored to the educational fixture remain on its dedicated
Docker route. See [Runtime Contract guide](docs/runtime-contract.md).

## 🔴 The problem

Static scanners (SAST) find important source-level risks, but a scanner-only workflow can leave three problems:

- **Noisy alerts.** Similar or weakly supported findings need grouping and human-checkable evidence.
- **Limited context.** Static evidence alone may not establish reachability or runtime authorization behavior.
- **Coverage gaps.** Dependencies, configuration and the running application need different checks; no single tool covers them all.

A fourth problem sits underneath all three: even when a scanner or an LLM correctly *suspects* a runtime issue (a missing authorization check, an IDOR), suspicion is not evidence. Someone still has to actually try to exploit it to know whether it is real.

> ### The research question
> **Does an AI agent on top of existing scanners add *measurable* value, or does it just repeat the scanner's output in nicer language — and can a bounded agent turn a suspicion into an actual, reproducible exploit without becoming unsafe to run?**
> Verdict is built to prove or disprove this, not to assume it.

## ✨ What's different

Combining scanners with an LLM is not new. This prototype focuses on bounded tool execution, traceable evidence, conservative candidate triage, an agent that actually *tests* its own suspicions rather than only reasoning about them, and a separate educational-target evaluation:

| | |
|---|---|
| 🌐 **Trusted lab and generic projects** | Dedicated Docker route for Security Lab Web; source-only or authorized Runtime Contract review for other local projects |
| 🧪 **Saved runtime evidence** | Bounded HTTP, optional ZAP/browser checks, and declared workflows; not exhaustive DAST |
| 🔒 **Evidence-gated AI** | AI citations are checked against source; source-grounded does not mean exploitable or confirmed vulnerable |
| 🎯 **Hypothesis-driven penetration testing** | A bounded, adaptive agent turns a source-grounded suspicion into exploitation evidence (or a documented "not reproduced") using read-only, isolated probes |
| 📊 **Post-scan evaluation** | A 15-positive-case fixture audit exists; a rigorous three-mode comparison remains experimental |

<details>
<summary><b>Scanner only vs Scanner + Agents</b></summary>

| | Scanner only | Scanner + Agents (Verdict) |
|---|---|---|
| Detects | Static rules, data flow, secrets and supported dependencies/configuration | Those findings plus AI candidates and bounded runtime observations |
| Context | Tool locations and traces vary by scanner | Collected source context and linked runtime evidence where available |
| Runtime issues (IDOR, headers, ...) | No active HTTP probing | Bounded lab probes, authorized contract-based checks, **and** the Penetration Agent's adaptive attempts, depending on the review mode |
| Suspicion vs proof | A rule firing is itself the "finding" | The Penetration Agent actually attempts exploitation before a verdict is written, where a Runtime Contract is available |
| Verdict | Raw scanner findings need interpretation | Confirmed / Likely / False Positive / Needs More Evidence from the Security Review agent, with an explicit "confirmed by the Penetration Agent" marker where it applies |
| Output | Tool-specific results | Merged observations, every penetration attempt (including ones that couldn't run), verdicts, policy decisions and explicit gaps |

</details>

## 🧭 Pipeline

The steps below describe the current pipeline. Runtime steps use an authorized
local URL or an explicitly trusted disposable Docker stack; source-only reviews
skip DAST and the Penetration Agent, and report that coverage gap. The three
agent stages are identified in the table.

<details>
<summary><b>Step reference (what each step does)</b></summary>

| # | Step | Type | What it does |
|---|---|---|---|
| 0 | Readiness check | Rule-based | Checks the output path, CodeQL, AI provider, all four scanner adapters, and the trusted Compose plan before starting the app. |
| 1 | Runtime setup + DAST first | Rule-based | For an authorized local app, probes the declared loopback URL; for an explicitly trusted Compose project, starts and cleans up a temporary stack. Baseline, selected ZAP/browser checks, and declared workflows record their own coverage. This FIRST stack is fully torn down before the static/AI stages — it is not the same session the Penetration Agent uses later. |
| 2 | Profiler + Scan Planner | Rule-based | Maps files, languages and dependencies, then plans tools; an early profile also supports preflight. Source changes stop later evidence collection. |
| 3 | Static scan | Tools | Semgrep CE, CodeQL CLI, Gitleaks and Trivy. Each required adapter must complete and produce readable output. |
| 4 | Code graph build | Rule-based (two-pass) | Runs Graphify (if `GRAPHIFY_COMMAND`/`--graphify-command` is set) or a deterministic built-in import graph otherwise, outside the scanned project; the profiler is then re-run with the graph attached so later steps see file "hotspots." |
| 5 | Import DAST evidence | Rule-based | Validates the selected Docker or Runtime Contract evidence and source/output links before normalization. |
| 6 | Normalize | Rule-based | Converts supported scanner and DAST output to one Finding format while retaining source IDs and evidence. |
| 7 | Merge & Dedup | Rule-based | Conservatively groups related observations and keeps originals; merged counts are not confirmed-vulnerability counts. |
| 8 | Initial Context Collector | Rule-based | Collects bounded source context where locations exist and preserves linked runtime evidence. |
| 9 | Risk Prioritization | Rule-based | Orders review work by risk, evidence, and code-graph hotspots; no finding is dropped or proved by its score. |
| 10 | **AI Discovery** | 🟣 **Agent 1 (LLM)** | Inspects planned areas the scanners may have missed, now ordered by code-graph hotspots. Required for a complete scan; outputs candidates, not free-form DAST. |
| 11 | Candidate Context Collector | Rule-based | Collects bounded source text and line anchors behind each AI suggestion. |
| 12 | Verification | Rule-based | Checks AI citations against the source snapshot. "Confirmed" here means source-grounded, not exploitable. |
| 13 | **Dynamic Penetration Testing Agent** | 🟠 **Agent 2 (rule-based; optional LLM planner)** | Opens its own second, isolated, time-bounded session and, for every source-grounded candidate, plans one of three templates (unauthenticated access, authorization matrix, IDOR), executes it read-only via HTTP/ZAP/Playwright, evaluates the HTTP status deterministically, and adapts to the next template until it confirms exploitation, rules it out, or exhausts its budget. Disabled unless a Runtime Contract is already supplied (then it reuses that authorization automatically); `--no-penetration-agent` turns it off. See the [dedicated section](#-autonomous-penetration-testing-agent) below. |
| 14 | Candidate Triage | Rule-based | Groups only grounded overlaps; uncertain and insufficiently evidenced candidates remain visible. The Penetration Agent's exploitation evidence is attached to Verification's notes here, never overriding its disposition. |
| 15 | **Security Review** | 🟢 **Agent 3 (LLM)** | Reviews all eligible groups in bounded calls and records Confirmed / Likely / False Positive / Needs More Evidence; pending groups make the scan partial. Sees the Penetration Agent's evidence as part of its input. |
| 16 | Policy Gate | Rule-based | Applies block, warn or allow decisions. A failed release gate can coexist with a completed scan. |
| 17 | **Final Report** | Rule-based | Generates a report from tool evidence, AI candidates, every penetration-testing attempt (including ones that never executed), Security Review verdicts, policy decisions and coverage gaps — with an explicit marker wherever the Penetration Agent independently confirmed a finding. |
| 18 | Optional lab evaluation | Separate command | Compares saved results with a held-out benchmark only after scanning; ground truth never enters scanners or AI. |

</details>

Steps 10–16 run through a LangGraph `StateGraph` in `src/security_reviewer_v2/agent_graph.py`.

The PowerShell web launcher enables LangSmith tracing for those agent stages
by default, prompting for a key if needed. The desktop shortcut does not
enable tracing by itself. The PowerShell launcher hides trace inputs, outputs
and metadata and has a `-NoLangSmith` escape hatch; see
[LangSmith setup](docs/langsmith-setup.md). Tracing does not replace the local
security evaluation report. The graph coordinates Discovery, evidence
collection, verification, the Penetration Testing Agent, triage, Security Review
and Policy Gate; because the Penetration Agent makes no model calls of its
own (it is rule-based by default), it carries an explicit named trace span
with its own input/output metadata so it still shows up as its own entry in
LangSmith rather than leaving nothing beyond the bare graph invocation.
Agent 1 also has its own graph in `discovery/agent.py`: it plans
the scope, runs bounded model batches, checks candidates, and loops through
on-demand context only within its configured limits. Agent 3 has its own graph
in `reviewers/agent.py`: it prepares evidence, plans bounded review batches,
retries missing group reviews, and finalizes pending results. If Discovery does
not complete its planned inspection, the outer graph does not run Agent 3.
Scanner execution and final reporting remain outside these graphs. The graphs
do not use persistent LangGraph checkpoints; existing saved-stage artifacts and
continuation commands remain separate from LangGraph persistence.

### Policy Gate

| Verdict + severity | Decision |
|---|---|
| 🔴 Confirmed Critical / High | **Block** |
| 🟠 Likely Critical / High | **Warn**; manual review is needed |
| 🔵 Other unresolved or non-blocking verdicts | **Warn** |
| ⚪ False Positive | **Allow** for that finding |

Unreviewed groups or unresolved candidates can leave the overall gate **incomplete**; scan completion and release approval are separate states.

### Safety rules

- The fixed trusted Docker lab enables bounded mutating and two-account checks for its disposable fixture; other runtime paths require explicit authorization and flags.
- AI Discovery has request and context limits and does not run arbitrary attacks against the target.
- The Penetration Testing Agent never issues a mutating request (GET/HEAD only), never invents an endpoint or account (both come from the source-discovered route index and the Runtime Contract's own declared accounts), and every planned attempt passes a deterministic validator before anything executes — even when an optional AI planner chose which of the three templates to try. Its own second session has a hard time ceiling and is torn down afterward with a cleanup check.
- An automatic run is "completed" only when required DAST, all four scanners, AI Discovery and group review succeed. This does not mean the Policy Gate passed or the app is safe.

## 🎯 Autonomous Penetration Testing Agent

Discovery and Security Review can both *suspect* a runtime issue, but a suspicion is not evidence. This agent exists to close that gap: for every candidate Verification has already source-grounded, it tries to actually reproduce the issue against an isolated test stack — and records every attempt, not only the ones that succeeded.

**How it decides what to try.** Three fixed, read-only templates: `unauthenticated_access` (no session at all), `authorization_matrix` (an authenticated account that is not the resource's owner), and `idor` (a concrete other-account resource id cited in the candidate's own evidence — never an invented one). By default the next template is chosen from a small keyword table on the hypothesis text; with `--penetration-ai-planner`, an LLM instead reasons over the hypothesis and the full record of every prior attempt's actual result and picks the next template (or says "stop") — the model only ever names one of the three known template ids, so it gains no new execution capability, and any unusable or failed AI reply falls back to the keyword table for that one attempt.

**How it decides what happened.** Deterministically: each template declares the expected *denial* HTTP status (401/403/404); a response outside that set is the "violation" (confirmed exploitation), never a bare, unexamined `200`. This judgment is never delegated to an LLM.

**How it executes.** Through `scanners/runtime_workflows.py` (the same bounded HTTP executor the DAST stage already uses) by default; it can corroborate a clean/inconclusive HTTP result once per hypothesis with a scoped ZAP active-scan attempt (needs the Agent's own disposable Compose stack) or a real, authenticated Playwright browser visit (needs Node.js), via `--dast-engine`/`--zap-auth-config` and `--browser-dast` respectively. Neither tool is ever used for free-form requests.

**When it stops.** On confirmed exploitation, on exhausting every applicable template, or on hitting its request/attempt/time budget (`--penetration-max-*` flags) — whichever comes first. Final per-hypothesis states are `exploitation_confirmed`, `not_reproduced`, `inconclusive`, `blocked`, or `cannot_test`; these describe the *test result*, never the final vulnerability verdict, which still belongs to Security Review and the Policy Gate.

**What ends up in the report.** The Markdown and JSON reports list every attempt — including templates the Agent drew up but could never execute at all (no account available, tool unavailable) — with the exact method, path, account, expected vs. actual HTTP status, and reasoning, so a reviewer can reproduce the same request after a fix. Wherever the Agent independently confirmed exploitation, the Scanner Observations, Security Review Verdicts, and Policy Decisions sections carry an explicit "✅ Independently confirmed by the Autonomous Penetration Agent" marker next to that specific finding.

**Enabling it.** It needs no separate flag beyond a Runtime Contract: give `--runtime-contract` (and, for a Compose-started target, `--allow-trusted-local-compose`) and it opens its own second, isolated session automatically, reusing that same authorization. `--no-penetration-agent` disables it explicitly; `--penetration-test-environment-config` points it at a *different* contract than the first DAST stage's, if needed. See `docs/dynamic-penetration-agent.md` (implementation notes) for the full design and current limitations — in particular, the ZAP/Playwright tool adapters are unit-tested against fakes only and should be validated once against a live stack before production use.

## 🗺️ Coverage map

This table describes the built-in baseline and fixed educational probes;
optional ZAP, declared workflows, and the Penetration Testing Agent can add
coverage, but do not guarantee that every vulnerability is tested.

| Vulnerability | Detected by |
|---|---|
| SQL Injection | Semgrep / CodeQL source analysis; no generic SQL-injection DAST probe |
| XSS (Reflected / Stored) | Static analysis plus fixed local HTTP reflection and write/read probes |
| Command Injection | Static scanner evidence; no fixed runtime exploitation probe |
| Path Traversal | Static scanner evidence; no fixed runtime exploitation probe |
| Hardcoded Secrets | Gitleaks and applicable Trivy filesystem secret checks |
| Broken Authorization / Missing Access Control | Fixed two-user HTTP probes in Security Lab Web, **and**, for other projects with a Runtime Contract, the Penetration Agent's `authorization_matrix`/`unauthenticated_access` templates |
| IDOR | Fixed two-user order and profile HTTP probes in Security Lab Web, **and** the Penetration Agent's `idor` template where the candidate's own evidence cites a concrete other-account resource id |
| CORS Misconfiguration | Fixed HTTP check for reflected origin with credentials |
| Vulnerable Dependencies | Trivy filesystem scan where supported manifests and vulnerability data exist |
| Insecure Docker settings | Trivy filesystem misconfiguration scan; built-image scanning is not implemented |

CodeQL runs alongside Semgrep for source flow analysis.

## 🌐 Local web deployment

The repository provides a localhost-only browser workspace served by Waitress.
Projects and independent worker jobs persist across UI restarts. Reports stay
outside the scanned project; credentials can be saved in the OS vault.
This is a single-user local deployment, not a public web service.

```powershell
& .\scripts\install_local.ps1
# Open the Verdict Security Reviewer desktop shortcut.
# Optional components: -InstallSemgrep -InstallZap
```

Open `http://127.0.0.1:8765`. The UI offers the trusted educational Docker
route (DAST + four scanners + all three agents), an explicit static-only project
route, and a generic full-project route. For a running local app, the UI can
create the Runtime Contract from its URL and endpoint fields. For a local
project with a detectable Compose service and loopback port, it proposes the
setup, asks for explicit trust and testing authorization on first use, then
starts and removes the temporary stack automatically. Successful settings are
remembered outside the source tree; changed Compose, root Dockerfile or `.dockerignore`
require approval again. Docker is not a safe boundary for untrusted code. Keep the default loopback binding; public hosting requires a
separate authenticated service and a stronger worker isolation design.

Simple Flask, FastAPI and Express applications can also use opt-in temporary
startup templates. The workspace includes saved projects, bounded ZAP options,
basic form login, safe cancellation, saved-AI resume, filtered findings,
prior-run comparison and export. Unsupported workflows remain explicit.

The **Guided Runtime Contract** walks developers through route discovery,
multiple test accounts, expected business rules, request/time limits and saving.
Declared HTTP workflows support verified bearer/cookie identities and chained
requests with captured IDs. Write tests require an explicitly approved disposable
Compose stack. The same declared accounts are what the Penetration Testing
Agent reuses for its own attempts — it never declares new ones. Results
distinguish rule violations from blocked or untested steps; this does not
promise exhaustive DAST. Follow the step-by-step
[`Runtime Contract guide`](docs/runtime-contract.md) to configure the editable
multi-service example or your own application's expected rules.

Runtime discovery is read-only and now recognizes common Python/Node route
declarations plus OpenAPI JSON/YAML. The UI can generate a **reviewable draft**
from discovered safe GET routes; it never invents credentials or business
assertions. For JavaScript-heavy applications, the optional bounded browser
crawl uses Playwright when installed, visits same-origin links without form
submissions, and records an explicit gap when unavailable. Each run includes
`coverage-summary.json`, separating HTTP probes, ZAP alerts, browser pages and
declared workflows. OAuth, MFA, GraphQL, WebSocket, race and upload workflows
remain explicit adapter gaps rather than false coverage.

See [`docs/local-web-deployment.md`](docs/local-web-deployment.md) for the
supported modes, report location and security boundaries.

## 📈 Experiment tracking

The current pipeline writes per-run JSON evidence plus Markdown and standalone HTML reports to the selected output directory (typically `reports/`), including tool execution, AI usage, every penetration-testing attempt, verdicts, policy decisions and coverage gaps. **MLflow is not integrated**; any future experiment-tracking schema and comparison protocol still need to be defined.

## 🧪 Evaluation plan

> **Current status:** post-scan checks exist for the bundled educational targets. A rigorous, controlled three-mode study has not been completed.

An eventual three-mode comparison needs a controlled protocol and clearly separated inputs before its numbers can support a broad research claim:

| Condition | What it isolates |
|---|---|
| **Scanner-only** | Planned baseline without AI; saved merged evidence may also include DAST and must be separated carefully |
| **LLM-only** | Proposed source-only comparison; not part of the automatic scan |
| **Hybrid** | The implemented full scan: fixed Docker DAST, four scanners, AI Discovery, the Penetration Testing Agent, and Security Review |

**Metrics:** positive-case recall is available for the educational fixtures. The comprehensive lab also has matched safe controls, but whole-report precision, F1 and False Positive Rate still need adjudication of extra findings and a validated comparison protocol. For the Penetration Agent specifically, `dynamic-penetration-test.json`'s `usage` block already tracks attempts-per-hypothesis, total requests, and exploitation-confirmed counts, so a before/after comparison (with vs. without the Agent) is possible once a controlled protocol is defined. Latency, token usage, severity quality and remediation correctness remain separate evaluation work.

The separate 18-scenario multi-service target also has a held-out post-scan
audit: `scripts/evaluate_verdict_multi_service.py` compares a completed saved
scan and final review with `benchmark/verdict-multi-service-scenarios.json`.
It creates JSON, Markdown and HTML evaluation files without running scanners
or passing ground truth to AI. See `benchmark/README.md` for the command and
interpretation limits.

The comprehensive lab has its own held-out evaluation in
`scripts/evaluate_verdict_comprehensive.py`; see
`docs/verdict-comprehensive-lab.md` for its confirmed cases and matched safe
controls. These fixture audits are not a cross-project performance claim.

**Also planned:** a held-out secondary test set and failure analysis by error type: false positive, false negative, wrong classification and wrong reasoning. Neither is implied by one completed educational-target scan.

> **How to read 15/15.** If a saved run matches all 15 known scenarios, that is positive-case coverage *for this educational app and that report*. It does not prove detection of every vulnerability in another project or measure precision from a positive-only sample.
