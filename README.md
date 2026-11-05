<p align="center">
  <img src="assets/banner.svg" alt="Verdict: Security Reviewer Agent" width="100%">
</p>

<p align="center">
  <img alt="stage" src="https://img.shields.io/badge/stage-in%20development-2F6BFF?style=for-the-badge">
  <img alt="agents" src="https://img.shields.io/badge/AI%20agents-2-7A4DFF?style=for-the-badge">
  <img alt="artifacts" src="https://img.shields.io/badge/artifacts-JSON%20%2B%20Markdown%20%2B%20HTML-FFB020?style=for-the-badge">
  <img alt="track" src="https://img.shields.io/badge/track-Data%20Science%20%26%20AI%20Agents-1E9E5A?style=for-the-badge">
</p>

<p align="center">
  <a href="#-overview">Overview</a> ·
  <a href="#-run-the-local-workspace">Run</a> ·
  <a href="#-the-problem">Problem</a> ·
  <a href="#-whats-different">What's different</a> ·
  <a href="#-pipeline">Pipeline</a> ·
  <a href="#-coverage-map">Coverage</a> ·
  <a href="#-evaluation-plan">Evaluation</a>
</p>

---

## 🛡️ Overview

**Verdict** is a pre-deployment security review pipeline. For its trusted Security Lab Web fixture, it runs bounded DAST in a temporary Docker Compose stack, removes the stack, then runs four scanners and **two AI agents** for discovery and evidence-based review. Other local projects can use an authorized loopback Runtime Contract. Developers may explicitly approve their own trusted Compose project for automatic startup and bounded generic DAST; untrusted project execution is not enabled on the Docker host.

| | Role | In one line |
|---|---|---|
| 🔎 **Scanners** | Semgrep CE · CodeQL CLI · Gitleaks · Trivy + bounded DAST probes | Produce findings and saved runtime evidence |
| 🟣 **Agent 1: AI Discovery** | Step 9 | Inspects planned gaps and proposes candidates; separate source verification does not prove exploitability. |
| 🟢 **Agent 2: Security Review** | Step 13 | Reviews eligible issue groups and records verdicts; reporting code generates the final report. |
| 📈 **Saved artifacts** | Per-run JSON, Markdown and HTML | Preserve evidence, review status, policy decisions and coverage gaps; MLflow is not integrated. |

**Team:** Hossam Elnagar · Safaa Abu Alsoud, internship / academic security research project.

## ▶️ Run the local workspace

Use Python 3.11 or newer. From the repository root, install the local workspace
and open the **Verdict Security Reviewer** desktop shortcut. Administrator
PowerShell is not required for the normal installation:

```powershell
& .\scripts\install_local.ps1
# Then open the Verdict Security Reviewer desktop shortcut.
```

The UI runs on `http://127.0.0.1:8770` and offers source-only reviews or
authorized DAST against a local app. For Docker reviews, start Docker Desktop
first. The installer can optionally prepare Semgrep and ZAP with
`-InstallSemgrep -InstallZap`; CodeQL, Gitleaks and Trivy are separate tools.
Use **System setup** in the UI to check what is available. See
[Local web deployment](docs/local-web-deployment.md) for the review modes and
first-use steps.

The project pipeline runs the bundled `targets/verdict-comprehensive-lab` or
an explicitly authorized local project. From the repository root, use a new
output directory for each run and provide a Runtime Contract for DAST.

The automatic command uses Groq by default. Set `GROQ_API_KEY` only in the
PowerShell session that runs the scan; never commit an API key to this
repository. A local Ollama provider can be selected instead when its service
and model are already available:

```powershell
& ".\.venv\Scripts\python.exe" ".\scripts\run_project_pipeline.py" `
  "targets\verdict-comprehensive-lab" `
  --output "reports\comprehensive-run" `
  --runtime-contract "C:\path\to\runtime-contract.json" `
  --allow-trusted-local-compose `
  --codeql-bundle 'C:\path\to\codeql-2.27.1\codeql' `
  --ai-provider ollama `
  --ai-model 'qwen2.5-coder:7b'
```

During a run, the pipeline validates the contract, starts the explicitly
trusted disposable stack, performs bounded DAST, then runs the static scanners,
Codebase Memory, AI Discovery and Security Review. JSON, Markdown and HTML
artifacts are written to the output directory.
Groq Discovery uses an 8,000-character prompt budget by default after a
comprehensive-lab scan using the 20,000-character budget failed during
context enrichment; Ollama
keeps the 20,000-character budget. `--ai-max-context-chars` overrides either
budget. A smaller budget can require more batches and may leave source-context
limitations visible; it does not change the security verdict rules.

### Current scope and boundaries

- The comprehensive lab route starts Docker only after explicit trust, testing
  authorization and runtime validation; it does not run untrusted code automatically.
- Its default DAST is bounded HTTP and two-account authorization testing.
  Optional ZAP adds bounded traditional crawling/passive analysis or approved
  active tests, not exhaustive browser or business-workflow coverage.
- Docker runs only explicitly trusted projects. Containers do not provide a
  safe execution boundary for arbitrary untrusted repositories; those projects
  can still receive a source-only review without starting their code.
- A run can be marked completed only when required DAST, all four scanners, AI
  Discovery and Security Review finish. Completion does not mean the Policy
  Gate allowed release or that the application is safe.
- AI candidates remain evidence-gated and may be reported as needing more
  evidence. Groq token/rate limits can make the AI stage partial; Ollama is the
  local alternative.
- Trivy currently performs the supported filesystem/dependency/configuration
  checks; built-image scanning and MLflow integration are not implemented.

For the current comprehensive lab target, the project also supports Codebase
Memory indexing, active ZAP, browser DAST and declared business workflows when
their explicit runtime configuration is supplied. These stages remain bounded
and report their own coverage or partial status; they do not silently become
full application coverage.

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

Codebase Memory is enabled by default for the project pipeline. It builds a
structural index of the scanned source tree (files, symbols, imports, calls and
routes) and feeds route/context corroboration into Application Map and AI
Discovery. It is not a vulnerability scanner and it does not replace
LangGraph; LangGraph orchestrates the AI review stages.

For a complete scan, omit `--static-only` and provide a Runtime Contract:

```powershell
& ".\.venv\Scripts\python.exe" ".\scripts\run_project_pipeline.py" `
  $project `
  --output $output `
  --runtime-contract 'C:\path\to\runtime-contract.json' `
  --codeql-bundle 'C:\path\to\codeql-2.27.1\codeql' `
  --ai-provider ollama `
  --ai-model 'qwen2.5-coder:7b'
```

The full mode runs bounded generic DAST against the explicitly authorized
runtime before the static and AI stages. An existing loopback app needs no
startup command. A reviewed trusted-local-project contract can start Compose
with `--allow-trusted-local-compose`; simple Flask, FastAPI and Express apps
can use an explicitly approved temporary startup template. The Guided Runtime
Contract in the UI can also declare account and business-workflow checks;
for a trusted Compose target, add `--auto-discovery-get` to probe current
source-backed GET suggestions on a second disposable stack before Review.
The flag cannot be combined with a prior `--approved-discovery-plan`.
write workflows require an approved disposable Compose stack. The fixed
two-user probes tailored to the educational fixture remain on its dedicated
Docker route. See [Runtime Contract guide](docs/runtime-contract.md).

## 🔬 Evaluation

Evaluation is a separate post-scan operation. It compares saved findings with
the educational ground-truth benchmark and reports detected and undetected
cases, recall lower bounds and adjudication limits. Ground truth is never sent
to scanners or agents during the scan. See
`scripts/evaluate_verdict_comprehensive.py` and the generated
`evaluation-*.md`/`evaluation-*.html` artifacts.

## 🔴 The problem

Static scanners (SAST) find important source-level risks, but a scanner-only workflow can leave three problems:

- **Noisy alerts.** Similar or weakly supported findings need grouping and human-checkable evidence.
- **Limited context.** Static evidence alone may not establish reachability or runtime authorization behavior.
- **Coverage gaps.** Dependencies, configuration and the running application need different checks; no single tool covers them all.

> ### The research question
> **Does an AI agent on top of existing scanners add *measurable* value, or does it just repeat the scanner's output in nicer language?**
> Verdict is built to prove or disprove this, not to assume it.

## ✨ What's different

Combining scanners with an LLM is not new. This prototype focuses on bounded tool execution, traceable evidence, conservative candidate triage and a separate educational-target evaluation:

| | |
|---|---|
| 🌐 **Trusted lab and generic projects** | Dedicated Docker route for Security Lab Web; source-only or authorized Runtime Contract review for other local projects |
| 🧪 **Saved runtime evidence** | Bounded HTTP, optional ZAP/browser checks, and declared workflows; not exhaustive DAST |
| 🔒 **Evidence-gated AI** | AI citations are checked against source; source-grounded does not mean exploitable or confirmed vulnerable |
| 📊 **Post-scan evaluation** | A 15-positive-case fixture audit exists; a rigorous three-mode comparison remains experimental |

<details>
<summary><b>Scanner only vs Scanner + Agents</b></summary>

| | Scanner only | Scanner + Agents (Verdict) |
|---|---|---|
| Detects | Static rules, data flow, secrets and supported dependencies/configuration | Those findings plus AI candidates and bounded runtime observations |
| Context | Tool locations and traces vary by scanner | Collected source context and linked runtime evidence where available |
| Runtime issues (IDOR, headers, ...) | No active HTTP probing | Bounded lab probes or authorized contract-based checks, depending on the review mode |
| Verdict | Raw scanner findings need interpretation | Confirmed / Likely / False Positive / Needs More Evidence from Agent 2 |
| Output | Tool-specific results | Merged observations, verdicts, policy decisions and explicit gaps |

</details>

## 🧭 Pipeline

The steps below describe the current pipeline. Runtime steps use an authorized
local URL or an explicitly trusted disposable Docker stack; source-only reviews
skip DAST and report that coverage gap. The two agent stages are identified in
the table.

<details>
<summary><b>Step reference (what each step does)</b></summary>

| # | Step | Type | What it does |
|---|---|---|---|
| 0 | Readiness check | Rule-based | Checks the output path, CodeQL, AI provider, all four scanner adapters, and the trusted Compose plan before starting the app. |
| 1 | Runtime setup + DAST first | Rule-based | For an authorized local app, probes the declared loopback URL; for an explicitly trusted Compose project, starts and cleans up a temporary stack. Baseline, selected ZAP/browser checks, and declared workflows record their own coverage. |
| 2 | Profiler + Scan Planner | Rule-based | Maps files, languages and dependencies, then plans tools; an early profile also supports preflight. Source changes stop later evidence collection. |
| 3 | Static scan | Tools | Semgrep CE, CodeQL CLI, Gitleaks and Trivy. Each required adapter must complete and produce readable output. |
| 4 | Import DAST evidence | Rule-based | Validates the selected Docker or Runtime Contract evidence and source/output links before normalization. |
| 5 | Normalize | Rule-based | Converts supported scanner and DAST output to one Finding format while retaining source IDs and evidence. |
| 6 | Merge & Dedup | Rule-based | Conservatively groups related observations and keeps originals; merged counts are not confirmed-vulnerability counts. |
| 7 | Initial Context Collector | Rule-based | Collects bounded source context where locations exist and preserves linked runtime evidence. |
| 8 | Risk Prioritization | Rule-based | Orders review work by risk and evidence; no finding is dropped or proved by its score. |
| 9 | **AI Discovery** | 🟣 **Agent 1** | Independently inspects planned scanner-silent and scanner-flagged areas. Required for a complete scan; outputs candidates, not free-form DAST. |
| 10 | Candidate Context Collector | Rule-based | Collects bounded source text and line anchors behind each AI suggestion. |
| 11 | Verification | Rule-based | Checks AI citations against the source snapshot. "Confirmed" here means source-grounded, not exploitable. |
| 12 | Candidate Triage | Rule-based | Groups only grounded overlaps; uncertain and insufficiently evidenced candidates remain visible. |
| 12a | Discovery GET probes and evidence link | Rule-based | With `--auto-discovery-get` and a trusted disposable Compose contract, probes up to 20 current source-backed GET proposals before Review. Links exact source-anchor candidates to status-only results and declared workflow assertions. An HTTP status alone remains inconclusive. |
| 13 | **Security Review** | 🟢 **Agent 2** | Reviews all eligible groups in bounded calls and records Confirmed / Likely / False Positive / Needs More Evidence; pending groups make the scan partial. |
| 14 | Policy Gate | Rule-based | Applies block, warn or allow decisions. A failed release gate can coexist with a completed scan. |
| 15 | **Final Report** | Rule-based | Generates a report from tool evidence, AI candidates, Agent 2 verdicts, policy decisions and coverage gaps. |
| 16 | Optional lab evaluation | Separate command | Compares saved results with a held-out benchmark only after scanning; ground truth never enters scanners or AI. |

</details>

Steps 9–14 run through a LangGraph `StateGraph` in `src/security_reviewer_v2/agent_graph.py`.

The PowerShell web launcher enables LangSmith tracing for those agent stages
by default, prompting for a key if needed. The desktop shortcut does not
enable tracing by itself. The PowerShell launcher hides trace inputs, outputs
and metadata and has a `-NoLangSmith` escape hatch; see
[LangSmith setup](docs/langsmith-setup.md). Tracing does not replace the local
security evaluation report. The graph coordinates Discovery, evidence
collection, verification, triage, Security Review
and Policy Gate. Agent 1 also has its own graph in `discovery/agent.py`: it plans
the scope, runs bounded model batches, checks candidates, and loops through
on-demand context only within its configured limits. Agent 2 has its own graph
in `reviewers/agent.py`: it prepares evidence, plans bounded review batches,
retries missing group reviews, and finalizes pending results. If Discovery does
not complete its planned inspection, the outer graph does not run Agent 2.
Scanner execution and final reporting remain outside these graphs. The graphs
do not use persistent LangGraph checkpoints; existing saved-stage artifacts and
continuation commands remain separate from LangGraph persistence.

`discovery-test-evidence.json` records any exact candidate-to-runtime links,
including the triage group and redacted assertion outcome. Proposals generated
by the current scan can execute as bounded, source-backed GET observations when
`--auto-discovery-get` is set on a trusted disposable Compose scan. Other
proposals remain unexecuted unless declared in a workflow contract.
An incomplete AI source citation can enter cautious review when a declared
security workflow on the exact source route failed an assertion; the citation
warning and runtime limits remain visible.
The held-out evaluation separately lists source-grounded Discovery candidates
not flagged by Review Agent for independent adjudication.

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
- An automatic run is "completed" only when required DAST, all four scanners, AI Discovery and group review succeed. This does not mean the Policy Gate passed or the app is safe.

## 🗺️ Coverage map

This table describes the built-in baseline and fixed educational probes;
optional ZAP and declared workflows can add coverage, but do not guarantee
that every vulnerability is tested.

| Vulnerability | Detected by |
|---|---|
| SQL Injection | Semgrep / CodeQL source analysis; no generic SQL-injection DAST probe |
| XSS (Reflected / Stored) | Static analysis plus fixed local HTTP reflection and write/read probes |
| Command Injection | Static scanner evidence; no fixed runtime exploitation probe |
| Path Traversal | Static scanner evidence; no fixed runtime exploitation probe |
| Hardcoded Secrets | Gitleaks and applicable Trivy filesystem secret checks |
| IDOR | Fixed two-user order and profile HTTP probes in Security Lab Web |
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
route (DAST + four scanners + both agents), an explicit static-only project
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
Compose stack. Results distinguish rule violations from blocked or untested steps;
this does not promise exhaustive DAST. Follow the step-by-step
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

The current pipeline writes per-run JSON evidence plus Markdown and standalone HTML reports to the selected output directory (typically `reports/`), including tool execution, AI usage, verdicts, policy decisions and coverage gaps. **MLflow is not integrated**; any future experiment-tracking schema and comparison protocol still need to be defined.

## 🧪 Evaluation plan

> **Current status:** post-scan checks exist for the bundled comprehensive lab. A rigorous, controlled three-mode study has not been completed.

An eventual three-mode comparison needs a controlled protocol and clearly separated inputs before its numbers can support a broad research claim:

| Condition | What it isolates |
|---|---|
| **Scanner-only** | Planned baseline without AI; saved merged evidence may also include DAST and must be separated carefully |
| **LLM-only** | Proposed source-only comparison; not part of the automatic scan |
| **Hybrid** | The implemented full scan: fixed Docker DAST, four scanners, AI Discovery and Security Review |

**Metrics:** positive-case recall is available for the educational fixtures. The comprehensive lab also has matched safe controls, but whole-report precision, F1 and False Positive Rate still need adjudication of extra findings and a validated comparison protocol. Latency, token usage, severity quality and remediation correctness remain separate evaluation work.

The comprehensive lab has its own held-out evaluation in
`scripts/evaluate_verdict_comprehensive.py`; see
`docs/verdict-comprehensive-lab.md` for its confirmed cases and matched safe
controls. The evaluator requires a completed AI review by default. Use
`--diagnostic-partial` only for a clearly labeled provisional audit when a
saved review is incomplete; it separates unmapped cases from actual missing
exact signals and never estimates precision or F1 from unassessed controls.
These fixture audits are not a cross-project performance claim.

Semgrep also runs bundled, review-oriented rules for explicit unsigned JWT
headers, base64-decoded identity returns and cookies set without HttpOnly.
These are candidate signals, not a substitute for runtime proof. The
corresponding rule tests include safe code examples to guard against false
positives. Generic DAST checks cookies on every declared GET endpoint and CSP
on declared HTML endpoints; guided workflows can additionally assert bounded
literal response text or headers without saving raw responses. One small inline
multipart test file is supported for explicitly approved disposable Compose
workflows; browser interactions, token tampering and concurrency still need
dedicated adapters and cannot be claimed as covered generically.

**Also planned:** a held-out secondary test set and failure analysis by error type: false positive, false negative, wrong classification and wrong reasoning. Neither is implied by one completed educational-target scan.

> **How to read 15/15.** If a saved run matches all 15 known scenarios, that is positive-case coverage *for this educational app and that report*. It does not prove detection of every vulnerability in another project or measure precision from a positive-only sample.

