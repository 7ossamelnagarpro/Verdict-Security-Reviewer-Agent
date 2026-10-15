# Verification, Candidate Triage, and Security Review

After AI Discovery, the pipeline collects candidate context and runs three
separate stages:

1. **Verification** checks that the AI's cited file, line range, literal
   evidence, and collected anchors are available in the profiled source
   snapshot. Its `confirmed` value means *source-grounded*, not *vulnerable*.
   Missing or stale evidence remains `needs_more_evidence`; invalid references
   may be `rejected`.
2. **Candidate Triage** groups only same-family evidence at a closely matching
   source location. It preserves every scanner and AI source ID in an issue
   group. A SQL injection and an XSS in the same route remain separate. Unknown
   categories and ambiguous matches stay separate as `uncertain_overlap`.
   `novel_candidate` means no matching **reported issue**, not proof that no
   scanner could have detected it. Inconclusive candidates remain listed but
   are not presented as confirmed vulnerabilities.
3. **Security Review Agent** receives one item per eligible issue group, with
   all grouped source evidence. It reviews every group in batches of at most
   three, additionally bounded by prompt size. Missing IDs are retried one at
   a time. If a group still has no model verdict, it is listed in
   `pending_ids`; the run becomes `partial` or `blocked`, never silently
   `completed`. The Policy Gate marks incomplete reviews and unresolved
   candidates as `incomplete` unless a confirmed high/critical finding already
   causes a `failed` decision.

To continue the saved Security Lab Web Discovery result without scanning again
or calling a model:

```powershell
.venv\Scripts\python.exe scripts\run_saved_review_stages.py `
  targets\security-lab-web `
  reports\stepwise-security-lab-web\discovery\groq-120b-combined-20261007.json `
  reports\stepwise-security-lab-web\merged\run-20261006T101740Z-298d9666\merged-findings.json `
  reports\stepwise-security-lab-web\review-stages-20261007 `
  --profile reports\stepwise-security-lab-web\profile.json `
  --scanner-context reports\stepwise-security-lab-web\context\run-20261006T101740Z-298d9666\context.json
```

This writes `candidate-context.json`, `verification.json`,
`candidate-triage.json`, and `stage-summary.json`. Add
`--review --provider groq --model openai/gpt-oss-120b` only after setting `GROQ_API_KEY` securely in
the terminal. No key value belongs in a command, file, or report. An explicit
review also writes `security-review.json`, `policy-gate.json`, and
`security-review-report.md`. A real model's verdict still requires validation
before relying on it for release decisions; grouping and source grounding do
not demonstrate exploitability.

Known limits: family and source-location grouping is conservative and may
leave duplicates; a shared route or category alone cannot prove the same root
cause. The basic secret redactor is best effort. Candidates with insufficient
source evidence need further context or manual review rather than being
upgraded automatically. No local test provider's output is a security review.

To recheck a completed scan after a source-grounding fix, without starting a
VM, rerunning scanners, or calling the AI provider, use a new derivative output
directory:

```powershell
.venv\Scripts\python.exe scripts\reverify_saved_discovery.py `
  reports\automatic-security-lab-20261009-095320 `
  --output reports\automatic-security-lab-20261009-095320-reverified
```

The command verifies every saved source hash before using the saved Discovery
and merged findings. It writes re-grounded Discovery, candidate context,
Verification, Candidate Triage, and a comparison summary to the new directory;
the original scan and its Security Review verdicts are unchanged. A numbered
quote must match its exact source line. If an AI citation is wrong by at most
two lines, the code may re-anchor it only to a **unique, exact** nearby match
inside the same Python function and the candidate's cited range. A compact
Python anchor can similarly match one complete statement laid out across up
to five physical lines, using the same token sequence, same-function boundary,
and unique nearby start line. Every correction is recorded as
`source_citation_reanchored` in the candidate and verification records.
Ambiguous, stale, out-of-scope, or otherwise unsupported citations stay
unresolved; no vulnerability is automatically confirmed.

After inspecting the derivative, review only changed issue groups and update
its policy/report with a model available in the current terminal session:

```powershell
.venv\Scripts\python.exe scripts\review_reverified_discovery.py `
  reports\automatic-security-lab-20261009-095320 `
  reports\automatic-security-lab-20261009-095320-reverified `
  --provider groq --model openai/gpt-oss-120b
```

`GROQ_API_KEY` must be set in that terminal's environment; never paste the key
into the command or a report. The script re-attests the source and compares all
recomputed evidence with the saved derivative before any model call. Previous
Security Review verdicts are reused only when the entire issue group's source
ID tuple is identical; changed/new groups are reviewed in bounded batches.
It writes `security-review.json`, `policy-gate.json`,
`security-review-report.md`, and `postscan-review-summary.json` **inside the
derivative only**. Provider failures leave explicit pending groups and can be
resumed with the same command. `status: completed` means the review ran to
completion, not that the policy passed or the project is secure. Neither
command starts a VM, reruns scanners, or repeats AI Discovery.

## Held-out review audit for Security Lab Web

The saved Groq review can be compared with the fixture's positive-only ground
truth **after** the agent run. The benchmark answers and the curated
correlation file stay outside `targets/security-lab-web` and must never enter
the scanner or agent prompts:

```powershell
.venv\Scripts\python.exe scripts\audit_security_lab_review.py `
  --ground-truth benchmark\security_lab_web_ground_truth.json `
  --review reports\stepwise-security-lab-web\review-stages-20261007\security-review.json `
  --mapping benchmark\security_lab_web_review_audit_mapping.json `
  --output-prefix reports\stepwise-security-lab-web\review-stages-20261007\security-review-audit
```

This writes a machine-readable JSON audit and a de-duplicated, human-readable
Markdown audit. It correlates repeated model reviews to the **same declared
benchmark case**, retains every raw review/source ID, and calls out extra
claims that require separate validation. The raw report and policy decisions
are unchanged. The curated mapping applies only to this saved review: if any
review ID is missing or newly added, evaluation fails rather than silently
miscounting it. Because the fixture has no safe/negative cases, this audit can
report positive-case recall, but not defensible precision, accuracy or F1.
