# Trusted Docker DAST for Security Lab Web

This is an **additional** automatic path for the fixed educational target. It
does not replace or modify the Hyper-V worker, and it does not execute an
unknown repository's Dockerfile or Compose file automatically. The existing
generic test-environment manager still requires an explicit configuration
outside the target repository and `trusted_lab` for host-side Compose.

The bundled target now has a Dockerfile and `compose.yaml`. Dockerfile builds
the Flask + SQLite application image; Compose runs one non-root web container
with reduced capabilities, bounded resources, and a port published only on
host `127.0.0.1:5055`. A multi-service project could use the same Compose
concept to start its application and database together. Docker/Compose do not
perform DAST themselves: the runner uses the existing bounded web and two-user
authorization probes.
The example configuration leaves the environment manager's *generic*
`authorization` flag off because it has no generic login workflow; this
fixed-target runner invokes the existing Security Lab Web two-user probe
explicitly on every run.

## Run

Install and start Docker Desktop (Linux containers), then ensure the four
required scanners, CodeQL, and the selected AI provider are ready. With the
default Groq provider, set `GROQ_API_KEY` in the PowerShell process environment;
never save it in the target or Compose file. From the repository root:

```powershell
$scanOutput = Join-Path (Get-Location) ('reports\automatic-security-lab-docker-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
& .\.venv\Scripts\python.exe .\scripts\run_docker_automatic_pipeline.py --output $scanOutput
```

The command checks scanner and AI readiness before starting Docker. It reads
[`examples/security-lab-web-docker-environment.json`](../examples/security-lab-web-docker-environment.json),
profiles the target, validates the selected Compose file using the guarded
environment manager, and starts a uniquely named stack. It waits for health,
runs the same fixed Security Lab Web web and authorization probes as the VM
path, writes `reports/docker-autoscan/<run-id>/runtime.json` and
`authorization.json`, and removes the stack and volumes. It verifies that no
containers for that Compose project remain before writing a passing manifest.
Only after cleanup does it run the existing four-scanner + required AI
pipeline, which validates the saved source/output hashes and imports the DAST
evidence. The report includes a distinct **Trusted Docker DAST** section; it
never claims the VM's no-switch or base-disk guarantees. A failed probe,
cleanup, or preflight does not produce a completed scan.

The Docker evidence loader now checks the hash-matched Dockerfile startup
recipe and rejects an inferred debug setting if Compose overrides the command
or entrypoint. In this educational recipe, Docker starts Flask with
`debug=False`; the separate `app.py` direct-run `debug=True` line is retained
as a conditional source warning, not treated as an active vulnerability in the
scanned Docker deployment. Other deployment methods still need their own
evidence. This scope check does not downgrade unrelated findings.

Candidate Triage also applies narrowly grounded issue correlation before
review: same request variable within a CodeQL XSS flow, one route/response
branch for selected runtime/static evidence, and a grounded `/admin` source
candidate against the matching authorization probe. Source IDs are retained.
The October 14 saved scan falls from 35 to 31 planned review groups under
these rules, with all 48 grouped source IDs preserved. This is a preview of
new Triage behavior, **not** a newly completed Security Review.

## Resume a partial Groq review without rerunning Docker or scanners

If DAST, scanners, and AI Discovery completed but Security Review stopped,
`run_saved_review_stages.py` can reuse matching completed reviews from the
original report and write a **new** derived report. Pass the saved Discovery,
merged findings, profile, scanner context, prior review, and Docker evidence
from the same run. Keep `GROQ_API_KEY` in the PowerShell process environment;
never put it in the command line. The original report is not modified.

```powershell
$saved = 'F:\(1) projects\SEC\agentic-security-reviewer-v2\reports\automatic-security-lab-docker-20261014-130258'
$continued = 'F:\(1) projects\SEC\agentic-security-reviewer-v2\reports\docker-review-resume-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
& .\.venv\Scripts\python.exe .\scripts\run_saved_review_stages.py `
  .\targets\security-lab-web `
  (Join-Path $saved 'ai-discovery.json') `
  (Join-Path $saved 'merged.json') `
  $continued `
  --profile (Join-Path $saved 'profile.json') `
  --scanner-context (Join-Path $saved 'context.json') `
  --prior-review (Join-Path $saved 'security-review.json') `
  --docker-runtime-evidence (Join-Path $saved 'docker-runtime-evidence.json') `
  --review --provider groq --model openai/gpt-oss-120b
```

Groq Security Review sends one issue group per API request. This addresses
the observed oversized three-group request under the 8K TPM tier; if an
individual group still exceeds the provider limit, it remains pending with
an explicit warning. Completion is not claimed until all eligible groups
are reviewed. Normal Groq 429 responses continue to use bounded retries.

### Re-review only selected groups from a completed saved report

If a review missed a saved runtime fact, keep the completed report unchanged
and derive a new one with `--re-review-id` (repeatable). The command requires
the original provider/model and an exact match for **all** saved issue groups;
it reuses every other verdict and refuses a pre-existing output directory.
This does not rerun Docker, scanners, or AI Discovery. After a Triage rule
change, however, old completed reviews no longer match every group exactly;
targeted re-review intentionally refuses to reuse them as though the groups
were unchanged. Use a normal saved-stage `--review` resume with the old
`--prior-review` to reuse only still-identical groups and review changed ones,
or start a new full scan later. Never edit old review JSON to force a match.

The historical October 14 command below documents the old targeted review;
it should **not** be rerun against the new Triage rules:

```powershell
$repo = 'F:\(1) projects\SEC\agentic-security-reviewer-v2'
$savedScan = Join-Path $repo 'reports\automatic-security-lab-docker-20261014-130258'
$savedReview = Join-Path $repo 'reports\docker-review-resume-20261014-164958'
$derived = Join-Path $repo ('reports\docker-targeted-review-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
& (Join-Path $repo '.venv\Scripts\python.exe') (Join-Path $repo 'scripts\run_saved_review_stages.py') `
  (Join-Path $repo 'targets\security-lab-web') `
  (Join-Path $savedScan 'ai-discovery.json') `
  (Join-Path $savedScan 'merged.json') `
  $derived `
  --profile (Join-Path $savedScan 'profile.json') `
  --scanner-context (Join-Path $savedScan 'context.json') `
  --prior-review (Join-Path $savedReview 'security-review.json') `
  --docker-runtime-evidence (Join-Path $savedScan 'docker-runtime-evidence.json') `
  --re-review-id merged-b0c02faa1b86ad4020d7 `
  --re-review-id merged-47d352c10702d005ff7f `
  --re-review-id merged-553fc2269771ce1811f3 `
  --review --provider groq --model openai/gpt-oss-120b
```

Run it only in a PowerShell session with `GROQ_API_KEY` already set. The
review prompt now distinguishes POST `/upload` from the separate GET of its
saved test file, and tells the reviewer to consider the source-hash-matched
login guard check alongside the bounded HTTP attempts. It does **not** force
any verdict: a fresh model response may still be inconclusive, and the path
traversal group still has no DAST exploitation probe. A new scan records an
explicit boolean for whether the upload test marker appeared in the served
body; older saved evidence remains usable through the trusted probe contract.

Adding a Dockerfile makes the profiler record an image-scan opportunity.
Trivy's applicable dependency/configuration tasks are still required and run;
the image task remains explicitly `not_applicable` until a separate built
image scan is implemented. A non-applicable image task is reported as a
coverage limit, not misreported as a failed Trivy installation.

Docker may retain the built image and build cache after the temporary
containers and volumes are removed. Image building may need network access to
fetch the Python base image and pinned Flask dependency. The test web port is
loopback-only, but this does not mean the Docker engine or image build is
networkless. Docker Desktop on Windows also has a shared Linux backend; this
is not a new disposable VM for every scan.

The current fixed probes are **not** generic DAST for arbitrary applications.
For another trusted project, the developer must supply and review a runnable
test environment or authorized test URL; unsupported routes and workflows
remain coverage gaps. Do not mark a third-party repository `trusted_lab`
merely to bypass the execution restriction.
