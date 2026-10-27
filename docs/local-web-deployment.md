# Local Web Deployment

Verdict is a single-user **localhost workspace**, not a public scanning service.
Waitress serves it on `127.0.0.1:8765`. Never expose it with port forwarding.

## Install and open

From the repository root:

```powershell
& .\scripts\install_local.ps1
```

The installer reuses the virtual environment and creates a **Verdict Security
Reviewer** desktop shortcut. Open it to start the UI without a terminal.
An older server using port 8765 must be stopped first; the launcher does not
kill unknown processes. The terminal launcher remains available.

Optional components:

```powershell
& .\scripts\install_local.ps1 -InstallSemgrep -InstallZap
```

This installs the verified Semgrep version and downloads the official ZAP image.
Docker Desktop, CodeQL, Gitleaks and Trivy remain external prerequisites.
Existing installations are reused. System setup detects executables; scan
preflight verifies supported versions and configuration.

For optional JavaScript/SPA coverage, install Playwright and its Chromium
browser. If it is absent, the run continues safely and records a browser
coverage gap instead of claiming a browser crawl.

```powershell
npm install --save-dev playwright
npx playwright install chromium
```

## First use

1. Check **System setup**, Docker and the CodeQL bundle path.
2. Choose Groq or a running local Ollama model. Save the Groq key in the OS
   credential vault, or supply GROQ_API_KEY in the launching environment.
   No plaintext vault fallback is allowed.
3. Select the educational app or your local source directory.
4. Use **Detect runtime setup**, review it, and confirm trust and authorization.
   Detection reads files without executing them. It recognizes common Python
   and Node routes plus OpenAPI JSON/YAML and lists coverage gaps.
5. If account or business coverage is wanted, enable the guided contract and
   use **Generate a reviewable draft**. It creates safe GET setup steps only;
   review every expected status, account and business assertion.
6. Select the optional bounded browser crawl for JavaScript applications.
   It visits same-origin links and never submits forms or clicks controls.
7. Save the project and start. A full scan never silently drops DAST.

## Runtime modes

| Mode | Startup and coverage |
| --- | --- |
| Educational Docker | Fixed trusted fixture, HTTP/two-user probes, optional ZAP, cleanup |
| My app: running URL | Authorized loopback HTTP app; baseline checks and optional passive ZAP |
| My app: trusted Compose | Validated approved recipe, temporary stack, baseline/optional ZAP, cleanup |
| My app: generated template | Temporary copy for simple Flask, FastAPI or Express |
| Static only | Four required scanners and both AI stages; explicitly no DAST |

Templates support root requirements.txt with a Python module:app entrypoint,
or Express with package-lock.json, npm start, and listening on PORT=8080 and
0.0.0.0. Databases, native build dependencies, OAuth and complex deployments
need a reviewed Compose setup or running URL. Temporary copies exclude .env,
private key files, dependency folders and Git metadata. Changed source invalidates
template runtime results. Generated configuration is not production attestation.

Compose rejects privileged containers, host bind mounts, Docker socket mounts,
external resources and unsupported host access. Docker is for trusted code,
not an isolation boundary for hostile repositories.

## ZAP and login

- Baseline retains existing bounded checks.
- ZAP passive adds traditional crawling and passive analysis.
- ZAP active requires explicit approval and a disposable Compose target.
  Active tests may change data; they are blocked for existing-URL targets.

The locally installed official image is resolved to its content ID for each run.
It joins the identified app container network namespace, or reaches a running
local app through Docker Desktop's host gateway. It never receives a Docker
socket. Crawling and active scans have explicit time/depth limits. The optional
browser crawl adds same-origin JavaScript rendering, but does not prove generic
IDOR or business-workflow correctness.

Optional form login takes a relative login path, field names and logged-in
response regex. Test credentials live in the OS vault. ZAP must observe a response
matching the logged-in indicator during crawling; failed verification never silently becomes authenticated coverage.
MFA, OAuth and complex JavaScript sessions need dedicated workflows. Use disposable
accounts and data. Application-generated redirects and server-side behavior still
require a trusted test environment; this is not a hostile-code sandbox.

## Jobs and recovery

SQLite state defaults to `%USERPROFILE%\VerdictSecurityReviewer\verdict.db`;
reports default to its reports subfolder. VERDICT_DATA_ROOT and
SECURITY_REVIEWER_REPORT_ROOT override those locations.

The worker is independent of the browser and web server. One job runs at a time.
Cancel stops its process tree and removes only its registered, uniquely named
Docker resources. It never uses Docker prune. Failed cleanup stays visible and
blocks new jobs until recovery.

After a crash, **Recover interrupted worker** checks PID and creation time before
stopping an orphan process. **Resume saved AI** verifies source fingerprints,
uses a new derived folder, and reuses compatible completed AI work. It does not
rerun Docker or scanners. Missing static artifacts or changed source require a
new scan. Incomplete discovery may be rerun and consume AI quota.

## Workspace navigation and history

The sidebar separates **My projects**, **New review**, **Review history**,
**Review results** (after opening a report), and **System setup**. Review setup
groups source, application runtime, web checks, business workflows and analysis
settings in separate cards. Advanced settings and individual workflow/account
editors expand on demand; existing saved values are retained.

In **Review history**, **Remove from history** removes one finished entry and
**Clear finished history** removes all finished entries from the main list after
confirmation. **Removed reviews → Restore to history** restores an entry.
This is reversible history management, not disk cleanup: report files, project
settings and comparison evidence remain unchanged. Running, queued, cancelling
and cleanup-failed jobs cannot be hidden. Removing a history entry does not
cancel a job or delete Docker resources.

## Reports and local security

Results separate observations, verdicts, evidence, remediation, limitations,
policy, pending work and coverage gaps. ZIP exports selected report artifacts,
not arbitrary workspace files or credentials. Reports can contain sensitive code;
review them before sharing.

Each completed report directory contains `security-review-report.md` and a
standalone `security-review-report.html`. Open the HTML file in a browser to
search and filter findings; it needs no internet connection. Both formats are
included in the ZIP export.

Every run also contains `coverage-summary.json`. It separates HTTP probes, ZAP
alerts, browser pages and declared workflow steps, and lists what was not tested.

Comparison uses stable issue IDs from the prior completed run of the same saved
project and mode. **No longer observed is not proof of a fix**: scope, coverage,
runtime, tools and AI behavior may differ.

The UI verifies Host, Origin and a per-server write token, blocks cross-site
access, escapes report content and serves raw files as downloads. This is not
multi-user authentication. Workers have the local developer's privileges;
other processes running as that user are not isolated.
