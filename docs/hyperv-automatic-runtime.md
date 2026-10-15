# Automatic isolated SAST + DAST for Security Lab Web

The completed manual pilot proved clone/start/local health/report/cleanup. This
next mode removes the per-scan Ubuntu console steps for the **fixed educational
Security Lab Web target only**. It is not a generic arbitrary-repository
executor. A one-time trusted service must first be installed in the permanent
Ubuntu base; its existing `Ubuntu-Docker-Ready` checkpoint is retained and a
new `Ubuntu-AutoScan-Ready` checkpoint is created.

The worker has **no Hyper-V virtual switch**. It starts the app on guest
loopback as the unprivileged `nobody` account, performs bounded web and
two-user authorization probes from trusted code inside the guest, saves the
results to the exchange disk, and powers off. The Windows runner verifies the
report and output hashes, removes only the disposable worker, then runs host
static scanners and imports the DAST evidence. No guest runtime URL is exposed
to Windows. For this fixed disposable educational target, bounded stored-XSS
and HTML-upload probes are enabled by default; the throwaway worker is removed
after the scan and the permanent base is never written by those probes.
The disposable fixed-target worker starts with 4 GiB RAM to fit this host;
the permanent base VM and its checkpoints retain their original 6 GiB setting.
The finalizer also checks that the guest used the same reviewed worker and
scanner script bytes as the host checkout. If those scripts change, update
the base service and create a new ready checkpoint before the next run.

## One-time trusted base setup

Use **Administrator PowerShell** for the Windows commands. The base VM must
start Off with its adapter disconnected. Never copy the target repository or
ground truth into the base.

1. Run `scripts/connect_hyperv_base_for_provisioning.ps1`. This temporarily
   starts the trusted base on the Default Switch for installation only.
2. In the base VM console, find its current IPv4 address using `hostname -I`.
   Run `scripts/install_hyperv_autoscan_base.ps1 -GuestAddress <IPv4>` from
   Administrator PowerShell. It copies only the trusted worker/scanner scripts
   via SSH/SCP and runs the Ubuntu installer with `sudo`. Enter passwords only
   in the SSH prompt, never in a project file or chat.
3. In Ubuntu, verify `systemctl is-enabled hyperv-autoscan.service` says
   `enabled`, then run `sudo poweroff`. Confirm the base VM is **Off**.
4. Run `scripts/disconnect_hyperv_base_after_provisioning.ps1` and verify its
   network adapter has no switch.
5. Run `scripts/create_hyperv_autoscan_checkpoint.ps1 -VmStorageRoot
   'F:\(1) projects\SEC\vm'`. It creates `Ubuntu-AutoScan-Ready` without
   deleting the earlier checkpoint.

Do not run the automatic pipeline until step 5 succeeds. These are one-time
setup actions; the normal scan command does not ask for Ubuntu console input.

## Each later scan

From Administrator PowerShell, choose a **new** output directory:

```powershell
& 'F:\(1) projects\SEC\agentic-security-reviewer-v2\scripts\run_hyperv_automatic_pipeline.ps1' `
  -VmStorageRoot 'F:\(1) projects\SEC\vm' `
  -WheelDirectory 'F:\(1) projects\SEC\vm\pilot-wheels' `
  -OutputDirectory 'F:\(1) projects\SEC\agentic-security-reviewer-v2\reports\automatic-security-lab-001'
```

The automatic fixed-target command includes the two bounded mutating probes.
To omit them for a diagnostic run, pass `-RuntimeMutating:$false`; the report
will then record that those cases were not exercised. This default must not be
copied to arbitrary projects without explicit target authorization and a
disposable test environment. AI Discovery runs on every full scan; the default is Groq
`openai/gpt-oss-120b`, requiring `GROQ_API_KEY` in the Administrator PowerShell
process environment. Configure that key through a secret manager or private
prompt, never on the command line or in the project. For local AI, pass
`-AiProvider ollama` and ensure its model service is running. `-AiDiscovery`
is a legacy compatibility switch and has no effect. `-CodeQLBundle` and
`-AiModel` remain optional. The wrapper now locates the installed CodeQL bundle
at `F:\(1) projects\SEC\tools\codeql-2.27.1\codeql` by default; use
`-CodeQLBundle` to select another bundle. Semgrep, CodeQL, Gitleaks, and Trivy
are all required for this fixed-target automatic scan. Before starting the VM,
the wrapper verifies that each planned scanner has a registered adapter and
available local prerequisites. Missing or unverified prerequisites stop the
run without creating a worker. A run ID is generated automatically. The wrapper
waits up to 20 minutes
for the guest to power off. On a timeout it powers off and **preserves** the
worker for diagnosis; it does not silently report successful DAST.

Completed guest artifacts are stored in `reports/hyperv-autoscan/<run-id>/`.
The final pipeline output contains `runtime.json`, `authorization.json`, their
normalized findings, `isolated-runtime-evidence.json`, and the usual static,
AI Discovery, policy, and report files. The automatic pipeline requires all four
scanner tasks to complete with normalized output, as well as completed guest
DAST. If a scanner fails after the preflight, the retained report is marked
`partial` with `scanner_requirement.satisfied=false` and the command exits
nonzero. Missing prerequisites or invalid evidence stop the run, never becoming
a clean result. If required AI
Discovery does not complete its planned inspection, the command exits nonzero
and retains an incomplete report with the scanner and DAST observations.
For Groq models using strict JSON schema, a content-dependent HTTP 400 now
triggers one bounded JSON-object fallback. The fallback is validated locally
against the discovery response shape; malformed output still leaves the run
incomplete. It never falls back for authentication or rate-limit errors.
The human-readable report lists every merged scanner and DAST observation even
when AI Discovery is blocked. It keeps those pre-review signals separate from
Security Review Agent verdicts and explicitly shows incomplete review status.
Bounded, allowlisted runtime facts (for example cross-account status codes and
whether responses matched) now survive normalization and appear in the report
and review input without response bodies, cookies, or secret values. A unique
Flask route match also contributes bounded source context; ambiguous routes
remain unresolved instead of being guessed. Source-code proximity alone is
not treated as proof of exploitability.
At issue-triage time, exact same-line/same-family alerts and SQL source alerts
explicitly present in one CodeQL sink flow can share one review group. Distinct
routes, different vulnerability families, ambiguous flows, and different sink
paths remain separate. Every original scanner record is still retained and
linked in the group; policy decisions apply to review groups rather than a
misleading raw-alert count.

For the isolated educational fixture only, the host can corroborate the
existing bounded login probe with the exact `app.py` bytes attested by the
guest. It checks the direct login handler and registered hooks conservatively;
an unfamiliar source shape, a changed source hash, or a blocked login response
leaves the case inconclusive. The extra facts appear in
`login-source-corroboration.json` and in that one normalized finding. The raw
guest `runtime.json`, other findings, and the ready checkpoint are unchanged.
Five unsuccessful requests plus this source review describe this isolated
fixture, not an assurance about external rate limits in another deployment.

After a completed scan, measure the educational fixture separately:

```powershell
& 'F:\(1) projects\SEC\agentic-security-reviewer-v2\.venv\Scripts\python.exe' `
  'F:\(1) projects\SEC\agentic-security-reviewer-v2\scripts\evaluate_security_lab_15.py' `
  '<the new scan output directory>'
```

This post-scan audit maps each of the 15 cases to an exact endpoint or source
anchor and the final review verdict. It never provides the ground-truth file
to the scanners or AI stages, and it does not claim precision or F1 from a
positive-only fixture. The latest saved baseline, `e56ac670`, remains 14
detected, 1 with insufficient evidence, and 0 not detected. A new host review
of that verified guest run, or a new full scan, is needed to measure the
effect of the login-source corroboration; it never retroactively edits the
saved report.

## Deliberate limits

- Only the reviewed Security Lab Web target and its staged Python wheels are
  supported. Unknown repositories still need an explicit startup/dependency,
  seed-data, account, and allowed-test manifest; they must not execute on the
  Windows host by fallback.
- The DAST probes are fixed HTTP checks, not full browser crawling or proof of
  exploitability. Negative probes do not prove absence of vulnerabilities.
- The one-time base setup and the initial fixed-target automatic scan were
  verified in run `f817b3cd`. That historical run predates mandatory AI
  Discovery; it does not demonstrate the new AI completion requirement.
