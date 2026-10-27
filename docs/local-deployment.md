# Local deployment

The current deployment target is a developer workstation. The reviewer runs
as a local Python CLI or a browser UI bound to `127.0.0.1:8765`. It is not a
public web service. See `docs/local-web-deployment.md` for the browser setup.

## Install

From the repository root in PowerShell:

```powershell
& .\scripts\install_local.ps1
```

CodeQL CLI, Gitleaks and Trivy are external prerequisites. The installer can
install the verified Semgrep version with `-InstallSemgrep`. Existing tools
are reused. Configure `GROQ_API_KEY` in the launching session or save a key in
the UI's OS credential vault; alternatively choose a running Ollama model.

## Run

Use `--static-only` for a source-only review. A full project review requires a
Runtime Contract (or an explicitly approved temporary startup template) and
therefore runs generic DAST first. See
`docs/runtime-contract.md` for the contract format.

Every run writes to a new report directory. Reports may contain source paths
and scanner evidence, but provider keys are never written to reports. Do not
commit report output or environment files containing secrets.

The fixed Security Lab Web Docker route remains a separate trusted educational
path. For other developer-owned projects, the UI can propose a Compose setup
and run bounded generic DAST only after explicit trust and authorization.
Execution of untrusted repositories is unsupported. Use source-only review
unless the owner has reviewed and explicitly trusted the runtime project.
