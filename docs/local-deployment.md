# Local deployment

The current deployment target is a developer workstation. The reviewer runs
as a local Python CLI; it is not a public web service and does not expose a
server port.

## Install

From the repository root in PowerShell:

```powershell
& .\scripts\install_local.ps1
```

Install Semgrep CE, CodeQL CLI, Gitleaks and Trivy separately. The CodeQL
bundle path is passed to each scan command. Configure `GROQ_API_KEY` only in
the current PowerShell session, or select an already-running Ollama model.

## Run

Use `--static-only` for a source-only review. A full project review requires a
Runtime Contract and therefore runs generic DAST first. See
`docs/runtime-contract.md` for the contract format.

Every run writes to a new report directory. Reports may contain source paths
and scanner evidence, but provider keys are never written to reports. Do not
commit report output or environment files containing secrets.

The fixed Security Lab Web Docker route remains a separate trusted educational
path. It is not the deployment mechanism for arbitrary repositories.
