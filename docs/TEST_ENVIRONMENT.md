# Local Test Environment

The pipeline can run bounded runtime checks when an authorized test
application is available. The launcher below executes `app.py` directly on
the Windows host, so it is **only for a reviewed, trusted educational lab**.
Never use it for a repository supplied by an unknown user. The current
[disposable VM worker](hyperv-automatic-runtime.md) supports only the fixed
Security Lab Web target, not arbitrary repositories.
Never point these checks at production.

## Start a target

From PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process RemoteSigned
.\scripts\start_test_env.ps1 -AppPath 'C:\Users\jonal\OneDrive\Desktop\tt' -Port 5000 -Python 'python' -TrustedLab
```

The launcher sets `SECURITY_REVIEWER_RUNTIME_URL` for the current terminal and
starts the target. The sample `tt` application creates its own SQLite test
database and includes the synthetic users `alice/alice123`, `bob/bob123`, and
`admin/admin123`.

In a second terminal, run the pipeline normally. It will use the exported URL
without requiring `--runtime-url`:

```powershell
.venv\Scripts\python.exe scripts\run_pre_review_pipeline.py `
  'C:\Users\jonal\OneDrive\Desktop\tt' `
  --output reports\tt-full-runtime `
  --codeql-bundle 'F:\(1) projects\SEC\tools\codeql-2.27.1\codeql' `
  --ai-provider ollama --ai-model qwen2.5-coder:7b `
  --review-max-findings 20 --runtime-mutating
```

AI Discovery is required for this full scan; this example selects local Ollama.
Safe checks run automatically. `--runtime-mutating` enables the two bounded
lab-only writes (stored XSS and HTML upload); use it only with a disposable
test database. Tests that require explicit multi-user credentials remain
opt-in, so an accidental scan cannot change a target. A runtime negative
result means only that the bounded probe did not confirm the behavior; it is
not a proof of safety.
