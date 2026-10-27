# Local Test Environment

The pipeline can run bounded runtime checks when an authorized test
application is available. The launcher below executes `app.py` directly on
the Windows host, so it is **only for a reviewed, trusted educational lab**.
Never use it for a repository supplied by an unknown user. There is no built-in
worker for running untrusted repositories; source-only review remains available
for those projects.
Never point these checks at production.

## Start a target

From PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process RemoteSigned
.\scripts\start_test_env.ps1 -AppPath 'C:\path\to\trusted-lab' -Port 5000 -Python 'python' -TrustedLab
```

The launcher sets `SECURITY_REVIEWER_RUNTIME_URL` for the current terminal and
starts the target. Prepare disposable test accounts and data for your own
trusted lab if its runtime checks require them.

In a second terminal, pass the URL explicitly: environment variables set by
the launcher are local to its own PowerShell session.

```powershell
.venv\Scripts\python.exe scripts\run_pre_review_pipeline.py `
  'C:\path\to\trusted-lab' `
  --output reports\trusted-lab-full-runtime `
  --runtime-url 'http://127.0.0.1:5000' `
  --codeql-bundle 'C:\path\to\codeql' `
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
