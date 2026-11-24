# LangSmith tracing for the local web app

LangSmith is for observing and comparing the LangGraph AI stages. It does not
run Semgrep, CodeQL, Gitleaks, Trivy or DAST, and it does not calculate the
security benchmark's precision or recall by itself. The local web launcher
enables tracing by default; you can explicitly turn it off for a launch.

## Set up on Windows

1. Create a LangSmith account at
   [smith.langchain.com](https://smith.langchain.com), then create a key in
   Settings > API Keys. A **Tracing Only** key has fewer permissions. If you
   need a **Personal Access Token**, that also works, but keep it private.
2. Open PowerShell in this repository and install the local environment if
   needed: `& .\scripts\install_local.ps1`.
3. To save the key in the Windows OS credential vault, run this from the
   repository root. The prompt calls it a "Password" because that is the
   vault tool's generic label; paste the LangSmith key there. No characters
   will appear while you type.

   ```powershell
   & .\.venv\Scripts\python.exe -m keyring set VerdictSecurityReviewer langsmith
   ```

   If your terminal cannot paste at the hidden prompt, copy the token in
   LangSmith, then run `& .\scripts\save_langsmith_from_clipboard.ps1` instead.
   This reads a single token from the clipboard without displaying it, saves
   it in the OS vault, and clears the clipboard after a successful save.

   If an old `LANGSMITH_API_KEY` is already set in this PowerShell window,
   remove that session variable so the new vault key is used:

   ```powershell
   Remove-Item Env:LANGSMITH_API_KEY -ErrorAction SilentlyContinue
   ```

4. Start the local UI:

   ```powershell
   & .\scripts\start_local_web.ps1 -Port 8770
   ```

   The launcher automatically enables LangSmith. If `LANGSMITH_API_KEY` is not
   already set in this PowerShell window, it reads the key from the OS vault;
   if the vault has no key, it prompts with hidden input for this session only.
   The key is not written to a project file. It is inherited by child scan
   workers.
5. Open `http://127.0.0.1:8770`, start a review, then view its LangGraph
   traces in the `Verdict-Security-Reviewer-Agent-local` tracing project in
   LangSmith. If the UI was already running, stop and restart it after saving
   the new key.

For CLI-only work, run `& .\scripts\enable_langsmith.ps1` before the pipeline
command in the same shell. For a different project name, pass
`-Project 'My-Project'` to that enable script before launching the UI.
To start the web UI without LangSmith, run
`& .\scripts\start_local_web.ps1 -Port 8770 -NoLangSmith`.
If your LangSmith account is outside the default US region, set its official
`LANGSMITH_ENDPOINT` before enabling tracing. For API keys that belong to
multiple workspaces, you may also need `LANGSMITH_WORKSPACE_ID`.

## Security and limitations

The web launcher calls the enable script by default. That script sets `LANGSMITH_HIDE_INPUTS=true`,
`LANGSMITH_HIDE_OUTPUTS=true`, and `LANGSMITH_HIDE_METADATA=true` **before**
`LANGSMITH_TRACING=true`. This prevents graph state, source snippets, findings,
prompts, responses and metadata from being sent as trace payloads. Run names,
timing and error information may still be sent to LangSmith; do not enable
cloud tracing if even those details are sensitive. With hidden payloads,
LangSmith is useful for stage sequence and latency, but cannot inspect the
full reasoning or evidence behind a verdict.

The project's model provider calls are made by custom Python code, not a
LangChain model wrapper. LangSmith will show the LangGraph stage spans, but
not a detailed nested LLM-request trace unless a separately reviewed model
wrapper is added later. Existing local JSON reports remain the source of
truth for security evidence and evaluation metrics.

To stop tracing in the current window:

```powershell
$env:LANGSMITH_TRACING = 'false'
```

Close the window to discard the session-only API key; never place it in a
committed `.env` file or PowerShell profile. No live cloud connection is
verified by installation alone: the first trace appears only after you run
an agent stage with a valid key.

## Running from WSL / Linux (why traces may not appear)

Variables set in a Windows PowerShell session, and the key stored in the Windows credential vault,
are **not visible** to a pipeline started inside WSL. The scripts now read an optional, git-ignored
`.env` in the repository root (only `LANGSMITH_*`, `LANGCHAIN_*`, `GROQ_*`, `SECURITY_REVIEWER_*` and
`TRIVY_*` names; real environment variables always win):

```
LANGSMITH_TRACING=true
LANGSMITH_API_KEY=lsv2_...
LANGSMITH_PROJECT=security-reviewer-v2
# EU region or an org-scoped key:
# LANGSMITH_ENDPOINT=https://eu.api.smith.langchain.com
# LANGSMITH_WORKSPACE_ID=...
```

Every run prints one line, `LangSmith tracing: ON (...)` or `OFF - missing ...`, so a missing key is never
silent. Both agents are grouped under one `pre-review-pipeline` trace and queued spans are flushed before exit.

## Large runs: keeping uploads small and non-blocking

* `metadata` / `redacted` modes send only the first 40 entries of any large list/dict (plus a count) and at most 8 nesting
  levels, because LangGraph traces every node with the whole graph state. Tune with `SECURITY_REVIEWER_TRACE_MAX_ITEMS`
  (`full` mode is not capped).
* Upload batches default to 128 KB (`SECURITY_REVIEWER_LANGSMITH_BATCH_BYTES`) with a 120 s read timeout
  (`SECURITY_REVIEWER_LANGSMITH_TIMEOUT_SECONDS`).
* The end-of-run flush waits at most 30 s (`SECURITY_REVIEWER_LANGSMITH_FLUSH_SECONDS`); undelivered traces are dropped with a
  warning and never affect the review result.
