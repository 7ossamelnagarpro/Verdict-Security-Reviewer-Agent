# Educational IDOR/Authorization Probe

`idor-dast` is a local, read-only differential probe. It is intentionally
separate from source scanners because IDOR is a runtime authorization property.

The Flask marketplace fixture exposes two routes:

- `/idor/vulnerable/orders/<id>` ignores `X-Test-User`.
- `/idor/safe/orders/<id>` checks ownership.

Run the fixture locally, then execute the probe with two synthetic identities:

```powershell
python -m flask --app app:create_app run --host 127.0.0.1 --port 5055 --no-debugger --no-reload
python -m security_reviewer_v2.scanners.idor `
  --config idor-probe-config.json `
  --output scans/idor-dast-result.json
python -m security_reviewer_v2.normalization.cli `
  scans/idor-dast-result.json `
  scans/normalized/idor-dast-result.normalized.json `
  --scanner idor
```

The probe compares User B's authorized response with User A's cross-user
response. A matching successful response is reported as `CWE-639`. It performs
GET requests only and is intended for an owned local/staging target with fake
accounts. Missing runtime access is represented as a blocked prerequisite in
the orchestrator; it is never interpreted as “safe”.

## Profiler opt-in

Adding a `security-review-runtime.json` manifest makes the Profiler add an
`idor-dast` task to the Scan Plan. The Profiler does not start the application
or read credential values. The runtime adapter remains responsible for loading
synthetic identities from the configured environment and verifying reachability.
