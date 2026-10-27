# Explicit Test Environment Manager (first version)

This component accepts a **user-supplied** JSON configuration. It never loads
startup instructions from an unknown repository automatically. The Project
Profiler inventories the repository; the environment planner checks the
selected Compose file against that inventory and reports missing prerequisites.
Profiling and planning do not build or run the target.

Two modes are supported:

1. `existing_url`: validate an already-running application on a literal
   loopback HTTP address with a GET health check. No build is needed.
2. `docker_compose`: validate a user-selected Compose file and, only with an
   explicit execution flag, start the stack, check readiness, and tear down
   that uniquely named stack when the session ends. The Compose recipe must
   be reviewed by its owner and explicitly marked `trusted_lab` or
   `trusted_local_project`. Untrusted projects are rejected; this application
   has no worker for executing them. Docker is required; no Docker installation
   is performed here.

The configuration must be **outside** the scanned project root. For example,
[`examples/security-lab-web-test-environment.json`](../examples/security-lab-web-test-environment.json)
describes an already-running local educational target. It contains no
passwords. Accounts, if needed, use `SECURITY_TEST_*` environment-variable
**names**; values are never saved in the plan or passed to an AI model.

To create a read-only plan:

```powershell
.venv\Scripts\python.exe -m security_reviewer_v2.test_environment.cli `
  targets\security-lab-web `
  --config examples\security-lab-web-test-environment.json `
  --output reports\test-environment\security-lab-web-plan.json
```

Add `--smoke-test` to check the live URL. For a Compose configuration, use
`--smoke-test --allow-compose-execution` only after reviewing the target's
recipe; that starts the stack, checks it, then removes the temporary stack.
Use `--hold --allow-compose-execution` to keep it running while a second
terminal performs the scan. Enter or Ctrl+C ends the session and attempts
cleanup. If cleanup fails, the CLI reports the unique Compose project name
for manual inspection.

Example of the Compose-specific portion of a user configuration:

```json
{
  "schema_version": "1.0",
  "mode": "docker_compose",
  "trust_level": "trusted_lab",
  "authorized_for_testing": true,
  "target": {"base_url": "http://127.0.0.1:5055", "health_path": "/", "expected_status": 200},
  "compose": {"file": "compose.test.yml", "app_service": "web"},
  "required_env": ["SECURITY_TEST_DB_PASSWORD"],
  "accounts": [
    {"role": "user_a", "username_env": "SECURITY_TEST_A_USER", "password_env": "SECURITY_TEST_A_PASSWORD"},
    {"role": "user_b", "username_env": "SECURITY_TEST_B_USER", "password_env": "SECURITY_TEST_B_PASSWORD"}
  ],
  "checks": {"authorization": true, "mutating": false}
}
```

The configured Compose application service must publish the declared port on
`127.0.0.1`. The guarded runner rejects privileged services, host bind mounts,
host networking, external networks/volumes, unsupported build privileges, and
non-loopback published ports. Only the explicitly listed `SECURITY_TEST_*`
variables and a minimal set of process variables are forwarded to Docker
Compose. A source-file hash
is checked again before startup. This is **defense in depth, not a security
boundary for untrusted code**; do not run arbitrary hostile Compose files on
the host. Use source-only review when you cannot explicitly trust a project's
runtime instructions.

This environment manager prepares and validates startup separately from the
Runtime Contract scanner. Guided contracts can run declared account and
business workflows, but they cannot infer credentials or business rules safely.
Missing prerequisites stay visible as `blocked`, not as a clean security result.

The full pipeline also accepts `--test-environment-config PATH`. It records
`test-environment-plan.json` and a summary entry alongside the Profiler output
without starting Compose or treating a blocked runtime environment as a
successful DAST scan. For the full project pipeline, supply a Runtime Contract
or use the local UI to create and review one; see [Runtime Contract](runtime-contract.md).
