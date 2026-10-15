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
   be reviewed by its owner and explicitly marked `trusted_lab`. Untrusted
   projects are rejected: they require a VM worker rather than Docker on the
   host. Docker is required; no Docker installation is performed here.

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
boundary equivalent to a VM**; do not run arbitrary hostile Compose files on
the host. For truly untrusted code, a dedicated disposable worker/VM is still
required.

For the stronger isolation design and a read-only host prerequisite check,
see [Hyper-V isolation](hyperv-isolation.md). A passing host check does **not**
mean a disposable VM worker has been built or tested.

The manager currently prepares and validates the environment. It does **not**
yet infer migrations or seed data, perform generic login, or turn account
references into a generic authorization matrix. The existing bounded Runtime
Scanner contains Security Lab Web-specific routes and test values, so it must
not be described as a universal DAST scanner. A user can pass the ready URL to
the existing pipeline explicitly, but generalized runtime testing is a
separate next step. Missing prerequisites stay visible as `blocked`, not as a
clean security result.

The full pipeline also accepts `--test-environment-config PATH`. It records
`test-environment-plan.json` and a summary entry alongside the Profiler output
without starting Compose or treating a blocked runtime environment as a
successful DAST scan. Startup and teardown remain explicit through the manager
CLI until a generic runtime-scanner contract is implemented.

For the fixed Security Lab Web example, a successfully completed, networkless
Hyper-V pilot can be attached with `--isolated-pilot-run-id ID`. This is a
validated historical health-smoke artifact, not automatic provisioning or
DAST. The pipeline refuses stale source fingerprints and records the remaining
dynamic-testing gap explicitly. See [Hyper-V isolation](hyperv-isolation.md).
