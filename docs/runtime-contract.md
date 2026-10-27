# Runtime Contract

A Runtime Contract is a small JSON file kept outside the project being
scanned. It is the explicit authorization and safety boundary for the full
project pipeline. The pipeline does not discover a contract inside untrusted
source and does not infer a start command.

## Current supported modes

The generic project entry point supports an already-running local HTTP target
(`mode: existing_url`). The target must bind to a loopback address, use an
explicit port, and be authorized by the person running the scan. Through the
local UI, a developer may also explicitly trust their own project and choose
`mode: docker_compose` with `trust_level: trusted_local_project`. This requires
the entrypoint's `--allow-trusted-local-compose` opt-in, a reviewed Compose
configuration and a loopback-published application port. Merely finding a
Compose file in a repository does not authorize execution.

The generic baseline DAST stage is bounded and uses GET requests. It checks the declared
health path, selected endpoint paths, common response security headers, cookie
attributes, and server-error responses. It does not perform browser crawling,
credentialed authorization workflows, or exploit confirmation by itself. The
optional browser crawl renders same-origin JavaScript pages when Playwright is
installed, but never submits forms or clicks controls. Choose
paths that are safe to visit: HTTP GET is not proof that an application has no side effects.

An optional `workflow_suite` adds declarative multi-account and business-rule
tests in the same runtime session, before teardown. It supports JSON/form login,
bearer tokens or cookies, explicit identity verification, sequential HTTP steps,
scalar captures, expected statuses and JSON assertions. Write steps require an
explicitly approved disposable Compose environment. Existing local applications
support read-only workflow steps (login requests are the necessary exception).

The local UI can also create this contract from fields or generate a temporary
Flask/FastAPI/Express startup template after explicit trust approval. Optional
ZAP crawling/passive analysis and active scanning are separate engine selections,
not changes to the baseline contract flags. Active ZAP requires a disposable
Compose target and explicit approval. Simple form login is supported through
separate settings and OS-vault test credentials; it is not generic IDOR testing.
Route discovery recognizes common Python/Node declarations and OpenAPI
JSON/YAML. **Generate a reviewable draft** turns safe discovered GET routes into
setup steps; it never invents credentials or business rules. See
`local-web-deployment.md` for scope and limitations.

Copy `examples/runtime-contract.json` outside the target project and edit the
URL and paths. Keep `authorized_for_testing: true` only when the target is
owned by, or explicitly authorized to, the person running the scan.

## Deliberate limitations

- Legacy `checks.authorization: true` and `checks.mutating: true` are still
  rejected by the generic baseline adapter. Configure `workflow_suite` instead;
  these flags do not silently enable unrestricted testing.
- Guided workflows currently support existing URLs and explicitly trusted
  Compose projects, not generated startup recipes. OAuth/MFA, browser form
  actions, GraphQL/WebSocket protocols, arbitrary reset commands,
  concurrency/race tests and file uploads are not implemented by this runner;
  discovery records these as explicit coverage gaps when detected.
- `fresh_stack` means one fresh stack per run, not per workflow. Create independent
  data in each workflow; cross-workflow contamination is otherwise possible.
- Unknown or untrusted project Compose execution is unsupported on this host.
  The trusted-local option is an explicit developer choice and does not make
  Docker a safe isolation boundary for hostile code.
- A completed generic DAST run proves only that these bounded probes completed;
  it does not prove that every endpoint or vulnerability was tested.

## Build a contract in the local UI

1. Select **My app · DAST + Static + AI**, choose a project directory, and click
   **Detect runtime setup**. Discovery reads Python route declarations and local
   OpenAPI JSON/YAML; it does not execute source or read benchmark answers. Confirm
   suggested URL, Compose service, health path, status and endpoint paths.
2. For the multi-service lab select **Start my trusted Docker Compose project**,
   `compose.yaml`, service `api`, URL `http://127.0.0.1:8090`, health `/healthz`,
   status `200`. Approve project trust and testing authorization.
3. Enable **Include account and business-workflow tests**. In **1. Discover**, use
   **Load editable order-service example** for this lab. It contains expected
   product rules, not the benchmark answers; review rules before testing other apps.
4. In **2. Accounts**, configure aliases, login format and session handling. The
   example uses `user_a`, `user_b`, `admin`, JSON POST `/auth/login`, fields
   `username`/`password`, bearer field `access_token`, verification GET `/me`,
   identity field `username`. HTTP 200 at login alone is not accepted as proof.
5. In **3. Workflows**, define setup steps and security assertions. For example:
   create an order as user A, capture its `id` as `order_id`, then GET
   `/orders/{{order_id}}` as user B expecting `403` or `404`. Request body, capture
   mappings and JSON assertions are optional advanced fields. Captures belong to
   their workflow and must be declared before use.
6. In **4. Limits & reset**, choose request/time limits and explicitly approve
   data changes for write workflows. Use **Fresh disposable Compose stack per
   run** for the lab. The runner cleans up only its own environment.
7. In **5. Validate & save**, validate structure and save the project. Return to
   **Accounts** and save each username/password in the OS vault. Credentials are
   not stored in the project or exported contract. For this disposable lab the
   fake passwords are `UserA-Lab-Only-1`, `UserB-Lab-Only-1`, `Admin-Lab-Only-1`.
8. Choose analysis settings and click **Start review**. Baseline plus workflows
   works without ZAP. ZAP is additional coverage; its separate simple form-login
   settings do not inherit these bearer accounts. Do not enable ZAP form login
   for this lab merely because a workflow account was configured.

The UI saves structured settings and generates the JSON contract outside the
target. **Download Runtime Contract** exports it without credentials. CLI users
provide referenced accounts through `SECURITY_TEST_WF_USER_A_USERNAME` and
`SECURITY_TEST_WF_USER_A_PASSWORD` (replace USER_A with the uppercase alias).

## Read the results correctly

The report's DAST panel shows declared/executed steps, rule violations, unresolved
steps, and account verification. `workflow-evidence.json` is included in report
exports, and its observations enter normalization and the ordinary review pipeline.
Raw response bodies, bearer tokens, passwords and capture values are not saved
in workflow evidence. Do not put secrets directly in request-body configuration.

Failed login, setup failures, unexpected server errors and exhausted budgets
produce explicit incomplete coverage, not a security pass. A rule violation is
an observation for review, not automatic proof of an exploitable vulnerability.
AI-only resume cannot repair failed runtime steps; that requires a new runtime run.

The editable lab example currently contains 13 workflows and 28 steps. This is
coverage of declared business rules, not a claim that all 18 benchmark scenarios
or all vulnerabilities are detected. Benchmark evaluation remains separate.
