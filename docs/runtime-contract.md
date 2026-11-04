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
installed, but never submits forms or clicks controls. For a trusted Compose
workflow run it starts automatically, verifies each configured test account,
and crawls with isolated bearer or cookie sessions. It records methods, paths,
and status codes without storing credentials, tokens, query values, or response
bodies. Choose
paths that are safe to visit: HTTP GET is not proof that an application has no side effects.

A reviewed `discovery-test-plan.json` from an earlier scan can be passed as
`--approved-discovery-plan PATH` with an approved disposable Compose contract.
The target snapshot must still match. Verdict probes at most 20 current,
source-declared GET paths without parameters or query strings and writes
`approved-discovery-probes.json` with observed statuses. This flag does not
authorize write proposals or infer expected authorization outcomes; those
remain explicit `workflow_suite` rules.

An optional `workflow_suite` adds declarative multi-account and business-rule
tests in the same runtime session, before teardown. It supports JSON/form login,
bearer tokens or cookies, explicit identity verification, sequential HTTP steps,
scalar captures, expected statuses, JSON assertions and literal response-header/text
assertions. A step may use `wait_before_seconds` (0–10) before a bounded GET
to allow an asynchronous worker to settle; it is not an unbounded poll.
An explicit `lockout_after_failures` (2–10) on an anonymous POST security
step checks a declared 423/429 response after that many identical prior
401 login attempts. A 401 then means this declared threshold did not trigger;
it is not proof that the endpoint has no rate limit under all conditions.
On an explicitly approved disposable target only, a security step may declare
`auth_probe` with `kind: numbered_cookie` (a bounded cookie name, prefix, and
number) or `kind: unsigned_jwt` (bounded scalar test claims). The runner
generates the synthetic credential in memory and records only the probe kind,
not the generated cookie or token. This is a narrow negative test of the
application's rejection behavior, not a general credential attack.
Write steps run automatically when the selected trusted Compose target and
workflow contract define them; the UI sets `allow_mutation` and `fresh_stack`
from those steps. CLI contracts must still declare these fields explicitly.
Existing local applications
support read-only workflow steps (login requests are the necessary exception).

The local UI can also create this contract from fields or generate a temporary
Flask/FastAPI/Express startup template after explicit trust approval. Optional
ZAP crawling/passive analysis and active scanning are separate engine selections,
not changes to the baseline contract flags. Active ZAP requires a disposable
Compose target. Simple form login is supported through
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
  concurrency/race tests and multi-file or large-file uploads are not implemented by this runner;
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
   mappings, JSON assertions and response assertions are optional advanced
   fields. Captures belong to
   their workflow and must be declared before use.
   Response assertions accept `header_present`, `header_absent`,
   `header_contains`, `header_not_contains`, `body_contains` and
   `body_not_contains`. They compare literal text, not regular expressions.
   For example, a `body_not_contains` check can assert that an inert database
   column marker is absent from an error response. Do not put real secrets in
   these saved rules.
   A multipart step can upload one inline test file using `field`, `filename`,
   `content_type` and `content` (at most 4 KiB), then capture its response ID
   and check how the application serves it. This is available only for an
   approved, disposable Compose run. It does not read arbitrary local files.
6. In **4. Limits & reset**, choose request/time limits. Write steps on the
   trusted disposable Compose target automatically use a fresh stack. The
   runner cleans up only its own environment.
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
in workflow evidence. `assertion_checks` records each condition's type, field,
operator and pass/fail/unknown result, but never its actual response value.
The workflow title describes the desired safe rule; a `violation` means that
at least one declared security expectation failed, not that the title happened.
Do not put secrets directly in request-body configuration.
Declared endpoint GETs also check cookie attributes and Content-Security-Policy
on HTML responses; supplying only a health path does not cover other routes.

Failed login, setup failures, unexpected server errors and exhausted budgets
produce explicit incomplete coverage, not a security pass. A rule violation is
an observation for review, not automatic proof of an exploitable vulnerability.
AI-only resume cannot repair failed runtime steps; that requires a new runtime run.

The editable lab example currently contains 13 workflows and 28 steps. This is
coverage of declared business rules, not a claim that all 18 benchmark scenarios
or all vulnerabilities are detected. Benchmark evaluation remains separate.
