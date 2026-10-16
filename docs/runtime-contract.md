# Runtime Contract

A Runtime Contract is a small JSON file kept outside the project being
scanned. It is the explicit authorization and safety boundary for the full
project pipeline. The pipeline does not discover a contract inside untrusted
source and does not infer a start command.

## Current supported mode

The generic project entry point currently supports an already-running local
HTTP target (`mode: existing_url`). The target must bind to a loopback address,
use an explicit port, and be authorized by the person running the scan.

The generic DAST stage is bounded and non-mutating. It checks the declared
health path, selected endpoint paths, common response security headers, cookie
attributes, and server-error responses. It does not perform browser crawling,
credentialed authorization workflows, or exploit confirmation.

Copy `examples/runtime-contract.json` outside the target project and edit the
URL and paths. Keep `authorized_for_testing: true` only when the target is
owned by, or explicitly authorized to, the person running the scan.

## Deliberate limitations

- `checks.authorization: true` is not supported by the generic adapter yet;
  use a project-specific authorization adapter.
- `checks.mutating: true` is rejected by the generic adapter. Mutating checks
  need a disposable target and a separate opt-in implementation.
- `mode: docker_compose` remains restricted to the reviewed trusted lab path;
  arbitrary project Compose execution requires the VM worker until a stronger
  sandbox policy is approved.
- A completed generic DAST run proves only that these bounded probes completed;
  it does not prove that every endpoint or vulnerability was tested.
