# Target Application Suite

These are isolated, local-only training fixtures for the security reviewer.
They contain deliberately vulnerable and safe counterparts, fake secrets only,
and a `ground_truth.json` file describing the expected labels. They are test
inputs, not production applications and must not be deployed publicly.

| Fixture | Purpose | Main evidence |
|---|---|---|
| `verdict-comprehensive-lab` | Broader disposable multi-service target with vulnerable and safe controls | Static, DAST, guided workflows, and post-scan evaluation |

Only the comprehensive lab is bundled here. The external Juice Shop checkout
is kept separately under `F:\(1) projects\SEC\external-test-targets` and is not
part of this repository. Ground truth stays in `benchmark/`, outside the
scanned target directory.
