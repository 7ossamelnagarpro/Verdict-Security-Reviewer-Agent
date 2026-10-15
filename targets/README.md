# Target Application Suite

These are isolated, local-only training fixtures for the security reviewer.
They contain deliberately vulnerable and safe counterparts, fake secrets only,
and a `ground_truth.json` file describing the expected labels. They are test
inputs, not production applications and must not be deployed publicly.

| Fixture | Purpose | Main evidence |
|---|---|---|
| `security-lab-web` | Realistic educational web application with vulnerable flows | SAST, DAST, secrets, and authorization testing |
| `target_app` | Minimal Python SQL-injection baseline | SAST and ground-truth evaluation |
| `juice-shop` | OWASP intentionally vulnerable web application | Multi-scanner and runtime testing |
| `owasp-benchmark-java` | OWASP Benchmark Java evaluation suite | Large-scale SAST ground truth |

All target applications are kept under this directory so scan paths and
ground-truth references remain predictable.
