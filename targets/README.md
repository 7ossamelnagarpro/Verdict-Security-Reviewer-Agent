# Target Application Suite

These are isolated, local-only training fixtures for the security reviewer.
They contain deliberately vulnerable and safe counterparts, fake secrets only,
and a `ground_truth.json` file describing the expected labels. They are test
inputs, not production applications and must not be deployed publicly.

| Fixture | Purpose | Main evidence |
|---|---|---|
| `security-lab-web` | Realistic educational web application with vulnerable flows | SAST, DAST, secrets, and authorization testing |
| `verdict-multi-service-lab` | Disposable FastAPI, worker, PostgreSQL, and mock-integration target | Multi-service DAST, workflow authorization, business logic, SAST, and AI discovery |
| `verdict-comprehensive-lab` | Broader disposable multi-service target with vulnerable and safe controls | Static, DAST, guided workflows, and post-scan evaluation |
| `target_app` | Minimal Python SQL-injection baseline | SAST and ground-truth evaluation |

Only the directories above are bundled. Optional Juice Shop checks in
`scripts/` require a separate, explicitly authorized local installation;
Juice Shop is not included here. Ground truth stays in `benchmark/`, outside
each scanned target directory.
