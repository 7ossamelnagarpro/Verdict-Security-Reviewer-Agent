# Trusted Docker runtime

Verdict can start the bundled `targets/security-lab-web` fixture automatically,
or start a developer-owned project through an explicitly reviewed Runtime
Contract. Neither route executes an unknown repository merely because it has a
Dockerfile or `compose.yaml`.

For the bundled educational fixture, start Docker Desktop and the four required
scanners, configure Groq or Ollama, then run from the repository root:

```powershell
$output = Join-Path (Get-Location) ('reports\docker-lab-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
& .\.venv\Scripts\python.exe .\scripts\run_docker_automatic_pipeline.py --output $output
```

This entrypoint validates scanner readiness and the pinned lab recipe before
starting a uniquely named Compose stack on host loopback. It runs bounded web
and authorization checks, records source-linked evidence, removes its own stack
and volumes, then runs the four scanners and two AI stages. Failed startup,
checks, or cleanup must not be reported as a completed review.

For another project, use the local UI or
[`runtime-contract.md`](runtime-contract.md) to declare the Compose file, app
service, loopback URL, health check and any account/workflow tests. Only
explicitly trusted projects may be built and started here. ZAP and browser
coverage are optional, bounded additions, not a guarantee of exhaustive DAST.

Docker build may access package repositories and may retain images or cache
after the temporary stack is removed. Containers are not a security boundary
for hostile source; use source-only review when the runtime cannot be trusted.
Never point active tests at production.
