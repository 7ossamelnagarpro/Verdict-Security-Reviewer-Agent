# Verdict Multi-Service Lab

This is a disposable, intentionally vulnerable local target for testing the Verdict Security Reviewer pipeline. It is not production software and must never be exposed to a shared network or the public internet.

## Services

- `api`: FastAPI application published only at `http://127.0.0.1:8090`.
- `worker`: processes local jobs and webhook callbacks.
- `db`: PostgreSQL on the private Compose network.
- `mock-external`: local payment/webhook stand-in on the private network.

## Verdict UI settings

```text
Project directory: targets/verdict-multi-service-lab
Startup method: Start my trusted Docker Compose project
Compose file: compose.yaml
App service: api
Local app URL: http://127.0.0.1:8090
Health path: /healthz
Expected status: 200
Additional endpoints: /healthz, /auth/login, /orders, /webhooks, /jobs
```

## Local test accounts

These are fake lab-only values:

```text
user_a / UserA-Lab-Only-1
user_b / UserB-Lab-Only-1
admin  / Admin-Lab-Only-1
```

## Run and reset

```bash
docker compose config
docker compose up --build -d --wait
curl http://127.0.0.1:8090/healthz
docker compose down --volumes --remove-orphans
```

The database is ephemeral. Never add real secrets or real payment data. The benchmark ground truth is intentionally stored outside this target in `benchmark/verdict-multi-service-scenarios.json` and must not be passed to scanners or AI.

The target deliberately includes authentication, authorization, workflow, API, configuration, worker-trust and data-exposure issues. A DAST result is bounded evidence, not proof that every possible issue was found.
