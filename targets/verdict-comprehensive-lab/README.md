# Order Desk local test application

This disposable application is for authorized security-tool testing only. Run it on your own machine, bound to loopback. Do not expose it to a shared network or use real accounts, secrets, payments, or customer data.

The application has an HTTP API and small browser pages. It supports accounts, a catalog, orders, invoices, comments, documents, jobs, and local webhook callbacks. `api` is the only published Compose service. `worker`, PostgreSQL, and `mock-external` stay on the private Compose network.

## Start

Run these commands from this target directory (`targets/verdict-comprehensive-lab`):

```powershell
docker compose -p verdict-comprehensive-lab config
docker compose -p verdict-comprehensive-lab up --build -d --wait
curl.exe http://127.0.0.1:8091/healthz
```

Open `http://127.0.0.1:8091/view` for the browser entry page, or `http://127.0.0.1:8091/docs` for the API description. The API is available only on `127.0.0.1:8091`.

All accounts and data are fake and resettable. Local demo accounts are `user_a` / `UserA-Lab-Only-1`, `user_b` / `UserB-Lab-Only-1`, and `admin` / `Admin-Lab-Only-1`. JSON login is `POST /auth/login`, returning `access_token`; protected API calls use `Authorization: Bearer <token>`. For browser-form testing, `GET /login` shows a form and `POST /auth/form-login` establishes a cookie session; `GET /account` confirms the signed-in username.

To reset seeded data, run:

```powershell
docker compose -p verdict-comprehensive-lab exec -T api python -m api.seed
```

To remove **only this lab's** containers and ephemeral database:

```powershell
docker compose -p verdict-comprehensive-lab down --volumes --remove-orphans
```

The test-only Compose stack is disposable. Docker hardening reduces risk but does not safely isolate untrusted code. Active scans can modify this lab's data. Always confirm that the local URL and project directory point to this lab before running them.
