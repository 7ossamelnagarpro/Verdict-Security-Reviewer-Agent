# VulnShop — Intentionally Vulnerable Practice Target

> Held-out benchmark notes: keep this file and the ground truth outside the
> `targets/security-lab-web` scan root. Do not supply them to scanners or AI
> discovery/review stages; use them only for test setup and post-scan evaluation.

A tiny Flask + SQLite app built **on purpose with security bugs** so you can
point your scanner (or Burp/ZAP/sqlmap) at it and verify detection.

> ⚠️ **Run locally only** (`127.0.0.1`). Never expose this to the internet or
> a shared network — it is deliberately broken.

## Run it

```bash
python -m pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000

Test accounts: `alice/alice123`, `bob/bob123`, `admin/admin123`

## Vulnerabilities included

| # | Type | Endpoint | How to trigger |
|---|------|----------|-----------------|
| 1 | IDOR | `GET /orders/<id>` | Log in as alice (order 100), then request `/orders/101` (bob's order) — no ownership check |
| 1b | IDOR | `GET /profile/<id>` | Log in as alice, request `/profile/3` to read admin's email/SSN |
| 2a | SQL Injection (auth bypass) | `POST /login` | username = `admin' --` |
| 2b | SQL Injection (UNION/error) | `GET /search?q=` | `q=' OR '1'='1` or `q=' UNION SELECT ...--` |
| 3 | Reflected XSS | `GET /search?q=` | `q=<script>alert(1)</script>` |
| 4 | Stored XSS | `POST /comments` | post a comment body of `<img src=x onerror=alert(1)>` |
| 5 | Broken access control | `GET /admin` | visit without admin role — the check doesn't actually block |
| 6 | Path traversal | `GET /files/<path>` | `/files/../secret_do_not_serve.txt` |
| 7 | Command injection | `GET /ping?host=` | `host=127.0.0.1;cat+/etc/passwd` |
| 8 | Weak/predictable session token | `token` cookie after login | format is `tok-<user_id>-staticsalt` — guessable |
| 9 | Sensitive data exposure | `GET /debug` | dumps secret key + full environment variables |
| 9b | Verbose errors | `/login`, `/search` with a SQL-breaking payload | raw DB error + query text returned to client |
| 10 | No brute-force protection | `/login` | no attempt counter/lockout/captcha — scriptable |
| 11 | CORS misconfiguration | any endpoint | reflects any `Origin` header + `Allow-Credentials: true` |
| 12 | Insecure file upload | `POST /upload` | upload a `.html` file with a script, then open it at `/uploads/<name>` |

## Notes for scanner testing

- IDs are **sequential integers** (orders 100–103, users 1–3) on purpose, so
  an automated IDOR scanner can enumerate them easily.
- Two real user sessions (alice, bob) are provided so you can test
  differential/authorization-matrix scanning (log in as alice, replay a
  request using bob's resource ID, compare responses).
- `/admin` is a good target for testing "does the scanner verify the
  response actually contains the protected data, not just a 200 status."
- `app.run(debug=True)` is left on intentionally — Flask's interactive
  debugger is itself a known RCE vector if reachable; don't skip disabling
  it when you adapt this for anything beyond localhost practice.

## Resetting data

Delete `vulnshop.db` and restart the app to reset users/orders/comments to
their original state.
