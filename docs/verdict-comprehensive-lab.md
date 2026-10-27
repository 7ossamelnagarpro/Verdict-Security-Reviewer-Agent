# Verdict Comprehensive Lab: local review setup

The source directory to scan is **only** `targets/verdict-comprehensive-lab`. Keep `benchmark/verdict-comprehensive-ground-truth.json` and `benchmark/check_comprehensive_lab.py` out of scanner and AI inputs. Run the independent checks only after the security review.

## Start and verify the disposable target

From the repository root:

```powershell
docker compose -p verdict-comprehensive-lab -f targets/verdict-comprehensive-lab/compose.yaml config --quiet
docker compose -p verdict-comprehensive-lab -f targets/verdict-comprehensive-lab/compose.yaml up --build -d --wait
& .\.venv\Scripts\python.exe -m unittest discover -s targets\verdict-comprehensive-lab\tests -v
& .\.venv\Scripts\python.exe benchmark\check_comprehensive_lab.py
```

The benchmark command resets the lab data, then proves the labeled behaviors. It mutates only this disposable stack. Avoid running it at the same time as a Verdict scan. For a fresh Verdict run after benchmarking, reset the stack again with `docker compose -p verdict-comprehensive-lab -f targets/verdict-comprehensive-lab/compose.yaml exec -T api python -m api.seed`.

## Values for Verdict's local UI

| Field | Value |
|---|---|
| Project directory | Absolute path to `targets/verdict-comprehensive-lab` on this computer |
| Review mode | My app · DAST + Static + AI |
| Startup method | Start my trusted Docker Compose project |
| Compose file | `compose.yaml` |
| App service | `api` |
| Local app URL | `http://127.0.0.1:8091` |
| Health path | `/healthz` |
| Expected HTTP status | `200` |
| Additional GET paths | `/`, `/view`, `/login`, `/comments`, `/catalog/search?q=widget`, `/catalog/query?q=widget`, `/admin/users`, `/debug/config` |

Approve Compose build/start and testing permission only for your own disposable copy. The example contract at `benchmark/verdict-comprehensive-runtime-contract.example.json` is a **baseline GET** contract; it does not enable authenticated workflow testing automatically.

## Accounts and authenticated workflows

The fake test identities are `user_a` / `UserA-Lab-Only-1`, `user_b` / `UserB-Lab-Only-1`, and `admin` / `Admin-Lab-Only-1`. For the existing API workflow mode, login is JSON `POST /auth/login` with fields `username` and `password`, session type `bearer`, token JSON field `access_token`, identity verification `GET /me`, username JSON field `username`. Save credentials through the UI's OS vault, not inside a contract or report.

Example guided steps, to review and adapt in the UI:

1. Cross-user order: login as A and B; as A, `POST /orders` with `{"item":"widget","quantity":1,"unit_price":100}`, capture `id` as `order_id`; as B, `GET /orders/{{order_id}}` should be denied (`403`/`404`).
2. Admin-only access: as A, `GET /admin/users` should be denied (`403`/`404`).
3. Price rule: as A, `POST /orders` with `{"item":"widget","quantity":1,"unit_price":0.01}` should not accept the client-supplied price; assert the response price equals catalog price `100`.
4. Coupon rule: after creating an order, as A, `POST /orders/{{order_id}}/apply-coupon` with `{"code":"WELCOME20","discount":99}` should not return a discount above `20`.
5. Payment replay: after creating an order, as A, `POST /orders/{{order_id}}/pay` twice; the second attempt should not produce another invoice.
6. Nested resource: as A, `GET /orders/1/notes/2` should not return the note attached to order 2.
7. Redirect: unauthenticated `GET /auth/continue?next=https://untrusted.example/` should not return an external `Location`. Do not follow the redirect during the test.

The lab contains additional cases not expressible by today's guided runner (notably multipart upload and some cookie/browser behaviors). Record those as coverage gaps; do not count them as passed. Browser crawl visits same-origin links but does not submit forms. A simple form/cookie login is separately available at `/auth/form-login` (fields `username`, `password`; logged-in marker `Signed in as`), while the guided API workflows use bearer tokens. ZAP form login does **not** inherit bearer credentials. Active ZAP requires the disposable Compose target and explicit approval.

## Benchmark interpretation and cleanup

The separate ground truth contains 35 confirmed behavior cases, one candidate-only safety exclusion, and 27 matched safe controls. Proof checks demonstrate the target's behavior, not Verdict's detection rate. Run Verdict first without supplying the ground truth, then compare saved findings against the labels. Positive recall can use confirmed cases; whole-report precision requires manual adjudication of every additional finding. A completed scan does not imply every HTTP operation was reached.

When finished, remove only this lab's stack and ephemeral database:

```powershell
docker compose -p verdict-comprehensive-lab -f targets/verdict-comprehensive-lab/compose.yaml down --volumes --remove-orphans
```
