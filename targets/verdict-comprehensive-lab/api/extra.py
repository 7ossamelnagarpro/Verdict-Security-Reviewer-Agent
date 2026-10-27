"""Additional order-service routes."""
from __future__ import annotations

import hashlib
import hmac
import html
import json
import os
import secrets
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from pydantic import BaseModel

from api.app import connection, make_token, principal

router = APIRouter()
FILES = Path("/tmp/verdict-files")
LAB_KEY = os.environ.get("APP_SECRET", "lab-only-not-a-real-secret").encode()


def init_extra() -> None:
    with connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS products (
                id SERIAL PRIMARY KEY, name TEXT NOT NULL, price NUMERIC NOT NULL
            );
            CREATE TABLE IF NOT EXISTS notes (
                id SERIAL PRIMARY KEY, order_id INTEGER NOT NULL, body TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS comments (
                id SERIAL PRIMARY KEY, author_id INTEGER NOT NULL, body TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS uploads (
                id SERIAL PRIMARY KEY, name TEXT NOT NULL, mime TEXT NOT NULL, body BYTEA NOT NULL
            );
            CREATE TABLE IF NOT EXISTS reset_tokens (
                token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, used BOOLEAN NOT NULL DEFAULT false
            );
            CREATE TABLE IF NOT EXISTS login_attempts (
                username TEXT PRIMARY KEY, failures INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY, user_id INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS visits (
                id SERIAL PRIMARY KEY, destination TEXT NOT NULL, accepted BOOLEAN NOT NULL
            );
        """)
        if conn.execute("SELECT count(*) AS n FROM products").fetchone()["n"] == 0:
            conn.execute("INSERT INTO products(name,price) VALUES ('widget',100),('gadget',75),('service',40)")
            conn.execute("INSERT INTO notes(order_id,body) VALUES (1,'packing note'),(2,'gift note')")
        conn.commit()
    (FILES / "public").mkdir(parents=True, exist_ok=True)
    (FILES / "private").mkdir(parents=True, exist_ok=True)
    (FILES / "public" / "manual.txt").write_text("Widget instructions", encoding="utf-8")
    (FILES / "private" / "internal.txt").write_text("INTERNAL-LAB-NOTE", encoding="utf-8")


def identity(authorization: str | None) -> dict:
    token = principal(authorization)
    with connection() as conn:
        row = conn.execute("SELECT id,username,role,email,ssn FROM users WHERE id=%s", (token["sub"],)).fetchone()
    if not row:
        raise HTTPException(401, "Unknown account")
    return dict(row)


def verified_identity(authorization: str | None) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Bearer token required")
    token = authorization.split(" ", 1)[1]
    with connection() as conn:
        row = conn.execute("""
            SELECT users.id,users.username,users.role,users.email,users.ssn
            FROM sessions JOIN users ON sessions.user_id=users.id WHERE sessions.token=%s
        """, (token,)).fetchone()
    if not row:
        raise HTTPException(401, "Invalid token")
    return dict(row)


def require_admin(authorization: str | None) -> dict:
    user = verified_identity(authorization)
    if user["role"] != "admin":
        raise HTTPException(403, "Administrator required")
    return user


class Login(BaseModel):
    username: str
    password: str


@router.get("/profiles/{profile_id}")
def profile(profile_id: int, authorization: str | None = Header(default=None)) -> dict:
    principal(authorization)
    with connection() as conn:
        row = conn.execute("SELECT id,username,email,ssn FROM users WHERE id=%s", (profile_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Profile not found")
    return dict(row)


@router.get("/profiles/{profile_id}/verified")
def verified_profile(profile_id: int, authorization: str | None = Header(default=None)) -> dict:
    user = verified_identity(authorization)
    if profile_id != user["id"]:
        raise HTTPException(403, "Not your profile")
    return {"id": user["id"], "username": user["username"], "email": user["email"]}


@router.post("/auth/legacy-login")
def legacy_login(body: Login) -> dict:
    query = f"SELECT id,username,role FROM users WHERE username='{body.username}' AND password='{body.password}'"
    with connection() as conn:
        row = conn.execute(query).fetchone()
    if not row:
        raise HTTPException(401, "Invalid credentials")
    return {"access_token": make_token(row), "username": row["username"]}


@router.post("/auth/checked-login")
def checked_login(body: Login) -> dict:
    with connection() as conn:
        row = conn.execute(
            "SELECT id,username,role FROM users WHERE username=%s AND password=%s",
            (body.username, body.password),
        ).fetchone()
    if not row:
        raise HTTPException(401, "Invalid credentials")
    token = secrets.token_urlsafe(32)
    with connection() as conn:
        conn.execute("INSERT INTO sessions(token,user_id) VALUES (%s,%s)", (token, row["id"]))
        conn.commit()
    return {"access_token": token, "username": row["username"]}


@router.get("/catalog/search", response_class=HTMLResponse)
def catalog_search(q: str = "") -> str:
    with connection() as conn:
        rows = conn.execute(f"SELECT name FROM products WHERE name ILIKE '%{q}%'").fetchall()
    return f"<h1>Results for {q}</h1>" + "".join(f"<p>{row['name']}</p>" for row in rows)


@router.get("/catalog/query", response_class=HTMLResponse)
def catalog_query(q: str = "") -> str:
    with connection() as conn:
        rows = conn.execute("SELECT name FROM products WHERE name ILIKE %s", (f"%{q}%",)).fetchall()
    return f"<h1>Results for {html.escape(q)}</h1>" + "".join(
        f"<p>{html.escape(row['name'])}</p>" for row in rows
    )


class Comment(BaseModel):
    body: str


@router.post("/comments")
def add_comment(body: Comment, authorization: str | None = Header(default=None)) -> dict:
    user = identity(authorization)
    with connection() as conn:
        row = conn.execute(
            "INSERT INTO comments(author_id,body) VALUES (%s,%s) RETURNING id",
            (user["id"], body.body),
        ).fetchone()
        conn.commit()
    return {"id": row["id"]}


@router.get("/comments", response_class=HTMLResponse)
def show_comments() -> str:
    with connection() as conn:
        rows = conn.execute("SELECT body FROM comments ORDER BY id").fetchall()
    return "<h1>Comments</h1>" + "".join(f"<p>{row['body']}</p>" for row in rows)


@router.post("/forum/messages")
def add_message(body: Comment, authorization: str | None = Header(default=None)) -> dict:
    user = verified_identity(authorization)
    with connection() as conn:
        row = conn.execute("INSERT INTO comments(author_id,body) VALUES (%s,%s) RETURNING id", (user["id"], body.body)).fetchone()
        conn.commit()
    return {"id": row["id"]}


@router.get("/forum/messages", response_class=HTMLResponse)
def show_messages() -> str:
    with connection() as conn:
        rows = conn.execute("SELECT body FROM comments ORDER BY id").fetchall()
    return "<h1>Messages</h1>" + "".join(f"<p>{html.escape(row['body'])}</p>" for row in rows)


@router.get("/admin/overview")
def admin_overview(authorization: str | None = Header(default=None)) -> dict:
    principal(authorization)
    with connection() as conn:
        count = conn.execute("SELECT count(*) AS n FROM users").fetchone()["n"]
    return {"users": count}


@router.get("/admin/audit")
def admin_audit(authorization: str | None = Header(default=None)) -> dict:
    require_admin(authorization)
    return {"status": "authorized"}


@router.get("/files")
def file_read(name: str) -> Response:
    file = (FILES / "public" / name).resolve()
    if not file.is_relative_to(FILES.resolve()) or not file.is_file():
        raise HTTPException(404, "File not found")
    return Response(file.read_text(encoding="utf-8"), media_type="text/plain")


@router.get("/files/verified")
def verified_file_read(name: str) -> Response:
    root = (FILES / "public").resolve()
    file = (root / name).resolve()
    if not file.is_relative_to(root) or not file.is_file():
        raise HTTPException(404, "File not found")
    return Response(file.read_text(encoding="utf-8"), media_type="text/plain")


@router.get("/errors/query")
def error_query() -> dict:
    try:
        with connection() as conn:
            conn.execute("SELECT unavailable_column FROM products")
    except Exception as error:
        raise HTTPException(500, f"Query failed: {error}") from error
    return {"status": "ok"}


@router.get("/errors/checked")
def checked_error() -> dict:
    try:
        with connection() as conn:
            conn.execute("SELECT unavailable_column FROM products")
    except Exception as error:
        raise HTTPException(500, "Operation failed") from error
    return {"status": "ok"}


@router.post("/auth/limited-login")
def limited_login(body: Login) -> dict:
    with connection() as conn:
        attempts = conn.execute(
            "SELECT failures FROM login_attempts WHERE username=%s", (body.username,)
        ).fetchone()
        if attempts and attempts["failures"] >= 3:
            raise HTTPException(429, "Try again later")
        row = conn.execute(
            "SELECT id,username,role FROM users WHERE username=%s AND password=%s",
            (body.username, body.password),
        ).fetchone()
        if not row:
            conn.execute("""
                INSERT INTO login_attempts(username,failures) VALUES (%s,1)
                ON CONFLICT(username) DO UPDATE SET failures=login_attempts.failures+1
            """, (body.username,))
            conn.commit()
            raise HTTPException(401, "Invalid credentials")
        conn.execute("DELETE FROM login_attempts WHERE username=%s", (body.username,))
        conn.commit()
    return checked_login(body)


@router.get("/session/start")
def session_start(username: str) -> Response:
    with connection() as conn:
        user = conn.execute("SELECT id FROM users WHERE username=%s", (username,)).fetchone()
    if not user:
        raise HTTPException(404, "Account not found")
    response = Response("session started")
    response.set_cookie("lab_session", f"session-{user['id']}")
    return response


@router.get("/login", response_class=HTMLResponse)
def login_page() -> str:
    return """<form action='/auth/form-login' method='post'>
    <input name='username'><input name='password' type='password'><button>Sign in</button></form>"""


@router.post("/auth/form-login")
async def form_login(request: Request) -> Response:
    form = await request.form()
    username = str(form.get("username", ""))
    password = str(form.get("password", ""))
    with connection() as conn:
        row = conn.execute(
            "SELECT id,username FROM users WHERE username=%s AND password=%s", (username, password)
        ).fetchone()
    if not row:
        raise HTTPException(401, "Invalid credentials")
    response = HTMLResponse(f"Signed in as {html.escape(row['username'])}")
    response.set_cookie("lab_session", f"session-{row['id']}")
    return response


@router.get("/account", response_class=HTMLResponse)
def account_page(request: Request) -> str:
    user = session_whoami(request)
    return f"<h1>Signed in as {html.escape(user['username'])}</h1>"


@router.get("/session/whoami")
def session_whoami(request: Request) -> dict:
    token = request.cookies.get("lab_session", "")
    if not token.startswith("session-") or not token[8:].isdigit():
        raise HTTPException(401, "Session required")
    with connection() as conn:
        row = conn.execute("SELECT username FROM users WHERE id=%s", (int(token[8:]),)).fetchone()
    if not row:
        raise HTTPException(401, "Session required")
    return {"username": row["username"]}


@router.get("/session/secure-start")
def secure_session_start(authorization: str | None = Header(default=None)) -> Response:
    user = verified_identity(authorization)
    token = secrets.token_urlsafe(32)
    with connection() as conn:
        conn.execute("INSERT INTO sessions(token,user_id) VALUES (%s,%s)", (token, user["id"]))
        conn.commit()
    response = Response("session started")
    response.set_cookie("verified_session", token, httponly=True, samesite="strict", secure=True)
    return response


@router.get("/session/secure-whoami")
def secure_session_whoami(request: Request) -> dict:
    token = request.cookies.get("verified_session", "")
    with connection() as conn:
        row = conn.execute(
            "SELECT username FROM sessions JOIN users ON sessions.user_id=users.id WHERE token=%s",
            (token,),
        ).fetchone()
    if not row:
        raise HTTPException(401, "Session required")
    return {"username": row["username"]}


@router.post("/uploads")
async def upload(request: Request, authorization: str | None = Header(default=None)) -> dict:
    identity(authorization)
    form = await request.form()
    file = form.get("file")
    if not file or not hasattr(file, "read"):
        raise HTTPException(400, "file required")
    payload = await file.read()
    if len(payload) > 65536:
        raise HTTPException(413, "file too large")
    with connection() as conn:
        row = conn.execute(
            "INSERT INTO uploads(name,mime,body) VALUES (%s,%s,%s) RETURNING id",
            (file.filename or "file", file.content_type or "application/octet-stream", payload),
        ).fetchone()
        conn.commit()
    return {"id": row["id"]}


@router.get("/uploads/{upload_id}")
def view_upload(upload_id: int) -> Response:
    with connection() as conn:
        row = conn.execute("SELECT mime,body FROM uploads WHERE id=%s", (upload_id,)).fetchone()
    if not row:
        raise HTTPException(404, "File not found")
    return Response(bytes(row["body"]), media_type=row["mime"])


@router.post("/documents")
async def save_document(request: Request, authorization: str | None = Header(default=None)) -> dict:
    verified_identity(authorization)
    form = await request.form()
    file = form.get("file")
    if not file or not hasattr(file, "read"):
        raise HTTPException(400, "file required")
    payload = await file.read()
    if len(payload) > 65536 or file.content_type != "text/plain":
        raise HTTPException(400, "Only small text files are accepted")
    with connection() as conn:
        row = conn.execute(
            "INSERT INTO uploads(name,mime,body) VALUES (%s,'text/plain',%s) RETURNING id",
            (secrets.token_hex(8), payload),
        ).fetchone()
        conn.commit()
    return {"id": row["id"]}


@router.get("/documents/{upload_id}")
def view_document(upload_id: int) -> Response:
    with connection() as conn:
        row = conn.execute("SELECT body FROM uploads WHERE id=%s AND mime='text/plain'", (upload_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Document not found")
    return Response(
        bytes(row["body"]), media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=document.txt", "X-Content-Type-Options": "nosniff"},
    )


@router.get("/me/verified")
def verified_me(authorization: str | None = Header(default=None)) -> dict:
    user = verified_identity(authorization)
    return {"id": user["id"], "username": user["username"], "role": user["role"]}


class OrderInput(BaseModel):
    item: str = "widget"
    quantity: int = 1
    unit_price: float | None = None
    owner_id: int | None = None
    status: str | None = None


@router.post("/orders/verified")
def verified_order(body: OrderInput, authorization: str | None = Header(default=None)) -> dict:
    user = verified_identity(authorization)
    if body.quantity < 1 or body.quantity > 10:
        raise HTTPException(400, "Invalid quantity")
    with connection() as conn:
        product = conn.execute("SELECT price FROM products WHERE name=%s", (body.item,)).fetchone()
        if not product:
            raise HTTPException(404, "Product not found")
        row = conn.execute(
            "INSERT INTO orders(owner_id,item,quantity,unit_price,status) VALUES (%s,%s,%s,%s,'new') RETURNING *",
            (user["id"], body.item, body.quantity, product["price"]),
        ).fetchone()
        conn.commit()
    return dict(row)


def owned_order(order_id: int, authorization: str | None) -> tuple[dict, dict]:
    user = verified_identity(authorization)
    with connection() as conn:
        order = conn.execute("SELECT * FROM orders WHERE id=%s", (order_id,)).fetchone()
    if not order:
        raise HTTPException(404, "Order not found")
    if order["owner_id"] != user["id"]:
        raise HTTPException(403, "Not your order")
    return dict(order), user


@router.get("/orders/{order_id}/verified")
def verified_get_order(order_id: int, authorization: str | None = Header(default=None)) -> dict:
    return owned_order(order_id, authorization)[0]


@router.post("/orders/{order_id}/verified-coupon")
def verified_coupon(order_id: int, body: dict, authorization: str | None = Header(default=None)) -> dict:
    order, _ = owned_order(order_id, authorization)
    if order["status"] != "new":
        raise HTTPException(409, "Order no longer editable")
    with connection() as conn:
        coupon = conn.execute("SELECT percent FROM coupons WHERE code=%s", (str(body.get("code", "")),)).fetchone()
        if not coupon:
            raise HTTPException(400, "Unknown coupon")
        row = conn.execute(
            "UPDATE orders SET discount=%s WHERE id=%s RETURNING *", (coupon["percent"], order_id)
        ).fetchone()
        conn.commit()
    return dict(row)


@router.post("/orders/{order_id}/verified-pay")
def verified_pay(order_id: int, authorization: str | None = Header(default=None)) -> dict:
    order, _ = owned_order(order_id, authorization)
    if order["status"] != "new":
        raise HTTPException(409, "Order is not payable")
    with connection() as conn:
        locked = conn.execute("SELECT * FROM orders WHERE id=%s FOR UPDATE", (order_id,)).fetchone()
        if locked["status"] != "new":
            raise HTTPException(409, "Order is not payable")
        amount = float(locked["quantity"]) * float(locked["unit_price"]) * (1 - float(locked["discount"]) / 100)
        invoice = conn.execute(
            "INSERT INTO invoices(order_id,amount,payment_reference) VALUES (%s,%s,%s) RETURNING *",
            (order_id, amount, "verified-" + secrets.token_hex(6)),
        ).fetchone()
        conn.execute("UPDATE orders SET status='paid' WHERE id=%s", (order_id,))
        conn.commit()
    return dict(invoice)


@router.post("/orders/{order_id}/verified-cancel")
def verified_cancel(order_id: int, authorization: str | None = Header(default=None)) -> dict:
    order, _ = owned_order(order_id, authorization)
    if order["status"] != "new":
        raise HTTPException(409, "Order cannot be cancelled")
    with connection() as conn:
        row = conn.execute("UPDATE orders SET status='cancelled' WHERE id=%s RETURNING *", (order_id,)).fetchone()
        conn.commit()
    return dict(row)


@router.get("/invoices/{invoice_id}/verified")
def verified_invoice(invoice_id: int, authorization: str | None = Header(default=None)) -> dict:
    user = verified_identity(authorization)
    with connection() as conn:
        row = conn.execute("""
            SELECT i.id,i.order_id,i.amount FROM invoices i
            JOIN orders o ON i.order_id=o.id WHERE i.id=%s AND o.owner_id=%s
        """, (invoice_id, user["id"])).fetchone()
    if not row:
        raise HTTPException(404, "Invoice not found")
    return dict(row)


@router.post("/jobs/verified")
def verified_job(body: dict, authorization: str | None = Header(default=None)) -> dict:
    user = verified_identity(authorization)
    if body.get("kind") not in {"echo", "report"}:
        raise HTTPException(400, "Unsupported job")
    with connection() as conn:
        row = conn.execute(
            "INSERT INTO jobs(kind,payload,run_as) VALUES (%s,%s,%s) RETURNING id,kind,run_as",
            (body["kind"], json.dumps(body.get("payload", {})), user["role"]),
        ).fetchone()
        conn.commit()
    return dict(row)


@router.post("/webhooks/verified")
def verified_webhook(body: dict, authorization: str | None = Header(default=None)) -> dict:
    user = verified_identity(authorization)
    target = str(body.get("target_url", ""))
    parts = urlsplit(target)
    if parts.scheme != "http" or parts.hostname != "mock-external" or parts.netloc != "mock-external:9000":
        raise HTTPException(400, "Invalid destination")
    with connection() as conn:
        row = conn.execute(
            "INSERT INTO jobs(kind,payload,run_as) VALUES ('webhook',%s,%s) RETURNING id,run_as",
            (json.dumps({"target_url": target, "body": body.get("body", {})}), user["role"]),
        ).fetchone()
        conn.commit()
    return dict(row)


@router.get("/orders/{order_id}/notes/{note_id}")
def order_note(order_id: int, note_id: int, authorization: str | None = Header(default=None)) -> dict:
    principal(authorization)
    with connection() as conn:
        row = conn.execute("SELECT id,order_id,body FROM notes WHERE id=%s", (note_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Note not found")
    return dict(row)


@router.get("/orders/{order_id}/notes/{note_id}/verified")
def verified_note(order_id: int, note_id: int, authorization: str | None = Header(default=None)) -> dict:
    owned_order(order_id, authorization)
    with connection() as conn:
        row = conn.execute(
            "SELECT id,order_id,body FROM notes WHERE id=%s AND order_id=%s", (note_id, order_id)
        ).fetchone()
    if not row:
        raise HTTPException(404, "Note not found")
    return dict(row)


@router.post("/auth/reset/request")
def request_reset(body: dict) -> dict:
    with connection() as conn:
        user = conn.execute("SELECT id FROM users WHERE username=%s", (str(body.get("username", "")),)).fetchone()
        if not user:
            raise HTTPException(404, "Account not found")
        token = secrets.token_urlsafe(16)
        conn.execute("INSERT INTO reset_tokens(token,user_id) VALUES (%s,%s)", (token, user["id"]))
        conn.commit()
    return {"reset_token": token}


@router.post("/auth/reset/confirm")
def confirm_reset(body: dict) -> dict:
    with connection() as conn:
        row = conn.execute(
            "SELECT user_id FROM reset_tokens WHERE token=%s", (str(body.get("token", "")),)
        ).fetchone()
        if not row:
            raise HTTPException(400, "Invalid token")
        conn.execute("UPDATE users SET password=%s WHERE id=%s", (str(body.get("password", "")), row["user_id"]))
        conn.commit()
    return {"status": "changed"}


@router.post("/auth/reset/verified-request")
def verified_reset_request(body: dict) -> dict:
    with connection() as conn:
        user = conn.execute("SELECT id FROM users WHERE username=%s", (str(body.get("username", "")),)).fetchone()
        if not user:
            raise HTTPException(404, "Account not found")
        token = secrets.token_urlsafe(32)
        conn.execute("INSERT INTO reset_tokens(token,user_id) VALUES (%s,%s)", (token, user["id"]))
        conn.commit()
    return {"reset_token": token}


@router.post("/auth/reset/verified-confirm")
def verified_reset_confirm(body: dict) -> dict:
    with connection() as conn:
        row = conn.execute(
            "UPDATE reset_tokens SET used=true WHERE token=%s AND used=false RETURNING user_id",
            (str(body.get("token", "")),),
        ).fetchone()
        if not row:
            raise HTTPException(400, "Invalid or used token")
        conn.execute("UPDATE users SET password=%s WHERE id=%s", (str(body.get("password", "")), row["user_id"]))
        conn.commit()
    return {"status": "changed"}


@router.get("/auth/continue")
def continue_to(next: str = "/") -> RedirectResponse:
    return RedirectResponse(next, status_code=302)


@router.get("/auth/continue/verified")
def verified_continue(next: str = "/") -> RedirectResponse:
    parts = urlsplit(next)
    if not next.startswith("/") or next.startswith("//") or parts.scheme or parts.netloc:
        raise HTTPException(400, "Local path required")
    return RedirectResponse(next, status_code=302)


@router.post("/integrations/hook")
async def receive_hook(request: Request) -> dict:
    body = await request.body()
    with connection() as conn:
        conn.execute("INSERT INTO visits(destination,accepted) VALUES (%s,true)", (body.decode("utf-8", "replace"),))
        conn.commit()
    return {"accepted": True}


@router.post("/integrations/hook-verified")
async def receive_verified_hook(request: Request, x_lab_signature: str | None = Header(default=None)) -> dict:
    body = await request.body()
    expected = hmac.new(LAB_KEY, body, hashlib.sha256).hexdigest()
    if not x_lab_signature or not hmac.compare_digest(x_lab_signature, expected):
        raise HTTPException(401, "Invalid signature")
    return {"accepted": True}


@router.post("/admin/roles/{user_id}")
def change_role(user_id: int, body: dict, authorization: str | None = Header(default=None)) -> dict:
    require_admin(authorization)
    role = str(body.get("role", ""))
    if role not in {"user", "admin"}:
        raise HTTPException(400, "Invalid role")
    with connection() as conn:
        row = conn.execute("UPDATE users SET role=%s WHERE id=%s RETURNING id,role", (role, user_id)).fetchone()
        conn.commit()
    if not row:
        raise HTTPException(404, "Account not found")
    return dict(row)


@router.get("/admin/token-report")
def token_report(authorization: str | None = Header(default=None)) -> dict:
    token = principal(authorization)
    if token.get("role") != "admin":
        raise HTTPException(403, "Administrator required")
    return {"status": "authorized"}


@router.get("/admin/current-report")
def current_report(authorization: str | None = Header(default=None)) -> dict:
    require_admin(authorization)
    return {"status": "authorized"}


@router.get("/status/secure")
def secure_status() -> Response:
    return Response(
        "ready", media_type="text/plain",
        headers={
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        },
    )


@router.get("/view")
def view_home() -> HTMLResponse:
    return HTMLResponse("""<!doctype html><html><head><title>Order Desk</title></head>
    <body><h1>Order Desk</h1><nav><a href='/catalog/query?q=widget'>Catalog</a>
    <a href='/comments'>Comments</a><a href='/healthz'>Status</a></nav></body></html>""")
