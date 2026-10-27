"""Intentionally vulnerable local API for exercising the reviewer pipeline.

This is a disposable fixture. It must never be exposed to a shared network.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import time
from contextlib import contextmanager
from typing import Any, Iterator

import psycopg
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from psycopg.rows import dict_row

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("verdict-lab")
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://lab:lab-only@db:5432/lab")
MOCK_EXTERNAL_URL = os.environ.get("MOCK_EXTERNAL_URL", "http://mock-external:9000")

app = FastAPI(title="Verdict Multi-Service Lab", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@contextmanager
def connection() -> Iterator[psycopg.Connection[Any]]:
    with psycopg.connect(DATABASE_URL, row_factory=dict_row) as conn:
        yield conn


def init_db() -> None:
    with connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user',
                email TEXT NOT NULL, ssn TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS orders (
                id SERIAL PRIMARY KEY, owner_id INTEGER NOT NULL,
                item TEXT NOT NULL, quantity INTEGER NOT NULL,
                unit_price NUMERIC NOT NULL, discount NUMERIC NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'new'
            );
            CREATE TABLE IF NOT EXISTS coupons (
                code TEXT PRIMARY KEY, percent INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS invoices (
                id SERIAL PRIMARY KEY, order_id INTEGER NOT NULL,
                amount NUMERIC NOT NULL, payment_reference TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS jobs (
                id SERIAL PRIMARY KEY, kind TEXT NOT NULL,
                payload JSONB NOT NULL, run_as TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'queued', result JSONB
            );
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                token TEXT PRIMARY KEY, user_id INTEGER NOT NULL,
                expires_at BIGINT NOT NULL
            );
        """)
        count = conn.execute("SELECT count(*) AS count FROM users").fetchone()["count"]
        if count == 0:
            conn.execute("""
                INSERT INTO users (username,password,role,email,ssn) VALUES
                ('user_a','UserA-Lab-Only-1','user','user_a@example.test','000-00-0001'),
                ('user_b','UserB-Lab-Only-1','user','user_b@example.test','000-00-0002'),
                ('admin','Admin-Lab-Only-1','admin','admin@example.test','000-00-0003');
                INSERT INTO coupons (code,percent) VALUES ('WELCOME20',20),('VIP50',50)
                ON CONFLICT DO NOTHING;
                INSERT INTO orders (owner_id,item,quantity,unit_price,status) VALUES
                (1,'demo-widget',1,100,'new'),(2,'demo-gadget',2,75,'new');
            """)
        conn.commit()


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def make_token(user: dict[str, Any]) -> str:
    # Deliberately unsigned fixture token: candidate for authentication review.
    header = _b64(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = _b64(json.dumps({"sub": user["id"], "username": user["username"], "role": user["role"]}).encode())
    return f"{header}.{payload}."


def principal(authorization: str | None) -> dict[str, Any]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Bearer token required")
    try:
        raw = authorization.split(" ", 1)[1].split(".")[1]
        raw += "=" * (-len(raw) % 4)
        return json.loads(base64.urlsafe_b64decode(raw))
    except Exception as error:
        raise HTTPException(401, "Invalid token") from error


class LoginBody(BaseModel):
    username: str
    password: str


class OrderBody(BaseModel):
    item: str = "demo-widget"
    quantity: int = Field(default=1, ge=1)
    unit_price: float = 100
    owner_id: int | None = None
    status: str = "new"


class CouponBody(BaseModel):
    code: str = "WELCOME20"
    discount: float | None = None


class JobBody(BaseModel):
    kind: str = "echo"
    payload: dict[str, Any] = {}
    run_as: str = "user"


def _login(username: str, password: str) -> dict[str, Any]:
    with connection() as conn:
        user = conn.execute(
            "SELECT id,username,password,role,email FROM users WHERE username=%s", (username,)
        ).fetchone()
    if not user or user["password"] != password:
        raise HTTPException(401, "Invalid credentials")
    # Candidate-only evidence: the fixture intentionally logs a fake value.
    log.info("login user=%s app_secret=%s", username, os.environ.get("APP_SECRET", "lab-only"))
    return {"access_token": make_token(user), "token_type": "bearer", "user": user["username"]}


@app.on_event("startup")
def startup() -> None:
    for _ in range(30):
        try:
            init_db()
            return
        except psycopg.OperationalError:
            time.sleep(1)
    raise RuntimeError("database did not become ready")


@app.get("/healthz")
def healthz() -> dict[str, str]:
    with connection() as conn:
        conn.execute("SELECT 1")
    return {"status": "ok", "service": "api"}


@app.get("/")
def index() -> dict[str, str]:
    return {"service": "verdict-multi-service-lab", "health": "/healthz"}


@app.post("/auth/login")
async def login(request: Request) -> dict[str, Any]:
    if "application/json" in request.headers.get("content-type", ""):
        data = await request.json()
    else:
        data = await request.form()
    return _login(str(data.get("username", "")), str(data.get("password", "")))


@app.post("/auth/register")
def register(body: LoginBody) -> dict[str, Any]:
    with connection() as conn:
        try:
            user = conn.execute(
                "INSERT INTO users (username,password,role,email,ssn) VALUES (%s,%s,'user',%s,'000-00-9999') RETURNING id,username,role",
                (body.username, body.password, f"{body.username}@example.test"),
            ).fetchone()
            conn.commit()
        except psycopg.errors.UniqueViolation as error:
            raise HTTPException(409, "username already exists") from error
    return {"user": user, "access_token": make_token(user)}


@app.post("/auth/refresh")
def refresh(authorization: str | None = Header(default=None)) -> dict[str, str]:
    user = principal(authorization)
    return {"access_token": make_token(user), "token_type": "bearer"}


@app.get("/me")
def me(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    user = principal(authorization)
    with connection() as conn:
        row = conn.execute("SELECT id,username,role,email,ssn FROM users WHERE id=%s", (user["sub"],)).fetchone()
    return dict(row or {})


@app.post("/orders")
def create_order(body: OrderBody, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    user = principal(authorization)
    # Intentional mass-assignment fixture: client-controlled owner/status/price are accepted.
    owner_id = body.owner_id or user["sub"]
    with connection() as conn:
        row = conn.execute(
            "INSERT INTO orders (owner_id,item,quantity,unit_price,status) VALUES (%s,%s,%s,%s,%s) RETURNING *",
            (owner_id, body.item, body.quantity, body.unit_price, body.status),
        ).fetchone()
        conn.commit()
    return dict(row)


@app.get("/orders/{order_id}")
def get_order(order_id: int, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    principal(authorization)
    with connection() as conn:
        row = conn.execute("SELECT * FROM orders WHERE id=%s", (order_id,)).fetchone()
    if not row:
        raise HTTPException(404, "order not found")
    return dict(row)


@app.post("/orders/{order_id}/apply-coupon")
def apply_coupon(order_id: int, body: CouponBody, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    principal(authorization)
    with connection() as conn:
        coupon = conn.execute("SELECT percent FROM coupons WHERE code=%s", (body.code,)).fetchone()
        percent = body.discount if body.discount is not None else (coupon["percent"] if coupon else 0)
        row = conn.execute("UPDATE orders SET discount=%s WHERE id=%s RETURNING *", (percent, order_id)).fetchone()
        conn.commit()
    return dict(row or {})


@app.post("/orders/{order_id}/pay")
def pay_order(order_id: int, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    principal(authorization)
    with connection() as conn:
        order = conn.execute("SELECT * FROM orders WHERE id=%s", (order_id,)).fetchone()
        if not order:
            raise HTTPException(404, "order not found")
        amount = float(order["quantity"]) * float(order["unit_price"]) * (1 - float(order["discount"]) / 100)
        conn.execute("UPDATE orders SET status='paid' WHERE id=%s", (order_id,))
        invoice = conn.execute(
            "INSERT INTO invoices (order_id,amount,payment_reference) VALUES (%s,%s,%s) RETURNING *",
            (order_id, amount, f"pay-{int(time.time())}"),
        ).fetchone()
        conn.commit()
    return dict(invoice)


@app.post("/orders/{order_id}/cancel")
def cancel_order(order_id: int, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    principal(authorization)
    with connection() as conn:
        row = conn.execute("UPDATE orders SET status='cancelled' WHERE id=%s RETURNING *", (order_id,)).fetchone()
        conn.commit()
    return dict(row or {})


@app.get("/invoices/{invoice_id}")
def invoice(invoice_id: int, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    principal(authorization)
    with connection() as conn:
        row = conn.execute("SELECT * FROM invoices WHERE id=%s", (invoice_id,)).fetchone()
    if not row:
        raise HTTPException(404, "invoice not found")
    return dict(row)


@app.get("/admin/users")
def admin_users(authorization: str | None = Header(default=None)) -> list[dict[str, Any]]:
    principal(authorization)
    with connection() as conn:
        rows = conn.execute("SELECT id,username,email,role,ssn FROM users ORDER BY id").fetchall()
    return [dict(row) for row in rows]


@app.get("/admin/jobs")
def admin_jobs(authorization: str | None = Header(default=None)) -> list[dict[str, Any]]:
    principal(authorization)
    with connection() as conn:
        rows = conn.execute("SELECT * FROM jobs ORDER BY id DESC").fetchall()
    return [dict(row) for row in rows]


@app.post("/webhooks")
def create_webhook(body: dict[str, Any], authorization: str | None = Header(default=None)) -> dict[str, Any]:
    principal(authorization)
    target_url = str(body.get("target_url", MOCK_EXTERNAL_URL + "/webhook"))
    # Deliberately weak destination validation, constrained to the lab network.
    if "mock-external" not in target_url:
        raise HTTPException(400, "only the local mock destination is accepted")
    with connection() as conn:
        row = conn.execute(
            "INSERT INTO jobs (kind,payload,run_as) VALUES ('webhook',%s,%s) RETURNING *",
            (json.dumps({"target_url": target_url, "body": body.get("body", {})}), str(body.get("run_as", "user"))),
        ).fetchone()
        conn.commit()
    return dict(row)


@app.post("/jobs")
def create_job(body: JobBody, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    principal(authorization)
    with connection() as conn:
        row = conn.execute(
            "INSERT INTO jobs (kind,payload,run_as) VALUES (%s,%s,%s) RETURNING *",
            (body.kind, json.dumps(body.payload), body.run_as),
        ).fetchone()
        conn.commit()
    return dict(row)


@app.get("/debug/config")
def debug_config() -> dict[str, Any]:
    return {"database_url": DATABASE_URL, "mock_external_url": MOCK_EXTERNAL_URL, "app_secret": os.environ.get("APP_SECRET")}


@app.get("/logout")
def logout() -> dict[str, str]:
    return {"status": "logged out"}
