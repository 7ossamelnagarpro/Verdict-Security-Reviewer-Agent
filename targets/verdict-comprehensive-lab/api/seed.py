from __future__ import annotations

import os
import time

import psycopg

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://lab:lab-only@localhost:5432/lab")


def reset() -> None:
    from api.app import init_db

    for _ in range(30):
        try:
            with psycopg.connect(DATABASE_URL) as conn:
                conn.execute("DROP TABLE IF EXISTS products, sessions, reset_tokens, login_attempts, notes, comments, uploads, visits, refresh_tokens, invoices, jobs, orders, coupons, users CASCADE")
                conn.commit()
            init_db()
            from api.extra import init_extra
            init_extra()
            return
        except psycopg.OperationalError:
            time.sleep(1)
    raise RuntimeError("database did not become ready")


if __name__ == "__main__":
    reset()
    print("seed reset complete")
