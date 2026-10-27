from __future__ import annotations

import json
import os
import time
import urllib.request

import psycopg
from psycopg.rows import dict_row

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://lab:lab-only@db:5432/lab")


def run_job(job: dict) -> dict:
    if job["kind"] == "webhook":
        payload = job["payload"]
        request = urllib.request.Request(
            payload["target_url"],
            data=json.dumps(payload.get("body", {})).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=3) as response:
            return {"status": response.status, "worker_identity": job["run_as"]}
    return {"status": "completed", "kind": job["kind"], "worker_identity": job["run_as"]}


def main() -> None:
    while True:
        try:
            with psycopg.connect(DATABASE_URL, row_factory=dict_row) as conn:
                job = conn.execute(
                    "UPDATE jobs SET status='running' WHERE id=(SELECT id FROM jobs WHERE status='queued' ORDER BY id LIMIT 1) RETURNING *"
                ).fetchone()
                conn.commit()
                if job:
                    try:
                        result = run_job(job)
                        with psycopg.connect(DATABASE_URL) as update:
                            update.execute("UPDATE jobs SET status='complete',result=%s WHERE id=%s", (json.dumps(result), job["id"]))
                            update.commit()
                    except Exception as error:
                        with psycopg.connect(DATABASE_URL) as update:
                            update.execute("UPDATE jobs SET status='failed',result=%s WHERE id=%s", (json.dumps({"error": str(error)}), job["id"]))
                            update.commit()
        except psycopg.OperationalError:
            pass
        time.sleep(1)


if __name__ == "__main__":
    main()
