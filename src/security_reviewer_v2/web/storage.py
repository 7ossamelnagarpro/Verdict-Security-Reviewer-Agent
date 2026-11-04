"""Persistent local projects and jobs; never stores credential values."""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path


def data_root() -> Path:
    return Path(
        os.environ.get(
            "VERDICT_DATA_ROOT", str(Path.home() / "VerdictSecurityReviewer")
        )
    ).resolve()


class Database:
    def __init__(self, root: Path | None = None):
        self.root = root or data_root()
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "verdict.db"
        with self.connect() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, status TEXT NOT NULL, data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS projects (id TEXT PRIMARY KEY, data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS settings (id TEXT PRIMARY KEY, data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS removed_history (id TEXT PRIMARY KEY);
            """)

    def connect(self):
        connection = sqlite3.connect(self.path, timeout=30)
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def all(self, table: str) -> list[dict]:
        self._table(table)
        with self.connect() as connection:
            return [
                json.loads(row[0])
                for row in connection.execute(
                    f"SELECT data FROM {table} ORDER BY rowid DESC"
                )
            ]

    def get(self, table: str, identifier: str) -> dict | None:
        self._table(table)
        with self.connect() as connection:
            row = connection.execute(
                f"SELECT data FROM {table} WHERE id=?", (identifier,)
            ).fetchone()
        return json.loads(row[0]) if row else None

    def removed_history(self) -> set[str]:
        with self.connect() as connection:
            return {
                row[0] for row in connection.execute("SELECT id FROM removed_history")
            }

    def change_history(
        self, identifier: str | None = None, *, remove: bool = True
    ) -> int:
        """Hide finished records reversibly. Reports, workers and projects are untouched."""
        terminal = {"completed", "failed", "cancelled", "interrupted"}
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if identifier is not None:
                row = connection.execute(
                    "SELECT status FROM jobs WHERE id=?", (identifier,)
                ).fetchone()
                if row is None:
                    raise ValueError("Review not found")
                if row[0] not in terminal:
                    raise ValueError(
                        "Finish or recover this review before removing it from history"
                    )
                identifiers = [identifier]
            else:
                identifiers = [
                    row[0]
                    for row in connection.execute("SELECT id, status FROM jobs")
                    if row[1] in terminal
                ]
            before = connection.total_changes
            if remove:
                connection.executemany(
                    "INSERT OR IGNORE INTO removed_history(id) VALUES (?)",
                    [(i,) for i in identifiers],
                )
            else:
                connection.executemany(
                    "DELETE FROM removed_history WHERE id=?",
                    [(i,) for i in identifiers],
                )
            return connection.total_changes - before

    def save(self, table: str, value: dict, *, exclusive_job: bool = False):
        self._table(table)
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if (
                exclusive_job
                and connection.execute(
                    "SELECT 1 FROM jobs WHERE status IN ('queued','running','cancelling','cleanup_failed') LIMIT 1"
                ).fetchone()
            ):
                raise ValueError(
                    "A review is already running; wait for it to finish or cancel it"
                )
            if table == "jobs":
                connection.execute(
                    "INSERT OR REPLACE INTO jobs VALUES (?, ?, ?)",
                    (value["id"], value["status"], json.dumps(value)),
                )
            else:
                connection.execute(
                    f"INSERT OR REPLACE INTO {table} VALUES (?, ?)",
                    (value["id"], json.dumps(value)),
                )

    @staticmethod
    def _table(table):
        if table not in {"jobs", "projects", "settings"}:
            raise ValueError("Unknown store")
