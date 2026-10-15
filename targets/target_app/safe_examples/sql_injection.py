"""Safe counterpart to the CWE-89 SQL injection example."""

from __future__ import annotations

import sqlite3


def find_users_safe(
    connection: sqlite3.Connection,
    username: str,
) -> list[dict[str, object]]:
    """Return matching users with a parameterized SQL query."""
    query = "SELECT id, username, email FROM users WHERE username = ?"
    rows = connection.execute(query, (username,)).fetchall()
    return [dict(row) for row in rows]

