"""CWE-89: intentionally vulnerable SQL query construction."""

from __future__ import annotations

import sqlite3


def find_users_vulnerable(
    connection: sqlite3.Connection,
    username: str,
) -> list[dict[str, object]]:
    """Return matching users using deliberately unsafe string concatenation."""
    query = (
        "SELECT id, username, email FROM users "
        f"WHERE username = '{username}'"
    )
    rows = connection.execute(query).fetchall()
    return [dict(row) for row in rows]

