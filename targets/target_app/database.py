"""Creates a disposable in-memory database for each educational request."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager


@contextmanager
def demo_database() -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL
        );

        INSERT INTO users (username, email) VALUES
            ('alice', 'alice@example.test'),
            ('bob', 'bob@example.test'),
            ('charlie', 'charlie@example.test');
        """
    )
    try:
        yield connection
    finally:
        connection.close()
