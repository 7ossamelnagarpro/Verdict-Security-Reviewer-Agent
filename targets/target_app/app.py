"""Local Flask app exposing matched vulnerable and safe examples."""

from __future__ import annotations

from flask import Flask, jsonify, request

from targets.target_app.database import demo_database
from targets.target_app.safe_examples.sql_injection import find_users_safe
from targets.target_app.vulnerable_examples.sql_injection import find_users_vulnerable


def create_app() -> Flask:
    app = Flask(__name__)

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "purpose": "local-security-training"})

    @app.get("/vulnerable/users")
    def vulnerable_users():
        username = request.args.get("username", "")
        with demo_database() as connection:
            users = find_users_vulnerable(connection, username)
        return jsonify(
            {
                "example_id": "SQLI-001-VULN",
                "warning": "Intentionally vulnerable local training endpoint",
                "count": len(users),
                "users": users,
            }
        )

    @app.get("/safe/users")
    def safe_users():
        username = request.args.get("username", "")
        with demo_database() as connection:
            users = find_users_safe(connection, username)
        return jsonify(
            {
                "example_id": "SQLI-001-SAFE",
                "count": len(users),
                "users": users,
            }
        )

    return app


if __name__ == "__main__":
    print("WARNING: intentionally vulnerable training app; local use only.")
    create_app().run(host="127.0.0.1", port=5000, debug=False)
