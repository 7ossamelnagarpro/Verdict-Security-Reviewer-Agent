"""Local educational web fixture. Never deploy it on a public network."""

import sqlite3
import os
import subprocess
import uuid
from flask import Flask, request, g, redirect, session, jsonify, make_response, send_from_directory

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "vulnshop.db")
UPLOAD_DIR = os.path.join(APP_DIR, "uploads")
FILES_DIR = os.path.join(APP_DIR, "files")

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(FILES_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = "dev-not-secret"


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------
def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()


def init_db():
    if os.path.exists(DB_PATH):
        return
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT,
            email TEXT,
            ssn TEXT
        );
        CREATE TABLE orders (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            item TEXT,
            total TEXT,
            card_last4 TEXT
        );
        CREATE TABLE comments (
            id INTEGER PRIMARY KEY,
            author TEXT,
            body TEXT
        );
        """
    )
    db.executemany(
        "INSERT INTO users (id, username, password, role, email, ssn) VALUES (?,?,?,?,?,?)",
        [
            (1, "alice", "alice123", "user", "alice@example.com", "100-11-0001"),
            (2, "bob", "bob123", "user", "bob@example.com", "100-11-0002"),
            (3, "admin", "admin123", "admin", "admin@example.com", "100-11-0000"),
        ],
    )
    db.executemany(
        "INSERT INTO orders (id, user_id, item, total, card_last4) VALUES (?,?,?,?,?)",
        [
            (100, 1, "Laptop", "1200.00", "4242"),
            (101, 2, "Phone", "800.00", "9191"),
            (102, 1, "Headphones", "150.00", "4242"),
            (103, 3, "Server rack", "4000.00", "0000"),
        ],
    )
    db.executemany(
        "INSERT INTO comments (id, author, body) VALUES (?,?,?)",
        [(1, "alice", "Great shop!"), (2, "bob", "Fast shipping.")],
    )
    db.commit()
    db.close()


SAMPLE_FILES = {"report.txt": "Public Q1 report. Nothing sensitive here.\n"}
for name, content in SAMPLE_FILES.items():
    path = os.path.join(FILES_DIR, name)
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(content)

SECRET_PATH = os.path.join(APP_DIR, "secret_do_not_serve.txt")
if not os.path.exists(SECRET_PATH):
    with open(SECRET_PATH, "w") as f:
        f.write("TOP-SECRET: db password = hunter2 / flag{path_traversal_found}\n")


# ---------------------------------------------------------------------------
# Session token helper
# ---------------------------------------------------------------------------
def make_token(user_id):
    return f"tok-{user_id}-staticsalt"


# ---------------------------------------------------------------------------
# Home / nav
# ---------------------------------------------------------------------------
@app.route("/")
def home():
    return """
    <h1>Security Lab Web</h1>
    <ul>
      <li><a href="/login">Login</a></li>
      <li><a href="/search?q=laptop">Search</a></li>
      <li><a href="/comments">Comments</a></li>
      <li><a href="/orders/100">Order #100</a></li>
      <li><a href="/files/report.txt">Files</a></li>
      <li><a href="/admin">Admin panel</a></li>
      <li><a href="/ping?host=127.0.0.1">Ping tool</a></li>
      <li><a href="/debug">Debug info</a></li>
    </ul>
    """


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return """
        <form method="post">
          user: <input name="username"><br>
          pass: <input name="password" type="password"><br>
          <button type="submit">Login</button>
        </form>
        """
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    db = get_db()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    try:
        row = db.execute(query).fetchone()
    except sqlite3.Error as e:
        return f"<pre>DB ERROR: {e}\nQuery was: {query}</pre>", 500

    if row:
        session["user_id"] = row["id"]
        session["role"] = row["role"]
        resp = make_response(redirect(f"/profile/{row['id']}"))
        resp.set_cookie("token", make_token(row["id"]))
        return resp
    return "Invalid credentials", 401


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------
@app.route("/search")
def search():
    q = request.args.get("q", "")
    db = get_db()
    query = f"SELECT id, item, total FROM orders WHERE item LIKE '%{q}%'"
    try:
        rows = db.execute(query).fetchall()
    except sqlite3.Error as e:
        return f"<pre>DB ERROR: {e}\nQuery: {query}</pre>", 500
    html = f"<h2>Results for: {q}</h2><ul>"
    for r in rows:
        html += f"<li>#{r['id']} {r['item']} - ${r['total']}</li>"
    html += "</ul>"
    return html


# ---------------------------------------------------------------------------
# Comments
# ---------------------------------------------------------------------------
@app.route("/comments", methods=["GET", "POST"])
def comments():
    db = get_db()
    if request.method == "POST":
        author = request.form.get("author", "anon")
        body = request.form.get("body", "")
        db.execute("INSERT INTO comments (author, body) VALUES (?,?)", (author, body))
        db.commit()
        return redirect("/comments")
    rows = db.execute("SELECT author, body FROM comments").fetchall()
    html = """
    <h2>Comments</h2>
    <form method="post">
      name: <input name="author"><br>
      comment: <textarea name="body"></textarea><br>
      <button type="submit">Post</button>
    </form>
    <ul>
    """
    for r in rows:
        html += f"<li><b>{r['author']}</b>: {r['body']}</li>"
    html += "</ul>"
    return html


# ---------------------------------------------------------------------------
# Orders
# ---------------------------------------------------------------------------
@app.route("/orders/<int:order_id>")
def view_order(order_id):
    if "user_id" not in session:
        return redirect("/login")
    db = get_db()
    row = db.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    if not row:
        return "Not found", 404
    return jsonify(dict(row))


# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------
@app.route("/profile/<int:user_id>")
def profile(user_id):
    if "user_id" not in session:
        return redirect("/login")
    db = get_db()
    row = db.execute(
        "SELECT id, username, email, ssn, role FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if not row:
        return "Not found", 404
    return jsonify(dict(row))


# ---------------------------------------------------------------------------
# Admin panel
# ---------------------------------------------------------------------------
@app.route("/admin")
def admin_panel():
    role = request.args.get("role") or session.get("role")
    if role != "admin":
        pass
    db = get_db()
    users = db.execute("SELECT id, username, role, email, ssn FROM users").fetchall()
    return jsonify([dict(u) for u in users])


# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------
@app.route("/files/<path:filename>")
def get_file(filename):
    full_path = os.path.join(FILES_DIR, filename)
    try:
        with open(full_path, "r", errors="replace") as f:
            content = f.read()
        return f"<pre>{content}</pre>"
    except Exception as e:
        return f"<pre>Error: {e}</pre>", 404


# ---------------------------------------------------------------------------
# Ping tool
# ---------------------------------------------------------------------------
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    cmd = f"ping -c 1 {host}"
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=5)
        return f"<pre>{out.decode(errors='replace')}</pre>"
    except Exception as e:
        return f"<pre>{e}</pre>"


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------
@app.route("/debug")
def debug():
    return jsonify(
        {
            "secret_key": app.secret_key,
            "db_path": DB_PATH,
            "env": dict(os.environ),
            "note": "This endpoint should never exist in production.",
        }
    )


# ---------------------------------------------------------------------------
# Response headers
# ---------------------------------------------------------------------------
@app.after_request
def add_cors(resp):
    origin = request.headers.get("Origin")
    if origin:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


# ---------------------------------------------------------------------------
# Uploads
# ---------------------------------------------------------------------------
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "GET":
        return """
        <form method="post" enctype="multipart/form-data">
          <input type="file" name="file"><button type="submit">Upload</button>
        </form>
        """
    f = request.files.get("file")
    if not f:
        return "No file", 400
    dest = os.path.join(UPLOAD_DIR, f.filename)
    f.save(dest)
    return f"Saved to /uploads/{f.filename}"


@app.route("/uploads/<path:filename>")
def serve_upload(filename):
    return send_from_directory(UPLOAD_DIR, filename)


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    init_db()
    print("Security Lab Web running on http://127.0.0.1:5000/")
    app.run(host="127.0.0.1", port=5000, debug=True)
