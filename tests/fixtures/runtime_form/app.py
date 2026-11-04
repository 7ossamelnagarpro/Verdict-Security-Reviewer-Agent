"""Disposable form-login smoke fixture. Never deploy as an application."""

from flask import Flask, redirect, request, session

app = Flask(__name__)
app.secret_key = "non-secret-disposable-test-fixture"


@app.get("/")
def index():
    if session.get("test_user"):
        return 'Signed in successfully. <a href="/account">My account</a>'
    return '<a href="/login">Log in</a>'


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if (
            request.form.get("username") == "demo"
            and request.form.get("password") == "demo-test-only"
        ):
            session["test_user"] = True
            return redirect("/")
        return "Login failed", 401
    return '<form method="post"><input name="username"><input name="password" type="password"><button>Log in</button></form>'


@app.get("/account")
def account():
    return (
        ("Signed in successfully. Test account", 200)
        if session.get("test_user")
        else ("Login required", 401)
    )
