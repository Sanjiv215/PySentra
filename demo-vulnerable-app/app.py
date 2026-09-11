"""Intentionally vulnerable local demo. Never deploy this application."""

from pathlib import Path

from flask import Flask, jsonify, make_response, request

app = Flask(__name__, static_folder=str(Path(__file__).parent / "static"))
USERS = [
    {"id": 1, "email": "alice@example.test", "password_hash": "sha256$demo-alice"},
    {"id": 2, "email": "bob@example.test", "password_hash": "sha256$demo-bob"},
]


@app.get("/")
def home():
    html = '<h1>World Monitor demo</h1><a href="/login">Login</a><script src="/static/app.js"></script>'
    response = make_response(html)
    response.set_cookie("session", "demo-session-0001")
    return response


@app.get("/login")
def login():
    return (
        '<form method="post">'
        '<input name="username">'
        '<input name="password" type="password">'
        '<button>Sign in</button>'
        '</form>'
    )


@app.get("/search")
def search():
    return "<h1>Search results</h1><p>You searched for: %s</p>" % request.args.get("q", "")


@app.get("/api/v1/users")
def users():
    response = jsonify(USERS)
    origin = request.headers.get("Origin")
    if origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    return response


@app.get("/api/order/<int:order_id>")
def order(order_id):
    return jsonify({"id": order_id, "owner_id": 2, "item": "restricted monitoring record", "amount": 125})


@app.get("/admin")
def admin():
    return "<h1>Admin dashboard</h1><p>Unprotected demo admin panel.</p>"


@app.get("/.env")
def env():
    return "FLASK_SECRET=demo-not-a-real-secret\nDATABASE_URL=sqlite:///demo.db\n"


@app.get("/error")
def error():
    trace = (
        '<pre>Traceback (most recent call last):\n'
        '  File "/srv/world-monitor/app.py", line 42\n'
        'Exception: demo database failure</pre>'
    )
    return trace, 500


@app.get("/robots.txt")
def robots():
    return "User-agent: *\nDisallow: /admin\nDisallow: /.env\n"


@app.get("/swagger.json")
def swagger():
    return jsonify({"swagger": "2.0", "paths": {"/api/v1/users": {}}})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
