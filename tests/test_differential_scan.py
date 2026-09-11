"""Regression test: verify scanner produces differential, target-specific findings."""

from urllib.parse import urlsplit

import requests
from flask import Flask, jsonify, make_response, request
from requests.structures import CaseInsensitiveDict

from pysentra.scanner.runner import run_scan


def create_hardened_app() -> Flask:
    app = Flask("hardened_app")

    @app.get("/")
    def home():
        resp = make_response("<h1>Hardened App</h1>")
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        resp.headers["Content-Security-Policy"] = "default-src 'self'"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers.add("Set-Cookie", "session=hardened123; HttpOnly; Secure; SameSite=Strict; Path=/")
        return resp

    @app.get("/login")
    def login():
        return (
            '<form method="post">'
            '<input type="hidden" name="csrf_token" value="abc">'
            '<input type="password" name="password">Enter 2FA Code'
            '</form>'
        )

    @app.get("/api/v1/users")
    def users():
        resp = jsonify([{"id": 1, "username": "user1"}])
        resp.headers["X-RateLimit-Limit"] = "100"
        resp.headers["X-RateLimit-Remaining"] = "99"
        return resp

    @app.get("/.env")
    def env():
        return ("Not Found", 404)

    @app.get("/admin")
    def admin():
        return ("Unauthorized", 401)

    @app.get("/search")
    def search():
        return "Clean search results"

    @app.get("/error")
    def err():
        return ("Internal Error", 500)

    return app


def create_vulnerable_app() -> Flask:
    app = Flask("vulnerable_app")

    @app.get("/")
    def home():
        resp = make_response("<h1>Vulnerable App</h1><script src='/static/app.js'></script>")
        resp.headers.add("Set-Cookie", "session=weak123; Path=/")
        return resp

    @app.get("/login")
    def login():
        return (
            '<form method="post">'
            '<input name="username">'
            '<input name="password" type="password">'
            '<button>Login</button>'
            '</form>'
        )

    @app.get("/api/v1/users")
    def users():
        resp = jsonify([{"id": 1, "email": "admin@vuln.local", "password_hash": "sha256$insecure"}])
        origin = request.headers.get("Origin")
        if origin:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Credentials"] = "true"
        return resp

    @app.get("/.env")
    def env():
        return "DATABASE_URL=postgres://admin:secret123@db.local/prod\nSECRET_KEY=supersecret\n"

    @app.get("/admin")
    def admin():
        return "<h1>Admin Panel</h1><p>Unrestricted administrative control</p>"

    @app.get("/search")
    def search():
        return "<h1>Search</h1><p>Results for " + request.args.get("q", "") + "</p>"

    @app.get("/error")
    def err():
        return ("Traceback (most recent call last):\n  File \"app.py\", line 42 in run\nException: boom", 500)

    return app


def test_differential_scan_reflects_actual_target_differences(monkeypatch, tmp_path):
    hardened_app = create_hardened_app()
    vulnerable_app = create_vulnerable_app()

    def mock_request(session, method, url, **kwargs):
        parsed = urlsplit(url)
        path = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")
        if "hardened.local" in parsed.netloc:
            flask_resp = hardened_app.test_client().open(path, method=method, headers=kwargs.get("headers"))
        elif "vulnerable.local" in parsed.netloc:
            flask_resp = vulnerable_app.test_client().open(path, method=method, headers=kwargs.get("headers"))
        else:
            flask_resp = make_response("404 Not Found", 404)

        result = requests.Response()
        result.status_code = flask_resp.status_code
        result._content = flask_resp.data
        result.headers = CaseInsensitiveDict(dict(flask_resp.headers))
        result.url = url
        return result

    monkeypatch.setattr(requests.Session, "request", mock_request)
    monkeypatch.chdir(tmp_path)

    modules = ["auth", "authz", "input", "api", "client", "tls", "storage"]

    # 1. Scan hardened target
    findings_hardened, _, report_hardened = run_scan(
        "https://hardened.local",
        modules,
        rate_limit=1000.0,
        test_app=False,
    )
    titles_hardened = {f.title for f in findings_hardened}

    # 2. Scan vulnerable target
    findings_vulnerable, _, report_vulnerable = run_scan(
        "http://vulnerable.local",
        modules,
        rate_limit=1000.0,
        test_app=False,
    )
    titles_vulnerable = {f.title for f in findings_vulnerable}

    # Hardened target should have ZERO findings because all security controls are met
    assert len(findings_hardened) == 0, f"Expected 0 findings on hardened target, got {titles_hardened}"

    # Vulnerable target must detect its specific security flaws
    expected_vulnerabilities = {
        "Target uses unencrypted HTTP",
        "Session cookie missing security attributes",
        "Login form lacks visible CSRF token",
        "Reflected input is not output-encoded",
        "API exposes sensitive user fields",
        "API rate-limit headers absent",
        "Content Security Policy missing",
        "Clickjacking protection missing",
        "Environment file exposed over HTTP",
        "Verbose error page exposes internals",
        "Unauthenticated admin path accessible",
        "Credentialed CORS origin reflection",
    }
    assert expected_vulnerabilities <= titles_vulnerable

    # Verify that the two reports are completely distinct and reflect individual responses
    assert titles_hardened != titles_vulnerable

    # Verify that evidence in findings contains actual server responses
    cors_finding = next(f for f in findings_vulnerable if f.title == "Credentialed CORS origin reflection")
    assert "https://pysentra.invalid" in cors_finding.poc_response_snippet
    assert "true" in cors_finding.poc_response_snippet

    env_finding = next(f for f in findings_vulnerable if f.title == "Environment file exposed over HTTP")
    assert "DATABASE_URL" in env_finding.poc_response_snippet


def test_finding_enforces_raw_evidence_and_rejects_phantom_titles():
    import pytest

    from pysentra.report.models import Finding

    # 1. Banned phantom title must raise ValueError
    with pytest.raises(ValueError, match="Prohibited phantom finding"):
        Finding(
            title="Account lockout not tested",
            scope_area="Authentication & Session Management",
            description="Fake desc",
            affected_component="/login",
            severity="Info",
            cvss_score=0.0,
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N",
            steps_to_reproduce=[],
            poc_request="",
            poc_response_snippet="fake evidence",
            business_impact="",
            remediation="",
        )

    # 2. Empty evidence must raise ValueError
    with pytest.raises(ValueError, match="without literal evidence"):
        Finding(
            title="Content Security Policy missing",
            scope_area="Client-Side Security Controls",
            description="Fake desc",
            affected_component="/",
            severity="Medium",
            cvss_score=5.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
            steps_to_reproduce=[],
            poc_request="GET / HTTP/1.1",
            poc_response_snippet="",
            business_impact="",
            remediation="",
        )

    # 3. Session cookie check without cookie content must raise ValueError
    with pytest.raises(ValueError, match="requires literal Set-Cookie header data"):
        Finding(
            title="Session cookie missing security attributes",
            scope_area="Authentication & Session Management",
            description="Fake desc",
            affected_component="/",
            severity="Medium",
            cvss_score=5.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
            steps_to_reproduce=[],
            poc_request="GET / HTTP/1.1",
            poc_response_snippet="no cookie here",
            business_impact="",
            remediation="",
        )

