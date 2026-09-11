"""Authentication and session management security checks."""

from typing import List

from pysentra.report.models import Finding

from .common import ContextProtocol, finding, get


def run(ctx: ContextProtocol) -> List[Finding]:
    """Execute authentication and session management checks."""
    out: List[Finding] = []
    r = get(ctx, "/", "auth")
    if r.status_code == 200:
        cookie = r.headers.get("Set-Cookie")
        if cookie:
            missing = [x for x in ("HttpOnly", "Secure", "SameSite") if x.lower() not in cookie.lower()]
            if missing:
                out.append(
                    finding(
                        "Authentication & Session Management",
                        "Session cookie missing security attributes",
                        "The session cookie lacks: " + ", ".join(missing),
                        "/",
                        "Medium",
                        "GET / HTTP/1.1",
                        cookie,
                        "Set HttpOnly, Secure, and an appropriate SameSite value on session cookies.",
                    )
                )
    login = get(ctx, "/login", "auth")
    if login.status_code == 200:
        form = getattr(login, "text", "")
        if "<form" in form.lower() or "password" in form.lower():
            if "csrf" not in form.lower() and "token" not in form.lower():
                out.append(
                    finding(
                        "Authentication & Session Management",
                        "Login form lacks visible CSRF token",
                        "The login form did not expose a CSRF token.",
                        "/login",
                        "Medium",
                        "GET /login HTTP/1.1",
                        form[:500],
                        "Use a server-validated CSRF token and SameSite cookies.",
                    )
                )
    return out
