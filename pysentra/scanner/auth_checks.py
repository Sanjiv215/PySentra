"""Authentication and session management security checks."""

from typing import List

from pysentra.report.models import Finding

from .common import ContextProtocol, finding, get


def run(ctx: ContextProtocol) -> List[Finding]:
    """Execute authentication and session management checks."""
    out: List[Finding] = []
    r = get(ctx, "/", "auth")
    if r.status_code != 200:
        return out
    cookie = r.headers.get("Set-Cookie", "")
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
    form = getattr(login, "text", "")
    if login.status_code == 200 and "csrf" not in form.lower():
        out.append(
            finding(
                "Authentication & Session Management",
                "Login form lacks visible CSRF token",
                "The login form did not expose a CSRF token.",
                "/login",
                "Medium",
                "GET /login HTTP/1.1",
                form,
                "Use a server-validated CSRF token and SameSite cookies.",
            )
        )
    if not ctx.test_app:
        out.append(
            finding(
                "Authentication & Session Management",
                "Account lockout not tested",
                "Rate/lockout tests are intentionally skipped without --target-is-test-app.",
                "/login",
                "Info",
                remediation="Manually verify rate limiting and lockout on an authorized test environment.",
            )
        )
    out.append(
        finding(
            "Authentication & Session Management",
            "MFA presence requires verification",
            "No MFA indicator was discovered during passive page inspection.",
            "/login",
            "Info",
            remediation="Offer MFA and require it for privileged accounts.",
        )
    )
    return out
