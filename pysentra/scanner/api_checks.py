"""API security checks."""

from typing import List

from pysentra.report.models import Finding

from .common import ContextProtocol, finding, get


def run(ctx: ContextProtocol) -> List[Finding]:
    """Execute API security checks."""
    out: List[Finding] = []
    r = get(ctx, "/api/v1/users", "api")
    r_text = getattr(r, "text", "")
    r_headers = getattr(r, "headers", {})
    if r.status_code == 200 and any(x in r_text.lower() for x in ("password_hash", "password", "email")):
        out.append(
            finding(
                "API Security",
                "API exposes sensitive user fields",
                "The API response contains password hashes and/or email data.",
                "/api/v1/users",
                "High",
                "GET /api/v1/users HTTP/1.1",
                r_text,
                "Return an allowlisted response schema; never return password hashes.",
            )
        )
    if r.status_code == 200 and not any(h.lower().startswith("x-ratelimit") for h in r_headers.keys()):
        out.append(
            finding(
                "API Security",
                "API rate-limit headers absent",
                "No X-RateLimit headers were observed; a small, rate-limited burst was not needed.",
                "/api/v1/users",
                "Low",
                "GET /api/v1/users HTTP/1.1",
                str(dict(r_headers)),
                "Apply request throttling and expose accurate limit headers.",
            )
        )
    for path in ("/robots.txt", "/sitemap.xml", "/swagger.json", "/openapi.json"):
        get(ctx, path, "api")
    return out
