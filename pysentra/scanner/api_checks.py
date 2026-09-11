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
    if r.status_code == 200:
        if any(x in r_text.lower() for x in ("password_hash", "password", "email")):
            out.append(
                finding(
                    "API Security",
                    "API exposes sensitive user fields",
                    "The API response contains password hashes and/or email data.",
                    "/api/v1/users",
                    "High",
                    "GET /api/v1/users HTTP/1.1",
                    r_text[:500],
                    "Return an allowlisted response schema; never return password hashes.",
                )
            )
        content_type = r_headers.get("Content-Type", "")
        rate_headers = ("ratelimit-limit", "ratelimit-remaining", "retry-after")
        has_rate_limit = any(h.lower().startswith("x-ratelimit") or h.lower() in rate_headers for h in r_headers.keys())
        if ("application/json" in content_type or r_text.startswith(("{", "["))) and not has_rate_limit:
            out.append(
                finding(
                    "API Security",
                    "API rate-limit headers absent",
                    "No RateLimit headers were observed on API response.",
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
