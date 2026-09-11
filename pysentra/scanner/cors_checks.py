"""CORS configuration checks."""

from typing import List

from pysentra.report.models import Finding

from .common import ContextProtocol, finding


def run(ctx: ContextProtocol) -> List[Finding]:
    """Execute CORS misconfiguration checks."""
    r = ctx.request(
        "GET",
        ctx.target + "/api/v1/users",
        "cors",
        headers={"Origin": "https://pysentra.invalid"},
    )
    h = getattr(r, "headers", {})
    origin = h.get("Access-Control-Allow-Origin", "")
    creds = h.get("Access-Control-Allow-Credentials", "").lower()
    if getattr(r, "status_code", 0) in (200, 201, 204) and origin == "https://pysentra.invalid" and creds == "true":
        return [
            finding(
                "API Security",
                "Credentialed CORS origin reflection",
                "An arbitrary Origin was reflected while credentials are allowed.",
                "/api/v1/users",
                "Critical",
                "GET /api/v1/users HTTP/1.1\nOrigin: https://pysentra.invalid",
                str(dict(h)),
                "Use a strict allowlist of trusted origins; never reflect arbitrary origins with credentials.",
            )
        ]
    return []
