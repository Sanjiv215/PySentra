"""Authorization and access control security checks."""

from typing import List

from pysentra.report.models import Finding

from .common import ContextProtocol, finding, get


def run(ctx: ContextProtocol) -> List[Finding]:
    """Execute authorization and access control checks."""
    out: List[Finding] = []
    if ctx.auth_token and ctx.second_auth_token:
        headers = {"Authorization": "Bearer " + str(ctx.auth_token)}
        r = get(ctx, "/api/order/2", "authz", headers=headers)
        if r.status_code == 200 and r.text.strip():
            out.append(
                finding(
                    "Authorization & Access Control",
                    "IDOR: another user's order is readable",
                    "A token for one user successfully retrieved order 2.",
                    "/api/order/2",
                    "High",
                    "GET /api/order/2 HTTP/1.1\nAuthorization: Bearer [user token]",
                    getattr(r, "text", "")[:500],
                    "Enforce object ownership server-side for every request.",
                )
            )
    r = get(ctx, "/admin", "authz")
    if r.status_code == 200:
        r_text = getattr(r, "text", "")
        if r_text.strip():
            out.append(
                finding(
                    "Authorization & Access Control",
                    "Unauthenticated admin path accessible",
                    "Forced browsing reached an admin endpoint without credentials.",
                    "/admin",
                    "High",
                    "GET /admin HTTP/1.1",
                    r_text[:500],
                    "Require authentication and role checks for administration endpoints.",
                )
            )
    return out
