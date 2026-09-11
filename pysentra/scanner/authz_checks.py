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
        if r.status_code == 200:
            out.append(
                finding(
                    "Authorization & Access Control",
                    "IDOR: another user's order is readable",
                    "A token for one user successfully retrieved order 2.",
                    "/api/order/2",
                    "High",
                    "GET /api/order/2 HTTP/1.1\nAuthorization: Bearer [user token]",
                    getattr(r, "text", ""),
                    "Enforce object ownership server-side for every request.",
                )
            )
    else:
        out.append(
            finding(
                "Authorization & Access Control",
                "IDOR check needs two test tokens",
                "Provide --auth-token and --second-auth-token to enable read-only cross-user tests.",
                "/api/order/<id>",
                "Info",
                remediation="Test object authorization with two accounts in an approved environment.",
            )
        )
    r = get(ctx, "/admin", "authz")
    if r.status_code == 200:
        out.append(
            finding(
                "Authorization & Access Control",
                "Unauthenticated admin path accessible",
                "Forced browsing reached an admin endpoint without credentials.",
                "/admin",
                "High",
                "GET /admin HTTP/1.1",
                getattr(r, "text", ""),
                "Require authentication and role checks for administration endpoints.",
            )
        )
    return out
