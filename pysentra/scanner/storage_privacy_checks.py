"""Data storage and privacy protection checks."""

from typing import List

from pysentra.report.models import Finding

from .common import ContextProtocol, finding, get


def run(ctx: ContextProtocol) -> List[Finding]:
    """Execute data storage and privacy checks."""
    out: List[Finding] = []
    r = get(ctx, "/.env", "storage")
    r_text = getattr(r, "text", "")
    if (
        r.status_code == 200
        and r_text.strip()
        and "<html" not in r_text.lower()
        and "<!doctype" not in r_text.lower()
        and any("=" in line for line in r_text.splitlines() if line.strip() and not line.strip().startswith("#"))
    ):
        out.append(
            finding(
                "Data Storage & Privacy Protections",
                "Environment file exposed over HTTP",
                "A sensitive .env-style response was publicly reachable.",
                "/.env",
                "Critical",
                "GET /.env HTTP/1.1",
                r_text[:500],
                "Remove sensitive files from the web root, revoke exposed secrets, "
                "and deny dotfiles at the server layer.",
            )
        )
    r_err = get(ctx, "/error", "storage")
    err_text = getattr(r_err, "text", "")
    err_signatures = ("traceback (most recent call last):", "exception", 'file "')
    if r_err.status_code >= 500 and any(x in err_text.lower() for x in err_signatures):
        out.append(
            finding(
                "Data Storage & Privacy Protections",
                "Verbose error page exposes internals",
                "An error route returned a stack trace or file path.",
                "/error",
                "Medium",
                "GET /error HTTP/1.1",
                err_text[:500],
                "Return generic client errors and retain stack traces only in protected logs.",
            )
        )
    return out
