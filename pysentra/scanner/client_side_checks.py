"""Client-side security controls checks."""

import re
from typing import List

from pysentra.report.models import Finding

from .common import ContextProtocol, finding, get


def run(ctx: ContextProtocol) -> List[Finding]:
    """Execute client-side security control checks."""
    out: List[Finding] = []
    r = get(ctx, "/", "client")
    h = getattr(r, "headers", {})
    if r.status_code != 200:
        return out
    if not h.get("Content-Security-Policy"):
        out.append(
            finding(
                "Client-Side Security Controls",
                "Content Security Policy missing",
                "No CSP response header was observed.",
                "/",
                "Medium",
                "GET / HTTP/1.1",
                str(dict(h)),
                "Deploy a restrictive Content-Security-Policy, avoiding unsafe-inline where possible.",
            )
        )
    if not h.get("X-Frame-Options") and "frame-ancestors" not in h.get("Content-Security-Policy", ""):
        out.append(
            finding(
                "Client-Side Security Controls",
                "Clickjacking protection missing",
                "Neither X-Frame-Options nor CSP frame-ancestors was found.",
                "/",
                "Medium",
                "GET / HTTP/1.1",
                str(dict(h)),
                "Set X-Frame-Options: DENY or a CSP frame-ancestors directive.",
            )
        )
    js = get(ctx, "/static/app.js", "client")
    js_text = getattr(js, "text", "")
    if js.status_code == 200 and re.search(r"(?:api[_-]?key|secret)\s*[=:]\s*['\"]", js_text, re.I):
        out.append(
            finding(
                "Client-Side Security Controls",
                "Hardcoded secret in JavaScript",
                "A key-like value was found in downloadable client code.",
                "/static/app.js",
                "High",
                "GET /static/app.js HTTP/1.1",
                js_text[:500],
                "Remove secrets from client bundles; rotate exposed credentials and use server-side storage.",
            )
        )
    return out
