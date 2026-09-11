"""Secure communication and TLS configuration checks."""

from typing import List

from pysentra.report.models import Finding

from .common import ContextProtocol, finding


def run(ctx: ContextProtocol) -> List[Finding]:
    """Execute TLS and secure communication checks."""
    out: List[Finding] = []
    if ctx.target.startswith("http://"):
        out.append(
            finding(
                "Secure Communication Mechanisms",
                "Target uses unencrypted HTTP",
                "The supplied target URL is HTTP and does not protect traffic in transit.",
                ctx.target,
                "High",
                f"GET {ctx.target}/ HTTP/1.1",
                "Protocol: http:// (unencrypted plaintext transport)",
                remediation="Serve the application exclusively over HTTPS and redirect HTTP to HTTPS; enable HSTS.",
            )
        )
    else:
        r = ctx.request("GET", ctx.target, "tls")
        headers = getattr(r, "headers", {})
        if getattr(r, "status_code", 0) > 0 and not headers.get("Strict-Transport-Security"):
            out.append(
                finding(
                    "Secure Communication Mechanisms",
                    "HSTS header missing",
                    "HTTPS target did not return Strict-Transport-Security.",
                    "/",
                    "Medium",
                    f"GET {ctx.target} HTTP/1.1",
                    str(dict(headers)),
                    remediation="Enable HSTS after HTTPS is fully deployed.",
                )
            )
    return out
