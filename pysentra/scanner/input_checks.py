"""Input validation and data handling security checks."""

from typing import List
from urllib.parse import quote

from pysentra.report.models import Finding

from .common import ContextProtocol, finding, get


def run(ctx: ContextProtocol) -> List[Finding]:
    """Execute input validation and data handling checks."""
    out: List[Finding] = []
    marker = "PYSENTRA_XSS_MARKER"
    r = get(ctx, "/search?q=" + quote(marker), "input")
    r_text = getattr(r, "text", "")
    if r.status_code == 200 and marker in r_text:
        out.append(
            finding(
                "Input Validation & Data Handling",
                "Reflected input is not output-encoded",
                "A harmless unique marker was reflected in the search response.",
                "/search",
                "Medium",
                "GET /search?q=" + marker + " HTTP/1.1",
                r_text,
                "Contextually encode output and validate input; adopt a restrictive CSP.",
            )
        )
    r = get(ctx, "/api/v1/users?sort='", "input")
    sql_text = getattr(r, "text", "")
    signatures = ("sql", "sqlite", "syntax error", "operationalerror")
    if any(s in sql_text.lower() for s in signatures):
        out.append(
            finding(
                "Input Validation & Data Handling",
                "SQL error detail exposed",
                "A benign quote probe elicited a database error signature.",
                "/api/v1/users",
                "Medium",
                "GET /api/v1/users?sort=' HTTP/1.1",
                sql_text,
                "Use parameterized queries and generic error handling.",
            )
        )
    if not ctx.test_app:
        out.append(
            finding(
                "Input Validation & Data Handling",
                "Upload and mass-assignment tests skipped",
                "These checks are gated to test applications.",
                "Upload/API endpoints",
                "Info",
                remediation="Manually validate upload allowlists and DTO field allowlists.",
            )
        )
    return out
