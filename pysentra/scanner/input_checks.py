from .common import finding, get
from urllib.parse import quote
def run(ctx):
    out=[]; marker="PYSENTRA_XSS_MARKER"; r=get(ctx,"/search?q="+quote(marker),"input")
    if r.status_code == 200 and marker in r.text: out.append(finding("Input Validation & Data Handling", "Reflected input is not output-encoded", "A harmless unique marker was reflected in the search response.", "/search", "Medium", "GET /search?q="+marker+" HTTP/1.1", r.text, "Contextually encode output and validate input; adopt a restrictive CSP."))
    r=get(ctx,"/api/v1/users?sort='","input")
    signatures=("sql", "sqlite", "syntax error", "operationalerror")
    if any(s in r.text.lower() for s in signatures): out.append(finding("Input Validation & Data Handling", "SQL error detail exposed", "A benign quote probe elicited a database error signature.", "/api/v1/users", "Medium", "GET /api/v1/users?sort=' HTTP/1.1", r.text, "Use parameterized queries and generic error handling."))
    if not ctx.test_app: out.append(finding("Input Validation & Data Handling", "Upload and mass-assignment tests skipped", "These checks are gated to test applications.", "Upload/API endpoints", "Info", remediation="Manually validate upload allowlists and DTO field allowlists."))
    return out
