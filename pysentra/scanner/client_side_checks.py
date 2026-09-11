from .common import finding, get
import re
def run(ctx):
    out=[]; r=get(ctx,"/","client"); h=r.headers
    if r.status_code != 200: return out
    if not h.get("Content-Security-Policy"): out.append(finding("Client-Side Security Controls", "Content Security Policy missing", "No CSP response header was observed.", "/", "Medium", "GET / HTTP/1.1", str(dict(h)), "Deploy a restrictive Content-Security-Policy, avoiding unsafe-inline where possible."))
    if not h.get("X-Frame-Options") and "frame-ancestors" not in h.get("Content-Security-Policy",""): out.append(finding("Client-Side Security Controls", "Clickjacking protection missing", "Neither X-Frame-Options nor CSP frame-ancestors was found.", "/", "Medium", "GET / HTTP/1.1", str(dict(h)), "Set X-Frame-Options: DENY or a CSP frame-ancestors directive."))
    js=get(ctx,"/static/app.js","client")
    if js.status_code == 200 and re.search(r"(?:api[_-]?key|secret)\s*[=:]\s*['\"]",js.text,re.I): out.append(finding("Client-Side Security Controls", "Hardcoded secret in JavaScript", "A key-like value was found in downloadable client code.", "/static/app.js", "High", "GET /static/app.js HTTP/1.1", js.text, "Remove secrets from client bundles; rotate exposed credentials and use server-side storage."))
    return out
