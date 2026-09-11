from .common import finding, get
def run(ctx):
    out=[]; r=get(ctx,"/.env","storage")
    if r.status_code == 200 and r.text.strip(): out.append(finding("Data Storage & Privacy Protections", "Environment file exposed over HTTP", "A sensitive .env-style response was publicly reachable.", "/.env", "Critical", "GET /.env HTTP/1.1", r.text, "Remove sensitive files from the web root, revoke exposed secrets, and deny dotfiles at the server layer."))
    r=get(ctx,"/error","storage")
    if r.status_code >= 500 and any(x in r.text.lower() for x in ("traceback", "exception", "file \"")): out.append(finding("Data Storage & Privacy Protections", "Verbose error page exposes internals", "An error route returned a stack trace or file path.", "/error", "Medium", "GET /error HTTP/1.1", r.text, "Return generic client errors and retain stack traces only in protected logs."))
    return out
