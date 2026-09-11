from .common import finding
def run(ctx):
    out=[]
    if ctx.target.startswith("http://"):
        out.append(finding("Secure Communication Mechanisms", "Target uses unencrypted HTTP", "The supplied target URL is HTTP and does not protect traffic in transit.", ctx.target, "High", "GET / HTTP/1.1", remediation="Serve the application exclusively over HTTPS and redirect HTTP to HTTPS; enable HSTS."))
    else:
        r=ctx.request("GET",ctx.target,"tls");
        if not r.headers.get("Strict-Transport-Security"): out.append(finding("Secure Communication Mechanisms", "HSTS header missing", "HTTPS target did not return Strict-Transport-Security.", "/", "Medium", remediation="Enable HSTS after HTTPS is fully deployed."))
    return out
