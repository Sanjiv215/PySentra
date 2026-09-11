from urllib.parse import urljoin
from pysentra.report.models import Finding
from pysentra.report.cvss import base_score

VECTORS = {"Critical":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N", "High":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", "Medium":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", "Low":"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", "Info":"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N"}
def finding(scope, title, description, component, severity, request="", response="", remediation="Restrict access and apply secure defaults."):
    vector=VECTORS[severity]
    return Finding(title, scope, description, component, severity, base_score(vector), vector,
        ["Only test systems you are authorized to assess.", "Send the request shown below and observe the response."], request, response[:500],
        "An attacker may expose data or weaken application security controls.", remediation)
def get(ctx, path, module, **kwargs): return ctx.request("GET", urljoin(ctx.target + "/", path.lstrip("/")), module, **kwargs)
