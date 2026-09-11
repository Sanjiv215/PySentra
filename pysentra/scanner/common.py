"""Common helper functions and constants for scanner check modules."""

from typing import Any, Dict, Protocol
from urllib.parse import urljoin

from pysentra.report.cvss import base_score
from pysentra.report.models import Finding

VECTORS: Dict[str, str] = {
    "Critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
    "High": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    "Medium": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "Low": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "Info": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N",
}


class ContextProtocol(Protocol):
    """Protocol defining the interface required by scanner check functions."""

    target: str
    test_app: bool
    auth_token: Any
    second_auth_token: Any

    def request(self, method: str, url: str, module: str, **kwargs: Any) -> Any:
        ...


def finding(
    scope: str,
    title: str,
    description: str,
    component: str,
    severity: str,
    request: str = "",
    response: str = "",
    remediation: str = "Restrict access and apply secure defaults.",
) -> Finding:
    """Create a standardized Finding instance with CVSS scoring."""
    vector = VECTORS.get(severity, VECTORS["Info"])
    return Finding(
        title=title,
        scope_area=scope,
        description=description,
        affected_component=component,
        severity=severity,
        cvss_score=base_score(vector),
        cvss_vector=vector,
        steps_to_reproduce=[
            "Only test systems you are authorized to assess.",
            "Send the request shown below and observe the response.",
        ],
        poc_request=request,
        poc_response_snippet=response[:500] if response else "",
        business_impact="An attacker may expose data or weaken application security controls.",
        remediation=remediation,
    )


def get(ctx: ContextProtocol, path: str, module: str, **kwargs: Any) -> Any:
    """Convenience helper to issue an audited GET request against ctx.target."""
    full_url = urljoin(ctx.target + "/", path.lstrip("/"))
    return ctx.request("GET", full_url, module, **kwargs)
