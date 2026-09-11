"""Scanner runner and orchestration for web applications and local codebases."""

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import requests

from pysentra.audit.logger import AuditLogger
from pysentra.report.aggregator import write_report
from pysentra.report.models import Finding

from . import (
    api_checks,
    auth_checks,
    authz_checks,
    client_side_checks,
    code_checks,
    cors_checks,
    input_checks,
    storage_privacy_checks,
    tls_checks,
)

MODULES: Dict[str, Any] = {
    "auth": auth_checks,
    "authz": authz_checks,
    "input": input_checks,
    "api": api_checks,
    "client": client_side_checks,
    "tls": tls_checks,
    "storage": storage_privacy_checks,
}


class FailedResponse:
    """Fallback response object returned when network requests encounter exceptions."""

    status_code: int = 0
    text: str = ""
    headers: Dict[str, str] = {}

    def __init__(self, message: str) -> None:
        self.text = message


class ScanContext:
    """Execution context holding configuration, rate limits, sessions, and audit logger."""

    def __init__(
        self,
        target: str,
        rate_limit: float,
        test_app: bool = False,
        auth_token: Optional[str] = None,
        second_auth_token: Optional[str] = None,
    ) -> None:
        self.target = target.rstrip("/")
        self.interval = 1.0 / max(rate_limit, 0.1)
        self.last = 0.0
        self.test_app = test_app
        self.auth_token = auth_token
        self.second_auth_token = second_auth_token
        self.audit = AuditLogger()
        self.session = requests.Session()
        ua = (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 "
            "(PySentra Security Scanner)"
        )
        self.session.headers.update({"User-Agent": ua})

    def request(self, method: str, url: str, module: str, **kwargs: Any) -> Any:
        """Issue a rate-limited and logged HTTP request."""
        wait = self.interval - (time.monotonic() - self.last)
        if wait > 0:
            time.sleep(wait)
        self.audit.log(method, url, module)
        self.last = time.monotonic()
        try:
            return self.session.request(method, url, timeout=8, allow_redirects=False, **kwargs)
        except requests.RequestException as e:
            return FailedResponse(str(e))


def is_url(target: str) -> bool:
    """Check if the target string is a web URL."""
    return target.startswith("http://") or target.startswith("https://")


def run_scan(
    target: str,
    selected: Sequence[str],
    rate_limit: float = 5.0,
    test_app: bool = False,
    auth_token: Optional[str] = None,
    second_auth_token: Optional[str] = None,
    progress: Callable[[str], None] = lambda _: None,
) -> Tuple[List[Finding], Path, Dict[str, Any]]:
    """Execute selected security modules against target (web URL or local folder)."""
    audit_entries: List[Dict[str, Any]] = []
    findings: List[Finding] = []

    if is_url(target):
        ctx = ScanContext(target, rate_limit, test_app, auth_token, second_auth_token)
        for name in selected:
            if name in MODULES:
                progress(name)
                findings.extend(MODULES[name].run(ctx))
        if "api" in selected or "client" in selected:
            findings.extend(cors_checks.run(ctx))
        audit_entries = ctx.audit.entries
    else:
        # Universal local code scan mode
        findings = code_checks.run_local_scan(target, progress=progress)
        audit_entries = [{
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": "STATIC_CODE_SCAN",
            "url": str(Path(target).resolve()),
            "module": "code_checks",
        }]

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_dir = Path.cwd() / "pysentra-reports" / timestamp
    data = write_report(report_dir, target, findings, audit_entries)
    return findings, report_dir, data
