"""Audit logging for all HTTP requests executed during scans."""

from datetime import datetime, timezone
from typing import Any, Dict, List


class AuditLogger:
    """In-memory audit log recorder for scan requests."""

    def __init__(self) -> None:
        self.entries: List[Dict[str, Any]] = []

    def log(self, method: str, url: str, module: str) -> None:
        """Record an outbound HTTP request entry."""
        self.entries.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": method,
            "url": url,
            "module": module,
        })
