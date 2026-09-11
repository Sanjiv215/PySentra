"""Data models for security findings and assessment results."""

from dataclasses import asdict, dataclass
from typing import Any, Dict, List


@dataclass
class Finding:
    """Represents a single vulnerability finding identified during scanning."""

    title: str
    scope_area: str
    description: str
    affected_component: str
    severity: str
    cvss_score: float
    cvss_vector: str
    steps_to_reproduce: List[str]
    poc_request: str
    poc_response_snippet: str
    business_impact: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding instance to a JSON-serializable dictionary."""
        return asdict(self)
