"""Data models for security findings and assessment results."""

from dataclasses import asdict, dataclass
from typing import Any, Dict, List

BANNED_PHANTOM_TITLES = {
    "IDOR check needs two test tokens",
    "Account lockout not tested",
    "Upload and mass-assignment tests skipped",
    "MFA presence requires verification",
}


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

    def __post_init__(self) -> None:
        """Validate that finding has literal evidence and is not a phantom placeholder."""
        if self.title in BANNED_PHANTOM_TITLES:
            raise ValueError(
                f"Prohibited phantom finding '{self.title}' cannot be instantiated. "
                "Only deterministic findings derived from actual target response data are permitted."
            )
        if not self.poc_response_snippet or not self.poc_response_snippet.strip():
            raise ValueError(
                f"Finding '{self.title}' cannot be instantiated without literal evidence in poc_response_snippet."
            )
        if self.title == "Session cookie missing security attributes":
            if "=" not in self.poc_response_snippet:
                raise ValueError(
                    f"Finding '{self.title}' requires literal Set-Cookie header data in poc_response_snippet."
                )

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding instance to a JSON-serializable dictionary."""
        return asdict(self)
