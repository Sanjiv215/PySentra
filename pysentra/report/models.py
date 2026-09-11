from dataclasses import asdict, dataclass

@dataclass
class Finding:
    title: str
    scope_area: str
    description: str
    affected_component: str
    severity: str
    cvss_score: float
    cvss_vector: str
    steps_to_reproduce: list[str]
    poc_request: str
    poc_response_snippet: str
    business_impact: str
    remediation: str

    def to_dict(self):
        return asdict(self)
