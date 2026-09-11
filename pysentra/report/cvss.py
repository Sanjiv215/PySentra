"""Small, dependency-free CVSS v3.1 base score calculator."""

import math
from typing import Any, Dict

METRICS: Dict[str, Any] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": (0.85, 0.85), "L": (0.62, 0.68), "H": (0.27, 0.5)},
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": None, "C": None},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def roundup(value: float) -> float:
    """Round up a floating point number to 1 decimal place per CVSS v3.1 spec."""
    return math.ceil(value * 10 - 1e-8) / 10


def base_score(vector: str) -> float:
    """Calculate the CVSS v3.1 Base Score from a vector string."""
    values = dict(x.split(":", 1) for x in vector.split("/")[1:])
    scope = values["S"]
    pr = METRICS["PR"][values["PR"]][1 if scope == "C" else 0]
    exploit = 8.22 * METRICS["AV"][values["AV"]] * METRICS["AC"][values["AC"]] * pr * METRICS["UI"][values["UI"]]
    impact_sub = (
        1.0
        - (1.0 - METRICS["C"][values["C"]])
        * (1.0 - METRICS["I"][values["I"]])
        * (1.0 - METRICS["A"][values["A"]])
    )
    if impact_sub <= 0:
        return 0.0
    impact = (
        6.42 * impact_sub
        if scope == "U"
        else 7.52 * (impact_sub - 0.029) - 3.25 * ((impact_sub - 0.02) ** 15)
    )
    score = min(impact + exploit, 10.0) if scope == "U" else min(1.08 * (impact + exploit), 10.0)
    return roundup(score)
