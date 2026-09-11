"""Small, dependency-free CVSS v3.1 base score calculator."""
import math

METRICS = {
    "AV": {"N": .85, "A": .62, "L": .55, "P": .2}, "AC": {"L": .77, "H": .44},
    "PR": {"N": (.85, .85), "L": (.62, .68), "H": (.27, .5)}, "UI": {"N": .85, "R": .62},
    "S": {"U": None, "C": None}, "C": {"H": .56, "L": .22, "N": 0},
    "I": {"H": .56, "L": .22, "N": 0}, "A": {"H": .56, "L": .22, "N": 0},
}
def roundup(value): return math.ceil(value * 10 - 1e-8) / 10
def base_score(vector: str) -> float:
    values = dict(x.split(":", 1) for x in vector.split("/")[1:])
    scope = values["S"]; pr = METRICS["PR"][values["PR"]][1 if scope == "C" else 0]
    exploit = 8.22 * METRICS["AV"][values["AV"]] * METRICS["AC"][values["AC"]] * pr * METRICS["UI"][values["UI"]]
    impact_sub = 1 - (1-METRICS["C"][values["C"]])*(1-METRICS["I"][values["I"]])*(1-METRICS["A"][values["A"]])
    if impact_sub <= 0: return 0.0
    impact = 6.42 * impact_sub if scope == "U" else 7.52*(impact_sub-.029)-3.25*(impact_sub-.02)**15
    score = min(impact + exploit, 10) if scope == "U" else min(1.08*(impact+exploit), 10)
    return roundup(score)
