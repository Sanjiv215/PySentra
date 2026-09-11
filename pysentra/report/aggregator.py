"""Report generation and aggregation for JSON and HTML formats."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Sequence, Union

from jinja2 import Environment, PackageLoader, select_autoescape

from pysentra.report.models import Finding


def write_report(
    directory: Union[Path, str],
    target: str,
    findings: Sequence[Finding],
    audit_entries: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    """Write report.json and report.html under directory, returning the summary dict."""
    target_dir = Path(directory)
    target_dir.mkdir(parents=True, exist_ok=True)

    counts = {
        s: sum(1 for f in findings if f.severity == s)
        for s in ("Critical", "High", "Medium", "Low", "Info")
    }
    risk = (
        round(sum(f.cvss_score for f in findings) / len(findings), 1)
        if findings
        else 0.0
    )
    data: Dict[str, Any] = {
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "weighted_risk_score": risk,
        "counts": counts,
        "findings": [f.to_dict() for f in findings],
        "audit_log": list(audit_entries),
    }

    (target_dir / "report.json").write_text(
        json.dumps(data, indent=2), encoding="utf-8"
    )

    env = Environment(
        loader=PackageLoader("pysentra", "report/templates"),
        autoescape=select_autoescape(),
    )
    template = env.get_template("report.html.j2")
    (target_dir / "report.html").write_text(
        template.render(**data), encoding="utf-8"
    )

    return data
