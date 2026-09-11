import json
from pathlib import Path
from datetime import datetime, timezone
from jinja2 import Environment, PackageLoader, select_autoescape
def write_report(directory, target, findings, audit_entries):
    directory=Path(directory); directory.mkdir(parents=True,exist_ok=True)
    counts={s:sum(f.severity==s for f in findings) for s in ("Critical","High","Medium","Low","Info")}
    risk=round(sum(f.cvss_score for f in findings)/len(findings),1) if findings else 0
    data={"target":target,"timestamp":datetime.now(timezone.utc).isoformat(),"weighted_risk_score":risk,"counts":counts,"findings":[f.to_dict() for f in findings],"audit_log":audit_entries}
    (directory/"report.json").write_text(json.dumps(data,indent=2),encoding="utf-8")
    env=Environment(loader=PackageLoader("pysentra","report/templates"),autoescape=select_autoescape())
    (directory/"report.html").write_text(env.get_template("report.html.j2").render(**data),encoding="utf-8")
    return data
