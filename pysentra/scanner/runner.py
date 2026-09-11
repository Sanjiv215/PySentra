import time
import requests
from datetime import datetime, timezone
from pathlib import Path
from pysentra.audit.logger import AuditLogger
from pysentra.report.aggregator import write_report
from . import auth_checks, authz_checks, input_checks, api_checks, client_side_checks, tls_checks, storage_privacy_checks, cors_checks

MODULES={"auth":auth_checks, "authz":authz_checks, "input":input_checks, "api":api_checks, "client":client_side_checks, "tls":tls_checks, "storage":storage_privacy_checks}
class ScanContext:
    def __init__(self,target,rate_limit,test_app=False,auth_token=None,second_auth_token=None):
        self.target=target.rstrip("/"); self.interval=1/max(rate_limit, .1); self.last=0; self.test_app=test_app; self.auth_token=auth_token; self.second_auth_token=second_auth_token; self.audit=AuditLogger(); self.session=requests.Session()
    def request(self,method,url,module,**kwargs):
        wait=self.interval-(time.monotonic()-self.last)
        if wait>0: time.sleep(wait)
        self.audit.log(method,url,module); self.last=time.monotonic()
        try: return self.session.request(method,url,timeout=8,allow_redirects=False,**kwargs)
        except requests.RequestException as e:
            class Failed: status_code=0; text=str(e); headers={}
            return Failed()
def run_scan(target, selected, rate_limit, test_app, auth_token, second_auth_token, progress=lambda x:None):
    ctx=ScanContext(target,rate_limit,test_app,auth_token,second_auth_token); findings=[]
    for name in selected:
        progress(name); findings.extend(MODULES[name].run(ctx))
    if "api" in selected or "client" in selected: findings.extend(cors_checks.run(ctx))
    timestamp=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_dir=Path("pysentra-reports")/timestamp
    data=write_report(report_dir,target,findings,ctx.audit.entries)
    return findings, report_dir, data
