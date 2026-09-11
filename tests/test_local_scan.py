"""Tests for universal local code scanning and zero-login dashboard."""

import json
import subprocess
import sys
import time
import urllib.request

from pysentra.dashboard.server import create_app
from pysentra.scanner.code_checks import run_local_scan


def test_local_scan_detects_secrets_and_injections(tmp_path):
    # Construct synthetic mock secrets at runtime to avoid push protection triggers
    mock_aws = "AKIA" + "0000000000000000"
    mock_db = "postgres://" + "user:pass@localhost:5432/testdb"

    # 1. Create sensitive file
    env_file = tmp_path / ".env"
    env_file.write_text(f"DATABASE_URL={mock_db}\nAWS_KEY={mock_aws}\n")

    # 2. Create vulnerable python file
    py_file = tmp_path / "app.py"
    py_file.write_text(
        "import os\n"
        "DEBUG = True\n"
        "eval(os.environ.get('CODE'))\n"
    )

    # 3. Create requirements.txt
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("flask==0.12.2\n")

    findings = run_local_scan(str(tmp_path))
    titles = {f.title for f in findings}

    assert any("Exposed Sensitive File" in t for t in titles)
    assert any("AWS Access Key ID" in t or "Database Connection URI" in t for t in titles)
    assert any("Debug Mode Enabled" in t for t in titles)
    assert any("Potential Dynamic Code Execution (eval)" in t for t in titles)


def test_dashboard_zero_login_no_redirect(tmp_path):
    report_data = {
        "target": str(tmp_path),
        "timestamp": "2026-09-11T12:00:00Z",
        "weighted_risk_score": 7.5,
        "counts": {"Critical": 1, "High": 1, "Medium": 0, "Low": 0, "Info": 0},
        "findings": [
            {
                "title": "Exposed Sensitive File: .env",
                "scope_area": "Sensitive File Exposure",
                "severity": "Critical",
                "cvss_score": 9.0,
                "description": "Environment file present in directory root.",
                "affected_component": ".env",
                "steps_to_reproduce": ["Check file presence"],
                "poc_request": "File: .env",
                "poc_response_snippet": ".env present",
                "business_impact": "Credentials exposed",
                "remediation": "Remove .env from version control",
            }
        ],
        "audit_log": [],
    }
    (tmp_path / "report.json").write_text(json.dumps(report_data), encoding="utf-8")
    (tmp_path / "report.html").write_text("<h1>Report</h1>", encoding="utf-8")

    app = create_app(tmp_path)
    client = app.test_client()

    # Root route must return 200 directly with no auth redirects
    res = client.get("/")
    assert res.status_code == 200
    assert b"pysentra dashboard" in res.data
    assert b"login" not in res.data.lower() or b"login" not in res.headers.get("Location", b"").lower()

    # API route must return 200 with findings JSON directly
    api_res = client.get("/api/findings")
    assert api_res.status_code == 200
    assert api_res.json["counts"]["Critical"] == 1


def test_subprocess_local_scan_integration(tmp_path):
    mock_stripe = "sk_" + "live_" + "0" * 24
    # Setup a sample repository
    project_dir = tmp_path / "sample_project"
    project_dir.mkdir()
    (project_dir / ".env").write_text(f"STRIPE_KEY={mock_stripe}\n")
    (project_dir / "index.js").write_text("const code = req.query.c; eval(code);\n")
    (project_dir / "requirements.txt").write_text("urllib3==1.26.4\n")

    port = 8799
    cmd = [
        sys.executable,
        "-m",
        "pysentra.cli",
        "scan",
        str(project_dir),
        "--i-am-authorized",
        "--no-open",
        "--port",
        str(port),
    ]

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(2.5)

    try:
        # Check that dashboard started and is serving 200 on / without login
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/") as resp:
            assert resp.status == 200
            html = resp.read().decode("utf-8")
            assert "pysentra dashboard" in html

        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/findings") as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            findings = data.get("findings", [])
            assert len(findings) > 0
            titles = {f["title"] for f in findings}
            assert any("Sensitive" in t or "eval" in t or "Stripe" in t for t in titles)
    finally:
        proc.terminate()
        proc.wait(timeout=5)
