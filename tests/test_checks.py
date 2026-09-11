"""Offline tests: every scanner request is served by the bundled Flask app."""
import importlib.util
from pathlib import Path
from urllib.parse import urlsplit

import requests
from requests.structures import CaseInsensitiveDict

from pysentra.scanner import api_checks, auth_checks, authz_checks, client_side_checks, cors_checks, input_checks, storage_privacy_checks, tls_checks
from pysentra.scanner.runner import run_scan


def demo_app():
    path = Path(__file__).parents[1] / "demo-vulnerable-app" / "app.py"
    spec = importlib.util.spec_from_file_location("pysentra_demo_for_tests", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.app


def response_from_flask(response):
    result = requests.Response()
    result.status_code = response.status_code
    result._content = response.data
    result.headers = CaseInsensitiveDict(dict(response.headers))
    result.url = "http://demo.local"
    return result


class DemoContext:
    target = "http://demo.local"
    test_app = True
    auth_token = None
    second_auth_token = None

    def request(self, method, url, module, **kwargs):
        parsed = urlsplit(url)
        path = parsed.path + (("?" + parsed.query) if parsed.query else "")
        response = demo_app().test_client().open(path, method=method, headers=kwargs.get("headers"))
        return response_from_flask(response)


def titles(findings):
    return {finding.title for finding in findings}


def test_auth_checks_detect_weak_cookie_and_csrf():
    assert "Session cookie missing security attributes" in titles(auth_checks.run(DemoContext()))


def test_authz_checks_detect_forced_browsing():
    assert "Unauthenticated admin path accessible" in titles(authz_checks.run(DemoContext()))


def test_input_checks_detect_reflection():
    assert "Reflected input is not output-encoded" in titles(input_checks.run(DemoContext()))


def test_api_checks_detect_sensitive_fields():
    assert "API exposes sensitive user fields" in titles(api_checks.run(DemoContext()))


def test_client_checks_detect_missing_csp():
    assert "Content Security Policy missing" in titles(client_side_checks.run(DemoContext()))


def test_tls_checks_detect_http():
    assert "Target uses unencrypted HTTP" in titles(tls_checks.run(DemoContext()))


def test_storage_checks_detect_env_file():
    assert "Environment file exposed over HTTP" in titles(storage_privacy_checks.run(DemoContext()))


def test_cors_checks_detect_origin_reflection():
    assert "Credentialed CORS origin reflection" in titles(cors_checks.run(DemoContext()))


def test_full_scan_against_in_process_demo(monkeypatch, tmp_path):
    app = demo_app()

    def local_request(_session, method, url, **kwargs):
        parsed = urlsplit(url)
        path = parsed.path + (("?" + parsed.query) if parsed.query else "")
        response = app.test_client().open(path, method=method, headers=kwargs.get("headers"))
        return response_from_flask(response)

    monkeypatch.setattr(requests.Session, "request", local_request)
    monkeypatch.chdir(tmp_path)
    findings, report_dir, report = run_scan(
        "http://demo.local", ["auth", "authz", "input", "api", "client", "tls", "storage"],
        10000, True, None, None,
    )
    expected = {
        "Authentication & Session Management", "Authorization & Access Control",
        "Input Validation & Data Handling", "API Security", "Client-Side Security Controls",
        "Secure Communication Mechanisms", "Data Storage & Privacy Protections",
    }
    assert expected <= {item.scope_area for item in findings}
    assert (report_dir / "report.json").is_file()
    assert (report_dir / "report.html").is_file()
    assert report["audit_log"]
