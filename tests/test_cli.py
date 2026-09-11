"""Tests for CLI arguments, input validation, and server defaults."""

import pytest

from pysentra.cli import validate_port, validate_rate_limit, validate_url
from pysentra.dashboard.server import serve


def test_validate_url_valid():
    assert validate_url("http://localhost:5000") == "http://localhost:5000"
    assert validate_url("https://example.com/app") == "https://example.com/app"


def test_validate_url_invalid():
    with pytest.raises(Exception):
        validate_url("not-a-url")
    with pytest.raises(Exception):
        validate_url("ftp://example.com")
    with pytest.raises(Exception):
        validate_url("http://")


def test_validate_rate_limit():
    assert validate_rate_limit("5") == 5.0
    assert validate_rate_limit("0.5") == 0.5
    with pytest.raises(Exception):
        validate_rate_limit("0")
    with pytest.raises(Exception):
        validate_rate_limit("-1")
    with pytest.raises(Exception):
        validate_rate_limit("invalid")


def test_validate_port():
    assert validate_port("80") == 80
    assert validate_port("8765") == 8765
    with pytest.raises(Exception):
        validate_port("0")
    with pytest.raises(Exception):
        validate_port("65536")
    with pytest.raises(Exception):
        validate_port("abc")


def test_serve_default_host_is_loopback(monkeypatch, tmp_path):
    bound_hosts = []

    class DummyApp:
        def run(self, host, port, debug, use_reloader):
            bound_hosts.append(host)

    monkeypatch.setattr("pysentra.dashboard.server.create_app", lambda _dir: DummyApp())
    serve(tmp_path, 8765)
    assert bound_hosts == ["127.0.0.1"]
