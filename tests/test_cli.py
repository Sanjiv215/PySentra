"""Tests for CLI arguments, input validation, and server defaults."""

import pytest

from pysentra.cli import validate_port, validate_rate_limit, validate_target
from pysentra.dashboard.server import serve


def test_validate_target_url():
    assert validate_target("http://localhost:5000") == "http://localhost:5000"
    assert validate_target("https://example.com/app") == "https://example.com/app"
    with pytest.raises(Exception):
        validate_target("ftp://example.com")
    with pytest.raises(Exception):
        validate_target("http://")


def test_validate_target_local_path(tmp_path):
    assert validate_target(".") == "."
    assert validate_target(str(tmp_path)) == str(tmp_path)
    with pytest.raises(Exception):
        validate_target("/nonexistent/path/that/does/not/exist")


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

def test_version_flag(capsys):
    from pysentra.cli import main
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "pysentra" in captured.out or "pysentra" in captured.err
