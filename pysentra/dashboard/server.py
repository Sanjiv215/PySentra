"""Local findings dashboard web application."""

import importlib.resources as pkg_resources
import json
from pathlib import Path
from typing import Any, Dict, Union

from flask import Flask, jsonify, render_template, send_from_directory

try:
    _templates_dir = str(pkg_resources.files("pysentra.dashboard").joinpath("templates"))
    _static_dir = str(pkg_resources.files("pysentra.dashboard").joinpath("static"))
except Exception:
    _templates_dir = str(Path(__file__).parent / "templates")
    _static_dir = str(Path(__file__).parent / "static")


def create_app(report_dir: Union[Path, str]) -> Flask:
    """Create a Flask application for displaying scan results."""
    resolved_dir = Path(report_dir).resolve()
    report_file = resolved_dir / "report.json"
    data: Dict[str, Any] = {}
    if report_file.is_file():
        data = json.loads(report_file.read_text(encoding="utf-8"))

    app = Flask(
        "pysentra.dashboard",
        template_folder=_templates_dir,
        static_folder=_static_dir,
    )

    @app.get("/")
    def index() -> str:
        return render_template("index.html", report=data)

    @app.get("/api/findings")
    def findings() -> Any:
        return jsonify(data)

    @app.get("/download/json")
    def json_download() -> Any:
        return send_from_directory(resolved_dir, "report.json", as_attachment=True)

    @app.get("/download/html")
    def html_download() -> Any:
        return send_from_directory(resolved_dir, "report.html", as_attachment=True)

    return app


def serve(report_dir: Union[Path, str], port: int = 8765, host: str = "127.0.0.1") -> None:
    """Serve the dashboard web server bound strictly to the given host (default: 127.0.0.1)."""
    app = create_app(report_dir)
    app.run(host=host, port=port, debug=False, use_reloader=False)
