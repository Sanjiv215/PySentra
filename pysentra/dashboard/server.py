from flask import Flask, jsonify, render_template, send_from_directory
from pathlib import Path
def create_app(report_dir):
    import json
    report_dir=Path(report_dir); data=json.loads((report_dir/"report.json").read_text())
    app=Flask(__name__)
    @app.get("/")
    def index(): return render_template("index.html", report=data)
    @app.get("/api/findings")
    def findings(): return jsonify(data)
    @app.get("/download/json")
    def json_download(): return send_from_directory(report_dir,"report.json",as_attachment=True)
    @app.get("/download/html")
    def html_download(): return send_from_directory(report_dir,"report.html",as_attachment=True)
    return app
def serve(report_dir, port): create_app(report_dir).run(host="127.0.0.1",port=port,debug=False,use_reloader=False)
