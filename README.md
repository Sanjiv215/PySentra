# pysentra

[![PyPI](https://img.shields.io/pypi/v/pysentra.svg)](https://pypi.org/project/pysentra/) [![Python](https://img.shields.io/pypi/pyversions/pysentra.svg)](https://pypi.org/project/pysentra/) [![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE) [![Build](https://github.com/Sanjiv215/PySentra/actions/workflows/test.yml/badge.svg)](https://github.com/Sanjiv215/PySentra/actions/workflows/test.yml)

Local-first security scanner for web applications (DAST) and universal local codebases (SAST + Secrets + Dependencies), featuring a zero-login live vulnerability dashboard.

> **Authorization required** — Use pysentra only against systems and codebases you own or have explicit permission to assess. It rate-limits requests, avoids destructive checks, and requires an authorization confirmation before scanning.

## Privacy

pysentra makes no external network calls other than to the target you specify and OSV.dev for dependency vulnerability checks. No telemetry, no analytics, no data leaves your machine. All scan reports, logs, and artifacts are stored locally in the `pysentra-reports/` directory.

## Install

```sh
pip install pysentra
```

For local development, use `pip install -e ".[dev]"`.

## Quickstart

### 1. Scan local code (Universal static & dependency scan)

Scan any repository or folder locally on any device without running the application:

```sh
cd ~/any/project
pysentra scan .
```

Or point to any local directory or file:

```sh
pysentra scan /path/to/repo
```

pysentra automatically inspects files for hardcoded secrets, insecure framework configs, vulnerable dependencies (via OSV.dev), exposed sensitive files, and potential code injection patterns.

### 2. Scan a running web app (DAST)

Run the intentionally vulnerable demo target in one terminal:

```sh
cd demo-vulnerable-app
pip install -r requirements.txt
python app.py
```

Then scan it from the project root:

```sh
pysentra scan http://localhost:5000 --i-am-authorized --target-is-test-app
```

Both modes generate `report.json` and a printable `report.html` under `pysentra-reports/<timestamp>/` and start the live dashboard at `http://127.0.0.1:8765` (no login or auth required).

## Dashboard

![Dashboard screenshot placeholder](docs/dashboard-placeholder.svg)

The dashboard provides severity cards, a findings chart, interactive filters, expandable evidence/PoCs, and JSON/HTML export links. It binds strictly to `127.0.0.1` and requires zero credentials.

## CLI Reference

| Flag | Purpose |
| --- | --- |
| `pysentra scan [target]` | Scan a target URL (`http://...`) or local directory/file path (default: `.`). |
| `--i-am-authorized` | Confirm authorization non-interactively. |
| `--target-is-test-app` | Enable extra safe checks only intended for the bundled test app. |
| `--modules auth,authz,...` | Comma-separated list of web check modules to run. |
| `--auth-token <token>` | First test token for read-only authorization checks. |
| `--second-auth-token <token>` | Second test token; enables cross-user IDOR checks. |
| `--rate-limit <n>` | Maximum requests per second (positive number); default `5`. |
| `--bind <host>` | Host address to bind the dashboard server; default `127.0.0.1`. |
| `--port <port>` | Dashboard server port (integer 1-65535); default `8765`. |
| `--headless-browser` | Request optional Playwright-based browser checks. |
| `--no-open` | Do not automatically open the dashboard in a browser. |

## Architecture

1. **Local Code Scanner (`code_checks`)**: Language-agnostic inspection covering Secrets, Dependencies (OSV.dev), Insecure Configs, Sensitive File Exposure, and Static Code Injection.
2. **Web Application Scanner (`scanner/`)**: Rate-limited, audited assessment covering Auth, AuthZ, Input Validation, API Security, Client-Side Controls, TLS/HSTS, Storage & Privacy, and CORS.
3. **Dashboard & Reporting (`dashboard/`, `report/`)**: Zero-login local web UI and JSON/HTML report generation.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Do not add checks that could be destructive, credential-brute-force targets, or bypass safeguards.
