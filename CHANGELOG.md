# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-09-11

### Added
- Production-grade v1.0.0 release of pysentra.
- Full Apache-2.0 licensing with accompanying `NOTICE` file.
- `SECURITY.md` defining supported versions and private vulnerability disclosure process.
- `CODE_OF_CONDUCT.md` adopting Contributor Covenant v2.1.
- GitHub issue templates (`bug_report.md`, `feature_request.md`) and pull request template (`PULL_REQUEST_TEMPLATE.md`).
- Dependabot configuration for GitHub Actions and pip dependency updates.
- Pre-commit configuration and CI linting (`ruff`), type checking (`mypy`), and test matrices (`pytest`).
- CLI argument `--bind` defaulting securely to loopback `127.0.0.1`.
- Input validation on target URL, rate limit, and dashboard port.
- Type hints across all modules and `py.typed` marker for PEP 561 compliance.

### Changed
- Dashboard server default binding locked strictly to `127.0.0.1` unless explicitly overridden via `--bind`.
- Version unified and managed strictly via `pyproject.toml`.

## [0.1.0] - 2026-09-11

### Added
- Authorization-gated, rate-limited scanner modules across seven web-security scope areas.
- JSON/HTML reporting and local findings dashboard.
- Intentionally vulnerable local Flask demo application.
