# Contributing to pysentra

Thank you for contributing to pysentra! pysentra is an authorized-use web application security scanner designed for safe, non-destructive security assessments with live visual reporting.

When contributing, ensure you preserve the core safeguards: **explicit authorization checks, strict rate limiting, audit logging, and non-destructive testing methodology**.

---

## Development Setup

1. **Clone and create a virtual environment:**
   ```sh
   git clone https://github.com/Sanjiv215/PySentra.git
   cd PySentra
   python3 -m venv .venv
   source .venv/bin/activate
   ```

2. **Install development dependencies:**
   ```sh
   pip install -e ".[dev]"
   ```

3. **Install pre-commit hooks (optional but recommended):**
   ```sh
   pip install pre-commit
   pre-commit install
   ```

---

## Code Quality & Testing

Before submitting a pull request, run the test and quality suite:

```sh
# Linting
ruff check .

# Type checking
mypy pysentra/

# Unit & integration tests
pytest
```

---

## Changelog Policy

**Every pull request that introduces new features, bug fixes, or behavioral changes must include an entry in [`CHANGELOG.md`](CHANGELOG.md) under the `[Unreleased]` section.**

### Changelog Entry Template

Add your change under the appropriate subsection in `CHANGELOG.md`:

```markdown
## [Unreleased]

### Added
- <Description of feature> ([#PR_NUMBER](https://github.com/Sanjiv215/PySentra/pull/PR_NUMBER))

### Changed
- <Description of change> ([#PR_NUMBER](https://github.com/Sanjiv215/PySentra/pull/PR_NUMBER))

### Fixed
- <Description of bug fix> ([#PR_NUMBER](https://github.com/Sanjiv215/PySentra/pull/PR_NUMBER))

### Security
- <Description of security improvement> ([#PR_NUMBER](https://github.com/Sanjiv215/PySentra/pull/PR_NUMBER))
```

---

## Security & Ethics Requirements

- **Non-Destructive Only**: Never add checks that modify production state, brute-force credentials, or execute denial-of-service payloads.
- **Privacy**: No telemetry, analytics, or external calls outside the user-specified target.
- **Bound Defaults**: All servers/listeners must default to local loopback (`127.0.0.1`).
