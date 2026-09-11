# Contributing to pysentra

Thanks for contributing. pysentra is an authorized-use security-testing prototype: preserve the authorization guard, rate limiting, audit log, and non-destructive design in every change.

## Development setup

```sh
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Run the test suite with `pytest`. Use clear Python, keep check modules narrowly scoped, cover behavior with tests, and never commit generated reports, `.env` files, credentials, or environments.
