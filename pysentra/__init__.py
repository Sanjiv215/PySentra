"""pysentra: authorization-gated local web security scanner & universal code auditor."""

import importlib.metadata

try:
    __version__ = importlib.metadata.version("pysentra")
except Exception:
    __version__ = "1.1.0"

__all__ = ["__version__"]
