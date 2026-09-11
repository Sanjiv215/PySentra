"""Command line interface for pysentra."""

import argparse
import importlib.metadata
import urllib.parse
import webbrowser
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.progress import Progress

from pysentra.dashboard.server import serve
from pysentra.scanner.runner import is_url, run_scan

try:
    __version__ = importlib.metadata.version("pysentra")
except Exception:
    __version__ = "1.2.0"

VALID_MODULES = ("auth", "authz", "input", "api", "client", "tls", "storage")


def validate_target(target_str: Optional[str]) -> str:
    """Validate that target is either a well-formed URL or an existing local path."""
    if not target_str or target_str == ".":
        return "."
    if target_str.startswith("http://") or target_str.startswith("https://"):
        parsed = urllib.parse.urlparse(target_str)
        if parsed.scheme in ("http", "https") and parsed.netloc:
            return target_str
        raise argparse.ArgumentTypeError(
            f"Invalid target URL '{target_str}'. Target must be a well-formed URL starting with 'http://' or 'https://'."
        )
    path = Path(target_str)
    if not path.exists():
        raise argparse.ArgumentTypeError(
            f"Invalid target '{target_str}'. Path does not exist on filesystem."
        )
    return str(path)


def validate_rate_limit(value_str: str) -> float:
    """Validate that rate limit is a sane positive number."""
    try:
        val = float(value_str)
        if val <= 0:
            raise ValueError
        return val
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"Invalid rate limit '{value_str}'. Rate limit must be a positive number (requests per second)."
        )


def validate_port(value_str: str) -> int:
    """Validate that port is an integer in 1..65535."""
    try:
        val = int(value_str)
        if not (1 <= val <= 65535):
            raise ValueError
        return val
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"Invalid port '{value_str}'. Port must be an integer between 1 and 65535."
        )


def main(argv: Optional[List[str]] = None) -> None:
    """Entry point for pysentra CLI."""
    parser = argparse.ArgumentParser(
        prog="pysentra",
        description="Authorized local-first web application & universal code security scanner",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser("scan", help="Scan a target URL or local folder for security vulnerabilities")
    scan_parser.add_argument(
        "target",
        nargs="?",
        default=".",
        type=validate_target,
        help="Target URL (e.g. http://localhost:5000) or local folder path (default: .)",
    )
    scan_parser.add_argument(
        "--i-am-authorized",
        action="store_true",
        help="Confirm authorization non-interactively",
    )
    scan_parser.add_argument(
        "--target-is-test-app",
        action="store_true",
        help="Enable extra safe checks intended only for the bundled test app",
    )
    scan_parser.add_argument(
        "--modules",
        default=",".join(VALID_MODULES),
        help=f"Comma-separated list of check modules to run for web target (default: {','.join(VALID_MODULES)})",
    )
    scan_parser.add_argument("--auth-token", help="First test token for read-only authorization checks")
    scan_parser.add_argument(
        "--second-auth-token",
        help="Second test token; enables cross-user IDOR checks",
    )
    scan_parser.add_argument(
        "--rate-limit",
        type=validate_rate_limit,
        default=5.0,
        help="Maximum requests per second for web scans (default: 5)",
    )
    scan_parser.add_argument(
        "--bind",
        default="127.0.0.1",
        help="Host address to bind the dashboard server (default: 127.0.0.1)",
    )
    scan_parser.add_argument(
        "--port",
        type=validate_port,
        default=8765,
        help="Dashboard server port (default: 8765)",
    )
    scan_parser.add_argument(
        "--headless-browser",
        action="store_true",
        help="Request optional Playwright-based browser checks",
    )
    scan_parser.add_argument(
        "--no-open",
        action="store_true",
        help="Do not automatically open the dashboard in a browser",
    )

    args = parser.parse_args(argv)
    target_is_url = is_url(args.target)

    if not args.i_am_authorized:
        prompt_text = (
            "Confirm you are authorized to scan this target [y/N]: "
            if target_is_url
            else "Confirm you are authorized to assess this local codebase [y/N]: "
        )
        try:
            confirmed = (
                input(prompt_text)
                .strip()
                .lower()
                in ("y", "yes")
            )
        except (EOFError, KeyboardInterrupt):
            confirmed = False
        if not confirmed:
            parser.error("refusing to scan without authorization confirmation")

    selected = [x.strip() for x in args.modules.split(",") if x.strip()]
    invalid_modules = set(selected) - set(VALID_MODULES)
    if invalid_modules:
        parser.error("unknown modules: " + ", ".join(sorted(invalid_modules)))
    if not selected:
        parser.error("no scan modules selected")

    console = Console()
    if target_is_url:
        console.print(
            f"[bold cyan]pysentra[/] scanning web URL {args.target} at no more than {args.rate_limit} requests/sec"
        )
    else:
        resolved_path = str(Path(args.target).resolve())
        console.print(f"[bold cyan]pysentra[/] scanning local path: {resolved_path}")

    with Progress() as progress:
        task = progress.add_task("Running checks", total=None if not target_is_url else len(selected))

        def update_progress(name: str) -> None:
            console.print(f"  [yellow]→[/] {name}")
            if target_is_url:
                progress.advance(task)

        findings, directory, _ = run_scan(
            args.target,
            selected,
            args.rate_limit,
            args.target_is_test_app,
            args.auth_token,
            args.second_auth_token,
            update_progress,
        )

    console.print(f"[bold green]Completed:[/] {len(findings)} findings. Reports: {directory}")

    host_for_url = "127.0.0.1" if args.bind in ("0.0.0.0", "::") else args.bind
    dashboard_url = f"http://{host_for_url}:{args.port}"
    console.print(
        f"Dashboard: [link={dashboard_url}]{dashboard_url}[/link] (bound to {args.bind}:{args.port}, Ctrl-C to stop)"
    )

    if not args.no_open:
        webbrowser.open(dashboard_url)

    try:
        serve(directory, port=args.port, host=args.bind)
    except KeyboardInterrupt:
        console.print("\nDashboard stopped.")


if __name__ == "__main__":
    main()
