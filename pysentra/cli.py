import argparse, sys, threading, webbrowser
from rich.console import Console
from rich.progress import Progress
from pysentra.scanner.runner import run_scan
from pysentra.dashboard.server import serve
VALID=("auth","authz","input","api","client","tls","storage")
def main():
    p=argparse.ArgumentParser(prog="pysentra",description="Authorized local-first web security scanner")
    sub=p.add_subparsers(dest="command",required=True); s=sub.add_parser("scan")
    s.add_argument("url"); s.add_argument("--i-am-authorized",action="store_true"); s.add_argument("--target-is-test-app",action="store_true"); s.add_argument("--modules",default=",".join(VALID)); s.add_argument("--auth-token"); s.add_argument("--second-auth-token"); s.add_argument("--rate-limit",type=float,default=5); s.add_argument("--port",type=int,default=8765); s.add_argument("--headless-browser",action="store_true"); s.add_argument("--no-open",action="store_true")
    args=p.parse_args()
    if not args.i_am_authorized:
        try: ok=input("Confirm you are authorized to scan this target [y/N]: ").strip().lower() in ("y","yes")
        except EOFError: ok=False
        if not ok: p.error("refusing to scan without authorization confirmation")
    selected=[x.strip() for x in args.modules.split(",") if x.strip()]
    bad=set(selected)-set(VALID)
    if bad: p.error("unknown modules: "+", ".join(sorted(bad)))
    console=Console(); console.print(f"[bold cyan]pysentra[/] scanning {args.url} at no more than {args.rate_limit} requests/sec")
    with Progress() as progress:
        task=progress.add_task("Running checks",total=len(selected))
        def update(name): console.print(f"  [yellow]→[/] {name}"); progress.advance(task)
        findings, directory, _=run_scan(args.url,selected,args.rate_limit,args.target_is_test_app,args.auth_token,args.second_auth_token,update)
    console.print(f"[bold green]Completed:[/] {len(findings)} findings. Reports: {directory}")
    url=f"http://127.0.0.1:{args.port}"
    console.print(f"Dashboard: [link={url}]{url}[/link] (Ctrl-C to stop)")
    if not args.no_open: webbrowser.open(url)
    try: serve(directory,args.port)
    except KeyboardInterrupt: console.print("\nDashboard stopped.")
if __name__ == "__main__": main()
