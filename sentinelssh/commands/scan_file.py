from ..generate_report import generate_report
from .formatter import format_pretty
from colorama import Fore
import json

DEFAULT_PATH = "sentinelssh/demo_input/ssh_auth.log"

def cmd_scan(args):
    report = generate_report(
        top_ips=args.top,
        path=args.path or DEFAULT_PATH,
        window_minutes=args.window
    )

    if not report:
        print(Fore.RED + "[!] No report generated")
        return

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(format_pretty(report))
