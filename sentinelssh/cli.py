import argparse
import json

from .commands.scan_file import *
from .commands.watch_file import *
from .commands.stats_file import *
from .commands.top_ips import *

def main():
    parser = argparse.ArgumentParser(
        description="SentinelSSH — CLI SSH Threat Analyzer"
    )

    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Scan log and print report")
    add_common_args(scan)

    top = sub.add_parser("top-ips", help="Show most active IPs")
    top.add_argument("-p", "--path", required=False)
    top.add_argument("-n", type=int, default=10)

    stats = sub.add_parser("stats", help="Show terminal graph stats")
    stats.add_argument("-p", "--path", required=False)
    stats.add_argument("-n",type=int, default=5)

    watch = sub.add_parser("watch", help="Live watch log file")
    watch.add_argument("-p", "--path", required=False)
    watch.add_argument("-i", "--interval", type=int, default=3)

    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "top-ips":
        cmd_top_ips(args)
    elif args.command == "stats":
        cmd_stats(args)
    elif args.command == "watch":
        cmd_watch(args)
    else:
        parser.print_help()

def add_common_args(p):
    p.add_argument("-t", "--top", type=int, default=5)
    p.add_argument("-p", "--path", required=False)
    p.add_argument("-w", "--window", type=int, default=2)
    p.add_argument("-j", "--json", action="store_true")



if __name__ == "__main__":
    main()
