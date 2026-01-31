import argparse
import json
from .generate_report import generate_report


def main():
    parser = argparse.ArgumentParser(
        description="SSH Threat Analyzer – detect and rank SSH attackers from auth logs"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=False,
        help="Command mode"
    )

    show_cmd = subparsers.add_parser(
        "show",
        help="Print report to terminal"
    )
    show_cmd.add_argument(
        "-top","-t",
        type=int,
        default=5,
        help="Show top N most dangerous IPs (default: 5)"
    )
    show_cmd.add_argument(
        "-json","-j",
        action="store_true",
        help="Print raw JSON instead of formatted text"
    )
    show_cmd.add_argument(
        "-path","-p",
        type=str,
        default="src/a.log",
        help="Path to SSH log file (default: src/a.log)"
    )

    write_cmd = subparsers.add_parser(
        "write",
        help="Write report to a file"
    )
    write_cmd.add_argument(
        "-top","-t",
        type=int,
        default=5,
        help="Write top N most dangerous IPs (default: 5)"
    )
    write_cmd.add_argument(
        "-out","-o",
        type=str,
        required=True,
        help="Output file path (required)"
    )
    write_cmd.add_argument(
        "-json","-j",
        action="store_true",
        help="Write raw JSON instead of formatted text"
    )
    write_cmd.add_argument(
        "-path","-p",
        type=str,
        default="src/a.log",
        help="Path to SSH log file (default: src/a.log)"
    )

    args = parser.parse_args()

    report = generate_report(
        top_ips=args.top,
        path=args.path
    )

    if args.json:
        output = json.dumps(report, indent=2)
    else:
        output = format_pretty(report)

    if args.command == "show":
        print(output)

    elif args.command == "write":
        file : str = args.out
        if file.__contains__(".txt") and args.json:
            file = file.replace(".txt",".json")
            print(f"[*] You gave a .txt but gave '--json' arg, so defaulting to {file}")
        elif file.__contains__(".json") and not args.json:
            file = file.replace(".json",".txt")
            print(f"[*] You gave a .json but didn't give '--json' arg, so defaulting to {file}")
        with open(file, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"[+] Report written to {file}")
    else:
        print(output)

def format_pretty(report):
    lines = []

    meta = report["meta"]
    lines.append("=== SSH THREAT REPORT ===")
    lines.append(f"Generated at : {meta['generated_at']}")
    lines.append(f"Total IPs   : {meta['total_ips']}")
    lines.append(f"Total Events: {meta['total_events']}")
    lines.append("")
    count = len(report["top_threats"])
    lines.append(f"================= TOP {count} IPs ===================")
    for i, entry in enumerate(report["top_threats"], 1):
        lines.append(f"{i}. IP: {entry['ip']}")
        lines.append(f"   Risk Level   : {entry['risk_level']}")
        lines.append(f"   Severity     : {entry['severity_score']}")
        lines.append(f"   Total Events : {entry['total_events']}")
        lines.append("   Reasons:")
        for reason in entry["reasons"]:
            lines.append(f"     - {reason}")
        lines.append("")

    
    return "\n".join(lines)


if __name__ == "__main__":
    main()
