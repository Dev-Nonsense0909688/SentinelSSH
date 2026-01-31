from colorama import Fore,Style, init

init(autoreset=True)

def risk_color(level: str):
    level = level.lower()
    if level == "critical":
        return Fore.RED + Style.BRIGHT
    if level == "high":
        return Fore.MAGENTA + Style.BRIGHT
    if level == "medium":
        return Fore.YELLOW + Style.BRIGHT
    if level == "low":
        return Fore.GREEN
    return Fore.WHITE

def format_pretty(report):
    lines = []
    m = report["meta"]

    lines.append("")
    lines.append(f"{Style.BRIGHT}{Fore.BLUE}========== SentinelSSH Threat Report ==========")
    lines.append(f"{Fore.WHITE}Generated : {m['generated_at']}")
    lines.append(f"{Fore.WHITE}IPs Found : {m['total_ips']}")
    lines.append(f"{Fore.WHITE}Events   : {m['total_events']}")
    lines.append(f"{Fore.WHITE}Burst Win: {m['window_minutes']}m")
    lines.append(Fore.WHITE + "-" * 45)

    for e in report["top_threats"]:
        col = risk_color(e["risk_level"])

        lines.append(f"{col}[{e['risk_level'].upper()}]{Style.RESET_ALL} {Fore.CYAN}{e['ip']}")
        lines.append(f"{Fore.WHITE}Attempts : {Fore.RED}{e['burst_attempts']} in {e['burst_window_m']}m")
        lines.append(f"{Fore.WHITE}Severity : {Fore.MAGENTA}{e['severity_score']}")
        lines.append(f"{Fore.WHITE}Events   : {e['total_events']}")

        if e["reasons"]:
            lines.append(Fore.WHITE + "Patterns:")
            for r in e["reasons"]:
                lines.append(f"  {Fore.YELLOW}- {r}")

        lines.append(Fore.WHITE + "-" * 45)

    return "\n".join(lines)