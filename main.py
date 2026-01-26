import re
import argparse
from collections import defaultdict
from colorama import Fore, Style, init

init(autoreset=True)

# ===================== REGEX =====================
LOG_PATTERN = re.compile(
    r'(?P<month>\w+)\s+'
    r'(?P<day>\d+)\s+'
    r'(?P<time>\d+:\d+:\d+).*?'
    r'(?P<status>Failed|Accepted) password for '
    r'(invalid user )?'
    r'(?P<user>\w+) from '
    r'(?P<ip>[\d.]+)'
)

# ===================== ANALYSIS =====================
def analyze_log(path, brute_threshold=3):
    fail_count = defaultdict(int)
    risk_score = defaultdict(int)
    unusual_logins = []
    records = []
    try:
     with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            match = LOG_PATTERN.search(line)
            if not match:
                continue

            ip = match.group("ip")
            hour = int(match.group("time").split(":")[0])
            status = match.group("status")

            records.append({"ip": ip})

            if status == "Failed":
                fail_count[ip] += 1
                risk_score[ip] += 2

            if hour <= 5:
                risk_score[ip] += 2
                unusual_logins.append((
                    ip,
                    match.group("month") + " " + match.group("day"),
                    match.group("time")
                ))
    except FileNotFoundError:
        print("File not found!")
        exit()
        
    bruteforce_ips = {}
    for ip in fail_count:
        if fail_count[ip] >= brute_threshold:
            bruteforce_ips[ip] = fail_count[ip]
            risk_score[ip] += 3

    sorted_risk = sorted(
        risk_score.items(),
        key=lambda x: x[1],
        reverse=True
    )

    return records, bruteforce_ips, unusual_logins, dict(sorted_risk)


# ===================== SUMMARY =====================
def print_summary(records, bruteforce, risk):
    print("\n======== SUMMARY REPORT ========\n")

    unique_ips = set()
    for r in records:
        unique_ips.add(r["ip"])

    print("Total unique IPs:", len(unique_ips))
    print("Total brute-force IPs:", len(bruteforce))

    if risk:
        highest_ip = next(iter(risk))
        print("Highest risk IP:", highest_ip)
        print("Highest risk score:", risk[highest_ip])
    else:
        print("Highest risk IP: None")

    print("\n===============================\n")


# ===================== MAIN =====================
def main():
    parser = argparse.ArgumentParser(description="SSH Log Risk Analyzer")

    parser.add_argument(
        "--file",
        required=True,
        help="Path to SSH auth.log file"
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=3,
        help="Brute-force detection threshold (default: 3)"
    )

    args = parser.parse_args()

    records, bruteforce, unusual, risk = analyze_log(
        args.file,
        brute_threshold=args.threshold
    )

    if bruteforce:
        print("\n======== Brute-force IPs ========\n")
        for ip in bruteforce:
            location = "Internal" if ip.startswith("192.168") else "External"
            color = Fore.YELLOW if location == "Internal" else Fore.RED
            print(f"{color}{ip}\t{location}")

    if unusual:
        print("\n======== Unusual Time Logins ========\n")
        print("IP\t\tDate\t\tTime")
        for ip, date, time in unusual:
            print(f"{ip}\t\t{date}\t\t{time}")

    if risk:
        print("\n======== Risk Scores ========\n")
        print("IP\t\tRisk Score\tLevel")

        for ip, score in risk.items():
            if score >= 50:
                color, level = Fore.RED, "CRITICAL"
            elif score >= 40:
                color, level = Fore.YELLOW, "HIGH"
            elif score >= 25:
                color, level = Fore.YELLOW, "MEDIUM"
            elif score >= 10:
                color, level = Fore.CYAN, "LOW"
            else:
                color, level = Fore.GREEN, "SAFE"

            print(f"{color}{ip}\t\t{score}\t\t{level}")

    print_summary(records, bruteforce, risk)


if __name__ == "__main__":
    main()
