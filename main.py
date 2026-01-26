import re
import argparse
from collections import defaultdict
from colorama import Fore, init

init(autoreset=True)

# ===================== REGEX =====================
LOG_PATTERN = re.compile(
    r'(?P<month>\w+)\s+'
    r'(?P<day>\d+)\s+'
    r'(?P<time>\d+:\d+:\d+).*?'
    r'(?P<status>Failed|Accepted)\s+'
    r'(password|publickey)\s+for\s+'
    r'(invalid user\s+)?'
    r'(?P<user>[^\s]+)\s+from\s+'
    r'(?P<ip>[a-fA-F0-9:.]+)'
)

# ===================== ANALYSIS =====================
def analyze_log(path, speed_threshold=6, time_window=60):
    fail_count = defaultdict(int)
    risk_score = defaultdict(float)
    fail_times = defaultdict(list)
    records = []

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                m = LOG_PATTERN.search(line)
                if not m:
                    continue

                ip = m.group("ip")
                status = m.group("status")

                # convert HH:MM:SS → seconds
                h, m_, s = map(int, m.group("time").split(":"))
                timestamp = h * 3600 + m_ * 60 + s
                
                records.append({"ip": ip})


                if status == "Failed":
                    fail_count[ip] += 1
                    fail_times[ip].append(timestamp)

                    # ---- progressive scoring ----
                    c = fail_count[ip]
                    if c <= 5:
                        risk_score[ip] += 1
                    elif c <= 20:
                        risk_score[ip] += 2
                    else:
                        risk_score[ip] += 3

    except FileNotFoundError:
        print("Log file not found.")
        exit(1)

    # ===================== SPEED-BASED BRUTE FORCE =====================
    bruteforce_ips = set()

    for ip, times in fail_times.items():
        times.sort()
        for i in range(len(times)):
            j = i
            while j < len(times) and times[j] - times[i] <= time_window:
                j += 1
            if j - i >= speed_threshold:
                bruteforce_ips.add(ip)
                risk_score[ip] *= 1.5
                break

    # sort risk descending
    risk_sorted = dict(
        sorted(risk_score.items(), key=lambda x: x[1], reverse=True)
    )
    


    return records, bruteforce_ips, risk_sorted


# ===================== SUMMARY =====================
def print_summary(records, bruteforce, risk):
    print("\n======== SUMMARY REPORT ========\n")

    unique_ips = {r["ip"] for r in records}
    print("Total unique IPs:", len(unique_ips))
    print("Total brute-force IPs:", len(bruteforce))

    if risk:
        top_ip = next(iter(risk))
        print("Highest risk IP:", top_ip)
        print("Highest risk score:", round(risk[top_ip], 2))
    else:
        print("Highest risk IP: None")

    print("\n===============================\n")


# ===================== OUTPUT =====================
def print_results(bruteforce, risk):
    if bruteforce:
        print("\n======== Brute-force IPs ========\n")
        for ip in bruteforce:
            location = "Internal" if ip.startswith("192.168") else "External"
            color = Fore.YELLOW if location == "Internal" else Fore.RED
            print(f"{color}{ip}\t{location}")

    if risk:
        print("\n======== Risk Scores ========\n")
        print("IP\t\tRisk\tLevel")

        for ip, score in risk.items():
            if score >= 60:
                color, level = Fore.RED, "CRITICAL"
            elif score >= 40:
                color, level = Fore.YELLOW, "HIGH"
            elif score >= 25:
                color, level = Fore.YELLOW, "MEDIUM"
            elif score >= 10:
                color, level = Fore.CYAN, "LOW"
            else:
                color, level = Fore.GREEN, "SAFE"

            print(f"{color}{ip}\t{round(score,2)}\t{level}")


# ===================== MAIN =====================
def main():
    parser = argparse.ArgumentParser(description="SSH Log Risk Analyzer")

    parser.add_argument(
        "--file",
        required=True,
        help="Path to SSH auth.log file"
    )

    parser.add_argument(
        "--speed",
        type=int,
        default=6,
        help="Failures within time window to trigger brute-force (default: 6)"
    )

    parser.add_argument(
        "--window",
        type=int,
        default=60,
        help="Time window in seconds (default: 60)"
    )

    args = parser.parse_args()

    records, bruteforce, risk = analyze_log(
        args.file,
        speed_threshold=args.speed,
        time_window=args.window
    )

    print_results(bruteforce, risk)
    print_summary(records, bruteforce, risk)


if __name__ == "__main__":
    main()
