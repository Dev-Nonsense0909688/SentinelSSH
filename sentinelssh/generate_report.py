from .parse_data import analyze_events
from .get_data import get_data
from datetime import datetime, timedelta
from collections import defaultdict
import os
from colorama import Style,init,Fore

init(autoreset=True) 

def parse_ts(ts):
    if isinstance(ts, datetime):
        return ts

    ts = ts.replace("Z", "")

    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return datetime.strptime(ts, "%H:%M:%S")

def compute_bursts(events, window_minutes=2):
    per_ip_times = defaultdict(list)

    for e in events:
        if "ip" not in e or "timestamp" not in e:
            continue
        per_ip_times[e["ip"]].append(parse_ts(e["timestamp"]))

    burst_map = {}
    window = timedelta(minutes=window_minutes)

    for ip, times in per_ip_times.items():
        if not times:
            continue

        times.sort()
        left = 0
        max_count = 0

        for right in range(len(times)):
            while times[right] - times[left] > window:
                left += 1
            max_count = max(max_count, right - left + 1)

        burst_map[ip] = {
            "attempts": max_count,
            "window_m": window_minutes
        }

    return burst_map

def generate_report(top_ips: int = 5, path: str = None, window_minutes: int = 2):
    if path is None:
        print(f"{Style.BRIGHT}{Fore.RED}[*] No log file path provided. Use --path to specify the log file.")
        return None

    if not os.path.exists(path):
        print(f"{Style.BRIGHT}{Fore.RED}[*]Log file does not exist: {path}")
        return None

    if not os.path.isfile(path):
        print(f"{Style.BRIGHT}{Fore.RED}[*]Provided path is not a file: {path}")
        return None

    events = get_data(path)
    if not events:
        print(f"{Style.BRIGHT}{Fore.RED}[*] No events parsed from log.")
        return None

    analysis = analyze_events(events)
    burst_map = compute_bursts(events, window_minutes)

    analysis = sorted(
        analysis,
        key=lambda x: (x["severity_score"], x["total_events"]),
        reverse=True
    )[:top_ips]

    report = {
        "meta": {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "total_ips": len(analysis),
            "total_events": sum(x["total_events"] for x in analysis),
            "window_minutes": window_minutes
        },
        "top_threats": []
    }

    for entry in analysis:
        ip = entry["ip"]
        burst = burst_map.get(ip, {"attempts": 0, "window_m": window_minutes})

        report["top_threats"].append({
            "ip": ip,
            "risk_level": entry["risk_level"],
            "severity_score": entry["severity_score"],
            "total_events": entry["total_events"],
            "reasons": entry["reasons"],
            "burst_attempts": burst["attempts"],
            "burst_window_m": burst["window_m"]
        })

    return report
