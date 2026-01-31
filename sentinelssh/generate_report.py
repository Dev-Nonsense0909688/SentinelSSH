from .parse_data import analyze_events
from .get_data import get_data
from datetime import datetime
import os


def generate_report(top_ips: int = 5, path: str = None):
    if path is None:
        print("[*] No log file path provided. Use --path to specify the log file.")
        return
    
    if not os.path.exists(path):
        print(f"Log file does not exist: {path}")
        return
    
    if not os.path.isfile(path):
        print(f"Provided path is not a file: {path}")
        return

    events = get_data(path)
    analysis = analyze_events(events)

    analysis = sorted(
        analysis,
        key=lambda x: (x["severity_score"], x["total_events"]),
        reverse=True
    )[:top_ips]

    report = {
        "meta": {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "total_ips": len(analysis),
            "total_events": sum(x["total_events"] for x in analysis)
        },
        "top_threats": []
    }

    for entry in analysis:
        report["top_threats"].append({
            "ip": entry["ip"],
            "risk_level": entry["risk_level"],
            "severity_score": entry["severity_score"],
            "total_events": entry["total_events"],
            "reasons": entry["reasons"]
        })
    return report
