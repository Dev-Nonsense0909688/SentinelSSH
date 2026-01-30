from src.get_data import get_data
from collections import defaultdict, Counter
import json

SEVERITY_SCORE = {
    "username_enumeration": 1,
    "ssh_bruteforce": 2,
    "automated_bruteforce": 3,
    "privileged_acc_bruteforce": 5
}


REASON_MAP = {
    "privileged_acc_bruteforce": "Privileged account (root) brute-force detected ({count} attempts)",
    "automated_bruteforce": "Automated brute-force detected ({count} attempts)",
    "ssh_bruteforce": "SSH brute-force attempts detected ({count} attempts)",
    "username_enumeration": "Username enumeration activity ({count} attempts)"
}

REASON_ORDER = [
    "privileged_acc_bruteforce",
    "automated_bruteforce",
    "ssh_bruteforce",
    "username_enumeration"
]

def risk_level(score):
    if score >= 300:
        return "CRITICAL"
    elif score >= 150:
        return "HIGH"
    elif score >= 50:
        return "MEDIUM"
    else:
        return "LOW"


def analyze_events(events):

    ip_attack_counts = defaultdict(Counter)
    ip_severity_score = defaultdict(int)

    for event in events:
        ip = event.get("ip")
        attack = event.get("attack_type")

        if not ip or not attack:
            continue

        ip_attack_counts[ip][attack] += 1

        if attack in SEVERITY_SCORE:
            ip_severity_score[ip] += SEVERITY_SCORE[attack]

    results = []

    for ip, attacks in ip_attack_counts.items():
        reasons = []

        for attack_type in REASON_ORDER:
            if attack_type in attacks:
                reasons.append(
                    REASON_MAP[attack_type].format(
                        count=attacks[attack_type]
                    )
                )

        score = ip_severity_score[ip]

        results.append({
            "ip": ip,
            "severity_score": score,
            "risk_level": risk_level(score),
            "total_events": sum(attacks.values()),
            "reasons": reasons
        })

    results.sort(
        key=lambda x: (x["severity_score"], x["total_events"]),
        reverse=True
    )

    return results

