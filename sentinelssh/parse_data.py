from collections import defaultdict, Counter
from .attack_events import load_map, load_names, load_severity

SEVERITY_SCORE = load_severity()
REASON_MAP = load_map()
REASON_ORDER = load_names()

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

