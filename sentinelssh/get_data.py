import re
import json
from .attack_events import AttackRule

CLEAN_RE = re.compile(
    r'^\w+\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\w+\[\d+\]:\s*'
)

RULES = [clss for clss in AttackRule.__subclasses__()]

def get_data(path="sentinelssh/a.log"):
    data = []

    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                time_match = re.search(r'\d{2}:\d{2}:\d{2}', line)
                timestamp = time_match.group(0) if time_match else None

                for rule in RULES:

                    m = rule.match(line=line,self=rule())
                    if not m:
                        continue

                    event = rule.build_event(
                        self = rule(),
                        match=m,
                        timestamp=timestamp,
                        line=CLEAN_RE.sub("", line)
                    )

                    data.append(event)

    except FileNotFoundError:
        print("Error: file not found ->", path)

    return data
