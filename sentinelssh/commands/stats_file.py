from ..generate_report import *
from colorama import Fore, Style
from collections import Counter

DEFAULT_PATH = "sentinelssh/demo_input/ssh_auth.log"

def cmd_stats(args):
    events = get_data(args.path or DEFAULT_PATH)
    counter = Counter(e["ip"] for e in events if "ip" in e)

    print(f"\n{Style.BRIGHT}{Fore.CYAN}Attack Volume Graph\n")

    if not counter:
        print(Fore.YELLOW + "No data.")
        return

    max_val = max(counter.values())
    scale = 40 / max_val if max_val else 1

    for ip, count in counter.most_common(args.n):
        bars = Fore.RED + "█" * int(count * scale)
        print(f"{Fore.YELLOW}{ip:<18} {bars} {Fore.WHITE}{count}")