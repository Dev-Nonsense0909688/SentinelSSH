from ..generate_report import *
from colorama import Fore, Style
from collections import Counter

DEFAULT_PATH = "sentinelssh/demo_input/ssh_auth.log"

def cmd_top_ips(args):
    events = get_data(args.path or DEFAULT_PATH)
    counter = Counter(e["ip"] for e in events if "ip" in e)

    print(f"\n{Style.BRIGHT}{Fore.CYAN}Top IP Attackers")
    print(Fore.WHITE + "-" * 32)

    for ip, count in counter.most_common(args.n):
        print(f"{Fore.YELLOW}{ip:<18} {Fore.RED}{count:>5} attempts")

    print("")
