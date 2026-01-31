from ..get_data import *
import time

DEFAULT_PATH = "sentinelssh/demo_input/ssh_auth.log"

def cmd_watch(args):
    print(f"Watching {args.path} (Ctrl+C to stop)\n")

    seen = 0

    while True:
        try:
            events = get_data(args.path or DEFAULT_PATH)
            if len(events) > seen:
                new = events[seen:]
                seen = len(events)

                for e in new:
                    ip = e.get("ip", "?")
                    attack = e.get("attack_type", "?")
                    print(f"[ALERT] {ip} → {attack}")

            time.sleep(args.interval)

        except KeyboardInterrupt:
            print("\nStopped.")
            break