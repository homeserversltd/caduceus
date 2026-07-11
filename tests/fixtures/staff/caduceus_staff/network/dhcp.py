import argparse
import json


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command")
    parser.add_argument("method", nargs="?")
    parser.add_argument("route", nargs="?")
    parser.add_argument("rest", nargs="*")
    parser.add_argument("--metadata-json", default="{}")
    args = parser.parse_args()
    if args.command == "intent":
        metadata = json.loads(args.metadata_json)
        print(json.dumps({
            "schema": "caduceus.network.dhcp.intent.v1",
            "ok": True,
            "accepted": True,
            "classification": "network-control",
            "method": args.method,
            "route": args.route,
            "metadata": metadata,
            "execution": "caduceus_staff.network.dhcp",
            "mutationPerformed": args.method not in ("GET", "HEAD", "OPTIONS"),
            "firstMissingSignal": "none",
        }))
        return
    print(json.dumps({
        "schema": f"caduceus.network.dhcp.{args.command.replace('-', '_')}.v1",
        "ok": True,
        "command": args.command,
        "execution": "caduceus_staff.network.dhcp",
        "mutationPerformed": args.command not in ("status", "leases", "reservations"),
        "firstMissingSignal": "none",
    }))


if __name__ == "__main__":
    main()
