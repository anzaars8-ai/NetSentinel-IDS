#!/usr/bin/env python3

"""Network Intrusion Detection System MVP."""

import argparse
import threading
import yaml

from parser.packet_parser import parse_packet

from features.flow_tracker import (
    FlowTracker
)

from detection.rules import (
    ALL_RULES
)

from alerts.alert_manager import (
    AlertManager
)

from database.db import (
    AlertStore
)

from capture.packet_capture import (
    PacketCapture
)

from api.app import (
    create_app
)


def load_config():

    with open(
        "config/config.yaml",
        "r"
    ) as file:

        return yaml.safe_load(file)


def main():

    parser = argparse.ArgumentParser(
        description="Network Intrusion Detection System"
    )

    parser.add_argument(
        "-i",
        "--interface",
        default=None,
        help="Network interface"
    )

    parser.add_argument(
        "--no-api",
        action="store_true",
        help="Disable Flask dashboard"
    )

    args = parser.parse_args()

    config = load_config()

    interface = (
        args.interface
        or
        config["capture"]["interface"]
    )

    tracker = FlowTracker(
        config["window"]["seconds"]
    )

    store = AlertStore(
        config["database"]["path"]
    )

    thresholds = config["thresholds"]

    def save_alert(alert):

        store.save(alert)

        print()
        print("=" * 70)
        print("[!] INTRUSION DETECTED")
        print(f"Rule       : {alert['rule']}")
        print(f"Severity   : {alert['severity']}")
        print(f"Source     : {alert['src_ip']}")
        print(f"Destination: {alert['dst_ip']}")
        print(f"Protocol   : {alert['proto']}")
        print(f"Confidence : {alert['confidence']}")
        print(f"Details    : {alert['description']}")
        print("=" * 70)

    manager = AlertManager(
        on_alert=save_alert
    )

    def process_packet(packet):
        """Process one packet without ever killing the capture loop."""
        try:
            parsed = parse_packet(packet)

            if parsed is None:
                return

            tracker.update(parsed)

            stats = tracker.stats_for(
                parsed["src_ip"]
            )

            for rule in ALL_RULES:
                try:
                    alert = rule(
                        parsed,
                        stats,
                        thresholds
                    )

                    if alert:
                        manager.process(alert)

                except Exception as exc:
                    print(
                        f"\\n[!] Detection rule error: "
                        f"{getattr(rule, "__name__", repr(rule))}: "
                        f"{type(exc).__name__}: {exc}",
                        flush=True
                    )

        except Exception as exc:
            print(
                f"\\n[!] PACKET PROCESSING ERROR: "
                f"{type(exc).__name__}: {exc}",
                flush=True
            )
            try:
                print(
                    f"    Packet: {packet.summary()}",
                    flush=True
                )
            except Exception:
                pass

    print()
    print("=" * 70)
    print("        NETWORK INTRUSION DETECTION SYSTEM")
    print("=" * 70)
    print()
    print(
        f"Interface : "
        f"{interface or 'Scapy default interface'}"
    )
    print(
        f"Window    : "
        f"{config['window']['seconds']} seconds"
    )
    print()
    print("Detection rules:")
    print("  [1] PORT_SCAN")
    print("  [2] PUBLIC_IP_SCAN")
    print("  [3] HIGH_CONN_RATE")
    print("  [4] HIGH_TRAFFIC")
    print("  [5] SYN_FLOOD")
    print()
    print("Dashboard: http://127.0.0.1:5000")
    print()
    print("Press CTRL+C to stop.")
    print("=" * 70)
    print()

    if not args.no_api:

        app = create_app(
            store,
            tracker
        )

        api_thread = threading.Thread(
            target=lambda:
                app.run(
                    host=config["api"]["host"],
                    port=config["api"]["port"],
                    debug=False,
                    use_reloader=False
                ),
            daemon=True
        )

        api_thread.start()

    capture = PacketCapture(
        interface
    )

    try:

        capture.start(
            process_packet
        )

    except KeyboardInterrupt:

        print()
        print("[*] IDS stopped.")

    finally:

        store.close()


if __name__ == "__main__":
    main()
