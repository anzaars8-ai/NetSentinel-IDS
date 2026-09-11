from scapy.all import IP, TCP

from parser.packet_parser import parse_packet

from features.flow_tracker import (
    FlowTracker
)

from detection.rules import (
    port_scan_rule
)

from alerts.alert_manager import (
    AlertManager
)


def test_full_pipeline():

    tracker = FlowTracker(10)

    thresholds = {
        "port_scan_unique_ports": 15,
        "port_scan_min_packets": 20,
    }

    generated_alerts = []

    manager = AlertManager(
        on_alert=generated_alerts.append
    )

    for port in range(1, 21):

        packet = (
            IP(
                src="192.168.1.50",
                dst="192.168.1.1"
            )
            /
            TCP(
                sport=40000 + port,
                dport=port,
                flags="S"
            )
        )

        parsed = parse_packet(packet)

        tracker.update(parsed)

        stats = tracker.stats_for(
            parsed["src_ip"]
        )

        alert = port_scan_rule(
            parsed,
            stats,
            thresholds
        )

        if alert:

            manager.process(
                alert
            )

    stats = tracker.stats_for(
        "192.168.1.50"
    )

    assert stats.packets == 20
    assert len(stats.unique_ports) == 20

    assert len(generated_alerts) == 1

    assert (
        generated_alerts[0]["rule"]
        == "PORT_SCAN"
    )
