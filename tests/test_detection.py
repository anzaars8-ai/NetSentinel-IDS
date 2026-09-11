from scapy.all import IP, TCP

from parser.packet_parser import parse_packet

from features.flow_tracker import (
    FlowTracker
)

from detection.rules import (
    port_scan_rule
)


def test_port_scan_detection():

    tracker = FlowTracker(10)

    thresholds = {
        "port_scan_unique_ports": 15,
        "port_scan_min_packets": 20,
    }

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
        "192.168.1.50"
    )

    alert = port_scan_rule(
        parsed,
        stats,
        thresholds
    )

    assert alert is not None
    assert alert["rule"] == "PORT_SCAN"
    assert alert["severity"] == "HIGH"
