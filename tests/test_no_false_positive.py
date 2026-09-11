from detection.rules import port_scan_rule


def test_no_port_scan_below_threshold():

    thresholds = {
        "port_scan_unique_ports": 15,
        "port_scan_min_packets": 20,
    }

    class Stats:

        packets = 5
        unique_ports = {80, 443}

    packet = {
        "src_ip": "192.168.1.50",
        "dst_ip": "192.168.1.1",
        "src_port": 40000,
        "dst_port": 80,
        "proto": "TCP",
    }

    alert = port_scan_rule(
        packet,
        Stats(),
        thresholds
    )

    assert alert is None
