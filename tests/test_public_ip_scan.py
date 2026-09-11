from detection.rules import public_ip_scan_rule


class Stats:
    packets = 5
    bytes_total = 300
    unique_ports = {22, 23, 80, 443, 8080}
    syns = 5


def test_external_public_ip_scan():

    packet = {
        "src_ip": "8.8.8.8",
        "dst_ip": "192.168.1.50",
        "src_port": 40000,
        "dst_port": 22,
        "proto": "TCP",
        "flags": "S",
    }

    thresholds = {
        "public_ip_scan_unique_ports": 5,
        "public_ip_scan_min_syns": 5,
    }

    alert = public_ip_scan_rule(
        packet,
        Stats(),
        thresholds
    )

    assert alert is not None
    assert alert["rule"] == "PUBLIC_IP_SCAN"
    assert alert["severity"] == "CRITICAL"


def test_private_source_is_ignored():

    packet = {
        "src_ip": "192.168.1.20",
        "dst_ip": "192.168.1.50",
        "src_port": 40000,
        "dst_port": 22,
        "proto": "TCP",
        "flags": "S",
    }

    thresholds = {
        "public_ip_scan_unique_ports": 5,
        "public_ip_scan_min_syns": 5,
    }

    alert = public_ip_scan_rule(
        packet,
        Stats(),
        thresholds
    )

    assert alert is None
