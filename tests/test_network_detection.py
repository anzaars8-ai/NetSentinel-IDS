from detection.rules import (
    port_scan_rule,
    horizontal_scan_rule,
    public_ip_scan_rule,
)


class Stats:
    def __init__(self, ports=None, syns=0, destinations=None):
        self.unique_ports = set(ports or [])
        self.syns = syns
        self.unique_destinations = set(destinations or [])


class Parsed:
    def __init__(self, src_ip, dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip


def test_network_port_scan():
    parsed = Parsed("192.168.1.20", "192.168.1.50")
    stats = Stats(range(1, 21), 20)

    alert = port_scan_rule(parsed, stats, {
        "port_scan_unique_ports": 15,
        "port_scan_min_syns": 10,
    })

    assert alert
    assert alert["rule"] == "PORT_SCAN"


def test_horizontal_scan():
    parsed = Parsed("192.168.1.20", "192.168.1.50")
    stats = Stats([80], 10, [
        "192.168.1.1",
        "192.168.1.2",
        "192.168.1.3",
        "192.168.1.4",
        "192.168.1.5",
        "192.168.1.6",
        "192.168.1.7",
        "192.168.1.8",
    ])

    alert = horizontal_scan_rule(parsed, stats, {
        "horizontal_scan_hosts": 8,
        "horizontal_scan_min_syns": 10,
    })

    assert alert
    assert alert["rule"] == "HORIZONTAL_SCAN"


def test_external_scan():
    parsed = Parsed("8.8.8.8", "192.168.1.50")
    stats = Stats(range(1, 6), 5)

    alert = public_ip_scan_rule(parsed, stats, {
        "public_ip_scan_unique_ports": 5,
        "public_ip_scan_min_syns": 5,
    })

    assert alert
    assert alert["rule"] == "PUBLIC_IP_SCAN"
