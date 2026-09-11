"""Network IDS detection rules."""

import ipaddress


def _base_alert(
    rule,
    severity,
    description,
    pkt,
    confidence
):
    return {
        "rule": rule,
        "severity": severity,
        "description": description,
        "src_ip": pkt["src_ip"],
        "dst_ip": pkt["dst_ip"],
        "src_port": pkt["src_port"],
        "dst_port": pkt["dst_port"],
        "proto": pkt["proto"],
        "confidence": confidence,
    }


def port_scan_rule(pkt, stats, thresholds):

    if (
        len(stats.unique_ports)
        >= thresholds["port_scan_unique_ports"]
        and
        stats.packets
        >= thresholds["port_scan_min_packets"]
    ):

        return _base_alert(
            "PORT_SCAN",
            "HIGH",
            (
                f"Port scan detected: "
                f"{pkt['src_ip']} touched "
                f"{len(stats.unique_ports)} "
                f"unique destination ports "
                f"with {stats.packets} packets"
            ),
            pkt,
            0.90,
        )

    return None


def public_ip_scan_rule(pkt, stats, thresholds):

    """
    Detect scanning activity against a public-facing host.

    This rule is intended for traffic actually observed arriving
    at the monitored host. It does NOT perform scanning itself.
    """

    try:
        source = ipaddress.ip_address(
            pkt["src_ip"]
        )

        destination = ipaddress.ip_address(
            pkt["dst_ip"]
        )

    except ValueError:
        return None

    # Source must be globally routable/external.
    if not source.is_global:
        return None

    # Destination must be a globally routable/public address.
    if not destination.is_global:
        return None

    unique_ports = len(
        stats.unique_ports
    )

    if (
        unique_ports
        >= thresholds["public_ip_scan_unique_ports"]
        and
        stats.packets
        >= thresholds["public_ip_scan_min_packets"]
    ):

        return _base_alert(
            "PUBLIC_IP_SCAN",
            "HIGH",
            (
                f"Public IP scan detected: external source "
                f"{pkt['src_ip']} targeted public address "
                f"{pkt['dst_ip']} across "
                f"{unique_ports} destination ports "
                f"with {stats.packets} packets"
            ),
            pkt,
            0.95,
        )

    return None


def high_conn_rate_rule(
    pkt,
    stats,
    thresholds
):

    if stats.syns >= thresholds["high_conn_rate"]:

        return _base_alert(
            "HIGH_CONN_RATE",
            "MEDIUM",
            (
                f"High connection rate: "
                f"{stats.syns} SYN packets from "
                f"{pkt['src_ip']}"
            ),
            pkt,
            0.70,
        )

    return None


def high_traffic_rule(
    pkt,
    stats,
    thresholds
):

    if stats.bytes_total >= thresholds["high_traffic_bytes"]:

        return _base_alert(
            "HIGH_TRAFFIC",
            "MEDIUM",
            (
                f"High traffic volume: "
                f"{stats.bytes_total / 1e6:.1f} MB "
                f"from {pkt['src_ip']}"
            ),
            pkt,
            0.60,
        )

    return None


def syn_flood_rule(
    pkt,
    stats,
    thresholds
):

    if stats.syns >= thresholds["syn_flood_min_syns"]:

        return _base_alert(
            "SYN_FLOOD",
            "CRITICAL",
            (
                f"Possible SYN flood: "
                f"{stats.syns} SYN packets from "
                f"{pkt['src_ip']}"
            ),
            pkt,
            0.80,
        )

    return None


ALL_RULES = [
    port_scan_rule,
    public_ip_scan_rule,
    high_conn_rate_rule,
    high_traffic_rule,
    syn_flood_rule,
]
