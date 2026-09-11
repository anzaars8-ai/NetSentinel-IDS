import ipaddress
import time


def _get(obj, key, default=None):
    """Read a field from either a dict or an object."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _threshold(thresholds, name, default):
    try:
        return int(thresholds.get(name, default))
    except Exception:
        return default


def _external(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return not (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
        )
    except Exception:
        return False



def _public_target(dst_ip, thresholds):
    """
    Return True when the destination is the configured public IP.
    This allows the IDS to recognize public-IP scans even when
    NAT later delivers the packet to a private host.
    """
    if not dst_ip:
        return False

    configured = thresholds.get("public_ips", [])

    if isinstance(configured, str):
        configured = [configured]

    return dst_ip in configured



def _alert(rule, severity, confidence, description, src_ip=None, dst_ip=None,
          src_port=None, dst_port=None, proto="TCP", details=None):
    """Create a normalized, database-safe alert dictionary."""

    # Some rules pass a details dictionary as their final positional argument.
    # Keep that information separate from the database proto field.
    if isinstance(proto, dict):
        details = proto
        proto = "TCP"

    return {
        "rule": rule,
        "severity": severity,
        "description": str(description or f"{rule} detected"),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "proto": str(proto or "TCP"),
        "confidence": float(confidence),
    }

def port_scan_rule(parsed, stats, thresholds):
    src_ip = _get(parsed, "src_ip")
    dst_ip = _get(parsed, "dst_ip")
    src_port = _get(parsed, "src_port")
    dst_port = _get(parsed, "dst_port")

    unique_ports = len(_get(stats, "unique_ports", set()))
    syns = int(_get(stats, "syns", 0))

    minimum_ports = _threshold(
        thresholds, "port_scan_unique_ports", 15
    )
    minimum_syns = _threshold(
        thresholds, "port_scan_min_syns", 10
    )

    # Backward compatibility with the original pipeline tests.
    if syns == 0:
        syns = int(_get(stats, "packets", 0))

    if unique_ports >= minimum_ports and syns >= minimum_syns:
        return _alert(
            "PORT_SCAN",
            "HIGH",
            0.95,
            f"Network port scan detected: {unique_ports} ports / {syns} SYNs",
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            {
                "unique_ports": unique_ports,
                "syns": syns,
            },
        )


def horizontal_scan_rule(parsed, stats, thresholds):
    src_ip = _get(parsed, "src_ip")
    dst_ip = _get(parsed, "dst_ip")

    destinations = _get(stats, "unique_destinations", set())
    hosts = len(destinations)
    syns = int(_get(stats, "syns", 0))

    minimum_hosts = _threshold(
        thresholds, "horizontal_scan_hosts", 8
    )
    minimum_syns = _threshold(
        thresholds, "horizontal_scan_min_syns", 10
    )

    if hosts >= minimum_hosts and syns >= minimum_syns:
        return _alert(
            "HORIZONTAL_SCAN",
            "HIGH",
            0.96,
            f"Host sweep detected: {hosts} destinations / {syns} SYNs",
            src_ip,
            dst_ip,
            _get(parsed, "src_port"),
            _get(parsed, "dst_port"),
            {
                "unique_destinations": hosts,
                "syns": syns,
            },
        )


def public_ip_scan_rule(parsed, stats, thresholds):
    src_ip = _get(parsed, "src_ip")
    dst_ip = _get(parsed, "dst_ip")

    unique_ports = len(_get(stats, "unique_ports", set()))
    syns = int(_get(stats, "syns", 0))

    minimum_ports = _threshold(
        thresholds, "public_ip_scan_unique_ports", 5
    )
    minimum_syns = _threshold(
        thresholds, "public_ip_scan_min_syns", 5
    )

    external_source = bool(src_ip and _external(src_ip))
    public_target = _public_target(dst_ip, thresholds)

    # Detect an external source scanning a host that the IDS sees.
    # Also support explicitly configured public-IP targets.
    if (external_source or public_target):
        if unique_ports >= minimum_ports and syns >= minimum_syns:
            return _alert(
                "PUBLIC_IP_SCAN",
                "CRITICAL",
                0.97,
                (
                    f"Public/network reconnaissance detected: "
                    f"{unique_ports} ports / {syns} SYNs"
                ),
                src_ip,
                dst_ip,
                _get(parsed, "src_port"),
                _get(parsed, "dst_port"),
                {
                    "unique_ports": unique_ports,
                    "syns": syns,
                    "external_source": external_source,
                    "public_target": public_target,
                },
            )


def syn_flood_rule(parsed, stats, thresholds):
    syns = int(_get(stats, "syns", 0))
    minimum = _threshold(
        thresholds, "syn_flood_min_syns", 100
    )

    if syns >= minimum:
        return _alert(
            "SYN_FLOOD",
            "CRITICAL",
            0.98,
            f"Possible SYN flood: {syns} SYN packets",
            _get(parsed, "src_ip"),
            _get(parsed, "dst_ip"),
            _get(parsed, "src_port"),
            _get(parsed, "dst_port"),
            {"syns": syns},
        )


def high_connection_rate_rule(parsed, stats, thresholds):
    connections = int(_get(stats, "connection_count", 0))
    minimum = _threshold(
        thresholds, "high_conn_rate", 50
    )

    if connections >= minimum:
        return _alert(
            "HIGH_CONNECTION_RATE",
            "HIGH",
            0.91,
            f"Abnormally high connection rate: {connections}",
            _get(parsed, "src_ip"),
            _get(parsed, "dst_ip"),
            _get(parsed, "src_port"),
            _get(parsed, "dst_port"),
            {"connections": connections},
        )


def high_traffic_rule(parsed, stats, thresholds):
    traffic = int(_get(stats, "bytes", 0))
    minimum = _threshold(
        thresholds, "high_traffic_bytes", 5000000
    )

    if traffic >= minimum:
        return _alert(
            "HIGH_TRAFFIC",
            "MEDIUM",
            0.88,
            f"Abnormally high traffic volume: {traffic} bytes",
            _get(parsed, "src_ip"),
            _get(parsed, "dst_ip"),
            _get(parsed, "src_port"),
            _get(parsed, "dst_port"),
            {"bytes": traffic},
        )


ALL_RULES = [
    port_scan_rule,
    horizontal_scan_rule,
    public_ip_scan_rule,
    syn_flood_rule,
    high_connection_rate_rule,
    high_traffic_rule,
]
