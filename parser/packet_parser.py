"""Parse Scapy packets into normalized dictionaries."""

from typing import Optional


def parse_packet(packet) -> Optional[dict]:
    """Extract IPv4/TCP/UDP fields."""

    if not packet.haslayer("IP"):
        return None

    ip = packet["IP"]

    parsed = {
        "src_ip": ip.src,
        "dst_ip": ip.dst,
        "proto": "OTHER",
        "src_port": None,
        "dst_port": None,
        "flags": "",
        "length": int(len(packet)),
    }

    if packet.haslayer("TCP"):
        tcp = packet["TCP"]

        parsed["proto"] = "TCP"
        parsed["src_port"] = int(tcp.sport)
        parsed["dst_port"] = int(tcp.dport)
        parsed["flags"] = str(tcp.flags)

    elif packet.haslayer("UDP"):
        udp = packet["UDP"]

        parsed["proto"] = "UDP"
        parsed["src_port"] = int(udp.sport)
        parsed["dst_port"] = int(udp.dport)

    return parsed
