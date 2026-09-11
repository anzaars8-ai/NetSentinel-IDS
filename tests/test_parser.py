from scapy.all import IP, TCP, UDP

from parser.packet_parser import parse_packet


def test_tcp_parser():

    packet = (
        IP(
            src="192.168.1.10",
            dst="192.168.1.1"
        )
        /
        TCP(
            sport=12345,
            dport=80
        )
    )

    result = parse_packet(packet)

    assert result is not None
    assert result["src_ip"] == "192.168.1.10"
    assert result["dst_ip"] == "192.168.1.1"
    assert result["proto"] == "TCP"
    assert result["src_port"] == 12345
    assert result["dst_port"] == 80


def test_udp_parser():

    packet = (
        IP(
            src="10.0.0.1",
            dst="10.0.0.2"
        )
        /
        UDP(
            sport=5000,
            dport=53
        )
    )

    result = parse_packet(packet)

    assert result["proto"] == "UDP"
    assert result["dst_port"] == 53
